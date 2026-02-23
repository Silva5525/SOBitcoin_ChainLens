// src/btc/tx/mod.rs
//!
//! Transaction analysis entrypoints.
//!
//! This module is the *public* API surface for transaction analysis.
//! It also contains the fixture adapter (`analyze_tx`) used by CLI/Web:
//! - decode raw tx hex
//! - reorder fixture `prevouts` into vin-order (fast-path if already ordered)
//! - call the core engine (`core`) and then build the JSON report (`report`)
//!
//! Design goals:
//! - Keep `crate::btc::tx::analyze_tx` stable (used by CLI/Web)
//! - Avoid allocations on the hot path (fast-path avoids HashMap)
//! - Keep JSON shaping in `report.rs`, not in the parser

pub mod core;
pub mod report;
pub mod script;
pub mod util;

pub use report::{
    Prevout, PrevoutInfo, RelativeTimelock, SegwitSavings, TxReport, VinReport, VoutReport,
    WarningItem,
};

pub use core::{analyze_tx_from_bytes_ordered, analyze_tx_from_bytes_ordered_lite, TxComputeFlags};

// Internal-only (block-mode) types/functions live under `btc::tx::core`.
// Example:
//   use crate::btc::tx::core::{analyze_tx_core_lite, CoreTx};

use ahash::AHashMap;

// For fixture parsing
use core::PrevoutKey;
use util::{hex_to_bytes, Cursor, read_varint};

/// Analyze a transaction described by the "fixture" format (raw tx hex + prevouts).
///
/// Inputs:
/// - `network`: affects address formatting (bc/tb, base58 prefixes)
/// - `raw_tx_hex`: full transaction serialization as hex
/// - `prevouts`: previous outputs for every non-coinbase input
///
/// Behavior:
/// - For coinbase transactions, `prevouts` is ignored.
/// - For non-coinbase transactions, the function expects `prevouts.len() == vin.len()`.
///   The fixture may list prevouts in any order; we re-order them into vin-order.
///
/// Errors:
/// - invalid hex
/// - truncated or malformed tx serialization
/// - missing/mismatching prevouts
pub fn analyze_tx(network: &str, raw_tx_hex: &str, prevouts: &[Prevout]) -> Result<TxReport, String> {
    // Decode tx hex once. All later slices borrow from this buffer.
    let raw = hex_to_bytes(raw_tx_hex)?;

    // --- 1) First pass: parse only the input outpoints (vin order) ---
    // We do a cheap scan to extract `(prev_txid, vout)` keys for each input.
    // This lets us:
    //   (a) detect coinbase quickly
    //   (b) check if fixture prevouts are already in vin-order (fast path)
    let mut c = Cursor::new(&raw);

    // version
    let _version = c.take_u32_le()?;

    // segwit marker/flag (if present)
    // We "peek" one byte. If it is 0x00, we expect 0x01 next (marker+flag).
    // Otherwise we backtrack and treat it as the varint that starts vin_count.
    let peek = c.take_u8()?;
    if peek == 0x00 {
        let flag = c.take_u8()?;
        if flag != 0x01 {
            return Err("invalid segwit flag".into());
        }
    } else {
        c.backtrack_1()?;
    }

    let vin_count_u64 = read_varint(&mut c)?;
    let vin_count = vin_count_u64 as usize;

    // Collect outpoints as (txid_le, vout) in vin order.
    // Note: tx serialization stores txid bytes little-endian.
    let mut coinbase = false;
    let mut keys: Vec<PrevoutKey> = Vec::with_capacity(vin_count);

    for vin_idx in 0..vin_count {
        let prev_txid_le_bytes = c.take(32)?;
        let prev_vout = c.take_u32_le()?;

        // Coinbase is a single input with a null outpoint (32x00 + vout=0xffffffff).
        if vin_idx == 0
            && vin_count == 1
            && prev_vout == 0xffff_ffff
            && prev_txid_le_bytes.iter().all(|&b| b == 0)
        {
            coinbase = true;
        }

        // skip scriptSig + sequence
        let script_len = read_varint(&mut c)? as usize;
        let _ = c.take(script_len)?;
        let _sequence = c.take_u32_le()?;

        if !coinbase {
            let mut txid_le = [0u8; 32];
            txid_le.copy_from_slice(prev_txid_le_bytes);
            keys.push(PrevoutKey { txid_le, vout: prev_vout });
        }
    }

    // Coinbase txs don't require prevouts.
    if coinbase {
        let empty: &[(u64, &[u8])] = &[];
        return analyze_tx_from_bytes_ordered(network, &raw, empty);
    }

    // Invariant: for non-coinbase, we need exactly one prevout per input.
    if prevouts.len() != keys.len() {
        return Err(format!(
            "prevouts length mismatch: got {} expected {}",
            prevouts.len(),
            keys.len()
        ));
    }

    /// Convert a fixture prevout (txid in display hex, big-endian) into our internal outpoint key.
    ///
    /// The tx serialization stores txid bytes little-endian, but humans display txids big-endian.
    #[inline]
    fn prevout_key_from_hex(txid_hex: &str, vout: u32) -> Result<PrevoutKey, String> {
        let mut be = crate::btc::tx::util::hex_to_bytes(txid_hex)?;
        if be.len() != 32 {
            return Err("prevout txid must be 32 bytes".into());
        }
        // Reverse to little-endian to match the serialized outpoint.
        be.reverse();
        let mut txid_le = [0u8; 32];
        txid_le.copy_from_slice(&be);
        Ok(PrevoutKey { txid_le, vout })
    }

    // --- 2) Fast path: if fixture prevouts are already in vin order, avoid HashMap entirely ---
    // This is a big win for CPU and allocations when fixtures are already aligned.
    let mut ordered_ok = true;
    for (i, p) in prevouts.iter().enumerate() {
        let k = prevout_key_from_hex(&p.txid_hex, p.vout)?;
        if k != keys[i] {
            ordered_ok = false;
            break;
        }
    }

    // We store scripts as owned Vec<u8> here because fixture gives scriptPubKey as hex strings.
    // Later we convert them to borrowed slices `&[u8]` for the parser.
    let mut prevouts_ordered: Vec<(u64, Vec<u8>)> = Vec::with_capacity(keys.len());

    if ordered_ok {
        // Ordered: just decode scripts in the same order.
        for p in prevouts {
            prevouts_ordered.push((
                p.value_sats,
                crate::btc::tx::util::hex_to_bytes(&p.script_pubkey_hex)?,
            ));
        }
    } else {
        // --- 3) General path: build a fast hash map from outpoint -> (value, script_pubkey_bytes) ---
        // We then rebuild an ordered vector by iterating vin keys.
        let mut prevmap: AHashMap<PrevoutKey, (u64, Vec<u8>)> =
            AHashMap::with_capacity(prevouts.len().saturating_mul(2));

        for p in prevouts {
            let k = prevout_key_from_hex(&p.txid_hex, p.vout)?;
            let spk_bytes = crate::btc::tx::util::hex_to_bytes(&p.script_pubkey_hex)?;
            prevmap.insert(k, (p.value_sats, spk_bytes));
        }

        for k in &keys {
            let (value, spk) = prevmap
                .remove(k)
                .ok_or_else(|| "missing prevout".to_string())?;
            prevouts_ordered.push((value, spk));
        }
    }

    // --- 4) Run the ordered analyzer ---
    // Convert owned scripts to borrowed slices for the zero-copy core analyzer.
    let borrowed: Vec<(u64, &[u8])> = prevouts_ordered
        .iter()
        .map(|(v, spk)| (*v, spk.as_slice()))
        .collect();

    analyze_tx_from_bytes_ordered(network, &raw, &borrowed)
}
