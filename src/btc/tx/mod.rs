// src/btc/tx/mod.rs
//
// Transaction analysis entrypoints.
// This file is the *API wrapper* around the faster core engine:
//   - parse a "fixture" (raw tx hex + prevouts)
//   - reorder prevouts into vin-order
//   - call the core analyzer
//   - return a JSON-ready TxReport

pub mod core;   // Public submodule: fast tx parsing + fee/weight/txid computation (hot path)
pub mod report; // Public submodule: JSON/report shaping (Vin/Vout/Warnings, etc.)
pub mod script; // Public submodule: script classification + disassembly helpers
pub mod util;   // Public submodule: small byte/hex/cursor utilities used across tx code

pub use report::{
    Prevout, PrevoutInfo, RelativeTimelock, SegwitSavings, TxReport, VinReport, VoutReport,
    WarningItem,
}; // Re-export report types so callers can `use chainlens::btc::tx::TxReport` etc.

pub use core::{analyze_tx_from_bytes_ordered, analyze_tx_from_bytes_ordered_lite, TxComputeFlags};
// Re-export the main entrypoints from core. "ordered" means prevouts are already aligned to vin order.

// Internal-only (block-mode) types/functions live under `btc::tx::core`.

use ahash::AHashMap; // Fast hash map implementation (lower overhead than std::collections::HashMap)

// For fixture parsing
use core::PrevoutKey;                  // Internal key type: (prev_txid_le, vout)
use util::{hex_to_bytes, Cursor, read_varint}; // Helpers: decode hex, read bytes safely, parse varints

/// Analyze a transaction described by the "fixture" format (raw tx hex + prevouts).
///
pub fn analyze_tx(network: &str, raw_tx_hex: &str, prevouts: &[Prevout]) -> Result<TxReport, String> {
    let raw = hex_to_bytes(raw_tx_hex)?; // Decode tx hex once; later parsing borrows slices from this buffer

    // --- 1) First pass: parse only the input outpoints (vin order) ---
    // Key idea: we do a cheap scan to extract each input's outpoint (prev_txid + vout).
    // That lets us detect coinbase and check if fixture prevouts are already ordered.
    let mut c = Cursor::new(&raw); // Cursor tracks position and prevents out-of-bounds reads

    let _version = c.take_u32_le()?; // Read tx version (not used here; full parse happens in core)

    // segwit marker/flag (if present)
    // Tricky bit: legacy tx has vin_count varint here.
    // SegWit tx inserts: marker=0x00, flag=0x01, then vin_count varint.
    let peek = c.take_u8()?;         // Read one byte to decide segwit vs legacy layout
    if peek == 0x00 {
        let flag = c.take_u8()?;     // If marker is 0x00, next must be 0x01
        if flag != 0x01 {
            return Err("invalid segwit flag".into()); // Reject malformed marker/flag sequence
        }
    } else {
        c.backtrack_1()?;            // Not segwit marker → put byte back so varint parsing sees it
    }

    let vin_count_u64 = read_varint(&mut c)?; // Read number of inputs (varint)
    let vin_count = vin_count_u64 as usize;  // Convert to usize for allocations/loops

    // Collect outpoints as (txid_le, vout) in vin order.
    // Note: tx serialization stores txid bytes little-endian.
    let mut coinbase = false; // Will be set if we detect a coinbase input pattern
    let mut keys: Vec<PrevoutKey> = Vec::with_capacity(vin_count); // Pre-allocate outpoint keys

    for vin_idx in 0..vin_count {
        let prev_txid_le_bytes = c.take(32)?; // Read prev txid bytes as stored on wire (little-endian)
        let prev_vout = c.take_u32_le()?;     // Read the output index being spent

        // Coinbase detection: a single-input tx with null outpoint.
        // (This is the canonical coinbase encoding used by Bitcoin.)
        if vin_idx == 0
            && vin_count == 1
            && prev_vout == 0xffff_ffff
            && prev_txid_le_bytes.iter().all(|&b| b == 0)
        {
            coinbase = true;
        }

        // skip scriptSig + sequence
        // We must advance the cursor correctly to reach the next input.
        let script_len = read_varint(&mut c)? as usize; // scriptSig length
        let _ = c.take(script_len)?;                    // scriptSig bytes (ignored here)
        let _sequence = c.take_u32_le()?;               // sequence (ignored here)

        if !coinbase {
            let mut txid_le = [0u8; 32];                // Fixed-size key storage
            txid_le.copy_from_slice(prev_txid_le_bytes);
            keys.push(PrevoutKey { txid_le, vout: prev_vout }); // Save outpoint key in vin order
        }
    }

    // Coinbase txs don't require prevouts.
    if coinbase {
        let empty: &[(u64, &[u8])] = &[];              // No prevouts for coinbase
        return analyze_tx_from_bytes_ordered(network, &raw, empty); // Run core analyzer directly
    }

    // Invariant: for non-coinbase, we need exactly one prevout per input.
    if prevouts.len() != keys.len() {
        return Err(format!(
            "prevouts length mismatch: got {} expected {}",
            prevouts.len(),
            keys.len()
        ));
    }

    /// Convert fixture txid (display hex = big-endian) into internal key (little-endian).
    /// Tricky bit: humans display txids reversed relative to on-wire byte order.
    #[inline]
    fn prevout_key_from_hex(txid_hex: &str, vout: u32) -> Result<PrevoutKey, String> {
        let mut be = crate::btc::tx::util::hex_to_bytes(txid_hex)?; // Decode displayed txid hex
        if be.len() != 32 {
            return Err("prevout txid must be 32 bytes".into());     // Validate txid length
        }
        be.reverse();                               // Convert BE display → LE wire order
        let mut txid_le = [0u8; 32];
        txid_le.copy_from_slice(&be);
        Ok(PrevoutKey { txid_le, vout })            // Return internal outpoint key
    }

    // --- 2) Fast path: if fixture prevouts are already in vin order, avoid HashMap entirely ---
    // This matters because HashMap costs CPU + allocations. If fixture is ordered, we keep it O(n).
    let mut ordered_ok = true;
    for (i, p) in prevouts.iter().enumerate() {
        let k = prevout_key_from_hex(&p.txid_hex, p.vout)?; // Convert fixture prevout into internal key
        if k != keys[i] {                                  // Compare to vin-order key list
            ordered_ok = false;
            break;
        }
    }

    // We store scripts as owned Vec<u8> because fixture scripts arrive as hex strings.
    // The core analyzer expects borrowed slices; we create those later.
    let mut prevouts_ordered: Vec<(u64, Vec<u8>)> = Vec::with_capacity(keys.len());

    if ordered_ok {
        // Ordered: decode scripts in the same order as inputs.
        for p in prevouts {
            prevouts_ordered.push((
                p.value_sats,                                      // prevout value in sats
                crate::btc::tx::util::hex_to_bytes(&p.script_pubkey_hex)?, // decode scriptPubKey hex
            ));
        }
    } else {
        // --- 3) General path: build a hash map from outpoint -> (value, scriptPubKeyBytes) ---
        // Then rebuild an ordered vector by iterating vin keys.
        let mut prevmap: AHashMap<PrevoutKey, (u64, Vec<u8>)> =
            AHashMap::with_capacity(prevouts.len().saturating_mul(2)); // Extra capacity to reduce rehashing

        for p in prevouts {
            let k = prevout_key_from_hex(&p.txid_hex, p.vout)?;
            let spk_bytes = crate::btc::tx::util::hex_to_bytes(&p.script_pubkey_hex)?;
            prevmap.insert(k, (p.value_sats, spk_bytes)); // Insert mapping for lookup by vin key
        }

        for k in &keys {
            let (value, spk) = prevmap
                .remove(k)                    // Remove ensures each prevout is used at most once
                .ok_or_else(|| "missing prevout".to_string())?; // Error if fixture didn't provide needed prevout
            prevouts_ordered.push((value, spk));          // Push in vin order
        }
    }

    // --- 4) Run the ordered analyzer ---
    // Convert owned Vec<u8> scripts into borrowed &[u8] slices for zero-copy core parsing.
    let borrowed: Vec<(u64, &[u8])> = prevouts_ordered
        .iter()
        .map(|(v, spk)| (*v, spk.as_slice()))
        .collect();

    analyze_tx_from_bytes_ordered(network, &raw, &borrowed) // Final: produce TxReport
}
