
// ============================================================================
// src/btc/tx/core.rs
// Core engine (parsing + compute), no JSON strings
// ============================================================================
//!
//! Core transaction parser and compute engine.
//!
//! Responsibilities:
//! - Parse raw transaction bytes into structured inputs/outputs.
//! - Compute txid/wtxid, weight/vbytes, fee, and basic warnings.
//! - Keep allocations low by borrowing most slices from the raw buffer.
//!
//! Non-goals:
//! - No signature checking or script execution.
//! - No JSON shaping (that lives in `report.rs`).

use std::hash::{Hash, Hasher};

use crate::btc::tx::script::{classify_input_spend, script_type};
use crate::btc::tx::util::{dsha256, read_varint, write_varint_hasher, Cursor, Dsha256Writer};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal output script classification used by the analyzer.
pub(crate) enum ScriptType {
    P2PKH = 0,
    P2SH = 1,
    P2WPKH = 2,
    P2WSH = 3,
    P2TR = 4,
    OpReturn = 5,
    Unknown = 6,
}

impl ScriptType {
    /// Stable string label used in JSON reports.
    #[inline]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ScriptType::P2PKH => "p2pkh",
            ScriptType::P2SH => "p2sh",
            ScriptType::P2WPKH => "p2wpkh",
            ScriptType::P2WSH => "p2wsh",
            ScriptType::P2TR => "p2tr",
            ScriptType::OpReturn => "op_return",
            ScriptType::Unknown => "unknown",
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal input spend classification derived from prevout + scripts (heuristic).
pub(crate) enum SpendType {
    P2PKH = 0,
    P2WPKH = 1,
    P2WSH = 2,
    P2TRKeyPath = 3,
    P2TRScriptPath = 4,
    P2SHP2WPKH = 5,
    P2SHP2WSH = 6,
    P2SH = 7,
    Unknown = 8,
}

impl SpendType {
    /// Stable string label used in JSON reports.
    #[inline]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SpendType::P2PKH => "p2pkh",
            SpendType::P2WPKH => "p2wpkh",
            SpendType::P2WSH => "p2wsh",
            SpendType::P2TRKeyPath => "p2tr_keypath",
            SpendType::P2TRScriptPath => "p2tr_scriptpath",
            SpendType::P2SHP2WPKH => "p2sh-p2wpkh",
            SpendType::P2SHP2WSH => "p2sh-p2wsh",
            SpendType::P2SH => "p2sh",
            SpendType::Unknown => "unknown",
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Internal warning codes emitted by cheap, best-effort checks.
pub(crate) enum WarningCode {
    RbfSignaling = 0,
    UnknownOutputScript = 1,
    DustOutput = 2,
    HighFee = 3,
}

impl WarningCode {
    /// Stable string label used in JSON reports.
    #[inline]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            WarningCode::RbfSignaling => "RBF_SIGNALING",
            WarningCode::UnknownOutputScript => "UNKNOWN_OUTPUT_SCRIPT",
            WarningCode::DustOutput => "DUST_OUTPUT",
            WarningCode::HighFee => "HIGH_FEE",
        }
    }
}

/// Parsed transaction input with attached prevout data.
///
/// Most byte slices borrow from the raw transaction buffer.
pub(crate) struct CoreInput<'a> {
    pub(crate) prev_txid_le: [u8; 32],
    pub(crate) vout: u32,
    pub(crate) sequence: u32,
    pub(crate) script_sig: &'a [u8],
    pub(crate) witness: Vec<&'a [u8]>,
    pub(crate) witness_script_asm: Option<String>,
    pub(crate) spend_type: SpendType,
    pub(crate) prev_value: u64,
    pub(crate) prev_spk: &'a [u8],
}

/// Parsed transaction output.
pub(crate) struct CoreOutput<'a> {
    pub(crate) value: u64,
    pub(crate) spk: &'a [u8],
    pub(crate) script_type: ScriptType,
}

/// Core transaction representation produced by the parser.
///
/// This is an internal, low-level structure (no JSON strings).
pub(crate) struct CoreTx<'a> {
    pub(crate) txid_le: [u8; 32],
    pub(crate) wtxid_le: Option<[u8; 32]>,
    pub(crate) version: u32,
    pub(crate) locktime: u32,
    pub(crate) segwit: bool,
    pub(crate) size_bytes: usize,
    pub(crate) non_witness_bytes: usize,
    pub(crate) witness_bytes: usize,
    pub(crate) weight: usize,
    pub(crate) vbytes: usize,
    pub(crate) total_input: u64,
    pub(crate) total_output: u64,
    pub(crate) fee: i64,
    pub(crate) rbf: bool,
    pub(crate) inputs: Vec<CoreInput<'a>>,
    pub(crate) outputs: Vec<CoreOutput<'a>>,
    pub(crate) warnings: Vec<WarningCode>,
}

#[derive(Clone, Copy, Debug)]
/// Feature gates for report building.
///
/// The core parser always parses the same bytes, but we can skip expensive/verbose fields
/// (addresses, disassembly, witness hex, OP_RETURN decoding, warnings) when doing bulk scanning.
pub struct TxComputeFlags {
    pub include_script_hex: bool,
    pub include_script_asm: bool,
    pub include_addresses: bool,
    pub include_witness_hex: bool,
    pub include_op_return: bool,
    pub include_warnings: bool,
}

impl TxComputeFlags {
        /// Full details (used by CLI/Web and tests).
    pub const FULL: Self = Self {
        include_script_hex: true,
        include_script_asm: true,
        include_addresses: true,
        include_witness_hex: true,
        include_op_return: true,
        include_warnings: true,
    };

        /// Minimal details (used for block-mode performance).
    pub const LITE: Self = Self {
        include_script_hex: false,
        include_script_asm: false,
        include_addresses: false,
        include_witness_hex: false,
        include_op_return: false,
        include_warnings: false,
    };
}

#[derive(Clone, Copy, Eq, PartialEq)]
/// Hash-map key for identifying a prevout by outpoint.
///
/// `txid_le` matches the on-wire byte order found in raw transactions.
pub(crate) struct PrevoutKey {
    pub(crate) txid_le: [u8; 32],
    pub(crate) vout: u32,
}

impl Hash for PrevoutKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.txid_le);
        state.write_u32(self.vout);
    }
}

/// Detect coinbase input by checking for the null outpoint.
///
/// A standard coinbase tx has exactly one input with:
/// - prev_txid = 32 bytes of 0x00
/// - vout = 0xffffffff
fn is_coinbase_outpoint(prev_txid_le: &[u8], vout: u32, vin_count: usize, vin_idx: usize) -> bool {
    vin_idx == 0
        && vin_count == 1
        && vout == 0xffff_ffff
        && prev_txid_le.iter().all(|&b| b == 0)
}

/// Parse a raw transaction and attach prevouts by vin-order.
///
/// `prevouts_ordered` must be in the same order as inputs (`vin`). Each entry is:
/// `(value_sats, script_pubkey_bytes)`.
///
/// Computes:
/// - txid (stripped for SegWit)
/// - wtxid (full serialization, only for SegWit)
/// - totals (input/output), fee, weight, vbytes
/// - spend type per input (heuristic)
/// - optional warnings
fn analyze_tx_from_bytes_ordered_impl<'a>(
    raw: &'a [u8],
    prevouts_ordered: &'a [(u64, &'a [u8])],
    flags: TxComputeFlags,
) -> Result<CoreTx<'a>, String> {
    let size_bytes = raw.len();
    let mut c = Cursor::new(raw);

    let version = c.take_u32_le()?;

        // --- segwit detection ---
    // The SegWit serialization inserts marker+flag bytes (0x00 0x01) after version.
    // We peek one byte to decide whether to treat it as marker or as the vin_count varint.
    let mut segwit = false;
    let peek = c.take_u8()?;
    if peek == 0x00 {
        let flag = c.take_u8()?;
        if flag != 0x01 {
            return Err("invalid segwit flag".into());
        }
        segwit = true;
    } else {
        c.backtrack_1()?;
    }

        // --- txid hashing for segwit ---
    // For SegWit transactions:
    // - txid = HASH256 of the "stripped" serialization (no witness)
    // - wtxid = HASH256 of the full serialization (with witness)
    // Instead of allocating a stripped buffer, we stream bytes into `Dsha256Writer`.
    // txid (stripped) streaming writer, only needed for segwit.
    let mut txid_hasher = if segwit { Some(Dsha256Writer::new()) } else { None };
    if let Some(h) = txid_hasher.as_mut() {
        h.write(&version.to_le_bytes());
    }

    let vin_count_u64 = read_varint(&mut c)?;
    let vin_count = vin_count_u64 as usize;
    if let Some(h) = txid_hasher.as_mut() {
        write_varint_hasher(h, vin_count_u64);
    }

    let mut inputs: Vec<CoreInput> = Vec::with_capacity(vin_count);
    let mut rbf_signaling = false;
    let mut coinbase = false;

    for vin_index in 0..vin_count {
        let prev_txid_le_bytes = c.take(32)?;
        let prev_vout = c.take_u32_le()?;

        if is_coinbase_outpoint(prev_txid_le_bytes, prev_vout, vin_count, vin_index) {
            coinbase = true;
        }

        if let Some(h) = txid_hasher.as_mut() {
            h.write(prev_txid_le_bytes);
            h.write(&prev_vout.to_le_bytes());
        }

        let script_len_u64 = read_varint(&mut c)?;
        let script_len = script_len_u64 as usize;
        if let Some(h) = txid_hasher.as_mut() {
            write_varint_hasher(h, script_len_u64);
        }

        let script_sig = c.take(script_len)?;
        if let Some(h) = txid_hasher.as_mut() {
            h.write(script_sig);
        }

        let sequence = c.take_u32_le()?;
        if let Some(h) = txid_hasher.as_mut() {
            h.write(&sequence.to_le_bytes());
        }

        if sequence < 0xffff_fffe {
            rbf_signaling = true;
        }

        let (prev_value, prev_spk) = if coinbase {
            (0u64, &[][..])
        } else {
            prevouts_ordered
                .get(vin_index)
                .copied()
                .ok_or_else(|| "prevouts_ordered length mismatch".to_string())?
        };

        let mut prev_txid_le = [0u8; 32];
        prev_txid_le.copy_from_slice(prev_txid_le_bytes);

        inputs.push(CoreInput {
            prev_txid_le,
            vout: prev_vout,
            sequence,
            script_sig,
            witness: Vec::new(),
            witness_script_asm: None,
            spend_type: SpendType::Unknown,
            prev_value,
            prev_spk,
        });
    }

    let vout_count_u64 = read_varint(&mut c)?;
    let vout_count = vout_count_u64 as usize;
    if let Some(h) = txid_hasher.as_mut() {
        write_varint_hasher(h, vout_count_u64);
    }

    let mut outputs: Vec<CoreOutput> = Vec::with_capacity(vout_count);
    let mut total_output_sats: u64 = 0;

    for _ in 0..vout_count {
        let value = c.take_u64_le()?;
        total_output_sats = total_output_sats.saturating_add(value);
        if let Some(h) = txid_hasher.as_mut() {
            h.write(&value.to_le_bytes());
        }

        let spk_len_u64 = read_varint(&mut c)?;
        let spk_len = spk_len_u64 as usize;
        if let Some(h) = txid_hasher.as_mut() {
            write_varint_hasher(h, spk_len_u64);
        }

        let spk = c.take(spk_len)?;
        if let Some(h) = txid_hasher.as_mut() {
            h.write(spk);
        }

        outputs.push(CoreOutput { value, spk, script_type: script_type(spk) });
    }

        // --- witness section (segwit only) ---
    // For each input, parse a CompactSize count followed by that many stack items.
    // Each item is length-prefixed with CompactSize.
    if segwit {
        for input in inputs.iter_mut() {
            let n_stack = read_varint(&mut c)? as usize;
            let mut items: Vec<&[u8]> = Vec::with_capacity(n_stack);
            for _ in 0..n_stack {
                let item_len = read_varint(&mut c)? as usize;
                let item = c.take(item_len)?;
                items.push(item);
            }
            input.witness = items;
        }
    }

    let locktime = c.take_u32_le()?;
    if let Some(h) = txid_hasher.as_mut() {
        h.write(&locktime.to_le_bytes());
    }

        // Any remaining bytes indicate a parse mismatch (or unknown extensions).
    // We treat this as an error to keep results deterministic.
    if c.remaining() != 0 {
        return Err("trailing bytes after parsing".into());
    }

    let non_witness_size = txid_hasher.as_ref().map(|h| h.len).unwrap_or(size_bytes);
    let witness_bytes = if segwit { size_bytes.saturating_sub(non_witness_size) } else { 0 };

    let txid_le = if segwit {
        txid_hasher.unwrap().finish()
    } else {
        dsha256(raw)
    };

    // wtxid is always hash of full serialization; only present when segwit.
    let wtxid_le = if segwit { Some(dsha256(raw)) } else { None };

    let mut total_input_sats: u64 = 0;
    for input in inputs.iter_mut() {
        total_input_sats = total_input_sats.saturating_add(input.prev_value);

        let (spend_type, ws_asm) = classify_input_spend(input.prev_spk, input.script_sig, &input.witness, flags.include_script_asm);
        input.spend_type = spend_type;
        if flags.include_script_asm {
            input.witness_script_asm = ws_asm;
        }
    }

    if coinbase {
        total_input_sats = total_output_sats;
        rbf_signaling = false;
    }

    let fee = if coinbase { 0 } else { total_input_sats as i64 - total_output_sats as i64 };

        // Weight/vbytes:
    // - legacy weight: size*4
    // - segwit weight: non_witness_size*4 + witness_bytes
    // vbytes is weight/4 rounded up.
    let weight = if segwit {
        non_witness_size * 4 + witness_bytes
    } else {
        size_bytes * 4
    };

    let vbytes = weight.div_ceil(4);

    // Warnings: best-effort + cheap checks.
    let mut warnings: Vec<WarningCode> = Vec::new();
    if flags.include_warnings {
        if rbf_signaling {
            warnings.push(WarningCode::RbfSignaling);
        }
        if outputs.iter().any(|o| o.script_type == ScriptType::Unknown) {
            warnings.push(WarningCode::UnknownOutputScript);
        }
        if outputs.iter().any(|o| o.value < 546 && o.script_type != ScriptType::OpReturn) {
            warnings.push(WarningCode::DustOutput);
        }
        if !coinbase && fee > 100_000_000 {
            warnings.push(WarningCode::HighFee);
        }
    }

    Ok(CoreTx {
        txid_le,
        wtxid_le,
        version,
        locktime,
        segwit,
        size_bytes,
        non_witness_bytes: non_witness_size,
        witness_bytes,
        weight,
        vbytes,
        total_input: total_input_sats,
        total_output: total_output_sats,
        fee,
        rbf: rbf_signaling,
        inputs,
        outputs,
        warnings,
    })
}

/// Full analyzer from raw bytes + ordered prevouts (vin-order).
///
/// Use this when you want the complete JSON output (scripts, asm, witness, addresses, warnings).
pub fn analyze_tx_from_bytes_ordered<'a>(
    network: &str,
    raw: &'a [u8],
    prevouts_ordered: &'a [(u64, &'a [u8])],
) -> Result<crate::btc::tx::report::TxReport, String> {
    let core = analyze_tx_from_bytes_ordered_impl(raw, prevouts_ordered, TxComputeFlags::FULL)?;
    crate::btc::tx::report::build_tx_report(network, core, TxComputeFlags::FULL)
}

/// LITE analyzer for block-mode performance.
pub fn analyze_tx_from_bytes_ordered_lite<'a>(
    network: &str,
    raw: &'a [u8],
    prevouts_ordered: &'a [(u64, &'a [u8])],
) -> Result<crate::btc::tx::report::TxReport, String> {
    let core = analyze_tx_from_bytes_ordered_impl(raw, prevouts_ordered, TxComputeFlags::LITE)?;
    crate::btc::tx::report::build_tx_report(network, core, TxComputeFlags::LITE)
}

/// Pure Core analyzer (LITE flags) for block-mode.
pub(crate) fn analyze_tx_core_lite<'a>(
    raw: &'a [u8],
    prevouts_ordered: &'a [(u64, &'a [u8])],
) -> Result<CoreTx<'a>, String> {
    analyze_tx_from_bytes_ordered_impl(raw, prevouts_ordered, TxComputeFlags::LITE)
}
