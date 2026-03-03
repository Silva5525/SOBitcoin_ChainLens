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

use std::hash::{Hash, Hasher}; // Import traits so we can implement `Hash` for PrevoutKey

use crate::btc::tx::script::{classify_input_spend, script_type}; // Bring script helpers into scope
use crate::btc::tx::util::{dsha256, read_varint, write_varint_hasher, Cursor, Dsha256Writer}; // Bring parsing + hashing utilities into scope

#[repr(u8)] // Force the enum to be stored as a single byte
#[derive(Clone, Copy, Debug, Eq, PartialEq)] // Auto-derive common traits (copyable, comparable, printable)
/// Internal output script classification used by the analyzer.
pub(crate) enum ScriptType {
    P2PKH = 0,    // Pay-to-PubKey-Hash
    P2SH = 1,     // Pay-to-Script-Hash
    P2WPKH = 2,   // Native SegWit P2WPKH
    P2WSH = 3,    // Native SegWit P2WSH
    P2TR = 4,     // Taproot
    OpReturn = 5, // OP_RETURN (provably unspendable)
    Unknown = 6,  // Anything not matching known templates
}

impl ScriptType {
    /// Stable string label used in JSON reports.
    #[inline] // Tell compiler to inline this tiny function
    pub(crate) fn as_str(self) -> &'static str { // Convert enum value to a fixed string
        match self { // Pick a string based on the variant
            ScriptType::P2PKH => "p2pkh", // Label for P2PKH
            ScriptType::P2SH => "p2sh", // Label for P2SH
            ScriptType::P2WPKH => "p2wpkh", // Label for P2WPKH
            ScriptType::P2WSH => "p2wsh", // Label for P2WSH
            ScriptType::P2TR => "p2tr", // Label for P2TR
            ScriptType::OpReturn => "op_return", // Label for OP_RETURN
            ScriptType::Unknown => "unknown", // Label for unknown
        }
    }
}

#[repr(u8)] // Store as a byte as well
#[derive(Clone, Copy, Debug, Eq, PartialEq)] // Copyable + comparable
/// Internal input spend classification derived from prevout + scripts (heuristic).
pub(crate) enum SpendType {
    P2PKH = 0,         // Spending a P2PKH output
    P2WPKH = 1,        // Spending a P2WPKH output
    P2WSH = 2,         // Spending a P2WSH output
    P2TRKeyPath = 3,   // Taproot key-path spend
    P2TRScriptPath = 4,// Taproot script-path spend
    P2SHP2WPKH = 5,    // P2SH nested P2WPKH
    P2SHP2WSH = 6,     // P2SH nested P2WSH
    P2SH = 7,          // Legacy P2SH spend (non-nested)
    Unknown = 8,       // Could not classify
}

impl SpendType {
    #[inline]
    pub(crate) fn as_str(self) -> &'static str { // Convert spend type to stable label
        match self { // Pick label per variant
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

#[repr(u8)] // Store warning code as a byte
#[derive(Clone, Copy, Debug, Eq, PartialEq)] // Copyable + comparable
/// Internal warning codes emitted by cheap, best-effort checks.
pub(crate) enum WarningCode {
    RbfSignaling = 0,       // At least one input signals Replace-By-Fee
    UnknownOutputScript = 1,// At least one output script is unrecognized
    DustOutput = 2,         // At least one output looks like dust
    HighFee = 3,            // Fee or fee-rate looks unusually high
}

impl WarningCode {
    #[inline] // Inline: tiny function
    pub(crate) fn as_str(self) -> &'static str { // Convert warning code to stable string
        match self { // Match on warning code
            WarningCode::RbfSignaling => "RBF_SIGNALING",
            WarningCode::UnknownOutputScript => "UNKNOWN_OUTPUT_SCRIPT",
            WarningCode::DustOutput => "DUST_OUTPUT",
            WarningCode::HighFee => "HIGH_FEE",
        }
    }
}

/// Parsed transaction input with attached prevout data.
pub(crate) struct CoreInput<'a> { // Input representation borrowing from raw buffers
    pub(crate) prev_txid_le: [u8; 32], // Previous transaction id (little-endian)
    pub(crate) vout: u32,              // Index of the previous output being spent
    pub(crate) sequence: u32,          // Sequence (used for RBF + relative locktimes)
    pub(crate) script_sig: &'a [u8],   // scriptSig bytes borrowed from raw tx
    pub(crate) witness: Vec<&'a [u8]>, // Witness stack items (each item borrows from raw tx)
    pub(crate) witness_script_asm: Option<String>, // Optional decoded witness script (only if requested)
    pub(crate) spend_type: SpendType,  // Best-effort classification of how this input is spending
    pub(crate) prev_value: u64,        // Value of the prevout (sats) provided by caller/undo
    pub(crate) prev_spk: &'a [u8],     // Prevout scriptPubKey bytes borrowed from provided prevout storage
}

pub(crate) struct CoreOutput<'a> { // Output representation borrowing from raw tx
    pub(crate) value: u64,              // Output value in satoshis
    pub(crate) spk: &'a [u8],           // scriptPubKey bytes borrowed from raw tx
    pub(crate) script_type: ScriptType, // Classified output type
}

/// Internal transaction representation (no JSON strings here).
pub(crate) struct CoreTx<'a> { // Minimal internal tx model used by hot paths
    pub(crate) txid_le: [u8; 32],           // txid (little-endian)
    pub(crate) wtxid_le: Option<[u8; 32]>,  // wtxid (little-endian) for segwit; None for legacy
    pub(crate) version: u32,                // Transaction version
    pub(crate) locktime: u32,               // nLockTime
    pub(crate) segwit: bool,                // Whether segwit marker/flag was present
    pub(crate) size_bytes: usize,           // Total serialized length in bytes
    pub(crate) non_witness_bytes: usize,    // Size of stripped serialization (no witness)
    pub(crate) witness_bytes: usize,        // Witness section byte size (0 if legacy)
    pub(crate) weight: usize,               // Weight units (BIP141)
    pub(crate) vbytes: usize,               // Virtual bytes = ceil(weight/4)
    pub(crate) total_input: u64,            // Sum of input values (from prevouts)
    pub(crate) total_output: u64,           // Sum of output values
    pub(crate) fee: i64,                    // Fee = inputs - outputs (0 for coinbase)
    pub(crate) rbf: bool,                   // Whether any input signals RBF
    pub(crate) inputs: Vec<CoreInput<'a>>,  // Parsed inputs
    pub(crate) outputs: Vec<CoreOutput<'a>>,// Parsed outputs
    pub(crate) warnings: Vec<WarningCode>,  // Cheap warnings (optional)
}

#[derive(Clone, Copy, Debug)] // Copyable flag bundle
/// Controls how much expensive data is computed.
pub struct TxComputeFlags { // Feature toggles for optional computations
    pub include_script_hex: bool,   // Whether to keep script hex in report
    pub include_script_asm: bool,   // Whether to disassemble scripts to ASM
    pub include_addresses: bool,    // Whether to derive addresses
    pub include_witness_hex: bool,  // Whether to include witness items as hex
    pub include_op_return: bool,    // Whether to parse OP_RETURN payload
    pub include_warnings: bool,     // Whether to compute warnings
}

impl TxComputeFlags {
    /// Full detail mode (CLI / Web usage).
    pub const FULL: Self = Self { // Full output: compute everything
        include_script_hex: true,
        include_script_asm: true,
        include_addresses: true,
        include_witness_hex: true,
        include_op_return: true,
        include_warnings: true,
    };

    /// Minimal mode (used in block scanning hot path).
    pub const LITE: Self = Self { // Minimal output: skip expensive features
        include_script_hex: false,
        include_script_asm: false,
        include_addresses: false,
        include_witness_hex: false,
        include_op_return: false,
        include_warnings: false,
    };
}

#[derive(Clone, Copy, Eq, PartialEq)] // Key must be comparable
/// Key used to match prevouts to inputs.
pub(crate) struct PrevoutKey { // Outpoint identifier
    pub(crate) txid_le: [u8; 32], // Prev txid stored in little-endian (wire order)
    pub(crate) vout: u32,         // Output index
}

impl Hash for PrevoutKey { // Allow PrevoutKey to be used in hash maps/sets
    fn hash<H: Hasher>(&self, state: &mut H) { // Write key bytes into the hasher
        state.write(&self.txid_le); // Hash txid bytes
        state.write_u32(self.vout); // Hash vout number
    }
}

// Detect standard coinbase pattern (null outpoint + single input)
fn is_coinbase_outpoint(prev_txid_le: &[u8], vout: u32, vin_count: usize, vin_idx: usize) -> bool { // Returns true if input is coinbase
    vin_idx == 0 // Only input index 0
        && vin_count == 1 // Coinbase tx must have exactly one input
        && vout == 0xffff_ffff // Coinbase vout field is 0xffffffff
        && prev_txid_le.iter().all(|&b| b == 0) // Coinbase prev txid is 32 bytes of 0
}

// =============================================================================================
// Core parsing + computation logic
// =============================================================================================

fn analyze_tx_from_bytes_ordered_impl<'a>( // Internal worker: returns CoreTx, expects prevouts in vin order
    raw: &'a [u8], // Raw serialized tx bytes
    prevouts_ordered: &'a [(u64, &'a [u8])], // One (value, scriptPubKey) per input, in vin order
    flags: TxComputeFlags, // Feature flags controlling extra computations
) -> Result<CoreTx<'a>, String> { // Returns CoreTx or an error string

    let size_bytes = raw.len(); // Total tx byte length
    let mut c = Cursor::new(raw); // Cursor for safe parsing
    let version = c.take_u32_le()?; // Read version (little-endian)

    // --- SegWit detection ---
    // If next byte is 0x00 and followed by 0x01 → this is SegWit marker+flag.
    // Otherwise it's the vin_count varint.
    let mut segwit = false; // Assume legacy until proven otherwise
    let peek = c.take_u8()?; // Read the next byte to decide layout
    if peek == 0x00 { // 0x00 could be segwit marker
        let flag = c.take_u8()?; // Read segwit flag
        if flag != 0x01 { // Must be exactly 0x01 in valid segwit tx
            return Err("invalid segwit flag".into()); // Reject malformed marker/flag
        }
        segwit = true; // Mark transaction as segwit
    } else {
        c.backtrack_1()?; // Not segwit marker → rewind one byte so varint reads correctly
    }

    // For SegWit, txid excludes witness. We stream stripped serialization into a hasher.
    let mut txid_hasher = if segwit { Some(Dsha256Writer::new()) } else { None }; // Create hasher only if needed
    if let Some(h) = txid_hasher.as_mut() { // Only run if segwit
        h.write(&version.to_le_bytes()); // txid stream starts with version
    }

    let vin_count_u64 = read_varint(&mut c)?; // Read number of inputs
    let vin_count = vin_count_u64 as usize; // Convert to usize
    if let Some(h) = txid_hasher.as_mut() { // Only for segwit
        write_varint_hasher(h, vin_count_u64); // Write varint into txid stream
    }

    let mut inputs: Vec<CoreInput> = Vec::with_capacity(vin_count); // Pre-allocate input vector
    let mut rbf_signaling = false; // Track BIP125 signaling across inputs
    let mut coinbase = false; // Track whether tx is coinbase

    // Each input contributes to stripped hash (if segwit)
    for vin_index in 0..vin_count { // Loop over each input
        let prev_txid_le_bytes = c.take(32)?; // Read prev txid (32 bytes)
        let prev_vout = c.take_u32_le()?; // Read prev output index

        if is_coinbase_outpoint(prev_txid_le_bytes, prev_vout, vin_count, vin_index) { // Check coinbase pattern
            coinbase = true; // Mark coinbase if pattern matches
        }

        if let Some(h) = txid_hasher.as_mut() { // Only for segwit
            h.write(prev_txid_le_bytes); // Add prev txid bytes to txid stream
            h.write(&prev_vout.to_le_bytes()); // Add vout to txid stream
        }

        let script_len_u64 = read_varint(&mut c)?; // Read scriptSig length
        let script_len = script_len_u64 as usize; // Convert to usize
        if let Some(h) = txid_hasher.as_mut() { // Only for segwit
            write_varint_hasher(h, script_len_u64); // Add script length to txid stream
        }

        let script_sig = c.take(script_len)?; // Read scriptSig bytes
        if let Some(h) = txid_hasher.as_mut() { // Only for segwit
            h.write(script_sig); // Add scriptSig to txid stream
        }

        let sequence = c.take_u32_le()?; // Read sequence
        if let Some(h) = txid_hasher.as_mut() { // Only for segwit
            h.write(&sequence.to_le_bytes()); // Add sequence to txid stream
        }

        // BIP125: sequence < 0xfffffffe → RBF signaling
        if sequence < 0xffff_fffe { // BIP125 condition
            rbf_signaling = true; // Record that at least one input signals RBF
        }

        let (prev_value, prev_spk) = if coinbase { // Coinbase has no real prevouts
            (0u64, &[][..]) // Use dummy prevout for coinbase
        } else {
            prevouts_ordered // Use provided prevouts
                .get(vin_index) // Match prevout to this vin index
                .copied() // Copy the tuple (u64, &[u8])
                .ok_or_else(|| "prevouts_ordered length mismatch".to_string())? // Error if missing
        };

        let mut prev_txid_le = [0u8; 32]; // Allocate fixed array for txid
        prev_txid_le.copy_from_slice(prev_txid_le_bytes); // Copy bytes into fixed array

        inputs.push(CoreInput { // Push parsed input into vector
            prev_txid_le, // Save prev txid
            vout: prev_vout, // Save vout
            sequence, // Save sequence
            script_sig, // Save scriptSig slice
            witness: Vec::new(), // Initialize witness as empty; filled later if segwit
            witness_script_asm: None, // Default: no decoded witness script
            spend_type: SpendType::Unknown, // Default classification until later
            prev_value, // Save prevout value
            prev_spk, // Save prevout scriptPubKey
        });
    }

    let vout_count_u64 = read_varint(&mut c)?; // Read number of outputs
    let vout_count = vout_count_u64 as usize; // Convert to usize
    if let Some(h) = txid_hasher.as_mut() { // Only for segwit
        write_varint_hasher(h, vout_count_u64); // Add output count to txid stream
    }

    let mut outputs: Vec<CoreOutput> = Vec::with_capacity(vout_count); // Pre-allocate outputs
    let mut total_output_sats: u64 = 0; // Running sum of output values

    for _ in 0..vout_count { // Loop outputs
        let value = c.take_u64_le()?; // Read output value
        total_output_sats = total_output_sats.saturating_add(value); // Add value (overflow-safe)
        if let Some(h) = txid_hasher.as_mut() { // Only for segwit
            h.write(&value.to_le_bytes()); // Add value to txid stream
        }

        let spk_len_u64 = read_varint(&mut c)?; // Read scriptPubKey length
        let spk_len = spk_len_u64 as usize; // Convert to usize
        if let Some(h) = txid_hasher.as_mut() { // Only for segwit
            write_varint_hasher(h, spk_len_u64); // Add script length to txid stream
        }

        let spk = c.take(spk_len)?; // Read scriptPubKey bytes
        if let Some(h) = txid_hasher.as_mut() { // Only for segwit
            h.write(spk); // Add scriptPubKey to txid stream
        }

        outputs.push(CoreOutput { // Save output
            value, // Store value
            spk, // Store scriptPubKey slice
            script_type: script_type(spk), // Classify the output script
        });
    }

    // --- Witness parsing ---
    // Each input has a CompactSize count followed by that many stack items.
    if segwit { // Only segwit tx has witness section
        for input in inputs.iter_mut() { // Iterate inputs to fill witness items
            let n_stack = read_varint(&mut c)? as usize; // Read number of witness stack items
            let mut items: Vec<&[u8]> = Vec::with_capacity(n_stack); // Pre-allocate item list
            for _ in 0..n_stack { // Loop stack items
                let item_len = read_varint(&mut c)? as usize; // Read item length
                let item = c.take(item_len)?; // Read item bytes
                items.push(item); // Save slice
            }
            input.witness = items; // Attach witness to input
        }
    }

    let locktime = c.take_u32_le()?; // Read locktime
    if let Some(h) = txid_hasher.as_mut() { // Only for segwit
        h.write(&locktime.to_le_bytes()); // Add locktime to txid stream
    }

    if c.remaining() != 0 { // If not at end, tx bytes were malformed
        return Err("trailing bytes after parsing".into()); // Error on trailing data
    }

    let non_witness_size = txid_hasher.as_ref().map(|h| h.len).unwrap_or(size_bytes); // Stripped size for segwit, else full size
    let witness_bytes = if segwit { size_bytes.saturating_sub(non_witness_size) } else { 0 }; // Witness size for segwit, else 0

    let txid_le = if segwit { txid_hasher.unwrap().finish() } else { dsha256(raw) }; // Compute txid (stripped for segwit)
    let wtxid_le = if segwit { Some(dsha256(raw)) } else { None }; // Compute wtxid (full tx) for segwit

    let mut total_input_sats: u64 = 0; // Running sum of input values
    for input in inputs.iter_mut() { // Iterate inputs to compute sum + classify spend type
        total_input_sats = total_input_sats.saturating_add(input.prev_value); // Add prevout value

        // Heuristic spend-type detection (not full script execution)
        let (spend_type, ws_asm) = classify_input_spend( // Classify how this input spends
            input.prev_spk, // Prevout scriptPubKey
            input.script_sig, // scriptSig bytes
            &input.witness, // Witness stack
            flags.include_script_asm, // Whether to compute witness script asm
        );
        input.spend_type = spend_type; // Store computed spend type
        if flags.include_script_asm { // Only store asm if requested
            input.witness_script_asm = ws_asm; // Save optional witness script disassembly
        }
    }

    if coinbase { // Special-case coinbase
        total_input_sats = total_output_sats; // Make fee compute as 0 by setting inputs==outputs
        rbf_signaling = false; // Coinbase does not signal RBF
    }

    let fee = if coinbase { 0 } else { total_input_sats as i64 - total_output_sats as i64 }; // Compute fee

    if !coinbase && fee < 0 { // Fee must not be negative for normal tx
        return Err("NEGATIVE_FEE (outputs > inputs)".into()); // Error if outputs exceed inputs
    }

    // Weight rules (BIP141):
    // legacy: size*4
    // segwit: stripped*4 + witness
    let weight = if segwit { non_witness_size * 4 + witness_bytes } else { size_bytes * 4 }; // Compute weight
    let vbytes = weight.div_ceil(4); // Compute vbytes as ceil(weight/4)

    let mut warnings: Vec<WarningCode> = Vec::new(); // Collect warnings here
    if flags.include_warnings { // Only compute warnings if enabled
        if rbf_signaling { // If any input signaled RBF
            warnings.push(WarningCode::RbfSignaling); // Add RBF warning
        }
        if outputs.iter().any(|o| o.script_type == ScriptType::Unknown) { // If any output is unknown
            warnings.push(WarningCode::UnknownOutputScript); // Add unknown script warning
        }
        if outputs.iter().any(|o| o.value < 546 && o.script_type != ScriptType::OpReturn) { // Simple dust heuristic
            warnings.push(WarningCode::DustOutput); // Add dust warning
        }
        if !coinbase { // Fee warnings only apply to non-coinbase
            let fee_sats = if fee > 0 { fee as u64 } else { 0 }; // Convert fee to u64 safely
            let fee_rate_sat_vb = if vbytes > 0 { fee_sats as f64 / vbytes as f64 } else { 0.0 }; // Compute fee rate
            if fee_sats > 1_000_000 || fee_rate_sat_vb > 200.0 { // Thresholds for "high" fees
                warnings.push(WarningCode::HighFee); // Add high fee warning
            }
        }
    }

    Ok(CoreTx { // Return the completed CoreTx struct
        txid_le, // Final txid
        wtxid_le, // Optional wtxid
        version, // Version
        locktime, // Locktime
        segwit, // SegWit flag
        size_bytes, // Total size
        non_witness_bytes: non_witness_size, // Stripped size
        witness_bytes, // Witness size
        weight, // Weight
        vbytes, // Virtual bytes
        total_input: total_input_sats, // Input sum
        total_output: total_output_sats, // Output sum
        fee, // Fee
        rbf: rbf_signaling, // RBF flag
        inputs, // Inputs
        outputs, // Outputs
        warnings, // Warnings
    })
}

// Public wrappers (FULL vs LITE)

pub fn analyze_tx_from_bytes_ordered<'a>( // Public API: ordered prevouts, full report
    network: &str, // Network label ("mainnet", etc.)
    raw: &'a [u8], // Raw tx bytes
    prevouts_ordered: &'a [(u64, &'a [u8])], // Prevouts aligned to vin order
) -> Result<crate::btc::tx::report::TxReport, String> { // Returns JSON-ready TxReport
    let core = analyze_tx_from_bytes_ordered_impl(raw, prevouts_ordered, TxComputeFlags::FULL)?; // Build CoreTx with FULL flags
    crate::btc::tx::report::build_tx_report(network, core, TxComputeFlags::FULL) // Convert CoreTx into TxReport
}

pub fn analyze_tx_from_bytes_ordered_lite<'a>( // Public API: ordered prevouts, lite report
    network: &str, // Network label
    raw: &'a [u8], // Raw tx bytes
    prevouts_ordered: &'a [(u64, &'a [u8])], // Prevouts aligned to vin order
) -> Result<crate::btc::tx::report::TxReport, String> { // Returns JSON-ready TxReport
    let core = analyze_tx_from_bytes_ordered_impl(raw, prevouts_ordered, TxComputeFlags::LITE)?; // Build CoreTx with LITE flags
    crate::btc::tx::report::build_tx_report(network, core, TxComputeFlags::LITE) // Convert CoreTx into TxReport
}

pub(crate) fn analyze_tx_core_lite<'a>( // Internal API: return CoreTx directly (used by block-mode)
    raw: &'a [u8], // Raw tx bytes
    prevouts_ordered: &'a [(u64, &'a [u8])], // Prevouts aligned to vin order
) -> Result<CoreTx<'a>, String> { // Returns CoreTx
    analyze_tx_from_bytes_ordered_impl(raw, prevouts_ordered, TxComputeFlags::LITE) // Reuse the same implementation
}
