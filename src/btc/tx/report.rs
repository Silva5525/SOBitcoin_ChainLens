// ============================================================================
// src/btc/tx/report.rs
// JSON schema layer (serde structs + report builder)
// ============================================================================
//!
//! JSON schema (output contract) for transaction analysis.
//!
//! This layer should be kept stable: external tools/tests often depend on field names.
//! It converts `core::CoreTx` (borrowed, numeric, low-level) into a JSON-friendly shape:
//! - human-readable hashes (txid/wtxid)
//! - optional decoded addresses
//! - optional script hex/asm
//! - optional OP_RETURN decoding

use serde::Serialize; // Import Serialize so structs can be converted to JSON via serde

use crate::btc::tx::core::{CoreTx, ScriptType}; // Import internal CoreTx model + ScriptType enum
use crate::btc::tx::script::{disasm_script, parse_op_return_data}; // Import script disassembler + OP_RETURN parser
use crate::btc::tx::util::{address_from_spk, bytes_to_hex, hash_to_display_hex}; // Import helpers for address + hex + hash formatting
use crate::btc::tx::TxComputeFlags; // Import feature flags controlling optional fields

/// Fixture input describing a previous output (value + scriptPubKey).
///
/// The fixture uses display txid hex (big-endian) and hex scriptPubKey.
#[derive(Debug, Clone)] // Allow printing for debug + cloning in tests
pub struct Prevout { // Public struct used when feeding fixture data into analyzer
    pub txid_hex: String, // Display txid (big-endian hex string)
    pub vout: u32, // Output index
    pub value_sats: u64, // Value in satoshis
    pub script_pubkey_hex: String, // scriptPubKey as hex string
}

/// Warning entry emitted by the analyzer.
///
/// `code` is a stable string identifier.
#[derive(Debug, Serialize)] // Serializable to JSON
pub struct WarningItem { // Public warning object
    pub code: String, // Stable warning identifier (e.g. "RBF_SIGNALING")
}

/// Approximate SegWit fee savings metrics.
///
/// We compare actual tx weight to an "as-if legacy" weight (size*4).
#[derive(Debug, Serialize)] // Serializable
pub struct SegwitSavings { // SegWit savings report block
    pub witness_bytes: usize, // Number of witness bytes
    pub non_witness_bytes: usize, // Number of stripped (non-witness) bytes
    pub total_bytes: usize, // Total serialized size
    pub weight_actual: usize, // Actual BIP141 weight
    pub weight_if_legacy: usize, // Hypothetical weight if no witness discount
    pub savings_pct: f64, // Percentage savings vs legacy
}

/// Prevout details embedded into each vin report.
#[derive(Debug, Serialize)] // Serializable
pub struct PrevoutInfo { // Embedded prevout info in each input
    pub value_sats: u64, // Prevout value
    pub script_pubkey_hex: String, // Prevout scriptPubKey as hex (optional depending on flags)
}

/// Relative timelock info (BIP68) derived from sequence.
///
/// This is a simplified representation used for reporting.
#[derive(Debug, Serialize)] // Serializable
pub struct RelativeTimelock { // Simplified BIP68 view
    pub enabled: bool, // Whether relative timelock rules apply

    #[serde(skip_serializing_if = "Option::is_none")] // Omit from JSON if None
    pub r#type: Option<String>, // "blocks" or "time"

    #[serde(skip_serializing_if = "Option::is_none")] // Omit if None
    pub value: Option<u64>, // Block count or seconds
}

/// Report entry for a single transaction input.
#[derive(Debug, Serialize)] // Serializable
pub struct VinReport { // JSON representation of one input
    pub txid: String, // Display prev txid (big-endian hex)
    pub vout: u32, // Prevout index
    pub sequence: u32, // Sequence number
    pub script_sig_hex: String, // scriptSig as hex (may be empty if disabled)
    pub script_asm: String, // scriptSig disassembly (may be empty)
    pub witness: Vec<String>, // Witness stack items as hex strings
    pub witness_script_asm: Option<String>, // Optional decoded witness script
    pub script_type: String, // Spend classification label
    pub address: Option<String>, // Derived address if applicable
    pub prevout: PrevoutInfo, // Embedded prevout info
    pub relative_timelock: RelativeTimelock, // Derived BIP68 view
}

/// Report entry for a single transaction output.
#[derive(Debug, Serialize)] // Serializable
pub struct VoutReport { // JSON representation of one output
    pub n: u32, // Output index
    pub value_sats: u64, // Value in satoshis
    pub script_pubkey_hex: String, // scriptPubKey hex (may be empty if disabled)
    pub script_asm: String, // script disassembly (may be empty)
    pub script_type: String, // Classified RBF_SIGNALINGoutput type
    pub address: Option<String>, // Derived address if applicable

    #[serde(skip_serializing_if = "Option::is_none")] // Omit if None
    pub op_return_data_hex: Option<String>, // OP_RETURN raw data as hex

    #[serde(skip_serializing_if = "Option::is_none")] // Omit if None
    pub op_return_data_utf8: Option<String>, // OP_RETURN data decoded as UTF-8 if valid

    #[serde(skip_serializing_if = "Option::is_none")] // Omit if None
    pub op_return_protocol: Option<String>, // Best-effort protocol label
}

/// Top-level transaction analysis report.
#[derive(Debug, Serialize)] // Serializable
pub struct TxReport { // Main JSON object returned by CLI/Web
    pub ok: bool, // Always true for successful analysis
    pub network: String, // Network label ("mainnet", etc.)
    pub segwit: bool, // Whether tx is segwit
    pub txid: String, // Display txid

    #[serde(skip_serializing_if = "Option::is_none")] // Omit if None
    pub wtxid: Option<String>, // Display wtxid (segwit only)

    pub version: u32, // Transaction version
    pub locktime: u32, // Raw nLockTime
    pub locktime_value: u32, // Duplicate field for compatibility
    pub size_bytes: usize, // Total serialized size
    pub weight: usize, // BIP141 weight
    pub vbytes: usize, // Virtual bytes
    pub fee_sats: i64, // Fee in satoshis
    pub fee_rate_sat_vb: f64, // Fee rate (sat/vB)
    pub total_input_sats: u64, // Sum of input values
    pub total_output_sats: u64, // Sum of output values
    pub rbf_signaling: bool, // Whether any input signals RBF
    pub locktime_type: String, // "none", "block_height", or "unix_timestamp"

    pub vin: Vec<VinReport>, // All input reports
    pub vout: Vec<VoutReport>, // All output reports
    pub warnings: Vec<WarningItem>, // Warnings emitted by analyzer

    #[serde(skip_serializing_if = "Option::is_none")] // Omit if None
    pub segwit_savings: Option<SegwitSavings>, // SegWit discount metrics
}

#[inline]
fn locktime_type(locktime: u32) -> String { // Convert numeric locktime into label
    if locktime == 0 { // 0 means no locktime
        return "none".into(); // Return "none"
    }
    if locktime < 500_000_000 { // Convention: below threshold = block height
        "block_height".into() // Height-based
    } else {
        "unix_timestamp".into() // Timestamp-based
    }
}

#[inline] // Inline small helper
fn relative_timelock(version: u32, sequence: u32) -> RelativeTimelock { // Build simplified BIP68 view
    if version < 2 { // BIP68 only applies to version >= 2
        return RelativeTimelock { enabled: false, r#type: None, value: None }; // Disabled
    }
    if (sequence & (1u32 << 31)) != 0 { // If disable flag (bit 31) is set
        return RelativeTimelock { enabled: false, r#type: None, value: None }; // Disabled
    }

    let v = (sequence & 0x0000_ffff) as u64; // Extract low 16 bits as relative value
    if (sequence & (1u32 << 22)) != 0 { // If bit 22 set → time-based
        RelativeTimelock { enabled: true, r#type: Some("time".into()), value: Some(v * 512) } // 512-second granularity
    } else {
        RelativeTimelock { enabled: true, r#type: Some("blocks".into()), value: Some(v) } // Block-based
    }
}

pub(crate) fn build_tx_report(network: &str, core: CoreTx, flags: TxComputeFlags) -> Result<TxReport, String> { // Convert CoreTx → TxReport
    let txid = hash_to_display_hex(core.txid_le); // Convert little-endian txid to display hex
    let wtxid = core.wtxid_le.map(hash_to_display_hex); // Convert wtxid if present

    let mut vin: Vec<VinReport> = Vec::with_capacity(core.inputs.len()); // Pre-allocate input reports
    for inp in &core.inputs { // Iterate inputs
        let prev_txid = hash_to_display_hex(inp.prev_txid_le); // Convert prev txid to display hex
        let script_sig_hex = if flags.include_script_hex { bytes_to_hex(inp.script_sig) } else { String::new() }; // Conditionally include scriptSig hex
        let script_asm = if flags.include_script_asm { disasm_script(inp.script_sig) } else { String::new() }; // Conditionally include ASM

		let witness: Vec<String> = if flags.include_witness_hex { // Conditionally include witness stack
            inp.witness.iter().map(|w| bytes_to_hex(w)).collect() // Convert each witness item to hex
        } else {
            Vec::new() // Empty if disabled
        };

        let witness_script_asm = if flags.include_script_asm { // Include witness script asm only if enabled
            inp.witness_script_asm.clone() // Clone optional string
        } else {
            None // Otherwise omit
        };

        let address = if flags.include_addresses { // Conditionally derive address
            address_from_spk(network, inp.prev_spk)? // Convert scriptPubKey to address
        } else {
            None // Omit if disabled
        };

        vin.push(VinReport { // Push input report
            txid: prev_txid,
            vout: inp.vout,
            sequence: inp.sequence,
            script_sig_hex,
            script_asm,
            witness,
            witness_script_asm,
            script_type: inp.spend_type.as_str().to_string(), // Convert spend type enum to string
            address,
            prevout: PrevoutInfo {
                value_sats: inp.prev_value, // Embed prevout value
                script_pubkey_hex: if flags.include_script_hex { bytes_to_hex(inp.prev_spk) } else { String::new() }, // Conditionally include prevout script hex
            },
            relative_timelock: relative_timelock(core.version, inp.sequence), // Compute BIP68 view
        });
    }

    let mut warnings: Vec<WarningItem> = Vec::new(); // Initialize empty warnings
    if flags.include_warnings { // Only include if enabled
        warnings = core
            .warnings
            .into_iter() // Consume warning codes
            .map(|w| WarningItem { code: w.as_str().to_string() }) // Convert to WarningItem
            .collect(); // Collect into Vec
    }

    let mut vout: Vec<VoutReport> = Vec::with_capacity(core.outputs.len()); // Pre-allocate output reports
    for (n, o) in core.outputs.iter().enumerate() { // Iterate outputs with index
        let spk_hex = if flags.include_script_hex { bytes_to_hex(o.spk) } else { String::new() }; // Conditionally include script hex
        let script_asm = if flags.include_script_asm { disasm_script(o.spk) } else { String::new() }; // Conditionally include asm
        let address = if flags.include_addresses { address_from_spk(network, o.spk)? } else { None }; // Conditionally derive address

        let mut op_return_data_hex: Option<String> = None; // Initialize optional OP_RETURN fields
        let mut op_return_data_utf8: Option<String> = None;
        let mut op_return_protocol: Option<String> = None;

        if flags.include_op_return && o.script_type == ScriptType::OpReturn { // Only parse OP_RETURN if enabled + correct type
            if let Some(data) = parse_op_return_data(o.spk) { // Extract payload bytes
                op_return_data_hex = Some(bytes_to_hex(&data)); // Store hex representation
                if let Ok(s) = std::str::from_utf8(&data) { // Attempt UTF-8 decoding
                    op_return_data_utf8 = Some(s.to_string()); // Store UTF-8 string if valid
                }
                op_return_protocol = Some("unknown".to_string()); // Placeholder protocol detection
            }
        }

        vout.push(VoutReport { // Push output report
            n: n as u32,
            value_sats: o.value,
            script_pubkey_hex: spk_hex,
            script_asm,
            script_type: o.script_type.as_str().to_string(), // Convert enum to string
            address,
            op_return_data_hex,
            op_return_data_utf8,
            op_return_protocol,
        });
    }

    let segwit_savings = if core.segwit { // Only compute if segwit
        let weight_actual = core.weight; // Actual weight
        let weight_if_legacy = core.size_bytes * 4; // Hypothetical legacy weight
        let savings_pct = if weight_if_legacy == 0 { // Avoid division by zero
            0.0
        } else {
            ((weight_if_legacy.saturating_sub(weight_actual)) as f64) * 100.0 / (weight_if_legacy as f64) // Percentage savings
        };
        Some(SegwitSavings {
            witness_bytes: core.witness_bytes,
            non_witness_bytes: core.non_witness_bytes,
            total_bytes: core.size_bytes,
            weight_actual,
            weight_if_legacy,
            savings_pct,
        })
    } else {
        None // No savings for legacy tx
    };

    let fee_rate_sat_vb = if core.vbytes == 0 { // Avoid division by zero
        0.0
    } else {
        core.fee as f64 / core.vbytes as f64 // Compute fee rate
    };

    Ok(TxReport { // Build final JSON report
        ok: true,
        network: network.into(),
        segwit: core.segwit,
        txid,
        wtxid,
        version: core.version,
        locktime: core.locktime,
        locktime_value: core.locktime,
        size_bytes: core.size_bytes,
        weight: core.weight,
        vbytes: core.vbytes,
        fee_sats: core.fee,
        fee_rate_sat_vb,
        total_input_sats: core.total_input,
        total_output_sats: core.total_output,
        rbf_signaling: core.rbf,
        locktime_type: locktime_type(core.locktime),
        vin,
        vout,
        warnings,
        segwit_savings,
    })
}
