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

use serde::Serialize;


use crate::btc::tx::core::{CoreTx, ScriptType};
use crate::btc::tx::script::{disasm_script, parse_op_return_data};
use crate::btc::tx::util::{address_from_spk, bytes_to_hex, hash_to_display_hex};
use crate::btc::tx::TxComputeFlags;

/// Fixture input describing a previous output (value + scriptPubKey).
///
/// The fixture uses display txid hex (big-endian) and hex scriptPubKey.
#[derive(Debug, Clone)]
pub struct Prevout {
    pub txid_hex: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
}

/// Warning entry emitted by the analyzer.
///
/// `code` is a stable string identifier.
#[derive(Debug, Serialize)]
pub struct WarningItem {
    pub code: String,
}

/// Approximate SegWit fee savings metrics.
///
/// We compare actual tx weight to an "as-if legacy" weight (size*4).
#[derive(Debug, Serialize)]
pub struct SegwitSavings {
    pub witness_bytes: usize,
    pub non_witness_bytes: usize,
    pub total_bytes: usize,
    pub weight_actual: usize,
    pub weight_if_legacy: usize,
    pub savings_pct: f64,
}

/// Prevout details embedded into each vin report.
#[derive(Debug, Serialize)]
pub struct PrevoutInfo {
    pub value_sats: u64,
    pub script_pubkey_hex: String,
}

/// Relative timelock info (BIP68) derived from sequence.
///
/// This is a simplified representation used for reporting.
#[derive(Debug, Serialize)]
pub struct RelativeTimelock {
    pub enabled: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
}

/// Report entry for a single transaction input.
#[derive(Debug, Serialize)]
pub struct VinReport {
    pub txid: String,
    pub vout: u32,
    pub sequence: u32,
    pub script_sig_hex: String,
    pub script_asm: String,
    pub witness: Vec<String>,
    pub witness_script_asm: Option<String>,
    pub script_type: String,
    pub address: Option<String>,
    pub prevout: PrevoutInfo,
    pub relative_timelock: RelativeTimelock,
}

/// Report entry for a single transaction output.
#[derive(Debug, Serialize)]
pub struct VoutReport {
    pub n: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub script_asm: String,
    pub script_type: String,
    pub address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_data_hex: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_data_utf8: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_protocol: Option<String>,
}

/// Top-level transaction analysis report.
///
/// This is the main JSON object returned by the CLI/Web endpoints.
#[derive(Debug, Serialize)]
pub struct TxReport {
    pub ok: bool,
    pub network: String,
    pub segwit: bool,
    pub txid: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub wtxid: Option<String>,

    pub version: u32,
    pub locktime: u32,
    pub locktime_value: u32,
    pub size_bytes: usize,
    pub weight: usize,
    pub vbytes: usize,
    pub fee_sats: i64,
    pub fee_rate_sat_vb: f64,
    pub total_input_sats: u64,
    pub total_output_sats: u64,
    pub rbf_signaling: bool,
    pub locktime_type: String,

    pub vin: Vec<VinReport>,
    pub vout: Vec<VoutReport>,
    pub warnings: Vec<WarningItem>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub segwit_savings: Option<SegwitSavings>,
}

/// Classify locktime value into a human-friendly type.
///
/// Bitcoin convention: values < 500_000_000 are interpreted as block height,
/// otherwise as UNIX timestamp.
#[inline]
fn locktime_type(locktime: u32) -> String {
    if locktime == 0 {
        return "none".into();
    }
    if locktime < 500_000_000 {
        "block_height".into()
    } else {
        "unix_timestamp".into()
    }
}

/// Compute a simplified BIP68 relative timelock representation.
///
/// Enabled if:
/// - tx version >= 2
/// - sequence disable flag (bit 31) is NOT set
///
/// If bit 22 is set, the value is time-based (units of 512 seconds), else block-based.
#[inline]
fn relative_timelock(version: u32, sequence: u32) -> RelativeTimelock {
    // BIP68: only if version >= 2 and disable flag is not set.
    if version < 2 {
        return RelativeTimelock { enabled: false, r#type: None, value: None };
    }
    if (sequence & (1u32 << 31)) != 0 {
        return RelativeTimelock { enabled: false, r#type: None, value: None };
    }

    let v = (sequence & 0x0000_ffff) as u64;
    if (sequence & (1u32 << 22)) != 0 {
        // time-based, 512-second granularity
        RelativeTimelock { enabled: true, r#type: Some("time".into()), value: Some(v * 512) }
    } else {
        RelativeTimelock { enabled: true, r#type: Some("blocks".into()), value: Some(v) }
    }
}

/// Build the public `TxReport` JSON shape from a parsed `CoreTx`.
///
/// `flags` allow gating expensive/verbose fields (script asm, witness hex, addresses, OP_RETURN).
pub(crate) fn build_tx_report(network: &str, core: CoreTx, flags: TxComputeFlags) -> Result<TxReport, String> {
    let txid = hash_to_display_hex(core.txid_le);
    let wtxid = core.wtxid_le.map(hash_to_display_hex);

    let mut vin: Vec<VinReport> = Vec::with_capacity(core.inputs.len());
    for inp in &core.inputs {
        let prev_txid = hash_to_display_hex(inp.prev_txid_le);

        let script_sig_hex = if flags.include_script_hex {
            bytes_to_hex(inp.script_sig)
        } else {
            String::new()
        };
        let script_asm = if flags.include_script_asm {
            disasm_script(inp.script_sig)
        } else {
            String::new()
        };

        let witness: Vec<String> = if flags.include_witness_hex {
            inp.witness.iter().map(|w| bytes_to_hex(w)).collect()
        } else {
            Vec::new()
        };

        let witness_script_asm = if flags.include_script_asm {
            inp.witness_script_asm.clone()
        } else {
            None
        };

        let address = if flags.include_addresses {
            address_from_spk(network, inp.prev_spk)?
        } else {
            None
        };

        vin.push(VinReport {
            txid: prev_txid,
            vout: inp.vout,
            sequence: inp.sequence,
            script_sig_hex,
            script_asm,
            witness,
            witness_script_asm,
            script_type: inp.spend_type.as_str().to_string(),
            address,
            prevout: PrevoutInfo {
                value_sats: inp.prev_value,
                script_pubkey_hex: if flags.include_script_hex { bytes_to_hex(inp.prev_spk) } else { String::new() },
            },
            relative_timelock: relative_timelock(core.version, inp.sequence),
        });
    }

    let mut warnings: Vec<WarningItem> = Vec::new();
    if flags.include_warnings {
        warnings = core
            .warnings
            .into_iter()
            .map(|w| WarningItem { code: w.as_str().to_string() })
            .collect();
    }

    let mut vout: Vec<VoutReport> = Vec::with_capacity(core.outputs.len());
    for (n, o) in core.outputs.iter().enumerate() {
        let spk_hex = if flags.include_script_hex { bytes_to_hex(o.spk) } else { String::new() };
        let script_asm = if flags.include_script_asm { disasm_script(o.spk) } else { String::new() };
        let address = if flags.include_addresses { address_from_spk(network, o.spk)? } else { None };

        let mut op_return_data_hex: Option<String> = None;
        let mut op_return_data_utf8: Option<String> = None;
        let mut op_return_protocol: Option<String> = None;

        if flags.include_op_return && o.script_type == ScriptType::OpReturn {
            if let Some(data) = parse_op_return_data(o.spk) {
                op_return_data_hex = Some(bytes_to_hex(&data));
                if let Ok(s) = std::str::from_utf8(&data) {
                    op_return_data_utf8 = Some(s.to_string());
                }
                // protocol detection is optional / best-effort
                op_return_protocol = Some("unknown".to_string());
            }
        }

        vout.push(VoutReport {
            n: n as u32,
            value_sats: o.value,
            script_pubkey_hex: spk_hex,
            script_asm,
            script_type: o.script_type.as_str().to_string(),
            address,
            op_return_data_hex,
            op_return_data_utf8,
            op_return_protocol,
        });
    }

    let segwit_savings = if core.segwit {
        let weight_actual = core.weight;
        let weight_if_legacy = core.size_bytes * 4;
        let savings_pct = if weight_if_legacy == 0 {
            0.0
        } else {
            ((weight_if_legacy.saturating_sub(weight_actual)) as f64) * 100.0 / (weight_if_legacy as f64)
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
        None
    };

    let fee_rate_sat_vb = if core.vbytes == 0 {
        0.0
    } else {
        core.fee as f64 / core.vbytes as f64
    };

    Ok(TxReport {
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

