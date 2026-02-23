// ============================================================================
// src/btc/tx/script.rs
// Script parsing + classification + disassembly helpers
// ============================================================================
//!
//! Script helpers.
//!
//! This module provides *best-effort* parsing and classification of:
//! - scriptPubKey templates (P2PKH/P2SH/P2WPKH/P2WSH/P2TR/OP_RETURN)
//! - input spend type (based on prevout SPK + scriptSig + witness)
//! - script disassembly for UI/debug output
//!
//! Important:
//! - This code does **not** validate signatures or execute scripts.
//! - It uses heuristics (especially for Taproot keypath/scriptpath detection).

use crate::btc::tx::core::{ScriptType, SpendType};
use crate::btc::tx::util::bytes_to_hex;

/// Classify an output script (scriptPubKey) into a small set of known templates.
///
/// This is used for per-output labeling and for warnings (unknown script type).
pub(crate) fn script_type(spk: &[u8]) -> ScriptType {
    if is_p2pkh_spk(spk) {
        return ScriptType::P2PKH;
    }
    if is_p2sh_spk(spk) {
        return ScriptType::P2SH;
    }
    if is_p2wpkh_spk(spk) {
        return ScriptType::P2WPKH;
    }
    if is_p2wsh_spk(spk) {
        return ScriptType::P2WSH;
    }
    if is_p2tr_spk(spk) {
        return ScriptType::P2TR;
    }
    if !spk.is_empty() && spk[0] == 0x6a {
        return ScriptType::OpReturn;
    }
    ScriptType::Unknown
}

/// Extract data bytes from an OP_RETURN script.
///
/// We read consecutive push-ops after OP_RETURN and concatenate their payloads.
/// If we encounter a non-push opcode or malformed length, we stop / return None.
pub(crate) fn parse_op_return_data(spk: &[u8]) -> Option<Vec<u8>> {
    if spk.is_empty() || spk[0] != 0x6a {
        return None;
    }

    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 1;

    while i < spk.len() {
        let op = spk[i];
        i += 1;

        // Some encoders insert OP_0; we simply ignore it.
        if op == 0x00 {
            continue;
        }

        let (n, is_push) = match op {
            0x01..=0x4b => (op as usize, true),
            0x4c => {
                if i + 1 > spk.len() {
                    return None;
                }
                let n = spk[i] as usize;
                i += 1;
                (n, true)
            }
            0x4d => {
                if i + 2 > spk.len() {
                    return None;
                }
                let n = u16::from_le_bytes([spk[i], spk[i + 1]]) as usize;
                i += 2;
                (n, true)
            }
            0x4e => {
                if i + 4 > spk.len() {
                    return None;
                }
                let n = u32::from_le_bytes([spk[i], spk[i + 1], spk[i + 2], spk[i + 3]]) as usize;
                i += 4;
                (n, true)
            }
            _ => (0, false),
        };

        // Stop at first non-push opcode. OP_RETURN scripts are "provably unspendable" anyway.
        if !is_push {
            break;
        }
        if i + n > spk.len() {
            return None;
        }

        out.extend_from_slice(&spk[i..i + n]);
        i += n;
    }

    Some(out)
}

/// Map an opcode byte to a friendly name.
///
/// This list is intentionally incomplete; unknown opcodes are reported as `OP_UNKNOWN_0xNN`.
#[inline]
fn opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "OP_0",
        0x4c => "OP_PUSHDATA1",
        0x4d => "OP_PUSHDATA2",
        0x4e => "OP_PUSHDATA4",
        0x4f => "OP_1NEGATE",
        0x50 => "OP_RESERVED",
        0x51 => "OP_1",
        0x52 => "OP_2",
        0x53 => "OP_3",
        0x54 => "OP_4",
        0x55 => "OP_5",
        0x56 => "OP_6",
        0x57 => "OP_7",
        0x58 => "OP_8",
        0x59 => "OP_9",
        0x5a => "OP_10",
        0x5b => "OP_11",
        0x5c => "OP_12",
        0x5d => "OP_13",
        0x5e => "OP_14",
        0x5f => "OP_15",
        0x60 => "OP_16",
        0x61 => "OP_NOP",
        0x63 => "OP_IF",
        0x64 => "OP_NOTIF",
        0x67 => "OP_ELSE",
        0x68 => "OP_ENDIF",
        0x69 => "OP_VERIFY",
        0x6a => "OP_RETURN",
        0x6d => "OP_2DROP",
        0x6e => "OP_2DUP",
        0x75 => "OP_DROP",
        0x76 => "OP_DUP",
        0x87 => "OP_EQUAL",
        0x88 => "OP_EQUALVERIFY",
        0xa9 => "OP_HASH160",
        0xac => "OP_CHECKSIG",
        0xae => "OP_CHECKMULTISIG",
        0xb1 => "OP_CHECKLOCKTIMEVERIFY",
        0xb2 => "OP_CHECKSEQUENCEVERIFY",
        0xba => "OP_CHECKSIGADD",
        _ => "OP_UNKNOWN",
    }
}

/// Best-effort disassembler for scripts.
///
/// The output is meant for UI/debug only. If the script is malformed (bad push lengths),
/// this function stops early instead of panicking.
pub(crate) fn disasm_script(script: &[u8]) -> String {
    if script.is_empty() {
        return String::new();
    }

    let mut out: Vec<String> = Vec::new();
    let mut i: usize = 0;

    while i < script.len() {
        let op = script[i];
        i += 1;

        // Small direct push
        if (0x01..=0x4b).contains(&op) {
            let n = op as usize;
            if i + n > script.len() {
                break;
            }
            out.push(format!("OP_PUSHBYTES_{} {}", n, bytes_to_hex(&script[i..i + n])));
            i += n;
            continue;
        }

        match op {
            0x4c => {
                // OP_PUSHDATA1
                if i + 1 > script.len() {
                    break;
                }
                let n = script[i] as usize;
                i += 1;
                if i + n > script.len() {
                    break;
                }
                out.push(format!("OP_PUSHDATA1 {}", bytes_to_hex(&script[i..i + n])));
                i += n;
            }
            0x4d => {
                // OP_PUSHDATA2
                if i + 2 > script.len() {
                    break;
                }
                let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                if i + n > script.len() {
                    break;
                }
                out.push(format!("OP_PUSHDATA2 {}", bytes_to_hex(&script[i..i + n])));
                i += n;
            }
            0x4e => {
                // OP_PUSHDATA4
                if i + 4 > script.len() {
                    break;
                }
                let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]]) as usize;
                i += 4;
                if i + n > script.len() {
                    break;
                }
                out.push(format!("OP_PUSHDATA4 {}", bytes_to_hex(&script[i..i + n])));
                i += n;
            }
            _ => {
                let name = opcode_name(op);
                if name == "OP_UNKNOWN" {
                    out.push(format!("OP_UNKNOWN_0x{:02x}", op));
                } else {
                    out.push(name.to_string());
                }
            }
        }
    }

    out.join(" ")
}

/// Return the last pushed data item from a script, if any.
///
/// This is commonly used to recover the redeemScript in P2SH spends
/// (the redeemScript is typically the last pushed item in scriptSig).
pub(crate) fn extract_last_push(script: &[u8]) -> Option<&[u8]> {
    let mut i = 0usize;
    let mut last: Option<&[u8]> = None;

    while i < script.len() {
        let op = script[i];
        i += 1;

        let n_opt: Option<usize> = match op {
            0x01..=0x4b => Some(op as usize),
            0x4c => {
                if i + 1 > script.len() {
                    return None;
                }
                let n = script[i] as usize;
                i += 1;
                Some(n)
            }
            0x4d => {
                if i + 2 > script.len() {
                    return None;
                }
                let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                Some(n)
            }
            0x4e => {
                if i + 4 > script.len() {
                    return None;
                }
                let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]]) as usize;
                i += 4;
                Some(n)
            }
            0x00 => Some(0),
            _ => None,
        };

        let Some(n) = n_opt else {
            continue;
        };

        if i + n > script.len() {
            return None;
        }
        let data = &script[i..i + n];
        i += n;
        last = Some(data);
    }

    last
}

/// Match a standard P2PKH scriptPubKey template.
#[inline]
pub(crate) fn is_p2pkh_spk(spk: &[u8]) -> bool {
    spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
}

/// Match a standard P2SH scriptPubKey template.
#[inline]
pub(crate) fn is_p2sh_spk(spk: &[u8]) -> bool {
    spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87
}

/// Match a standard P2WPKH v0 witness program template.
#[inline]
pub(crate) fn is_p2wpkh_spk(spk: &[u8]) -> bool {
    spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14
}

/// Match a standard P2WSH v0 witness program template.
#[inline]
pub(crate) fn is_p2wsh_spk(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20
}

/// Match a standard P2TR v1 witness program template.
#[inline]
pub(crate) fn is_p2tr_spk(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20
}

/// Infer the spend type for an input.
///
/// Inputs:
/// - `prevout_spk`: the previous output's scriptPubKey (tells us what is being spent)
/// - `script_sig`: the input scriptSig (may contain redeemScript for P2SH)
/// - `witness_items`: witness stack items (SegWit/taproot)
///
/// Output:
/// - `SpendType`: coarse classification used in the JSON report
/// - optional `witness_script_asm`: if requested and available, disassembled witnessScript
///
/// Notes:
/// - For P2SH nested SegWit, we inspect the *redeemScript* (last push in scriptSig).
/// - Taproot keypath/scriptpath detection is heuristic:
///   - keypath is often a single 64-byte schnorr signature
///   - scriptpath usually includes a control block (starts with 0xc0 or 0xc1)
pub(crate) fn classify_input_spend(
    prevout_spk: &[u8],
    script_sig: &[u8],
    witness_items: &[&[u8]],
    include_witness_script_asm: bool,
) -> (SpendType, Option<String>) {
    if is_p2pkh_spk(prevout_spk) {
        return (SpendType::P2PKH, None);
    }
    if is_p2wpkh_spk(prevout_spk) {
        return (SpendType::P2WPKH, None);
    }
    if is_p2wsh_spk(prevout_spk) {
        let ws_asm = if include_witness_script_asm {
            witness_items.last().map(|b| disasm_script(b))
        } else {
            None
        };
        return (SpendType::P2WSH, ws_asm);
    }
    if is_p2tr_spk(prevout_spk) {
        // Heuristic: single 64-byte item is a common keypath schnorr signature.
        if witness_items.len() == 1 && witness_items[0].len() == 64 {
            return (SpendType::P2TRKeyPath, None);
        }
        // Heuristic: last item might be a control block for script path.
        if let Some(last) = witness_items.last() {
            if !last.is_empty() && (last[0] == 0xc0 || last[0] == 0xc1) {
                return (SpendType::P2TRScriptPath, None);
            }
        }
        return (SpendType::Unknown, None);
    }
    if is_p2sh_spk(prevout_spk) {
        // P2SH spends reveal redeemScript in scriptSig.
        let Some(rs) = extract_last_push(script_sig) else {
            return (SpendType::Unknown, None);
        };
        // Nested SegWit: redeemScript itself is a witness program.
        if is_p2wpkh_spk(rs) {
            return (SpendType::P2SHP2WPKH, None);
        }
        if is_p2wsh_spk(rs) {
            let ws_asm = if include_witness_script_asm {
                witness_items.last().map(|b| disasm_script(b))
            } else {
                None
            };
            return (SpendType::P2SHP2WSH, ws_asm);
        }
        return (SpendType::P2SH, None);
    }
    (SpendType::Unknown, None)
}
