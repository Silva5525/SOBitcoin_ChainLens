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

use crate::btc::tx::core::{ScriptType, SpendType}; // Import enums used for classification results
use crate::btc::tx::util::bytes_to_hex; // Import helper to convert byte slices into hex strings

/// Classify an output script (scriptPubKey) into a small set of known templates.
///
/// This is used for per-output labeling and for warnings (unknown script type).
pub(crate) fn script_type(spk: &[u8]) -> ScriptType { // Takes scriptPubKey bytes and returns a ScriptType enum
    if is_p2pkh_spk(spk) { // Check if script matches standard P2PKH template
        return ScriptType::P2PKH; // Return P2PKH classification
    }
    if is_p2sh_spk(spk) { // Check P2SH template
        return ScriptType::P2SH; // Return P2SH
    }
    if is_p2wpkh_spk(spk) { // Check native SegWit P2WPKH template
        return ScriptType::P2WPKH; // Return P2WPKH
    }
    if is_p2wsh_spk(spk) { // Check native SegWit P2WSH template
        return ScriptType::P2WSH; // Return P2WSH
    }
    if is_p2tr_spk(spk) { // Check Taproot (v1 witness program) template
        return ScriptType::P2TR; // Return P2TR
    }
    if !spk.is_empty() && spk[0] == 0x6a { // If first opcode is OP_RETURN (0x6a)
        return ScriptType::OpReturn; // Return OP_RETURN classification
    }
    ScriptType::Unknown // If no known template matched
}

/// Extract data bytes from an OP_RETURN script.
///
/// We read consecutive push-ops after OP_RETURN and concatenate their payloads.
/// If we encounter a non-push opcode or malformed length, we stop / return None.
pub(crate) fn parse_op_return_data(spk: &[u8]) -> Option<Vec<u8>> { // Returns concatenated pushed data if valid OP_RETURN
    if spk.is_empty() || spk[0] != 0x6a { // Must start with OP_RETURN
        return None; // Not an OP_RETURN script
    }

    let mut out: Vec<u8> = Vec::new(); // Buffer for concatenated pushed data
    let mut i: usize = 1; // Start reading after OP_RETURN opcode

    while i < spk.len() { // Loop until end of script
        let op = spk[i]; // Read next opcode byte
        i += 1; // Move cursor forward

        if op == 0x00 { // Some encoders insert OP_0 (push empty)
            continue; // Ignore OP_0 and continue
        }

        let (n, is_push) = match op { // Determine push length depending on opcode
            0x01..=0x4b => (op as usize, true), // Direct push of 1..75 bytes
            0x4c => { // OP_PUSHDATA1
                if i + 1 > spk.len() { // Ensure length byte exists
                    return None; // Malformed
                }
                let n = spk[i] as usize; // Length is next byte
                i += 1; // Advance cursor
                (n, true) // Return length and mark as push
            }
            0x4d => { // OP_PUSHDATA2
                if i + 2 > spk.len() { // Ensure 2 length bytes exist
                    return None;
                }
                let n = u16::from_le_bytes([spk[i], spk[i + 1]]) as usize; // Read 16-bit little-endian length
                i += 2; // Advance cursor
                (n, true)
            }
            0x4e => { // OP_PUSHDATA4
                if i + 4 > spk.len() { // Ensure 4 length bytes exist
                    return None;
                }
                let n = u32::from_le_bytes([spk[i], spk[i + 1], spk[i + 2], spk[i + 3]]) as usize; // Read 32-bit length
                i += 4; // Advance cursor
                (n, true)
            }
            _ => (0, false), // Any other opcode is not a push
        };

        if !is_push { // If opcode is not a push
            break; // Stop parsing further
        }
        if i + n > spk.len() { // Ensure enough bytes remain for push
            return None; // Malformed script
        }

        out.extend_from_slice(&spk[i..i + n]); // Append pushed data to output buffer
        i += n; // Advance cursor past pushed data
    }

    Some(out) // Return concatenated data
}

#[inline]
fn opcode_name(op: u8) -> &'static str { // Map raw opcode byte to its human-readable Bitcoin Script name
    match op { // Match the opcode numeric value
        0x00 => "OP_0", // Push empty vector (also represents number 0)

        0x4c => "OP_PUSHDATA1", // Next 1 byte contains length of pushed data
        0x4d => "OP_PUSHDATA2", // Next 2 bytes (LE) contain length of pushed data
        0x4e => "OP_PUSHDATA4", // Next 4 bytes (LE) contain length of pushed data

        0x4f => "OP_1NEGATE", // Push the number -1 onto the stack
        0x50 => "OP_RESERVED", // Reserved opcode (invalid unless in special contexts)

        0x51 => "OP_1",  // Push number 1
        0x52 => "OP_2",  // Push number 2
        0x53 => "OP_3",  // Push number 3
        0x54 => "OP_4",  // Push number 4
        0x55 => "OP_5",  // Push number 5
        0x56 => "OP_6",  // Push number 6
        0x57 => "OP_7",  // Push number 7
        0x58 => "OP_8",  // Push number 8
        0x59 => "OP_9",  // Push number 9
        0x5a => "OP_10", // Push number 10
        0x5b => "OP_11", // Push number 11
        0x5c => "OP_12", // Push number 12
        0x5d => "OP_13", // Push number 13
        0x5e => "OP_14", // Push number 14
        0x5f => "OP_15", // Push number 15
        0x60 => "OP_16", // Push number 16

        0x61 => "OP_NOP", // No operation (does nothing)

        0x63 => "OP_IF",     // Begin IF block (executes if top stack item is true)
        0x64 => "OP_NOTIF",  // Begin NOTIF block (executes if top stack item is false)
        0x67 => "OP_ELSE",   // Else branch inside IF/NOTIF block
        0x68 => "OP_ENDIF",  // End IF/ELSE block

        0x69 => "OP_VERIFY", // Fail script if top stack item is false
        0x6a => "OP_RETURN", // Immediately make script fail (used for provably unspendable outputs)

        0x6d => "OP_2DROP", // Remove top two stack items
        0x6e => "OP_2DUP",  // Duplicate top two stack items
        0x75 => "OP_DROP",  // Remove top stack item
        0x76 => "OP_DUP",   // Duplicate top stack item

        0x87 => "OP_EQUAL",        // Push true if top two items are equal
        0x88 => "OP_EQUALVERIFY",  // OP_EQUAL + OP_VERIFY

        0xa9 => "OP_HASH160", // Replace top item with HASH160 (RIPEMD160(SHA256(x)))

        0xac => "OP_CHECKSIG",       // Verify ECDSA/Schnorr signature against pubkey
        0xae => "OP_CHECKMULTISIG",  // Verify multiple signatures (legacy multisig)

        0xb1 => "OP_CHECKLOCKTIMEVERIFY",   // Enforce absolute locktime condition (BIP65)
        0xb2 => "OP_CHECKSEQUENCEVERIFY",   // Enforce relative timelock (BIP112)

        0xba => "OP_CHECKSIGADD", // Taproot opcode: add signature result to accumulator (BIP342)

        _ => "OP_UNKNOWN", // Any opcode not explicitly mapped above
    }
}

pub(crate) fn disasm_script(script: &[u8]) -> String { // Convert raw script into human-readable ASM string
    if script.is_empty() { // If script has no bytes
        return String::new(); // Return empty string
    }

    let mut out: Vec<String> = Vec::new(); // Collect individual ASM tokens
    let mut i: usize = 0; // Cursor index

    while i < script.len() { // Loop over script bytes
        let op = script[i]; // Read opcode
        i += 1; // Advance cursor

        if (0x01..=0x4b).contains(&op) { // Direct push 1..75 bytes
            let n = op as usize; // Length equals opcode value
            if i + n > script.len() { // Bounds check
                break; // Stop on malformed script
            }
            out.push(format!("OP_PUSHBYTES_{} {}", n, bytes_to_hex(&script[i..i + n]))); // Add push token with hex data
            i += n; // Advance cursor
            continue; // Continue next loop iteration
        }

        match op { // Handle other pushdata opcodes or normal opcodes
            0x4c => { // OP_PUSHDATA1
                if i + 1 > script.len() { break; }
                let n = script[i] as usize;
                i += 1;
                if i + n > script.len() { break; }
                out.push(format!("OP_PUSHDATA1 {}", bytes_to_hex(&script[i..i + n])));
                i += n;
            }
            0x4d => { // OP_PUSHDATA2
                if i + 2 > script.len() { break; }
                let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                if i + n > script.len() { break; }
                out.push(format!("OP_PUSHDATA2 {}", bytes_to_hex(&script[i..i + n])));
                i += n;
            }
            0x4e => { // OP_PUSHDATA4
                if i + 4 > script.len() { break; }
                let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]]) as usize;
                i += 4;
                if i + n > script.len() { break; }
                out.push(format!("OP_PUSHDATA4 {}", bytes_to_hex(&script[i..i + n])));
                i += n;
            }
            _ => { // Any other opcode
                let name = opcode_name(op); // Get friendly name
                if name == "OP_UNKNOWN" { // If not recognized
                    out.push(format!("OP_UNKNOWN_0x{:02x}", op)); // Include raw opcode value
                } else {
                    out.push(name.to_string()); // Use known opcode name
                }
            }
        }
    }

    out.join(" ") // Join tokens with spaces into final ASM string
}

pub(crate) fn extract_last_push(script: &[u8]) -> Option<&[u8]> { // Return last pushed data element if any
    let mut i = 0usize; // Cursor index
    let mut last: Option<&[u8]> = None; // Track last pushed slice

    while i < script.len() { // Iterate through script
        let op = script[i]; // Read opcode
        i += 1; // Advance cursor

        let n_opt: Option<usize> = match op { // Determine push length
            0x01..=0x4b => Some(op as usize),
            0x4c => {
                if i + 1 > script.len() { return None; }
                let n = script[i] as usize;
                i += 1;
                Some(n)
            }
            0x4d => {
                if i + 2 > script.len() { return None; }
                let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                Some(n)
            }
            0x4e => {
                if i + 4 > script.len() { return None; }
                let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]]) as usize;
                i += 4;
                Some(n)
            }
            0x00 => Some(0), // OP_0 pushes empty
            _ => None, // Non-push opcode
        };

        let Some(n) = n_opt else { continue; }; // Skip non-push opcodes

        if i + n > script.len() { return None; } // Bounds check
        let data = &script[i..i + n]; // Slice pushed data
        i += n; // Advance cursor
        last = Some(data); // Update last pushed data reference
    }

    last // Return last pushed slice (if any)
}

#[inline]
pub(crate) fn is_p2pkh_spk(spk: &[u8]) -> bool { // Check standard P2PKH template
    spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
}

#[inline]
pub(crate) fn is_p2sh_spk(spk: &[u8]) -> bool { // Check standard P2SH template
    spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87
}

#[inline]
pub(crate) fn is_p2wpkh_spk(spk: &[u8]) -> bool { // Check v0 P2WPKH template
    spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14
}

#[inline]
pub(crate) fn is_p2wsh_spk(spk: &[u8]) -> bool { // Check v0 P2WSH template
    spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20
}

#[inline]
pub(crate) fn is_p2tr_spk(spk: &[u8]) -> bool { // Check v1 Taproot template
    spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20
}

pub(crate) fn classify_input_spend(
    prevout_spk: &[u8], // ScriptPubKey of the output being spent
    script_sig: &[u8], // scriptSig of this input
    witness_items: &[&[u8]], // Witness stack items
    include_witness_script_asm: bool, // Whether to disassemble witnessScript
) -> (SpendType, Option<String>) { // Return spend classification + optional witness script ASM
    if is_p2pkh_spk(prevout_spk) { // Legacy P2PKH
        return (SpendType::P2PKH, None);
    }
    if is_p2wpkh_spk(prevout_spk) { // Native SegWit P2WPKH
        return (SpendType::P2WPKH, None);
    }
    if is_p2wsh_spk(prevout_spk) { // Native SegWit P2WSH
        let ws_asm = if include_witness_script_asm { // If ASM requested
            witness_items.last().map(|b| disasm_script(b)) // Disassemble last witness item (witnessScript)
        } else {
            None
        };
        return (SpendType::P2WSH, ws_asm);
    }
    if is_p2tr_spk(prevout_spk) { // Taproot spend
        if witness_items.len() == 1 && witness_items[0].len() == 64 { // Heuristic: single 64-byte Schnorr sig
            return (SpendType::P2TRKeyPath, None);
        }
        if let Some(last) = witness_items.last() { // Possibly script-path
            if !last.is_empty() && (last[0] == 0xc0 || last[0] == 0xc1) { // Control block prefix
                return (SpendType::P2TRScriptPath, None);
            }
        }
        return (SpendType::Unknown, None); // Could not classify
    }
    if is_p2sh_spk(prevout_spk) { // Legacy P2SH
        let Some(rs) = extract_last_push(script_sig) else { // Extract redeemScript from scriptSig
            return (SpendType::Unknown, None);
        };
        if is_p2wpkh_spk(rs) { // Nested P2WPKH
            return (SpendType::P2SHP2WPKH, None);
        }
        if is_p2wsh_spk(rs) { // Nested P2WSH
            let ws_asm = if include_witness_script_asm {
                witness_items.last().map(|b| disasm_script(b))
            } else {
                None
            };
            return (SpendType::P2SHP2WSH, ws_asm);
        }
        return (SpendType::P2SH, None); // Plain P2SH
    }
    (SpendType::Unknown, None) // Default fallback
}
