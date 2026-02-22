// src/btc/tx.rs

use ahash::AHashMap;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
pub struct Prevout {
    pub txid_hex: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
}

// README schema expects warnings as an array of objects that only contain { code }
#[derive(Debug, Serialize)]
pub struct WarningItem {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct SegwitSavings {
    pub witness_bytes: usize,
    pub non_witness_bytes: usize,
    pub total_bytes: usize,
    pub weight_actual: usize,
    pub weight_if_legacy: usize,
    pub savings_pct: f64,
}

#[derive(Debug, Serialize)]
pub struct PrevoutInfo {
    pub value_sats: u64,
    pub script_pubkey_hex: String,
}

#[derive(Debug, Serialize)]
pub struct RelativeTimelock {
    pub enabled: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>, // "blocks" | "time"

    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>, // blocks OR seconds
}

#[derive(Debug, Serialize)]
pub struct VinReport {
    pub txid: String,
    pub vout: u32,
    pub sequence: u32,
    pub script_sig_hex: String,
    pub script_asm: String,
    pub witness: Vec<String>,
    /// Only present for p2wsh and p2sh-p2wsh spends (disassembly of the witnessScript).
    pub witness_script_asm: Option<String>,
    pub script_type: String,
    pub address: Option<String>,
    pub prevout: PrevoutInfo,
    pub relative_timelock: RelativeTimelock,
}

#[derive(Debug, Serialize)]
pub struct VoutReport {
    pub n: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub script_asm: String,
    pub script_type: String,
    pub address: Option<String>,

    pub op_return_data_hex: Option<String>,
    pub op_return_data_utf8: Option<String>,
    pub op_return_protocol: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TxReport {
    pub ok: bool,
    pub network: String,
    pub segwit: bool,
    pub txid: String,
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
    pub segwit_savings: Option<SegwitSavings>,
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }

    fn backtrack_1(&mut self) -> Result<(), String> {
        if self.i == 0 {
            return Err("cursor underflow".into());
        }
        self.i -= 1;
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.i + n > self.b.len() {
            return Err("unexpected EOF".into());
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }

    fn take_u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn take_u32_le(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn take_u64_le(&mut self) -> Result<u64, String> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.i)
    }
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex).map_err(|_| "invalid hex".to_string())
}

fn bytes_to_hex(b: &[u8]) -> String {
    hex::encode(b)
}

fn dsha256(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

fn hash_to_display_hex(hash_le: [u8; 32]) -> String {
    let mut be = hash_le;
    be.reverse();
    bytes_to_hex(&be)
}

/// Streaming double-SHA256 writer (lets us compute txid without allocating a "stripped" buffer).
struct Dsha256Writer {
    h: Sha256,
    len: usize,
}

impl Dsha256Writer {
    #[inline]
    fn new() -> Self {
        Self {
            h: Sha256::new(),
            len: 0,
        }
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.h.update(bytes);
        self.len += bytes.len();
    }

    #[inline]
    fn finish(self) -> [u8; 32] {
        let h1 = self.h.finalize();
        let h2 = Sha256::digest(h1);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h2);
        out
    }
}

#[inline]
fn write_varint_hasher(out: &mut Dsha256Writer, n: u64) {
    match n {
        0x00..=0xfc => out.write(&[n as u8]),
        0xfd..=0xffff => {
            let b0 = 0xfdu8;
            let le = (n as u16).to_le_bytes();
            out.write(&[b0]);
            out.write(&le);
        }
        0x1_0000..=0xffff_ffff => {
            let b0 = 0xfeu8;
            let le = (n as u32).to_le_bytes();
            out.write(&[b0]);
            out.write(&le);
        }
        _ => {
            let b0 = 0xffu8;
            let le = n.to_le_bytes();
            out.write(&[b0]);
            out.write(&le);
        }
    }
}

fn read_varint(c: &mut Cursor) -> Result<u64, String> {
    let n = c.take_u8()? as u64;
    match n {
        0x00..=0xfc => Ok(n),
        0xfd => {
            let s = c.take(2)?;
            Ok(u16::from_le_bytes([s[0], s[1]]) as u64)
        }
        0xfe => Ok(c.take_u32_le()? as u64),
        0xff => Ok(c.take_u64_le()?),
        _ => Err("invalid varint prefix".into()),
    }
}

fn script_type(spk: &[u8]) -> String {
    if spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
    {
        return "p2pkh".into();
    }
    if spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87 {
        return "p2sh".into();
    }
    if spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14 {
        return "p2wpkh".into();
    }
    if spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20 {
        return "p2wsh".into();
    }
    if spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20 {
        return "p2tr".into();
    }
    if !spk.is_empty() && spk[0] == 0x6a {
        return "op_return".into();
    }
    "unknown".into()
}

fn parse_op_return_data(spk: &[u8]) -> Option<Vec<u8>> {
    // scriptPubKey for OP_RETURN outputs is typically:
    // OP_RETURN <pushdata...> [<pushdata...> ...]
    // Requirement: concatenate *all* data pushes after OP_RETURN, in order.
    if spk.is_empty() || spk[0] != 0x6a {
        return None;
    }

    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 1; // after OP_RETURN

    while i < spk.len() {
        let op = spk[i];
        i += 1;

        // OP_0 pushes an empty vector.
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

        // Stop at first non-push opcode (requirement only concerns pushes).
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

#[inline]
fn opcode_name(op: u8) -> String {
    // Bitcoin Core Script opcode names.
    // Unknown / undefined opcodes must render as OP_UNKNOWN_0xNN.
    let s: Option<&'static str> = match op {
        0x00 => Some("OP_0"),
        0x4c => Some("OP_PUSHDATA1"),
        0x4d => Some("OP_PUSHDATA2"),
        0x4e => Some("OP_PUSHDATA4"),
        0x4f => Some("OP_1NEGATE"),
        0x50 => Some("OP_RESERVED"),
        0x51 => Some("OP_1"),
        0x52 => Some("OP_2"),
        0x53 => Some("OP_3"),
        0x54 => Some("OP_4"),
        0x55 => Some("OP_5"),
        0x56 => Some("OP_6"),
        0x57 => Some("OP_7"),
        0x58 => Some("OP_8"),
        0x59 => Some("OP_9"),
        0x5a => Some("OP_10"),
        0x5b => Some("OP_11"),
        0x5c => Some("OP_12"),
        0x5d => Some("OP_13"),
        0x5e => Some("OP_14"),
        0x5f => Some("OP_15"),
        0x60 => Some("OP_16"),
        0x61 => Some("OP_NOP"),
        0x62 => Some("OP_VER"),
        0x63 => Some("OP_IF"),
        0x64 => Some("OP_NOTIF"),
        0x65 => Some("OP_VERIF"),
        0x66 => Some("OP_VERNOTIF"),
        0x67 => Some("OP_ELSE"),
        0x68 => Some("OP_ENDIF"),
        0x69 => Some("OP_VERIFY"),
        0x6a => Some("OP_RETURN"),
        0x6b => Some("OP_TOALTSTACK"),
        0x6c => Some("OP_FROMALTSTACK"),
        0x6d => Some("OP_2DROP"),
        0x6e => Some("OP_2DUP"),
        0x6f => Some("OP_3DUP"),
        0x70 => Some("OP_2OVER"),
        0x71 => Some("OP_2ROT"),
        0x72 => Some("OP_2SWAP"),
        0x73 => Some("OP_IFDUP"),
        0x74 => Some("OP_DEPTH"),
        0x75 => Some("OP_DROP"),
        0x76 => Some("OP_DUP"),
        0x77 => Some("OP_NIP"),
        0x78 => Some("OP_OVER"),
        0x79 => Some("OP_PICK"),
        0x7a => Some("OP_ROLL"),
        0x7b => Some("OP_ROT"),
        0x7c => Some("OP_SWAP"),
        0x7d => Some("OP_TUCK"),
        0x7e => Some("OP_CAT"),
        0x7f => Some("OP_SUBSTR"),
        0x80 => Some("OP_LEFT"),
        0x81 => Some("OP_RIGHT"),
        0x82 => Some("OP_SIZE"),
        0x83 => Some("OP_INVERT"),
        0x84 => Some("OP_AND"),
        0x85 => Some("OP_OR"),
        0x86 => Some("OP_XOR"),
        0x87 => Some("OP_EQUAL"),
        0x88 => Some("OP_EQUALVERIFY"),
        0x89 => Some("OP_RESERVED1"),
        0x8a => Some("OP_RESERVED2"),
        0x8b => Some("OP_1ADD"),
        0x8c => Some("OP_1SUB"),
        0x8d => Some("OP_2MUL"),
        0x8e => Some("OP_2DIV"),
        0x8f => Some("OP_NEGATE"),
        0x90 => Some("OP_ABS"),
        0x91 => Some("OP_NOT"),
        0x92 => Some("OP_0NOTEQUAL"),
        0x93 => Some("OP_ADD"),
        0x94 => Some("OP_SUB"),
        0x95 => Some("OP_MUL"),
        0x96 => Some("OP_DIV"),
        0x97 => Some("OP_MOD"),
        0x98 => Some("OP_LSHIFT"),
        0x99 => Some("OP_RSHIFT"),
        0x9a => Some("OP_BOOLAND"),
        0x9b => Some("OP_BOOLOR"),
        0x9c => Some("OP_NUMEQUAL"),
        0x9d => Some("OP_NUMEQUALVERIFY"),
        0x9e => Some("OP_NUMNOTEQUAL"),
        0x9f => Some("OP_LESSTHAN"),
        0xa0 => Some("OP_GREATERTHAN"),
        0xa1 => Some("OP_LESSTHANOREQUAL"),
        0xa2 => Some("OP_GREATERTHANOREQUAL"),
        0xa3 => Some("OP_MIN"),
        0xa4 => Some("OP_MAX"),
        0xa5 => Some("OP_WITHIN"),
        0xa6 => Some("OP_RIPEMD160"),
        0xa7 => Some("OP_SHA1"),
        0xa8 => Some("OP_SHA256"),
        0xa9 => Some("OP_HASH160"),
        0xaa => Some("OP_HASH256"),
        0xab => Some("OP_CODESEPARATOR"),
        0xac => Some("OP_CHECKSIG"),
        0xad => Some("OP_CHECKSIGVERIFY"),
        0xae => Some("OP_CHECKMULTISIG"),
        0xaf => Some("OP_CHECKMULTISIGVERIFY"),
        0xb0 => Some("OP_NOP1"),
        0xb1 => Some("OP_CHECKLOCKTIMEVERIFY"),
        0xb2 => Some("OP_CHECKSEQUENCEVERIFY"),
        0xb3 => Some("OP_NOP4"),
        0xb4 => Some("OP_NOP5"),
        0xb5 => Some("OP_NOP6"),
        0xb6 => Some("OP_NOP7"),
        0xb7 => Some("OP_NOP8"),
        0xb8 => Some("OP_NOP9"),
        0xb9 => Some("OP_NOP10"),
        0xba => Some("OP_CHECKSIGADD"),
        0xfd => Some("OP_PUBKEYHASH"),
        0xfe => Some("OP_PUBKEY"),
        0xff => Some("OP_INVALIDOPCODE"),
        _ => None,
    };

    if let Some(name) = s {
        name.to_string()
    } else {
        format!("OP_UNKNOWN_0x{:02x}", op)
    }
}

fn disasm_script(script: &[u8]) -> String {
    if script.is_empty() {
        return String::new();
    }

    let mut out: Vec<String> = Vec::new();
    let mut i: usize = 0;

    while i < script.len() {
        let op = script[i];
        i += 1;

        // Direct push
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
            0x00 => out.push("OP_0".to_string()),
            0x4c => {
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
            _ => out.push(opcode_name(op)),
        }
    }

    out.join(" ")
}

fn extract_last_push(script: &[u8]) -> Option<&[u8]> {
    // Returns the data bytes of the last push in a script (used for P2SH redeemScript detection).
    // Only considers canonical push opcodes (direct pushes and PUSHDATA1/2/4).
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

#[inline]
fn is_p2pkh_spk(spk: &[u8]) -> bool {
    spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
}

#[inline]
fn is_p2sh_spk(spk: &[u8]) -> bool {
    spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87
}

#[inline]
fn is_p2wpkh_spk(spk: &[u8]) -> bool {
    spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14
}

#[inline]
fn is_p2wsh_spk(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20
}

#[inline]
fn is_p2tr_spk(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20
}

fn classify_input_spend(
    prevout_spk: &[u8],
    script_sig: &[u8],
    witness_items: &[Vec<u8>],
) -> (String, Option<String>) {
    // Returns (script_type, witness_script_asm).
    // witness_script_asm is only set for p2wsh and p2sh-p2wsh per README.

    if is_p2pkh_spk(prevout_spk) {
        return ("p2pkh".to_string(), None);
    }
    if is_p2wpkh_spk(prevout_spk) {
        return ("p2wpkh".to_string(), None);
    }
    if is_p2wsh_spk(prevout_spk) {
        let ws_asm = witness_items.last().map(|b| disasm_script(b));
        return ("p2wsh".to_string(), ws_asm);
    }
    if is_p2tr_spk(prevout_spk) {
        if witness_items.len() == 1 && witness_items[0].len() == 64 {
            return ("p2tr_keypath".to_string(), None);
        }
        if let Some(last) = witness_items.last() {
            if !last.is_empty() && (last[0] == 0xc0 || last[0] == 0xc1) {
                return ("p2tr_scriptpath".to_string(), None);
            }
        }
        return ("unknown".to_string(), None);
    }
    if is_p2sh_spk(prevout_spk) {
        let Some(rs) = extract_last_push(script_sig) else {
            return ("unknown".to_string(), None);
        };
        if is_p2wpkh_spk(rs) {
            return ("p2sh-p2wpkh".to_string(), None);
        }
        if is_p2wsh_spk(rs) {
            let ws_asm = witness_items.last().map(|b| disasm_script(b));
            return ("p2sh-p2wsh".to_string(), ws_asm);
        }
        return ("unknown".to_string(), None);
    }

    ("unknown".to_string(), None)
}

#[inline]
fn locktime_type(locktime: u32) -> String {
    if locktime == 0 {
        return "none".into();
    }
    // Consensus convention: < 500_000_000 => block height, else unix timestamp
    if locktime < 500_000_000 {
        "block_height".into()
    } else {
        "unix_timestamp".into()
    }
}

#[inline]
fn relative_timelock(version: u32, sequence: u32) -> RelativeTimelock {
    // BIP68 only applies to tx version >= 2
    if version < 2 {
        return RelativeTimelock {
            enabled: false,
            r#type: None,
            value: None,
        };
    }

    // Disable flag (bit 31) => disabled
    if (sequence & (1u32 << 31)) != 0 {
        return RelativeTimelock {
            enabled: false,
            r#type: None,
            value: None,
        };
    }

    // Low 16 bits are the value
    let v = (sequence & 0x0000_ffff) as u64;

    // Type flag (bit 22): 0 = blocks, 1 = time (512-second units)
    if (sequence & (1u32 << 22)) != 0 {
        RelativeTimelock {
            enabled: true,
            r#type: Some("time".into()),
            value: Some(v * 512),
        }
    } else {
        RelativeTimelock {
            enabled: true,
            r#type: Some("blocks".into()),
            value: Some(v),
        }
    }
}


#[derive(Clone, Copy, Eq, PartialEq)]
struct PrevoutKey {
    // txid in little-endian bytes (matches tx serialization)
    txid_le: [u8; 32],
    vout: u32,
}

impl Hash for PrevoutKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.txid_le);
        state.write_u32(self.vout);
    }
}

/// Fast path for block-mode: analyze a transaction from raw bytes and an *ordered* prevout list.
///
/// `prevouts_ordered` must be in the same order as the transaction inputs (vin order).
/// Each entry is `(value_sats, script_pubkey_bytes)`.
///
/// This avoids hex decoding/encoding and avoids building a prevout HashMap.
pub fn analyze_tx_from_bytes_ordered(
    network: &str,
    raw: &[u8],
    prevouts_ordered: &[(u64, Vec<u8>)],
) -> Result<TxReport, String> {
    #[inline]
    fn txid_le_slice_to_display_hex(txid_le: &[u8]) -> String {
        let mut be = [0u8; 32];
        be.copy_from_slice(txid_le);
        be.reverse();
        hex::encode(be)
    }

    let size_bytes = raw.len();
    let mut c = Cursor::new(raw);

    // --- Header / segwit detection ---
    let version = c.take_u32_le()?;

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

    // For legacy txs, txid is just dSHA256(raw) and wtxid must be null.
    // For segwit txs, wtxid is dSHA256(raw) and txid is dSHA256(stripped).
    let (wtxid_full, mut txid_hasher) = if segwit {
        (Some(hash_to_display_hex(dsha256(raw))), Some(Dsha256Writer::new()))
    } else {
        (None, None)
    };

    if let Some(h) = txid_hasher.as_mut() {
        h.write(&version.to_le_bytes());
        // marker+flag are NOT included in txid serialization
    }

    // --- VIN ---
    let vin_count_u64 = read_varint(&mut c)?;
    let vin_count = vin_count_u64 as usize;
    if let Some(h) = txid_hasher.as_mut() {
        write_varint_hasher(h, vin_count_u64);
    }

    let mut vin_outpoints: Vec<(String, u32)> = Vec::with_capacity(vin_count);
    let mut vin_script_sig_hex: Vec<String> = Vec::with_capacity(vin_count);
    let mut vin_script_sig_asm: Vec<String> = Vec::with_capacity(vin_count);
    let mut vin_script_sig_bytes: Vec<Vec<u8>> = Vec::with_capacity(vin_count);
    let mut vin_sequences: Vec<u32> = Vec::with_capacity(vin_count);

    let mut rbf_signaling = false;
    let mut coinbase = false;

    for _ in 0..vin_count {
        let prev_txid_le_bytes = c.take(32)?;
        let prev_vout = c.take_u32_le()?;

        if !coinbase
            && vin_count == 1
            && prev_vout == 0xffff_ffff
            && prev_txid_le_bytes.iter().all(|&b| b == 0)
        {
            coinbase = true;
        }

        if let Some(h) = txid_hasher.as_mut() {
            // TxID serialization uses LE txid.
            h.write(prev_txid_le_bytes);
            h.write(&prev_vout.to_le_bytes());
        }

        // Human display uses BE.
        let prev_txid_hex = txid_le_slice_to_display_hex(prev_txid_le_bytes);
        vin_outpoints.push((prev_txid_hex, prev_vout));

        let script_len_u64 = read_varint(&mut c)?;
        let script_len = script_len_u64 as usize;
        if let Some(h) = txid_hasher.as_mut() {
            write_varint_hasher(h, script_len_u64);
        }

        let script_sig = c.take(script_len)?;
        if let Some(h) = txid_hasher.as_mut() {
            h.write(script_sig);
        }
        vin_script_sig_hex.push(bytes_to_hex(script_sig));
        vin_script_sig_asm.push(disasm_script(script_sig));
        vin_script_sig_bytes.push(script_sig.to_vec());

        let sequence = c.take_u32_le()?;
        if let Some(h) = txid_hasher.as_mut() {
            h.write(&sequence.to_le_bytes());
        }
        vin_sequences.push(sequence);

        if sequence < 0xffff_fffe {
            rbf_signaling = true;
        }
    }

    // --- VOUT ---
    let vout_count_u64 = read_varint(&mut c)?;
    let vout_count = vout_count_u64 as usize;
    if let Some(h) = txid_hasher.as_mut() {
        write_varint_hasher(h, vout_count_u64);
    }

    let mut total_output_sats: u64 = 0;
    let mut vout_reports: Vec<VoutReport> = Vec::with_capacity(vout_count);
    let mut has_unknown_output = false;

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

        let stype = script_type(spk);
        if stype == "unknown" {
            has_unknown_output = true;
        }

        let (op_hex, op_utf8, op_proto) = if stype == "op_return" {
            // Concatenate all pushes after OP_RETURN per README requirements.
            if let Some(data) = parse_op_return_data(spk) {
                let h = bytes_to_hex(&data);
                let u = std::str::from_utf8(&data).ok().map(|s| s.to_string());

                let proto = if data.starts_with(&[0x6f, 0x6d, 0x6e, 0x69]) {
                    "omni"
                } else if data.starts_with(&[0x01, 0x09, 0xf9, 0x11, 0x02]) {
                    "opentimestamps"
                } else {
                    "unknown"
                };

                (Some(h), u, Some(proto.to_string()))
            } else {
                // bare OP_RETURN or malformed push encoding
                (Some(String::new()), None, Some("unknown".to_string()))
            }
        } else {
            (None, None, None)
        };

        vout_reports.push(VoutReport {
            n: vout_reports.len() as u32,
            value_sats: value,
            script_pubkey_hex: bytes_to_hex(spk),
            script_asm: disasm_script(spk),
            script_type: stype,
            address: None,
            op_return_data_hex: op_hex,
            op_return_data_utf8: op_utf8,
            op_return_protocol: op_proto,
        });
    }

    // --- Witness ---
    let mut witnesses: Vec<Vec<String>> = vec![Vec::new(); vin_count];
    let mut witnesses_bytes: Vec<Vec<Vec<u8>>> = vec![Vec::new(); vin_count];
    if segwit {
        for (idx, slot) in witnesses.iter_mut().enumerate() {
            let n_stack = read_varint(&mut c)? as usize;
            let mut items_hex: Vec<String> = Vec::with_capacity(n_stack);
            let mut items_bytes: Vec<Vec<u8>> = Vec::with_capacity(n_stack);
            for _ in 0..n_stack {
                let item_len = read_varint(&mut c)? as usize;
                let item = c.take(item_len)?;
                items_hex.push(bytes_to_hex(item));
                items_bytes.push(item.to_vec());
            }
            *slot = items_hex;
            witnesses_bytes[idx] = items_bytes;
        }
    }

    // locktime
    let locktime = c.take_u32_le()?;
    if let Some(h) = txid_hasher.as_mut() {
        h.write(&locktime.to_le_bytes());
    }

    if c.remaining() != 0 {
        return Err("trailing bytes after parsing".into());
    }

    // non-witness size is only meaningful for segwit txs (txid-hasher len).
    let non_witness_size = if let Some(h) = txid_hasher.as_ref() {
        h.len
    } else {
        size_bytes
    };

    let txid = if segwit {
        hash_to_display_hex(txid_hasher.take().unwrap().finish())
    } else {
        // Legacy txid is the hash of the full raw tx.
        hash_to_display_hex(dsha256(raw))
    };

    if segwit && !coinbase && prevouts_ordered.len() != vin_count {
        return Err(format!(
            "prevouts_ordered length mismatch: got {} expected {}",
            prevouts_ordered.len(),
            vin_count
        ));
    }

    let mut total_input_sats: u64 = 0;
    let mut vin_reports: Vec<VinReport> = Vec::with_capacity(vin_count);

    if coinbase {
        rbf_signaling = false;
    }

    // Build vin reports using moves (avoid clones).
    let mut out_iter = vin_outpoints.into_iter();
    let mut ss_iter = vin_script_sig_hex.into_iter();
    let mut asm_iter = vin_script_sig_asm.into_iter();
    let mut ssb_iter = vin_script_sig_bytes.into_iter();
    let mut seq_iter = vin_sequences.into_iter();
    let mut wit_iter = witnesses.into_iter();
    let mut witb_iter = witnesses_bytes.into_iter();

    for i in 0..vin_count {
        let (txid_in, vout_in) = out_iter.next().unwrap();
        let script_sig_hex = ss_iter.next().unwrap();
        let script_asm = asm_iter.next().unwrap();
        let sequence = seq_iter.next().unwrap();
        let witness = wit_iter.next().unwrap();
        let witness_b = witb_iter.next().unwrap();
        let script_sig_b = ssb_iter.next().unwrap();

        if coinbase {
            vin_reports.push(VinReport {
                txid: txid_in,
                vout: vout_in,
                sequence,
                script_sig_hex,
                script_asm,
                witness,
                witness_script_asm: None,
                script_type: "unknown".to_string(),
                address: None,
                prevout: PrevoutInfo {
                    value_sats: 0,
                    script_pubkey_hex: String::new(),
                },
                relative_timelock: RelativeTimelock {
                    enabled: false,
                    r#type: None,
                    value: None,
                },
            });
            continue;
        }

        let (val, spk_bytes) = &prevouts_ordered[i];
        total_input_sats = total_input_sats.saturating_add(*val);

        let (in_type, witness_script_asm) = classify_input_spend(spk_bytes, &script_sig_b, &witness_b);

        vin_reports.push(VinReport {
            txid: txid_in,
            vout: vout_in,
            sequence,
            script_sig_hex,
            script_asm,
            witness,
            witness_script_asm,
            script_type: in_type,
            address: None,
            prevout: PrevoutInfo {
                value_sats: *val,
                script_pubkey_hex: bytes_to_hex(spk_bytes),
            },
            relative_timelock: relative_timelock(version, sequence),
        });
    }

    if coinbase {
        total_input_sats = total_output_sats;
    }

    let mut fee_sats_i64 = (total_input_sats as i64) - (total_output_sats as i64);
    if coinbase {
        fee_sats_i64 = 0;
    }

    let (weight, vbytes, wtxid_opt, segwit_savings) = if segwit {
        let witness_bytes = size_bytes.saturating_sub(non_witness_size);
        let weight_actual = non_witness_size * 4 + witness_bytes;
        let vbytes = weight_actual.div_ceil(4);

        let weight_if_legacy = size_bytes * 4;
        let savings_pct = if weight_if_legacy == 0 {
            0.0
        } else {
            (1.0 - (weight_actual as f64 / weight_if_legacy as f64)) * 100.0
        };

        (
            weight_actual,
            vbytes,
            wtxid_full,
            Some(SegwitSavings {
                witness_bytes,
                non_witness_bytes: non_witness_size,
                total_bytes: size_bytes,
                weight_actual,
                weight_if_legacy,
                savings_pct: (savings_pct * 100.0).round() / 100.0,
            }),
        )
    } else {
        let weight = size_bytes * 4;
        let vbytes = weight.div_ceil(4);
        (weight, vbytes, None, None)
    };

    let fee_rate = if coinbase || vbytes == 0 {
        0.0
    } else {
        (fee_sats_i64 as f64) / (vbytes as f64)
    };
    let fee_rate_2dp = (fee_rate * 100.0).round() / 100.0;

    let mut warnings: Vec<WarningItem> = Vec::new();

    if rbf_signaling {
        warnings.push(WarningItem {
            code: "RBF_SIGNALING".into(),
        });
    }

    if has_unknown_output {
        warnings.push(WarningItem {
            code: "UNKNOWN_OUTPUT_SCRIPT".into(),
        });
    }

    Ok(TxReport {
        ok: true,
        network: network.into(),
        segwit,
        txid,
        wtxid: wtxid_opt,
        version,
        locktime,
        locktime_value: locktime,
        size_bytes,
        weight,
        vbytes,
        fee_sats: fee_sats_i64,
        fee_rate_sat_vb: fee_rate_2dp,
        total_input_sats,
        total_output_sats,
        rbf_signaling,
        locktime_type: locktime_type(locktime),
        vin: vin_reports,
        vout: vout_reports,
        warnings,
        segwit_savings,
    })
}

pub fn analyze_tx(network: &str, raw_tx_hex: &str, prevouts: &[Prevout]) -> Result<TxReport, String> {
    let raw = hex_to_bytes(raw_tx_hex)?;

    // --- 1) First pass: parse only the input outpoints (vin order) ---
    let mut c = Cursor::new(&raw);

    // version
    let _version = c.take_u32_le()?;

    // segwit marker/flag (if present)
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
    let mut coinbase = false;
    let mut keys: Vec<PrevoutKey> = Vec::with_capacity(vin_count);

    for vin_idx in 0..vin_count {
        let prev_txid_le_bytes = c.take(32)?;
        let prev_vout = c.take_u32_le()?;

        if vin_idx == 0
            && vin_count == 1
            && prev_vout == 0xffff_ffff
            && prev_txid_le_bytes.iter().all(|&b| b == 0)
        {
            coinbase = true;
        }

        let script_len = read_varint(&mut c)? as usize;
        let _ = c.take(script_len)?; // scriptSig
        let _sequence = c.take_u32_le()?; // sequence

        if !coinbase {
            let mut txid_le = [0u8; 32];
            txid_le.copy_from_slice(prev_txid_le_bytes);
            keys.push(PrevoutKey {
                txid_le,
                vout: prev_vout,
            });
        }
    }

    // Coinbase txs don't require prevouts.
    if coinbase {
        return analyze_tx_from_bytes_ordered(network, &raw, &[]);
    }

    if prevouts.len() != keys.len() {
        return Err(format!(
            "prevouts length mismatch: got {} expected {}",
            prevouts.len(),
            keys.len()
        ));
    }

    // Helper: fixture prevout uses display big-endian txid; tx serialization uses little-endian.
    #[inline]
    fn prevout_key_from_hex(txid_hex: &str, vout: u32) -> Result<PrevoutKey, String> {
        let mut be = hex_to_bytes(txid_hex)?;
        if be.len() != 32 {
            return Err("prevout txid must be 32 bytes".into());
        }
        be.reverse();
        let mut txid_le = [0u8; 32];
        txid_le.copy_from_slice(&be);
        Ok(PrevoutKey { txid_le, vout })
    }

    // --- 2) Fast path: if fixture prevouts are already in vin order, avoid HashMap entirely ---
    let mut ordered_ok = true;
    for (i, p) in prevouts.iter().enumerate() {
        let k = prevout_key_from_hex(&p.txid_hex, p.vout)?;
        if k != keys[i] {
            ordered_ok = false;
            break;
        }
    }

    let mut prevouts_ordered: Vec<(u64, Vec<u8>)> = Vec::with_capacity(keys.len());

    if ordered_ok {
        for p in prevouts {
            prevouts_ordered.push((p.value_sats, hex_to_bytes(&p.script_pubkey_hex)?));
        }
    } else {
        // --- 3) General path: build a fast hash map from outpoint -> (value, script_pubkey_bytes) ---
        let mut prevmap: AHashMap<PrevoutKey, (u64, Vec<u8>)> =
            AHashMap::with_capacity(prevouts.len().saturating_mul(2));

        for p in prevouts {
            let k = prevout_key_from_hex(&p.txid_hex, p.vout)?;
            let spk_bytes = hex_to_bytes(&p.script_pubkey_hex)?;
            prevmap.insert(k, (p.value_sats, spk_bytes));
        }

        for k in &keys {
            let (value, spk) = prevmap
                .remove(k)
                .ok_or_else(|| "missing prevout".to_string())?;
            prevouts_ordered.push((value, spk));
        }
    }

    // --- 4) Run the ordered, allocation-lean analyzer ---
    analyze_tx_from_bytes_ordered(network, &raw, &prevouts_ordered)
}
