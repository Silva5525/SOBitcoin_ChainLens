// src/btc/tx.rs

use ahash::AHashMap;
use bech32::{ToBase32, Variant};
use bs58;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};

// ===============================
// CORE LAYER (Performance First)
// ===============================

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    #[inline]
    fn as_str(self) -> &'static str {
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
    #[inline]
    fn as_str(self) -> &'static str {
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
pub(crate) enum WarningCode {
    RbfSignaling = 0,
    UnknownOutputScript = 1,
    DustOutput = 2,
    HighFee = 3,
}

impl WarningCode {
    #[inline]
    fn as_str(self) -> &'static str {
        match self {
            WarningCode::RbfSignaling => "RBF_SIGNALING",
            WarningCode::UnknownOutputScript => "UNKNOWN_OUTPUT_SCRIPT",
            WarningCode::DustOutput => "DUST_OUTPUT",
            WarningCode::HighFee => "HIGH_FEE",
        }
    }
}

// Internal zero-heap core representations (no Strings)
pub(crate) struct CoreInput<'a> {
    pub(crate) prev_txid_le: [u8; 32],
    pub(crate) vout: u32,
    pub(crate) sequence: u32,
    pub(crate) script_sig: &'a [u8],
    pub(crate) witness: Vec<&'a [u8]>,
    pub(crate) spend_type: SpendType,
    pub(crate) prev_value: u64,
    pub(crate) prev_spk: &'a [u8],
}

pub(crate) struct CoreOutput<'a> {
    pub(crate) value: u64,
    pub(crate) spk: &'a [u8],
    pub(crate) script_type: ScriptType,
}

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

// NOTE:
// Next refactor step:
// 1) Convert script_type() -> ScriptType (remove String returns)
// 2) Convert classify_input_spend() -> SpendType
// 3) Make analyze_tx_from_bytes_ordered_impl build CoreTx
// 4) Add separate build_tx_report(CoreTx) -> TxReport
// This splits Core Engine from JSON Layer (Bitcoin Core style).


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

fn hash_to_display_hex(hash: [u8; 32]) -> String {
    // Bitcoin displays hashes as big-endian hex; SHA256 output here is treated as internal byte order.
    // We reverse for human display.
    let mut be = hash;
    be.reverse();
    bytes_to_hex(&be)
}

#[derive(Clone, Copy)]
struct NetParams {
    p2pkh_prefix: u8,
    p2sh_prefix: u8,
    bech32_hrp: &'static str,
}

fn net_params(network: &str) -> Result<NetParams, String> {
    match network {
        "main" | "mainnet" | "bitcoin" => Ok(NetParams {
            p2pkh_prefix: 0x00,
            p2sh_prefix: 0x05,
            bech32_hrp: "bc",
        }),
        "test" | "testnet" | "signet" | "regtest" => Ok(NetParams {
            p2pkh_prefix: 0x6f,
            p2sh_prefix: 0xc4,
            bech32_hrp: "tb",
        }),
        _ => Err(format!("unsupported network: {network}")),
    }
}

fn base58check(version: u8, payload: &[u8]) -> String {
    let mut buf = Vec::with_capacity(1 + payload.len() + 4);
    buf.push(version);
    buf.extend_from_slice(payload);
    let chk = dsha256(&buf);
    buf.extend_from_slice(&chk[0..4]);
    bs58::encode(buf).into_string()
}

fn bech32_witness_addr(hrp: &str, witver: u8, program: &[u8]) -> Result<String, String> {
    if witver > 16 {
        return Err("invalid witness version".into());
    }
    if program.len() < 2 || program.len() > 40 {
        return Err("invalid witness program length".into());
    }

    let variant = if witver == 0 {
        Variant::Bech32
    } else {
        Variant::Bech32m
    };

    let mut data = Vec::with_capacity(1 + (program.len() * 8 + 4) / 5);
    data.push(bech32::u5::try_from_u8(witver).map_err(|_| "invalid witver".to_string())?);
    data.extend_from_slice(&program.to_base32());

    bech32::encode(hrp, data, variant).map_err(|e| format!("bech32 encode error: {e}"))
}

fn address_from_spk(network: &str, spk: &[u8]) -> Result<Option<String>, String> {
    let p = net_params(network)?;

    if is_p2pkh_spk(spk) {
        let h160 = &spk[3..23];
        return Ok(Some(base58check(p.p2pkh_prefix, h160)));
    }
    if is_p2sh_spk(spk) {
        let h160 = &spk[2..22];
        return Ok(Some(base58check(p.p2sh_prefix, h160)));
    }
    if is_p2wpkh_spk(spk) {
        let prog = &spk[2..22];
        return Ok(Some(bech32_witness_addr(p.bech32_hrp, 0, prog)?));
    }
    if is_p2wsh_spk(spk) {
        let prog = &spk[2..34];
        return Ok(Some(bech32_witness_addr(p.bech32_hrp, 0, prog)?));
    }
    if is_p2tr_spk(spk) {
        let prog = &spk[2..34];
        return Ok(Some(bech32_witness_addr(p.bech32_hrp, 1, prog)?));
    }

    Ok(None)
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

fn script_type(spk: &[u8]) -> ScriptType {
    if spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
    {
        return ScriptType::P2PKH;
    }
    if spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87 {
        return ScriptType::P2SH;
    }
    if spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14 {
        return ScriptType::P2WPKH;
    }
    if spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20 {
        return ScriptType::P2WSH;
    }
    if spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20 {
        return ScriptType::P2TR;
    }
    if !spk.is_empty() && spk[0] == 0x6a {
        return ScriptType::OpReturn;
    }
    ScriptType::Unknown
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
        if witness_items.len() == 1 && witness_items[0].len() == 64 {
            return (SpendType::P2TRKeyPath, None);
        }
        if let Some(last) = witness_items.last() {
            if !last.is_empty() && (last[0] == 0xc0 || last[0] == 0xc1) {
                return (SpendType::P2TRScriptPath, None);
            }
        }
        return (SpendType::Unknown, None);
    }
    if is_p2sh_spk(prevout_spk) {
        let Some(rs) = extract_last_push(script_sig) else {
            return (SpendType::Unknown, None);
        };
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


#[derive(Clone, Copy, Debug)]
pub struct TxComputeFlags {
    pub include_script_hex: bool,
    pub include_script_asm: bool,
    pub include_addresses: bool,
    pub include_witness_hex: bool,
    pub include_op_return: bool,
    pub include_warnings: bool,
}

impl TxComputeFlags {
    pub const FULL: Self = Self {
        include_script_hex: true,
        include_script_asm: true,
        include_addresses: true,
        include_witness_hex: true,
        include_op_return: true,
        include_warnings: true,
    };

    // Designed for block-mode performance.
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
fn analyze_tx_from_bytes_ordered_impl<'a>(
    _network: &str,
    raw: &'a [u8],
    prevouts_ordered: &'a [(u64, &'a [u8])],
    flags: TxComputeFlags,
) -> Result<CoreTx<'a>, String> {
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

    let mut txid_hasher = if segwit {
        Some(Dsha256Writer::new())
    } else {
        None
    };

    if let Some(h) = txid_hasher.as_mut() {
        h.write(&version.to_le_bytes());
    }

    // --- VIN ---
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

        if vin_index == 0
            && vin_count == 1
            && prev_vout == 0xffff_ffff
            && prev_txid_le_bytes.iter().all(|&b| b == 0)
        {
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

        let witness: Vec<&[u8]> = Vec::new(); // filled later

        inputs.push(CoreInput {
            prev_txid_le: {
                let mut t = [0u8; 32];
                t.copy_from_slice(prev_txid_le_bytes);
                t
            },
            vout: prev_vout,
            sequence,
            script_sig,
            witness,
            spend_type: SpendType::Unknown, // filled later
            prev_value,
            prev_spk,
        });
    }

    // --- VOUT ---
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

        outputs.push(CoreOutput {
            value,
            spk,
            script_type: script_type(spk),
        });
    }

    // --- Witness ---
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

    if c.remaining() != 0 {
        return Err("trailing bytes after parsing".into());
    }

    let non_witness_size = txid_hasher.as_ref().map(|h| h.len).unwrap_or(size_bytes);
    let non_witness_bytes = non_witness_size;
    let witness_bytes = if segwit {
        size_bytes.saturating_sub(non_witness_size)
    } else {
        0
    };

    let txid_le = if segwit {
        txid_hasher.unwrap().finish()
    } else {
        dsha256(raw)
    };

        // Compute input totals + spend types
    let mut total_input_sats: u64 = 0;
    for input in inputs.iter_mut() {
        total_input_sats = total_input_sats.saturating_add(input.prev_value);
        input.spend_type = classify_input_spend(
            input.prev_spk,
            input.script_sig,
            &input.witness,
            false,
        )
        .0;
    }

    if coinbase {
        total_input_sats = total_output_sats;
        rbf_signaling = false;
    }

    let fee = if coinbase {
        0
    } else {
        total_input_sats as i64 - total_output_sats as i64
    };

    let weight = if segwit {
        let witness_bytes = size_bytes.saturating_sub(non_witness_size);
        non_witness_size * 4 + witness_bytes
    } else {
        size_bytes * 4
    };

        let vbytes = weight.div_ceil(4);

    // --- Core warning generation (enum-based, no Strings) ---
    let mut warnings: Vec<WarningCode> = Vec::new();

    if flags.include_warnings {
        if rbf_signaling {
            warnings.push(WarningCode::RbfSignaling);
        }

        // Unknown output scripts
        if outputs.iter().any(|o| o.script_type == ScriptType::Unknown) {
            warnings.push(WarningCode::UnknownOutputScript);
        }

        // Dust detection (simple heuristic: < 546 sats and not OP_RETURN)
        if outputs.iter().any(|o| {
            o.value < 546 && o.script_type != ScriptType::OpReturn
        }) {
            warnings.push(WarningCode::DustOutput);
        }

        // High fee heuristic (> 1 BTC absolute fee)
        if !coinbase && fee > 100_000_000 {
            warnings.push(WarningCode::HighFee);
        }
    }

    Ok(CoreTx {
        txid_le,
        wtxid_le: if segwit { Some(dsha256(raw)) } else { None },
        version,
        locktime,
        segwit,
        size_bytes,
        non_witness_bytes,
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

// JSON layer: build TxReport from CoreTx
fn build_tx_report(network: &str, core: CoreTx, flags: TxComputeFlags) -> Result<TxReport, String> {
    let txid = hash_to_display_hex(core.txid_le);
    let wtxid = core.wtxid_le.map(hash_to_display_hex);

    // --- vin ---
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

        let (spend_type, witness_script_asm) = classify_input_spend(
            inp.prev_spk,
            inp.script_sig,
            &inp.witness,
            flags.include_script_asm,
        );

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
            script_type: spend_type.as_str().to_string(),
            address,
            prevout: PrevoutInfo {
                value_sats: inp.prev_value,
                script_pubkey_hex: if flags.include_script_hex {
                    bytes_to_hex(inp.prev_spk)
                } else {
                    String::new()
                },
            },
            relative_timelock: relative_timelock(core.version, inp.sequence),
        });
    }

    // --- vout ---
    let mut vout: Vec<VoutReport> = Vec::with_capacity(core.outputs.len());
    for (n, o) in core.outputs.iter().enumerate() {
        let spk_hex = if flags.include_script_hex {
            bytes_to_hex(o.spk)
        } else {
            String::new()
        };
        let script_asm = if flags.include_script_asm {
            disasm_script(o.spk)
        } else {
            String::new()
        };
        let address = if flags.include_addresses {
            address_from_spk(network, o.spk)?
        } else {
            None
        };

        let mut op_return_data_hex: Option<String> = None;
        let mut op_return_data_utf8: Option<String> = None;
        let mut op_return_protocol: Option<String> = None;

        if flags.include_op_return && o.script_type == ScriptType::OpReturn {
            if let Some(data) = parse_op_return_data(o.spk) {
                op_return_data_hex = Some(bytes_to_hex(&data));
                if let Ok(s) = std::str::from_utf8(&data) {
                    op_return_data_utf8 = Some(s.to_string());
                }
                // Protocol detection (minimal): schema requires a non-null enum for OP_RETURN.
                // We default to "unknown" unless we detect a known prefix.
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

    // --- segwit savings ---
    let segwit_savings = if core.segwit {
        let weight_actual = core.weight;
        let weight_if_legacy = core.size_bytes * 4;
        let savings_pct = if weight_if_legacy == 0 {
            0.0
        } else {
            ((weight_if_legacy.saturating_sub(weight_actual)) as f64) * 100.0
                / (weight_if_legacy as f64)
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
        fee_rate_sat_vb: if core.vbytes == 0 {
            0.0
        } else {
            core.fee as f64 / core.vbytes as f64
        },
        total_input_sats: core.total_input,
        total_output_sats: core.total_output,
        rbf_signaling: core.rbf,
        locktime_type: locktime_type(core.locktime),
        vin,
        vout,
        warnings: core
            .warnings
            .into_iter()
            .map(|w| WarningItem {
                code: w.as_str().to_string(),
            })
            .collect(),
        segwit_savings,
    })
}

/// Full (README-complete) transaction analyzer.
pub fn analyze_tx_from_bytes_ordered<'a>(
    network: &str,
    raw: &'a [u8],
    prevouts_ordered: &'a [(u64, &'a [u8])],
) -> Result<TxReport, String> {
    let core = analyze_tx_from_bytes_ordered_impl(
        network,
        raw,
        prevouts_ordered,
        TxComputeFlags::FULL,
    )?;
    build_tx_report(network, core, TxComputeFlags::FULL)
}

/// LITE analyzer for block-mode performance.
///
/// IMPORTANT:
/// In high-performance block-mode we should NOT build a TxReport at all.
/// This wrapper exists only for compatibility with existing callers.
pub fn analyze_tx_from_bytes_ordered_lite<'a>(
    network: &str,
    raw: &[u8],
    prevouts_ordered: &[(u64, &[u8])],
) -> Result<TxReport, String> {
    let core = analyze_tx_from_bytes_ordered_impl(
        network,
        raw,
        prevouts_ordered,
        TxComputeFlags::LITE,
    )?;
    build_tx_report(network, core, TxComputeFlags::LITE)
}

/// NEW: Pure Core analyzer for block-mode.
///
/// This is the function block/mod.rs should call directly.
/// It avoids ANY JSON construction and returns CoreTx.
pub fn analyze_tx_core_lite<'a>(
    raw: &'a [u8],
    prevouts_ordered: &'a [(u64, &'a [u8])],
) -> Result<CoreTx<'a>, String> {
    analyze_tx_from_bytes_ordered_impl(
        "main", // network not needed for core computation
        raw,
        prevouts_ordered,
        TxComputeFlags::LITE,
    )
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
        {
        let empty: &[(u64, &[u8])] = &[];
        return analyze_tx_from_bytes_ordered(network, &raw, empty);
    }
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
    {
        // Convert owned scripts to borrowed slices for the zero-copy core analyzer.
        let borrowed: Vec<(u64, &[u8])> = prevouts_ordered
            .iter()
            .map(|(v, spk)| (*v, spk.as_slice()))
            .collect();
        analyze_tx_from_bytes_ordered(network, &raw, &borrowed)
    }
}

