use sha2::{Digest, Sha256};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct Prevout {
    pub txid_hex: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
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
    pub size_bytes: usize,
    pub weight: usize,
    pub vbytes: usize,
    pub fee_sats: i64,
    pub fee_rate_sat_vb: f64,
    pub total_input_sats: u64,
    pub total_output_sats: u64,
    pub rbf_signaling: bool,
    pub locktime_type: String,
    pub vin_count: usize,
    pub vout_count: usize,
    pub vout_script_types: Vec<String>,
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self { Self { b, i: 0 } }
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
        Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
    }
    fn remaining(&self) -> usize { self.b.len().saturating_sub(self.i) }
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 { return Err("hex length must be even".into()); }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16)
            .map_err(|_| "invalid hex".to_string())?;
        out.push(byte);
    }
    Ok(out)
}

fn bytes_to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn dsha256(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(&h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
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

fn script_type(script: &[u8]) -> String {
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        return "p2pkh".into();
    }
    if !script.is_empty() && script[0] == 0x6a {
        return "op_return".into();
    }
    "unknown".into()
}

pub fn analyze_tx(network: &str, raw_tx_hex: &str, prevouts: &[Prevout]) -> Result<TxReport, String> {
    let raw = hex_to_bytes(raw_tx_hex)?;
    let size_bytes = raw.len();

    // legacy txid
    let txid_le = dsha256(&raw);
    let mut txid_be = txid_le;
    txid_be.reverse();
    let txid = bytes_to_hex(&txid_be);

    let mut c = Cursor::new(&raw);

    let version = c.take_u32_le()?;

    // segwit marker/flag detection
    let mut segwit = false;
    let peek = c.take_u8()?;
    if peek == 0x00 {
        let flag = c.take_u8()?;
        if flag != 0x01 { return Err("invalid segwit flag".into()); }
        segwit = true;
    } else {
        c.i -= 1;
    }
    if segwit {
        return Err("segwit not implemented yet".into());
    }

    let vin_count = read_varint(&mut c)? as usize;

    let mut rbf_signaling = false;
    for _ in 0..vin_count {
        let _prev_txid_le = c.take(32)?;
        let _vout = c.take_u32_le()?;
        let script_len = read_varint(&mut c)? as usize;
        let _script_sig = c.take(script_len)?;
        let sequence = c.take_u32_le()?;
        if sequence < 0xffff_fffe { rbf_signaling = true; }
    }

    let vout_count = read_varint(&mut c)? as usize;

    let mut total_output_sats: u64 = 0;
    let mut vout_script_types = Vec::with_capacity(vout_count);

    for _ in 0..vout_count {
        let value = c.take_u64_le()?;
        total_output_sats = total_output_sats.saturating_add(value);
        let spk_len = read_varint(&mut c)? as usize;
        let spk = c.take(spk_len)?;
        vout_script_types.push(script_type(spk));
    }

    let locktime = c.take_u32_le()?;

    if c.remaining() != 0 {
        return Err("trailing bytes after parsing".into());
    }

    let total_input_sats: u64 = prevouts.iter().map(|p| p.value_sats).sum();
    let fee_sats_i64 = (total_input_sats as i64) - (total_output_sats as i64);

    let weight = size_bytes * 4;
    let vbytes = (weight + 3) / 4;

    let fee_rate = if vbytes == 0 { 0.0 } else { (fee_sats_i64 as f64) / (vbytes as f64) };
    let fee_rate_2dp = (fee_rate * 100.0).round() / 100.0;

    Ok(TxReport {
        ok: true,
        network: network.into(),
        segwit,
        txid,
        wtxid: None,
        version,
        locktime,
        size_bytes,
        weight,
        vbytes,
        fee_sats: fee_sats_i64,
        fee_rate_sat_vb: fee_rate_2dp,
        total_input_sats,
        total_output_sats,
        rbf_signaling,
        locktime_type: "none".into(),
        vin_count,
        vout_count,
        vout_script_types,
    })
}
