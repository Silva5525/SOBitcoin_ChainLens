// src/btc/block/parser.rs

use sha2::{Digest, Sha256};

fn err(code: &str, msg: impl AsRef<str>) -> String {
    format!("{code}: {}", msg.as_ref())
}

pub(crate) fn ensure_len(kind: &str, field: &str, val: u64, max: u64) -> Result<(), String> {
    if val > max {
        return Err(err(
            "INSANE_LEN",
            format!("{kind}: {field} too large: {val} > {max}"),
        ));
    }
    Ok(())
}

pub(crate) struct Cursor<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) i: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    pub(crate) fn pos(&self) -> usize {
        self.i
    }
    pub(crate) fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.i)
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.i + n > self.b.len() {
            return Err(err(
                "UNEXPECTED_EOF",
                format!(
                    "unexpected EOF at pos={} need={} have_remaining={}",
                    self.i,
                    n,
                    self.b.len().saturating_sub(self.i)
                ),
            ));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    pub(crate) fn take_u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn take_u16_le(&mut self) -> Result<u16, String> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    pub(crate) fn take_u32_le(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub(crate) fn take_u64_le(&mut self) -> Result<u64, String> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
    }
}

pub(crate) fn bytes_to_hex(b: &[u8]) -> String {
    hex::encode(b)
}

pub(crate) fn dsha256(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

pub(crate) fn hash_to_display_hex(hash_le: [u8; 32]) -> String {
    let mut be = hash_le;
    be.reverse();
    bytes_to_hex(&be)
}

pub(crate) fn read_varint(c: &mut Cursor) -> Result<u64, String> {
    // Bitcoin CompactSize
    let first = c.take_u8()? as u64;
    match first {
        0x00..=0xfc => Ok(first),
        0xfd => Ok(c.take_u16_le()? as u64),
        0xfe => Ok(c.take_u32_le()? as u64),
        0xff => Ok(c.take_u64_le()?),
        _ => Err(err("INVALID_VARINT", "invalid varint prefix")),
    }
}

pub(crate) fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0x00..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

pub(crate) fn merkle_root(txids_le: &[[u8; 32]]) -> [u8; 32] {
    if txids_le.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = txids_le.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&pair[0]);
            buf.extend_from_slice(&pair[1]);
            next.push(dsha256(&buf));
        }
        level = next;
    }
    level[0]
}

pub(crate) fn parse_tx_raw_and_txid_le(block: &[u8], bc: &mut Cursor) -> Result<(Vec<u8>, [u8; 32]), String> {
    let start = bc.pos();

    let version = bc.take_u32_le()?;
    let mut segwit = false;

    let mut stripped: Vec<u8> = Vec::new();
    stripped.extend_from_slice(&version.to_le_bytes());

    let peek = bc.take_u8()?;
    if peek == 0x00 {
        let flag = bc.take_u8()?;
        if flag != 0x01 {
            return Err(err("INVALID_TX", "invalid segwit flag"));
        }
        segwit = true;
    } else {
        bc.i -= 1;
    }

    let vin_count = read_varint(bc)?;
    ensure_len("tx", "vin_count", vin_count, 50_000)?;
    write_varint(&mut stripped, vin_count);

    for _ in 0..vin_count {
        let prev_txid = bc.take(32)?;
        let vout = bc.take(4)?;
        stripped.extend_from_slice(prev_txid);
        stripped.extend_from_slice(vout);

        let script_len = read_varint(bc)?;
        ensure_len("tx", "script_sig_len", script_len, 1_000_000)?;
        write_varint(&mut stripped, script_len);
        let script = bc.take(script_len as usize)?;
        stripped.extend_from_slice(script);

        let seq = bc.take(4)?;
        stripped.extend_from_slice(seq);
    }

    let vout_count = read_varint(bc)?;
    ensure_len("tx", "vout_count", vout_count, 50_000)?;
    write_varint(&mut stripped, vout_count);

    for _ in 0..vout_count {
        let value = bc.take(8)?;
        stripped.extend_from_slice(value);

        let spk_len = read_varint(bc)?;
        ensure_len("tx", "script_pubkey_len", spk_len, 10_000)?;
        write_varint(&mut stripped, spk_len);
        let spk = bc.take(spk_len as usize)?;
        stripped.extend_from_slice(spk);
    }

    if segwit {
        for _ in 0..vin_count {
            let n_items_u64 = read_varint(bc)?;
            ensure_len("tx", "witness_item_count", n_items_u64, 10_000)?;
            let n_items = n_items_u64 as usize;

            for _ in 0..n_items {
                let item_len_u64 = read_varint(bc)?;
                ensure_len("tx", "witness_item_len", item_len_u64, 4_000_000)?;

                if item_len_u64 > (usize::MAX as u64) {
                    return Err(err("INSANE_LEN", "witness_item_len does not fit usize"));
                }
                let item_len = item_len_u64 as usize;
                let _ = bc.take(item_len)?;
            }
        }
    }

    let lock = bc.take(4)?;
    stripped.extend_from_slice(lock);

    let end = bc.pos();
    let raw = block[start..end].to_vec();

    let txid_le = if segwit { dsha256(&stripped) } else { dsha256(&raw) };
    Ok((raw, txid_le))
}

pub(crate) fn decode_bip34_height(coinbase_script: &[u8]) -> u64 {
    if coinbase_script.is_empty() {
        return 0;
    }
    let n = coinbase_script[0] as usize;
    if n == 0 || 1 + n > coinbase_script.len() || n > 8 {
        return 0;
    }
    let mut val: u64 = 0;
    for (i, b) in coinbase_script[1..1 + n].iter().enumerate() {
        val |= (*b as u64) << (8 * i);
    }
    val
}

pub(crate) fn coinbase_extract_script_and_outsum(raw_tx: &[u8]) -> Result<(Vec<u8>, u64), String> {
    let mut c = Cursor::new(raw_tx);
    let _version = c.take_u32_le()?;

    let p = c.take_u8()?;
    if p == 0x00 {
        let _f = c.take_u8()?;
    } else {
        c.i -= 1;
    }

    let vin_n = read_varint(&mut c)?;
    if vin_n != 1 {
        return Err(err("INVALID_COINBASE", "coinbase must have exactly 1 input"));
    }

    let prev = c.take(32)?;
    let vout = c.take_u32_le()?;
    if prev.iter().any(|&b| b != 0) || vout != 0xffff_ffff {
        return Err(err(
            "INVALID_COINBASE",
            "coinbase input outpoint must be (32x00, vout=0xffffffff)",
        ));
    }

    let script_len = read_varint(&mut c)? as usize;
    let script = c.take(script_len)?.to_vec();

    let _seq = c.take(4)?;

    let vout_n = read_varint(&mut c)?;
    let mut outsum: u64 = 0;
    for _ in 0..vout_n {
        let value = c.take_u64_le()?;
        outsum = outsum.saturating_add(value);
        let spk_len = read_varint(&mut c)? as usize;
        let _ = c.take(spk_len)?;
    }

    Ok((script, outsum))
}
