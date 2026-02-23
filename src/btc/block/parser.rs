// src/btc/block/parser.rs
//
// Low-level block/transaction parsing utilities.
//
// Responsibilities:
//   - Provide a minimal zero-copy Cursor over raw block bytes.
//   - Implement Bitcoin CompactSize (VarInt) decoding.
//   - Provide fast-path helpers for blk↔rev pairing.
//   - Skip transactions efficiently while computing txid (segwit-aware).
//   - Compute merkle roots and BIP34 coinbase height.
//
// Design goals:
//   - No unnecessary allocations in hot paths.
//   - Strict bounds checking with clear error codes.
//   - Keep tx-skipping logic close to Bitcoin Core serialization rules.

use sha2::{Digest, Sha256};

/// Helper to build structured error strings with a stable code prefix.
fn err(code: &str, msg: impl AsRef<str>) -> String {
    format!("{code}: {}", msg.as_ref())
}

/// Sanity-check upper bounds for length/count fields.
///
/// This protects against pathological allocations or maliciously large fields
/// in corrupted blk/rev data.
pub(crate) fn ensure_len(kind: &str, field: &str, val: u64, max: u64) -> Result<(), String> {
    if val > max {
        return Err(err(
            "INSANE_LEN",
            format!("{kind}: {field} too large: {val} > {max}"),
        ));
    }
    Ok(())
}

/// Zero-copy byte cursor over a block/transaction buffer.
///
/// Maintains a position index and provides LE helpers for primitive types.
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
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }
}

/// Encode raw bytes as lowercase hex.
pub(crate) fn bytes_to_hex(b: &[u8]) -> String {
    hex::encode(b)
}

/// Bitcoin-style double SHA256.
pub(crate) fn dsha256(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

/// Convert internal little-endian hash to display hex (big-endian).
pub(crate) fn hash_to_display_hex(hash_le: [u8; 32]) -> String {
    let mut be = hash_le;
    be.reverse();
    bytes_to_hex(&be)
}

/// Read Bitcoin CompactSize (VarInt) from a Cursor.
pub(crate) fn read_varint(c: &mut Cursor) -> Result<u64, String> {
    let first = c.take_u8()? as u64;
    match first {
        0x00..=0xfc => Ok(first),
        0xfd => Ok(c.take_u16_le()? as u64),
        0xfe => Ok(c.take_u32_le()? as u64),
        0xff => Ok(c.take_u64_le()?),
        // Unreachable due to u8 range, but keep for defensive clarity.
        _ => Err(err("INVALID_VARINT", "invalid varint prefix")),
    }
}

// ------------------------------------------------------------
// Hot-path helpers (max speed)
// ------------------------------------------------------------

/// Read Bitcoin CompactSize/VarInt directly from a byte-slice cursor.
///
/// This avoids `Cursor` construction and is suitable for ultra-cheap checks in hot paths
/// (e.g. blk↔rev pairing).
#[inline]
pub(crate) fn read_varint_bytes(input: &mut &[u8]) -> Result<u64, String> {
    if input.is_empty() {
        return Err(err("UNEXPECTED_EOF", "varint: empty input"));
    }
    let first = input[0];
    *input = &input[1..];

    match first {
        0x00..=0xfc => Ok(first as u64),
        0xfd => {
            if input.len() < 2 {
                return Err(err("UNEXPECTED_EOF", "varint: 0xfd missing 2 bytes"));
            }
            let v = u16::from_le_bytes([input[0], input[1]]) as u64;
            *input = &input[2..];
            Ok(v)
        }
        0xfe => {
            if input.len() < 4 {
                return Err(err("UNEXPECTED_EOF", "varint: 0xfe missing 4 bytes"));
            }
            let v = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as u64;
            *input = &input[4..];
            Ok(v)
        }
        0xff => {
            if input.len() < 8 {
                return Err(err("UNEXPECTED_EOF", "varint: 0xff missing 8 bytes"));
            }
            let v = u64::from_le_bytes([
                input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
            ]);
            *input = &input[8..];
            Ok(v)
        }
    }
}

/// Ultra-cheap extraction of the block transaction count from a raw block payload.
///
/// Block payload format: 80-byte header followed by CompactSize(tx_count).
///
/// This is intentionally minimal and intended for fast-path plausibility checks.
#[inline]
pub(crate) fn block_tx_count_fast(block_payload: &[u8]) -> Result<u64, String> {
    if block_payload.len() < 81 {
        return Err(err("UNEXPECTED_EOF", "block: too small for header + tx_count"));
    }
    let mut cur = &block_payload[80..];
    let txc = read_varint_bytes(&mut cur)?;
    // Conservative sanity bound. Real blocks are far below this, but allow wiggle room.
    ensure_len("block", "tx_count", txc, 200_000)?;
    Ok(txc)
}

#[inline]
fn sha256d_finish(h: Sha256) -> [u8; 32] {
    let h1 = h.finalize();
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

#[inline]
fn sha256_update_varint(h: &mut Sha256, n: u64) {
    match n {
        0x00..=0xfc => h.update([n as u8]),
        0xfd..=0xffff => {
            h.update([0xfd]);
            h.update((n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            h.update([0xfe]);
            h.update((n as u32).to_le_bytes());
        }
        _ => {
            h.update([0xff]);
            h.update(n.to_le_bytes());
        }
    }
}

/// Compute the merkle root from a list of txids (little-endian).
///
/// Duplicates the last element if the level has odd length,
/// matching Bitcoin consensus behavior.
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
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(dsha256(&buf));
        }
        level = next;
    }
    level[0]
}

/// Skip a transaction and return its txid (little-endian).
///
/// Thin wrapper around the extended variant that also returns vin_count.
pub(crate) fn parse_tx_skip_and_txid_le(
    block: &[u8],
    bc: &mut Cursor,
) -> Result<[u8; 32], String> {
    let (txid, _vin_count) = parse_tx_skip_and_txid_le_and_vin_count(block, bc)?;
    Ok(txid)
}

/// Skip a transaction, computing its txid (LE) and returning vin_count.
///
/// Segwit-aware:
///   - For legacy txs, txid = dsha256(full serialization).
///   - For segwit txs, txid = dsha256(stripped serialization).
///
/// This function avoids building full transaction structures and is
/// optimized for block-mode scanning.
pub(crate) fn parse_tx_skip_and_txid_le_and_vin_count(
    block: &[u8],
    bc: &mut Cursor,
) -> Result<([u8; 32], u64), String> {
    let start = bc.pos();

    let version = bc.take_u32_le()?;

    let peek = bc.take_u8()?;
    let segwit = if peek == 0x00 {
        let flag = bc.take_u8()?;
        if flag != 0x01 {
            return Err(err("INVALID_TX", "invalid segwit flag"));
        }
        true
    } else {
        bc.i -= 1;
        false
    };

    if !segwit {
        let vin_count = read_varint(bc)?;
        ensure_len("tx", "vin_count", vin_count, 50_000)?;
        for _ in 0..vin_count {
            let _ = bc.take(32)?;
            let _ = bc.take(4)?;
            let script_len = read_varint(bc)?;
            ensure_len("tx", "script_sig_len", script_len, 1_000_000)?;
            let _ = bc.take(script_len as usize)?;
            let _ = bc.take(4)?;
        }

        let vout_count = read_varint(bc)?;
        ensure_len("tx", "vout_count", vout_count, 50_000)?;
        for _ in 0..vout_count {
            let _ = bc.take(8)?;
            let spk_len = read_varint(bc)?;
            ensure_len("tx", "script_pubkey_len", spk_len, 10_000)?;
            let _ = bc.take(spk_len as usize)?;
        }

        let _ = bc.take(4)?; // locktime
        let end = bc.pos();
        return Ok((dsha256(&block[start..end]), vin_count));
    }

    // Segwit: stream stripped serialization directly into hasher.
    let mut h = Sha256::new();
    h.update(version.to_le_bytes());

    let vin_count = read_varint(bc)?;
    ensure_len("tx", "vin_count", vin_count, 50_000)?;
    sha256_update_varint(&mut h, vin_count);

    for _ in 0..vin_count {
        let prev_txid = bc.take(32)?;
        let vout = bc.take(4)?;
        h.update(prev_txid);
        h.update(vout);

        let script_len = read_varint(bc)?;
        ensure_len("tx", "script_sig_len", script_len, 1_000_000)?;
        sha256_update_varint(&mut h, script_len);
        let script = bc.take(script_len as usize)?;
        h.update(script);

        let seq = bc.take(4)?;
        h.update(seq);
    }

    let vout_count = read_varint(bc)?;
    ensure_len("tx", "vout_count", vout_count, 50_000)?;
    sha256_update_varint(&mut h, vout_count);

    for _ in 0..vout_count {
        let value = bc.take(8)?;
        h.update(value);

        let spk_len = read_varint(bc)?;
        ensure_len("tx", "script_pubkey_len", spk_len, 10_000)?;
        sha256_update_varint(&mut h, spk_len);
        let spk = bc.take(spk_len as usize)?;
        h.update(spk);
    }

    // Skip witness (not hashed into txid).
    for _ in 0..vin_count {
        let n_items = read_varint(bc)?;
        ensure_len("tx", "witness_item_count", n_items, 10_000)?;
        for _ in 0..n_items {
            let item_len = read_varint(bc)?;
            ensure_len("tx", "witness_item_len", item_len, 4_000_000)?;
            let _ = bc.take(item_len as usize)?;
        }
    }

    let lock = bc.take(4)?;
    h.update(lock);

    Ok((sha256d_finish(h), vin_count))
}

/// Skip a transaction and return only the vin_count.
///
/// Cheaper than computing txid and used when only input counts
/// are required (e.g. undo parsing alignment).
pub(crate) fn parse_tx_skip_and_vin_count(bc: &mut Cursor) -> Result<u64, String> {
    let _version = bc.take_u32_le()?;

    // Detect segwit marker/flag.
    let peek = bc.take_u8()?;
    let segwit = if peek == 0x00 {
        let flag = bc.take_u8()?;
        if flag != 0x01 {
            return Err(err("INVALID_TX", "invalid segwit flag"));
        }
        true
    } else {
        bc.i -= 1;
        false
    };

    // vin
    let vin_count = read_varint(bc)?;
    ensure_len("tx", "vin_count", vin_count, 50_000)?;
    for _ in 0..vin_count {
        let _ = bc.take(32)?;
        let _ = bc.take(4)?;
        let script_len = read_varint(bc)?;
        ensure_len("tx", "script_sig_len", script_len, 1_000_000)?;
        let _ = bc.take(script_len as usize)?;
        let _ = bc.take(4)?;
    }

    // vout
    let vout_count = read_varint(bc)?;
    ensure_len("tx", "vout_count", vout_count, 50_000)?;
    for _ in 0..vout_count {
        let _ = bc.take(8)?;
        let spk_len = read_varint(bc)?;
        ensure_len("tx", "script_pubkey_len", spk_len, 10_000)?;
        let _ = bc.take(spk_len as usize)?;
    }

    // witness (only present in segwit txs)
    if segwit {
        for _ in 0..vin_count {
            let n_items = read_varint(bc)?;
            ensure_len("tx", "witness_item_count", n_items, 10_000)?;
            for _ in 0..n_items {
                let item_len = read_varint(bc)?;
                ensure_len("tx", "witness_item_len", item_len, 4_000_000)?;
                let _ = bc.take(item_len as usize)?;
            }
        }
    }

    let _ = bc.take(4)?; // locktime
    Ok(vin_count)
}

/// Decode BIP34 block height from the coinbase scriptSig.
///
/// Returns 0 if script is malformed or height encoding is invalid.
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

/// Extract coinbase scriptSig and total output sum from a raw coinbase tx.
///
/// Validates that the single input has outpoint (32x00, vout=0xffffffff).
pub(crate) fn coinbase_extract_script_and_outsum(raw_tx: &[u8]) -> Result<(Vec<u8>, u64), String> {
    let mut c = Cursor::new(raw_tx);
    let _version = c.take_u32_le()?;

    // Consume optional segwit marker/flag. Coinbase txs in practice are non-segwit,
    // but keep this tolerant for fixtures.
    let p = c.take_u8()?;
    if p == 0x00 {
        let _ = c.take_u8()?;
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

    let _ = c.take(4)?; // sequence

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
