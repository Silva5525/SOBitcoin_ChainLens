// ============================================================================
// src/btc/tx/util.rs
// Low-level utils (cursor, hex, hashing, varints, address encoding)
// ============================================================================
//!
//! Low-level helpers used by the TX parser and report builder.
//!
//! Keep this module small, deterministic, and allocation-lean.
//! Most functions here are "leaf" utilities: hex, varints, hashing, cursor reads,
//! and best-effort address formatting.

use bech32::{ToBase32, Variant};
use bs58;
use sha2::{Digest, Sha256};

/// A bounds-checked cursor over a byte slice.
///
/// The parser uses this to avoid panics and to produce clean errors
/// for truncated or malformed transactions.
pub(crate) struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    /// Create a new cursor starting at byte 0.
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }

    /// Step back by one byte.
    ///
    /// Used after peeking the SegWit marker byte when the tx is not SegWit.
    pub(crate) fn backtrack_1(&mut self) -> Result<(), String> {
        if self.i == 0 {
            return Err("cursor underflow".into());
        }
        self.i -= 1;
        Ok(())
    }

    /// Take `n` bytes and advance the cursor.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.i + n > self.b.len() {
            return Err("unexpected EOF".into());
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }

    /// Read one byte.
    pub(crate) fn take_u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    /// Read a 32-bit little-endian integer.
    pub(crate) fn take_u32_le(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Read a 64-bit little-endian integer.
    pub(crate) fn take_u64_le(&mut self) -> Result<u64, String> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    /// Number of bytes remaining in the input.
    pub(crate) fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.i)
    }
}

/// Decode strict hex string into bytes.
pub(crate) fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex).map_err(|_| "invalid hex".to_string())
}

/// Encode bytes into lowercase hex.
pub(crate) fn bytes_to_hex(b: &[u8]) -> String {
    hex::encode(b)
}

/// Bitcoin HASH256 (double-SHA256).
pub(crate) fn dsha256(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

/// Convert internal little-endian hash bytes into the standard display hex.
///
/// Bitcoin displays txid/block hashes as big-endian hex.
pub(crate) fn hash_to_display_hex(mut hash: [u8; 32]) -> String {
    hash.reverse();
    bytes_to_hex(&hash)
}

/// Address encoding parameters for a network.
#[derive(Clone, Copy)]
struct NetParams {
    p2pkh_prefix: u8,
    p2sh_prefix: u8,
    bech32_hrp: &'static str,
}

/// Map a `network` string to address parameters.
///
/// Note: for simplicity, signet/regtest use the `tb` HRP here.
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

/// Base58Check encode: version byte + payload + 4-byte checksum.
fn base58check(version: u8, payload: &[u8]) -> String {
    let mut buf = Vec::with_capacity(1 + payload.len() + 4);
    buf.push(version);
    buf.extend_from_slice(payload);
    let chk = dsha256(&buf);
    buf.extend_from_slice(&chk[0..4]);
    bs58::encode(buf).into_string()
}

/// Encode a SegWit address as bech32/bech32m.
///
/// - witness version 0 => bech32 (BIP173)
/// - witness version 1+ => bech32m (BIP350)
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
    data.push(
        bech32::u5::try_from_u8(witver).map_err(|_| "invalid witver".to_string())?,
    );
    data.extend_from_slice(&program.to_base32());

    bech32::encode(hrp, data, variant).map_err(|e| format!("bech32 encode error: {e}"))
}

/// Best-effort address extraction from common scriptPubKey templates.
///
/// Returns `Ok(None)` for scripts that don't have a standard address encoding.
pub(crate) fn address_from_spk(network: &str, spk: &[u8]) -> Result<Option<String>, String> {
    let p = net_params(network)?;

    if crate::btc::tx::script::is_p2pkh_spk(spk) {
        // OP_DUP OP_HASH160 PUSH20 <h160> OP_EQUALVERIFY OP_CHECKSIG
        let h160 = &spk[3..23];
        return Ok(Some(base58check(p.p2pkh_prefix, h160)));
    }
    if crate::btc::tx::script::is_p2sh_spk(spk) {
        // OP_HASH160 PUSH20 <h160> OP_EQUAL
        let h160 = &spk[2..22];
        return Ok(Some(base58check(p.p2sh_prefix, h160)));
    }
    if crate::btc::tx::script::is_p2wpkh_spk(spk) {
        // 0 <20-byte program>
        let prog = &spk[2..22];
        return Ok(Some(bech32_witness_addr(p.bech32_hrp, 0, prog)?));
    }
    if crate::btc::tx::script::is_p2wsh_spk(spk) {
        // 0 <32-byte program>
        let prog = &spk[2..34];
        return Ok(Some(bech32_witness_addr(p.bech32_hrp, 0, prog)?));
    }
    if crate::btc::tx::script::is_p2tr_spk(spk) {
        // 1 <32-byte program>
        let prog = &spk[2..34];
        return Ok(Some(bech32_witness_addr(p.bech32_hrp, 1, prog)?));
    }

    Ok(None)
}

/// A streaming HASH256 writer.
///
/// This lets us compute the SegWit txid (hash of the *stripped* serialization)
/// without allocating a full "stripped transaction" buffer.
pub(crate) struct Dsha256Writer {
    h: Sha256,
    /// Number of bytes written into the first SHA256 round.
    pub(crate) len: usize,
}

impl Dsha256Writer {
    /// New streaming writer.
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            h: Sha256::new(),
            len: 0,
        }
    }

    /// Feed bytes into the hasher.
    #[inline]
    pub(crate) fn write(&mut self, bytes: &[u8]) {
        self.h.update(bytes);
        self.len += bytes.len();
    }

    /// Finalize as HASH256.
    #[inline]
    pub(crate) fn finish(self) -> [u8; 32] {
        let h1 = self.h.finalize();
        let h2 = Sha256::digest(h1);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h2);
        out
    }
}

/// Write a Bitcoin CompactSize integer into a streaming hasher.
///
/// Used for the SegWit txid hash where we rebuild the "stripped" serialization on the fly.
#[inline]
pub(crate) fn write_varint_hasher(out: &mut Dsha256Writer, n: u64) {
    match n {
        0x00..=0xfc => out.write(&[n as u8]),
        0xfd..=0xffff => {
            out.write(&[0xfdu8]);
            out.write(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.write(&[0xfeu8]);
            out.write(&(n as u32).to_le_bytes());
        }
        _ => {
            out.write(&[0xffu8]);
            out.write(&n.to_le_bytes());
        }
    }
}

/// Read a Bitcoin CompactSize integer.
///
/// Returns `u64` so callers can range-check safely before casting to `usize`.
pub(crate) fn read_varint(c: &mut Cursor) -> Result<u64, String> {
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
