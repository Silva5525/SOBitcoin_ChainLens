// ============================================================================
// src/btc/tx/util.rs
// Low-level utils (cursor, hex, hashing, varints, address encoding)
// ============================================================================
//!
//! Low-level helpers used by the TX parser and report builder.
//!
//! Most functions here are "leaf" utilities: hex, varints, hashing, cursor reads,

use bech32::{ToBase32, Variant}; // Import Bech32 traits + variant enum (Bech32 vs Bech32m)
use bs58; // Import Base58 encoding crate (used for legacy addresses)
use sha2::{Digest, Sha256}; // Import SHA256 hasher + Digest trait

/// A bounds-checked cursor over a byte slice.
///
/// The parser uses this to avoid panics and to produce clean errors
/// for truncated or malformed transactions.
pub(crate) struct Cursor<'a> { // Cursor struct borrowing a byte slice
    b: &'a [u8], // Underlying byte buffer
    i: usize, // Current read position (index into buffer)
}

impl<'a> Cursor<'a> {
    /// Create a new cursor starting at byte 0.
    pub(crate) fn new(b: &'a [u8]) -> Self { // Constructor
        Self { b, i: 0 } // Initialize with index at 0
    }

    /// Step back by one byte.
    ///
    /// Used after peeking the SegWit marker byte when the tx is not SegWit.
    pub(crate) fn backtrack_1(&mut self) -> Result<(), String> { // Move cursor one byte backwards
        if self.i == 0 { // Prevent underflow
            return Err("cursor underflow".into()); // Error if already at start
        }
        self.i -= 1; // Decrement index
        Ok(()) // Return success
    }

    /// Take `n` bytes and advance the cursor.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], String> { // Read slice of length n
        if self.i + n > self.b.len() { // Bounds check
            return Err("unexpected EOF".into()); // Error if not enough bytes
        }
        let s = &self.b[self.i..self.i + n]; // Slice requested range
        self.i += n; // Advance cursor
        Ok(s) // Return slice
    }

    /// Read one byte.
    pub(crate) fn take_u8(&mut self) -> Result<u8, String> { // Convenience wrapper for 1-byte read
        Ok(self.take(1)?[0]) // Read 1 byte and extract first element
    }

    /// Read a 32-bit little-endian integer.
    pub(crate) fn take_u32_le(&mut self) -> Result<u32, String> { // Read 4 bytes LE
        let s = self.take(4)?; // Take 4 bytes
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]])) // Convert to u32 (LE)
    }

    /// Read a 64-bit little-endian integer.
    pub(crate) fn take_u64_le(&mut self) -> Result<u64, String> { // Read 8 bytes LE
        let s = self.take(8)?; // Take 8 bytes
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], // Convert to u64 (LE)
        ]))
    }

    /// Number of bytes remaining in the input.
    pub(crate) fn remaining(&self) -> usize { // Return unread byte count
        self.b.len().saturating_sub(self.i) // Total length minus current index (overflow-safe)
    }
}

/// Decode strict hex string into bytes.
pub(crate) fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> { // Convert hex string → Vec<u8>
    hex::decode(hex).map_err(|_| "invalid hex".to_string()) // Use hex crate and map error to String
}

/// Encode bytes into lowercase hex.
pub(crate) fn bytes_to_hex(b: &[u8]) -> String { // Convert bytes → hex string
    hex::encode(b) // Use hex crate encoder
}

/// Bitcoin HASH256 (double-SHA256).
pub(crate) fn dsha256(data: &[u8]) -> [u8; 32] { // Compute SHA256(SHA256(data))
    let h1 = Sha256::digest(data); // First SHA256 round
    let h2 = Sha256::digest(h1); // Second SHA256 round
    let mut out = [0u8; 32]; // Allocate 32-byte array
    out.copy_from_slice(&h2); // Copy hash into array
    out // Return 32-byte hash
}

/// Convert internal little-endian hash bytes into the standard display hex.
///
/// Bitcoin displays txid/block hashes as big-endian hex.
pub(crate) fn hash_to_display_hex(mut hash: [u8; 32]) -> String { // Convert LE hash → display hex
    hash.reverse(); // Reverse byte order (LE → BE)
    bytes_to_hex(&hash) // Encode as hex string
}

/// Address encoding parameters for a network.
#[derive(Clone, Copy)] // Copyable small struct
struct NetParams { // Holds version bytes + HRP
    p2pkh_prefix: u8, // Base58 version for P2PKH
    p2sh_prefix: u8, // Base58 version for P2SH
    bech32_hrp: &'static str, // Human-readable part for Bech32
}

/// Map a `network` string to address parameters.
///
/// Note: for simplicity, signet/regtest use the `tb` HRP here.
fn net_params(network: &str) -> Result<NetParams, String> { // Convert network label → NetParams
    match network { // Match known network aliases
        "main" | "mainnet" | "bitcoin" => Ok(NetParams { // Mainnet variants
            p2pkh_prefix: 0x00, // Mainnet P2PKH prefix
            p2sh_prefix: 0x05, // Mainnet P2SH prefix
            bech32_hrp: "bc", // Mainnet Bech32 HRP
        }),
        "test" | "testnet" | "signet" | "regtest" => Ok(NetParams { // Test-like networks
            p2pkh_prefix: 0x6f, // Testnet P2PKH prefix
            p2sh_prefix: 0xc4, // Testnet P2SH prefix
            bech32_hrp: "tb", // Testnet Bech32 HRP
        }),
        _ => Err(format!("unsupported network: {network}")), // Error for unknown network
    }
}

/// Base58Check encode: version byte + payload + 4-byte checksum.
fn base58check(version: u8, payload: &[u8]) -> String { // Build Base58Check string
    let mut buf = Vec::with_capacity(1 + payload.len() + 4); // Allocate buffer (version + payload + checksum)
    buf.push(version); // Add version byte
    buf.extend_from_slice(payload); // Add payload bytes
    let chk = dsha256(&buf); // Compute double-SHA256 checksum
    buf.extend_from_slice(&chk[0..4]); // Append first 4 checksum bytes
    bs58::encode(buf).into_string() // Encode whole buffer into Base58 string
}

/// Encode a SegWit address as bech32/bech32m.
///
/// - witness version 0 => bech32 (BIP173)
/// - witness version 1+ => bech32m (BIP350)
fn bech32_witness_addr(hrp: &str, witver: u8, program: &[u8]) -> Result<String, String> { // Build Bech32 address
    if witver > 16 { // Witness version must be 0..16
        return Err("invalid witness version".into());
    }
    if program.len() < 2 || program.len() > 40 { // Witness program length must be 2..40 bytes
        return Err("invalid witness program length".into());
    }

    let variant = if witver == 0 { // Version 0 uses classic Bech32
        Variant::Bech32
    } else { // Version >=1 uses Bech32m
        Variant::Bech32m
    };

    let mut data = Vec::with_capacity(1 + (program.len() * 8 + 4) / 5); // Pre-allocate base32 data buffer
    data.push(
        bech32::u5::try_from_u8(witver).map_err(|_| "invalid witver".to_string())?, // Convert version to 5-bit value
    );
    data.extend_from_slice(&program.to_base32()); // Convert program bytes to base32 and append

    bech32::encode(hrp, data, variant).map_err(|e| format!("bech32 encode error: {e}")) // Encode final address string
}

/// Best-effort address extraction from common scriptPubKey templates.
///
/// Returns `Ok(None)` for scripts that don't have a standard address encoding.
pub(crate) fn address_from_spk(network: &str, spk: &[u8]) -> Result<Option<String>, String> { // Try to derive address
    let p = net_params(network)?; // Resolve network parameters

    if crate::btc::tx::script::is_p2pkh_spk(spk) { // If P2PKH
        let h160 = &spk[3..23]; // Extract 20-byte HASH160
        return Ok(Some(base58check(p.p2pkh_prefix, h160))); // Encode Base58Check
    }
    if crate::btc::tx::script::is_p2sh_spk(spk) { // If P2SH
        let h160 = &spk[2..22]; // Extract HASH160
        return Ok(Some(base58check(p.p2sh_prefix, h160))); // Encode Base58Check
    }
    if crate::btc::tx::script::is_p2wpkh_spk(spk) { // If P2WPKH
        let prog = &spk[2..22]; // Extract witness program
        return Ok(Some(bech32_witness_addr(p.bech32_hrp, 0, prog)?)); // Encode Bech32
    }
    if crate::btc::tx::script::is_p2wsh_spk(spk) { // If P2WSH
        let prog = &spk[2..34]; // Extract witness program
        return Ok(Some(bech32_witness_addr(p.bech32_hrp, 0, prog)?)); // Encode Bech32
    }
    if crate::btc::tx::script::is_p2tr_spk(spk) { // If Taproot (v1)
        let prog = &spk[2..34]; // Extract 32-byte program
        return Ok(Some(bech32_witness_addr(p.bech32_hrp, 1, prog)?)); // Encode Bech32m
    }

    Ok(None) // No recognized address format
}

/// A streaming HASH256 writer.
///
/// This lets us compute the SegWit txid (hash of the *stripped* serialization)
/// without allocating a full "stripped transaction" buffer.
pub(crate) struct Dsha256Writer { // Streaming double-SHA256 helper
    h: Sha256, // First SHA256 state
    /// Number of bytes written into the first SHA256 round.
    pub(crate) len: usize, // Track number of stripped bytes hashed
}

impl Dsha256Writer {
    /// New streaming writer.
    #[inline]
    pub(crate) fn new() -> Self { // Constructor
        Self {
            h: Sha256::new(), // Initialize SHA256 state
            len: 0, // Initialize byte counter
        }
    }

    /// Feed bytes into the hasher.
    #[inline]
    pub(crate) fn write(&mut self, bytes: &[u8]) { // Add bytes to hash stream
        self.h.update(bytes); // Update SHA256 state
        self.len += bytes.len(); // Increase byte counter
    }

    /// Finalize as HASH256.
    #[inline]
    pub(crate) fn finish(self) -> [u8; 32] { // Complete double-SHA256
        let h1 = self.h.finalize(); // Finish first SHA256
        let h2 = Sha256::digest(h1); // Second SHA256 round
        let mut out = [0u8; 32]; // Allocate output buffer
        out.copy_from_slice(&h2); // Copy result
        out // Return final hash
    }
}

/// Write a Bitcoin CompactSize integer into a streaming hasher.
///
/// Used for the SegWit txid hash where we rebuild the "stripped" serialization on the fly.
#[inline]
pub(crate) fn write_varint_hasher(out: &mut Dsha256Writer, n: u64) { // Serialize varint into hash stream
    match n { // Choose encoding based on value range
        0x00..=0xfc => out.write(&[n as u8]), // Single-byte encoding
        0xfd..=0xffff => { // 0xfd prefix + 2 bytes
            out.write(&[0xfdu8]);
            out.write(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => { // 0xfe prefix + 4 bytes
            out.write(&[0xfeu8]);
            out.write(&(n as u32).to_le_bytes());
        }
        _ => { // 0xff prefix + 8 bytes
            out.write(&[0xffu8]);
            out.write(&n.to_le_bytes());
        }
    }
}

/// Read a Bitcoin CompactSize integer.
///
/// Returns `u64` so callers can range-check safely before casting to `usize`.
pub(crate) fn read_varint(c: &mut Cursor) -> Result<u64, String> { // Parse CompactSize integer
    let n = c.take_u8()? as u64; // Read first prefix byte
    match n { // Interpret based on prefix
        0x00..=0xfc => Ok(n), // Single-byte value
        0xfd => { // Next 2 bytes are value
            let s = c.take(2)?; // Read 2 bytes
            Ok(u16::from_le_bytes([s[0], s[1]]) as u64) // Convert LE → u16 → u64
        }
        0xfe => Ok(c.take_u32_le()? as u64), // Next 4 bytes
        0xff => Ok(c.take_u64_le()?), // Next 8 bytes
        _ => Err("invalid varint prefix".into()), // Fallback (should not occur)
    }
}
