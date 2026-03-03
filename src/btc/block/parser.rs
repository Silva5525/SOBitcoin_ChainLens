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

use sha2::{Digest, Sha256}; // Import SHA256 hashing primitives from sha2 crate

/// Helper to build structured error strings with a stable code prefix.
fn err(code: &str, msg: impl AsRef<str>) -> String { // Create formatted error string
    format!("{code}: {}", msg.as_ref()) // Prefix message with error code
}

/// Sanity-check upper bounds for length/count fields.
///
/// This protects against pathological allocations or maliciously large fields
/// in corrupted blk/rev data.
pub(crate) fn ensure_len(kind: &str, field: &str, val: u64, max: u64) -> Result<(), String> { // Validate that a parsed length is reasonable
    if val > max { // If parsed value exceeds allowed maximum
        return Err(err( // Return structured error
            "INSANE_LEN", // Error code
            format!("{kind}: {field} too large: {val} > {max}"), // Detailed message
        ));
    }
    Ok(()) // Otherwise accept value
}

/// Zero-copy byte cursor over a block/transaction buffer.
///
/// Maintains a position index and provides LE helpers for primitive types.
pub(crate) struct Cursor<'a> { // Lightweight cursor that borrows underlying byte slice
    pub(crate) b: &'a [u8], // Underlying byte slice
    pub(crate) i: usize,    // Current offset within slice
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self { // Construct cursor at position 0
        Self { b, i: 0 } // Initialize fields
    }

    pub(crate) fn pos(&self) -> usize { // Return current offset
        self.i
    }

    pub(crate) fn remaining(&self) -> usize { // Return number of unread bytes
        self.b.len().saturating_sub(self.i) // Prevent underflow
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], String> { // Take n bytes and advance cursor
        if self.i + n > self.b.len() { // If request exceeds available bytes
            return Err(err( // Return EOF error
                "UNEXPECTED_EOF",
                format!(
                    "unexpected EOF at pos={} need={} have_remaining={}",
                    self.i,
                    n,
                    self.b.len().saturating_sub(self.i)
                ),
            ));
        }
        let s = &self.b[self.i..self.i + n]; // Slice requested bytes
        self.i += n; // Advance cursor
        Ok(s) // Return slice
    }

    pub(crate) fn take_u8(&mut self) -> Result<u8, String> { // Read one byte
        Ok(self.take(1)?[0]) // Take 1 byte and return as u8
    }

    pub(crate) fn take_u16_le(&mut self) -> Result<u16, String> { // Read little-endian u16
        let s = self.take(2)?; // Take 2 bytes
        Ok(u16::from_le_bytes([s[0], s[1]])) // Convert to u16
    }

    pub(crate) fn take_u32_le(&mut self) -> Result<u32, String> { // Read little-endian u32
        let s = self.take(4)?; // Take 4 bytes
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]])) // Convert
    }

    pub(crate) fn take_u64_le(&mut self) -> Result<u64, String> { // Read little-endian u64
        let s = self.take(8)?; // Take 8 bytes
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ])) // Convert
    }
}

/// Encode raw bytes as lowercase hex.
pub(crate) fn bytes_to_hex(b: &[u8]) -> String { // Convert bytes to hex string
    hex::encode(b) // Use hex crate
}

/// Bitcoin-style double SHA256.
pub(crate) fn dsha256(data: &[u8]) -> [u8; 32] { // Compute SHA256(SHA256(data))
    let h1 = Sha256::digest(data); // First SHA256
    let h2 = Sha256::digest(h1);   // Second SHA256
    let mut out = [0u8; 32]; // Allocate fixed-size array
    out.copy_from_slice(&h2); // Copy digest bytes
    out // Return hash
}

/// Convert internal little-endian hash to display hex (big-endian).
pub(crate) fn hash_to_display_hex(hash_le: [u8; 32]) -> String { // Convert LE hash to display format
    let mut be = hash_le; // Copy input
    be.reverse(); // Reverse to big-endian
    bytes_to_hex(&be) // Convert to hex
}

/// Read Bitcoin CompactSize (VarInt) from a Cursor.
pub(crate) fn read_varint(c: &mut Cursor) -> Result<u64, String> { // Decode varint
    let first = c.take_u8()? as u64; // Read first prefix byte
    match first { // Match prefix
        0x00..=0xfc => Ok(first), // Small value stored directly
        0xfd => Ok(c.take_u16_le()? as u64), // Next 2 bytes
        0xfe => Ok(c.take_u32_le()? as u64), // Next 4 bytes
        0xff => Ok(c.take_u64_le()?), // Next 8 bytes
        _ => Err(err("INVALID_VARINT", "invalid varint prefix")), // Defensive fallback
    }
}

// ------------------------------------------------------------
// Hot-path helpers (max speed)
// ------------------------------------------------------------

#[inline] // Hint compiler to inline
pub(crate) fn read_varint_bytes(input: &mut &[u8]) -> Result<u64, String> { // Decode varint directly from slice
    if input.is_empty() { // No bytes available
        return Err(err("UNEXPECTED_EOF", "varint: empty input")); // Error
    }
    let first = input[0]; // Peek first byte
    *input = &input[1..]; // Advance slice by 1

    match first { // Decode based on prefix
        0x00..=0xfc => Ok(first as u64),
        0xfd => {
            if input.len() < 2 { // Need 2 bytes
                return Err(err("UNEXPECTED_EOF", "varint: 0xfd missing 2 bytes"));
            }
            let v = u16::from_le_bytes([input[0], input[1]]) as u64; // Decode
            *input = &input[2..]; // Advance
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

#[inline] // Inline for speed
pub(crate) fn block_tx_count_fast(block_payload: &[u8]) -> Result<u64, String> { // Quickly extract tx_count
    if block_payload.len() < 81 { // Need at least 80 header + 1 varint byte
        return Err(err("UNEXPECTED_EOF", "block: too small for header + tx_count"));
    }
    let mut cur = &block_payload[80..]; // Skip 80-byte header
    let txc = read_varint_bytes(&mut cur)?; // Read tx_count
    ensure_len("block", "tx_count", txc, 200_000)?; // Sanity bound
    Ok(txc) // Return tx_count
}

#[inline]
fn sha256d_finish(h: Sha256) -> [u8; 32] { // Finalize streaming SHA256 and apply second round
    let h1 = h.finalize(); // Finish first round
    let h2 = Sha256::digest(h1); // Second SHA256
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

#[inline]
fn sha256_update_varint(h: &mut Sha256, n: u64) { // Encode a CompactSize integer exactly as Bitcoin would serialize it, but directly into a SHA256 stream
    // IMPORTANT: When computing a txid for SegWit transactions,
    // we must hash the "stripped" serialization byte-for-byte identical
    // to how it appears on the wire (except witness). That includes
    // encoding the varint prefix correctly.

    match n { // Choose encoding based on numeric range (Bitcoin CompactSize rules)
        0x00..=0xfc => {
            // For values 0..252: encoded as a single byte
            h.update([n as u8]); // Write that single byte into the hash stream
        }
        0xfd..=0xffff => {
            // For values 253..65535:
            // prefix 0xfd followed by 2-byte little-endian integer
            h.update([0xfd]); // Write marker byte
            h.update((n as u16).to_le_bytes()); // Write 2-byte LE payload
        }
        0x1_0000..=0xffff_ffff => {
            // For values 65536..4294967295:
            // prefix 0xfe followed by 4-byte little-endian integer
            h.update([0xfe]); // Write marker byte
            h.update((n as u32).to_le_bytes()); // Write 4-byte LE payload
        }
        _ => {
            // For larger values:
            // prefix 0xff followed by full 8-byte little-endian integer
            h.update([0xff]); // Write marker byte
            h.update(n.to_le_bytes()); // Write 8-byte LE payload
        }
    }
}

pub(crate) fn merkle_root(txids_le: &[[u8; 32]]) -> [u8; 32] { // Compute Bitcoin merkle root
    if txids_le.is_empty() { // Empty block edge case
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = txids_le.to_vec(); // Copy txids into mutable vector
    while level.len() > 1 { // Repeat until one hash remains
        if level.len() % 2 == 1 { // If odd number of elements
            level.push(*level.last().unwrap()); // Duplicate last element (Bitcoin rule)
        }
        let mut next = Vec::with_capacity(level.len() / 2); // Next level storage
        for pair in level.chunks(2) { // Process pairs
            let mut buf = [0u8; 64]; // 64-byte buffer
            buf[..32].copy_from_slice(&pair[0]); // First hash
            buf[32..].copy_from_slice(&pair[1]); // Second hash
            next.push(dsha256(&buf)); // Hash pair
        }
        level = next; // Move to next level
    }
    level[0] // Final root
}

pub(crate) fn parse_tx_skip_and_txid_le(
    block: &[u8], // Full block buffer
    bc: &mut Cursor, // Cursor positioned at tx start
) -> Result<[u8; 32], String> { // Return txid
    let (txid, _vin_count) = parse_tx_skip_and_txid_le_and_vin_count(block, bc)?; // Call extended version
    Ok(txid) // Return only txid
}

pub(crate) fn parse_tx_skip_and_txid_le_and_vin_count(
    block: &[u8], // Full block buffer
    bc: &mut Cursor, // Cursor at tx start
) -> Result<([u8; 32], u64), String> { // Return (txid, vin_count)
    let start = bc.pos(); // Remember tx start offset

    let version = bc.take_u32_le()?; // Read version

    let peek = bc.take_u8()?; // Peek next byte
    let segwit = if peek == 0x00 { // Possible segwit marker
        let flag = bc.take_u8()?; // Read flag
        if flag != 0x01 { // Must be 0x01
            return Err(err("INVALID_TX", "invalid segwit flag"));
        }
        true // Segwit transaction
    } else {
        bc.i -= 1; // Rewind one byte
        false // Legacy transaction
    };

    if !segwit { // Legacy path
        let vin_count = read_varint(bc)?; // Read vin count
        ensure_len("tx", "vin_count", vin_count, 50_000)?; // Sanity bound
        for _ in 0..vin_count { // Skip inputs
            let _ = bc.take(32)?;
            let _ = bc.take(4)?;
            let script_len = read_varint(bc)?;
            ensure_len("tx", "script_sig_len", script_len, 1_000_000)?;
            let _ = bc.take(script_len as usize)?;
            let _ = bc.take(4)?;
        }

        let vout_count = read_varint(bc)?; // Read output count
        ensure_len("tx", "vout_count", vout_count, 50_000)?;
        for _ in 0..vout_count { // Skip outputs
            let _ = bc.take(8)?;
            let spk_len = read_varint(bc)?;
            ensure_len("tx", "script_pubkey_len", spk_len, 10_000)?;
            let _ = bc.take(spk_len as usize)?;
        }

        let _ = bc.take(4)?; // Skip locktime
        let end = bc.pos(); // End offset
        return Ok((dsha256(&block[start..end]), vin_count)); // Compute txid over full serialization
    }

    // Segwit path: stream stripped serialization
    let mut h = Sha256::new(); // Initialize SHA256 state
    h.update(version.to_le_bytes()); // Hash version

    let vin_count = read_varint(bc)?;
    ensure_len("tx", "vin_count", vin_count, 50_000)?;
    sha256_update_varint(&mut h, vin_count); // Hash vin count

    for _ in 0..vin_count { // Process inputs
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

    for _ in 0..vout_count { // Process outputs
        let value = bc.take(8)?;
        h.update(value);

        let spk_len = read_varint(bc)?;
        ensure_len("tx", "script_pubkey_len", spk_len, 10_000)?;
        sha256_update_varint(&mut h, spk_len);
        let spk = bc.take(spk_len as usize)?;
        h.update(spk);
    }

    for _ in 0..vin_count { // Skip witness data (not hashed into txid)
        let n_items = read_varint(bc)?;
        ensure_len("tx", "witness_item_count", n_items, 10_000)?;
        for _ in 0..n_items {
            let item_len = read_varint(bc)?;
            ensure_len("tx", "witness_item_len", item_len, 4_000_000)?;
            let _ = bc.take(item_len as usize)?;
        }
    }

    let lock = bc.take(4)?; // Read locktime
    h.update(lock); // Hash locktime

    Ok((sha256d_finish(h), vin_count)) // Return computed txid and vin_count
}

pub(crate) fn parse_tx_skip_and_vin_count(bc: &mut Cursor) -> Result<u64, String> { // Skip over a full transaction and return only vin_count (used when we do not need txid)
    let _version = bc.take_u32_le()?; // Read and ignore version (we only skip, not hash)

    let peek = bc.take_u8()?; // Peek next byte to detect SegWit marker
    let segwit = if peek == 0x00 { // 0x00 may indicate segwit marker
        let flag = bc.take_u8()?; // Read the flag byte
        if flag != 0x01 { // Valid segwit flag must be 0x01
            return Err(err("INVALID_TX", "invalid segwit flag")); // Reject malformed tx
        }
        true // This is a SegWit transaction
    } else {
        bc.i -= 1; // Not segwit → rewind one byte so varint can read it
        false // Legacy transaction
    };

    let vin_count = read_varint(bc)?; // Read number of inputs
    ensure_len("tx", "vin_count", vin_count, 50_000)?; // Sanity-check to avoid insane allocations

    // Skip all inputs (we do not store them, just move cursor forward)
    for _ in 0..vin_count {
        let _ = bc.take(32)?; // Skip prev txid
        let _ = bc.take(4)?;  // Skip prev vout
        let script_len = read_varint(bc)?; // Read scriptSig length
        ensure_len("tx", "script_sig_len", script_len, 1_000_000)?; // Bound script size
        let _ = bc.take(script_len as usize)?; // Skip scriptSig bytes
        let _ = bc.take(4)?; // Skip sequence
    }

    let vout_count = read_varint(bc)?; // Read number of outputs
    ensure_len("tx", "vout_count", vout_count, 50_000)?; // Sanity-check output count

    // Skip all outputs
    for _ in 0..vout_count {
        let _ = bc.take(8)?; // Skip value (8-byte LE)
        let spk_len = read_varint(bc)?; // Read scriptPubKey length
        ensure_len("tx", "script_pubkey_len", spk_len, 10_000)?; // Bound script size
        let _ = bc.take(spk_len as usize)?; // Skip scriptPubKey bytes
    }

    if segwit { // If segwit, witness section follows outputs
        for _ in 0..vin_count {
            let n_items = read_varint(bc)?; // Read number of witness stack items for this input
            ensure_len("tx", "witness_item_count", n_items, 10_000)?; // Sanity bound
            for _ in 0..n_items {
                let item_len = read_varint(bc)?; // Read witness item length
                ensure_len("tx", "witness_item_len", item_len, 4_000_000)?; // Bound witness size
                let _ = bc.take(item_len as usize)?; // Skip witness item bytes
            }
        }
    }

    let _ = bc.take(4)?; // Skip final locktime field
    Ok(vin_count) // Return only the number of inputs
}

pub(crate) fn decode_bip34_height(coinbase_script: &[u8]) -> u64 { // Decode block height from coinbase script
    if coinbase_script.is_empty() { // Empty script
        return 0; // Invalid
    }
    let n = coinbase_script[0] as usize; // First byte indicates push length
    if n == 0 || 1 + n > coinbase_script.len() || n > 8 { // Validate bounds
        return 0;
    }
    let mut val: u64 = 0; // Accumulate height
    for (i, b) in coinbase_script[1..1 + n].iter().enumerate() { // Read pushed bytes
        val |= (*b as u64) << (8 * i); // Little-endian decode
    }
    val // Return decoded height
}

pub(crate) fn coinbase_extract_script_and_outsum(raw_tx: &[u8]) -> Result<(Vec<u8>, u64), String> { // Extract scriptSig + output sum
    let mut c = Cursor::new(raw_tx); // Create cursor
    let _version = c.take_u32_le()?; // Skip version

    let p = c.take_u8()?; // Peek for segwit marker
    if p == 0x00 { // If marker present
        let _ = c.take_u8()?; // Consume flag
    } else {
        c.i -= 1; // Rewind if not segwit
    }

    let vin_n = read_varint(&mut c)?; // Read input count
    if vin_n != 1 { // Coinbase must have exactly one input
        return Err(err("INVALID_COINBASE", "coinbase must have exactly 1 input"));
    }

    let prev = c.take(32)?; // Read prev txid
    let vout = c.take_u32_le()?; // Read vout
    if prev.iter().any(|&b| b != 0) || vout != 0xffff_ffff { // Validate null outpoint
        return Err(err(
            "INVALID_COINBASE",
            "coinbase input outpoint must be (32x00, vout=0xffffffff)",
        ));
    }

    let script_len = read_varint(&mut c)? as usize; // Read scriptSig length
    let script = c.take(script_len)?.to_vec(); // Copy scriptSig bytes

    let _ = c.take(4)?; // Skip sequence

    let vout_n = read_varint(&mut c)?; // Read output count
    let mut outsum: u64 = 0; // Initialize output sum
    for _ in 0..vout_n { // Sum outputs
        let value = c.take_u64_le()?;
        outsum = outsum.saturating_add(value);
        let spk_len = read_varint(&mut c)? as usize;
        let _ = c.take(spk_len)?;
    }

    Ok((script, outsum)) // Return (coinbase_script, total_output_sats)
}
