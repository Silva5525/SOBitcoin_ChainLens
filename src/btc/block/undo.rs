// src/btc/block/undo.rs
//
// Strict + fast parser for Bitcoin Core `rev*.dat` undo payloads (CBlockUndo).
//
// Goals:
//   - Zero-copy where possible (ScriptSlice over undo payload or arena).
//   - Fast structural validation for blk↔rev pairing.
//   - Optional strict materialization (amount + script reconstruction).
//
// This mirrors Bitcoin Core serialization semantics (serialize.h, ScriptCompressor),
// but is optimized for analysis rather than full node validation.

use super::parser; // Use block parser utilities (Cursor, ensure_len, varint helpers, tx skip)

use k256::elliptic_curve::sec1::ToEncodedPoint; // Needed to convert k256 PublicKey into SEC1 encoded bytes
use k256::PublicKey; // Used to decompress secp256k1 pubkeys for ScriptCompressor formats 4/5

// -----------------------------------------------------------------------------
// Zero-copy script representation
// -----------------------------------------------------------------------------

/// Identifies where the script bytes live.
///
/// - `Undo`: raw bytes inside the original undo payload.
/// - `Arena`: reconstructed/expanded script stored in a shared arena buffer.
#[allow(dead_code)] // Some variants are only used in certain build paths
#[derive(Debug, Clone, Copy)] // Small copyable enum for cheap passing
pub(crate) enum ScriptSrc {
    Undo,  // Script bytes live inside undo payload
    Arena, // Script bytes live inside the arena buffer
}

/// A zero-copy slice descriptor for a scriptPubKey.
///
/// Instead of allocating `Vec<u8>` per script, we store (src, start, len).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScriptSlice {
    pub src: ScriptSrc, // Which backing buffer holds the bytes
    pub start: usize,   // Start offset within that buffer
    pub len: usize,     // Length in bytes
}

#[allow(dead_code)]
impl ScriptSlice {
    /// Materialize the slice as `&[u8]` using either undo payload or arena.
    #[inline]
    pub fn as_slice<'a>(&self, undo_payload: &'a [u8], arena: &'a [u8]) -> &'a [u8] {
        match self.src { // Choose the backing buffer based on ScriptSrc
            ScriptSrc::Undo => &undo_payload[self.start..self.start + self.len], // Borrow from raw undo bytes
            ScriptSrc::Arena => &arena[self.start..self.start + self.len], // Borrow from reconstructed arena
        }
    }
}

/// For each non-coinbase tx: a list of (value_sats, ScriptSlice) per input.
#[allow(dead_code)]
type UndoPrevoutsSlices = Vec<Vec<(u64, ScriptSlice)>>; // Outer Vec: per tx, inner Vec: per input

// -----------------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------------

/// Build a prefixed error string.
fn err(code: &str, msg: impl AsRef<str>) -> String {
    format!("{code}: {}", msg.as_ref()) // Keep error strings machine-parsable by prefixing code
}

/// Enforce an upper bound for length-like fields.
fn ensure_len(kind: &str, field: &str, val: u64, max: u64) -> Result<(), String> {
    parser::ensure_len(kind, field, val, max) // Delegate to shared parser bound-check helper
}

/// Read Bitcoin Core base-128 VarInt (serialize.h semantics).
///
/// NOTE: This is *not* Bitcoin CompactSize. Core's VarInt here is used by ScriptCompressor and Undo.
fn read_varint_core(c: &mut parser::Cursor) -> Result<u64, String> {
    let mut n: u64 = 0; // Accumulator
    loop {
        let ch = c.take_u8()? as u64; // Read next byte
        let data = ch & 0x7f; // Lower 7 bits carry data
        n = (n << 7) | data; // Shift previous bits and append new 7-bit chunk
        if (ch & 0x80) != 0 { // High bit set means: more bytes follow
            n = n
                .checked_add(1) // Core varint adds 1 when continuation bit is set (serialize.h behavior)
                .ok_or_else(|| err("VARINT_OVERFLOW", "core varint overflow"))?;
            continue; // Keep reading bytes
        }
        return Ok(n); // High bit not set: end of varint
    }
}

/// Read Bitcoin CompactSize integer.
///
/// Used for: CBlockUndo.nTxUndo and per-CTxUndo vin count.
fn read_compactsize(c: &mut parser::Cursor) -> Result<u64, String> {
    let first = c.take_u8()?; // Read prefix byte
    match first {
        0x00..=0xfc => Ok(first as u64), // Direct encoding for 0..252
        0xfd => Ok(c.take_u16_le()? as u64), // 0xfd + u16 LE
        0xfe => Ok(c.take_u32_le()? as u64), // 0xfe + u32 LE
        0xff => Ok(c.take_u64_le()?),        // 0xff + u64 LE
    }
}

// -----------------------------------------------------------------------------
// Hot-path helpers (used during blk↔rev pairing)
// -----------------------------------------------------------------------------

/// Ultra-cheap read of `nTxUndo` from a CBlockUndo payload.
///
/// Only reads the leading CompactSize and enforces a sanity bound.
#[inline]
pub(crate) fn undo_txundo_count_fast(undo_payload: &[u8]) -> Result<u64, String> {
    let mut c = parser::Cursor::new(undo_payload); // Cursor over undo bytes
    let n = read_compactsize(&mut c)?; // Read CompactSize(nTxUndo)
    ensure_len("undo", "n_txundo", n, 200_000)?; // Bound count to avoid insane loops
    Ok(n)
}

/// Byte-slice variant of `undo_txundo_count_fast`.
///
/// Avoids constructing a Cursor and advances the input slice.
#[inline]
#[allow(dead_code)]
pub(crate) fn undo_txundo_count_fast_bytes(input: &mut &[u8]) -> Result<u64, String> {
    if input.is_empty() {
        return Err(err("COMPACTSIZE_EOF", "empty input"));
    }
    let first = input[0]; // Prefix byte
    *input = &input[1..]; // Advance slice by 1

    let n = match first {
        0x00..=0xfc => first as u64,
        0xfd => {
            if input.len() < 2 {
                return Err(err("COMPACTSIZE_EOF", "0xfd but missing 2 bytes"));
            }
            let v = u16::from_le_bytes([input[0], input[1]]) as u64; // Decode LE u16
            *input = &input[2..]; // Advance
            v
        }
        0xfe => {
            if input.len() < 4 {
                return Err(err("COMPACTSIZE_EOF", "0xfe but missing 4 bytes"));
            }
            let v = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as u64; // Decode LE u32
            *input = &input[4..]; // Advance
            v
        }
        0xff => {
            if input.len() < 8 {
                return Err(err("COMPACTSIZE_EOF", "0xff but missing 8 bytes"));
            }
            let v = u64::from_le_bytes([
                input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
            ]); // Decode LE u64
            *input = &input[8..]; // Advance
            v
        }
    };

    ensure_len("undo", "n_txundo", n, 200_000)?; // Same sanity check
    Ok(n)
}

// -----------------------------------------------------------------------------
// Amount + script decompression (Core-compatible)
// -----------------------------------------------------------------------------

/// Decompress Bitcoin Core's compressed amount format.
///
/// This is used in undo to store satoshi amounts compactly.
fn decompress_amount(x: u64) -> u64 {
    if x == 0 {
        return 0; // Special-case: 0 stays 0
    }
    let mut x = x - 1; // Core format uses (x-1) internally
    let e = (x % 10) as u32; // Exponent (number of trailing zeros)
    x /= 10; // Remove exponent digit

    let mut n: u64;
    if e < 9 {
        let d = (x % 9) + 1; // Digit 1..9
        x /= 9;
        n = x * 10 + d; // Rebuild base number
    } else {
        n = x + 1; // Special case when exponent==9
    }

    for _ in 0..e {
        n *= 10; // Apply trailing zeros
    }
    n
}

/// Reconstruct uncompressed pubkey (65 bytes) from X coordinate + parity.
///
/// ScriptCompressor stores some P2PK scripts as (x, parity) and we rebuild 65-byte pubkey.
fn decompress_uncompressed_pubkey_from_x(x32: &[u8], y_is_odd: bool) -> Result<Vec<u8>, String> {
    if x32.len() != 32 {
        return Err(err("INVALID_PUBKEY", "x32 must be 32 bytes"));
    }

    let mut comp = [0u8; 33]; // Build compressed pubkey bytes
    comp[0] = if y_is_odd { 0x03 } else { 0x02 }; // Prefix indicates parity
    comp[1..].copy_from_slice(x32); // Copy x coordinate

    let pk = PublicKey::from_sec1_bytes(&comp) // Let k256 compute the y coordinate on the curve
        .map_err(|_| err("INVALID_PUBKEY", "failed to decompress pubkey from x"))?;

    let enc = pk.to_encoded_point(false); // Request uncompressed SEC1 encoding
    let bytes = enc.as_bytes(); // Borrow encoded bytes
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(err("INVALID_PUBKEY", "unexpected uncompressed encoding"));
    }

    Ok(bytes.to_vec()) // Return owned bytes for arena append
}

// -----------------------------------------------------------------------------
// Strict zero-copy parsing
// -----------------------------------------------------------------------------

/// Read one compressed script and return a zero-copy ScriptSlice.
///
/// ScriptCompressor encoding:
///   0 -> P2PKH (20 bytes hash160)
///   1 -> P2SH  (20 bytes hash160)
///   2/3 -> P2PK compressed (32-byte X + prefix)
///   4/5 -> P2PK uncompressed (32-byte X + parity)
///   >=6 -> raw script of length (nsize-6)
#[allow(dead_code)]
fn read_compressed_script_slice(c: &mut parser::Cursor, arena: &mut Vec<u8>) -> Result<ScriptSlice, String> {
    let nsize = read_varint_core(c)?; // Read Core base-128 varint script "type/size" code

    match nsize {
        0 => {
            // P2PKH
            let h160 = c.take(20)?; // Read hash160
            let start = arena.len(); // Remember arena start
            arena.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 PUSH20
            arena.extend_from_slice(h160); // 20-byte pubkey-hash
            arena.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
            let len = arena.len() - start; // Compute appended length
            Ok(ScriptSlice { src: ScriptSrc::Arena, start, len }) // Script bytes live in arena
        }
        1 => {
            // P2SH
            let h160 = c.take(20)?;
            let start = arena.len();
            arena.extend_from_slice(&[0xa9, 0x14]); // OP_HASH160 PUSH20
            arena.extend_from_slice(h160);
            arena.push(0x87); // OP_EQUAL
            let len = arena.len() - start;
            Ok(ScriptSlice { src: ScriptSrc::Arena, start, len })
        }
        2 | 3 => {
            // P2PK (compressed)
            let x = c.take(32)?; // X coordinate
            let prefix = if nsize == 2 { 0x02 } else { 0x03 }; // Even/odd prefix
            let start = arena.len();
            arena.push(0x21); // PUSH33
            arena.push(prefix); // Pubkey prefix
            arena.extend_from_slice(x); // Pubkey X
            arena.push(0xac); // OP_CHECKSIG
            let len = arena.len() - start;
            Ok(ScriptSlice { src: ScriptSrc::Arena, start, len })
        }
        4 | 5 => {
            // P2PK (uncompressed)
            let x = c.take(32)?; // X coordinate
            let y_is_odd = nsize == 5; // 4=even, 5=odd
            let pubkey65 = decompress_uncompressed_pubkey_from_x(x, y_is_odd)?; // Expand to 65-byte uncompressed
            let start = arena.len();
            arena.push(0x41); // PUSH65
            arena.extend_from_slice(&pubkey65); // 65-byte pubkey
            arena.push(0xac); // OP_CHECKSIG
            let len = arena.len() - start;
            Ok(ScriptSlice { src: ScriptSrc::Arena, start, len })
        }
        _ => {
            if nsize < 6 {
                return Err(err("INVALID_SCRIPT_COMPRESSION", "nsize < 6 unexpected"));
            }

            let raw_len_u64 = nsize - 6; // Raw script length
            ensure_len("undo", "compressed_script_raw_len", raw_len_u64, 100_000)?; // Bound script length

            let raw_len: usize = usize::try_from(raw_len_u64) // Convert to usize
                .map_err(|_| err("LEN_OVERFLOW", format!("raw_len too large for usize: {raw_len_u64}")))?;

            let start = c.pos(); // Start offset within undo payload
            let _ = c.take(raw_len)?; // Advance cursor over raw bytes
            Ok(ScriptSlice { src: ScriptSrc::Undo, start, len: raw_len }) // Reference raw bytes directly
        }
    }
}

/// Read one CTxUndo input entry (value + script).
///
/// Structure mirrors Bitcoin Core's CTxInUndo serialization.
#[allow(dead_code)]
fn read_one_inundo_slice(rc: &mut parser::Cursor, arena: &mut Vec<u8>) -> Result<(u64, ScriptSlice), String> {
    let ncode = read_varint_core(rc)?; // Core varint encoding of (height, is_coinbase) style field
    let height = ncode >> 1; // Height is stored in high bits

    if height > 0 {
        let _tx_version = read_varint_core(rc)?; // If height>0, a tx version field is present
    }

    let comp_amt = read_varint_core(rc)?; // Compressed amount
    let spk = read_compressed_script_slice(rc, arena)?; // Compressed script → ScriptSlice
    let value_sats = decompress_amount(comp_amt); // Convert to satoshis

    if spk.len > 100_000 {
        return Err(err("INSANE_LEN", format!("spk too large: {}", spk.len)));
    }

    Ok((value_sats, spk)) // Return (value, script)
}

/// Strictly parse full undo payload into zero-copy slices.
#[allow(dead_code)]
pub(crate) fn parse_undo_payload_strict_slices(
    undo_payload: &[u8], // Raw undo payload for one block
    vin_counts_non_cb: &[u64], // Expected vin counts for each non-coinbase tx
    arena: &mut Vec<u8>, // Shared arena for reconstructed scripts
) -> Result<UndoPrevoutsSlices, String> {
    let mut uc = parser::Cursor::new(undo_payload); // Cursor over undo bytes
    let v = read_undo_for_block_from_cursor_slices(&mut uc, vin_counts_non_cb, arena)?; // Parse everything
    if uc.remaining() != 0 {
        return Err(err(
            "UNDO_TRAILING_BYTES",
            format!("undo payload has {} trailing bytes", uc.remaining()),
        )); // Strict: payload must end exactly
    }
    Ok(v)
}

// -----------------------------------------------------------------------------
// Fast structural validation (no allocations)
// -----------------------------------------------------------------------------

/// Extract CompactSize(vin_count) from a raw transaction slice.
///
/// Used for validating undo payload structure against parsed block txs.
pub(crate) fn extract_vin_count(raw_tx: &[u8]) -> Result<u64, String> {
    let mut c = parser::Cursor::new(raw_tx); // Cursor over tx bytes
    let _ver = c.take_u32_le()?; // Skip version

    // SegWit marker+flag (0x00 0x01) may be present.
    let p = c.take_u8()?; // Peek next byte
    if p == 0x00 {
        let _f = c.take_u8()?; // Consume flag (we only need to reach vin_count)
    } else {
        c.i -= 1; // Not segwit: rewind
    }

    parser::read_varint(&mut c) // Read vin_count (Bitcoin CompactSize)
}

/// Convenience wrapper for callers that already have the tx as a slice.
#[inline]
pub(crate) fn extract_vin_count_from_slice(raw_tx: &[u8]) -> Result<u64, String> {
    extract_vin_count(raw_tx) // Just forward to extract_vin_count
}

/// Skip a ScriptCompressor-compressed script without allocating.
#[inline]
fn skip_compressed_script(rc: &mut parser::Cursor) -> Result<(), String> {
    let nsize = read_varint_core(rc)?; // Core base-128 varint code

    match nsize {
        0 | 1 => {
            let _ = rc.take(20)?; // Skip hash160
            Ok(())
        }
        2 | 3 | 4 | 5 => {
            let _ = rc.take(32)?; // Skip X coordinate
            Ok(())
        }
        _ => {
            if nsize < 6 {
                return Err(err("INVALID_SCRIPT_COMPRESSION", "nsize < 6 unexpected"));
            }
            let raw_len_u64 = nsize - 6; // Raw script length
            ensure_len("undo", "compressed_script_raw_len", raw_len_u64, 100_000)?; // Bound
            let raw_len: usize = usize::try_from(raw_len_u64)
                .map_err(|_| err("LEN_OVERFLOW", format!("raw_len too large for usize: {raw_len_u64}")))?;
            let _ = rc.take(raw_len)?; // Skip raw bytes
            Ok(())
        }
    }
}

/// Skip a single `CTxUndo` input entry (value + script) without allocating.
#[inline]
fn skip_one_inundo(rc: &mut parser::Cursor) -> Result<(), String> {
    let ncode = read_varint_core(rc)?; // Read nCode
    let height = ncode >> 1; // Extract height
    if height > 0 {
        let _tx_version = read_varint_core(rc)?; // Skip tx version if present
    }
    let _comp_amt = read_varint_core(rc)?; // Skip compressed amount
    skip_compressed_script(rc)?; // Skip script
    Ok(())
}

/// Strictly validate undo payload structure against expected vin counts.
///
/// This checks:
///   - CBlockUndo.nTxUndo (with optional extra empty entry for coinbase),
///   - per-txundo vin counts match the block's tx vin counts,
///   - payload ends exactly at record end.
fn validate_undo_payload_strict_structure(undo_payload: &[u8], vin_counts_non_cb: &[u64]) -> Result<(), String> {
    let mut uc = parser::Cursor::new(undo_payload); // Cursor over undo

    let n_txundo = read_compactsize(&mut uc)?; // Read nTxUndo
    ensure_len("undo", "n_txundo", n_txundo, 200_000)?; // Bound

    let expected = vin_counts_non_cb.len() as u64; // Expected txundo entries (non-coinbase tx count)

    let mut has_cb_undo = false; // Track whether coinbase undo entry exists
    if n_txundo == expected {
        // ok
    } else if n_txundo == expected.saturating_add(1) {
        has_cb_undo = true; // Some datasets include an explicit empty entry for coinbase
    } else {
        return Err(err(
            "UNDO_MISMATCH",
            format!(
                "undo txundo count mismatch: undo={}, expected={} (or {} if coinbase included)",
                n_txundo,
                expected,
                expected.saturating_add(1)
            ),
        ));
    }

    if has_cb_undo {
        let cb_vin_n = read_compactsize(&mut uc)?; // Coinbase entry: vin count should be 0
        if cb_vin_n != 0 {
            return Err(err(
                "UNDO_MISMATCH",
                format!("coinbase undo present but vin_n != 0: got={cb_vin_n}"),
            ));
        }
    }

    for (txundo_idx, &vin_expected) in vin_counts_non_cb.iter().enumerate() { // Validate each non-coinbase txundo
        let vin_n = read_compactsize(&mut uc)?; // vin count stored in undo
        ensure_len("undo", "vin_count", vin_n, 100_000)?; // Bound

        if vin_n != vin_expected { // Must match block's vin count
            return Err(err(
                "UNDO_MISMATCH",
                format!(
                    "undo vin count mismatch: txundo_idx={} undo={} expected={}",
                    txundo_idx, vin_n, vin_expected
                ),
            ));
        }

        for _ in 0..(vin_n as usize) { // Skip each per-input undo record
            skip_one_inundo(&mut uc)?;
        }
    }

    if uc.remaining() != 0 { // Strict: must end exactly
        return Err(err(
            "UNDO_TRAILING_BYTES",
            format!("undo payload has {} trailing bytes", uc.remaining()),
        ));
    }

    Ok(())
}

/// Parse undo payload into per-tx per-input (value, ScriptSlice) tuples.
///
/// This is the strict, zero-copy path used by block-mode analysis.
#[allow(dead_code)]
fn read_undo_for_block_from_cursor_slices(
    rc: &mut parser::Cursor, // Cursor over undo payload
    vin_counts_non_cb: &[u64], // Expected vin count per non-coinbase tx
    arena: &mut Vec<u8>, // Arena buffer for reconstructed scripts
) -> Result<UndoPrevoutsSlices, String> {
    let n_txundo = read_compactsize(rc)?; // Read nTxUndo
    ensure_len("undo", "n_txundo", n_txundo, 200_000)?; // Bound

    let expected = vin_counts_non_cb.len() as u64; // Expected non-coinbase count

    let mut has_cb_undo = false; // Whether coinbase undo entry exists
    if n_txundo == expected {
        // ok
    } else if n_txundo == expected.saturating_add(1) {
        has_cb_undo = true;
    } else {
        return Err(err(
            "UNDO_MISMATCH",
            format!(
                "undo txundo count mismatch: undo={}, expected={} (or {} if coinbase included)",
                n_txundo,
                expected,
                expected.saturating_add(1)
            ),
        ));
    }

    if has_cb_undo {
        let cb_vin_n = read_compactsize(rc)?; // Coinbase vin count should be 0
        if cb_vin_n != 0 {
            return Err(err(
                "UNDO_MISMATCH",
                format!("coinbase undo present but vin_n != 0: got={cb_vin_n}"),
            ));
        }
    }

    let mut all: UndoPrevoutsSlices = Vec::with_capacity(vin_counts_non_cb.len()); // Allocate outer vec

    for (txundo_idx, &vin_expected) in vin_counts_non_cb.iter().enumerate() {
        let vin_n = read_compactsize(rc)?; // Read vin count for this txundo
        ensure_len("undo", "vin_count", vin_n, 100_000)?;

        if vin_n != vin_expected {
            return Err(err(
                "UNDO_MISMATCH",
                format!(
                    "undo vin count mismatch: txundo_idx={} undo={} expected={}",
                    txundo_idx, vin_n, vin_expected
                ),
            ));
        }

        let mut ins: Vec<(u64, ScriptSlice)> = Vec::with_capacity(vin_n as usize); // Allocate per-input list
        for _ in 0..(vin_n as usize) {
            ins.push(read_one_inundo_slice(rc, arena)?); // Read value+script for each input
        }
        all.push(ins); // Push txundo entry
    }

    Ok(all)
}

// -----------------------------------------------------------------------------
// Fast structural validation (no allocations)
// -----------------------------------------------------------------------------

/// Validate undo payload strictly against vin counts from the block.
///
/// This is used in blk↔rev pairing fallback: verify that the undo record actually matches the block.
pub(crate) fn validate_undo_payload_against_block(block: &[u8], undo_payload: &[u8]) -> Result<(), String> {
    let mut bc = parser::Cursor::new(block); // Cursor over block payload

    if bc.remaining() < 80 {
        return Err(err("INVALID_BLOCK", "block payload too small for header"));
    }

    let _header = bc.take(80)?; // Skip header

    let tx_count = parser::read_varint(&mut bc)?; // Read tx_count
    if tx_count == 0 {
        return Err(err("INVALID_BLOCK", "block has zero transactions"));
    }

    let mut vin_counts_non_cb: Vec<u64> = Vec::with_capacity((tx_count as usize).saturating_sub(1)); // Store vin counts for non-coinbase txs

    for tx_idx in 0..(tx_count as usize) {
        let start = bc.pos(); // Start offset of tx
        let _txid_le = parser::parse_tx_skip_and_txid_le(block, &mut bc)?; // Skip tx and compute txid (also advances cursor)
        let end = bc.pos(); // End offset of tx

        if tx_idx == 0 {
            continue; // Skip coinbase (undo is for non-coinbase txs)
        }

        vin_counts_non_cb.push(extract_vin_count_from_slice(&block[start..end])?); // Extract vin count from tx bytes
    }

    validate_undo_payload_strict_structure(undo_payload, &vin_counts_non_cb) // Validate undo structure matches those vin counts
}
