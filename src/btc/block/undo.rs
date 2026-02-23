// src/btc/block/undo.rs

use super::parser;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;

// Zero-copy representation for scriptPubKey bytes in undo payload.
// Some scripts are stored raw inside the undo payload; others are stored in a compressed form and
// must be expanded. Expanded scripts are appended into a shared arena buffer.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum ScriptSrc {
    Undo,
    Arena,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScriptSlice {
    pub src: ScriptSrc,
    pub start: usize,
    pub len: usize,
}

#[allow(dead_code)]
impl ScriptSlice {
    #[inline]
    pub fn as_slice<'a>(&self, undo_payload: &'a [u8], arena: &'a [u8]) -> &'a [u8] {
        match self.src {
            ScriptSrc::Undo => &undo_payload[self.start..self.start + self.len],
            ScriptSrc::Arena => &arena[self.start..self.start + self.len],
        }
    }
}

#[allow(dead_code)]
type UndoPrevoutsSlices = Vec<Vec<(u64, ScriptSlice)>>;

fn err(code: &str, msg: impl AsRef<str>) -> String {
    format!("{code}: {}", msg.as_ref())
}

fn ensure_len(kind: &str, field: &str, val: u64, max: u64) -> Result<(), String> {
    parser::ensure_len(kind, field, val, max)
}

fn read_varint_core(c: &mut parser::Cursor) -> Result<u64, String> {
    // Bitcoin Core base-128 VarInt encoding (serialize.h)
    let mut n: u64 = 0;
    loop {
        let ch = c.take_u8()? as u64;
        let data = ch & 0x7f;
        n = (n << 7) | data;
        if (ch & 0x80) != 0 {
            n = n.checked_add(1).ok_or_else(|| err("VARINT_OVERFLOW", "core varint overflow"))?;
            continue;
        }
        return Ok(n);
    }
}

fn read_compactsize(c: &mut parser::Cursor) -> Result<u64, String> {
    // Bitcoin CompactSize
    let first = c.take_u8()?;
    match first {
        0x00..=0xfc => Ok(first as u64),
        0xfd => Ok(c.take_u16_le()? as u64),
        0xfe => Ok(c.take_u32_le()? as u64),
        0xff => Ok(c.take_u64_le()?),
    }
}

// ------------------------------------------------------------
// Hot-path helpers
// ------------------------------------------------------------
/// Ultra-cheap read of the number of `CTxUndo` entries in a `CBlockUndo` payload.
///
/// This reads only the leading CompactSize (`nTxUndo`) and performs the same sanity bound
/// used by the strict parser.
///
/// Intended for fast blk↔rev pairing in `block/io.rs`.
#[inline]
pub(crate) fn undo_txundo_count_fast(undo_payload: &[u8]) -> Result<u64, String> {
    let mut c = parser::Cursor::new(undo_payload);
    let n = read_compactsize(&mut c)?;
    ensure_len("undo", "n_txundo", n, 200_000)?;
    Ok(n)
}

/// Even cheaper variant that operates on a byte slice cursor and also returns bytes consumed.
///
/// This avoids constructing `parser::Cursor` and is useful if you already have a `&[u8]` cursor.
#[inline]
#[allow(dead_code)]
pub(crate) fn undo_txundo_count_fast_bytes(input: &mut &[u8]) -> Result<u64, String> {
    if input.is_empty() {
        return Err(err("COMPACTSIZE_EOF", "empty input"));
    }
    let first = input[0];
    *input = &input[1..];

    let n = match first {
        0x00..=0xfc => first as u64,
        0xfd => {
            if input.len() < 2 {
                return Err(err("COMPACTSIZE_EOF", "0xfd but missing 2 bytes"));
            }
            let v = u16::from_le_bytes([input[0], input[1]]) as u64;
            *input = &input[2..];
            v
        }
        0xfe => {
            if input.len() < 4 {
                return Err(err("COMPACTSIZE_EOF", "0xfe but missing 4 bytes"));
            }
            let v = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as u64;
            *input = &input[4..];
            v
        }
        0xff => {
            if input.len() < 8 {
                return Err(err("COMPACTSIZE_EOF", "0xff but missing 8 bytes"));
            }
            let v = u64::from_le_bytes([
                input[0], input[1], input[2], input[3],
                input[4], input[5], input[6], input[7],
            ]);
            *input = &input[8..];
            v
        }
    };

    ensure_len("undo", "n_txundo", n, 200_000)?;
    Ok(n)
}


fn decompress_amount(x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    let mut x = x - 1;
    let e = (x % 10) as u32;
    x /= 10;

    let mut n: u64;
    if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        n = x * 10 + d;
    } else {
        n = x + 1;
    }

    for _ in 0..e {
        n *= 10;
    }
    n
}

fn decompress_uncompressed_pubkey_from_x(x32: &[u8], y_is_odd: bool) -> Result<Vec<u8>, String> {
    if x32.len() != 32 {
        return Err(err("INVALID_PUBKEY", "x32 must be 32 bytes"));
    }

    let mut comp = [0u8; 33];
    comp[0] = if y_is_odd { 0x03 } else { 0x02 };
    comp[1..].copy_from_slice(x32);

    let pk = PublicKey::from_sec1_bytes(&comp)
        .map_err(|_| err("INVALID_PUBKEY", "failed to decompress pubkey from x"))?;

    let enc = pk.to_encoded_point(false);
    let bytes = enc.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(err("INVALID_PUBKEY", "unexpected uncompressed encoding"));
    }

    Ok(bytes.to_vec())
}


// Zero-copy variant: returns a ScriptSlice into either undo_payload (raw scripts) or the arena
// (expanded standard scripts). No per-script Vec allocations.
#[allow(dead_code)]
fn read_compressed_script_slice(c: &mut parser::Cursor, arena: &mut Vec<u8>) -> Result<ScriptSlice, String> {
    // ScriptCompressor uses Bitcoin Core base-128 VarInt (not CompactSize).
    let nsize = read_varint_core(c)?;

    match nsize {
        0 => {
            // P2PKH
            let h160 = c.take(20)?;
            let start = arena.len();
            arena.extend_from_slice(&[0x76, 0xa9, 0x14]);
            arena.extend_from_slice(h160);
            arena.extend_from_slice(&[0x88, 0xac]);
            let len = arena.len() - start;
            Ok(ScriptSlice { src: ScriptSrc::Arena, start, len })
        }
        1 => {
            // P2SH
            let h160 = c.take(20)?;
            let start = arena.len();
            arena.extend_from_slice(&[0xa9, 0x14]);
            arena.extend_from_slice(h160);
            arena.push(0x87);
            let len = arena.len() - start;
            Ok(ScriptSlice { src: ScriptSrc::Arena, start, len })
        }
        2 | 3 => {
            // P2PK (compressed pubkey)
            let x = c.take(32)?;
            let prefix = if nsize == 2 { 0x02 } else { 0x03 };
            let start = arena.len();
            arena.push(0x21);
            arena.push(prefix);
            arena.extend_from_slice(x);
            arena.push(0xac);
            let len = arena.len() - start;
            Ok(ScriptSlice { src: ScriptSrc::Arena, start, len })
        }
        4 | 5 => {
            // P2PK (uncompressed pubkey)
            let x = c.take(32)?;
            let y_is_odd = nsize == 5;
            let pubkey65 = decompress_uncompressed_pubkey_from_x(x, y_is_odd)?;
            let start = arena.len();
            arena.push(0x41);
            arena.extend_from_slice(&pubkey65);
            arena.push(0xac);
            let len = arena.len() - start;
            Ok(ScriptSlice { src: ScriptSrc::Arena, start, len })
        }
        _ => {
            if nsize < 6 {
                return Err(err("INVALID_SCRIPT_COMPRESSION", "nsize < 6 unexpected"));
            }

            let raw_len_u64 = nsize - 6;
            ensure_len("undo", "compressed_script_raw_len", raw_len_u64, 100_000)?;

            let raw_len: usize = usize::try_from(raw_len_u64)
                .map_err(|_| err("LEN_OVERFLOW", format!("raw_len too large for usize: {raw_len_u64}")))?;

            // Raw script is already present in the undo payload; return a view into it.
            let start = c.pos();
            let _ = c.take(raw_len)?;
            Ok(ScriptSlice { src: ScriptSrc::Undo, start, len: raw_len })
        }
    }
}


#[allow(dead_code)]
fn read_one_inundo_slice(rc: &mut parser::Cursor, arena: &mut Vec<u8>) -> Result<(u64, ScriptSlice), String> {
    let ncode = read_varint_core(rc)?;
    let height = ncode >> 1;

    if height > 0 {
        let _tx_version = read_varint_core(rc)?;
    }

    let comp_amt = read_varint_core(rc)?;
    let spk = read_compressed_script_slice(rc, arena)?;
    let value_sats = decompress_amount(comp_amt);

    if spk.len > 100_000 {
        return Err(err("INSANE_LEN", format!("spk too large: {}", spk.len)));
    }

    Ok((value_sats, spk))
}

#[allow(dead_code)]
fn read_undo_for_block_from_cursor_slices(
    rc: &mut parser::Cursor,
    vin_counts_non_cb: &[u64],
    arena: &mut Vec<u8>,
) -> Result<UndoPrevoutsSlices, String> {
    let n_txundo = read_compactsize(rc)?;
    ensure_len("undo", "n_txundo", n_txundo, 200_000)?;

    let expected = vin_counts_non_cb.len() as u64;

    let mut has_cb_undo = false;
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
        let cb_vin_n = read_compactsize(rc)?;
        if cb_vin_n != 0 {
            return Err(err(
                "UNDO_MISMATCH",
                format!("coinbase undo present but vin_n != 0: got={cb_vin_n}"),
            ));
        }
    }

    let mut all: UndoPrevoutsSlices = Vec::with_capacity(vin_counts_non_cb.len());

    for (txundo_idx, &vin_expected) in vin_counts_non_cb.iter().enumerate() {
        let vin_n = read_compactsize(rc)?;
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

        let mut ins: Vec<(u64, ScriptSlice)> = Vec::with_capacity(vin_n as usize);
        for _ in 0..(vin_n as usize) {
            ins.push(read_one_inundo_slice(rc, arena)?);
        }
        all.push(ins);
    }

    Ok(all)
}

// Zero-copy strict parser: returns ScriptSlice references that can be materialized as &[u8]
// using ScriptSlice::as_slice(undo_payload, arena).
#[allow(dead_code)]
pub(crate) fn parse_undo_payload_strict_slices(
    undo_payload: &[u8],
    vin_counts_non_cb: &[u64],
    arena: &mut Vec<u8>,
) -> Result<UndoPrevoutsSlices, String> {
    let mut uc = parser::Cursor::new(undo_payload);
    let v = read_undo_for_block_from_cursor_slices(&mut uc, vin_counts_non_cb, arena)?;
    if uc.remaining() != 0 {
        return Err(err(
            "UNDO_TRAILING_BYTES",
            format!("undo payload has {} trailing bytes", uc.remaining()),
        ));
    }
    Ok(v)
}

pub(crate) fn extract_vin_count(raw_tx: &[u8]) -> Result<u64, String> {
    let mut c = parser::Cursor::new(raw_tx);
    let _ver = c.take_u32_le()?;

    let p = c.take_u8()?;
    if p == 0x00 {
        let _f = c.take_u8()?;
    } else {
        c.i -= 1;
    }

    parser::read_varint(&mut c)
}

pub(crate) fn extract_vin_count_from_slice(raw_tx: &[u8]) -> Result<u64, String> {
    extract_vin_count(raw_tx)
}

#[inline]
fn skip_compressed_script(rc: &mut parser::Cursor) -> Result<(), String> {
    // ScriptCompressor uses Bitcoin Core base-128 VarInt (not CompactSize).
    let nsize = read_varint_core(rc)?;

    match nsize {
        0 | 1 => {
            // P2PKH or P2SH: 20-byte hash160
            let _ = rc.take(20)?;
            Ok(())
        }
        2 | 3 | 4 | 5 => {
            // P2PK: 32-byte X coordinate (compressed or uncompressed key)
            let _ = rc.take(32)?;
            Ok(())
        }
        _ => {
            if nsize < 6 {
                return Err(err("INVALID_SCRIPT_COMPRESSION", "nsize < 6 unexpected"));
            }
            let raw_len_u64 = nsize - 6;
            ensure_len("undo", "compressed_script_raw_len", raw_len_u64, 100_000)?;
            let raw_len: usize = usize::try_from(raw_len_u64)
                .map_err(|_| err("LEN_OVERFLOW", format!("raw_len too large for usize: {raw_len_u64}")))?;
            let _ = rc.take(raw_len)?;
            Ok(())
        }
    }
}

#[inline]
fn skip_one_inundo(rc: &mut parser::Cursor) -> Result<(), String> {
    // Matches read_one_inundo/read_one_inundo_slice structure:
    //   ncode (varint_core)
    //   optional tx_version (varint_core) if height>0
    //   comp_amt (varint_core)
    //   compressed_script (varint_core + payload)
    let ncode = read_varint_core(rc)?;
    let height = ncode >> 1;
    if height > 0 {
        let _tx_version = read_varint_core(rc)?;
    }
    let _comp_amt = read_varint_core(rc)?;
    skip_compressed_script(rc)?;
    Ok(())
}

fn validate_undo_payload_strict_structure(
    undo_payload: &[u8],
    vin_counts_non_cb: &[u64],
) -> Result<(), String> {
    let mut uc = parser::Cursor::new(undo_payload);

    // CBlockUndo: CompactSize(nTxUndo)
    // Usually tx_count - 1, but some fixtures include an extra empty CTxUndo for coinbase.
    let n_txundo = read_compactsize(&mut uc)?;
    ensure_len("undo", "n_txundo", n_txundo, 200_000)?;

    let expected = vin_counts_non_cb.len() as u64;

    let mut has_cb_undo = false;
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
        let cb_vin_n = read_compactsize(&mut uc)?;
        if cb_vin_n != 0 {
            return Err(err(
                "UNDO_MISMATCH",
                format!("coinbase undo present but vin_n != 0: got={cb_vin_n}"),
            ));
        }
    }

    for (txundo_idx, &vin_expected) in vin_counts_non_cb.iter().enumerate() {
        let vin_n = read_compactsize(&mut uc)?;
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

        // Skip vin_n inputs.
        for _ in 0..(vin_n as usize) {
            skip_one_inundo(&mut uc)?;
        }
    }

    if uc.remaining() != 0 {
        return Err(err(
            "UNDO_TRAILING_BYTES",
            format!("undo payload has {} trailing bytes", uc.remaining()),
        ));
    }

    Ok(())
}

// --- Drop-in replacement for your existing function ---
// This preserves the external signature but makes it much faster.
// It still computes vin_counts_non_cb the same way as before; a further speedup
// is possible by adding a parser helper that returns vin_count during skip.

pub(crate) fn validate_undo_payload_against_block(
    block: &[u8],
    undo_payload: &[u8],
) -> Result<(), String> {
    let mut bc = parser::Cursor::new(block);

    if bc.remaining() < 80 {
        return Err(err("INVALID_BLOCK", "block payload too small for header"));
    }

    // Skip header (no allocation)
    let _header = bc.take(80)?;

    let tx_count = parser::read_varint(&mut bc)?;
    if tx_count == 0 {
        return Err(err("INVALID_BLOCK", "block has zero transactions"));
    }

    // We only need vin-counts for non-coinbase txs.
    // Parse each tx as a slice range without copying.
    let mut vin_counts_non_cb: Vec<u64> =
        Vec::with_capacity((tx_count as usize).saturating_sub(1));

    for tx_idx in 0..(tx_count as usize) {
        let start = bc.pos();
        let _txid_le = parser::parse_tx_skip_and_txid_le(block, &mut bc)?;
        let end = bc.pos();

        if tx_idx == 0 {
            // coinbase: ignore
            continue;
        }

        vin_counts_non_cb.push(extract_vin_count_from_slice(&block[start..end])?);
    }

    // FAST structural validation (no script allocations, no pubkey decompression)
    validate_undo_payload_strict_structure(undo_payload, &vin_counts_non_cb)
}
