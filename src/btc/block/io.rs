// src/btc/block/io.rs

use super::parser;
use super::undo;

use sha2::{Digest, Sha256};

const MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

fn err(code: &str, msg: impl AsRef<str>) -> String {
    format!("{code}: {}", msg.as_ref())
}

fn key_is_all_zero(key: &[u8]) -> bool {
    key.iter().all(|&b| b == 0)
}

/// A zero-copy record reference into a decoded dat buffer.
pub(crate) type RecordRange = std::ops::Range<usize>;

pub(crate) fn xor_decode_with_shift(mut data: Vec<u8>, key: &[u8], shift: usize) -> Vec<u8> {
    if key.is_empty() {
        return data;
    }
    let klen = key.len();
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[(i + shift) % klen];
    }
    data
}

pub(crate) fn read_dat_records_strict(
    buf: &[u8],
    kind: &'static str,
) -> Result<Vec<RecordRange>, String> {
    // blk*.dat framing: MAGIC(4) | size(u32 LE) | payload(size)
    let mut out: Vec<RecordRange> = Vec::new();
    let mut i: usize = 0;

    while i + 8 <= buf.len() {
        if buf[i..i + 4] != MAGIC {
            return Err(err(
                "BAD_MAGIC",
                format!(
                    "{kind}: expected MAGIC at offset {i}, got {:02x?}",
                    &buf[i..i + 4]
                ),
            ));
        }

        let size = u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]) as usize;
        let payload_start = i + 8;
        let payload_end = payload_start.saturating_add(size);

        if payload_end > buf.len() {
            return Err(err(
                "TRUNCATED_RECORD",
                format!(
                    "{kind}: record payload truncated: need {size}, have {}",
                    buf.len().saturating_sub(payload_start)
                ),
            ));
        }

        out.push(payload_start..payload_end);
        i = payload_end;
    }

    if out.is_empty() {
        return Err(err("NO_RECORDS_FOUND", format!("{kind}: no records found")));
    }

    Ok(out)
}

fn read_rev_records_strict(buf: &[u8], kind: &'static str) -> Result<Vec<RecordRange>, String> {
    // Bitcoin Core-like rev*.dat framing:
    //   MAGIC(4) | size(u32 LE) | undo_payload(size) | checksum(32)
    // The fixtures include the 32-byte checksum trailer per record.
    // We do *not* validate the checksum here; correctness is enforced later by
    // `validate_undo_payload_against_block`.
    let mut out: Vec<RecordRange> = Vec::new();
    let mut i: usize = 0;

    while i + 8 <= buf.len() {
        if buf[i..i + 4] != MAGIC {
            return Err(err(
                "BAD_MAGIC",
                format!(
                    "{kind}: expected MAGIC at offset {i}, got {:02x?}",
                    &buf[i..i + 4]
                ),
            ));
        }

        let size = u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]) as usize;
        let payload_start = i + 8;
        let payload_end = payload_start.saturating_add(size);
        let trailer_end = payload_end.saturating_add(32);

        if trailer_end > buf.len() {
            return Err(err(
                "TRUNCATED_RECORD",
                format!(
                    "{kind}: record truncated: need payload={size} + 32-byte checksum, have {}",
                    buf.len().saturating_sub(payload_start)
                ),
            ));
        }

        out.push(payload_start..payload_end);
        i = trailer_end;
    }

    if out.is_empty() {
        return Err(err("NO_RECORDS_FOUND", format!("{kind}: no records found")));
    }

    Ok(out)
}


fn dsha256_bytes(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

// (legacy helper retained for potential future use; not used for fixtures)
#[allow(dead_code)]
fn rev_checksum(undo_payload: &[u8]) -> [u8; 32] {
    // Bitcoin Core has checksums for some on-disk structures, but the challenge fixtures
    // do not include a trailing checksum field in rev*.dat records.
    dsha256_bytes(undo_payload)
}

/// Pair rev-records to blk-records by index (Core-like ordering).
///
/// We do NOT attempt to "search" a matching rev record:
/// the rev checksum is only an integrity check, not a block identifier.
/// Any block↔undo mismatch is caught later by `validate_undo_payload_against_block`.
fn pair_rev_to_blocks_by_checksum(
    blk_ranges: &[RecordRange],
    rev_ranges: &[RecordRange],
) -> Result<Vec<RecordRange>, String> {
    // Core-like ordering: record i in blk pairs with record i in rev.
    if blk_ranges.len() != rev_ranges.len() {
        return Err(err(
            "RECORD_COUNT_MISMATCH",
            format!(
                "rev records={} blk records={}",
                rev_ranges.len(),
                blk_ranges.len()
            ),
        ));
    }
    Ok(rev_ranges.to_vec())
}

fn validate_block_payload(block: &[u8]) -> Result<(), String> {
    let mut bc = parser::Cursor::new(block);

    if bc.remaining() < 80 {
        return Err(err("INVALID_BLOCK", "block payload too small for header"));
    }

    // Avoid header Vec copy.
    let header = bc.take(80)?;
    let mut hc = parser::Cursor::new(header);

    let _version = hc.take_u32_le()?;
    let _prev = hc.take(32)?;

    let merkle = {
        let s = hc.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        a
    };

    let _ts = hc.take_u32_le()?;
    let _bits = hc.take_u32_le()?;
    let _nonce = hc.take_u32_le()?;

    let tx_count = parser::read_varint(&mut bc)?;
    if tx_count == 0 {
        return Err(err("INVALID_BLOCK", "tx_count=0"));
    }

    // Hot path: avoid materializing raw tx bytes.
    let mut txids_le: Vec<[u8; 32]> = Vec::with_capacity(tx_count as usize);
    for _ in 0..tx_count {
        let txid_le = parser::parse_tx_skip_and_txid_le(block, &mut bc)?;
        txids_le.push(txid_le);
    }

    let mr_calc = parser::merkle_root(&txids_le);
    if mr_calc != merkle {
        return Err(err("MERKLE_MISMATCH", "merkle mismatch"));
    }

    Ok(())
}

fn decode_blk_best(blk_raw: Vec<u8>, key: &[u8]) -> Result<Vec<u8>, String> {
    let blk = if key.is_empty() || key_is_all_zero(key) {
        blk_raw
    } else {
        xor_decode_with_shift(blk_raw, key, 0)
    };

    let recs = read_dat_records_strict(&blk, "blk")?;
    if recs.is_empty() {
        return Err(err("BLK_DECODE_FAILED", "no blk records"));
    }

    // Validate first record as a cheap sanity check for key correctness.
    let first = &blk[recs[0].clone()];
    validate_block_payload(first).map_err(|e| err("BLK_DECODE_FAILED", e))?;
    Ok(blk)
}

pub(crate) fn decode_blk_best_to_records(
    blk_raw: Vec<u8>,
    key: &[u8],
) -> Result<(Vec<u8>, Vec<RecordRange>), String> {
    let blk = decode_blk_best(blk_raw, key)?;
    let blk_ranges = read_dat_records_strict(&blk, "blk")?;
    Ok((blk, blk_ranges))
}

fn decode_rev_records_against_blocks(
    rev_raw: Vec<u8>,
    key: &[u8],
    blk_buf: &[u8],
    blk_ranges: &[RecordRange],
) -> Result<(Vec<u8>, Vec<RecordRange>), String> {
    let mut rev = rev_raw;
    if !key.is_empty() && !key_is_all_zero(key) {
        rev = xor_decode_with_shift(rev, key, 0);
    }

    let rev_ranges = read_rev_records_strict(&rev, "rev")?;

    let paired_undo_ranges = pair_rev_to_blocks_by_checksum(blk_ranges, &rev_ranges)?;

    for (i, (br, ur)) in blk_ranges
        .iter()
        .zip(paired_undo_ranges.iter())
        .enumerate()
    {
        let block = &blk_buf[br.clone()];
        let undo_payload = &rev[ur.clone()];
        undo::validate_undo_payload_against_block(block, undo_payload).map_err(|e| {
            err(
                "UNDO_BLOCK_PAIR_MISMATCH",
                format!("record[{i}] undo did not validate against block: {e}"),
            )
        })?;
    }

    Ok((rev, paired_undo_ranges))
}

pub(crate) fn decode_blk_and_rev_best(
    blk_raw: Vec<u8>,
    rev_raw: Vec<u8>,
    key: &[u8],
) -> Result<(Vec<u8>, Vec<RecordRange>, Vec<u8>, Vec<RecordRange>), String> {
    let blk = decode_blk_best(blk_raw, key)?;
    let blk_ranges = read_dat_records_strict(&blk, "blk")?;
    let (rev, undo_ranges) = decode_rev_records_against_blocks(rev_raw, key, &blk, &blk_ranges)?;
    Ok((blk, blk_ranges, rev, undo_ranges))
}
