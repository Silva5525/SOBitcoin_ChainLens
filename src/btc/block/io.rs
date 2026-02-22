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

// (legacy helper retained for potential future use; not used in current pairing logic)
#[allow(dead_code)]
fn rev_checksum(undo_payload: &[u8]) -> [u8; 32] {
    dsha256_bytes(undo_payload)
}

/// Helpers to extract structural counts from block and undo payloads.
///
/// We do not rely on on-disk ordering between blk*.dat and rev*.dat.
/// Instead, pairing is done using structural invariants and full validation
/// against the block's transactions.
fn block_tx_count(block: &[u8]) -> Result<u64, String> {
    let mut bc = parser::Cursor::new(block);
    if bc.remaining() < 80 {
        return Err(err("INVALID_BLOCK", "block payload too small for header"));
    }
    bc.take(80)?;
    parser::read_varint(&mut bc).map_err(|e| err("INVALID_BLOCK", e))
}

fn undo_txundo_count(undo_payload: &[u8]) -> Result<u64, String> {
    let mut uc = parser::Cursor::new(undo_payload);
    parser::read_varint(&mut uc).map_err(|e| err("INVALID_UNDO", e))
}

/// Pair rev-records to blk-records without assuming identical on-disk ordering.
///
/// In Bitcoin Core, blk and rev offsets are resolved via the block index DB.
/// In this challenge (no block index available), we pair using a strong invariant:
///   undo_txundo_count == tx_count - 1 (coinbase has no undo entry)
/// plus a full structural validation:
///   validate_undo_payload_against_block(block, undo_payload)
///
/// A strict 1:1 mapping is enforced (each rev record used at most once).
fn pair_rev_to_blocks_by_checksum(
    blk_buf: &[u8],
    blk_ranges: &[RecordRange],
    rev_buf: &[u8],
    rev_ranges: &[RecordRange],
) -> Result<Vec<RecordRange>, String> {
    if blk_ranges.is_empty() {
        return Err(err("NO_RECORDS_FOUND", "blk: no records found"));
    }
    if rev_ranges.is_empty() {
        return Err(err("NO_RECORDS_FOUND", "rev: no records found"));
    }


    // Index rev records by their leading txundo-count varint.
    let mut by_undo_cnt: std::collections::HashMap<u64, Vec<usize>> = std::collections::HashMap::new();
    for (j, ur) in rev_ranges.iter().enumerate() {
        let undo_payload = &rev_buf[ur.clone()];
        let undo_cnt = undo_txundo_count(undo_payload)?;
        by_undo_cnt.entry(undo_cnt).or_default().push(j);
    }

    let mut used = vec![false; rev_ranges.len()];
    let mut out: Vec<RecordRange> = Vec::with_capacity(blk_ranges.len());

    for (i, br) in blk_ranges.iter().enumerate() {
        let block = &blk_buf[br.clone()];
        let txc = block_tx_count(block)?;
        if txc == 0 {
            return Err(err("INVALID_BLOCK", format!("block[{i}] tx_count=0")));
        }

        let expected = txc.saturating_sub(1);

        // Candidate rev indices (try exact expected first, then txc).
        let mut cand: Vec<usize> = Vec::new();
        if let Some(v) = by_undo_cnt.get(&expected) {
            cand.extend_from_slice(v);
        }
        if expected != txc {
            if let Some(v) = by_undo_cnt.get(&txc) {
                cand.extend_from_slice(v);
            }
        }


        let mut chosen: Option<usize> = None;
        for &j in &cand {
            if used[j] {
                continue;
            }
            let ur = &rev_ranges[j];
            let undo_payload = &rev_buf[ur.clone()];
            if undo::validate_undo_payload_against_block(block, undo_payload).is_ok() {
                chosen = Some(j);
                break;
            }
        }

        let Some(j) = chosen else {
            return Err(err(
                "REV_PAIRING_FAILED",
                format!(
                    "could not find matching undo for block[{i}] (tx_count={txc}, expected_undo_count={expected})"
                ),
            ));
        };

        used[j] = true;
        out.push(rev_ranges[j].clone());

    }

    Ok(out)
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

    // Fast path: fixtures use an all-zero XOR key. In that case, we can skip the
    // expensive merkle validation pass here.
    //
    // If you want strict key verification (e.g. for debugging), set:
    //   CHAINLENS_STRICT_KEY=1
    let strict_key = std::env::var("CHAINLENS_STRICT_KEY").is_ok();
    if strict_key || !(key.is_empty() || key_is_all_zero(key)) {
        let recs = read_dat_records_strict(&blk, "blk")?;
        if recs.is_empty() {
            return Err(err("BLK_DECODE_FAILED", "no blk records"));
        }
        // Validate first record as a sanity check for key correctness.
        let first = &blk[recs[0].clone()];
        validate_block_payload(first).map_err(|e| err("BLK_DECODE_FAILED", e))?;
    }

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

    let paired_undo_ranges =
        pair_rev_to_blocks_by_checksum(blk_buf, blk_ranges, &rev, &rev_ranges)?;

    // Pairing already performed full structural validation via
    // `validate_undo_payload_against_block` for each chosen (block, undo) pair.
    // Avoid re-validating here to keep block-mode fast.
    //
    // If you want a redundant validation pass (debugging), set:
    //   CHAINLENS_STRICT_UNDO=1
    if std::env::var("CHAINLENS_STRICT_UNDO").is_ok() {
        for (i, (br, ur)) in blk_ranges.iter().zip(paired_undo_ranges.iter()).enumerate() {
            let block = &blk_buf[br.clone()];
            let undo_payload = &rev[ur.clone()];
            undo::validate_undo_payload_against_block(block, undo_payload).map_err(|e| {
                err(
                    "UNDO_BLOCK_PAIR_MISMATCH",
                    format!("record[{i}] undo did not validate against block: {e}"),
                )
            })?;
        }
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
