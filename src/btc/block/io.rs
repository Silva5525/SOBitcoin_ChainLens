// src/btc/block/io.rs

use super::parser;
use super::undo;

const MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

fn err(code: &str, msg: impl AsRef<str>) -> String {
    format!("{code}: {}", msg.as_ref())
}

fn key_is_all_zero(key: &[u8]) -> bool {
    key.iter().all(|&b| b == 0)
}

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

pub(crate) fn read_dat_records_strict(buf: &[u8], kind: &'static str) -> Result<Vec<Vec<u8>>, String> {
    let mut out: Vec<Vec<u8>> = Vec::new();
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

        out.push(buf[payload_start..payload_end].to_vec());
        i = payload_end;
    }

    if out.is_empty() {
        return Err(err("NO_RECORDS_FOUND", format!("{kind}: no records found")));
    }

    Ok(out)
}

#[derive(Clone)]
struct RevRecord {
    undo: Vec<u8>,
    checksum: [u8; 32],
}

fn read_rev_records_strict(buf: &[u8], kind: &'static str) -> Result<Vec<RevRecord>, String> {
    // rev*.dat framing: MAGIC(4) | size(u32 LE) | undo_payload(size) | checksum(32)
    let mut out: Vec<RevRecord> = Vec::new();
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
        let checksum_end = payload_end.saturating_add(32);

        if checksum_end > buf.len() {
            return Err(err(
                "TRUNCATED_RECORD",
                format!(
                    "{kind}: truncated record: need payload={size} + 32 checksum, have_remaining={}",
                    buf.len().saturating_sub(payload_start)
                ),
            ));
        }

        let undo_payload = buf[payload_start..payload_end].to_vec();
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&buf[payload_end..checksum_end]);

        out.push(RevRecord {
            undo: undo_payload,
            checksum,
        });
        i = checksum_end;
    }

    if out.is_empty() {
        return Err(err("NO_RECORDS_FOUND", format!("{kind}: no records found")));
    }

    Ok(out)
}

fn block_prev_hash_le(block: &[u8]) -> Result<[u8; 32], String> {
    if block.len() < 80 {
        return Err(err("INVALID_BLOCK", "block too small for header"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&block[4..36]);
    Ok(out)
}

fn rev_checksum(prev_hash_le: &[u8; 32], undo_payload: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + undo_payload.len());
    buf.extend_from_slice(prev_hash_le);
    buf.extend_from_slice(undo_payload);
    parser::dsha256(&buf)
}

fn pair_rev_to_blocks_by_checksum(
    blk_records: &[Vec<u8>],
    rev_records: &[RevRecord],
) -> Result<Vec<Vec<u8>>, String> {
    let mut used = vec![false; rev_records.len()];
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(blk_records.len());

    for (bi, block) in blk_records.iter().enumerate() {
        let prev_hash_le = block_prev_hash_le(block)?;
        let mut found: Option<usize> = None;

        for (ri, rr) in rev_records.iter().enumerate() {
            if used[ri] {
                continue;
            }
            if rev_checksum(&prev_hash_le, &rr.undo) == rr.checksum {
                found = Some(ri);
                break;
            }
        }

        let ri = found.ok_or_else(|| {
            err(
                "REV_PAIRING_FAILED",
                format!("no matching rev record found for blk record[{bi}] (by checksum)"),
            )
        })?;

        used[ri] = true;
        out.push(rev_records[ri].undo.clone());
    }

    Ok(out)
}

fn validate_block_payload(block: &[u8]) -> Result<(), String> {
    let mut bc = parser::Cursor::new(block);

    if bc.remaining() < 80 {
        return Err(err("INVALID_BLOCK", "block payload too small for header"));
    }
    let header = bc.take(80)?.to_vec();

    let mut hc = parser::Cursor::new(&header);
    let _version = hc.take_u32_le()?;
    let _prev = hc.take(32)?;
    let merkle = hc.take(32)?.to_vec();
    let _ts = hc.take_u32_le()?;
    let _bits = hc.take_u32_le()?;
    let _nonce = hc.take_u32_le()?;

    let tx_count = parser::read_varint(&mut bc)?;
    if tx_count == 0 {
        return Err(err("INVALID_BLOCK", "tx_count=0"));
    }

    let mut txids_le: Vec<[u8; 32]> = Vec::with_capacity(tx_count as usize);
    for _ in 0..tx_count {
        let (_raw, txid_le) = parser::parse_tx_raw_and_txid_le(block, &mut bc)?;
        txids_le.push(txid_le);
    }

    let mr_calc = parser::merkle_root(&txids_le);
    let mut mr_hdr_le = [0u8; 32];
    mr_hdr_le.copy_from_slice(&merkle);

    if mr_calc != mr_hdr_le {
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

    validate_block_payload(&recs[0]).map_err(|e| err("BLK_DECODE_FAILED", e))?;
    Ok(blk)
}

pub(crate) fn decode_blk_best_to_records(
    blk_raw: Vec<u8>,
    key: &[u8],
) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    let blk = decode_blk_best(blk_raw, key)?;
    let blk_records = read_dat_records_strict(&blk, "blk")?;
    Ok((blk_records, blk))
}

fn decode_rev_records_against_blocks(
    rev_raw: Vec<u8>,
    key: &[u8],
    blk_records: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    let mut rev = rev_raw;
    if !key.is_empty() && !key_is_all_zero(key) {
        rev = xor_decode_with_shift(rev, key, 0);
    }

    let rev_records = read_rev_records_strict(&rev, "rev")?;
    if rev_records.len() != blk_records.len() {
        return Err(err(
            "RECORD_COUNT_MISMATCH",
            format!("rev records={} blk records={}", rev_records.len(), blk_records.len()),
        ));
    }

    let paired_undo = pair_rev_to_blocks_by_checksum(blk_records, &rev_records)?;

    for (i, (block, undo_payload)) in blk_records.iter().zip(paired_undo.iter()).enumerate() {
        undo::validate_undo_payload_against_block(block, undo_payload).map_err(|e| {
            err(
                "UNDO_BLOCK_PAIR_MISMATCH",
                format!("record[{i}] undo did not validate against block: {e}"),
            )
        })?;
    }

    Ok(paired_undo)
}

pub(crate) fn decode_blk_and_rev_best(
    blk_raw: Vec<u8>,
    rev_raw: Vec<u8>,
    key: &[u8],
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), String> {
    let blk = decode_blk_best(blk_raw, key)?;
    let blk_records = read_dat_records_strict(&blk, "blk")?;
    let rev_records = decode_rev_records_against_blocks(rev_raw, key, &blk_records)?;
    Ok((blk_records, rev_records))
}
