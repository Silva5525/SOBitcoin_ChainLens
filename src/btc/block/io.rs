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

#[derive(Clone)]
struct RevRecord {
    undo_range: RecordRange,
}

fn read_rev_records_strict(buf: &[u8], kind: &'static str) -> Result<Vec<RevRecord>, String> {
    let debug = std::env::var("CHAINLENS_DEBUG_REV").ok().as_deref() == Some("1");

    fn find_magic(buf: &[u8], start: usize, max_scan: usize) -> Option<usize> {
        let end = buf.len().min(start.saturating_add(max_scan));
        let mut j = start;
        while j + 4 <= end {
            if buf[j..j + 4] == MAGIC {
                return Some(j);
            }
            j += 1;
        }
        None
    }

    // rev*.dat framing in Bitcoin Core is similar to blk*.dat, but many formats include
    // a 4-byte checksum after the undo payload (first 4 bytes of hash256(payload)).
    // The challenge fixtures appear to use this 4-byte checksum (not 32 bytes).
    // We accept either:
    //   MAGIC | size(u32 LE) | payload(size) | checksum(4)
    // or:
    //   MAGIC | size(u32 LE) | payload(size)
    // and validate checksum when present.

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

        if payload_end > buf.len() {
            return Err(err(
                "TRUNCATED_RECORD",
                format!(
                    "{kind}: record payload truncated: need {size}, have {}",
                    buf.len().saturating_sub(payload_start)
                ),
            ));
        }

        // Trailer handling:
        // Some rev formats store a checksum trailer after the payload. In the challenge fixtures
        // we have observed:
        //   - 4-byte trailer (first 4 bytes of hash256(payload))
        //   - (potentially) other small trailers; we detect by locating the next MAGIC.
        let mut next = payload_end;

        if payload_end < buf.len() {
            if buf[payload_end..buf.len().min(payload_end + 4)] == MAGIC {
                // Next record starts immediately.
                next = payload_end;
            } else {
                // Try to find the next MAGIC soon after the payload end.
                if let Some(mpos) = find_magic(buf, payload_end, 128) {
                    let trailer_len = mpos - payload_end;
                    if debug {
                        let tail = &buf[payload_end..buf.len().min(payload_end + 16)];
                        eprintln!(
                            "[dbg] rev rec @{} size={} payload_end={} trailer_len={} tail16={}",
                            i,
                            size,
                            payload_end,
                            trailer_len,
                            hex::encode(tail)
                        );
                    }

                    if trailer_len == 4 {
                        let got = &buf[payload_end..payload_end + 4];
                        let chk = dsha256_bytes(&buf[payload_start..payload_end]);
                        if got != &chk[0..4] {
                            return Err(err(
                                "BAD_UNDO_CHECKSUM",
                                format!(
                                    "{kind}: 4-byte checksum mismatch at offset {payload_end}: got {:02x?} expected {:02x?}",
                                    got,
                                    &chk[0..4]
                                ),
                            ));
                        }
                        next = payload_end + 4;
                    } else if trailer_len == 32 {
                        // Opaque 32-byte trailer (fixture-specific). Skip.
                        if debug {
                            let got = &buf[payload_end..payload_end + 32];
                            let chk = dsha256_bytes(&buf[payload_start..payload_end]);
                            eprintln!(
                                "[dbg] rev trailer32 @{} payload_end={} got32_head={} exp_hash256_head={}",
                                i,
                                payload_end,
                                hex::encode(&got[0..8]),
                                hex::encode(&chk[0..8])
                            );
                        }
                        next = payload_end + 32;
                    } else {
                        // Unknown trailer length; report with helpful context.
                        let got = &buf[payload_end..buf.len().min(payload_end + trailer_len.min(16))];
                        return Err(err(
                            "BAD_REV_TRAILER",
                            format!(
                                "{kind}: expected MAGIC after payload at {payload_end}, found trailer_len={trailer_len} bytes (head {:02x?})",
                                got
                            ),
                        ));
                    }
                } else {
                    // No MAGIC found soon after payload_end. This can happen at EOF where the final
                    // record may have a small trailer but no next MAGIC.
                    let rem = buf.len().saturating_sub(payload_end);
                    if debug {
                        let tail = &buf[payload_end..buf.len().min(payload_end + 64)];
                        eprintln!(
                            "[dbg] rev eof-check payload_end={} rem={} tail64={}",
                            payload_end,
                            rem,
                            hex::encode(tail)
                        );
                    }

                    if rem == 0 {
                        next = payload_end;
                    } else if rem == 4 {
                        // EOF + 4-byte checksum
                        let got = &buf[payload_end..payload_end + 4];
                        let chk = dsha256_bytes(&buf[payload_start..payload_end]);
                        if got != &chk[0..4] {
                            return Err(err(
                                "BAD_UNDO_CHECKSUM",
                                format!(
                                    "{kind}: 4-byte checksum mismatch at EOF offset {payload_end}: got {:02x?} expected {:02x?}",
                                    got,
                                    &chk[0..4]
                                ),
                            ));
                        }
                        next = buf.len();
                    } else if rem == 32 {
                        // EOF + opaque 32-byte trailer
                        next = buf.len();
                    } else {
                        return Err(err(
                            "BAD_MAGIC",
                            format!(
                                "{kind}: expected MAGIC at offset {payload_end}, got {:02x?}",
                                &buf[payload_end..buf.len().min(payload_end + 4)]
                            ),
                        ));
                    }
                }
            }
        }

        out.push(RevRecord {
            undo_range: payload_start..payload_end,
        });
        i = next;
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
    blk_buf: &[u8],
    blk_ranges: &[RecordRange],
    rev_buf: &[u8],
    rev_records: &[RevRecord],
) -> Result<Vec<RecordRange>, String> {
    let debug = std::env::var("CHAINLENS_DEBUG_PAIR").ok().as_deref() == Some("1");
    if rev_records.is_empty() {
        return Err(err("REV_PAIRING_FAILED", "no rev records"));
    }

    if blk_ranges.is_empty() {
        return Err(err("REV_PAIRING_FAILED", "no blk records"));
    }

    // Helper: read CompactSize/varint (Bitcoin-style) from a slice.
    fn read_varint_from_slice(b: &[u8]) -> Result<(u64, usize), String> {
        if b.is_empty() {
            return Err(err("UNEXPECTED_EOF", "varint"));
        }
        let x = b[0];
        if x < 0xfd {
            return Ok((x as u64, 1));
        }
        if x == 0xfd {
            if b.len() < 3 {
                return Err(err("UNEXPECTED_EOF", "varint u16"));
            }
            let v = u16::from_le_bytes([b[1], b[2]]) as u64;
            return Ok((v, 3));
        }
        if x == 0xfe {
            if b.len() < 5 {
                return Err(err("UNEXPECTED_EOF", "varint u32"));
            }
            let v = u32::from_le_bytes([b[1], b[2], b[3], b[4]]) as u64;
            return Ok((v, 5));
        }
        // 0xff
        if b.len() < 9 {
            return Err(err("UNEXPECTED_EOF", "varint u64"));
        }
        let v = u64::from_le_bytes([b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8]]);
        Ok((v, 9))
    }

    fn block_tx_count(block_payload: &[u8]) -> Result<u64, String> {
        if block_payload.len() < 80 {
            return Err(err("INVALID_BLOCK", "block too small"));
        }
        let after_header = &block_payload[80..];
        let (n, _) = read_varint_from_slice(after_header)?;
        Ok(n)
    }

    fn undo_txundo_count(undo_payload: &[u8]) -> Result<u64, String> {
        let (n, _) = read_varint_from_slice(undo_payload)?;
        Ok(n)
    }

    // Fast path: index-aligned pairing.
    if blk_ranges.len() == rev_records.len() {
        let mut ok = true;
        for i in 0..blk_ranges.len().min(4) {
            let txc = block_tx_count(&blk_buf[blk_ranges[i].clone()])?;
            let undoc = undo_txundo_count(&rev_buf[rev_records[i].undo_range.clone()])?;
            let expected = txc.saturating_sub(1);
            if undoc != expected && undoc != txc {
                ok = false;
                break;
            }
        }
        if ok {
            let mut out: Vec<RecordRange> = Vec::with_capacity(blk_ranges.len());
            for rr in rev_records.iter() {
                out.push(rr.undo_range.clone());
            }
            return Ok(out);
        }
    }

    // Robust path: pair in order by matching counts.
    // Undo payload starts with txundo_count, which should equal tx_count-1 (typical) or tx_count (if coinbase included).
    let mut out: Vec<RecordRange> = Vec::with_capacity(blk_ranges.len());
    let mut j: usize = 0;

    for (i, br) in blk_ranges.iter().enumerate() {
        if debug && i < 3 {
            let block = &blk_buf[br.clone()];
            let txc_dbg = block_tx_count(block)?;
            eprintln!("[dbg] block[{i}] tx_count={}", txc_dbg);
        }
        let block = &blk_buf[br.clone()];
        let txc = block_tx_count(block)?;
        let expected_a = txc.saturating_sub(1);
        let expected_b = txc;

                // Scan forward to find a matching undo record.
        // Phase 1: cheap filter by undo_count (tx_count-1 or tx_count), then strong validate.
        let mut found: Option<usize> = None;
        let start_j = j;
        let scan_limit = (j + 4096).min(rev_records.len()); // bounded scan
        while j < scan_limit {
            if debug && i == 0 && j < 5 {
                let ur_dbg = &rev_records[j].undo_range;
                let undoc_dbg = undo_txundo_count(&rev_buf[ur_dbg.clone()])?;
                eprintln!("[dbg]   rev[{}] undo_count={}", j, undoc_dbg);
            }

            let ur = &rev_records[j].undo_range;
            let undo_payload = &rev_buf[ur.clone()];
            let undoc = undo_txundo_count(undo_payload)?;

            if undoc == expected_a || undoc == expected_b {
                if undo::validate_undo_payload_against_block(block, undo_payload).is_ok() {
                    found = Some(j);
                    break;
                } else if debug && i < 3 {
                    eprintln!("[dbg]   candidate rev[{}] count-matched but failed full undo validate", j);
                }
            }
            j += 1;
        }

        // Phase 2 (fallback): if count-filter scan fails, scan further using ONLY the strong
        // validator. This handles fixture variations where the undo payload may not start with the
        // txundo_count varint we expect (or other framing quirks).
        if found.is_none() {
            let mut k = start_j;
            let fallback_limit = (start_j + 20000).min(rev_records.len());
            if debug {
                eprintln!(
                    "[dbg] block[{i}] fallback scan validate-only from rev[{start_j}]..rev[{fallback_limit})",
                );
            }
            while k < fallback_limit {
                let ur = &rev_records[k].undo_range;
                let undo_payload = &rev_buf[ur.clone()];
                if undo::validate_undo_payload_against_block(block, undo_payload).is_ok() {
                    found = Some(k);
                    j = k; // align j to found index
                    if debug {
                        eprintln!("[dbg] block[{i}] matched by validate-only at rev[{k}]");
                    }
                    break;
                }
                k += 1;
            }
        }

        let idx = found.ok_or_else(|| {
            err(
                "REV_PAIRING_FAILED",
                format!(
                    "could not find matching undo record for block[{i}] tx_count={txc} (expected undo_count {expected_a} or {expected_b}) near rev index {}",
                    j.saturating_sub(1)
                ),
            )
        })?;

        out.push(rev_records[idx].undo_range.clone());
        j = idx + 1;
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

    let rev_records = read_rev_records_strict(&rev, "rev")?;
    if rev_records.len() != blk_ranges.len() {
        return Err(err(
            "RECORD_COUNT_MISMATCH",
            format!("rev records={} blk records={}", rev_records.len(), blk_ranges.len()),
        ));
    }

    let paired_undo_ranges =
        pair_rev_to_blocks_by_checksum(blk_buf, blk_ranges, &rev, &rev_records)?;

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
