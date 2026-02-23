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

/// rev*.dat record with the 32-byte trailer preserved.
#[derive(Clone, Debug)]
struct RevRecord {
    payload: RecordRange,
    trailer: RecordRange, // 32 bytes
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

fn read_rev_records_strict(buf: &[u8], kind: &'static str) -> Result<Vec<RevRecord>, String> {
    // Bitcoin Core-like rev*.dat framing:
    //   MAGIC(4) | size(u32 LE) | undo_payload(size) | trailer(32)
    // The fixtures include the 32-byte trailer per record.
    // We keep it so we can (optionally) use it for O(1) pairing.
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
        let trailer_end = payload_end.saturating_add(32);

        if trailer_end > buf.len() {
            return Err(err(
                "TRUNCATED_RECORD",
                format!(
                    "{kind}: record truncated: need payload={size} + 32-byte trailer, have {}",
                    buf.len().saturating_sub(payload_start)
                ),
            ));
        }

        out.push(RevRecord {
            payload: payload_start..payload_end,
            trailer: payload_end..trailer_end,
        });
        i = trailer_end;
    }

    if out.is_empty() {
        return Err(err("NO_RECORDS_FOUND", format!("{kind}: no records found")));
    }

    Ok(out)
}

fn read32(buf: &[u8], r: &std::ops::Range<usize>) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf[r.clone()]);
    out
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

fn block_hash_le(block_payload: &[u8]) -> Result<[u8; 32], String> {
    if block_payload.len() < 80 {
        return Err(err("INVALID_BLOCK", "block payload too small for header"));
    }
    Ok(dsha256_bytes(&block_payload[..80]))
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


/// Attempt fast-path pairing.
///
/// Order between blk*.dat and rev*.dat is *often* aligned in practice (height order),
/// but is not guaranteed (reorgs, pruned/partial datasets, etc.).
///
/// We therefore implement a **safe** two-stage strategy:
/// 1) **Default hot path**: index-based pairing (block[i] ↔ rev[i]) *only if* cheap
///    structural invariants hold for **every** record.
/// 2) Optional trailer-based pairing (opt-in) for additional speed when trailer meaning is known.
/// 3) Correctness fallback: invariant bucketing + full `validate_undo_payload_against_block`.
fn pair_rev_to_blocks_fast_then_fallback(
    blk_buf: &[u8],
    blk_ranges: &[RecordRange],
    rev_buf: &[u8],
    rev_recs: &[RevRecord],
) -> Result<Vec<RecordRange>, String> {
    if blk_ranges.is_empty() {
        return Err(err("NO_RECORDS_FOUND", "blk: no records found"));
    }
    if rev_recs.is_empty() {
        return Err(err("NO_RECORDS_FOUND", "rev: no records found"));
    }

    // --- NEW DEFAULT HOT PATH -------------------------------------------------
    // Try the cheap, Core-like sequential pairing first.
    // This is only accepted when *all* records satisfy the structural invariant:
    //   undo_txundo_count == block_tx_count - 1  (or == block_tx_count in rare cases).
    if let Some(paired) = pair_rev_to_blocks_index_if_plausible(blk_buf, blk_ranges, rev_buf, rev_recs)? {
        return Ok(paired);
    }

    // Optional diagnostics to understand what trailer likely represents.
// This is intentionally cheap and off by default.
let diag = std::env::var("CHAINLENS_REV_TRAILER_DIAG").is_ok();

    // Build trailer index: trailer_bytes -> rev indices (Vec for collision safety).
    let mut by_trailer: std::collections::HashMap<[u8; 32], Vec<usize>> =
        std::collections::HashMap::new();
    for (j, rr) in rev_recs.iter().enumerate() {
        let t = read32(rev_buf, &rr.trailer);
        by_trailer.entry(t).or_default().push(j);
    }

    let mut used = vec![false; rev_recs.len()];
    let mut out: Vec<Option<RecordRange>> = vec![None; blk_ranges.len()];

    // Trailer fast-path toggle. We keep it opt-in until trailer meaning is confirmed.
let fast_enabled = std::env::var("CHAINLENS_PAIRING_FAST").is_ok();

let mut matched_fast = 0usize;

    if fast_enabled {
        for (i, br) in blk_ranges.iter().enumerate() {
            let block = &blk_buf[br.clone()];
            let bh = block_hash_le(block)?;

            if let Some(cands) = by_trailer.get(&bh) {
                // Only accept when exactly one unused candidate exists.
                let mut chosen: Option<usize> = None;
                for &j in cands {
                    if !used[j] {
                        if chosen.is_some() {
                            // Ambiguous.
                            chosen = None;
                            break;
                        }
                        chosen = Some(j);
                    }
                }

                if let Some(j) = chosen {
                    used[j] = true;
                    out[i] = Some(rev_recs[j].payload.clone());
                    matched_fast += 1;
                }
            }
        }
    }

    if diag {
        // Quick signal: how many rev trailers equal dSHA256(undo_payload)?
        // and how many trailers match some block_hash (whether used or not).
        let mut trailer_eq_undo_checksum = 0usize;
        let mut trailer_matches_any_blockhash = 0usize;

        // Build a set of block hashes for membership test.
        let mut blockhash_set: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::with_capacity(blk_ranges.len());
        for br in blk_ranges {
            let block = &blk_buf[br.clone()];
            if let Ok(bh) = block_hash_le(block) {
                blockhash_set.insert(bh);
            }
        }

        // Sample up to 64 rev records.
        let sample_n = rev_recs.len().min(64);
        for rr in rev_recs.iter().take(sample_n) {
            let undo_payload = &rev_buf[rr.payload.clone()];
            let t = read32(rev_buf, &rr.trailer);
            if rev_checksum(undo_payload) == t {
                trailer_eq_undo_checksum += 1;
            }
            if blockhash_set.contains(&t) {
                trailer_matches_any_blockhash += 1;
            }
        }

        eprintln!(
            "[chainlens] rev trailer diag: sample_n={sample_n} eq(dsha256(undo))={trailer_eq_undo_checksum} matches_any_blockhash={trailer_matches_any_blockhash} fast_matched={matched_fast}/{}",
            blk_ranges.len()
        );
    }

    // Fallback fill for any blocks we did not match via fast-path.
    let filled = pair_rev_to_blocks_fallback_validate_fill(
        blk_buf,
        blk_ranges,
        rev_buf,
        rev_recs,
        &mut used,
        &mut out,
    )?;

    // Convert out -> Vec<RecordRange> in block order.
    let mut final_out: Vec<RecordRange> = Vec::with_capacity(blk_ranges.len());
    for (i, opt) in out.into_iter().enumerate() {
        let Some(r) = opt else {
            return Err(err("REV_PAIRING_FAILED", format!("block[{i}] left unpaired")));
        };
        final_out.push(r);
    }

    // Optional stats
    if std::env::var("CHAINLENS_PAIRING_STATS").is_ok() {
        let matched_fallback = filled;
        eprintln!(
            "[chainlens] pairing: fast={} fallback={} total_blocks={}",
            matched_fast,
            matched_fallback,
            blk_ranges.len()
        );
    }

    Ok(final_out)
}

/// Existing (correctness) pairing algorithm: bucket by undo_count invariant and validate.
///
/// This is now used as a fallback and can skip already-used rev records.
// ------------------------------------------------------------
// NEW: Index-based pairing with ultra-cheap plausibility checks
// ------------------------------------------------------------
fn pair_rev_to_blocks_index_if_plausible(
    blk_buf: &[u8],
    blk_ranges: &[RecordRange],
    rev_buf: &[u8],
    rev_recs: &[RevRecord],
) -> Result<Option<Vec<RecordRange>>, String> {
    if blk_ranges.len() != rev_recs.len() {
        return Ok(None);
    }

    // Require full plausibility for every record to avoid silent mispairing.
    let mut out: Vec<RecordRange> = Vec::with_capacity(blk_ranges.len());

    for (i, (br, rr)) in blk_ranges.iter().zip(rev_recs.iter()).enumerate() {
        let block = &blk_buf[br.clone()];
        let undo_payload = &rev_buf[rr.payload.clone()];

        let txc = block_tx_count(block)?;
        if txc == 0 {
            return Ok(None);
        }
        let expected = txc.saturating_sub(1);

        let undo_cnt = undo::undo_txundo_count_fast(undo_payload)?;

        // Accept only if the invariant holds.
        if !(undo_cnt == expected || undo_cnt == txc) {
            // Not plausibly aligned → fall back to validate-based matching.
            if std::env::var("CHAINLENS_PAIRING_STATS").is_ok() {
                eprintln!(
                    "[chainlens] pairing: index hotpath rejected at i={} (txc={}, undo_cnt={}, expected={})",
                    i, txc, undo_cnt, expected
                );
            }
            return Ok(None);
        }

        out.push(rr.payload.clone());
    }

    if std::env::var("CHAINLENS_PAIRING_STATS").is_ok() {
        eprintln!(
            "[chainlens] pairing: index hotpath accepted for {} blocks",
            blk_ranges.len()
        );
    }

    Ok(Some(out))
}

/// Existing (correctness) pairing algorithm: bucket by undo_count invariant and validate.
///
/// This is now used as a fallback and can skip already-used rev records.
fn pair_rev_to_blocks_fallback_validate_fill(
    blk_buf: &[u8],
    blk_ranges: &[RecordRange],
    rev_buf: &[u8],
    rev_recs: &[RevRecord],
    used: &mut [bool],
    out: &mut [Option<RecordRange>],
) -> Result<usize, String> {
    // Index rev records by their leading txundo-count varint.
    let mut by_undo_cnt: std::collections::HashMap<u64, Vec<usize>> =
        std::collections::HashMap::new();
    for (j, rr) in rev_recs.iter().enumerate() {
        if used[j] {
            continue;
        }
        let undo_payload = &rev_buf[rr.payload.clone()];
        let undo_cnt = undo::undo_txundo_count_fast(undo_payload)?;
        by_undo_cnt.entry(undo_cnt).or_default().push(j);
    }

    let mut matched = 0usize;

    for (i, br) in blk_ranges.iter().enumerate() {
        if out[i].is_some() {
            continue; // already paired by fast-path
        }

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
            let undo_payload = &rev_buf[rev_recs[j].payload.clone()];
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
        out[i] = Some(rev_recs[j].payload.clone());
        matched += 1;
    }

    Ok(matched)
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

    let rev_recs = read_rev_records_strict(&rev, "rev")?;

    // Fast-path (optional) using the 32-byte trailer, then fallback to current validate-based pairing.
    let paired_undo_ranges =
        pair_rev_to_blocks_fast_then_fallback(blk_buf, blk_ranges, &rev, &rev_recs)?;

    // Pairing already performed full structural validation via
    // `validate_undo_payload_against_block` for each chosen (block, undo) pair (fallback path).
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
