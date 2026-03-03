// src/btc/block/io.rs
//
// Block / undo file decoding and pairing logic.
//
// Responsibilities:
//   - XOR-decode blk*.dat / rev*.dat using xor.dat key.
//   - Parse strict Bitcoin Core-style record framing.
//   - Pair block records with corresponding undo records.
//   - Provide fast-path pairing with safe fallback validation.

use super::parser; // Import sibling module `parser` (block parsing utilities)
use super::undo; // Import sibling module `undo` (undo parsing + validation)

use sha2::{Digest, Sha256}; // Import SHA256 hashing traits + concrete hasher

/// Bitcoin mainnet magic bytes (used by fixtures here).
const MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9]; // MAGIC bytes for mainnet blk/rev record headers

/// Format a structured error string with code prefix.
fn err(code: &str, msg: impl AsRef<str>) -> String { // Build consistent "CODE: message" errors
    format!("{code}: {}", msg.as_ref()) // Return formatted string
} // End of err helper

/// Check whether an XOR key is all-zero.
fn key_is_all_zero(key: &[u8]) -> bool { // Return true if key contains only 0 bytes
    key.iter().all(|&b| b == 0) // Check all bytes == 0
}

/// A zero-copy record reference into a decoded dat buffer.
pub(crate) type RecordRange = std::ops::Range<usize>; // Range indexes into a buffer (start..end)

/// rev*.dat record with the 32-byte trailer preserved.
#[derive(Clone, Debug)] // Make RevRecord clonable and printable for debug
struct RevRecord { // Internal representation of one rev record
    payload: RecordRange, // Byte range for the undo payload
    trailer: RecordRange, // Byte range for the 32-byte trailer (usually block hash)
}

/// XOR-decode a buffer using repeating key with positional shift.
pub(crate) fn xor_decode_with_shift(mut data: Vec<u8>, key: &[u8], shift: usize) -> Vec<u8> { // XOR-decode bytes with repeating key
    if key.is_empty() { // If key has length 0
        return data; // Nothing to do, return input unchanged
    } // End key.is_empty check
    let klen = key.len(); // Cache key length for modulo
    for (i, b) in data.iter_mut().enumerate() { // Iterate every mutable byte with index
        *b ^= key[(i + shift) % klen]; // XOR byte with key byte (shifted stream)
    } // End XOR loop
    data // Return decoded data
} // End xor_decode_with_shift

/// Parse strict blk*.dat-style framing into zero-copy payload ranges.
///
/// Format: MAGIC(4) | size(u32 LE) | payload(size)
pub(crate) fn read_dat_records_strict( // Parse a decoded blk buffer into payload ranges
    buf: &[u8], // Full decoded file buffer
    kind: &'static str, // "blk" or "rev" label for error text
) -> Result<Vec<RecordRange>, String> { // Return list of payload ranges or error
    let mut out: Vec<RecordRange> = Vec::new(); // Prepare output vector
    let mut i: usize = 0; // Cursor offset into buf

    while i + 8 <= buf.len() { // Need at least 8 bytes for header
        if buf[i..i + 4] != MAGIC { // Check MAGIC prefix at current offset
            return Err(err( // Return structured error
                "BAD_MAGIC", // Error code
                format!( // Build detail message
                    "{kind}: expected MAGIC at offset {i}, got {:02x?}", // Describe mismatch
                    &buf[i..i + 4] // Show actual bytes
                ),
            )); // End Err
        } // End MAGIC check

        let size = u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]) as usize; // Read payload length
        let payload_start = i + 8; // Payload begins after 8-byte header
        let payload_end = payload_start.saturating_add(size); // Compute end index safely

        if payload_end > buf.len() { // If payload would exceed buffer
            return Err(err( // Return truncation error
                "TRUNCATED_RECORD", // Error code
                format!( // Build message
                    "{kind}: record payload truncated: need {size}, have {}", // Explain needed vs available
                    buf.len().saturating_sub(payload_start) // Compute available bytes
                ),
            )); // End Err
        } // End truncation check

        out.push(payload_start..payload_end); // Store the payload slice range
        i = payload_end; // Move cursor to next record header
    } // End record loop

    if out.is_empty() { // If we never found any records
        return Err(err("NO_RECORDS_FOUND", format!("{kind}: no records found"))); // Return error
    } // End empty check

    Ok(out) // Return parsed ranges
} // End read_dat_records_strict

/// Parse strict rev*.dat framing including 32-byte trailer.
///
/// Format:
///   MAGIC(4) | size(u32 LE) | undo_payload(size) | trailer(32) // Exact format
fn read_rev_records_strict(buf: &[u8], kind: &'static str) -> Result<Vec<RevRecord>, String> { // Parse rev buffer into payload+trailer ranges
    let mut out: Vec<RevRecord> = Vec::new(); // Output undo records
    let mut i: usize = 0; // Cursor offset

    while i + 8 <= buf.len() { // Need at least header bytes
        if buf[i..i + 4] != MAGIC { // Validate MAGIC
            return Err(err( // Return bad magic
                "BAD_MAGIC", // Error code
                format!( // Detail message
                    "{kind}: expected MAGIC at offset {i}, got {:02x?}", // Describe mismatch
                    &buf[i..i + 4] // Actual bytes
                ),
            )); // End Err
        } // End MAGIC check

        let size = u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]) as usize; // Read undo payload size
        let payload_start = i + 8; // Payload begins after header
        let payload_end = payload_start.saturating_add(size); // Payload end index
        let trailer_end = payload_end.saturating_add(32); // Trailer is always 32 bytes

        if trailer_end > buf.len() { // Ensure we have payload + trailer
            return Err(err( // Return truncation error
                "TRUNCATED_RECORD", // Code
                format!( // Message
                    "{kind}: record truncated: need payload={size} + 32-byte trailer, have {}", // Needed vs available
                    buf.len().saturating_sub(payload_start) // Available bytes
                ),
            )); // End Err
        } // End truncation check

        out.push(RevRecord { // Store record ranges
            payload: payload_start..payload_end, // Payload range
            trailer: payload_end..trailer_end, // Trailer range
        }); // End push
        i = trailer_end; // Advance to next record
    } // End loop

    if out.is_empty() { // If no records parsed
        return Err(err("NO_RECORDS_FOUND", format!("{kind}: no records found"))); // Error
    } // End empty check

    Ok(out) // Return parsed RevRecord list
} // End read_rev_records_strict

/// Read 32 bytes from a buffer range. // Doc for read32
fn read32(buf: &[u8], r: &std::ops::Range<usize>) -> [u8; 32] { // Copy 32 bytes into fixed array
    let mut out = [0u8; 32]; // Allocate output array
    out.copy_from_slice(&buf[r.clone()]); // Copy bytes from buffer slice
    out // Return array
} // End read32

/// Double SHA256 (Bitcoin-style hash). // Doc for hashing helper
fn dsha256_bytes(data: &[u8]) -> [u8; 32] { // Return HASH256(data)
    let h1 = Sha256::digest(data); // Compute SHA256(data)
    let h2 = Sha256::digest(h1); // Compute SHA256(SHA256(data))
    let mut out = [0u8; 32]; // Allocate output array
    out.copy_from_slice(&h2); // Copy hash bytes
    out // Return final hash
} // End dsha256_bytes

#[allow(dead_code)] // This helper may be unused in some builds
/// Compute checksum of undo payload (legacy helper). // Doc: undo checksum
fn rev_checksum(undo_payload: &[u8]) -> [u8; 32] { // Compute checksum of undo payload
    dsha256_bytes(undo_payload) // Return HASH256(undo_payload)
} // End rev_checksum

/// Compute block hash (little-endian internal representation). // Doc: block hash from header
fn block_hash_le(block_payload: &[u8]) -> Result<[u8; 32], String> { // Compute hash of 80-byte header
    if block_payload.len() < 80 { // Validate minimum header length
        return Err(err("INVALID_BLOCK", "block payload too small for header")); // Error if truncated
    } // End size check
    Ok(dsha256_bytes(&block_payload[..80])) // Hash first 80 bytes
} // End block_hash_le

/// Attempt fast pairing first, then fallback to validation-based pairing. // Doc: pairing strategy
///
/// Strategy:
///   1) Try index-based alignment if structurally plausible. // Fastest path
///   2) Optional trailer-based pairing (env-controlled). // Use rev trailer hash if enabled
///   3) Fallback: bucket by undo_count + full validation. // Correctness fallback
fn pair_rev_to_blocks_fast_then_fallback( // Main pairing function
    blk_buf: &[u8], // Entire decoded blk buffer
    blk_ranges: &[RecordRange], // Payload ranges for blocks
    rev_buf: &[u8], // Entire decoded rev buffer
    rev_recs: &[RevRecord], // Parsed rev payload+trailer records
) -> Result<Vec<RecordRange>, String> { // Return undo payload ranges aligned to blocks
    if blk_ranges.is_empty() { // Guard: no blk records
        return Err(err("NO_RECORDS_FOUND", "blk: no records found")); // Error
    } // End guard
    if rev_recs.is_empty() { // Guard: no rev records
        return Err(err("NO_RECORDS_FOUND", "rev: no records found")); // Error
    } // End guard

    if let Some(paired) = // Try cheap index pairing
        pair_rev_to_blocks_index_if_plausible(blk_buf, blk_ranges, rev_buf, rev_recs)? // Attempt hot path
    { // If hot path returned Some
        return Ok(paired); // Accept hot path pairing
    } // End hot path

    let mut by_trailer: std::collections::HashMap<[u8; 32], Vec<usize>> = // Map trailer hash -> rev indices
        std::collections::HashMap::new(); // Create empty hash map
    for (j, rr) in rev_recs.iter().enumerate() { // Iterate all rev records with index
        let t = read32(rev_buf, &rr.trailer); // Read trailer bytes (32) into array
        by_trailer.entry(t).or_default().push(j); // Append j to bucket for this trailer
    } // End trailer map build

    let mut used = vec![false; rev_recs.len()]; // Track which rev records have been assigned
    let mut out: Vec<Option<RecordRange>> = vec![None; blk_ranges.len()]; // Output slots per block

    let fast_enabled = std::env::var("CHAINLENS_PAIRING_FAST").is_ok(); // Env toggle for trailer fast pairing
    let mut matched_fast = 0usize; // Counter for fast matches

    if fast_enabled { // Only run trailer pairing if enabled
        for (i, br) in blk_ranges.iter().enumerate() { // Iterate blocks with index
            let block = &blk_buf[br.clone()]; // Slice block payload
            let bh = block_hash_le(block)?; // Compute block hash (little-endian)

            if let Some(cands) = by_trailer.get(&bh) { // Get candidate rev records for this hash
                let mut chosen: Option<usize> = None; // Track unique candidate
                for &j in cands { // Iterate candidate rev indices
                    if !used[j] { // Only consider unused rev record
                        if chosen.is_some() { // If we already chose one
                            chosen = None; // Mark as ambiguous
                            break; // Stop; we require unique match
                        } // End ambiguity check
                        chosen = Some(j); // Select this candidate
                    } // End unused check
                } // End candidate loop

                if let Some(j) = chosen { // If we found exactly one unique candidate
                    used[j] = true; // Mark this rev record as used
                    out[i] = Some(rev_recs[j].payload.clone()); // Assign its payload range to this block index
                    matched_fast += 1; // Increase counter
                } // End unique match
            } // End candidates exist
        } // End block loop
    } // End fast_enabled

    let filled = pair_rev_to_blocks_fallback_validate_fill( // Run fallback for remaining slots
        blk_buf, // Pass blk buffer
        blk_ranges, // Pass block ranges
        rev_buf, // Pass rev buffer
        rev_recs, // Pass rev records
        &mut used, // Pass mutable used flags
        &mut out, // Pass mutable output slots
    )?; // Propagate errors

    let mut final_out: Vec<RecordRange> = Vec::with_capacity(blk_ranges.len()); // Final output ranges
    for (i, opt) in out.into_iter().enumerate() { // Convert Option ranges into concrete list
        let Some(r) = opt else { // If any block is still missing undo
            return Err(err("REV_PAIRING_FAILED", format!("block[{i}] left unpaired"))); // Error
        }; // End missing check
        final_out.push(r); // Push concrete range
    } // End conversion loop

    if std::env::var("CHAINLENS_PAIRING_STATS").is_ok() { // Optional debug stats
        eprintln!( // Print stats to stderr
            "[chainlens] pairing: fast={} fallback={} total_blocks={}", // Format string
            matched_fast, // How many were paired via trailer fast path
            filled, // How many were filled by fallback
            blk_ranges.len() // Total blocks
        ); // End eprintln
    } // End stats

    Ok(final_out) // Return final aligned undo ranges
} // End pair_rev_to_blocks_fast_then_fallback

/// Ultra-cheap index-based pairing. // Doc: cheapest pairing method
///
/// Accept only if ALL records satisfy the undo_count invariant. // Safety condition for index pairing
fn pair_rev_to_blocks_index_if_plausible( // Try pairing by index position
    blk_buf: &[u8], // Decoded blk buffer
    blk_ranges: &[RecordRange], // Block payload ranges
    rev_buf: &[u8], // Decoded rev buffer
    rev_recs: &[RevRecord], // Rev records
) -> Result<Option<Vec<RecordRange>>, String> { // Some(ranges) if plausible, else None
    if blk_ranges.len() != rev_recs.len() { // Index pairing requires equal count
        return Ok(None); // Reject if counts differ
    } // End count check

    let mut out: Vec<RecordRange> = Vec::with_capacity(blk_ranges.len()); // Prepare output ranges

    for (i, (br, rr)) in blk_ranges.iter().zip(rev_recs.iter()).enumerate() { // Iterate aligned pairs
        let block = &blk_buf[br.clone()]; // Slice block payload
        let undo_payload = &rev_buf[rr.payload.clone()]; // Slice undo payload

        let txc = parser::block_tx_count_fast(block)?; // Read tx_count quickly from block
        if txc == 0 { // tx_count must be >= 1
            return Ok(None); // Reject as implausible
        } // End txc check
        let expected = txc.saturating_sub(1); // Expected undo count for non-coinbase txs

        let undo_cnt = undo::undo_txundo_count_fast(undo_payload)?; // Read undo txundo count quickly

        if !(undo_cnt == expected || undo_cnt == txc) { // Accept either expected or txc (compat heuristic)
            if std::env::var("CHAINLENS_PAIRING_STATS").is_ok() { // Optional debug stats
                eprintln!( // Print rejection reason
                    "[chainlens] pairing: index hotpath rejected at i={} (txc={}, undo_cnt={}, expected={})", // Message
                    i, // Index
                    txc, // Block tx_count
                    undo_cnt, // Undo count
                    expected // Expected undo count
                ); // End eprintln
            } // End stats
            return Ok(None); // Reject hot path pairing
        } // End invariant check

        out.push(rr.payload.clone()); // Accept this payload range
    } // End loop

    Ok(Some(out)) // Return paired ranges
} // End pair_rev_to_blocks_index_if_plausible

/// Fallback pairing using structural bucketing + semantic validation. // Doc: slower but correct
fn pair_rev_to_blocks_fallback_validate_fill( // Fill missing out[] slots by validating candidates
    blk_buf: &[u8], // Decoded blk buffer
    blk_ranges: &[RecordRange], // Block ranges
    rev_buf: &[u8], // Decoded rev buffer
    rev_recs: &[RevRecord], // Rev records
    used: &mut [bool], // Mutable used flags for rev records
    out: &mut [Option<RecordRange>], // Mutable output slots (None = not assigned yet)
) -> Result<usize, String> { // Return number of newly matched records
    let mut by_undo_cnt: std::collections::HashMap<u64, Vec<usize>> = // Map undo_count -> rev indices
        std::collections::HashMap::new(); // Create map
    for (j, rr) in rev_recs.iter().enumerate() { // Iterate rev records
        if used[j] { // Skip already used
            continue; // Continue loop
        } // End skip
        let undo_payload = &rev_buf[rr.payload.clone()]; // Slice undo payload
        let undo_cnt = undo::undo_txundo_count_fast(undo_payload)?; // Extract undo count
        by_undo_cnt.entry(undo_cnt).or_default().push(j); // Bucket index j under undo_cnt
    } // End bucket build

    let mut matched = 0usize; // Count how many matches we assign

    for (i, br) in blk_ranges.iter().enumerate() { // Iterate blocks by index
        if out[i].is_some() { // If already assigned
            continue; // Skip
        } // End skip

        let block = &blk_buf[br.clone()]; // Slice block payload
        let txc = parser::block_tx_count_fast(block)?; // Fast tx_count
        if txc == 0 { // Validate
            return Err(err("INVALID_BLOCK", format!("block[{i}] tx_count=0"))); // Error
        } // End validate

        let expected = txc.saturating_sub(1); // Expected undo count

        let mut cand: Vec<usize> = Vec::new(); // Candidate rev indices list
        if let Some(v) = by_undo_cnt.get(&expected) { // Candidates with expected undo count
            cand.extend_from_slice(v); // Add them
        } // End expected bucket
        if expected != txc { // Only add txc bucket if different
            if let Some(v) = by_undo_cnt.get(&txc) { // Candidates with undo count == txc
                cand.extend_from_slice(v); // Add them too
            } // End txc bucket
        } // End conditional

        // Try to find exactly one candidate that validates against this block. // High-level goal
        let mut chosen: Option<usize> = None; // Track chosen candidate
        for &j in cand.iter() { // Iterate candidate indices
            if used[j] { // Skip used candidates
                continue; // Continue
            } // End skip

            let undo_payload = &rev_buf[rev_recs[j].payload.clone()]; // Slice candidate undo payload
            if undo::validate_undo_payload_against_block(block, undo_payload).is_ok() { // Validate by semantic check
                if chosen.is_some() { // If we already found one valid candidate
                    chosen = None; // Mark ambiguous
                    break; // Stop search
                } // End ambiguity check
                chosen = Some(j); // Save this candidate
            } // End validation ok
        } // End candidate loop

        let Some(j) = chosen else { // If we couldn't find a unique valid undo
            return Err(err( // Return pairing failure
                "REV_PAIRING_FAILED", // Code
                format!( // Message
                    "could not find matching undo for block[{i}] (tx_count={txc}, expected_undo_count={expected})" // Details
                ),
            )); // End error
        }; // End else

        used[j] = true; // Mark rev record as used
        out[i] = Some(rev_recs[j].payload.clone()); // Assign the payload range
        matched += 1; // Increase matched count
    } // End blocks loop

    Ok(matched) // Return how many were matched
} // End fallback pairing

/// Validate block payload structurally + verify merkle root. // Doc: sanity check for decoded block
fn validate_block_payload(block: &[u8]) -> Result<(), String> { // Validate block structure and merkle
    let mut bc = parser::Cursor::new(block); // Create cursor to parse from block bytes

    if bc.remaining() < 80 { // Need at least the 80-byte header
        return Err(err("INVALID_BLOCK", "block payload too small for header")); // Error if too small
    } // End header size check

    let header = bc.take(80)?; // Read 80-byte header
    let mut hc = parser::Cursor::new(header); // Cursor for header fields

    let _version = hc.take_u32_le()?; // Read version (unused here)
    let _prev = hc.take(32)?; // Read prev block hash (unused here)

    let merkle = { // Read merkle root into fixed array
        let s = hc.take(32)?; // Read 32 bytes
        let mut a = [0u8; 32]; // Allocate array
        a.copy_from_slice(s); // Copy bytes
        a // Return array
    }; // End merkle block

    let _ts = hc.take_u32_le()?; // Read timestamp (unused)
    let _bits = hc.take_u32_le()?; // Read nBits (unused)
    let _nonce = hc.take_u32_le()?; // Read nonce (unused)

    let tx_count = parser::read_varint(&mut bc)?; // Read tx count varint
    if tx_count == 0 { // Blocks must have at least coinbase
        return Err(err("INVALID_BLOCK", "tx_count=0")); // Error
    } // End tx_count check

    let mut txids_le: Vec<[u8; 32]> = Vec::with_capacity(tx_count as usize); // Collect txids for merkle
    for _ in 0..tx_count { // Loop each tx
        let txid_le = parser::parse_tx_skip_and_txid_le(block, &mut bc)?; // Skip tx bytes and compute txid
        txids_le.push(txid_le); // Push txid into vector
    } // End tx loop

    let mr_calc = parser::merkle_root(&txids_le); // Compute merkle root from txids
    if mr_calc != merkle { // Compare computed vs header merkle
        return Err(err("MERKLE_MISMATCH", "merkle mismatch")); // Error if mismatch
    } // End compare

    Ok(()) // Validation succeeded
} // End validate_block_payload

/// Decode blk file with best-effort key validation. // Doc: decode and optionally validate
fn decode_blk_best(blk_raw: Vec<u8>, key: &[u8]) -> Result<Vec<u8>, String> { // Decode blk by XORing with key if needed
    let blk = if key.is_empty() || key_is_all_zero(key) { // If key is empty or all zeros
        blk_raw // Treat as plaintext
    } else {
        xor_decode_with_shift(blk_raw, key, 0) // XOR-decode with shift 0
    }; // End conditional

    let strict_key = std::env::var("CHAINLENS_STRICT_KEY").is_ok(); // Env toggle: always validate decode
    if strict_key || !(key.is_empty() || key_is_all_zero(key)) { // Validate if strict or if we actually used a key
        let recs = read_dat_records_strict(&blk, "blk")?; // Parse record ranges
        if recs.is_empty() { // Should not happen because strict parser errors, but keep guard
            return Err(err("BLK_DECODE_FAILED", "no blk records")); // Error
        } // End guard
        let first = &blk[recs[0].clone()]; // Grab first block record payload
        validate_block_payload(first).map_err(|e| err("BLK_DECODE_FAILED", e))?; // Validate structure+merkle
    } // End validation block

    Ok(blk) // Return decoded blk buffer
} // End decode_blk_best

/// Decode blk and return buffer + record ranges. // Doc: convenience wrapper
pub(crate) fn decode_blk_best_to_records( // Decode blk and also split into records
    blk_raw: Vec<u8>, // Raw blk file bytes
    key: &[u8], // XOR key bytes
) -> Result<(Vec<u8>, Vec<RecordRange>), String> { // Return decoded buffer + ranges
    let blk = decode_blk_best(blk_raw, key)?; // Decode blk file
    let blk_ranges = read_dat_records_strict(&blk, "blk")?; // Parse record ranges
    Ok((blk, blk_ranges)) // Return both
} // End decode_blk_best_to_records

/// Decode rev file and pair undo payloads to blocks. // Doc: decode and align rev with blk
fn decode_rev_records_against_blocks( // Decode rev and compute undo ranges in block order
    rev_raw: Vec<u8>, // Raw rev file bytes
    key: &[u8], // XOR key
    blk_buf: &[u8], // Decoded blk buffer
    blk_ranges: &[RecordRange], // Block record ranges
) -> Result<(Vec<u8>, Vec<RecordRange>), String> { // Return decoded rev buffer + aligned undo ranges
    let mut rev = rev_raw; // Make rev mutable so we can replace with decoded
    if !key.is_empty() && !key_is_all_zero(key) { // Only decode if key is meaningful
        rev = xor_decode_with_shift(rev, key, 0); // XOR-decode rev
    } // End decode

    let rev_recs = read_rev_records_strict(&rev, "rev")?; // Parse rev records (payload + trailer)

    let paired_undo_ranges = // Compute pairing from blocks to undo payloads
        pair_rev_to_blocks_fast_then_fallback(blk_buf, blk_ranges, &rev, &rev_recs)?; // Use main pairing function

    if std::env::var("CHAINLENS_STRICT_UNDO").is_ok() { // Optional strict validation mode
        for (i, (br, ur)) in blk_ranges.iter().zip(paired_undo_ranges.iter()).enumerate() { // Iterate pairs
            let block = &blk_buf[br.clone()]; // Slice block payload
            let undo_payload = &rev[ur.clone()]; // Slice undo payload
            undo::validate_undo_payload_against_block(block, undo_payload).map_err(|e| { // Validate undo against block
                err( // Map error into structured string
                    "UNDO_BLOCK_PAIR_MISMATCH", // Error code
                    format!("record[{i}] undo did not validate against block: {e}"), // Detail message
                )
            })?; // Propagate error
        } // End strict loop
    } // End strict mode

    Ok((rev, paired_undo_ranges)) // Return decoded rev + aligned undo ranges
} // End decode_rev_records_against_blocks

/// Decode blk + rev together and return:
///   (blk_buf, blk_ranges, rev_buf, undo_ranges) // Doc: combined decode output
pub(crate) fn decode_blk_and_rev_best( // Decode both files and align block<->undo records
    blk_raw: Vec<u8>, // Raw blk file bytes
    rev_raw: Vec<u8>, // Raw rev file bytes
    key: &[u8], // XOR key
) -> Result<(Vec<u8>, Vec<RecordRange>, Vec<u8>, Vec<RecordRange>), String> { // Return decoded buffers + ranges
    let blk = decode_blk_best(blk_raw, key)?; // Decode blk
    let blk_ranges = read_dat_records_strict(&blk, "blk")?; // Parse block ranges
    let (rev, undo_ranges) = // Decode rev and align to blocks
        decode_rev_records_against_blocks(rev_raw, key, &blk, &blk_ranges)?; // Pair rev to blk
    Ok((blk, blk_ranges, rev, undo_ranges)) // Return everything
} // End decode_blk_and_rev_best
