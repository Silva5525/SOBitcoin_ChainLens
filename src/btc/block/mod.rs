// src/btc/block/mod.rs
//                                                    
//
// Block-mode orchestration layer.
//
// Responsibilities:
//   - Glue together io.rs (decode), parser.rs (structure), undo.rs (UTXO restore).   // Connect lower-level components
//   - Run high-speed CoreTx analysis over all transactions in a block.              // Analyze every tx efficiently
//   - Build compact BlockReport structures for CLI/Web output.                      // Produce JSON-friendly results
//
// Design goals:
//   - Zero-copy parsing of block payloads.            // Avoid allocating/copying when slicing the raw bytes
//   - CoreTx hot path (avoid heavy TxReport construction in loops). // Keep inner loops lightweight
//   - Bounded parallelism for large blocks.           // Use threads, but not unbounded / not too many

mod report;                                           // Declare internal submodule (file: report.rs). Not public.
mod io;                                               // Declare internal submodule (file: io.rs). Not public.
mod parser;                                           // Declare internal submodule (file: parser.rs). Not public.
mod undo;                                             // Declare internal submodule (file: undo.rs). Not public.

pub use report::{                                     // Re-export selected public report types at `btc::block::...`
    BlockHeaderReport,                                // Public report: header fields + hashes
    BlockReport,                                      // Public report: full block JSON container
    BlockStatsReport,                                 // Public report: aggregated stats
    CoinbaseReport,                                   // Public report: coinbase info
};

use std::collections::BTreeMap;                       // Ordered map (stable JSON key order)
use std::fs;                                          // File IO (read blk/rev/xor files)

// Public JSON type re-exported from btc::tx          // Note: TxReport is defined in tx module, used here for output
use crate::btc::tx::TxReport;                         // Import TxReport type for block report transactions

// Internal core engine types (not re-exported at btc::tx level) // These are “hot-path” types
use crate::btc::tx::core::{                           // Pull items from tx core module
    analyze_tx_core_lite,                             // Fast tx analyzer returning CoreTx
    CoreTx,                                           // Internal tx representation (fast, minimal)
};

use parser::{                                         // Import helper utilities from parser module
    bytes_to_hex,                                     // Convert raw bytes to hex string
    hash_to_display_hex,                              // Convert 32-byte hash (LE) into display hex (BE)
    merkle_root,                                      // Compute merkle root from txids
    Cursor,                                           // Safe cursor to read bytes without panics
};

/// Classify nLockTime semantics according to Bitcoin rules.
#[inline]                                             // Hint compiler to inline (small function)
fn locktime_type_str(locktime: u32) -> &'static str { // Returns a static string describing locktime meaning
    if locktime == 0 {                                // Locktime 0 means “no locktime”
        return "none";                               // Return type label
    }
    if locktime < 500_000_000 {                       // Bitcoin rule: below threshold = block height
        "block_height"                                // Return label for height-based locktime
    } else {                                          // Otherwise it is a UNIX timestamp
        "unix_timestamp"                              // Return label for time-based locktime
    }
}

/// Convert a `CoreTx` (hot-path internal type) into a lightweight `TxReport`.
///
/// This avoids vin/vout reconstruction in block mode. // We keep block loop fast by not building heavy structures
#[inline]                                             // Hint: inline for speed
fn core_to_tx_report_lite(network: &str, idx: usize, tx: &CoreTx) -> TxReport { // Build a minimal TxReport
    let txid = hash_to_display_hex(tx.txid_le);        // Convert txid (little-endian) to display hex
    let wtxid = tx.wtxid_le.map(hash_to_display_hex);  // If segwit, convert wtxid too

    // Coinbase has no fee.                            // Fee is defined only for non-coinbase transactions
    let fee_sats = if idx == 0 { 0 } else { tx.fee };  // tx index 0 = coinbase → fee=0
    let fee_rate_sat_vb = if tx.vbytes == 0 {          // Avoid division by zero
        0.0                                            // If vbytes is 0, set fee rate to 0
    } else {
        (fee_sats as f64) / (tx.vbytes as f64)         // Fee rate in sat/vB
    };

    TxReport {                                        // Construct the JSON output struct
        ok: true,                                     // Mark analysis ok
        network: network.to_string(),                 // Copy network string ("mainnet")
        segwit: tx.segwit,                            // Whether segwit was detected
        txid,                                         // Display txid
        wtxid,                                        // Optional display wtxid
        version: tx.version,                          // tx version
        locktime: tx.locktime,                        // raw locktime
        locktime_value: tx.locktime,                  // same value (kept for compatibility)
        size_bytes: tx.size_bytes,                    // serialized size in bytes
        weight: tx.weight,                            // weight units
        vbytes: tx.vbytes,                            // virtual bytes
        fee_sats,                                     // computed fee (0 for coinbase)
        fee_rate_sat_vb,                              // computed fee rate
        total_input_sats: tx.total_input,             // sum of inputs (from undo prevouts)
        total_output_sats: tx.total_output,           // sum of outputs
        rbf_signaling: tx.rbf,                        // RBF signaling flag
        locktime_type: locktime_type_str(tx.locktime).to_string(), // locktime interpretation
        vin: Vec::new(),                              // empty: block-mode lite does not populate vin
        vout: Vec::new(),                             // empty: block-mode lite does not populate vout
        warnings: Vec::new(),                         // empty: no per-tx warnings here
        segwit_savings: None,                         // empty: not computed in lite path
    }
}

/// Map internal script type index → display string.   // Converts compact numeric type to readable label
#[inline]                                             // Inline: small match
fn script_type_idx_to_str(idx: usize) -> &'static str { // Convert index to string
    match idx {                                       // Match against known script types
        0 => "p2pkh",                                  // Pay-to-PubKey-Hash
        1 => "p2sh",                                   // Pay-to-Script-Hash
        2 => "p2wpkh",                                 // Native segwit P2WPKH
        3 => "p2wsh",                                  // Native segwit P2WSH
        4 => "p2tr",                                   // Taproot
        5 => "op_return",                              // OP_RETURN output
        _ => "unknown",                                // Everything else
    }
}

use undo::parse_undo_payload_strict_slices;           // Import undo parser that returns borrowed slices

/// Helper for structured error strings.
fn err(code: &str, msg: impl AsRef<str>) -> String { // Accepts any string-like message
    format!("{code}: {}", msg.as_ref())               // Format as "CODE: message"
}

/// High-speed block transaction analysis using undo slices.
///
/// Returns `CoreTx` to avoid JSON/report construction in the hot path. // Keep it fast
fn analyze_txs_with_undo_slices_core<'a>(             // Lifetime 'a ties CoreTx borrows to block/undo buffers
    block: &'a [u8],                                  // Full raw block payload bytes
    tx_ranges: &[(usize, usize)],                     // Offsets for each tx inside `block`
    undo_prevouts: &'a [Vec<(u64, &'a [u8])>],         // For each non-coinbase tx: prevout (value, scriptPubKey)
) -> Result<Vec<CoreTx<'a>>, String> {                // Returns CoreTx list or error string
    if tx_ranges.is_empty() {                         // Sanity check: must contain at least coinbase
        return Err(err("INVALID_BLOCK", "block has zero transactions")); // Error if no txs
    }
    if tx_ranges.len().saturating_sub(1) != undo_prevouts.len() { // Undo is only for non-coinbase txs
        return Err(err(                               // Build mismatch error
            "UNDO_MISMATCH",                          // Error code
            format!(                                  // Detailed message
                "undo tx count mismatch: non_cb_txs={} undo_txs={}",
                tx_ranges.len().saturating_sub(1),
                undo_prevouts.len()
            ),
        ));
    }

    // Pre-allocate result array and insert coinbase first. // Avoid reallocations
    let mut out: Vec<Option<CoreTx<'a>>> = Vec::with_capacity(tx_ranges.len()); // Option so we can fill in parallel
    out.resize_with(tx_ranges.len(), || None);        // Fill with None placeholders

    let (cb_s, cb_e) = tx_ranges[0];                  // Coinbase tx byte range
    let empty: &[(u64, &[u8])] = &[];                 // Coinbase has no prevouts
    let coinbase_core = analyze_tx_core_lite(&block[cb_s..cb_e], empty) // Analyze coinbase tx
        .map_err(|e| err("ANALYZE_TX_FAILED", e))?;   // Convert analyzer error into our error format
    out[0] = Some(coinbase_core);                     // Store coinbase at index 0

    // Sequential path for small blocks (thread overhead dominates). // Avoid threads for small workloads
    let threads = std::thread::available_parallelism() // Ask OS how many CPU threads are available
        .map(|n| n.get())                              // Convert NonZeroUsize to usize
        .unwrap_or(1);                                 // Fallback if query fails
    if threads <= 1 || tx_ranges.len() < 128 {        // If only 1 thread, or small block, do sequential
        for i in 1..tx_ranges.len() {                 // Loop over non-coinbase transactions
            let (s, e) = tx_ranges[i];                // Byte range for tx i
            let per_in = &undo_prevouts[i - 1];       // Undo prevouts for tx i (index shifted by 1)
            let core = analyze_tx_core_lite(&block[s..e], per_in) // Analyze tx with prevouts
                .map_err(|e| err("ANALYZE_TX_FAILED", e))?;      // Map error
            out[i] = Some(core);                      // Store result
        }

        return out                                    // Convert Vec<Option<CoreTx>> into Vec<CoreTx>
            .into_iter()
            .enumerate()
            .map(|(i, x)| x.ok_or_else(|| err("INTERNAL", format!("missing core tx at index {i}"))))
            .collect();
    }

    // Parallel hot path for large blocks.             // Use scoped threads to speed up big blocks
    let n = tx_ranges.len();                          // Total number of transactions
    let work = n - 1;                                 // Work items exclude coinbase
    let t = threads.min(work).max(1);                 // Number of worker threads (bounded)
    let chunk = (work + t - 1) / t;                   // Chunk size per thread (ceil division)

    std::thread::scope(|scope| -> Result<(), String> { // Scoped threads so borrowed data stays valid
        let mut handles = Vec::with_capacity(t);      // Store join handles

        for tid in 0..t {                             // Spawn up to t worker threads
            let start_i = 1 + tid * chunk;            // First tx index for this thread (skip coinbase)
            let end_i = (start_i + chunk).min(n);     // End tx index (exclusive)
            if start_i >= end_i {                     // If no work, skip
                continue;
            }

            handles.push(scope.spawn(move || -> Result<Vec<(usize, CoreTx<'a>)>, String> { // Spawn worker
                let mut local: Vec<(usize, CoreTx<'a>)> = Vec::with_capacity(end_i - start_i); // Thread-local results
                for i in start_i..end_i {             // Process assigned tx indices
                    let (s, e) = tx_ranges[i];        // Slice range
                    let per_in = &undo_prevouts[i - 1]; // Undo prevouts for this tx
                    let core = analyze_tx_core_lite(&block[s..e], per_in) // Analyze
                        .map_err(|e| err("ANALYZE_TX_FAILED", e))?;      // Map error
                    local.push((i, core));            // Save (index, result)
                }
                Ok(local)                              // Return thread results
            }));
        }

        for h in handles {                             // Join all worker threads
            let local = h
                .join()                                // Wait for thread
                .map_err(|_| err("THREAD_PANIC", "tx analysis thread panicked"))??; // Convert panic into error
            for (i, core) in local {                   // Fill shared output vector
                out[i] = Some(core);                   // Store result at correct index
            }
        }

        Ok(())                                         // Signal success to outer scope
    })?;                                               // Propagate any error

    out.into_iter()                                    // Convert Vec<Option<CoreTx>> into Vec<CoreTx>
        .enumerate()
        .map(|(i, x)| x.ok_or_else(|| err("INTERNAL", format!("missing core tx at index {i}"))))
        .collect()
}

/// Block-mode entrypoint used by CLI (`--block`).
///
/// Reads blk/rev/xor files, decodes records, and produces one `BlockReport` per block. // High-level workflow
pub fn analyze_block_file(                             // Public function (reachable as chainlens::btc::block::analyze_block_file)
    blk_path: &str,                                    // Path to blk*.dat file
    rev_path: &str,                                    // Path to rev*.dat file
    xor_path: &str,                                    // Path to xor key file
) -> Result<Vec<BlockReport>, String> {                // Returns a report per block record
    let key = fs::read(xor_path)                       // Read XOR key from disk
        .map_err(|e| err("IO_ERROR", format!("read xor key failed: {e}")))?;
    let blk_raw = fs::read(blk_path)                   // Read raw blk bytes
        .map_err(|e| err("IO_ERROR", format!("read blk failed: {e}")))?;
    let rev_raw = fs::read(rev_path)                   // Read raw rev bytes
        .map_err(|e| err("IO_ERROR", format!("read rev failed: {e}")))?;

    let (blk_buf, blk_ranges, rev_buf, undo_ranges) =  // Decode/deframe blk+rev into buffers + record ranges
        io::decode_blk_and_rev_best(blk_raw, rev_raw, &key)?;

    if blk_ranges.len() != undo_ranges.len() {         // Ensure we have matching block and undo records
        return Err(err(
            "RECORD_COUNT_MISMATCH",
            format!("blk records={} rev records={}", blk_ranges.len(), undo_ranges.len()),
        ));
    }

    let mut out = Vec::with_capacity(blk_ranges.len()); // Pre-allocate reports vector
    for (br, ur) in blk_ranges.iter().zip(undo_ranges.iter()) { // Iterate record pairs
        let block = &blk_buf[br.clone()];              // Slice out the block payload
        let undo_payload = &rev_buf[ur.clone()];       // Slice out the undo payload
        out.push(analyze_one_block_payload_record_rev(block, undo_payload)?); // Analyze and push report
    }

    Ok(out)                                            // Return all reports
}

/// Web helper: analyze only the first block record (blk+xor only).
pub fn analyze_block_file_first_block(
    blk_path: &str,                                    // Path to blk*.dat
    xor_path: &str,                                    // Path to xor key
) -> Result<BlockReport, String> {                     // Returns one block report
    let key = fs::read(xor_path)
        .map_err(|e| err("IO_ERROR", format!("read xor key failed: {e}")))?;
    let blk_raw = fs::read(blk_path)
        .map_err(|e| err("IO_ERROR", format!("read blk failed: {e}")))?;

    let (blk_buf, blk_ranges) = io::decode_blk_best_to_records(blk_raw, &key)?; // Decode only blk into records

    let first = blk_ranges
        .into_iter()
        .next()                                        // Take first record
        .ok_or_else(|| err("INVALID_BLOCK", "no block records"))?; // Error if none

    analyze_one_block_payload(&blk_buf[first.clone()])  // Analyze block without undo (fees will be 0)
}

/// Analyze one block payload WITH undo data (full block-mode path).
fn analyze_one_block_payload_record_rev(
    block: &[u8],                                      // Block payload bytes
    undo_payload: &[u8],                               // Undo payload bytes for the same block
) -> Result<BlockReport, String> {                     // Returns a BlockReport or error
    // (Implementation unchanged – comments kept concise; logic mirrors Bitcoin Core flow.) // High-level note

    let mut bc = Cursor::new(block);                   // Cursor over full block bytes
    if bc.remaining() < 80 {                           // Header must be at least 80 bytes
        return Err(err("INVALID_BLOCK", "block payload too small for header"));
    }

    let header = bc.take(80)?;                         // Take the 80-byte block header
    let mut hc = Cursor::new(header);                  // Cursor over header bytes

    let version = hc.take_u32_le()?;                   // Read version (LE)
    let prev_le = { let s = hc.take(32)?; let mut a=[0u8;32]; a.copy_from_slice(s); a }; // Read prev block hash (LE)
    let merkle_le = { let s = hc.take(32)?; let mut a=[0u8;32]; a.copy_from_slice(s); a }; // Read merkle root (LE)
    let timestamp = hc.take_u32_le()?;                 // Read timestamp
    let bits_u32 = hc.take_u32_le()?;                  // Read compact difficulty bits
    let nonce = hc.take_u32_le()?;                     // Read nonce

    let block_hash_le = parser::dsha256(header);       // Compute double-SHA256(header)
    let block_hash = hash_to_display_hex(block_hash_le); // Convert to display hex

    let prev_block_hash = { let mut be=prev_le; be.reverse(); bytes_to_hex(&be) }; // Display prev hash as BE hex
    let merkle_root_hdr_display = { let mut be=merkle_le; be.reverse(); bytes_to_hex(&be) }; // Display merkle as BE hex

    let tx_count = parser::read_varint(&mut bc)?;      // Read transaction count (varint)
    if tx_count == 0 { return Err(err("INVALID_BLOCK", "tx_count=0")); } // Must have coinbase

    let mut tx_ranges: Vec<(usize, usize)> = Vec::with_capacity(tx_count as usize); // Store tx byte ranges
    let mut vin_counts_non_cb: Vec<u64> = Vec::with_capacity((tx_count as usize).saturating_sub(1)); // Store vin counts

    for tx_idx in 0..(tx_count as usize) {             // Iterate all txs
        let start = bc.pos();                          // Record start offset
        let vin_count = parser::parse_tx_skip_and_vin_count(&mut bc)?; // Skip tx bytes and return vin count
        let end = bc.pos();                            // Record end offset
        tx_ranges.push((start, end));                  // Save tx slice range
        if tx_idx != 0 { vin_counts_non_cb.push(vin_count); } // Save vin count for non-coinbase txs
    }

    let (cb_s, cb_e) = tx_ranges[0];                   // Coinbase range
    let (coinbase_script, coinbase_outsum) =
        parser::coinbase_extract_script_and_outsum(&block[cb_s..cb_e])?; // Extract coinbase script + sum outputs
    let bip34_height = parser::decode_bip34_height(&coinbase_script); // Decode block height from script (BIP34)
    let coinbase_script_hex = bytes_to_hex(&coinbase_script); // Hex for report

    let mut undo_arena: Vec<u8> = Vec::new();          // Arena for decompressed undo data
    let undo_prevouts_slices =
        parse_undo_payload_strict_slices(undo_payload, &vin_counts_non_cb, &mut undo_arena)?; // Parse undo prevouts

    let undo_prevouts: Vec<Vec<(u64, &[u8])>> = undo_prevouts_slices // Convert slice handles into (value, &[u8]) pairs
        .iter()
        .map(|txu| {
            txu.iter()
                .map(|(v, spk_slice)| (*v, spk_slice.as_slice(undo_payload, &undo_arena))) // Borrow actual script bytes
                .collect()
        })
        .collect();

    let tx_cores = analyze_txs_with_undo_slices_core(block, &tx_ranges, &undo_prevouts)?; // Analyze txs into CoreTx

    let mut txids_le: Vec<[u8; 32]> = Vec::with_capacity(tx_cores.len()); // Collect txids for merkle check
    for tx in &tx_cores { txids_le.push(tx.txid_le); } // Push each txid (LE)

    let mr_calc = merkle_root(&txids_le);              // Compute merkle root from txids
    if mr_calc != merkle_le {                          // Compare with header merkle root
        return Err(err("MERKLE_MISMATCH", format!("header={} computed={}", merkle_root_hdr_display, hash_to_display_hex(mr_calc))));
    }

    let mut total_fees: u64 = 0;                       // Total fees in sats (non-coinbase)
    let mut total_weight: u64 = 0;                     // Total weight across all txs
    let mut total_vbytes_non_cb: u64 = 0;              // Total vbytes across non-coinbase txs

    let mut script_counts: [u64; 7] = [0; 7];          // Counters per script-type index (0..=6)
    for tx in tx_cores.iter() {                        // For each tx
        for o in tx.outputs.iter() {                   // For each output
            let i = (o.script_type as usize).min(6);   // Clamp to avoid out-of-range
            script_counts[i] = script_counts[i].saturating_add(1); // Count output type
        }
    }

    let mut script_summary: BTreeMap<String, u64> = BTreeMap::new(); // Build ordered summary map
    for (i, c) in script_counts.iter().enumerate() {   // Convert counts into strings
        if *c > 0 {                                    // Only include non-zero entries
            script_summary.insert(script_type_idx_to_str(i).to_string(), *c); // Insert into map
        }
    }

    for (idx, tx) in tx_cores.iter().enumerate() {     // Aggregate fees/weight
        total_weight = total_weight.saturating_add(tx.weight as u64); // Add weight
        if idx != 0 {                                  // Skip coinbase for fee stats
            if tx.fee > 0 { total_fees = total_fees.saturating_add(tx.fee as u64); } // Add fee
            total_vbytes_non_cb = total_vbytes_non_cb.saturating_add(tx.vbytes as u64); // Add vbytes
        }
    }

    let avg_fee_rate_sat_vb = if total_vbytes_non_cb == 0 { // Avoid division by zero
        0.0
    } else {
        (total_fees as f64) / (total_vbytes_non_cb as f64) // Compute average sat/vB across non-coinbase txs
    };

    Ok(BlockReport {                                   // Build and return the final BlockReport
        ok: true,                                      // Mark ok
        mode: "block",                                 // Report mode identifier
        block_header: BlockHeaderReport {              // Header sub-report
            version,
            prev_block_hash,
            merkle_root: merkle_root_hdr_display,
            merkle_root_valid: true,                   // True because we validated above
            timestamp,
            bits: format!("{bits_u32:08x}"),            // Difficulty bits as 8-hex-digits
            nonce,
            block_hash,
        },
        tx_count,                                      // Number of txs
        coinbase: CoinbaseReport {                     // Coinbase sub-report
            bip34_height,
            coinbase_script_hex,
            total_output_sats: coinbase_outsum,
        },
        transactions: tx_cores                          // Convert CoreTx list into TxReport list
            .iter()
            .enumerate()
            .map(|(i, tx)| core_to_tx_report_lite("mainnet", i, tx))
            .collect(),
        block_stats: BlockStatsReport {                // Aggregated stats
            total_fees_sats: total_fees,
            total_weight,
            avg_fee_rate_sat_vb,
            script_type_summary: script_summary,
        },
    })
}

/// Analyze block WITHOUT undo (fees/feerates will be zero for non-coinbase txs).
fn analyze_one_block_payload(block: &[u8]) -> Result<BlockReport, String> { // Private helper
    // Implementation mirrors full path but builds empty undo prevouts. // High-level note

    let mut bc = Cursor::new(block);                   // Cursor over block bytes
    if bc.remaining() < 80 { return Err(err("INVALID_BLOCK", "block payload too small for header")); } // Ensure header exists

    let header = bc.take(80)?;                         // Read header
    let mut hc = Cursor::new(header);                  // Cursor over header

    let version = hc.take_u32_le()?;                   // Version
    let prev_le = { let s = hc.take(32)?; let mut a=[0u8;32]; a.copy_from_slice(s); a }; // Prev hash
    let merkle_le = { let s = hc.take(32)?; let mut a=[0u8;32]; a.copy_from_slice(s); a }; // Merkle root
    let timestamp = hc.take_u32_le()?;                 // Timestamp
    let bits_u32 = hc.take_u32_le()?;                  // Bits
    let nonce = hc.take_u32_le()?;                     // Nonce

    let block_hash_le = parser::dsha256(header);       // Compute block hash
    let block_hash = hash_to_display_hex(block_hash_le); // Display block hash

    let prev_block_hash = { let mut be=prev_le; be.reverse(); bytes_to_hex(&be) }; // Display prev hash
    let merkle_root_hdr_display = { let mut be=merkle_le; be.reverse(); bytes_to_hex(&be) }; // Display merkle

    let tx_count = parser::read_varint(&mut bc)?;      // Read tx count
    if tx_count == 0 { return Err(err("INVALID_BLOCK", "tx_count=0")); } // Must have coinbase

    let mut tx_ranges: Vec<(usize, usize)> = Vec::with_capacity(tx_count as usize); // Store tx ranges
    for _ in 0..(tx_count as usize) {                  // Iterate txs
        let start = bc.pos();                          // Start offset
        let _ = parser::parse_tx_skip_and_vin_count(&mut bc)?; // Skip tx
        let end = bc.pos();                            // End offset
        tx_ranges.push((start, end));                  // Save range
    }

    let (cb_s, cb_e) = tx_ranges[0];                   // Coinbase slice
    let (coinbase_script, coinbase_outsum) =
        parser::coinbase_extract_script_and_outsum(&block[cb_s..cb_e])?; // Extract coinbase info
    let bip34_height = parser::decode_bip34_height(&coinbase_script); // Decode height
    let coinbase_script_hex = bytes_to_hex(&coinbase_script); // Hex for report

    let undo_prevouts: Vec<Vec<(u64, &[u8])>> = vec![Vec::new(); tx_ranges.len().saturating_sub(1)]; // Empty prevouts
    let tx_cores = analyze_txs_with_undo_slices_core(block, &tx_ranges, &undo_prevouts)?; // Analyze with empty prevouts

    let mut txids_le: Vec<[u8; 32]> = Vec::with_capacity(tx_cores.len()); // Collect txids
    for tx in &tx_cores { txids_le.push(tx.txid_le); } // Push txids

    let mr_calc = merkle_root(&txids_le);              // Compute merkle
    if mr_calc != merkle_le {                          // Validate merkle
        return Err(err("MERKLE_MISMATCH", format!("header={} computed={}", merkle_root_hdr_display, hash_to_display_hex(mr_calc))));
    }

    let mut total_fees: u64 = 0;                       // Fees are zero here (no undo)
    let mut total_weight: u64 = 0;                     // Total weight
    let mut total_vbytes_non_cb: u64 = 0;              // Total vbytes (will be 0-fee still)

    let mut script_counts: [u64; 7] = [0; 7];          // Script type counters
    for tx in tx_cores.iter() {
        for o in tx.outputs.iter() {
            let i = (o.script_type as usize).min(6);
            script_counts[i] = script_counts[i].saturating_add(1);
        }
    }


        let mut script_summary: BTreeMap<String, u64> = BTreeMap::new(); // Create ordered map for script-type summary (sorted keys in JSON)
    for (i, c) in script_counts.iter().enumerate() { // Iterate over all internal script-type counters
        if *c > 0 { // Only include script types that actually appear in the block
            script_summary.insert(script_type_idx_to_str(i).to_string(), *c); // Convert index → readable name and insert count
        }
    }

    for (idx, tx) in tx_cores.iter().enumerate() { // Iterate over all analyzed transactions
        total_weight = total_weight.saturating_add(tx.weight as u64); // Add each tx weight (protect against overflow)
        if idx != 0 { // Skip coinbase for fee statistics
            if tx.fee > 0 { total_fees = total_fees.saturating_add(tx.fee as u64); } // Add fee if positive
            total_vbytes_non_cb = total_vbytes_non_cb.saturating_add(tx.vbytes as u64); // Add virtual size for avg feerate calc
        }
    }

    let avg_fee_rate_sat_vb = if total_vbytes_non_cb == 0 { 0.0 } // Avoid division by zero
    else { (total_fees as f64) / (total_vbytes_non_cb as f64) }; // Compute average sat/vB over non-coinbase txs

    Ok(BlockReport { // Build final BlockReport struct
        ok: true, // Mark analysis successful
        mode: "block", // Report mode identifier
        block_header: BlockHeaderReport { // Nested header report
            version, // Block version
            prev_block_hash, // Previous block hash (display hex)
            merkle_root: merkle_root_hdr_display, // Merkle root from header (display hex)
            merkle_root_valid: true, // True because we validated it earlier
            timestamp, // Block timestamp
            bits: format!("{bits_u32:08x}"), // Difficulty bits formatted as 8-digit hex
            nonce, // Block nonce
            block_hash, // Computed block hash (display hex)
        },
        tx_count, // Total number of transactions in block
        coinbase: CoinbaseReport { // Coinbase-specific information
            bip34_height, // Block height decoded from coinbase script (BIP34)
            coinbase_script_hex, // Coinbase script in hex
            total_output_sats: coinbase_outsum, // Total satoshis created in coinbase tx
        },
        transactions: tx_cores // Convert CoreTx list into lightweight TxReport list
            .iter()
            .enumerate()
            .map(|(i, tx)| core_to_tx_report_lite("mainnet", i, tx)) // Build per-tx report
            .collect(),
        block_stats: BlockStatsReport { // Aggregated block statistics
            total_fees_sats: total_fees, // Sum of all non-coinbase fees
            total_weight, // Total block weight
            avg_fee_rate_sat_vb, // Average fee rate (sat/vB)
            script_type_summary: script_summary, // Output script-type distribution
        },
    })
}
