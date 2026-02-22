// src/btc/block/mod.rs

mod report;
mod io;
mod parser;
mod undo;

pub use report::{BlockHeaderReport, BlockReport, BlockStatsReport, CoinbaseReport};

use std::collections::BTreeMap;
use std::fs;

use crate::btc::tx::analyze_tx_from_bytes_ordered;

use io::decode_blk_and_rev_best;
use parser::{bytes_to_hex, hash_to_display_hex, merkle_root, Cursor};
use undo::{extract_vin_count_from_slice, parse_undo_payload_strict};

fn err(code: &str, msg: impl AsRef<str>) -> String {
    format!("{code}: {}", msg.as_ref())
}

/// Analyze all txs in a block (coinbase + non-coinbase) using undo prevouts.
///
/// Hot path: avoid per-tx `Vec<u8>` copies by passing `&block[start..end]` slices.
/// Also uses bounded parallelism for non-coinbase txs.
fn analyze_txs_with_undo_slices(
    block: &[u8],
    tx_ranges: &[(usize, usize)],
    undo_prevouts: &[Vec<(u64, Vec<u8>)>],
) -> Result<Vec<crate::btc::tx::TxReport>, String> {
    use crate::btc::tx::TxReport;

    if tx_ranges.is_empty() {
        return Err(err("INVALID_BLOCK", "block has zero transactions"));
    }
    if tx_ranges.len().saturating_sub(1) != undo_prevouts.len() {
        return Err(err(
            "UNDO_MISMATCH",
            format!(
                "undo tx count mismatch: non_cb_txs={} undo_txs={}",
                tx_ranges.len().saturating_sub(1),
                undo_prevouts.len()
            ),
        ));
    }

    // Pre-size output and fill coinbase.
    // Note: `vec![None; n]` requires `Option<TxReport>: Clone` which we don't want.
    let mut out: Vec<Option<TxReport>> = Vec::with_capacity(tx_ranges.len());
    out.resize_with(tx_ranges.len(), || None);

    let (cb_s, cb_e) = tx_ranges[0];
    let coinbase_report = analyze_tx_from_bytes_ordered("mainnet", &block[cb_s..cb_e], &[])
        .map_err(|e| err("ANALYZE_TX_FAILED", e))?;
    out[0] = Some(coinbase_report);

    // For small blocks, sequential is faster (thread overhead dominates).
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if threads <= 1 || tx_ranges.len() < 128 {
        for i in 1..tx_ranges.len() {
            let (s, e) = tx_ranges[i];
            let per_in = &undo_prevouts[i - 1];
            let rep = analyze_tx_from_bytes_ordered("mainnet", &block[s..e], per_in)
                .map_err(|e| err("ANALYZE_TX_FAILED", e))?;
            out[i] = Some(rep);
        }

        return out
            .into_iter()
            .enumerate()
            .map(|(i, x)| x.ok_or_else(|| err("INTERNAL", format!("missing tx report at index {i}"))))
            .collect();
    }

    // Parallel hot path.
    let n = tx_ranges.len();
    let work = n - 1;
    let t = threads.min(work).max(1);
    let chunk = (work + t - 1) / t;

    std::thread::scope(|scope| -> Result<(), String> {
        let mut handles = Vec::with_capacity(t);

        for tid in 0..t {
            let start_i = 1 + tid * chunk;
            let end_i = (start_i + chunk).min(n);
            if start_i >= end_i {
                continue;
            }

            handles.push(scope.spawn(move || -> Result<Vec<(usize, TxReport)>, String> {
                let mut local: Vec<(usize, TxReport)> = Vec::with_capacity(end_i - start_i);
                for i in start_i..end_i {
                    let (s, e) = tx_ranges[i];
                    let per_in = &undo_prevouts[i - 1];
                    let rep = analyze_tx_from_bytes_ordered("mainnet", &block[s..e], per_in)
                        .map_err(|e| err("ANALYZE_TX_FAILED", e))?;
                    local.push((i, rep));
                }
                Ok(local)
            }));
        }

        for h in handles {
            let local = h
                .join()
                .map_err(|_| err("THREAD_PANIC", "tx analysis thread panicked"))??;
            for (i, rep) in local {
                out[i] = Some(rep);
            }
        }

        Ok(())
    })?;

    out.into_iter()
        .enumerate()
        .map(|(i, x)| x.ok_or_else(|| err("INTERNAL", format!("missing tx report at index {i}"))))
        .collect()
}

/// Block-mode entrypoint used by `cli.sh --block`.
///
/// Reads blk/rev/xor files, decodes records, parses every block record, and writes one report per block.
pub fn analyze_block_file(
    blk_path: &str,
    rev_path: &str,
    xor_path: &str,
) -> Result<Vec<BlockReport>, String> {
    let key = fs::read(xor_path).map_err(|e| err("IO_ERROR", format!("read xor key failed: {e}")))?;
    let blk_raw = fs::read(blk_path).map_err(|e| err("IO_ERROR", format!("read blk failed: {e}")))?;
    let rev_raw = fs::read(rev_path).map_err(|e| err("IO_ERROR", format!("read rev failed: {e}")))?;

    let (blk_buf, blk_ranges, rev_buf, undo_ranges) = decode_blk_and_rev_best(blk_raw, rev_raw, &key)?;

    if blk_ranges.len() != undo_ranges.len() {
        return Err(err(
            "RECORD_COUNT_MISMATCH",
            format!("blk records={} rev records={}", blk_ranges.len(), undo_ranges.len()),
        ));
    }

    let mut out = Vec::with_capacity(blk_ranges.len());
    for (br, ur) in blk_ranges.iter().zip(undo_ranges.iter()) {
        let block = &blk_buf[br.clone()];
        let undo_payload = &rev_buf[ur.clone()];
        out.push(analyze_one_block_payload_record_rev(block, undo_payload)?);
    }

    Ok(out)
}

/// Backwards-compatible helper for the web app (analyze first block only).
///
/// NOTE: This reads *only* blk+xor. For full block-mode the web endpoint should call `analyze_block_file`.
pub fn analyze_block_file_first_block(blk_path: &str, xor_path: &str) -> Result<BlockReport, String> {
    let key = fs::read(xor_path).map_err(|e| err("IO_ERROR", format!("read xor key failed: {e}")))?;
    let blk_raw = fs::read(blk_path).map_err(|e| err("IO_ERROR", format!("read blk failed: {e}")))?;

    let (blk_buf, blk_ranges) = io::decode_blk_best_to_records(blk_raw, &key)?;

    let first = blk_ranges
        .into_iter()
        .next()
        .ok_or_else(|| err("INVALID_BLOCK", "no block records"))?;

    analyze_one_block_payload(&blk_buf[first.clone()], &[])
}


fn analyze_one_block_payload_record_rev(block: &[u8], undo_payload: &[u8]) -> Result<BlockReport, String> {
    // --- parse header ---
    let mut bc = Cursor::new(block);
    if bc.remaining() < 80 {
        return Err(err("INVALID_BLOCK", "block payload too small for header"));
    }

    // zero-copy: header ist jetzt ein Slice
    let header = bc.take(80)?;
    let mut hc = Cursor::new(header);

    let version = hc.take_u32_le()?;
    let prev_le = {
        let s = hc.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        a
    };
    let merkle_le = {
        let s = hc.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        a
    };
    let timestamp = hc.take_u32_le()?;
    let bits_u32 = hc.take_u32_le()?;
    let nonce = hc.take_u32_le()?;

    let block_hash_le = parser::dsha256(header);
    let block_hash = hash_to_display_hex(block_hash_le);

    let prev_block_hash = {
        let mut be = prev_le;
        be.reverse();
        bytes_to_hex(&be)
    };
    let merkle_root_hdr_display = {
        let mut be = merkle_le;
        be.reverse();
        bytes_to_hex(&be)
    };

    // --- parse txs (NO raw tx copies) ---
    let tx_count = parser::read_varint(&mut bc)?;

    let mut txids_le: Vec<[u8; 32]> = Vec::with_capacity(tx_count as usize);
    let mut tx_ranges: Vec<(usize, usize)> = Vec::with_capacity(tx_count as usize);

    for _ in 0..tx_count {
        let start = bc.pos();
        let txid_le = parser::parse_tx_skip_and_txid_le(block, &mut bc)?;
        let end = bc.pos();
        txids_le.push(txid_le);
        tx_ranges.push((start, end));
    }

    // --- verify merkle ---
    let mr_calc = merkle_root(&txids_le);
    if mr_calc != merkle_le {
        return Err(err(
            "MERKLE_MISMATCH",
            format!(
                "header={} computed={}",
                merkle_root_hdr_display,
                hash_to_display_hex(mr_calc)
            ),
        ));
    }

    if tx_ranges.is_empty() {
        return Err(err("INVALID_BLOCK", "block has zero transactions"));
    }

    // --- coinbase ---
    let (cb_s, cb_e) = tx_ranges[0];
    let (coinbase_script, coinbase_outsum) =
        parser::coinbase_extract_script_and_outsum(&block[cb_s..cb_e])?;
    let bip34_height = parser::decode_bip34_height(&coinbase_script);
    let coinbase_script_hex = bytes_to_hex(&coinbase_script);

    // --- undo parse needs vin counts of non-coinbase txs ---
    let mut vin_counts_non_cb: Vec<u64> = Vec::with_capacity(tx_ranges.len().saturating_sub(1));
    for &(s, e) in tx_ranges.iter().skip(1) {
        vin_counts_non_cb.push(extract_vin_count_from_slice(&block[s..e])?);
    }
    let undo_prevouts = parse_undo_payload_strict(undo_payload, &vin_counts_non_cb)?;

    // --- analyze txs (bounded parallelism, slices) ---
    let tx_reports = analyze_txs_with_undo_slices(block, &tx_ranges, &undo_prevouts)?;

    // --- block stats ---
    let mut total_fees: u64 = 0;
    let mut total_weight: u64 = 0;
    let mut total_vbytes_non_cb: u64 = 0;
    let mut script_summary: BTreeMap<String, u64> = BTreeMap::new();

    for (idx, tx) in tx_reports.iter().enumerate() {
        total_weight = total_weight.saturating_add(tx.weight as u64);

        if idx != 0 {
            if tx.fee_sats > 0 {
                total_fees = total_fees.saturating_add(tx.fee_sats as u64);
            }
            total_vbytes_non_cb = total_vbytes_non_cb.saturating_add(tx.vbytes as u64);
        }

        for o in &tx.vout {
            let k = if o.script_type.is_empty() { "unknown" } else { &o.script_type };
            *script_summary.entry(k.to_string()).or_insert(0) += 1;
        }
    }

    let avg_fee_rate_sat_vb = if total_vbytes_non_cb == 0 {
        0.0
    } else {
        (total_fees as f64) / (total_vbytes_non_cb as f64)
    };

    Ok(BlockReport {
        ok: true,
        mode: "block".to_string(),
        block_header: BlockHeaderReport {
            version,
            prev_block_hash,
            merkle_root: merkle_root_hdr_display,
            merkle_root_valid: true,
            timestamp,
            bits: format!("{bits_u32:08x}"),
            nonce,
            block_hash,
        },
        tx_count,
        coinbase: CoinbaseReport {
            bip34_height,
            coinbase_script_hex,
            total_output_sats: coinbase_outsum,
        },
        transactions: tx_reports,
        block_stats: BlockStatsReport {
            total_fees_sats: total_fees,
            total_weight,
            avg_fee_rate_sat_vb,
            script_type_summary: serde_json::to_value(script_summary)
                .unwrap_or_else(|_| serde_json::json!({})),
        },
    })
}

/// Legacy entrypoint kept for the web's "first block" demo mode.
fn analyze_one_block_payload(block: &[u8], undo_payload: &[u8]) -> Result<BlockReport, String> {
    let mut bc = Cursor::new(block);
    if bc.remaining() < 80 {
        return Err(err("INVALID_BLOCK", "block payload too small for header"));
    }

    // Legacy: keep the header vec to avoid changing Cursor signature expectations elsewhere.
    let header = bc.take(80)?.to_vec();
    let mut hc = Cursor::new(&header);

    let version = hc.take_u32_le()?;
    let prev_le = {
        let s = hc.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        a
    };
    let merkle_le = {
        let s = hc.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        a
    };
    let timestamp = hc.take_u32_le()?;
    let bits_u32 = hc.take_u32_le()?;
    let nonce = hc.take_u32_le()?;

    let block_hash_le = parser::dsha256(&header);
    let block_hash = hash_to_display_hex(block_hash_le);

    let prev_block_hash = {
        let mut be = prev_le;
        be.reverse();
        bytes_to_hex(&be)
    };
    let merkle_root_hdr_display = {
        let mut be = merkle_le;
        be.reverse();
        bytes_to_hex(&be)
    };

    let tx_count = parser::read_varint(&mut bc)?;

    let mut txids_le: Vec<[u8; 32]> = Vec::with_capacity(tx_count as usize);
    let mut tx_ranges: Vec<(usize, usize)> = Vec::with_capacity(tx_count as usize);

    for _ in 0..tx_count {
        let start = bc.pos();
        let txid_le = parser::parse_tx_skip_and_txid_le(block, &mut bc)?;
        let end = bc.pos();
        txids_le.push(txid_le);
        tx_ranges.push((start, end));
    }

    let mr_calc = merkle_root(&txids_le);
    if mr_calc != merkle_le {
        return Err(err(
            "MERKLE_MISMATCH",
            format!(
                "header={} computed={}",
                merkle_root_hdr_display,
                hash_to_display_hex(mr_calc)
            ),
        ));
    }

    if tx_ranges.is_empty() {
        return Err(err("INVALID_BLOCK", "block has zero transactions"));
    }

    // --- coinbase ---
    let (cb_s, cb_e) = tx_ranges[0];
    let (coinbase_script, coinbase_outsum) =
        parser::coinbase_extract_script_and_outsum(&block[cb_s..cb_e])?;
    let bip34_height = parser::decode_bip34_height(&coinbase_script);
    let coinbase_script_hex = bytes_to_hex(&coinbase_script);

    // --- tx analysis (NOW: Vec<TxReport>) ---
    let tx_reports: Vec<crate::btc::tx::TxReport> = if undo_payload.is_empty() {
        if tx_ranges.len() > 1 {
            return Err(err("UNDO_MISSING", "undo payload required for non-coinbase tx analysis"));
        }
        let coinbase_report = analyze_tx_from_bytes_ordered("mainnet", &block[cb_s..cb_e], &[])
            .map_err(|e| err("ANALYZE_TX_FAILED", e))?;
        vec![coinbase_report]
    } else {
        let mut vin_counts_non_cb: Vec<u64> = Vec::with_capacity(tx_ranges.len().saturating_sub(1));
        for &(s, e) in tx_ranges.iter().skip(1) {
            vin_counts_non_cb.push(extract_vin_count_from_slice(&block[s..e])?);
        }
        let undo_prevouts = parse_undo_payload_strict(undo_payload, &vin_counts_non_cb)?;
        analyze_txs_with_undo_slices(block, &tx_ranges, &undo_prevouts)?
    };

    // --- block stats (NO JSON get()) ---
    let mut total_fees: u64 = 0;
    let mut total_weight: u64 = 0;
    let mut total_vbytes_non_cb: u64 = 0;
    let mut script_summary: BTreeMap<String, u64> = BTreeMap::new();

    for (idx, tx) in tx_reports.iter().enumerate() {
        total_weight = total_weight.saturating_add(tx.weight as u64);

        if idx != 0 {
            if tx.fee_sats > 0 {
                total_fees = total_fees.saturating_add(tx.fee_sats as u64);
            }
            total_vbytes_non_cb = total_vbytes_non_cb.saturating_add(tx.vbytes as u64);
        }

        for o in &tx.vout {
            let k = if o.script_type.is_empty() { "unknown" } else { &o.script_type };
            *script_summary.entry(k.to_string()).or_insert(0) += 1;
        }
    }

    let avg_fee_rate_sat_vb = if total_vbytes_non_cb == 0 {
        0.0
    } else {
        (total_fees as f64) / (total_vbytes_non_cb as f64)
    };

    Ok(BlockReport {
        ok: true,
        mode: "block".to_string(),
        block_header: BlockHeaderReport {
            version,
            prev_block_hash,
            merkle_root: merkle_root_hdr_display,
            merkle_root_valid: true,
            timestamp,
            bits: format!("{bits_u32:08x}"),
            nonce,
            block_hash,
        },
        tx_count,
        coinbase: CoinbaseReport {
            bip34_height,
            coinbase_script_hex,
            total_output_sats: coinbase_outsum,
        },
        transactions: tx_reports,
        block_stats: BlockStatsReport {
            total_fees_sats: total_fees,
            total_weight,
            avg_fee_rate_sat_vb,
            script_type_summary: serde_json::to_value(script_summary)
                .unwrap_or_else(|_| serde_json::json!({})),
        },
    })
}
