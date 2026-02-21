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
) -> Result<Vec<serde_json::Value>, String> {
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
    let mut out: Vec<serde_json::Value> = vec![serde_json::Value::Null; tx_ranges.len()];

    let (cb_s, cb_e) = tx_ranges[0];
    let coinbase_report = analyze_tx_from_bytes_ordered("mainnet", &block[cb_s..cb_e], &[])
        .map_err(|e| err("ANALYZE_TX_FAILED", e))?;
    out[0] = serde_json::to_value(coinbase_report)
        .map_err(|e| err("SERDE_FAILED", e.to_string()))?;

    // For small blocks, sequential is faster (thread overhead dominates).
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if threads <= 1 || tx_ranges.len() < 128 {
        for i in 1..tx_ranges.len() {
            let (s, e) = tx_ranges[i];
            let per_in = &undo_prevouts[i - 1];
            let rep = analyze_tx_from_bytes_ordered("mainnet", &block[s..e], per_in)
                .map_err(|e| err("ANALYZE_TX_FAILED", e))?;
            out[i] = serde_json::to_value(rep).map_err(|e| err("SERDE_FAILED", e.to_string()))?;
        }
        return Ok(out);
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

            handles.push(scope.spawn(move || -> Result<Vec<(usize, serde_json::Value)>, String> {
                let mut local: Vec<(usize, serde_json::Value)> = Vec::with_capacity(end_i - start_i);
                for i in start_i..end_i {
                    let (s, e) = tx_ranges[i];
                    let per_in = &undo_prevouts[i - 1];

                    let rep = analyze_tx_from_bytes_ordered("mainnet", &block[s..e], per_in)
                        .map_err(|e| err("ANALYZE_TX_FAILED", e))?;
                    let v = serde_json::to_value(rep)
                        .map_err(|e| err("SERDE_FAILED", e.to_string()))?;
                    local.push((i, v));
                }
                Ok(local)
            }));
        }

        for h in handles {
            let local = h
                .join()
                .map_err(|_| err("THREAD_PANIC", "tx analysis thread panicked"))??;
            for (i, v) in local {
                out[i] = v;
            }
        }

        Ok(())
    })?;

    Ok(out)
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

    let (blk_records, rev_records) = decode_blk_and_rev_best(blk_raw, rev_raw, &key)?;

    if blk_records.len() != rev_records.len() {
        return Err(err(
            "RECORD_COUNT_MISMATCH",
            format!("blk records={} rev records={}", blk_records.len(), rev_records.len()),
        ));
    }

    let mut out = Vec::with_capacity(blk_records.len());
    for (block_bytes, undo_bytes) in blk_records.into_iter().zip(rev_records.into_iter()) {
        out.push(analyze_one_block_payload_record_rev(&block_bytes, &undo_bytes)?);
    }

    Ok(out)
}

/// Backwards-compatible helper for the web app (analyze first block only).
///
/// NOTE: This reads *only* blk+xor. For full block-mode the web endpoint should call `analyze_block_file`.
pub fn analyze_block_file_first_block(blk_path: &str, xor_path: &str) -> Result<BlockReport, String> {
    let key = fs::read(xor_path).map_err(|e| err("IO_ERROR", format!("read xor key failed: {e}")))?;
    let blk_raw = fs::read(blk_path).map_err(|e| err("IO_ERROR", format!("read blk failed: {e}")))?;

    let (blk_records, _blk) = io::decode_blk_best_to_records(blk_raw, &key)?;

    let first = blk_records
        .into_iter()
        .next()
        .ok_or_else(|| err("INVALID_BLOCK", "no block records"))?;

    analyze_one_block_payload(&first, &[])
}

fn analyze_one_block_payload_record_rev(block: &[u8], undo_payload: &[u8]) -> Result<BlockReport, String> {
    // --- parse header ---
    let mut bc = Cursor::new(block);
    if bc.remaining() < 80 {
        return Err(err("INVALID_BLOCK", "block payload too small for header"));
    }

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
    let tx_reports_json = analyze_txs_with_undo_slices(block, &tx_ranges, &undo_prevouts)?;

    // --- block stats ---
    let mut total_fees: u64 = 0;
    let mut total_weight: u64 = 0;
    let mut total_vbytes_non_cb: u64 = 0;
    let mut script_summary: BTreeMap<String, u64> = BTreeMap::new();

    for (idx, txv) in tx_reports_json.iter().enumerate() {
        if let Some(w) = txv.get("weight").and_then(|x| x.as_u64()) {
            total_weight = total_weight.saturating_add(w);
        }
        if idx != 0 {
            if let Some(f) = txv.get("fee_sats").and_then(|x| x.as_u64()) {
                total_fees = total_fees.saturating_add(f);
            }
            if let Some(vb) = txv.get("vbytes").and_then(|x| x.as_u64()) {
                total_vbytes_non_cb = total_vbytes_non_cb.saturating_add(vb);
            }
        }

        if let Some(vout) = txv.get("vout").and_then(|x| x.as_array()) {
            for o in vout {
                let k = o
                    .get("script_type")
                    .and_then(|x| x.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                *script_summary.entry(k).or_insert(0) += 1;
            }
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
        transactions: tx_reports_json,
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

    let (cb_s, cb_e) = tx_ranges[0];
    let (coinbase_script, coinbase_outsum) =
        parser::coinbase_extract_script_and_outsum(&block[cb_s..cb_e])?;
    let bip34_height = parser::decode_bip34_height(&coinbase_script);
    let coinbase_script_hex = bytes_to_hex(&coinbase_script);

    let tx_reports_json = if undo_payload.is_empty() {
        if tx_ranges.len() > 1 {
            return Err(err("UNDO_MISSING", "undo payload required for non-coinbase tx analysis"));
        }
        let coinbase_report = analyze_tx_from_bytes_ordered("mainnet", &block[cb_s..cb_e], &[])
            .map_err(|e| err("ANALYZE_TX_FAILED", e))?;
        vec![serde_json::to_value(coinbase_report)
            .map_err(|e| err("SERDE_FAILED", e.to_string()))?]
    } else {
        let mut vin_counts_non_cb: Vec<u64> = Vec::with_capacity(tx_ranges.len().saturating_sub(1));
        for &(s, e) in tx_ranges.iter().skip(1) {
            vin_counts_non_cb.push(extract_vin_count_from_slice(&block[s..e])?);
        }
        let undo_prevouts = parse_undo_payload_strict(undo_payload, &vin_counts_non_cb)?;
        analyze_txs_with_undo_slices(block, &tx_ranges, &undo_prevouts)?
    };

    let mut total_fees: u64 = 0;
    let mut total_weight: u64 = 0;
    let mut total_vbytes_non_cb: u64 = 0;
    let mut script_summary: BTreeMap<String, u64> = BTreeMap::new();

    for (idx, txv) in tx_reports_json.iter().enumerate() {
        if let Some(w) = txv.get("weight").and_then(|x| x.as_u64()) {
            total_weight = total_weight.saturating_add(w);
        }
        if idx != 0 {
            if let Some(f) = txv.get("fee_sats").and_then(|x| x.as_u64()) {
                total_fees = total_fees.saturating_add(f);
            }
            if let Some(vb) = txv.get("vbytes").and_then(|x| x.as_u64()) {
                total_vbytes_non_cb = total_vbytes_non_cb.saturating_add(vb);
            }
        }

        if let Some(vout) = txv.get("vout").and_then(|x| x.as_array()) {
            for o in vout {
                let k = o
                    .get("script_type")
                    .and_then(|x| x.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                *script_summary.entry(k).or_insert(0) += 1;
            }
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
        transactions: tx_reports_json,
        block_stats: BlockStatsReport {
            total_fees_sats: total_fees,
            total_weight,
            avg_fee_rate_sat_vb,
            script_type_summary: serde_json::to_value(script_summary)
                .unwrap_or_else(|_| serde_json::json!({})),
        },
    })
}
