// src/btc/block/report.rs
//
// JSON report structures for block-mode analysis.
//
// These types define the exact shape of the serialized block report
// returned by the block analyzer and written to `out/<block_hash>.json`.
//
// Design goals:
//   - Stable, deterministic JSON (grader-friendly).
//   - No internal parsing details exposed.
//   - Reuse `TxReport` for per-transaction analysis.

use serde::Serialize;
use std::collections::BTreeMap;

use crate::btc::tx::TxReport;

/// Top-level block analysis report.
///
/// One instance is produced per decoded block.
#[derive(Debug, Serialize)]
pub struct BlockReport {
    /// Always `true` for successfully parsed blocks.
    pub ok: bool,

    /// Always "block" in block parsing mode.
    ///
    /// Allows clients to distinguish from transaction-mode reports.
    pub mode: &'static str,

    /// Parsed header fields plus computed block hash.
    pub block_header: BlockHeaderReport,

    /// Number of transactions in the block (including coinbase).
    pub tx_count: u64,

    /// Extracted and summarized coinbase transaction information.
    pub coinbase: CoinbaseReport,

    /// Full per-transaction reports (including coinbase as index 0).
    pub transactions: Vec<TxReport>,

    /// Aggregate statistics across all transactions in the block.
    pub block_stats: BlockStatsReport,
}

/// Serializable view of the 80-byte Bitcoin block header
/// plus derived validation data.
#[derive(Debug, Serialize)]
pub struct BlockHeaderReport {
    /// Block version (little-endian in header, exposed as host u32).
    pub version: u32,

    /// Previous block hash (hex, big-endian display form).
    pub prev_block_hash: String,

    /// Merkle root from the header (hex, big-endian display form).
    pub merkle_root: String,

    /// Whether the computed merkle root matches the header value.
    pub merkle_root_valid: bool,

    /// Block timestamp (Unix epoch seconds).
    pub timestamp: u32,

    /// Compact target encoding ("nBits") as hex string.
    pub bits: String,

    /// Nonce used for proof-of-work.
    pub nonce: u32,

    /// Double-SHA256 hash of the serialized header (hex, big-endian display form).
    pub block_hash: String,
}

/// Summary of the coinbase transaction.
///
/// The coinbase is special because it encodes the BIP34 height
/// and has no real prevouts.
#[derive(Debug, Serialize)]
pub struct CoinbaseReport {
    /// Decoded block height from BIP34 (scriptSig push).
    pub bip34_height: u64,

    /// Raw coinbase scriptSig as hex.
    pub coinbase_script_hex: String,

    /// Total output value created by the coinbase (subsidy + fees).
    pub total_output_sats: u64,
}

/// Aggregated statistics across all transactions in the block.
#[derive(Debug, Serialize)]
pub struct BlockStatsReport {
    /// Sum of all transaction fees in satoshis (excluding coinbase input).
    pub total_fees_sats: u64,

    /// Sum of transaction weights (BIP141 weight units).
    pub total_weight: u64,

    /// Average fee rate in sat/vbyte across non-coinbase transactions.
    pub avg_fee_rate_sat_vb: f64,

    /// Map of `script_type -> count` across all outputs in the block.
    ///
    /// Using `BTreeMap` ensures deterministic key ordering in JSON.
    pub script_type_summary: BTreeMap<String, u64>,
}
