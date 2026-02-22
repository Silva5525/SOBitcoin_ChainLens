// src/btc/block/report.rs

use serde::Serialize;
use crate::btc::tx::TxReport;

#[derive(Debug, Serialize)]
pub struct BlockReport {
    pub ok: bool,
    pub mode: String, // "block"
    pub block_header: BlockHeaderReport,
    pub tx_count: u64,
    pub coinbase: CoinbaseReport,
	pub transactions: Vec<TxReport>,
    pub block_stats: BlockStatsReport,
}

#[derive(Debug, Serialize)]
pub struct BlockHeaderReport {
    pub version: u32,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub merkle_root_valid: bool,
    pub timestamp: u32,
    pub bits: String,
    pub nonce: u32,
    pub block_hash: String,
}

#[derive(Debug, Serialize)]
pub struct CoinbaseReport {
    pub bip34_height: u64,
    pub coinbase_script_hex: String,
    pub total_output_sats: u64,
}

#[derive(Debug, Serialize)]
pub struct BlockStatsReport {
    pub total_fees_sats: u64,
    pub total_weight: u64,
    pub avg_fee_rate_sat_vb: f64,
    pub script_type_summary: serde_json::Value,
}
