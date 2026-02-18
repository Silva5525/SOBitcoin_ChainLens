use std::fs;
use serde::Deserialize;

use chainlens::btc::tx::{analyze_tx, Prevout};

#[derive(Deserialize)]
struct FixturePrevout {
    txid: String,
    vout: u32,
    value_sats: u64,
    script_pubkey_hex: String,
}

#[derive(Deserialize)]
struct FixtureTx {
    network: String,
    raw_tx: String,
    prevouts: Vec<FixturePrevout>,
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: chainlens_cli <fixture.json>");
        std::process::exit(2);
    });

    let s = fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("failed to read fixture {}: {}", path, e);
        std::process::exit(2);
    });

    let fx: FixtureTx = serde_json::from_str(&s).unwrap_or_else(|e| {
        eprintln!("invalid fixture json: {}", e);
        std::process::exit(2);
    });

    let prevouts: Vec<Prevout> = fx.prevouts.into_iter().map(|p| Prevout {
        txid_hex: p.txid,
        vout: p.vout,
        value_sats: p.value_sats,
        script_pubkey_hex: p.script_pubkey_hex,
    }).collect();

    let report = analyze_tx(&fx.network, &fx.raw_tx, &prevouts).unwrap_or_else(|e| {
        let err = serde_json::json!({
            "ok": false,
            "error": { "code": "PARSE_ERROR", "message": e }
        });
        println!("{}", serde_json::to_string_pretty(&err).unwrap());
        std::process::exit(1);
    });

    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
