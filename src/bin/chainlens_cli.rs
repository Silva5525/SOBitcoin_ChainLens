use std::{fs, path::Path};
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
    let args: Vec<String> = std::env::args().collect();

    // --- Block mode ---
    if args.len() >= 5 && args[1] == "--block" {
        let blk = &args[2];
        let _rev = &args[3]; // currently unused
        let xor = &args[4];

        fs::create_dir_all("out").unwrap();

        let report = chainlens::btc::block::analyze_block_file_first_block(blk, xor)
            .unwrap_or_else(|e| {
                let err = serde_json::json!({
                    "ok": false,
                    "error": { "code": "BLOCK_PARSE_ERROR", "message": e }
                });
                println!("{}", serde_json::to_string_pretty(&err).unwrap());
                std::process::exit(1);
            });

        let out_path = format!("out/{}.json", report.block_header.block_hash);
        let json = serde_json::to_string_pretty(&report).unwrap();
        fs::write(&out_path, &json).unwrap();

        println!("{json}");
        return;
    }

    // --- Tx mode ---
    if args.len() < 2 {
        eprintln!("usage:\n  chainlens_cli <fixture.json>\n  chainlens_cli --block <blk.dat> <rev.dat> <xor.dat>");
        std::process::exit(2);
    }

    let path = &args[1];

    let s = fs::read_to_string(path).unwrap_or_else(|e| {
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

    let report = match analyze_tx(&fx.network, &fx.raw_tx, &prevouts) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({
                "ok": false,
                "error": { "code": "PARSE_ERROR", "message": e }
            });
            println!("{}", serde_json::to_string_pretty(&err).unwrap());
            std::process::exit(1);
        }
    };

    let out_dir = Path::new("out");
    let _ = fs::create_dir_all(out_dir);

    let json = serde_json::to_string_pretty(&report).unwrap();
    let out_path = out_dir.join(format!("{}.json", report.txid));
    let _ = fs::write(&out_path, &json);

    println!("{}", json);
}
