// Import filesystem helpers and path utilities from the standard library
use std::{fs, path::Path};

// Import Serde trait to allow JSON → struct deserialization
use serde::Deserialize;

// Import the transaction analyzer and Prevout type from the library
use chainlens::btc::tx::{analyze_tx, Prevout};

///////////////////////////////////////////////////////////////
// Structures describing the fixture JSON input format
///////////////////////////////////////////////////////////////

/// Represents a single previous output entry from the fixture JSON.
///
/// Each prevout describes the UTXO being spent by an input.
#[derive(Deserialize)] // Allows serde to parse JSON into this struct
struct FixturePrevout {
    txid: String,              // Previous transaction ID (hex)
    vout: u32,                 // Output index being spent
    value_sats: u64,           // Value in satoshis
    script_pubkey_hex: String, // ScriptPubKey hex of the prevout
}

/// Top-level fixture format used in transaction analysis mode.
///
/// Contains raw transaction data and the referenced prevouts.
#[derive(Deserialize)]
struct FixtureTx {
    network: String,                  // Network name (mainnet/testnet)
    raw_tx: String,                   // Raw transaction hex
    prevouts: Vec<FixturePrevout>,    // List of previous outputs
}

///////////////////////////////////////////////////////////////
// Program entry point
///////////////////////////////////////////////////////////////

/// CLI entry point.
///
/// Supports two modes:
/// - Transaction mode: analyzes a fixture JSON file
/// - Block mode: analyzes a block data file pair
fn main() {
    // Collect command line arguments into a vector
    let args: Vec<String> = std::env::args().collect();

    ///////////////////////////////////////////////////////////
    // --- Block mode ---
    ///////////////////////////////////////////////////////////

    // If program is called with "--block" and enough arguments
    if args.len() >= 5 && args[1] == "--block" {

        // Paths to block data files // bugfix
        let blk = &args[2];
        let _rev = &args[3]; // Currently unused but reserved // bugfix
        let xor = &args[4];

        // Ensure output directory exists
        fs::create_dir_all("out").unwrap();

        // Run block analyzer; exit with JSON error if it fails
        let report = chainlens::btc::block::analyze_block_file_first_block(blk, xor)
            .unwrap_or_else(|e| {
                let err = serde_json::json!({
                    "ok": false,
                    "error": { "code": "BLOCK_PARSE_ERROR", "message": e }
                });
                println!("{}", serde_json::to_string_pretty(&err).unwrap());
                std::process::exit(1);
            });

        // Build output file path based on block hash
        let out_path = format!("out/{}.json", report.block_header.block_hash);

        // Convert report to pretty JSON
        let json = serde_json::to_string_pretty(&report).unwrap();

        // Write JSON file to disk
        fs::write(&out_path, &json).unwrap();

        // Print JSON to stdout
        println!("{json}");

        // Exit early (do not run tx mode)
        return;
    }

    ///////////////////////////////////////////////////////////
    // --- Transaction mode ---
    ///////////////////////////////////////////////////////////

    // If not enough arguments, print usage and exit
    if args.len() < 2 {
        eprintln!("usage:\n  chainlens_cli <fixture.json>\n  chainlens_cli --block <blk.dat> <rev.dat> <xor.dat>");
        std::process::exit(2);
    }

    // Path to fixture JSON file
    let path = &args[1];

    // Read fixture file into string
    let s = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("failed to read fixture {}: {}", path, e);
        std::process::exit(2);
    });

    // Deserialize JSON string into FixtureTx struct
    let fx: FixtureTx = serde_json::from_str(&s).unwrap_or_else(|e| {
        eprintln!("invalid fixture json: {}", e);
        std::process::exit(2);
    });

    // Convert fixture prevouts into internal Prevout format
    let prevouts: Vec<Prevout> = fx.prevouts.into_iter().map(|p| Prevout {
        txid_hex: p.txid,
        vout: p.vout,
        value_sats: p.value_sats,
        script_pubkey_hex: p.script_pubkey_hex,
    }).collect();

    // Run transaction analyzer
    let report = match analyze_tx(&fx.network, &fx.raw_tx, &prevouts) {
        Ok(r) => r,
        Err(e) => {
            // If analyzer fails, print JSON error and exit
            let err = serde_json::json!({
                "ok": false,
                "error": { "code": "PARSE_ERROR", "message": e }
            });
            println!("{}", serde_json::to_string_pretty(&err).unwrap());
            std::process::exit(1);
        }
    };

    // Ensure output directory exists
    let out_dir = Path::new("out");
    let _ = fs::create_dir_all(out_dir);

    // Convert report to pretty JSON
    let json = serde_json::to_string_pretty(&report).unwrap();

    // Build output path using transaction ID
    let out_path = out_dir.join(format!("{}.json", report.txid));

    // Write JSON report to disk (ignore errors)
    let _ = fs::write(&out_path, &json);

    // Print JSON report to stdout
    println!("{}", json);
}
