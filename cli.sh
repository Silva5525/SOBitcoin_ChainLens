#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

###############################################################################
# cli.sh — Bitcoin transaction / block analyzer CLI
#
# Usage:
#   ./cli.sh <fixture.json>                    Single-transaction mode
#   ./cli.sh --block <blk.dat> <rev.dat> <xor.dat>   Block mode
#
# Transaction mode:
#   - Reads the fixture JSON (raw_tx + prevouts)
#   - Parses the transaction and computes all fields
#   - Writes JSON report to out/<txid>.json
#   - Prints JSON report to stdout
#   - Exits 0 on success, 1 on error
#
# Block mode:
#   - Reads blk*.dat, rev*.dat, and xor.dat
#   - Parses all blocks and transactions
#   - Writes JSON report per block to out/<block_hash>.json
#   - Exits 0 on success, 1 on error
###############################################################################

error_json() {
  local code="$1"
  local message="$2"
  printf '{"ok":false,"error":{"code":"%s","message":"%s"}}\n' "$code" "$message"
}

# --- Block mode ---
if [[ "${1:-}" == "--block" ]]; then
  shift
  if [[ $# -lt 3 ]]; then
    error_json "INVALID_ARGS" "Block mode requires: --block <blk.dat> <rev.dat> <xor.dat>"
    echo "Error: Block mode requires 3 file arguments: <blk.dat> <rev.dat> <xor.dat>" >&2
    exit 1
  fi

  BLK_FILE="$1"
  REV_FILE="$2"
  XOR_FILE="$3"

  for f in "$BLK_FILE" "$REV_FILE" "$XOR_FILE"; do
    if [[ ! -f "$f" ]]; then
      error_json "FILE_NOT_FOUND" "File not found: $f"
      echo "Error: File not found: $f" >&2
      exit 1
    fi
  done

  # Create output directory
  mkdir -p out

  # TODO: Implement block parsing
  #   1. Read and XOR-decode blk*.dat and rev*.dat using xor.dat key
  #   2. Parse 80-byte block headers
  #   3. Parse all transactions in each block
  #   4. Parse undo data for prevouts
  #   5. Compute merkle root and verify
  #   6. Identify coinbase, decode BIP34 height
  #   7. Write out/<block_hash>.json for each block

  # Build release binary if missing
  if [[ ! -x "./target/release/chainlens_cli" ]]; then
    cargo build --release >/dev/null
  fi

  exec ./target/release/chainlens_cli --block "$BLK_FILE" "$REV_FILE" "$XOR_FILE"
fi

# --- Single-transaction mode ---
if [[ $# -lt 1 ]]; then
  error_json "INVALID_ARGS" "Usage: cli.sh <fixture.json> or cli.sh --block <blk> <rev> <xor>"
  echo "Error: No fixture file provided" >&2
  exit 1
fi

FIXTURE="$1"

if [[ ! -f "$FIXTURE" ]]; then
  error_json "FILE_NOT_FOUND" "Fixture file not found: $FIXTURE"
  echo "Error: Fixture file not found: $FIXTURE" >&2
  exit 1
fi

# Create output directory
mkdir -p out

# TODO: Implement transaction parsing
#   1. Read fixture JSON (network, raw_tx, prevouts)
#   2. Parse raw_tx hex (version, inputs, outputs, witness, locktime)
#   3. Match prevouts to inputs by (txid, vout)
#   4. Compute txid, wtxid, fees, weight, vbytes
#   5. Classify input/output scripts, derive addresses
#   6. Detect RBF, timelocks, warnings
#   7. Build and output JSON report
#   8. Write to out/<txid>.json and print to stdout

# Build release binary if missing
if [[ ! -x "./target/release/chainlens_cli" ]]; then
  cargo build --release >/dev/null
fi

exec ./target/release/chainlens_cli "$FIXTURE"
