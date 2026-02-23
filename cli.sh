#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

error_json() {
  local code="$1"
  local message="$2"
  printf '{"ok":false,"error":{"code":"%s","message":"%s"}}\n' "$code" "$message"
}

hex16() {
  # prints first 16 bytes as hex (no spaces)
  head -c 16 "$1" | xxd -p -c 16
}

fsize() {
  # portable-ish size
  if command -v stat >/dev/null 2>&1; then
    stat -c '%s' "$1" 2>/dev/null || stat -f '%z' "$1"
  else
    wc -c <"$1"
  fi
}

# --- Block mode ---
if [[ "${1:-}" == "--block" ]]; then
  shift
  if [[ $# -lt 3 ]]; then
    error_json "INVALID_ARGS" "Block mode requires: --block <blk.dat> <rev.dat> <xor.dat>"
    exit 1
  fi

  BLK_FILE="$1"
  REV_FILE="$2"
  XOR_FILE="$3"

  for f in "$BLK_FILE" "$REV_FILE" "$XOR_FILE"; do
    if [[ ! -f "$f" ]]; then
      error_json "FILE_NOT_FOUND" "File not found: $f"
      exit 1
    fi
  done

  mkdir -p out

  echo "[dbg] blk: $BLK_FILE  size=$(fsize "$BLK_FILE")  head16=$(hex16 "$BLK_FILE")" >&2
  echo "[dbg] rev: $REV_FILE  size=$(fsize "$REV_FILE")  head16=$(hex16 "$REV_FILE")" >&2
  echo "[dbg] xor: $XOR_FILE  size=$(fsize "$XOR_FILE")  head16=$(hex16 "$XOR_FILE")" >&2

  # quick gzip hint
  if [[ "$(hex16 "$BLK_FILE" | cut -c1-8)" == "1f8b0800" ]]; then
    echo "[dbg] blk looks gzip-compressed (1f8b0800)" >&2
  fi
  if [[ "$(hex16 "$REV_FILE" | cut -c1-8)" == "1f8b0800" ]]; then
    echo "[dbg] rev looks gzip-compressed (1f8b0800)" >&2
  fi

  if [[ ! -x "./target/release/chainlens_cli" ]]; then
    cargo build --release --bin chainlens_cli --quiet
  fi

  exec ./target/release/chainlens_cli --block "$BLK_FILE" "$REV_FILE" "$XOR_FILE"
fi

# --- Single-transaction mode ---
if [[ $# -lt 1 ]]; then
  error_json "INVALID_ARGS" "Usage: cli.sh <fixture.json> or cli.sh --block <blk> <rev> <xor>"
  exit 1
fi

FIXTURE="$1"

if [[ ! -f "$FIXTURE" ]]; then
  error_json "FILE_NOT_FOUND" "Fixture file not found: $FIXTURE"
  exit 1
fi

mkdir -p out

if [[ ! -x "./target/release/chainlens_cli" ]]; then
  cargo build --release >/dev/null
fi

exec ./target/release/chainlens_cli "$FIXTURE"

