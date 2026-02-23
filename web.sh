#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"


###############################################################################
# web.sh — ChainLens Web Visualizer
#
# Behavior:
#   - Reads PORT env var (default: 3000)
#   - Prints the URL exactly once (e.g., http://127.0.0.1:3000)
#   - Keeps running until terminated
#   - Must serve GET /api/health -> 200 { "ok": true }
###############################################################################


PORT="${PORT:-3000}"

if [[ ! -x "./target/release/chainlens_web" ]]; then
  # Build ONLY the web binary.
  cargo build --release --bin chainlens_web --quiet
fi

export PORT
exec ./target/release/chainlens_web
