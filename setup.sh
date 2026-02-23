#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# setup.sh — Install project dependencies
#
# Add your install commands below (e.g., npm install, pip install, cargo build).
# This script is run once before grading to set up the environment.
###############################################################################

# Decompress block fixtures if not already present
for gz in fixtures/blocks/*.dat.gz; do
  dat="${gz%.gz}"
  if [[ ! -f "$dat" ]]; then
    echo "Decompressing $(basename "$gz")..."
    gunzip -k "$gz"
  fi
done

# Prebuild Rust binaries once during setup so per-fixture cli.sh calls are fast.
# This avoids 60s timeouts on the first fixture in GitHub runners.
cargo build --release --bin chainlens_cli --bin chainlens_web --quiet

echo "Setup complete"
