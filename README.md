# ChainLens

**MIT License | Rust | Bitcoin**

High-performance Bitcoin block and transaction analyzer written in Rust.

ChainLens parses raw `blk*.dat` and `rev*.dat` files directly from Bitcoin Core, reconstructs full block context (including undo data), verifies Merkle roots, computes fees and weight metrics, and produces structured JSON reports.

The project is built with one primary goal:

> **Maximum speed with correctness — similar to Bitcoin Core design principles.**

---

# ✨ Features

## 🔍 Transaction Mode

* Analyze a single transaction from raw bytes
* Computes:

  * txid / wtxid
  * weight & virtual size
  * fees & fee rate
  * script classification (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN, …)
  * RBF detection
  * locktime analysis
  * Optional detailed vin/vout report

## 📦 Block Mode (High-Performance)

* Direct parsing of:

  * `blk*.dat`
  * `rev*.dat`
  * `xor.dat` (obfuscation key)
* Strict Bitcoin Core record framing
* Undo-data pairing (fast path + safe fallback)
* Merkle root verification
* Parallel transaction analysis for large blocks
* Aggregated block statistics:

  * total fees
  * total weight
  * average fee rate
  * script type distribution

---

# 🏗 Architecture Overview

```
src/
├── btc/
│   ├── block/      # Block parsing, undo handling, Merkle, reports
│   ├── tx/         # Transaction parsing, script classification, reports
│   └── mod.rs
│
├── bin/
│   ├── chainlens_cli.rs   # Command-line interface
│   └── chainlens_web.rs   # Web server interface
│
└── lib.rs
```

## Design Philosophy

ChainLens separates computation into two layers:

### 1️⃣ Core Layer (Hot Path)

Minimal structures focused on:

* fee calculation
* weight computation
* hashing
* script classification

Used in block mode for maximum throughput.

### 2️⃣ Report Layer

Transforms core results into structured JSON for:

* CLI output
* Web API
* External integrations

This separation keeps block processing extremely fast while still enabling detailed inspection when needed.

---

# 🚀 Installation

Requires Rust (stable).

```bash
cargo build --release
```

Binary will be located at:

```
target/release/chainlens_cli
```

---

# 🖥 CLI Usage

## Transaction Mode

# open fixtures for tests
cd fixtures/blocks
gunzip *.gz
cd ../../

Analyze a transaction from file:
=======

```bash
./target/release/chainlens_cli fixtures/transactions/dust_output.json
```

Outputs structured JSON (out/*.json & terminal).

---

## Block Mode

Analyze raw Bitcoin Core block files:

```bash
./target/release/chainlens_cli --block fixtures/blocks/blk04330.dat fixtures/blocks/rev04330.dat fixtures/blocks/xor.dat
```

Produces JSON reports for each block inside the file (out/*.json).

---

# 🌐 Web Interface

Start the web server (development mode):

```bash
cargo run --bin chainlens_web
```

Or run the compiled release binary:

```bash
./target/release/chainlens_web
```

Then open:

```
http://127.0.0.1:3000
```

# use fixtures/transactions/*.json for test

cd fixtures/transactions


The web UI allows:

* Pasting transaction fixtures
* Viewing formatted JSON
* Inspecting fee distribution
* Script type statistics

---

# ⚡ Performance Strategy

ChainLens is optimized around the following principles:

* Zero-copy parsing where possible
* Strict framing validation
* Minimal allocations in hot paths
* Chunked parallel execution for large blocks
* Deterministic output ordering

Block pairing strategy:

1. Fast index-based pairing
2. Trailer hash pairing (optional fast mode)
3. Safe fallback validation

---

# 🔐 Correctness Guarantees

* Double SHA256 hashing identical to Bitcoin Core
* Merkle root verification
* Strict varint decoding
* Strict undo validation
* Defensive script parsing (never panics on malformed scripts)

---

# 📊 Output Format

Block reports include:

* block header fields
* block hash
* transaction count
* coinbase analysis (BIP34 height extraction)
* per-transaction summaries
* aggregated block statistics

Transaction reports include:

* txid / wtxid
* fee & fee rate
* weight & vsize
* script classifications
* warnings (if applicable)

All outputs are JSON and stable for programmatic use.

---

# 🧠 Intended Use Cases

* Blockchain analytics
* Fee research
* Mempool analysis prototypes
* Block validation experiments
* Educational deep-dive into Bitcoin internals
* Backend component for explorers

---

# 🛣 Roadmap

Planned improvements:

* Full Taproot script-path decoding
* Extended script ASM output
* Benchmark suite
* Mainnet/Testnet auto-detection
* REST API documentation
* Performance comparison against other parsers

---

# 📜 License

This project is licensed under the MIT License.

See the `LICENSE` file for the full license text.

---

# 🧠 Project Status

ChainLens originated as an implementation project for the Summer of Bitcoin technical challenge.

It was developed with a strong focus on performance, correctness, and low-level Bitcoin data handling, and later refined into a standalone engineering showcase.

ChainLens is a standalone engineering project focused on performance and correctness.

It is not actively developed as a long-term product. The repository is published for transparency, educational value, and technical showcase purposes.

---

# 🤝 Contributions

This project is currently not seeking external contributions.

You are welcome to fork and experiment with it under the terms of the MIT License.

---

# 🧩 Why ChainLens?

Bitcoin Core validates blocks.

ChainLens **analyzes** them — fast, deterministic, and structured.
