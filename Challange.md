[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/BdrW_bK5)
# Week 1 Challenge: Chain Lens

Build a CLI tool that turns a raw Bitcoin transaction into a precise, machine-checkable JSON report, and a web visualizer (built on top of the same logic) that explains the transaction to non-technical users with diagrams, annotations, and friendly language.

This is a protocol-focused challenge: you are expected to lean on your understanding of Bitcoin transaction serialization and accounting to make your implementation robust beyond the small set of public examples.

---

## Assumptions / scope

- You do **not** need to validate signatures or execute scripts. This challenge is about parsing + accounting + classification.
- You may assume fixtures provide all required prevouts. You don't need to connect to a node or external API to fetch missing data.
- `network` will be `mainnet` for Week 1 evaluation.

## Deliverables

You must ship **both**:

1. **CLI analyzer** (machine-checkable correctness).
2. **Web transaction visualizer** (human-friendly explanation + graphics).

---

## Required repo interface

Your repository must include these scripts:

### 1) `cli.sh`

- Reads the fixture file.
- Runs your CLI analyzer.
- If the mode specified is `--block`, runs in block parsing mode; otherwise, runs in single-transaction mode.
- Writes the JSON report to a file named `out/<txid>.json` (where `<txid>` is the computed transaction ID). The `out/` directory must be created if it does not exist.
- If the fixture is a **single-transaction** fixture (no `"mode"` field), also prints the JSON report to **stdout**.
- Exits:
  - `0` on success
  - `1` on error (invalid fixture, malformed tx, inconsistent prevouts, etc.)

### 2) `web.sh`

- Starts the web visualizer.
- Must print a single line containing the URL (e.g. `http://127.0.0.1:3000`) to stdout.
- Must keep running until terminated (CTRL+C / SIGTERM).
- Must honor `PORT` if set (default `3000`).

---

## Fixture input format (for `cli.sh`)

Fixture JSON schema (transaction mode):

```json
{
  "network": "mainnet",
  "raw_tx": "0200000001...",
  "prevouts": [
    {
      "txid": "11...aa",
      "vout": 0,
      "value_sats": 123456,
      "script_pubkey_hex": "0014..."
    }
  ]
}
```

Notes:

- `raw_tx` is hex-encoded Bitcoin transaction bytes (no `0x` prefix).
- `prevouts` provides the **spent outputs** so you can compute fees.
- Do **not** assume `prevouts` is ordered the same as the transaction inputs; match prevouts to inputs by `(txid, vout)`.
- If a prevout is missing, duplicated, or does not correspond to an input outpoint, you must error.

---

## Block parsing mode

Block-level analysis uses Bitcoin Core's raw data files directly instead of a fixture JSON.

### Block-mode CLI invocation

```bash
cli.sh --block <blk*.dat> <rev*.dat> <xor.dat>
```

- `<blk*.dat>`: path to a Bitcoin Core block data file (e.g. `blk00000.dat`). A single file may contain **multiple blocks** — your parser must parse and generate a report for every block in the file.
- `<rev*.dat>`: path to the corresponding undo data file (e.g. `rev00000.dat`). Contains the prevout information (value + scriptPubKey) for every input spent in the block, in the same format as Bitcoin Core's undo records. This mirrors how Bitcoin Core stores the data needed to reverse a block during a reorg.
- `<xor.dat>`: path to the XOR key file used by Bitcoin Core to obfuscate `blk*.dat` and `rev*.dat` files. Your parser must XOR-decode the block and undo data before parsing. If the XOR key is all zeros, no transformation is needed.

When the CLI receives a `--block` flag, it operates in block mode. Otherwise (when given a plain fixture JSON path), it operates in single-transaction mode (the default).

### Block-mode output file

For each block in the file, the CLI must write a separate JSON report to a file named `out/<block_hash>.json` (where `<block_hash>` is the computed block hash in standard reversed-hex convention). The `out/` directory must be created if it does not exist. Block-mode output is **not** printed to stdout (only the files are written).

### Block-mode CLI behavior

In block mode, the CLI must:

1. Parse the 80-byte block header.
2. Parse all transactions.
3. Parse the undo data to recover prevouts for all non-coinbase inputs.
4. Compute the merkle root from the parsed transactions.
5. **Verify** the computed merkle root matches the header's `merkle_root`. If mismatch, return a structured error.
6. Identify the coinbase transaction (first tx): it must have exactly one input with `txid = 0x00...00` and `vout = 0xFFFFFFFF`.
7. For the coinbase input, decode the BIP34 block height from the scriptSig.

### Block-mode output

```json
{
  "ok": true,
  "mode": "block",
  "block_header": {
    "version": 536870912,
    "prev_block_hash": "...",
    "merkle_root": "...",
    "merkle_root_valid": true,
    "timestamp": 1710000000,
    "bits": "...",
    "nonce": 12345,
    "block_hash": "..."
  },
  "tx_count": 150,
  "coinbase": {
    "bip34_height": 800000,
    "coinbase_script_hex": "...",
    "total_output_sats": 631250000
  },
  "transactions": [ "/* same format as single-tx analysis, one per tx */" ],
  "block_stats": {
    "total_fees_sats": 6250000,
    "total_weight": 3996000,
    "avg_fee_rate_sat_vb": 25.1,
    "script_type_summary": {
      "p2wpkh": 420,
      "p2tr": 180,
      "p2sh": 55,
      "p2pkh": 30,
      "p2wsh": 12,
      "op_return": 8,
      "unknown": 2
    }
  }
}
```

**Notes:**
- `total_fees_sats` is the sum of fees across all non-coinbase transactions.
- Prevout data for all non-coinbase inputs comes exclusively from the undo file (`rev*.dat`). There is no `prevouts` array in block mode.

---

## Transaction output format

```json
{
  "ok": true,
  "network": "mainnet",
  "segwit": true,
  "txid": "...",
  "wtxid": "...",
  "version": 2,
  "locktime": 800000,
  "size_bytes": 222,
  "weight": 561,
  "vbytes": 141,
  "total_input_sats": 123456,
  "total_output_sats": 120000,
  "fee_sats": 3456,
  "fee_rate_sat_vb": 24.51,
  "rbf_signaling": true,
  "locktime_type": "block_height",
  "locktime_value": 800000,
  "segwit_savings": {
    "witness_bytes": 107,
    "non_witness_bytes": 115,
    "total_bytes": 222,
    "weight_actual": 561,
    "weight_if_legacy": 888,
    "savings_pct": 36.82
  },
  "vin": [
    {
      "txid": "...",
      "vout": 0,
      "sequence": 4194311,
      "script_sig_hex": "...",
      "script_asm": "...",
      "witness": ["..."],
      "script_type": "p2wpkh",
      "address": "bc1...",
      "prevout": {
        "value_sats": 123456,
        "script_pubkey_hex": "..."
      },
      "relative_timelock": {
        "enabled": true,
        "type": "blocks",
        "value": 7
      }
    }
  ],
  "vout": [
    {
      "n": 0,
      "value_sats": 120000,
      "script_pubkey_hex": "...",
      "script_asm": "OP_0 OP_PUSHBYTES_20 89abcdef0123456789abcdef0123456789abcdef",
      "script_type": "p2wpkh",
      "address": "bc1..."
    },
    {
      "n": 1,
      "value_sats": 0,
      "script_pubkey_hex": "6a08736f622d32303236",
      "script_asm": "OP_RETURN OP_PUSHBYTES_8 736f622d32303236",
      "script_type": "op_return",
      "address": null,
      "op_return_data_hex": "736f622d32303236",
      "op_return_data_utf8": "sob-2026",
      "op_return_protocol": "unknown"
    }
  ],
  "warnings": [
    { "code": "RBF_SIGNALING" }
  ]
}
```

Field requirements:

- `txid`: hex string (64 chars), standard display convention.
- `wtxid`: must be `null` for non-SegWit transactions.
- `fee_rate_sat_vb`: JSON number; evaluator accepts small rounding differences (+/-0.01).
- `address`: required for recognized types (on both inputs and outputs), else `null`.
- `vout[n].n`: must equal the output index `n` (0-based).
- `witness`: for legacy txs, return `[]` for each input. For SegWit, return the **exact** witness stack items in order (hex strings, including empty items as `""`).
- `warnings`: order does not matter.
- `segwit_savings`: must be `null` for non-SegWit transactions.

On errors:

- `error.code` and `error.message` must be present and non-empty strings.

Error output (on failures) must be:

```json
{ "ok": false, "error": { "code": "INVALID_TX", "message": "..." } }
```

---

## Script classification (outputs)

Classify each output `script_pubkey_hex` into one of these `script_type` values:

- `p2pkh`
- `p2sh`
- `p2wpkh`
- `p2wsh`
- `p2tr`
- `op_return`
- `unknown`

For recognized types (`p2pkh`, `p2sh`, `p2wpkh`, `p2wsh`, `p2tr`), `address` must be the corresponding mainnet address string. For anything else, `address` must be `null`.

### OP_RETURN payload decoding

For outputs classified as `op_return`, add three additional fields:

- `op_return_data_hex`: concatenation of all data pushes after `OP_RETURN`, in order. If there are no data pushes (bare `OP_RETURN`), return `""`.
- `op_return_data_utf8`: UTF-8 decode of the raw bytes. If the bytes are not valid UTF-8, return `null`.
- `op_return_protocol`: detect known protocols by prefix:
  - `"omni"` — data starts with `6f6d6e69` (ASCII "omni")
  - `"opentimestamps"` — data starts with `0109f91102`
  - `"unknown"` — anything else (including empty)

**Parsing requirement:** OP_RETURN payloads may use any valid push opcode (direct push `0x01`-`0x4b`, `OP_PUSHDATA1`, `OP_PUSHDATA2`, `OP_PUSHDATA4`). Your parser must handle all of these, not just assume a single direct push. Multiple push operations after `OP_RETURN` are concatenated.

---

## Script classification (inputs)

Classify each input's spend type into a `script_type` field on every `vin[]` entry:

- `p2pkh`
- `p2sh-p2wpkh`
- `p2sh-p2wsh`
- `p2wpkh`
- `p2wsh`
- `p2tr_keypath`
- `p2tr_scriptpath`
- `unknown`

Also add `address` to each `vin[]` entry, derived from the prevout scriptPubKey using the same rules as output addresses.

---

## Script disassembly

Add a `script_asm` field to:
- Each `vout[]` (disassembly of `script_pubkey_hex`)
- Each `vin[]` (disassembly of `script_sig_hex`)

**Format:** space-separated tokens. Opcodes use their standard names (`OP_DUP`, `OP_HASH160`, `OP_CHECKSIG`, etc.). Data pushes are rendered as `OP_PUSHBYTES_<n> <hex>` for direct pushes (`0x01`-`0x4b`), `OP_PUSHDATA1 <hex>` / `OP_PUSHDATA2 <hex>` / `OP_PUSHDATA4 <hex>` for extended pushes. `OP_0` is rendered as `OP_0`. `OP_1` through `OP_16` are rendered as `OP_1`..`OP_16`. Empty scripts produce `""`.

**Example:**
```
"script_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 89abcdef0123456789abcdef0123456789abcdef OP_EQUALVERIFY OP_CHECKSIG"
```

**Opcode table:** participants must support all opcodes defined in Bitcoin Core. Unknown/undefined opcodes should render as `OP_UNKNOWN_<0xNN>`.

Witness items are **not** disassembled (they are raw data stack items, not scripts) — with one exception: for `p2wsh` and `p2sh-p2wsh` inputs, add a `witness_script_asm` field containing the disassembly of the last witness item (the witnessScript).

---

## Timelock & RBF detection

Add the following top-level fields to the CLI output:

- `rbf_signaling`: `boolean` — whether the transaction signals BIP125 replaceability.
- `locktime_type`: one of `"none"`, `"block_height"`, or `"unix_timestamp"`.
- `locktime_value`: the raw locktime integer.

### Per-input relative timelock (BIP68)

Add a `relative_timelock` object to each `vin[]` entry with the following shape:

- `{ "enabled": false }` — when relative timelock is disabled. Omit `type` and `value`.
- `{ "enabled": true, "type": "blocks", "value": <blocks> }` — block-based relative lock.
- `{ "enabled": true, "type": "time", "value": <seconds> }` — time-based relative lock.

---

## Weight / vbytes rules

Compute `size_bytes`, `weight`, and `vbytes` according to BIP141.

---

## Witness discount analysis

For SegWit transactions, add a `segwit_savings` object to the top-level output with the following fields:

- `witness_bytes`
- `non_witness_bytes`
- `total_bytes`
- `weight_actual`
- `weight_if_legacy`
- `savings_pct` (rounded to 2 decimal places)

For non-SegWit transactions, `segwit_savings` must be `null`.

Refer to BIP141 for how witness and non-witness bytes are defined and weighted.

---

## Warnings (required codes)

Emit warning codes when:

- `HIGH_FEE`: if `fee_sats > 1_000_000` OR `fee_rate_sat_vb > 200`
- `DUST_OUTPUT`: any non-`op_return` output has `value_sats < 546`
- `UNKNOWN_OUTPUT_SCRIPT`: any output has `script_type == "unknown"`
- `RBF_SIGNALING`: if `rbf_signaling` is `true`

You may add more warnings, but these codes must be present when applicable.

---

## Web visualizer requirements (candidate-facing)

Your web app must:

- Provide a **single-page transaction visualizer** that can analyze a fixture transaction and explain it in plain English.
- Use visuals: diagrams, annotations, callouts, color-coding, etc.
- Make it understandable for non-technical users (avoid jargon or define it inline).

Recommended UX (not strictly required, but strongly encouraged):

- A "story" view: **What happened?** -> **Who paid whom?** -> **What did it cost?** -> **Is anything risky?**
- A visual graph:
  - Inputs on the left, outputs on the right, arrows connecting the "value flow"
  - Highlight fee as a "missing slice" (inputs minus outputs)
- Tooltips for terms like "input", "output", "fee", "vbytes", "SegWit", "OP_RETURN"
- One-click "show technical details" section for hex/script fields
- Good defaults for non-technical users: hide raw hex until requested

Minimum functional requirements:

1. A way to load a transaction fixture (paste the JSON fixture contents OR paste `raw_tx` hex and `prevouts`).
2. A way to upload block files (`blk*.dat`, `rev*.dat`, `xor.dat`) for block-mode analysis.
3. A rendered view that includes (visibly):
   - `txid`
   - fee and feerate
   - number of inputs and outputs
   - script type labels per output (e.g. "P2WPKH", "Taproot", "OP_RETURN")
4. For block mode: a block overview showing tx count, total fees, and a transaction list that can be expanded to see individual tx analysis.
5. Must not require external internet access to function once dependencies are installed.
6. Must expose a health endpoint: `GET /api/health` -> `200` with JSON `{ "ok": true }`.

---

## Sample tests

Public fixtures will be provided in `fixtures/`.

Example:

```bash
cli.sh fixtures/transactions/tx_legacy_p2pkh.json
```

The public fixtures are examples only; the evaluator will run a broad set of additional (hidden) fixtures. Build your analyzer to be correct and resilient according to the Bitcoin transaction format and the contract above.

---

## Acceptance criteria (definitive)

- `cli.sh` succeeds on all provided fixtures
- CLI JSON report matches the required schema and rules (txid/wtxid, vbytes/weight, fees, script classification, warnings, timelocks, script disassembly, segwit savings)
- Web app launches via `web.sh` and serves the required API (`/api/health`, `/api/analyze`)
- Errors are returned as structured JSON with non-empty `error.code` and `error.message`
- Demo video link is included in `demo.md` at the repository root (the file should contain only the link):
  - **Where to upload:** YouTube, Loom, or Google Drive. The link must be viewable by evaluators without requesting access (public or unlisted is fine; no "request access" links).
  - **What to record:** a screen recording of your **web UI** walkthrough (no code walkthrough; don't spend time scrolling through source files).
  - **What to demonstrate:** use your UI to analyze **one** real transaction or provided fixture and visually point to the parts as you explain them.
  - **How to explain:** speak as if to a non-technical person who has never seen Bitcoin before; use simple language and define terms as you introduce them.
  - **Topics your walkthrough must cover (using the UI):**
    - what a transaction "is" at a high level (moving value by spending old outputs and creating new outputs)
    - inputs (what is being spent) and outputs (who is receiving)
    - fee and fee rate (why it exists; inputs minus outputs)
    - weight/vbytes (why transaction "size" matters for fees)
    - SegWit vs legacy at a high level (where witness data fits; what changes between txid and wtxid)
    - script/address types shown in your UI (P2PKH / P2SH / P2WPKH / P2WSH / P2TR / OP_RETURN) and what they mean in plain terms
    - RBF signaling: what it means for a transaction to be replaceable, and how nSequence controls it
    - timelocks: absolute vs relative, and what they prevent
    - SegWit discount visualization: a side-by-side or overlay showing actual weight vs hypothetical legacy weight
    - any warnings your UI shows (e.g., dust, high fee, unknown script, RBF)
  - **Hard limit:** the video must be strictly **less than 2 minutes** long.

---

## Hidden fixture categories

The evaluator will test with fixtures covering (but not limited to) the following scenarios. You do not need to create these fixtures yourself, but your implementation must handle all of them correctly:

- Taproot keypath spend (1 witness item, 64 bytes)
- Taproot scriptpath spend (witness with script, control block starting with `0xc0`/`0xc1`)
- P2SH-P2WPKH input (nested SegWit)
- P2SH-P2WSH input (nested SegWit multisig)
- P2WSH input with complex witnessScript
- Transaction with RBF signaling (`sequence = 0xFFFFFFFD`)
- Transaction with relative timelock (BIP68 -- blocks-based)
- Transaction with relative timelock (BIP68 -- time-based)
- Transaction with absolute locktime (block height)
- Transaction with absolute locktime (unix timestamp)
- OP_RETURN with `OP_PUSHDATA1`
- OP_RETURN with multiple pushes
- OP_RETURN with Omni prefix
- OP_RETURN with non-UTF8 binary data
- A small raw block with undo file (e.g., a real mainnet block with 5-10 transactions)
- A block with invalid merkle root (should error)
- A block with truncated/malformed undo data (should error)
- A block with undo data containing compressed P2PK scripts (nSize 2/3 and 4/5)
- A block with undo data using special-type compression (nSize 0 = P2PKH, nSize 1 = P2SH)
- A block with undo data containing raw scripts (nSize >= 6)
- Transaction with all inputs having disabled relative timelocks (bit 31 set)
- Transaction mixing RBF-signaling and non-signaling inputs

---

## Evaluation criteria

Evaluation happens in two phases:

### Phase 1: Automated evaluation (before deadline)

- **CLI correctness:** your `cli.sh` will be run against all public fixtures.
- **Block parsing:** block-mode invocations will be tested with real mainnet block files.
- **Web health check:** `web.sh` must start successfully and respond to `GET /api/health` with `200 { "ok": true }`.
- **Error handling:** invalid inputs must produce structured error JSON (`{ "ok": false, "error": { "code": "...", "message": "..." } }`) and exit code `1`.

### Phase 2: Manual evaluation (after deadline)

- **Hidden fixtures:** your CLI will be tested against a broad set of hidden fixtures covering the scenarios listed above.
- **Web UI quality:** clarity of explanations, visual design, diagrams, and how well the UI teaches non-technical users about Bitcoin transactions.
- **Demo video:** evaluated for coverage of required topics, clarity of explanation, and adherence to the 2-minute time limit.
- **Code quality:** readability, structure, and appropriate use of abstractions.

---

## Plagiarism policy

- All submitted code must be your own original work. You may use AI coding assistants (e.g. GitHub Copilot, ChatGPT, Claude) as tools, but you must understand and be able to explain every part of your submission.
- Copying code from other participants' submissions (current or past cohorts) is strictly prohibited.
- Using open-source libraries and referencing public documentation (BIPs, Bitcoin wiki, Stack Exchange, etc.) is encouraged — that is research, not plagiarism.
- Submissions will be checked for similarity against other participants. If two or more submissions share substantially identical logic or structure beyond what would arise from following the spec, all involved submissions may be disqualified.
- If you are unsure whether something counts as plagiarism, ask before submitting.

