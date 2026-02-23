# README_WEB.md

# ChainLens Web – Usage

This file explains only how to start and use the ChainLens website.

---

## Start the Web Server

From the project root:

```bash
./web.sh
```

The server will:

- Build the web binary (if needed)
- Start the HTTP server
- Print a single URL like:

```
http://127.0.0.1:3000
```

Open that URL in your browser.

---

### Alternative (Cargo)

```bash
cargo run --release --bin chainlens_web
```

---

### Custom Port

```bash
PORT=8080 ./web.sh
```

Then open:

```
http://127.0.0.1:8080
```

---

## Using the Website

1. Open the printed URL in your browser.
2. Paste a valid transaction fixture JSON into the input field.
3. Click **Analyze**.

Example fixture format:

```json
{
  "network": "mainnet",
  "raw_tx": "<raw transaction hex>",
  "prevouts": [
    {
      "txid": "<previous txid>",
      "vout": 0,
      "value_sats": 100000,
      "script_pubkey_hex": "<script hex>"
    }
  ]
}
```

The website will:

- Show TXID
- Show fee and fee rate
- Show size and weight
- Detect SegWit
- Display inputs and outputs
- Render a value flow diagram
- Show the full JSON report

---

## Stop the Server

Press:

```
CTRL + C
```

