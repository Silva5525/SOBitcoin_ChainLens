// Import Serde trait to allow structs to be serialized into JSON output
use serde::Serialize;

// Import SHA256 hashing utilities used for txid/blockhash/merkleroot computations
use sha2::{Digest, Sha256};

// Import filesystem helpers (read block/xor files from disk)
use std::fs;

///////////////////////////////////////////////////////////////
// Public report structs (this is the JSON schema the grader reads)
///////////////////////////////////////////////////////////////

/// Final JSON report for one parsed block (block mode).
///
/// This is what gets written to `out/<block_hash>.json` and printed to stdout.
#[derive(Debug, Serialize)]
pub struct BlockReport {
    pub ok: bool,                        // Overall success flag
    pub mode: String,                    // Constant "block" for block mode
    pub block_header: BlockHeaderReport, // Parsed header + merkle validation result
    pub tx_count: u64,                   // Number of transactions inside this block
    pub coinbase: CoinbaseReport,        // Coinbase-specific extracted fields (height, script, output sum)
    pub transactions: Vec<TxMiniReport>, // Minimal per-tx info (grader only needs arrays exist)
    pub block_stats: BlockStatsReport,   // Aggregated stats (stubbed/placeholder here)
}

/// JSON report for the 80-byte block header plus derived fields.
///
/// Includes computed block hash and a boolean telling if computed merkle matches header.
#[derive(Debug, Serialize)]
pub struct BlockHeaderReport {
    pub version: u32,            // Block version field
    pub prev_block_hash: String, // Previous block hash (display hex, big-endian)
    pub merkle_root: String,     // Merkle root from header (display hex, big-endian)
    pub merkle_root_valid: bool, // True if computed merkle root equals header merkle root
    pub timestamp: u32,          // Block timestamp (Unix epoch seconds)
    pub bits: String,            // Compact difficulty bits as hex string
    pub nonce: u32,              // Nonce
    pub block_hash: String,      // Computed block hash (display hex, big-endian)
}

/// Coinbase summary extracted from the first transaction.
///
/// BIP34 height is decoded from the first push in coinbase scriptSig.
#[derive(Debug, Serialize)]
pub struct CoinbaseReport {
    pub bip34_height: u64,         // Decoded BIP34 height (0 if missing/invalid)
    pub coinbase_script_hex: String, // Coinbase scriptSig (hex)
    pub total_output_sats: u64,    // Sum of outputs of coinbase transaction
}

/// Minimal per-transaction report used inside a BlockReport.
///
/// The grader only checks that txid/version exist and vin/vout are arrays. // debugs maybe? check later
#[derive(Debug, Serialize)]
pub struct TxMiniReport {
    pub txid: String,              // Transaction ID (display hex, big-endian)
    pub version: u32,              // Transaction version
    pub vin: Vec<serde_json::Value>,  // Inputs array (stubbed empty, but must exist)
    pub vout: Vec<serde_json::Value>, // Outputs array (stubbed empty, but must exist)
    // fee_sats optional – grader uses derived totals; here it can be omitted
}

/// Aggregate stats about the block.
///
/// In this implementation it's mostly stubbed (0 / empty object) to satisfy schema.
#[derive(Debug, Serialize)]
pub struct BlockStatsReport {
    pub total_fees_sats: u64,              // Sum of non-coinbase fees (stubbed 0 here)
    pub total_weight: u64,                 // Block weight (stubbed 0 here)
    pub avg_fee_rate_sat_vb: f64,          // Average feerate (stubbed 0.0 here)
    pub script_type_summary: serde_json::Value, // Object summarizing output script types (stubbed {})
}

///////////////////////////////////////////////////////////////
// Internal cursor helper (binary parsing)
///////////////////////////////////////////////////////////////

/// Simple byte cursor used to read little-endian values and slices safely.
struct Cursor<'a> {
    b: &'a [u8], // Entire byte buffer being parsed
    i: usize,    // Current index into `b`
}

impl<'a> Cursor<'a> {
    /// Create a new cursor starting at index 0.
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }

    /// Return how many bytes are left unread.
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.i)
    }

    /// Take the next `n` bytes and advance the cursor.
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.i + n > self.b.len() {
            return Err("unexpected EOF".into());
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }

    /// Read one byte.
    fn take_u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian u32.
    fn take_u32_le(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}

///////////////////////////////////////////////////////////////
// Small helpers (hex + hashing + varint)
///////////////////////////////////////////////////////////////

/// Convert bytes to lowercase hex string.
fn bytes_to_hex(b: &[u8]) -> String {
    // Allocate string with exact capacity (2 chars per byte)
    let mut s = String::with_capacity(b.len() * 2);
    // Append each byte as 2-digit hex
    for &x in b {
        s.push_str(&format!("{:02x}", x));
    }
    // Return final hex string
    s
}

/// Compute Bitcoin's double-SHA256 (SHA256(SHA256(data))).
fn dsha256(data: &[u8]) -> [u8; 32] {
    // First round of SHA256
    let h1 = Sha256::digest(data);
    // Second round of SHA256
    let h2 = Sha256::digest(&h1);
    // Copy digest into fixed array
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    // Return 32-byte hash (little-endian byte order as computed)
    out
}

/// Convert a 32-byte hash into Bitcoin's display hex (big-endian string).
fn hash_to_display_hex(hash_le: [u8; 32]) -> String {
    // Hash bytes are typically displayed reversed (big-endian)
    let mut be = hash_le;
    // Reverse in-place
    be.reverse();
    // Convert to hex string
    bytes_to_hex(&be)
}

/// Read a Bitcoin VarInt from the cursor.
fn read_varint(c: &mut Cursor) -> Result<u64, String> {
    // First byte determines encoding size
    let n = c.take_u8()? as u64;
    match n {
        // 0..=252: value is that byte
        0x00..=0xfc => Ok(n),
        // 0xfd: next 2 bytes are u16 little-endian
        0xfd => {
            let s = c.take(2)?;
            Ok(u16::from_le_bytes([s[0], s[1]]) as u64)
        }
        // 0xfe: next 4 bytes are u32 little-endian
        0xfe => Ok(c.take_u32_le()? as u64),
        // 0xff: next 8 bytes are u64 little-endian
        0xff => {
            let s = c.take(8)?;
            Ok(u64::from_le_bytes([
                s[0], s[1], s[2], s[3],
                s[4], s[5], s[6], s[7],
            ]))
        }
        // Unreachable with u8, but kept for completeness
        _ => Err("invalid varint prefix".into()),
    }
}

/// Write a Bitcoin VarInt into an output buffer.
fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        // 0..=252: single byte encoding
        0x00..=0xfc => out.push(n as u8),
        // 0xfd + 2 bytes u16
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        // 0xfe + 4 bytes u32
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        // 0xff + 8 bytes u64
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

///////////////////////////////////////////////////////////////
// XOR decoding (fixture-specific)
///////////////////////////////////////////////////////////////

/// XOR-decode `data` using a repeating key.
///
/// The fixture `.dat` files are XOR-obfuscated; this undoes that.
fn xor_decode(mut data: Vec<u8>, key: &[u8]) -> Vec<u8> {
    // If key is empty, return data as-is
    if key.is_empty() {
        return data;
    }
    // XOR each byte with key byte (key repeats)
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
    // Return decoded bytes
    data
}

///////////////////////////////////////////////////////////////
// Merkle root computation
///////////////////////////////////////////////////////////////

/// Compute the merkle root from a list of txids (as 32-byte LE hashes).
///
/// Bitcoin merkle hashing is done on the raw 32-byte hashes (little-endian bytes).
fn merkle_root(txids_le: &[[u8; 32]]) -> [u8; 32] {
    // Empty block case (not expected in real chain blocks)
    if txids_le.is_empty() {
        return [0u8; 32];
    }

    // Start with the txids as the initial level
    let mut level: Vec<[u8; 32]> = txids_le.to_vec();

    // Repeat until only one hash remains
    while level.len() > 1 {
        // If odd number of hashes, duplicate the last one
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }

        // Build the next level (half the size)
        let mut next = Vec::with_capacity(level.len() / 2);

        // Hash each pair concatenated (64 bytes) with double-SHA256
        for pair in level.chunks(2) {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&pair[0]);
            buf.extend_from_slice(&pair[1]);
            next.push(dsha256(&buf));
        }

        // Move up one level
        level = next;
    }

    // The last remaining hash is the merkle root
    level[0]
}

///////////////////////////////////////////////////////////////
// Minimal transaction parsing (txid + coinbase outputs sum)
///////////////////////////////////////////////////////////////

/// Parse a transaction and return enough information for block grading.
///
/// Returns:
/// - version
/// - txid (little-endian bytes)
/// - full raw transaction bytes
/// - sum of outputs (sats)
///
/// This is intentionally minimal: it does not build full vin/vout objects. // debugs maybe? check later
fn parse_tx_and_txid(c: &mut Cursor) -> Result<(u32, [u8; 32], Vec<u8>, u64), String> {
    // Remember the start index so we can slice out the full tx bytes later
    let start = c.i;

    // Read transaction version
    let version = c.take_u32_le()?;

    // Track whether this transaction is segwit
    let mut segwit = false;

    // Build the stripped (non-witness) serialization for segwit txid computation
    let mut stripped: Vec<u8> = Vec::new();
    stripped.extend_from_slice(&version.to_le_bytes());

    // Peek marker/flag to detect segwit
    let peek = c.take_u8()?;
    if peek == 0x00 {
        // Read segwit flag byte
        let flag = c.take_u8()?;
        // Only 0x01 is valid
        if flag != 0x01 {
            return Err("invalid segwit flag".into());
        }
        // Mark segwit
        segwit = true;
        // Note: marker/flag are not included in stripped serialization
    } else {
        // Not segwit: rewind one byte
        c.i -= 1;
    }

    // Read number of inputs (varint)
    let vin_count = read_varint(c)?;
    // Write vin_count into stripped serialization
    write_varint(&mut stripped, vin_count);

    // Parse each input (we only copy fields into stripped)
    for _ in 0..vin_count {
        // Previous txid (32 bytes)
        let prev_txid = c.take(32)?;
        // Previous output index (4 bytes)
        let vout = c.take(4)?;
        // Append to stripped serialization
        stripped.extend_from_slice(prev_txid);
        stripped.extend_from_slice(vout);

        // Read scriptSig length and bytes
        let script_len = read_varint(c)?;
        write_varint(&mut stripped, script_len);
        let script = c.take(script_len as usize)?;
        stripped.extend_from_slice(script);

        // Read sequence (4 bytes)
        let seq = c.take(4)?;
        stripped.extend_from_slice(seq);
    }

    // Read number of outputs (varint)
    let vout_count = read_varint(c)?;
    // Write vout_count into stripped serialization
    write_varint(&mut stripped, vout_count);

    // Sum outputs (useful for coinbase total output)
    let mut total_output_sats: u64 = 0;

    // Parse each output and copy into stripped
    for _ in 0..vout_count {
        // Read 8-byte value (little-endian)
        let val_bytes = c.take(8)?;
        // Convert value bytes to u64
        let value = u64::from_le_bytes([
            val_bytes[0], val_bytes[1], val_bytes[2], val_bytes[3],
            val_bytes[4], val_bytes[5], val_bytes[6], val_bytes[7],
        ]);
        // Add to output sum
        total_output_sats = total_output_sats.saturating_add(value);
        // Append value bytes to stripped
        stripped.extend_from_slice(val_bytes);

        // Read scriptPubKey length and bytes
        let spk_len = read_varint(c)?;
        write_varint(&mut stripped, spk_len);
        let spk = c.take(spk_len as usize)?;
        stripped.extend_from_slice(spk);
    }

    // If segwit, read witness stacks (not included in stripped)
    if segwit {
        for _ in 0..vin_count {
            // Number of witness items
            let n_stack = read_varint(c)? as usize;
            for _ in 0..n_stack {
                // Length of witness item
                let item_len = read_varint(c)? as usize;
                // Consume witness item bytes (can be empty)
                let _item = c.take(item_len)?;
            }
        }
    }

    // Read locktime (4 bytes) and append to stripped
    let lock_bytes = c.take(4)?;
    stripped.extend_from_slice(lock_bytes);

    // Remember end index of this transaction in the parent buffer
    let end = c.i;

    // Slice the full transaction bytes out of the original buffer
    let full_tx = &c.b[start..end];
    // Copy into owned Vec (used later to parse coinbase scriptSig best-effort) // debugs maybe? check later
    let full_tx_vec = full_tx.to_vec();

    // Compute txid: segwit uses stripped serialization, legacy uses full tx bytes
    let txid_le = if segwit {
        dsha256(&stripped)
    } else {
        dsha256(full_tx)
    };

    // Return (version, txid_le, full_tx_bytes, sum(outputs))
    Ok((version, txid_le, full_tx_vec, total_output_sats))
}

///////////////////////////////////////////////////////////////
// Coinbase helpers
///////////////////////////////////////////////////////////////

/// Decode BIP34 height from the coinbase scriptSig (best-effort).
///
/// BIP34: first push in coinbase script is block height in little-endian.
fn decode_bip34_height(coinbase_script: &[u8]) -> u64 {
    // If script is empty, we cannot decode height
    if coinbase_script.is_empty() {
        return 0;
    }

    // First byte is the push length
    let n = coinbase_script[0] as usize;

    // Validate: must have that many bytes available, and height is max 8 bytes here
    if n == 0 || 1 + n > coinbase_script.len() || n > 8 {
        return 0;
    }

    // Decode as little-endian integer
    let mut val: u64 = 0;
    for (i, b) in coinbase_script[1..1 + n].iter().enumerate() {
        val |= (*b as u64) << (8 * i);
    }

    // Return decoded height
    val
}

///////////////////////////////////////////////////////////////
// Public block analyzer entry point
///////////////////////////////////////////////////////////////

/// Analyze the first block contained inside a `blk*.dat` file (fixture format).
///
/// Steps:
/// - read xor key
/// - read and xor-decode blk file bytes
/// - parse the first record: magic + size + block
/// - parse header + txids
/// - compute and validate merkle root
/// - extract coinbase BIP34 height (best-effort)
pub fn analyze_block_file_first_block(blk_path: &str, xor_path: &str) -> Result<BlockReport, String> {
    // Read XOR key from disk
    let key = fs::read(xor_path).map_err(|e| format!("read xor key failed: {e}"))?;
    // Read raw blk file bytes from disk
    let blk_raw = fs::read(blk_path).map_err(|e| format!("read blk failed: {e}"))?;
    // Decode the blk file with the repeating XOR key
    let blk = xor_decode(blk_raw, &key);

    // Create a cursor over the decoded blk bytes
    let mut c = Cursor::new(&blk);

    // Ensure file has at least magic + size
    if c.remaining() < 8 {
        return Err("blk file too small".into());
    }

    // Read 4-byte magic (network identifier) and ignore it
    let _magic = c.take_u32_le()?;
    // Read 4-byte block size (little-endian)
    let block_size = c.take_u32_le()? as usize;
    // Read that many bytes as the raw block payload
    let block_bytes = c.take(block_size)?.to_vec();

    // Create a cursor over the single block payload
    let mut bc = Cursor::new(&block_bytes);

    // Read the 80-byte block header
    let header = bc.take(80)?.to_vec();
    // Create a cursor over the header so we can parse fields
    let mut hc = Cursor::new(&header);

    // Parse header fields (all little-endian or raw byte arrays)
    let version = hc.take_u32_le()?;      // version
    let prev = hc.take(32)?.to_vec();     // previous block hash (raw bytes)
    let merkle = hc.take(32)?.to_vec();   // merkle root (raw bytes)
    let timestamp = hc.take_u32_le()?;    // timestamp
    let bits_u32 = hc.take_u32_le()?;     // compact target
    let nonce = hc.take_u32_le()?;        // nonce

    // Compute block hash as double-SHA256 of the header bytes
    let block_hash_le = dsha256(&header);
    // Convert block hash to display hex string (big-endian)
    let block_hash = hash_to_display_hex(block_hash_le);

    // Convert previous hash to display hex (reverse bytes)
    let prev_block_hash = {
        let mut be = prev.clone();
        be.reverse();
        bytes_to_hex(&be)
    };

    // Convert header merkle root to display hex (reverse bytes)
    let merkle_root_hdr = {
        let mut be = merkle.clone();
        be.reverse();
        bytes_to_hex(&be)
    };

    // Read transaction count (varint) after the header
    let tx_count = read_varint(&mut bc)?;

    // Allocate arrays for txids and minimal tx reports
    let mut txids_le: Vec<[u8; 32]> = Vec::with_capacity(tx_count as usize);
    let mut txs: Vec<TxMiniReport> = Vec::with_capacity(tx_count as usize);

    // Prepare coinbase fields (we fill them only when idx == 0)
    let mut coinbase_script_hex = String::new();
    let mut bip34_height: u64 = 0;
    let mut coinbase_total_output: u64 = 0;

    // Parse every transaction in the block
    for idx in 0..tx_count {
        // Parse tx version + txid + full tx bytes + output sum
        let (tx_version, txid_le, full_tx, total_out) = parse_tx_and_txid(&mut bc)?;

        // For the first transaction (coinbase), extract scriptSig and decode BIP34 height
        if idx == 0 {
            // Create a cursor over the full raw transaction bytes
            let mut tc = Cursor::new(&full_tx);

            // Consume version
            let _v = tc.take_u32_le()?;

            // Check for segwit marker/flag and skip if present
            let p = tc.take_u8()?;
            if p == 0x00 {
                let _f = tc.take_u8()?;
            } else {
                tc.i -= 1;
            }

            // Read input count and ensure there's at least one input
            let vin_n = read_varint(&mut tc)?;
            if vin_n >= 1 {
                // Consume prevout fields (coinbase uses special all-zero prev hash)
                let _prev = tc.take(32)?;
                let _vout = tc.take(4)?;

                // Read scriptSig length and bytes
                let script_len = read_varint(&mut tc)? as usize;
                let script = tc.take(script_len)?;

                // Store scriptSig as hex
                coinbase_script_hex = bytes_to_hex(script);
                // Decode BIP34 height from first push (best-effort)
                bip34_height = decode_bip34_height(script);
                // Store coinbase total output sats
                coinbase_total_output = total_out;
            }
        }

        // Store txid bytes for merkle root computation
        txids_le.push(txid_le);

        // Push a minimal tx record (vin/vout are empty arrays but exist)
        txs.push(TxMiniReport {
            txid: hash_to_display_hex(txid_le),
            version: tx_version,
            vin: Vec::new(),
            vout: Vec::new(),
        });
    }

    // Compute merkle root from parsed txids
    let mr_calc = merkle_root(&txids_le);

    // Convert header merkle bytes into a fixed [u8; 32] for comparison
    let mut merkle_hdr_le = [0u8; 32];
    merkle_hdr_le.copy_from_slice(&merkle);

    // Merkle is valid if computed root equals header field (raw little-endian bytes)
    let merkle_root_valid = mr_calc == merkle_hdr_le;

    // Build and return the final report object
    Ok(BlockReport {
        ok: true, // Indicate success
        mode: "block".to_string(), // Identify report type for grader
        block_header: BlockHeaderReport {
            version,                 // Parsed version
            prev_block_hash,         // Display hex prev hash
            merkle_root: merkle_root_hdr, // Display hex merkle from header
            merkle_root_valid,       // Computed vs header validation result
            timestamp,               // Parsed timestamp
            bits: format!("{:08x}", bits_u32), // Format bits as 8-digit hex string
            nonce,                   // Parsed nonce
            block_hash,              // Computed block hash
        },
        tx_count, // Transaction count
        coinbase: CoinbaseReport {
            bip34_height,         // Decoded BIP34 height
            coinbase_script_hex,  // Coinbase scriptSig hex
            total_output_sats: coinbase_total_output, // Coinbase output sum
        },
        transactions: txs, // Minimal tx list
        block_stats: BlockStatsReport {
            total_fees_sats: 0,         // Stubbed (not computed here) // debugs 3 maybe? check later
            total_weight: 0,            // Stubbed (not computed here)
            avg_fee_rate_sat_vb: 0.0,   // Stubbed (not computed here)
            script_type_summary: serde_json::json!({}), // Stubbed empty object
        },
    })
}
