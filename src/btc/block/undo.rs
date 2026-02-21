// src/btc/block/undo.rs

use super::parser;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;

type UndoPrevouts = Vec<Vec<(u64, Vec<u8>)>>;

fn err(code: &str, msg: impl AsRef<str>) -> String {
    format!("{code}: {}", msg.as_ref())
}

fn ensure_len(kind: &str, field: &str, val: u64, max: u64) -> Result<(), String> {
    parser::ensure_len(kind, field, val, max)
}

fn read_varint_core(c: &mut parser::Cursor) -> Result<u64, String> {
    // Bitcoin Core base-128 VarInt encoding (serialize.h)
    let mut n: u64 = 0;
    loop {
        let ch = c.take_u8()? as u64;
        let data = ch & 0x7f;
        n = (n << 7) | data;
        if (ch & 0x80) != 0 {
            n = n.checked_add(1).ok_or_else(|| err("VARINT_OVERFLOW", "core varint overflow"))?;
            continue;
        }
        return Ok(n);
    }
}

fn read_compactsize(c: &mut parser::Cursor) -> Result<u64, String> {
    // Bitcoin CompactSize
    let first = c.take_u8()?;
    match first {
        0x00..=0xfc => Ok(first as u64),
        0xfd => Ok(c.take_u16_le()? as u64),
        0xfe => Ok(c.take_u32_le()? as u64),
        0xff => Ok(c.take_u64_le()?),
    }
}

fn decompress_amount(x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    let mut x = x - 1;
    let e = (x % 10) as u32;
    x /= 10;

    let mut n: u64;
    if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        n = x * 10 + d;
    } else {
        n = x + 1;
    }

    for _ in 0..e {
        n *= 10;
    }
    n
}

fn decompress_uncompressed_pubkey_from_x(x32: &[u8], y_is_odd: bool) -> Result<Vec<u8>, String> {
    if x32.len() != 32 {
        return Err(err("INVALID_PUBKEY", "x32 must be 32 bytes"));
    }

    let mut comp = [0u8; 33];
    comp[0] = if y_is_odd { 0x03 } else { 0x02 };
    comp[1..].copy_from_slice(x32);

    let pk = PublicKey::from_sec1_bytes(&comp)
        .map_err(|_| err("INVALID_PUBKEY", "failed to decompress pubkey from x"))?;

    let enc = pk.to_encoded_point(false);
    let bytes = enc.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(err("INVALID_PUBKEY", "unexpected uncompressed encoding"));
    }

    Ok(bytes.to_vec())
}

fn read_compressed_script(c: &mut parser::Cursor) -> Result<Vec<u8>, String> {
    // ScriptCompressor uses Bitcoin Core base-128 VarInt (not CompactSize).
    let nsize = read_varint_core(c)?;

    match nsize {
        0 => {
            let h160 = c.take(20)?;
            let mut spk = Vec::with_capacity(25);
            spk.extend_from_slice(&[0x76, 0xa9, 0x14]);
            spk.extend_from_slice(h160);
            spk.extend_from_slice(&[0x88, 0xac]);
            Ok(spk)
        }
        1 => {
            let h160 = c.take(20)?;
            let mut spk = Vec::with_capacity(23);
            spk.extend_from_slice(&[0xa9, 0x14]);
            spk.extend_from_slice(h160);
            spk.push(0x87);
            Ok(spk)
        }
        2 | 3 => {
            let x = c.take(32)?;
            let prefix = if nsize == 2 { 0x02 } else { 0x03 };
            let mut pubkey = Vec::with_capacity(33);
            pubkey.push(prefix);
            pubkey.extend_from_slice(x);

            let mut spk = Vec::with_capacity(35);
            spk.push(0x21);
            spk.extend_from_slice(&pubkey);
            spk.push(0xac);
            Ok(spk)
        }
        4 | 5 => {
            let x = c.take(32)?;
            let y_is_odd = nsize == 5;
            let pubkey65 = decompress_uncompressed_pubkey_from_x(x, y_is_odd)?;

            let mut spk = Vec::with_capacity(67);
            spk.push(0x41);
            spk.extend_from_slice(&pubkey65);
            spk.push(0xac);
            Ok(spk)
        }
        _ => {
            if nsize < 6 {
                return Err(err("INVALID_SCRIPT_COMPRESSION", "nsize < 6 unexpected"));
            }

            let raw_len_u64 = nsize - 6;
            ensure_len("undo", "compressed_script_raw_len", raw_len_u64, 100_000)?;

            let raw_len: usize = usize::try_from(raw_len_u64)
                .map_err(|_| err("LEN_OVERFLOW", format!("raw_len too large for usize: {raw_len_u64}")))?;

            Ok(c.take(raw_len)?.to_vec())
        }
    }
}

fn read_one_inundo(rc: &mut parser::Cursor) -> Result<(u64, Vec<u8>), String> {
    let ncode = read_varint_core(rc)?;
    let height = ncode >> 1;

    if height > 0 {
        let _tx_version = read_varint_core(rc)?;
    }

    let comp_amt = read_varint_core(rc)?;
    let spk = read_compressed_script(rc)?;
    let value_sats = decompress_amount(comp_amt);

    if spk.len() > 100_000 {
        return Err(err("INSANE_LEN", format!("spk too large: {}", spk.len())));
    }

    Ok((value_sats, spk))
}

fn read_undo_for_block_from_cursor(
    rc: &mut parser::Cursor,
    vin_counts_non_cb: &[u64],
) -> Result<UndoPrevouts, String> {
    // CBlockUndo: CompactSize(nTxUndo)
    // Usually tx_count - 1, but some fixtures include an extra empty CTxUndo for coinbase.
    let n_txundo = read_compactsize(rc)?;
    ensure_len("undo", "n_txundo", n_txundo, 200_000)?;

    let expected = vin_counts_non_cb.len() as u64;

    let mut has_cb_undo = false;
    if n_txundo == expected {
        // ok
    } else if n_txundo == expected.saturating_add(1) {
        has_cb_undo = true;
    } else {
        return Err(err(
            "UNDO_MISMATCH",
            format!(
                "undo txundo count mismatch: undo={}, expected={} (or {} if coinbase included)",
                n_txundo,
                expected,
                expected.saturating_add(1)
            ),
        ));
    }

    if has_cb_undo {
        let cb_vin_n = read_compactsize(rc)?;
        if cb_vin_n != 0 {
            return Err(err(
                "UNDO_MISMATCH",
                format!("coinbase undo present but vin_n != 0: got={cb_vin_n}"),
            ));
        }
    }

    let mut all: UndoPrevouts = Vec::with_capacity(vin_counts_non_cb.len());

    for (txundo_idx, &vin_expected) in vin_counts_non_cb.iter().enumerate() {
        let vin_n = read_compactsize(rc)?;
        ensure_len("undo", "vin_count", vin_n, 100_000)?;

        if vin_n != vin_expected {
            return Err(err(
                "UNDO_MISMATCH",
                format!(
                    "undo vin count mismatch: txundo_idx={} undo={} expected={}",
                    txundo_idx, vin_n, vin_expected
                ),
            ));
        }

        let mut ins = Vec::with_capacity(vin_n as usize);
        for _ in 0..(vin_n as usize) {
            ins.push(read_one_inundo(rc)?);
        }
        all.push(ins);
    }

    Ok(all)
}

pub(crate) fn parse_undo_payload_strict(undo_payload: &[u8], vin_counts_non_cb: &[u64]) -> Result<UndoPrevouts, String> {
    let mut uc = parser::Cursor::new(undo_payload);
    let v = read_undo_for_block_from_cursor(&mut uc, vin_counts_non_cb)?;
    if uc.remaining() != 0 {
        return Err(err(
            "UNDO_TRAILING_BYTES",
            format!("undo payload has {} trailing bytes", uc.remaining()),
        ));
    }
    Ok(v)
}

pub(crate) fn extract_vin_count(raw_tx: &[u8]) -> Result<u64, String> {
    let mut c = parser::Cursor::new(raw_tx);
    let _ver = c.take_u32_le()?;

    let p = c.take_u8()?;
    if p == 0x00 {
        let _f = c.take_u8()?;
    } else {
        c.i -= 1;
    }

    parser::read_varint(&mut c)
}

pub(crate) fn extract_vin_count_from_slice(raw_tx: &[u8]) -> Result<u64, String> {
    extract_vin_count(raw_tx)
}

pub(crate) fn validate_undo_payload_against_block(block: &[u8], undo_payload: &[u8]) -> Result<(), String> {
    let mut bc = parser::Cursor::new(block);

    if bc.remaining() < 80 {
        return Err(err("INVALID_BLOCK", "block payload too small for header"));
    }
    let _header = bc.take(80)?;

    let tx_count = parser::read_varint(&mut bc)?;
    if tx_count == 0 {
        return Err(err("INVALID_BLOCK", "block has zero transactions"));
    }

    let mut raw_txs: Vec<Vec<u8>> = Vec::with_capacity(tx_count as usize);
    for _ in 0..tx_count {
        let (raw, _txid_le) = parser::parse_tx_raw_and_txid_le(block, &mut bc)?;
        raw_txs.push(raw);
    }

    let mut vin_counts_non_cb: Vec<u64> = Vec::with_capacity(raw_txs.len().saturating_sub(1));
    for raw in raw_txs.iter().skip(1) {
        vin_counts_non_cb.push(extract_vin_count(raw)?);
    }

    let _ = parse_undo_payload_strict(undo_payload, &vin_counts_non_cb)?;
    Ok(())
}
