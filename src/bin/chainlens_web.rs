// src/bin/chainlens_web.rs
//
// Web server entry point for Chainlens.
//
// Provides:
//   - a static single-page UI (index.html),
//   - JSON APIs for transaction analysis and block-file analysis.
//
// The heavy parsing/analysis logic is implemented in `chainlens::btc::*`.
// This binary focuses on HTTP I/O, input validation, and stable error shapes.

use axum::{
    extract::{Multipart, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};
use tempfile::tempdir;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use chainlens::btc::block::analyze_block_file;
use chainlens::btc::tx::{analyze_tx, Prevout};

/// One input UTXO referenced by the transaction under analysis.
///
/// This matches the challenge "fixture" JSON schema.
#[derive(Debug, Deserialize)]
struct FixturePrevout {
    /// Previous transaction id (hex, display form).
    txid: String,
    /// Output index within the previous transaction.
    vout: u32,
    /// Amount of the previous output in satoshis.
    value_sats: u64,
    /// Previous output scriptPubKey as hex.
    script_pubkey_hex: String,
}

/// Request payload for `/api/analyze`.
#[derive(Debug, Deserialize)]
struct TxFixture {
    /// Network name: e.g. "mainnet", "testnet", "signet", "regtest".
    network: String,
    /// Raw transaction bytes as hex.
    raw_tx: String,
    /// Prevouts for each input (in the same order as inputs in `raw_tx`).
    prevouts: Vec<FixturePrevout>,
}

/// Standard API error envelope.
///
/// We keep this shape stable so the frontend can render errors consistently.
#[derive(Debug, Serialize)]
struct ApiError {
    ok: bool,
    error: ApiErrorInner,
}

/// Error payload containing a machine-readable code and human message.
#[derive(Debug, Serialize)]
struct ApiErrorInner {
    code: String,
    message: String,
}

/// Build a client error (HTTP 400) in the standard envelope.
fn api_err(code: &str, message: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiError {
            ok: false,
            error: ApiErrorInner {
                code: code.to_string(),
                message: message.into(),
            },
        }),
    )
}

/// Build a server error (HTTP 500) in the standard envelope.
fn api_500(code: &str, message: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            ok: false,
            error: ApiErrorInner {
                code: code.to_string(),
                message: message.into(),
            },
        }),
    )
}

#[tokio::main]
async fn main() {
    // Default logging is "info" unless overridden by RUST_LOG.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    // Placeholder for future shared state.
    // Keeping it as Arc makes handler signatures stable if we add config/caches later.
    let state = Arc::new(());

    let app = Router::new()
        .route("/", get(index))
        .route("/api/health", get(health))
        .route("/api/analyze", post(analyze_tx_fixture))
        .route("/api/analyze/block", post(analyze_block_upload))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Grader/runtime convention: bind to PORT if provided.
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    // Bind to 0.0.0.0 for container/test compatibility.
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    // Spec: print exactly one line containing the URL.
    println!("http://{}:{}", "127.0.0.1", port);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind failed");
    axum::serve(listener, app).await.expect("server failed");
}

/// Health probe endpoint.
async fn health() -> impl IntoResponse {
    Json(json!({ "ok": true }))
}

/// Serves the single-page visualizer UI.
///
/// Path is relative to this file: `src/bin/chainlens_web.rs`.
/// The UI lives at `src/btc/web/static/index.html`.
const INDEX_HTML: &str = include_str!("../btc/web/static/index.html");

/// Render the UI root page.
async fn index() -> impl IntoResponse {
    // `Html` sets content-type to text/html; charset=utf-8.
    Html(INDEX_HTML)
}

/// Analyze a single transaction fixture (JSON) and return an analysis report.
///
/// Endpoint: POST `/api/analyze`
async fn analyze_tx_fixture(
    State(_state): State<Arc<()>>,
    Json(fx): Json<TxFixture>,
) -> impl IntoResponse {
    // Minimal validation to fail fast on empty payloads.
    if fx.network.trim().is_empty() {
        return api_err("INVALID_FIXTURE", "network must be non-empty").into_response();
    }
    if fx.raw_tx.trim().is_empty() {
        return api_err("INVALID_FIXTURE", "raw_tx must be non-empty").into_response();
    }

    // Convert fixture prevouts into the internal analyzer input format.
    let prevouts: Vec<Prevout> = fx
        .prevouts
        .into_iter()
        .map(|p| Prevout {
            txid_hex: p.txid,
            vout: p.vout,
            value_sats: p.value_sats,
            script_pubkey_hex: p.script_pubkey_hex,
        })
        .collect();

    match analyze_tx(&fx.network, &fx.raw_tx, &prevouts) {
        Ok(report) => (
            StatusCode::OK,
            Json(serde_json::to_value(report).unwrap()),
        )
            .into_response(),
        Err(e) => api_err("ANALYZE_TX_FAILED", e).into_response(),
    }
}

/// Analyze uploaded `blk.dat`, `rev.dat`, and `xor.dat` files.
///
/// Endpoint: POST `/api/analyze/block`
///
/// Expects multipart fields:
///   - "blk": blk*.dat contents
///   - "rev": rev*.dat contents
///   - "xor": xor.dat contents
async fn analyze_block_upload(
    State(_state): State<Arc<()>>,
    mut mp: Multipart,
) -> impl IntoResponse {
    // Use a temp directory so files are cleaned up automatically.
    let dir = match tempdir() {
        Ok(d) => d,
        Err(e) => return api_500("TEMP_DIR_FAILED", e.to_string()).into_response(),
    };

    let mut blk_path: Option<std::path::PathBuf> = None;
    let mut rev_path: Option<std::path::PathBuf> = None;
    let mut xor_path: Option<std::path::PathBuf> = None;

    // Read all multipart fields, write recognized ones to disk.
    loop {
        match mp.next_field().await {
            Ok(Some(field)) => {
                let name = field.name().unwrap_or("").to_string();

                let data = match field.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        return api_err("MULTIPART_READ_FAILED", e.to_string())
                            .into_response()
                    }
                };

                // Ignore unknown field names to allow future extensibility.
                let path = match name.as_str() {
                    "blk" => dir.path().join("blk.dat"),
                    "rev" => dir.path().join("rev.dat"),
                    "xor" => dir.path().join("xor.dat"),
                    _ => continue,
                };

                if let Err(e) = std::fs::write(&path, &data) {
                    return api_500("FILE_WRITE_FAILED", e.to_string()).into_response();
                }

                match name.as_str() {
                    "blk" => blk_path = Some(path),
                    "rev" => rev_path = Some(path),
                    "xor" => xor_path = Some(path),
                    _ => {}
                }
            }
            Ok(None) => break,
            Err(e) => {
                return api_err("MULTIPART_FAILED", e.to_string()).into_response();
            }
        }
    }

    // Ensure all required fields are present.
    let blk = match blk_path {
        Some(p) => p,
        None => return api_err("MISSING_FIELD", "missing multipart field: blk").into_response(),
    };
    let rev = match rev_path {
        Some(p) => p,
        None => return api_err("MISSING_FIELD", "missing multipart field: rev").into_response(),
    };
    let xor = match xor_path {
        Some(p) => p,
        None => return api_err("MISSING_FIELD", "missing multipart field: xor").into_response(),
    };

    // Hand off to the block analyzer.
    // We pass file paths as &str to match the analyzer signature.
    match analyze_block_file(
        blk.to_string_lossy().as_ref(),
        rev.to_string_lossy().as_ref(),
        xor.to_string_lossy().as_ref(),
    ) {
        Ok(reports) => (
            StatusCode::OK,
            // Explicit content-type helps when proxies strip defaults.
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            Json(serde_json::to_value(reports).unwrap()),
        )
            .into_response(),
        Err(e) => api_err("ANALYZE_BLOCK_FAILED", e).into_response(),
    }
}
