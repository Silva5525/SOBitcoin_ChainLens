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

use axum::{ // Import core Axum web framework types
    extract::{Multipart, State}, // Extractors for multipart uploads and shared state
    http::{header, StatusCode}, // HTTP header constants + status codes
    response::{Html, IntoResponse}, // Response helpers (HTML + trait for converting into responses)
    routing::{get, post}, // HTTP method routing helpers
    Json, Router, // JSON wrapper + router builder
};
use serde::{Deserialize, Serialize}; // Derive traits for JSON (de)serialization
use serde_json::json; // Helper macro for building small JSON values inline
use std::{net::SocketAddr, sync::Arc}; // Socket address type + atomic reference counting pointer
use tempfile::tempdir; // Temporary directory helper (auto-cleanup on drop)
use tower_http::trace::TraceLayer; // HTTP tracing middleware for logging requests
use tracing_subscriber::EnvFilter; // Environment-based log filtering

use chainlens::btc::block::analyze_block_file; // Import block analyzer entrypoint
use chainlens::btc::tx::{analyze_tx, Prevout}; // Import tx analyzer + Prevout struct

/// One input UTXO referenced by the transaction under analysis.
///
/// This matches the challenge "fixture" JSON schema.
#[derive(Debug, Deserialize)] // Allow JSON → struct parsing + debug printing
struct FixturePrevout { // Represents one prevout entry in incoming JSON
    /// Previous transaction id (hex, display form).
    txid: String, // Big-endian display txid hex
    /// Output index within the previous transaction.
    vout: u32, // Output index number
    /// Amount of the previous output in satoshis.
    value_sats: u64, // Value in satoshis
    /// Previous output scriptPubKey as hex.
    script_pubkey_hex: String, // scriptPubKey encoded as hex string
}

/// Request payload for `/api/analyze`.
#[derive(Debug, Deserialize)] // Allow JSON body → struct
struct TxFixture { // Represents full transaction fixture payload
    /// Network name: e.g. "mainnet", "testnet", "signet", "regtest".
    network: String, // Network label string
    /// Raw transaction bytes as hex.
    raw_tx: String, // Serialized transaction in hex
    /// Prevouts for each input (in the same order as inputs in `raw_tx`).
    prevouts: Vec<FixturePrevout>, // List of prevout descriptions
}

/// Standard API error envelope.
///
/// We keep this shape stable so the frontend can render errors consistently.
#[derive(Debug, Serialize)] // Allow struct → JSON
struct ApiError { // Top-level error response object
    ok: bool, // Always false for error responses
    error: ApiErrorInner, // Nested error details
}

/// Error payload containing a machine-readable code and human message.
#[derive(Debug, Serialize)] // Serializable to JSON
struct ApiErrorInner { // Detailed error information
    code: String, // Stable error code identifier
    message: String, // Human-readable explanation
}

/// Build a client error (HTTP 400) in the standard envelope.
fn api_err(code: &str, message: impl Into<String>) -> (StatusCode, Json<ApiError>) { // Returns HTTP 400 + JSON body
    (
        StatusCode::BAD_REQUEST, // HTTP 400 status
        Json(ApiError { // Wrap ApiError inside Json extractor
            ok: false, // Mark failure
            error: ApiErrorInner {
                code: code.to_string(), // Copy code into owned String
                message: message.into(), // Convert message into String
            },
        }),
    )
}

/// Build a server error (HTTP 500) in the standard envelope.
fn api_500(code: &str, message: impl Into<String>) -> (StatusCode, Json<ApiError>) { // Returns HTTP 500 + JSON body
    (
        StatusCode::INTERNAL_SERVER_ERROR, // HTTP 500 status
        Json(ApiError {
            ok: false, // Mark failure
            error: ApiErrorInner {
                code: code.to_string(), // Copy code
                message: message.into(), // Convert message
            },
        }),
    )
}

#[tokio::main] // Start Tokio async runtime automatically
async fn main() { // Async main function (required for async server)
    // Default logging is "info" unless overridden by RUST_LOG.
    tracing_subscriber::fmt() // Initialize default tracing subscriber
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap())) // Set default level to info
        .init(); // Activate logging

    // Placeholder for future shared state.
    // Keeping it as Arc makes handler signatures stable if we add config/caches later.
    let state = Arc::new(()); // Currently empty shared state wrapped in Arc

    let app = Router::new() // Create new Axum router
        .route("/", get(index)) // GET / → index handler
        .route("/api/health", get(health)) // GET health endpoint
        .route("/api/analyze", post(analyze_tx_fixture)) // POST tx analysis endpoint
        .route("/api/analyze/block", post(analyze_block_upload)) // POST block analysis endpoint
        .layer(TraceLayer::new_for_http()) // Add HTTP tracing middleware
        .with_state(state); // Attach shared state

    // Grader/runtime convention: bind to PORT if provided.
    let port: u16 = std::env::var("PORT") // Try read PORT env variable
        .ok() // Convert Result → Option
        .and_then(|s| s.parse().ok()) // Parse string into u16
        .unwrap_or(3000); // Default to 3000 if not set

    // Bind to 0.0.0.0 for container/test compatibility.
    let addr = SocketAddr::from(([0, 0, 0, 0], port)); // Build socket address

    // Spec: print exactly one line containing the URL.
    println!("http://{}:{}", "127.0.0.1", port); // Print local URL for graders

    let listener = tokio::net::TcpListener::bind(addr) // Bind TCP listener
        .await // Await async bind
        .expect("bind failed"); // Panic if bind fails
    axum::serve(listener, app) // Start HTTP server
        .await // Await server future
        .expect("server failed"); // Panic if server crashes
}

/// Health probe endpoint.
async fn health() -> impl IntoResponse { // Returns JSON response
    Json(json!({ "ok": true })) // Simple { "ok": true }
}

/// Serves the single-page visualizer UI.
///
/// Path is relative to this file: `src/bin/chainlens_web.rs`.
/// The UI lives at `src/btc/web/static/index.html`.
const INDEX_HTML: &str = include_str!("../btc/web/static/index.html"); // Embed static HTML at compile time

/// Render the UI root page.
async fn index() -> impl IntoResponse { // Return HTML response
    // `Html` sets content-type to text/html; charset=utf-8.
    Html(INDEX_HTML) // Return embedded HTML page
}

/// Analyze a single transaction fixture (JSON) and return an analysis report.
///
/// Endpoint: POST `/api/analyze`
async fn analyze_tx_fixture(
    State(_state): State<Arc<()>>, // Extract shared state (unused for now)
    Json(fx): Json<TxFixture>, // Extract JSON body into TxFixture
) -> impl IntoResponse {
    // Minimal validation to fail fast on empty payloads.
    if fx.network.trim().is_empty() { // Ensure network is not blank
        return api_err("INVALID_FIXTURE", "network must be non-empty").into_response(); // Return 400
    }
    if fx.raw_tx.trim().is_empty() { // Ensure raw_tx not blank
        return api_err("INVALID_FIXTURE", "raw_tx must be non-empty").into_response(); // Return 400
    }

    // Convert fixture prevouts into the internal analyzer input format.
    let prevouts: Vec<Prevout> = fx
        .prevouts // Take prevouts vector
        .into_iter() // Consume it
        .map(|p| Prevout { // Convert each FixturePrevout → Prevout
            txid_hex: p.txid,
            vout: p.vout,
            value_sats: p.value_sats,
            script_pubkey_hex: p.script_pubkey_hex,
        })
        .collect(); // Collect into Vec

    match analyze_tx(&fx.network, &fx.raw_tx, &prevouts) { // Call core tx analyzer
        Ok(report) => ( // On success
            StatusCode::OK, // HTTP 200
            Json(serde_json::to_value(report).unwrap()), // Serialize report into JSON value
        )
            .into_response(), // Convert tuple into HTTP response
        Err(e) => api_err("ANALYZE_TX_FAILED", e).into_response(), // Return structured 400 error
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
    State(_state): State<Arc<()>>, // Extract shared state
    mut mp: Multipart, // Extract multipart form data
) -> impl IntoResponse {
    // Use a temp directory so files are cleaned up automatically.
    let dir = match tempdir() { // Create temp directory
        Ok(d) => d, // Success
        Err(e) => return api_500("TEMP_DIR_FAILED", e.to_string()).into_response(), // 500 on failure
    };

    let mut blk_path: Option<std::path::PathBuf> = None; // Path for blk file
    let mut rev_path: Option<std::path::PathBuf> = None; // Path for rev file
    let mut xor_path: Option<std::path::PathBuf> = None; // Path for xor file

    // Read all multipart fields, write recognized ones to disk.
    loop { // Loop over multipart fields
        match mp.next_field().await { // Fetch next field
            Ok(Some(field)) => { // If a field exists
                let name = field.name().unwrap_or("").to_string(); // Get field name

                let data = match field.bytes().await { // Read field bytes
                    Ok(b) => b, // Success
                    Err(e) => {
                        return api_err("MULTIPART_READ_FAILED", e.to_string()) // 400 on read error
                            .into_response()
                    }
                };

                // Ignore unknown field names to allow future extensibility.
                let path = match name.as_str() { // Decide filename by field name
                    "blk" => dir.path().join("blk.dat"),
                    "rev" => dir.path().join("rev.dat"),
                    "xor" => dir.path().join("xor.dat"),
                    _ => continue, // Skip unknown fields
                };

                if let Err(e) = std::fs::write(&path, &data) { // Write file to temp dir
                    return api_500("FILE_WRITE_FAILED", e.to_string()).into_response(); // 500 if write fails
                }

                match name.as_str() { // Store resulting path
                    "blk" => blk_path = Some(path),
                    "rev" => rev_path = Some(path),
                    "xor" => xor_path = Some(path),
                    _ => {}
                }
            }
            Ok(None) => break, // No more fields → exit loop
            Err(e) => {
                return api_err("MULTIPART_FAILED", e.to_string()).into_response(); // 400 on multipart parsing error
            }
        }
    }

    // Ensure all required fields are present.
    let blk = match blk_path { // Validate blk provided
        Some(p) => p,
        None => return api_err("MISSING_FIELD", "missing multipart field: blk").into_response(),
    };
    let rev = match rev_path { // Validate rev provided
        Some(p) => p,
        None => return api_err("MISSING_FIELD", "missing multipart field: rev").into_response(),
    };
    let xor = match xor_path { // Validate xor provided
        Some(p) => p,
        None => return api_err("MISSING_FIELD", "missing multipart field: xor").into_response(),
    };

    // Hand off to the block analyzer.
    // We pass file paths as &str to match the analyzer signature.
    match analyze_block_file(
        blk.to_string_lossy().as_ref(), // Convert PathBuf → &str
        rev.to_string_lossy().as_ref(),
        xor.to_string_lossy().as_ref(),
    ) {
        Ok(reports) => ( // On success
            StatusCode::OK, // HTTP 200
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")], // Explicit content-type header
            Json(serde_json::to_value(reports).unwrap()), // Serialize reports into JSON value
        )
            .into_response(), // Convert into response
        Err(e) => api_err("ANALYZE_BLOCK_FAILED", e).into_response(), // Return structured 400 error
    }
}
