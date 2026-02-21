// src/bin/chainlens_web.rs

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

#[derive(Debug, Deserialize)]
struct FixturePrevout {
    txid: String,
    vout: u32,
    value_sats: u64,
    script_pubkey_hex: String,
}

#[derive(Debug, Deserialize)]
struct TxFixture {
    network: String,
    raw_tx: String,
    prevouts: Vec<FixturePrevout>,
}

#[derive(Debug, Serialize)]
struct ApiError {
    ok: bool,
    error: ApiErrorInner,
}

#[derive(Debug, Serialize)]
struct ApiErrorInner {
    code: String,
    message: String,
}

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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let state = Arc::new(());

    let app = Router::new()
        .route("/", get(index))
        .route("/api/health", get(health))
        .route("/api/analyze", post(analyze_tx_fixture))
        .route("/api/analyze/block", post(analyze_block_upload))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    // Bind to 0.0.0.0 for container/test compatibility
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    // Spec: print exactly one line containing the URL
    println!("http://{}:{}", "127.0.0.1", port);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind failed");
    axum::serve(listener, app).await.expect("server failed");
}

async fn health() -> impl IntoResponse {
    Json(json!({ "ok": true }))
}

async fn index() -> impl IntoResponse {
    Html("Chain Lens Web API running. Use /api/health or POST /api/analyze.")
}

async fn analyze_tx_fixture(
    State(_state): State<Arc<()>>,
    Json(fx): Json<TxFixture>,
) -> impl IntoResponse {
    if fx.network.trim().is_empty() {
        return api_err("INVALID_FIXTURE", "network must be non-empty").into_response();
    }
    if fx.raw_tx.trim().is_empty() {
        return api_err("INVALID_FIXTURE", "raw_tx must be non-empty").into_response();
    }

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

async fn analyze_block_upload(
    State(_state): State<Arc<()>>,
    mut mp: Multipart,
) -> impl IntoResponse {
    let dir = match tempdir() {
        Ok(d) => d,
        Err(e) => return api_500("TEMP_DIR_FAILED", e.to_string()).into_response(),
    };

    let mut blk_path: Option<std::path::PathBuf> = None;
    let mut rev_path: Option<std::path::PathBuf> = None;
    let mut xor_path: Option<std::path::PathBuf> = None;

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

    match analyze_block_file(
        blk.to_string_lossy().as_ref(),
        rev.to_string_lossy().as_ref(),
        xor.to_string_lossy().as_ref(),
    ) {
        Ok(reports) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            Json(serde_json::to_value(reports).unwrap()),
        )
            .into_response(),
        Err(e) => api_err("ANALYZE_BLOCK_FAILED", e).into_response(),
    }
}
