//! HTTP surface.  Route order is load-bearing: static files are served before
//! asset resolution, and asset resolution is the fallback for everything else.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use axum::body::Body;
use axum::extract::{ws::WebSocketUpgrade, Path, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_MODIFIED_SINCE, LAST_MODIFIED};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::Client;
use crate::config::Config;
use crate::encoding::latin1_decode;
use crate::http::{self, Cors};
use crate::util::{base64_encode, extension_of, safe_join};
use crate::{debug, warn};

const STATUS_PAGE: &str = include_str!("status.html");
const MAX_BATCH_FILES: usize = 50;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub client: Arc<Client>,
    pub cors: Arc<Cors>,
    pub health: Arc<Value>,
}

pub fn router(state: AppState) -> Router {
    let enable_wsproxy = state.cfg.enable_wsproxy;

    let mut router = Router::new()
        .route("/api/health", get(health))
        .route("/api/cache-stats", get(cache_stats))
        .route("/api/missing-files", get(missing_files))
        .route("/list-files", get(list_files))
        .route("/search", post(search))
        // roBrowser's `FileManager.search` posts to the remote-client base URL
        // rather than to /search, so the root has to answer it too.  The
        // reference has no POST route at all, so nothing depends on the 404
        // this replaces.  GET keeps going to the same handler as everything
        // else, since registering the path at all takes it out of the fallback.
        .route("/", post(search).get(serve_path))
        .route("/batch", post(batch));

    if enable_wsproxy {
        router = router.route("/ws/{*target}", get(ws_upgrade));
    }

    router
        .fallback(serve_path)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            cors_middleware,
        ))
        .with_state(state)
}

async fn cors_middleware(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let origin = Cors::origin_of(request.headers());

    if request.method() == Method::OPTIONS {
        return state.cors.preflight(origin.as_deref());
    }

    let mut response = next.run(request).await;
    state.cors.apply(origin.as_deref(), &mut response);
    response
}

// ---------------------------------------------------------------------------
// JSON endpoints
// ---------------------------------------------------------------------------

fn json_response(
    headers: &HeaderMap,
    state: &AppState,
    value: &Value,
    cache_control: &str,
) -> Response {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .header(CACHE_CONTROL, cache_control)
        .body(Body::empty())
        .unwrap();
    http::maybe_compress(headers, response, body, state.cfg.enable_compression)
}

/// Startup validation merged with live counters.  Answers immediately, before
/// any asset is warm — it is a readiness probe, not a smoke test.
async fn health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let mut value = (*state.health).clone();
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "missingFiles".into(),
            serde_json::to_value(state.client.missing_summary()).unwrap_or(Value::Null),
        );
        object.insert(
            "cache".into(),
            serde_json::to_value(state.client.cache_stats()).unwrap_or(Value::Null),
        );
        object.insert(
            "index".into(),
            serde_json::to_value(state.client.index_stats()).unwrap_or(Value::Null),
        );
        object.insert("esrgan".into(), json!({ "enabled": false }));
    }
    json_response(&headers, &state, &value, "no-store")
}

async fn cache_stats(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let value = json!({
        "cache": state.client.cache_stats(),
        "index": state.client.index_stats(),
    });
    json_response(&headers, &state, &value, "no-store")
}

async fn missing_files(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let value = serde_json::to_value(state.client.missing_summary()).unwrap_or(Value::Null);
    json_response(&headers, &state, &value, "no-store")
}

async fn list_files(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let value = Value::Array(
        state
            .client
            .list_files()
            .into_iter()
            .map(|name| Value::String(name.to_string()))
            .collect(),
    );
    json_response(&headers, &state, &value, "public, max-age=300")
}

#[derive(Deserialize)]
struct SearchBody {
    filter: Option<String>,
}

/// Percent-and-plus decoding for one `application/x-www-form-urlencoded` value.
fn form_decode(value: &str) -> String {
    let plus_expanded = value.replace('+', " ");
    let decoded: Vec<u8> = percent_encoding::percent_decode_str(&plus_expanded).collect();
    String::from_utf8_lossy(&decoded).into_owned()
}

/// Pull `filter` out of a body that may be JSON or a form.
///
/// The client sends `filter=<regex>` as `application/x-www-form-urlencoded`;
/// the reference server happens to accept both because Express installs the
/// JSON and urlencoded parsers side by side, so both must work here.
fn search_filter(headers: &HeaderMap, body: &[u8]) -> Option<String> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.starts_with("application/x-www-form-urlencoded") {
        for pair in std::str::from_utf8(body).ok()?.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                if key == "filter" {
                    return Some(form_decode(value));
                }
            }
        }
        return None;
    }

    serde_json::from_slice::<SearchBody>(body).ok()?.filter
}

async fn search(State(state): State<AppState>, headers: HeaderMap, body: bytes::Bytes) -> Response {
    let filter = search_filter(&headers, &body).unwrap_or_default();

    if !state.cfg.client_enablesearch || filter.is_empty() {
        return http::text(
            StatusCode::BAD_REQUEST,
            "Search feature is disabled or invalid filter",
        );
    }

    // Case-insensitive, like `new RegExp(filter, 'i')`.
    let Ok(regex) = regex_lite::RegexBuilder::new(&filter)
        .case_insensitive(true)
        .build()
    else {
        return http::text(StatusCode::BAD_REQUEST, "Invalid filter expression");
    };

    let matches = state.client.search(&regex);
    let body = matches.join("\n").into_bytes();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::empty())
        .unwrap();
    http::maybe_compress(&headers, response, body, state.cfg.enable_compression)
}

#[derive(Deserialize)]
struct BatchBody {
    files: Option<Vec<String>>,
}

/// Fetch several assets in one round trip.  Failures are omitted from the
/// result rather than failing the batch — the client treats a missing key as a
/// miss and moves on.
async fn batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<axum::Json<BatchBody>>,
) -> Response {
    let files = body.and_then(|axum::Json(b)| b.files).unwrap_or_default();

    if files.is_empty() || files.len() > MAX_BATCH_FILES {
        let body = json!({ "error": "Invalid files array (1-50 files)" });
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
    }

    let mut results: BTreeMap<String, String> = BTreeMap::new();
    for path in files {
        if let Some(file) = state.client.get_file(&path).await {
            results.insert(path, base64_encode(&file.data));
        }
    }

    let body = serde_json::to_vec(&results).unwrap_or_else(|_| b"{}".to_vec());
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Body::empty())
        .unwrap();
    http::maybe_compress(&headers, response, body, state.cfg.enable_compression)
}

// ---------------------------------------------------------------------------
// WebSocket proxy
// ---------------------------------------------------------------------------

async fn ws_upgrade(
    State(state): State<AppState>,
    Path(target): Path<String>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let allowed = Arc::new(state.cfg.ws_allowed_targets.clone());
    upgrade.on_upgrade(move |socket| crate::wsproxy::proxy(socket, target, allowed))
}

// ---------------------------------------------------------------------------
// Static files and assets
// ---------------------------------------------------------------------------

/// Turn a request target into the path the client meant.
///
/// roBrowser percent-encodes its mojibake paths as UTF-8, so the usual decode
/// is right; a client that sends the raw CP949 bytes instead is decoded as
/// Latin-1, which lands on the same string.
fn decode_request_path(raw: &str) -> String {
    let bytes: Vec<u8> = percent_encoding::percent_decode_str(raw).collect();
    match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(_) => latin1_decode(&bytes),
    }
}

async fn serve_path(State(state): State<AppState>, request: Request) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return http::text(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed");
    }

    let raw_path = request.uri().path().to_string();
    let headers = request.headers().clone();
    let is_head = request.method() == Method::HEAD;
    let relative = decode_request_path(raw_path.trim_start_matches('/'));

    // 1. The built client, when this server is also serving it.
    if state.cfg.enable_static_serve {
        if let Some(response) = serve_static(&state, &headers, &relative).await {
            return finish(response, is_head);
        }
    }

    // 2. The project's own landing page at the root.
    if relative.is_empty() {
        return finish(serve_root(&state, &headers).await, is_head);
    }

    // 3. Assets: local files, the override directory, then the archives.
    match state.client.get_file(&relative).await {
        Some(file) => {
            let response = http::asset_response(
                &headers,
                &relative,
                &file.data,
                Some(&file.etag),
                state.cfg.enable_compression,
            );
            finish(response, is_head)
        }
        None => {
            debug!("404 {relative}");
            finish(http::not_found(), is_head)
        }
    }
}

/// A HEAD response carries the headers of the GET and none of the body.
fn finish(mut response: Response, is_head: bool) -> Response {
    if is_head {
        *response.body_mut() = Body::empty();
    }
    response
}

async fn serve_root(state: &AppState, headers: &HeaderMap) -> Response {
    let index = state.cfg.root.join("index.html");
    if index.is_file() {
        if let Ok(content) = tokio::fs::read(&index).await {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/html; charset=utf-8")
                .header(
                    CACHE_CONTROL,
                    format!("public, max-age={}", http::INDEX_MAX_AGE),
                )
                .body(Body::empty())
                .unwrap();
            return http::maybe_compress(headers, response, content, state.cfg.enable_compression);
        }
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header(
            CACHE_CONTROL,
            format!("public, max-age={}", http::INDEX_MAX_AGE),
        )
        .body(Body::empty())
        .unwrap();
    http::maybe_compress(
        headers,
        response,
        STATUS_PAGE.as_bytes().to_vec(),
        state.cfg.enable_compression,
    )
}

/// Serve a file out of `ROBROWSER_PATH`.  Returns `None` when there is nothing
/// there, so the request can fall through to asset resolution.
async fn serve_static(state: &AppState, headers: &HeaderMap, relative: &str) -> Option<Response> {
    let base = &state.cfg.robrowser_path;
    let candidate = safe_join(base, relative)?;

    let metadata = tokio::fs::metadata(&candidate).await.ok()?;
    let (path, metadata) = if metadata.is_dir() {
        let index = candidate.join("index.html");
        let index_meta = tokio::fs::metadata(&index).await.ok()?;
        (index, index_meta)
    } else {
        (candidate, metadata)
    };

    // Weak validator built from size and mtime, the same shape `express.static`
    // sends, so an existing browser cache stays valid across the swap.
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let etag = weak_etag(metadata.len(), modified);
    let last_modified = httpdate::fmt_http_date(modified);

    if etag_matches_weak(headers, &etag) || not_modified_since(headers, modified) {
        return Some(
            Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(ETAG, &etag)
                .header(LAST_MODIFIED, &last_modified)
                .header(CACHE_CONTROL, "public, max-age=0")
                .body(Body::empty())
                .unwrap(),
        );
    }

    let content = match tokio::fs::read(&path).await {
        Ok(content) => content,
        Err(e) => {
            warn!("Static read failed for {}: {e}", path.display());
            return None;
        }
    };

    let ext = extension_of(&path.to_string_lossy());
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, http::content_type_for(&ext))
        .header(ETAG, &etag)
        .header(LAST_MODIFIED, &last_modified)
        .header(CACHE_CONTROL, "public, max-age=0")
        .body(Body::empty())
        .unwrap();

    Some(http::maybe_compress(
        headers,
        response,
        content,
        state.cfg.enable_compression,
    ))
}

fn weak_etag(len: u64, modified: SystemTime) -> String {
    let millis = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("W/\"{len:x}-{millis:x}\"")
}

fn etag_matches_weak(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|c| c.trim() == etag || c.trim() == "*"))
        .unwrap_or(false)
}

fn not_modified_since(headers: &HeaderMap, modified: SystemTime) -> bool {
    let Some(value) = headers.get(IF_MODIFIED_SINCE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Ok(since) = httpdate::parse_http_date(value) else {
        return false;
    };
    // HTTP dates have one-second resolution; anything finer would produce
    // spurious 200s on every reload.
    let truncate = |t: SystemTime| {
        t.duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };
    truncate(modified) <= truncate(since)
}
