//! HTTP surface.  Route order is load-bearing: static files are served before
//! asset resolution, and asset resolution is the fallback for everything else.

use std::collections::BTreeMap;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use axum::body::Body;
use axum::extract::{ws::WebSocketUpgrade, Path, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, ETAG, IF_MODIFIED_SINCE, LAST_MODIFIED, VARY,
};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::Client;
use crate::compact;
use crate::config::Config;
use crate::encoding::latin1_decode;
use crate::http::{self, Cors};
use crate::util::{base64_encode, extension_of, public_asset_path, safe_join};
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

    if let Some((prefix, _)) = state.cfg.app_proxy.clone() {
        router = router.route(
            &format!("{prefix}{{*rest}}"),
            axum::routing::any(crate::appproxy::forward),
        );
    }

    if state.cfg.web_server_proxy.is_some() {
        for path in crate::appproxy::WEB_SERVER_ROUTES {
            router = router.route(
                path,
                axum::routing::any(crate::appproxy::forward_web_server),
            );
        }
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

/// Public readiness reveals no local paths, controls or credentials. Detailed
/// counters remain in the diagnostic routes; process identity uses the private
/// authenticated control socket, never this unauthenticated HTTP endpoint.
async fn health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    json_response(
        &headers,
        &state,
        &json!({
            "status": "ok",
            "service": "robrowser-remoteclient",
            "version": env!("CARGO_PKG_VERSION"),
        }),
        "no-store",
    )
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

    if !public_asset_path(&relative) {
        return finish(http::not_found(), is_head);
    }

    // Generated host configuration lives with the asset generation, not in
    // the signed application payload (which may be on another volume).
    let generated = match relative.as_str() {
        "" | "index.html" => Some("index.html"),
        "Config.local.js" => Some("Config.local.js"),
        _ => None,
    };
    if let Some(name) = generated {
        if let Ok(bytes) = tokio::fs::read(state.cfg.root.join(name)).await {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, http::content_type_for(&extension_of(name)))
                .header(CACHE_CONTROL, "no-store")
                .body(Body::from(bytes))
                .unwrap();
            return finish(response, is_head);
        }
    }

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
            // A remote player's proxy asks for compact pictures (compact.rs).
            let quality = state.cfg.compact_image_quality;
            let compact = compact::wanted(&headers, &relative, file.data.len(), quality);
            if compact {
                let etag = compact::etag(&file.etag, quality);
                if http::etag_matches(&headers, &etag) {
                    return finish(http::not_modified(&etag), is_head);
                }
            }
            let coding = http::asset_coding(
                &headers,
                &relative,
                file.data.len(),
                state.cfg.enable_compression,
            );
            // A revalidation that will be answered 304 needs no body made.
            let revalidating = http::is_static_extension(&extension_of(&relative))
                && http::etag_matches(&headers, &file.etag);
            let encoded = match coding {
                Some(coding) if !revalidating => state
                    .client
                    .encoded(&relative, &file, coding)
                    .await
                    .map(|body| (coding, body)),
                _ => None,
            };
            if compact && !revalidating {
                if let Some(body) = state.client.compacted(&relative, &file, quality).await {
                    // Brotli can still win on a small, flat picture.
                    let sent = encoded.as_ref().map_or(file.data.len(), |(_, b)| b.len());
                    if body.len() < sent {
                        let etag = compact::etag(&file.etag, quality);
                        return finish(http::compact_response(&etag, &body), is_head);
                    }
                }
            }
            let response = http::asset_response(
                &headers,
                &relative,
                &file.data,
                Some(&file.etag),
                http::negotiates_coding(&relative, file.data.len(), state.cfg.enable_compression),
                encoded
                    .as_ref()
                    .map(|(coding, body)| (*coding, body.as_slice())),
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

/// Codings the client build may have precompressed a file into, best first,
/// with the extension of the sibling that holds each.
const PRECOMPRESSED: [(&str, &str); 2] = [("br", "br"), ("gzip", "gz")];

/// The precompressed siblings of `path` (`Online.js.br`, `Online.js.gz`) that
/// are regular files no older than it, in preference order.  A stale sibling
/// is a build that did not finish, and serving it would serve old code.
async fn fresh_siblings(
    path: &FsPath,
    modified: SystemTime,
) -> Vec<(PathBuf, &'static str, &'static str)> {
    // `/Online.js.br` asked for by name is just a file, not a representation.
    let ext = extension_of(&path.to_string_lossy());
    if PRECOMPRESSED.iter().any(|(_, sibling)| *sibling == ext) {
        return Vec::new();
    }

    let mut fresh = Vec::new();
    for (coding, sibling_ext) in PRECOMPRESSED {
        let mut sibling = path.as_os_str().to_owned();
        sibling.push(".");
        sibling.push(sibling_ext);
        let sibling = PathBuf::from(sibling);
        let Ok(meta) = tokio::fs::metadata(&sibling).await else {
            continue;
        };
        let sibling_modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        if meta.is_file() && sibling_modified >= modified {
            fresh.push((sibling, coding, sibling_ext));
        }
    }
    fresh
}

/// Serve a file out of `ROBROWSER_PATH`.  Returns `None` when there is nothing
/// there, so the request can fall through to asset resolution.
///
/// When the build left a fresh `.br` or `.gz` beside the file and the client
/// accepts that coding, its bytes go out as they are, instead of gzipping a
/// 13 MB `Online.js` at level 1 on every request.  Each representation has its
/// own ETag, so a conditional request revalidates the bytes it actually holds.
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

    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let siblings = if state.cfg.enable_compression {
        fresh_siblings(&path, modified).await
    } else {
        Vec::new()
    };
    // With a sibling on disk the response depends on Accept-Encoding whichever
    // representation is chosen, so every answer for this path says so.
    let varies = !siblings.is_empty();
    let chosen = siblings
        .into_iter()
        .find(|(_, coding, _)| http::accepts_encoding(headers, coding));

    // Weak validator built from size and mtime, the same shape `express.static`
    // sends, so an existing browser cache stays valid across the swap.  A
    // precompressed representation tags it with its coding.
    let suffix = chosen
        .as_ref()
        .map(|(_, _, ext)| format!("-{ext}"))
        .unwrap_or_default();
    let etag = weak_etag(metadata.len(), modified, &suffix);
    let last_modified = httpdate::fmt_http_date(modified);

    if etag_matches_weak(headers, &etag) || not_modified_since(headers, modified) {
        let mut builder = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(ETAG, &etag)
            .header(LAST_MODIFIED, &last_modified)
            .header(CACHE_CONTROL, "public, max-age=0");
        if varies {
            builder = builder.header(VARY, "Accept-Encoding");
        }
        return Some(builder.body(Body::empty()).unwrap());
    }

    let ext = extension_of(&path.to_string_lossy());
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, http::content_type_for(&ext))
        .header(ETAG, &etag)
        .header(LAST_MODIFIED, &last_modified)
        .header(CACHE_CONTROL, "public, max-age=0");
    if varies {
        builder = builder.header(VARY, "Accept-Encoding");
    }

    if let Some((sibling, coding, _)) = &chosen {
        match tokio::fs::read(sibling).await {
            Ok(content) => {
                return Some(
                    builder
                        .header(CONTENT_ENCODING, *coding)
                        .body(Body::from(content))
                        .unwrap(),
                );
            }
            Err(e) => {
                // The ETag already names this representation, so a failed read
                // cannot quietly become a different one under the same tag.
                warn!("Static read failed for {}: {e}", sibling.display());
                return None;
            }
        }
    }

    let content = match tokio::fs::read(&path).await {
        Ok(content) => content,
        Err(e) => {
            warn!("Static read failed for {}: {e}", path.display());
            return None;
        }
    };

    Some(http::maybe_compress(
        headers,
        builder.body(Body::empty()).unwrap(),
        content,
        state.cfg.enable_compression,
    ))
}

fn weak_etag(len: u64, modified: SystemTime, suffix: &str) -> String {
    let millis = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("W/\"{len:x}-{millis:x}{suffix}\"")
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
