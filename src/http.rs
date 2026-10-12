//! Response construction: content types, cache headers, conditional requests,
//! compression and CORS.

use std::io::Write;

use axum::body::Body;
use axum::http::header::{
    ACCEPT_ENCODING, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
    ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_ENCODING,
    CONTENT_TYPE, ETAG, IF_NONE_MATCH, LAST_MODIFIED, ORIGIN, VARY,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::util::extension_of;

/// One day, immutable — game assets are content-addressed by their ETag and
/// never change under a given path in a shipped client.
pub const STATIC_MAX_AGE: u32 = 86_400;
pub const INDEX_MAX_AGE: u32 = 60;
const COMPRESSION_THRESHOLD: usize = 1024;

/// Extensions that get an ETag and a long cache lifetime.  Taken verbatim from
/// the reference so that a browser's existing cache stays valid across the
/// swap.
const STATIC_EXTENSIONS: [&str; 22] = [
    "grf", "gat", "rsw", "gnd", "rsm", "str", "spr", "act", "pal", "bmp", "tga", "jpg", "jpeg",
    "png", "gif", "wav", "mp3", "ogg", "txt", "xml", "lub", "lua",
];

/// Game assets that are worth compressing on the wire.
const COMPRESSIBLE_GAME_EXTENSIONS: [&str; 14] = [
    "spr", "act", "rsm", "gnd", "gat", "rsw", "str", "bmp", "tga", "pal", "lub", "lua", "txt",
    "xml",
];

pub fn is_static_extension(ext: &str) -> bool {
    STATIC_EXTENSIONS.contains(&ext)
}

/// Content type for an extension.  Unknown extensions — which is most of the
/// game's formats — become `application/octet-stream`, exactly as Express's
/// `res.type()` resolves them.
pub fn content_type_for(ext: &str) -> &'static str {
    match ext {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "txt" | "text" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "wav" => "audio/wav",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "mp4" => "video/mp4",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "map" => "application/json; charset=utf-8",
        "webmanifest" => "application/manifest+json",
        "avif" => "image/avif",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

fn is_compressible(ext: &str, content_type: &str) -> bool {
    if COMPRESSIBLE_GAME_EXTENSIONS.contains(&ext) {
        return true;
    }
    content_type.starts_with("text/")
        || content_type.starts_with("image/svg")
        || content_type.starts_with("application/json")
        || content_type.starts_with("application/xml")
        || content_type.starts_with("application/javascript")
        || content_type.starts_with("application/wasm")
}

pub fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|e| e.trim().starts_with("gzip")))
        .unwrap_or(false)
}

/// True when `Accept-Encoding` admits `coding`: the coding listed by name
/// (case-insensitive) with a non-zero `q`, or, when it is not listed, a
/// non-zero `*`.  `br;q=0` is a refusal, not a match.
pub fn accepts_encoding(headers: &HeaderMap, coding: &str) -> bool {
    let Some(value) = headers.get(ACCEPT_ENCODING).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let mut wildcard = None;
    for item in value.split(',') {
        let mut parts = item.split(';');
        let name = parts.next().unwrap_or("").trim();
        // A missing `q` is 1; one that does not parse is treated as a refusal.
        let acceptable = parts
            .find_map(|param| {
                let (key, q) = param.split_once('=')?;
                key.trim().eq_ignore_ascii_case("q").then(|| q.trim())
            })
            .map(|q| q.parse::<f32>().map(|q| q > 0.0).unwrap_or(false))
            .unwrap_or(true);
        if name.eq_ignore_ascii_case(coding) {
            return acceptable;
        }
        if name == "*" {
            wildcard = Some(acceptable);
        }
    }
    wildcard.unwrap_or(false)
}

/// A content coding the server makes for game assets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    Br,
    Gzip,
}

impl Coding {
    pub fn name(self) -> &'static str {
        match self {
            Coding::Br => "br",
            Coding::Gzip => "gzip",
        }
    }
}

/// Gzip level for game assets.  The result is kept with the cached file, so
/// it is paid once per file rather than once per request: level 6 makes the
/// `.lub` tables about a third smaller than level 1, at about 60 MB/s.
const ASSET_GZIP_LEVEL: u32 = 6;
/// Brotli quality and window for game assets.  Quality 5 is where brotli
/// stops getting much smaller for what it costs: half the size of level-1
/// gzip on the text tables, at about the speed of gzip level 6.
const ASSET_BROTLI_QUALITY: u32 = 5;
const ASSET_BROTLI_WINDOW: u32 = 22;

/// True when `path` is a game asset worth compressing, so its answer depends
/// on `Accept-Encoding` whether or not this client gets it compressed.
pub fn negotiates_coding(path: &str, len: usize, compression_enabled: bool) -> bool {
    let ext = extension_of(path);
    compression_enabled
        && len >= COMPRESSION_THRESHOLD
        && is_compressible(&ext, content_type_for(&ext))
}

/// The coding to send `path` in, or `None` for its bytes as they are.
/// Browsers offer `br` only over HTTPS, so a player on the LAN gets gzip.
pub fn asset_coding(
    request_headers: &HeaderMap,
    path: &str,
    len: usize,
    compression_enabled: bool,
) -> Option<Coding> {
    if !negotiates_coding(path, len, compression_enabled) {
        return None;
    }
    [Coding::Br, Coding::Gzip]
        .into_iter()
        .find(|coding| accepts_encoding(request_headers, coding.name()))
}

/// `data` in `coding`, or `None` when that is not smaller.  Tens of
/// milliseconds for a large table, so call it off the async workers.
pub fn encode_asset(coding: Coding, data: &[u8]) -> Option<Vec<u8>> {
    let encoded = match coding {
        Coding::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::new(ASSET_GZIP_LEVEL));
            encoder.write_all(data).ok()?;
            encoder.finish().ok()?
        }
        Coding::Br => {
            let mut out = Vec::new();
            {
                let mut writer = brotli::CompressorWriter::new(
                    &mut out,
                    4096,
                    ASSET_BROTLI_QUALITY,
                    ASSET_BROTLI_WINDOW,
                );
                writer.write_all(data).ok()?;
                writer.flush().ok()?;
            }
            out
        }
    };
    (encoded.len() < data.len()).then_some(encoded)
}

fn gzip(data: &[u8]) -> Option<Vec<u8>> {
    // Level 1, for responses made per request (JSON, the landing page): they
    // are not kept, so each one pays.  Game assets go through `encode_asset`,
    // whose result is kept with the cached file.
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(1));
    encoder.write_all(data).ok()?;
    encoder.finish().ok()
}

/// True when the client's `If-None-Match` matches the entity tag we would send.
pub fn etag_matches(headers: &HeaderMap, etag: &str) -> bool {
    let Some(value) = headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let quoted = format!("\"{etag}\"");
    value
        .split(',')
        .map(|s| s.trim())
        .any(|candidate| candidate == quoted || candidate == "*")
}

/// Build the response for a resolved asset, honouring conditional requests.
///
/// `encoded` is the body already in the coding [`asset_coding`] chose, when
/// that came out smaller; `vary` is [`negotiates_coding`], so a cache keeps
/// the encoded and plain bodies apart even when this one is plain.
pub fn asset_response(
    request_headers: &HeaderMap,
    path: &str,
    data: &[u8],
    etag: Option<&str>,
    vary: bool,
    encoded: Option<(Coding, &[u8])>,
) -> Response {
    let ext = extension_of(path);
    let content_type = content_type_for(&ext);
    let is_static = is_static_extension(&ext);

    if is_static {
        if let Some(etag) = etag {
            if etag_matches(request_headers, etag) {
                return not_modified(etag);
            }
        }
    }

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type);

    if is_static {
        if let Some(etag) = etag {
            builder = builder.header(ETAG, format!("\"{etag}\""));
        }
        builder = builder
            .header(
                CACHE_CONTROL,
                format!("public, max-age={STATIC_MAX_AGE}, immutable"),
            )
            .header(
                LAST_MODIFIED,
                httpdate::fmt_http_date(std::time::SystemTime::now()),
            );
    } else {
        builder = builder.header(CACHE_CONTROL, "no-cache, no-store, must-revalidate");
    }

    if vary {
        builder = builder.header(VARY, "Accept-Encoding");
    }
    match encoded {
        Some((coding, body)) => builder
            .header(CONTENT_ENCODING, coding.name())
            .body(Body::from(body.to_vec()))
            .unwrap(),
        None => builder.body(Body::from(data.to_vec())).unwrap(),
    }
}

/// The compact form of a picture (compact.rs), for a request that asked for
/// it.  Cached like the original, under its own ETag.
pub fn compact_response(etag: &str, body: &[u8]) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "image/webp")
        .header(ETAG, format!("\"{etag}\""))
        .header(
            CACHE_CONTROL,
            format!("public, max-age={STATIC_MAX_AGE}, immutable"),
        )
        .header(
            LAST_MODIFIED,
            httpdate::fmt_http_date(std::time::SystemTime::now()),
        )
        .header(VARY, "Accept-Encoding, X-Compact-Images")
        .body(Body::from(body.to_vec()))
        .unwrap()
}

pub fn not_modified(etag: &str) -> Response {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(ETAG, format!("\"{etag}\""))
        .header(
            CACHE_CONTROL,
            format!("public, max-age={STATIC_MAX_AGE}, immutable"),
        )
        .body(Body::empty())
        .unwrap()
}

pub fn not_found() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .body(Body::from("File not found"))
        .unwrap()
}

pub fn text(status: StatusCode, body: impl Into<String>) -> Response {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body.into()))
        .unwrap()
}

/// Compress a JSON or text payload if the client asked for it.  Small payloads
/// and non-gzip clients pass straight through.
pub fn maybe_compress(
    request_headers: &HeaderMap,
    mut response: Response,
    body: Vec<u8>,
    compression_enabled: bool,
) -> Response {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if compression_enabled
        && body.len() >= COMPRESSION_THRESHOLD
        && is_compressible("", &content_type)
        && accepts_gzip(request_headers)
    {
        if let Some(gz) = gzip(&body) {
            if gz.len() < body.len() {
                response
                    .headers_mut()
                    .insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                response
                    .headers_mut()
                    .insert(VARY, HeaderValue::from_static("Accept-Encoding"));
                *response.body_mut() = Body::from(gz);
                return response;
            }
        }
    }

    *response.body_mut() = Body::from(body);
    response
}

/// Same-origin is the design, so this exists only so that a client served from
/// somewhere else — the reference's `live-server` on :8000, say — keeps working.
pub struct Cors {
    allowed_origins: Vec<String>,
}

impl Cors {
    pub fn new(client_public_url: Option<&str>) -> Cors {
        let mut allowed_origins: Vec<String> = [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://localhost:3338",
            "http://127.0.0.1:3338",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        if let Some(url) = client_public_url {
            let url = url.trim_end_matches('/').to_string();
            if !allowed_origins.contains(&url) {
                allowed_origins.insert(0, url);
            }
        }

        Cors { allowed_origins }
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|o| o == origin)
    }

    /// Read the request's `Origin` before the request is consumed by the
    /// handler chain; the response is decorated afterwards.
    pub fn origin_of(headers: &HeaderMap) -> Option<String> {
        headers
            .get(ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    pub fn apply(&self, origin: Option<&str>, response: &mut Response) {
        let Some(origin) = origin else { return };
        if !self.origin_allowed(origin) {
            return;
        }
        let headers = response.headers_mut();
        if let Ok(value) = HeaderValue::from_str(origin) {
            headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, value);
        }
        headers.insert(
            ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        headers.insert(VARY, HeaderValue::from_static("Origin"));
    }

    pub fn preflight(&self, origin: Option<&str>) -> Response {
        let mut response = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(
                ACCESS_CONTROL_ALLOW_METHODS,
                "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD",
            )
            .header(ACCESS_CONTROL_ALLOW_HEADERS, "*")
            .body(Body::empty())
            .unwrap();
        self.apply(origin, &mut response);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn game_formats_fall_back_to_octet_stream() {
        assert_eq!(content_type_for("spr"), "application/octet-stream");
        assert_eq!(content_type_for("act"), "application/octet-stream");
        assert_eq!(content_type_for("gnd"), "application/octet-stream");
        assert_eq!(content_type_for("txt"), "text/plain; charset=utf-8");
    }

    #[test]
    fn static_extension_list_matches_the_specification() {
        for ext in [
            "grf", "gat", "rsw", "gnd", "rsm", "str", "spr", "act", "pal", "bmp", "tga", "jpg",
            "jpeg", "png", "gif", "wav", "mp3", "ogg", "txt", "xml", "lub", "lua",
        ] {
            assert!(is_static_extension(ext), "{ext} should be a static asset");
        }
        assert!(!is_static_extension("html"));
        assert!(!is_static_extension("js"));
    }

    #[test]
    fn if_none_match_is_compared_quoted() {
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, HeaderValue::from_static("\"abc123\""));
        assert!(etag_matches(&headers, "abc123"));
        assert!(!etag_matches(&headers, "abc124"));

        let mut unquoted = HeaderMap::new();
        unquoted.insert(IF_NONE_MATCH, HeaderValue::from_static("abc123"));
        assert!(!etag_matches(&unquoted, "abc123"));
    }

    #[test]
    fn if_none_match_accepts_a_list_and_a_wildcard() {
        let mut headers = HeaderMap::new();
        headers.insert(
            IF_NONE_MATCH,
            HeaderValue::from_static("\"zzz\", \"abc123\""),
        );
        assert!(etag_matches(&headers, "abc123"));

        let mut star = HeaderMap::new();
        star.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(etag_matches(&star, "anything"));
    }

    #[test]
    fn accept_encoding_is_matched_by_token_and_honours_q_zero() {
        let accepts = |value: &'static str, coding: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(value));
            accepts_encoding(&headers, coding)
        };
        assert!(accepts("gzip, deflate, br", "br"));
        assert!(accepts("gzip, deflate, br", "gzip"));
        assert!(accepts("BR;q=0.5", "br"));
        assert!(!accepts("br;q=0, gzip", "br"));
        assert!(!accepts("br; q=0.000", "br"));
        assert!(accepts("br; q=0.001", "br"));
        assert!(!accepts("brotli, gzipx", "br"));
        assert!(!accepts("brotli, gzipx", "gzip"));
        assert!(accepts("*", "br"));
        assert!(!accepts("*, br;q=0", "br"));
        assert!(!accepts("identity", "gzip"));
        assert!(!accepts_encoding(&HeaderMap::new(), "gzip"));
    }

    #[test]
    fn gzip_round_trips() {
        use std::io::Read;
        let data = vec![b'a'; 4096];
        let gz = gzip(&data).unwrap();
        assert!(gz.len() < data.len());
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn cors_only_reflects_known_origins() {
        let cors = Cors::new(Some("http://example.test:9000"));
        assert!(cors.origin_allowed("http://example.test:9000"));
        assert!(cors.origin_allowed("http://localhost:8000"));
        assert!(!cors.origin_allowed("http://evil.test"));
    }
}
