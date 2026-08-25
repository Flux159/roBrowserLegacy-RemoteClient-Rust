//! The HTTP surface, driven over a real socket.

mod support;

use robrowser_remoteclient::encoding::to_mojibake;
use serde_json::json;
use support::{client_for, config_for, request, write_data_ini, GrfBuilder, TempDir, TestServer};

const KOREAN: &str = "data\\texture\\유저인터페이스\\btn_ok.bmp";

async fn server(overrides: &[(&str, &str)]) -> (TempDir, TestServer) {
    let dir = TempDir::new("http");
    GrfBuilder::new()
        .file("data\\hello.txt", b"hello from the archive")
        .file("data\\big.spr", &vec![0x11u8; 40_000])
        .file(KOREAN, &vec![0x22u8; 3000])
        .file("data\\config.lub", b"return { a = 1 }")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);

    let client = client_for(&dir.path, overrides);
    let cfg = config_for(&dir.path, overrides);
    let health = json!({
        "status": "ok",
        "hasWarnings": false,
        "summary": { "errors": 0, "warnings": 0, "info": 1 },
        "details": {},
        "messages": { "errors": [], "warnings": [], "info": ["ok"] },
    });
    let server = TestServer::start(cfg, client, health).await;
    (dir, server)
}

/// Percent-encode a path the way a browser encodes a URL: UTF-8 bytes, with
/// the reserved set escaped.  roBrowser's mojibake paths arrive like this.
fn encode_path(path: &str) -> String {
    let mut out = String::from("/");
    for byte in path.as_bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[tokio::test]
async fn serves_an_asset_with_an_etag_and_a_long_cache_lifetime() {
    let (_dir, server) = server(&[]).await;
    let response = request(server.addr, "GET", "/data/hello.txt", &[], None).await;

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello from the archive");
    assert_eq!(
        response.header("cache-control"),
        Some("public, max-age=86400, immutable")
    );
    let etag = response.header("etag").unwrap().to_string();
    assert!(etag.starts_with('"') && etag.len() == 18, "{etag}");
}

#[tokio::test]
async fn a_matching_if_none_match_gets_a_304_with_no_body() {
    let (_dir, server) = server(&[]).await;
    let first = request(server.addr, "GET", "/data/hello.txt", &[], None).await;
    let etag = first.header("etag").unwrap().to_string();

    let second = request(
        server.addr,
        "GET",
        "/data/hello.txt",
        &[("If-None-Match", &etag)],
        None,
    )
    .await;

    assert_eq!(second.status, 304);
    assert!(second.body.is_empty());
    assert_eq!(second.header("etag"), Some(etag.as_str()));
}

#[tokio::test]
async fn a_stale_if_none_match_gets_the_body() {
    let (_dir, server) = server(&[]).await;
    let response = request(
        server.addr,
        "GET",
        "/data/hello.txt",
        &[("If-None-Match", "\"0000000000000000\"")],
        None,
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello from the archive");
}

#[tokio::test]
async fn a_korean_path_is_served_under_its_percent_encoded_mojibake_spelling() {
    let (_dir, server) = server(&[]).await;
    let requested = to_mojibake(&KOREAN.replace('\\', "/"));
    let response = request(server.addr, "GET", &encode_path(&requested), &[], None).await;

    assert_eq!(response.status, 200);
    assert_eq!(response.body, vec![0x22u8; 3000]);
    assert_eq!(response.header("content-type"), Some("image/bmp"));
}

#[tokio::test]
async fn a_korean_path_is_also_served_under_its_unicode_spelling() {
    let (_dir, server) = server(&[]).await;
    let requested = KOREAN.replace('\\', "/");
    let response = request(server.addr, "GET", &encode_path(&requested), &[], None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, vec![0x22u8; 3000]);
}

#[tokio::test]
async fn a_missing_asset_is_a_404_that_is_not_cached() {
    let (_dir, server) = server(&[]).await;
    let response = request(server.addr, "GET", "/data/absent.txt", &[], None).await;
    assert_eq!(response.status, 404);
    assert_eq!(response.header("cache-control"), Some("no-store"));
}

#[tokio::test]
async fn unknown_game_formats_get_octet_stream() {
    let (_dir, server) = server(&[]).await;
    let response = request(server.addr, "GET", "/data/big.spr", &[], None).await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("content-type"),
        Some("application/octet-stream")
    );
}

#[tokio::test]
async fn compressible_assets_are_gzipped_when_the_client_asks() {
    let (_dir, server) = server(&[]).await;
    let response = request(
        server.addr,
        "GET",
        "/data/big.spr",
        &[("Accept-Encoding", "gzip, deflate")],
        None,
    )
    .await;

    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-encoding"), Some("gzip"));
    // `request` transparently decodes, so this is the original payload.
    assert_eq!(response.body, vec![0x11u8; 40_000]);
}

#[tokio::test]
async fn a_client_that_does_not_accept_gzip_gets_plain_bytes() {
    let (_dir, server) = server(&[]).await;
    let response = request(server.addr, "GET", "/data/big.spr", &[], None).await;
    assert_eq!(response.header("content-encoding"), None);
    assert_eq!(response.body.len(), 40_000);
}

#[tokio::test]
async fn head_returns_the_headers_without_the_body() {
    let (_dir, server) = server(&[]).await;
    let response = request(server.addr, "HEAD", "/data/hello.txt", &[], None).await;
    assert_eq!(response.status, 200);
    assert!(response.body.is_empty());
    assert!(response.header("etag").is_some());
}

#[tokio::test]
async fn health_reports_validation_plus_live_counters() {
    let (_dir, server) = server(&[]).await;
    // Touch an asset so the counters are not all zero.
    request(server.addr, "GET", "/data/hello.txt", &[], None).await;

    let response = request(server.addr, "GET", "/api/health", &[], None).await;
    assert_eq!(response.status, 200);

    let body = response.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["index"]["grfCount"], 1);
    assert_eq!(body["index"]["uniqueFiles"], 4);
    assert!(body["cache"]["size"].as_u64().unwrap() >= 1);
    assert!(body["missingFiles"]["total"].as_u64().is_some());
    assert_eq!(body["esrgan"]["enabled"], false);
}

#[tokio::test]
async fn cache_stats_has_the_documented_shape() {
    let (_dir, server) = server(&[]).await;
    request(server.addr, "GET", "/data/hello.txt", &[], None).await;
    request(server.addr, "GET", "/data/hello.txt", &[], None).await;

    let body = request(server.addr, "GET", "/api/cache-stats", &[], None)
        .await
        .json();

    let cache = &body["cache"];
    for key in [
        "size",
        "maxSize",
        "memoryUsedMB",
        "maxMemoryMB",
        "hits",
        "misses",
        "hitRate",
    ] {
        assert!(!cache[key].is_null(), "cache.{key} missing");
    }
    assert!(cache["hitRate"].as_str().unwrap().ends_with('%'));
    assert!(body["index"]["totalFiles"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn missing_files_records_what_was_asked_for() {
    let (_dir, server) = server(&[]).await;
    request(server.addr, "GET", "/data/ghost.spr", &[], None).await;

    let body = request(server.addr, "GET", "/api/missing-files", &[], None)
        .await
        .json();

    assert_eq!(body["total"], 1);
    assert_eq!(body["files"][0]["requestedPath"], "data/ghost.spr");
    assert_eq!(body["files"][0]["grfPath"], "data\\ghost.spr");
    assert!(body["logFile"]
        .as_str()
        .unwrap()
        .ends_with("missing-files.log"));
}

#[tokio::test]
async fn list_files_returns_every_indexed_path() {
    let (_dir, server) = server(&[]).await;
    let response = request(server.addr, "GET", "/list-files", &[], None).await;
    assert_eq!(
        response.header("cache-control"),
        Some("public, max-age=300")
    );

    let files: Vec<String> = serde_json::from_value(response.json()).unwrap();
    assert_eq!(files.len(), 4);
    assert!(files.contains(&"data\\hello.txt".to_string()));
    assert!(files.contains(&KOREAN.to_string()));
}

#[tokio::test]
async fn search_returns_newline_separated_paths() {
    let (_dir, server) = server(&[]).await;
    let response = request(
        server.addr,
        "POST",
        "/search",
        &[("Content-Type", "application/json")],
        Some(br#"{"filter":"\\.lub$"}"#),
    )
    .await;

    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "data\\config.lub");
}

#[tokio::test]
async fn search_rejects_an_empty_filter() {
    let (_dir, server) = server(&[]).await;
    let response = request(
        server.addr,
        "POST",
        "/search",
        &[("Content-Type", "application/json")],
        Some(br#"{"filter":""}"#),
    )
    .await;
    assert_eq!(response.status, 400);
}

#[tokio::test]
async fn search_can_be_disabled() {
    let (_dir, server) = server(&[("CLIENT_ENABLESEARCH", "false")]).await;
    let response = request(
        server.addr,
        "POST",
        "/search",
        &[("Content-Type", "application/json")],
        Some(br#"{"filter":"lub"}"#),
    )
    .await;
    assert_eq!(response.status, 400);
}

#[tokio::test]
async fn batch_returns_base64_and_omits_failures() {
    let (_dir, server) = server(&[]).await;
    let response = request(
        server.addr,
        "POST",
        "/batch",
        &[("Content-Type", "application/json")],
        Some(br#"{"files":["data/hello.txt","data/nope.txt"]}"#),
    )
    .await;

    assert_eq!(response.status, 200);
    let body = response.json();
    assert_eq!(body["data/hello.txt"], "aGVsbG8gZnJvbSB0aGUgYXJjaGl2ZQ==");
    assert!(body.get("data/nope.txt").is_none());
}

#[tokio::test]
async fn batch_refuses_more_than_fifty_files() {
    let (_dir, server) = server(&[]).await;
    let files: Vec<String> = (0..51).map(|i| format!("data/f{i}.txt")).collect();
    let payload = serde_json::to_vec(&json!({ "files": files })).unwrap();

    let response = request(
        server.addr,
        "POST",
        "/batch",
        &[("Content-Type", "application/json")],
        Some(&payload),
    )
    .await;

    assert_eq!(response.status, 400);
    assert_eq!(response.json()["error"], "Invalid files array (1-50 files)");
}

#[tokio::test]
async fn batch_refuses_an_empty_list() {
    let (_dir, server) = server(&[]).await;
    let response = request(
        server.addr,
        "POST",
        "/batch",
        &[("Content-Type", "application/json")],
        Some(br#"{"files":[]}"#),
    )
    .await;
    assert_eq!(response.status, 400);
}

#[tokio::test]
async fn the_root_serves_a_status_page_when_no_index_html_exists() {
    let (_dir, server) = server(&[]).await;
    let response = request(server.addr, "GET", "/", &[], None).await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(response.header("cache-control"), Some("public, max-age=60"));
    assert!(response.text().contains("roBrowser Remote Client"));
}

#[tokio::test]
async fn the_root_prefers_an_index_html_on_disk() {
    let dir = TempDir::new("http-index");
    GrfBuilder::new()
        .file("data\\hello.txt", b"x")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);
    dir.write("index.html", b"<h1>local landing page</h1>");

    let client = client_for(&dir.path, &[]);
    let cfg = config_for(&dir.path, &[]);
    let server = TestServer::start(cfg, client, json!({})).await;

    let response = request(server.addr, "GET", "/", &[], None).await;
    assert_eq!(response.text(), "<h1>local landing page</h1>");
}

#[tokio::test]
async fn static_serving_comes_before_asset_resolution() {
    let dir = TempDir::new("http-static");
    GrfBuilder::new()
        .file("data\\hello.txt", b"from the archive")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);

    let bundle = TempDir::new("bundle");
    bundle.write("index.html", b"<html>client bundle</html>");
    bundle.write("data/hello.txt", b"from the bundle");
    bundle.write("app.js", b"console.log('hi')");

    let overrides = [
        ("ENABLE_STATIC_SERVE", "true"),
        ("ROBROWSER_PATH", bundle.path.to_str().unwrap()),
    ];
    let client = client_for(&dir.path, &overrides);
    let cfg = config_for(&dir.path, &overrides);
    let server = TestServer::start(cfg, client, json!({})).await;

    // A file present in both places comes from the bundle.
    let hello = request(server.addr, "GET", "/data/hello.txt", &[], None).await;
    assert_eq!(hello.body, b"from the bundle");
    assert_eq!(hello.header("cache-control"), Some("public, max-age=0"));

    // The bundle's index answers the root.
    let root = request(server.addr, "GET", "/", &[], None).await;
    assert_eq!(root.body, b"<html>client bundle</html>");

    // And a conditional request on a static file is honoured.
    let etag = request(server.addr, "GET", "/app.js", &[], None)
        .await
        .header("etag")
        .unwrap()
        .to_string();
    let cached = request(
        server.addr,
        "GET",
        "/app.js",
        &[("If-None-Match", &etag)],
        None,
    )
    .await;
    assert_eq!(cached.status, 304);
}

#[tokio::test]
async fn a_static_request_that_misses_falls_through_to_the_archives() {
    let dir = TempDir::new("http-fallthrough");
    GrfBuilder::new()
        .file("data\\only-in-grf.txt", b"from the archive")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);

    let bundle = TempDir::new("bundle-empty");
    bundle.write("index.html", b"bundle");

    let overrides = [
        ("ENABLE_STATIC_SERVE", "true"),
        ("ROBROWSER_PATH", bundle.path.to_str().unwrap()),
    ];
    let client = client_for(&dir.path, &overrides);
    let cfg = config_for(&dir.path, &overrides);
    let server = TestServer::start(cfg, client, json!({})).await;

    let response = request(server.addr, "GET", "/data/only-in-grf.txt", &[], None).await;
    assert_eq!(response.body, b"from the archive");
}

#[tokio::test]
async fn static_serving_refuses_to_escape_the_bundle() {
    let dir = TempDir::new("http-escape");
    GrfBuilder::new()
        .file("data\\x.txt", b"x")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);

    let bundle = TempDir::new("bundle-escape");
    bundle.write("index.html", b"bundle");
    std::fs::write(bundle.path.parent().unwrap().join("outside.txt"), b"secret").unwrap();

    let overrides = [
        ("ENABLE_STATIC_SERVE", "true"),
        ("ROBROWSER_PATH", bundle.path.to_str().unwrap()),
    ];
    let client = client_for(&dir.path, &overrides);
    let cfg = config_for(&dir.path, &overrides);
    let server = TestServer::start(cfg, client, json!({})).await;

    let response = request(server.addr, "GET", "/../outside.txt", &[], None).await;
    assert_ne!(response.body, b"secret");
    let _ = std::fs::remove_file(bundle.path.parent().unwrap().join("outside.txt"));
}

#[tokio::test]
async fn cors_reflects_a_known_origin_and_ignores_others() {
    let (_dir, server) = server(&[]).await;

    let allowed = request(
        server.addr,
        "GET",
        "/api/health",
        &[("Origin", "http://127.0.0.1:8000")],
        None,
    )
    .await;
    assert_eq!(
        allowed.header("access-control-allow-origin"),
        Some("http://127.0.0.1:8000")
    );

    let denied = request(
        server.addr,
        "GET",
        "/api/health",
        &[("Origin", "http://evil.example")],
        None,
    )
    .await;
    assert_eq!(denied.header("access-control-allow-origin"), None);
}

#[tokio::test]
async fn preflight_is_answered_without_reaching_a_handler() {
    let (_dir, server) = server(&[]).await;
    let response = request(
        server.addr,
        "OPTIONS",
        "/batch",
        &[
            ("Origin", "http://127.0.0.1:8000"),
            ("Access-Control-Request-Method", "POST"),
        ],
        None,
    )
    .await;

    assert_eq!(response.status, 204);
    assert!(response
        .header("access-control-allow-methods")
        .unwrap()
        .contains("POST"));
}

/// roBrowser's own `FileManager.search` posts `filter=<regex>` as
/// `application/x-www-form-urlencoded` to the remote-client base URL, not JSON
/// to /search.  Both shapes and both paths have to work.
#[tokio::test]
async fn search_accepts_a_urlencoded_form_body() {
    let (_dir, server) = server(&[]).await;
    let response = request(
        server.addr,
        "POST",
        "/search",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some(b"filter=%5C.lub%24"),
    )
    .await;

    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "data\\config.lub");
}

#[tokio::test]
async fn search_is_answered_at_the_remote_client_base_url() {
    let (_dir, server) = server(&[]).await;
    let response = request(
        server.addr,
        "POST",
        "/",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some(b"filter=%5C.lub%24"),
    )
    .await;

    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "data\\config.lub");
}

#[tokio::test]
async fn search_handles_plus_encoded_spaces() {
    let dir = TempDir::new("http-search-space");
    GrfBuilder::new()
        .file("data\\my file.txt", b"spaced")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);

    let client = client_for(&dir.path, &[]);
    let cfg = config_for(&dir.path, &[]);
    let server = TestServer::start(cfg, client, json!({})).await;

    let response = request(
        server.addr,
        "POST",
        "/search",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some(b"filter=my+file"),
    )
    .await;

    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "data\\my file.txt");
}

/// The client percent-encodes each path segment of a forward-slash path, which
/// is the only shape it ever actually sends.
#[tokio::test]
async fn the_clients_own_url_shape_resolves() {
    let (_dir, server) = server(&[]).await;

    // `filename.replace(/\\/g,'/')` then `encodeURIComponent` per segment.
    let mojibake = to_mojibake(&KOREAN.replace('\\', "/"));
    let url: String = std::iter::once(String::new())
        .chain(mojibake.split('/').map(|segment| {
            segment
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || "-_.!~*'()".contains(c) {
                        c.to_string()
                    } else {
                        let mut buffer = [0u8; 4];
                        c.encode_utf8(&mut buffer)
                            .bytes()
                            .map(|b| format!("%{b:02X}"))
                            .collect()
                    }
                })
                .collect::<String>()
        }))
        .collect::<Vec<_>>()
        .join("/");

    let response = request(server.addr, "GET", &url, &[], None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, vec![0x22u8; 3000]);
}
