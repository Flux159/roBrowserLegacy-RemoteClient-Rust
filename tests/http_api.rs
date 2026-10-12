//! The HTTP surface, driven over a real socket.

mod support;

use robrowser_remoteclient::encoding::to_mojibake;
use serde_json::json;
use std::time::Duration;
use support::{client_for, config_for, request, write_data_ini, GrfBuilder, TempDir, TestServer};

const KOREAN: &str = "data\\texture\\유저인터페이스\\btn_ok.bmp";

#[tokio::test]
async fn external_music_serves_bytes_but_private_files_and_containers_do_not() {
    let external = TempDir::new("http-client");
    external.write("BGM/track.mp3", b"external music");
    let web = TempDir::new("http-private-web");
    for path in [
        ".env",
        "resources/DATA.INI",
        "leak.grf",
        "logs/missing-files.log",
    ] {
        web.write(path, b"private");
    }
    let (dir, server) = server(&[
        ("BGM_PATH", external.join("BGM").to_str().unwrap()),
        ("ROBROWSER_PATH", web.path.to_str().unwrap()),
        ("ENABLE_STATIC_SERVE", "true"),
    ])
    .await;
    dir.write(
        ".translation/data/secret.txt",
        b"private translation snapshot",
    );
    let response = request(server.addr, "GET", "/BGM/track.mp3", &[], None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"external music");
    dir.write(
        "Config.local.js",
        b"window.ROConfigLocal = {renewal: false};",
    );
    web.write("Config.local.js", b"stale bundled configuration");
    let config = request(server.addr, "GET", "/Config.local.js", &[], None).await;
    assert_eq!(config.body, b"window.ROConfigLocal = {renewal: false};");
    assert_eq!(config.header("cache-control"), Some("no-store"));
    let paths = [
        "/.env",
        "/%2eenv",
        "/resources/DATA.INI",
        "/leak.grf",
        "/logs/missing-files.log",
        "/.translation/data/secret.txt",
        "/resources/data.grf",
    ];
    for path in paths {
        assert_eq!(
            request(server.addr, "GET", path, &[], None).await.status,
            404,
            "{path}"
        );
    }
    let body = json!({"files": ["resources/data.grf", ".translation/data/secret.txt"]}).to_string();
    let response = request(
        server.addr,
        "POST",
        "/batch",
        &[("Content-Type", "application/json")],
        Some(body.as_bytes()),
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.json(), json!({}));
}

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
async fn a_client_that_offers_br_gets_brotli_and_the_same_bytes_each_time() {
    let (_dir, server) = server(&[]).await;
    let mut bodies = Vec::new();
    for _ in 0..2 {
        let response = request(
            server.addr,
            "GET",
            "/data/big.spr",
            &[("Accept-Encoding", "gzip, deflate, br")],
            None,
        )
        .await;
        assert_eq!(response.status, 200);
        assert_eq!(response.header("content-encoding"), Some("br"));
        assert_eq!(response.header("vary"), Some("Accept-Encoding"));
        bodies.push(response.body);
    }
    // The second answer comes from the encoding kept with the cached file.
    assert_eq!(bodies[0], bodies[1]);
    let mut decoded = Vec::new();
    brotli::BrotliDecompress(&mut bodies[0].as_slice(), &mut decoded).unwrap();
    assert_eq!(decoded, vec![0x11u8; 40_000]);
}

#[tokio::test]
async fn a_plain_answer_to_a_compressible_asset_still_varies_on_accept_encoding() {
    let (_dir, server) = server(&[]).await;
    let response = request(server.addr, "GET", "/data/big.spr", &[], None).await;
    assert_eq!(response.header("content-encoding"), None);
    assert_eq!(response.header("vary"), Some("Accept-Encoding"));
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
async fn health_is_minimal_and_does_not_disclose_local_paths() {
    let (_dir, server) = server(&[]).await;
    let response = request(server.addr, "GET", "/api/health", &[], None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(
        response.json(),
        json!({
            "status": "ok", "service": "robrowser-remoteclient",
            "version": env!("CARGO_PKG_VERSION"),
        })
    );
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

/// A static bundle holding `Online.js` (big enough that on-the-fly gzip would
/// kick in) and whichever precompressed siblings the test writes.
async fn precompressed_server(enable_compression: &str) -> (TempDir, TempDir, TestServer, Vec<u8>) {
    let dir = TempDir::new("http-precompressed");
    GrfBuilder::new()
        .file("data\\x.txt", b"x")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);

    let bundle = TempDir::new("bundle-precompressed");
    let original = b"console.log('client');\n".repeat(200);
    bundle.write("Online.js", &original);

    let overrides = [
        ("ENABLE_STATIC_SERVE", "true"),
        ("ENABLE_COMPRESSION", enable_compression),
        ("ROBROWSER_PATH", bundle.path.to_str().unwrap()),
    ];
    let client = client_for(&dir.path, &overrides);
    let cfg = config_for(&dir.path, &overrides);
    let server = TestServer::start(cfg, client, json!({})).await;
    (dir, bundle, server, original)
}

/// Set a file's mtime relative to now, so freshness does not depend on how
/// quickly the test wrote its files.
fn set_age(path: &std::path::Path, seconds_ago: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(seconds_ago);
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn a_fresh_br_sibling_is_served_to_a_client_that_accepts_br() {
    let (_dir, bundle, server, _) = precompressed_server("true").await;
    // `request` does not decode brotli, so these bytes come back verbatim.
    bundle.write("Online.js.br", b"pretend brotli");
    bundle.write("Online.js.gz", &gzip_bytes(b"from the gz sibling"));
    set_age(&bundle.join("Online.js"), 60);
    set_age(&bundle.join("Online.js.br"), 30);
    set_age(&bundle.join("Online.js.gz"), 30);

    let response = request(
        server.addr,
        "GET",
        "/Online.js",
        &[("Accept-Encoding", "gzip, deflate, br")],
        None,
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-encoding"), Some("br"));
    assert_eq!(response.header("vary"), Some("Accept-Encoding"));
    assert_eq!(
        response.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    assert_eq!(response.header("cache-control"), Some("public, max-age=0"));
    assert!(response.header("etag").unwrap().ends_with("-br\""));
    assert_eq!(response.body, b"pretend brotli");

    let head = request(
        server.addr,
        "HEAD",
        "/Online.js",
        &[("Accept-Encoding", "br")],
        None,
    )
    .await;
    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-encoding"), Some("br"));
    assert!(head.body.is_empty());
}

#[tokio::test]
async fn gzip_falls_back_to_the_gz_sibling_and_br_q0_is_a_refusal() {
    let (_dir, bundle, server, _) = precompressed_server("true").await;
    bundle.write("Online.js.br", b"pretend brotli");
    bundle.write("Online.js.gz", &gzip_bytes(b"from the gz sibling"));
    set_age(&bundle.join("Online.js"), 60);
    set_age(&bundle.join("Online.js.br"), 30);
    set_age(&bundle.join("Online.js.gz"), 30);

    for accept in ["gzip, deflate", "br;q=0, gzip"] {
        let response = request(
            server.addr,
            "GET",
            "/Online.js",
            &[("Accept-Encoding", accept)],
            None,
        )
        .await;
        assert_eq!(
            response.header("content-encoding"),
            Some("gzip"),
            "{accept}"
        );
        assert_eq!(response.header("vary"), Some("Accept-Encoding"));
        assert!(response.header("etag").unwrap().ends_with("-gz\""));
        // `request` gunzips, so this proves the sibling went out, not a fresh
        // compression of the original.
        assert_eq!(response.body, b"from the gz sibling", "{accept}");
    }
}

#[tokio::test]
async fn a_stale_sibling_is_ignored() {
    let (_dir, bundle, server, original) = precompressed_server("true").await;
    bundle.write("Online.js.br", b"stale brotli");
    set_age(&bundle.join("Online.js.br"), 120);
    set_age(&bundle.join("Online.js"), 60);

    let response = request(
        server.addr,
        "GET",
        "/Online.js",
        &[("Accept-Encoding", "gzip, br")],
        None,
    )
    .await;
    assert_eq!(response.status, 200);
    // Today's on-the-fly gzip of the original, under the original's tag.
    assert_eq!(response.header("content-encoding"), Some("gzip"));
    assert_eq!(response.body, original);
    let etag = response.header("etag").unwrap();
    assert!(
        !etag.ends_with("-br\"") && !etag.ends_with("-gz\""),
        "{etag}"
    );
}

#[tokio::test]
async fn without_accept_encoding_or_with_compression_off_the_original_is_served() {
    let (_dir, bundle, server, original) = precompressed_server("true").await;
    bundle.write("Online.js.br", b"pretend brotli");
    set_age(&bundle.join("Online.js"), 60);
    set_age(&bundle.join("Online.js.br"), 30);

    let response = request(server.addr, "GET", "/Online.js", &[], None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-encoding"), None);
    assert_eq!(response.body, original);
    let etag = response.header("etag").unwrap();
    assert!(
        etag.starts_with("W/\"") && !etag.ends_with("-br\""),
        "{etag}"
    );
    // The answer would have differed for a br client, so caches are told.
    assert_eq!(response.header("vary"), Some("Accept-Encoding"));

    // Asked for by name, the sibling is just a file.
    let direct = request(
        server.addr,
        "GET",
        "/Online.js.br",
        &[("Accept-Encoding", "br")],
        None,
    )
    .await;
    assert_eq!(direct.header("content-encoding"), None);
    assert_eq!(direct.body, b"pretend brotli");

    let (_dir, bundle, server, original) = precompressed_server("false").await;
    bundle.write("Online.js.br", b"pretend brotli");
    set_age(&bundle.join("Online.js"), 60);
    set_age(&bundle.join("Online.js.br"), 30);
    let response = request(
        server.addr,
        "GET",
        "/Online.js",
        &[("Accept-Encoding", "br, gzip")],
        None,
    )
    .await;
    assert_eq!(response.header("content-encoding"), None);
    assert_eq!(response.header("vary"), None);
    assert_eq!(response.body, original);
}

#[tokio::test]
async fn each_representation_revalidates_against_its_own_etag() {
    let (_dir, bundle, server, _) = precompressed_server("true").await;
    bundle.write("Online.js.br", b"pretend brotli");
    set_age(&bundle.join("Online.js"), 60);
    set_age(&bundle.join("Online.js.br"), 30);

    let br = request(
        server.addr,
        "GET",
        "/Online.js",
        &[("Accept-Encoding", "br")],
        None,
    )
    .await;
    let br_etag = br.header("etag").unwrap().to_string();
    let plain = request(server.addr, "GET", "/Online.js", &[], None).await;
    let plain_etag = plain.header("etag").unwrap().to_string();
    assert_ne!(br_etag, plain_etag);
    assert_eq!(br.header("last-modified"), plain.header("last-modified"));

    // The br tag revalidates the br representation...
    let cached = request(
        server.addr,
        "GET",
        "/Online.js",
        &[("Accept-Encoding", "br"), ("If-None-Match", &br_etag)],
        None,
    )
    .await;
    assert_eq!(cached.status, 304);
    assert!(cached.body.is_empty());
    assert_eq!(cached.header("etag"), Some(br_etag.as_str()));
    assert_eq!(cached.header("vary"), Some("Accept-Encoding"));

    // ...but not the identity one, and the identity tag not the br one.
    let mismatched = request(
        server.addr,
        "GET",
        "/Online.js",
        &[("If-None-Match", &br_etag)],
        None,
    )
    .await;
    assert_eq!(mismatched.status, 200);
    let mismatched = request(
        server.addr,
        "GET",
        "/Online.js",
        &[("Accept-Encoding", "br"), ("If-None-Match", &plain_etag)],
        None,
    )
    .await;
    assert_eq!(mismatched.status, 200);
    assert_eq!(mismatched.body, b"pretend brotli");

    let cached = request(
        server.addr,
        "GET",
        "/Online.js",
        &[("If-None-Match", &plain_etag)],
        None,
    )
    .await;
    assert_eq!(cached.status, 304);
    assert_eq!(cached.header("etag"), Some(plain_etag.as_str()));
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

/// A one-shot loopback "app": records the request it is sent and answers
/// with `reply`.
async fn fake_app(reply: &'static str) -> (String, tokio::task::JoinHandle<String>) {
    fake_app_holding(reply, Duration::ZERO).await
}

/// As `fake_app`, but keeping the connection open for `hold` after answering,
/// as rAthena's web-server does through the app's port forward.
async fn fake_app_holding(
    reply: &'static str,
    hold: Duration,
) -> (String, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut seen = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            seen.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&seen).to_string();
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if seen.len() >= end + 4 + length {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        stream.write_all(reply.as_bytes()).await.unwrap();
        tokio::time::sleep(hold).await;
        String::from_utf8_lossy(&seen).to_string()
    });
    (target, handle)
}

#[tokio::test]
async fn a_configured_prefix_is_forwarded_to_the_loopback_app_and_nothing_else_is() {
    let (target, app) = fake_app("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: ro-remember-3338=x; Path=/_friend/remember/; HttpOnly; SameSite=Strict\r\nX-Internal: secret\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}").await;
    let (_dir, server) = server(&[
        ("APP_PROXY_PREFIX", "/_friend/remember/"),
        ("APP_PROXY_TARGET", &target),
    ])
    .await;
    let response = request(
        server.addr,
        "POST",
        "/_friend/remember/status",
        &[
            ("Origin", "http://192.168.1.20:3338"),
            ("Cookie", "ro-remember-3338=abc"),
            ("Content-Type", "application/json"),
            ("X-Forwarded-For", "1.2.3.4"),
        ],
        Some(b"{}"),
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"{\"ok\":true}");
    assert!(response
        .header("set-cookie")
        .unwrap()
        .starts_with("ro-remember-3338=x"));
    assert_eq!(response.header("x-internal"), None);
    let seen = app.await.unwrap();
    assert!(
        seen.starts_with("POST /_friend/remember/status HTTP/1.1\r\n"),
        "{seen}"
    );
    assert!(
        seen.contains("origin: http://192.168.1.20:3338\r\n"),
        "{seen}"
    );
    assert!(seen.contains("cookie: ro-remember-3338=abc\r\n"), "{seen}");
    // The peer this server saw, never the one the client claimed.
    assert!(seen.contains("X-Forwarded-For: 127.0.0.1\r\n"), "{seen}");
    assert!(!seen.contains("1.2.3.4"), "{seen}");
    assert!(seen.ends_with("\r\n\r\n{}"), "{seen}");

    // Only POST; and an app that is not listening is a 502, not a hang.
    assert_eq!(
        request(server.addr, "GET", "/_friend/remember/status", &[], None)
            .await
            .status,
        405
    );
    let too_big = vec![b'x'; 5000];
    assert_eq!(
        request(
            server.addr,
            "POST",
            "/_friend/remember/status",
            &[],
            Some(&too_big)
        )
        .await
        .status,
        413
    );
}

#[tokio::test]
async fn without_both_settings_or_with_an_outside_target_nothing_is_forwarded() {
    for overrides in [
        vec![("APP_PROXY_PREFIX", "/_friend/remember/")],
        vec![
            ("APP_PROXY_PREFIX", "/_friend/remember/"),
            ("APP_PROXY_TARGET", "192.168.1.5:80"),
        ],
        vec![
            ("APP_PROXY_PREFIX", "/api/"),
            ("APP_PROXY_TARGET", "127.0.0.1:9"),
        ],
    ] {
        let (_dir, server) = server(&overrides).await;
        assert_eq!(
            request(server.addr, "GET", "/_friend/remember/status", &[], None)
                .await
                .status,
            404
        );
    }
    let (_dir, server) = server(&[
        ("APP_PROXY_PREFIX", "/_friend/remember/"),
        ("APP_PROXY_TARGET", "127.0.0.1:9"),
    ])
    .await;
    assert_eq!(
        request(
            server.addr,
            "POST",
            "/_friend/remember/status",
            &[],
            Some(b"{}")
        )
        .await
        .status,
        502
    );
}

#[tokio::test]
async fn guild_emblems_go_to_the_web_server_and_nothing_else_does() {
    let emblem = "HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\nContent-Length: 6\r\nConnection: close\r\n\r\nGIF89a";
    let (target, web) = fake_app(emblem).await;
    let (_dir, server) = server(&[("WEB_SERVER_TARGET", &target)]).await;
    // An emblem may be 50 KB, more than the app proxy's 4 KiB.
    let form = vec![b'e'; 50_000];
    let response = request(
        server.addr,
        "POST",
        "/emblem/download",
        &[("Content-Type", "multipart/form-data; boundary=x")],
        Some(&form),
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("image/gif"));
    assert_eq!(response.body, b"GIF89a");
    let seen = web.await.unwrap();
    assert!(
        seen.starts_with("POST /emblem/download HTTP/1.1\r\n"),
        "{seen}"
    );
    assert!(
        seen.contains("content-type: multipart/form-data; boundary=x\r\n"),
        "{seen}"
    );

    // Only the two emblem paths, only POST, and not more than 64 KiB.
    assert_eq!(
        request(server.addr, "GET", "/emblem/download", &[], None)
            .await
            .status,
        405
    );
    // Any other web-server path is answered like any POST this server does not
    // route. Without a body: one the server never reads can reset the socket
    // before its reply is read (as below).
    assert_eq!(
        request(server.addr, "POST", "/userconfig/load", &[], None)
            .await
            .status,
        request(server.addr, "POST", "/no/such/route", &[], None)
            .await
            .status
    );
    // Refused on its Content-Length, before any body is read. So send only the
    // headers and close our side: sending the body races the reply (a socket
    // closed with unread data is reset, sometimes before the 413 is read), and
    // leaving it open keeps the server waiting for a body it will never use.
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        let head = format!(
            "POST /emblem/upload HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: 70000\r\n\r\n",
            server.addr
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        let reply = String::from_utf8_lossy(&reply);
        assert!(reply.starts_with("HTTP/1.1 413 "), "{reply}");
    }
}

#[tokio::test]
async fn an_emblem_answer_is_passed_on_without_waiting_for_the_close() {
    let emblem = "HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\nContent-Length: 6\r\nConnection: close\r\n\r\nGIF89a";
    let (target, _web) = fake_app_holding(emblem, Duration::from_secs(30)).await;
    let (_dir, server) = server(&[("WEB_SERVER_TARGET", &target)]).await;
    let started = std::time::Instant::now();
    let response = request(
        server.addr,
        "POST",
        "/emblem/download",
        &[],
        Some(b"GDID=1"),
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"GIF89a");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn emblems_are_not_forwarded_without_a_loopback_web_server() {
    for overrides in [vec![], vec![("WEB_SERVER_TARGET", "192.168.1.5:8888")]] {
        let (_dir, server) = server(&overrides).await;
        // Not routed: a missing file, as without this feature.
        assert_eq!(
            request(server.addr, "GET", "/emblem/download", &[], None)
                .await
                .status,
            404
        );
    }
    let (_dir, server) = server(&[("WEB_SERVER_TARGET", "127.0.0.1:9")]).await;
    let response = request(server.addr, "POST", "/emblem/download", &[], Some(b"{}")).await;
    assert_eq!(response.status, 502);
}

/// A 64x64 24-bit BMP with enough detail that a lossy WebP is much smaller.
fn noisy_bmp() -> Vec<u8> {
    let (w, h) = (64u32, 64u32);
    let mut out = Vec::new();
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(54 + w * h * 3).to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&54u32.to_le_bytes());
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&w.to_le_bytes());
    out.extend_from_slice(&h.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&24u16.to_le_bytes());
    out.extend_from_slice(&[0; 24]);
    for y in 0..h {
        for x in 0..w {
            let n = ((x * 7 + y * 13) % 17) as u8;
            out.extend_from_slice(&[128 + n, (y * 4) as u8, (x * 4) as u8 ^ n]);
        }
    }
    out
}

async fn picture_server(overrides: &[(&str, &str)]) -> (TempDir, TestServer) {
    let dir = TempDir::new("compact");
    GrfBuilder::new()
        .file("data\\texture\\wall.bmp", &noisy_bmp())
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);
    let client = client_for(&dir.path, overrides);
    let cfg = config_for(&dir.path, overrides);
    let server = TestServer::start(cfg, client, json!({ "status": "ok" })).await;
    (dir, server)
}

#[tokio::test]
async fn a_request_for_compact_images_gets_a_smaller_webp_with_its_own_etag() {
    let (_dir, server) = picture_server(&[]).await;
    let headers = [
        ("X-Compact-Images", "1"),
        ("Accept-Encoding", "gzip, deflate, br"),
    ];
    let response = request(server.addr, "GET", "/data/texture/wall.bmp", &headers, None).await;

    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("image/webp"));
    assert_eq!(response.header("content-encoding"), None);
    assert_eq!(
        response.header("vary"),
        Some("Accept-Encoding, X-Compact-Images")
    );
    assert_eq!(&response.body[..4], b"RIFF");
    assert_eq!(&response.body[8..12], b"WEBP");
    assert!(response.body.len() < noisy_bmp().len() / 2);
    let etag = response.header("etag").unwrap().to_string();
    assert!(etag.ends_with("-w85\""), "{etag}");

    let again = request(
        server.addr,
        "GET",
        "/data/texture/wall.bmp",
        &[("X-Compact-Images", "1"), ("If-None-Match", &etag)],
        None,
    )
    .await;
    assert_eq!(again.status, 304);
    assert_eq!(again.header("etag"), Some(etag.as_str()));
}

#[tokio::test]
async fn without_the_header_a_picture_is_sent_exactly() {
    let (_dir, server) = picture_server(&[]).await;
    let response = request(server.addr, "GET", "/data/texture/wall.bmp", &[], None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("image/bmp"));
    assert_eq!(response.body, noisy_bmp());
}

#[tokio::test]
async fn compact_images_can_be_switched_off() {
    let (_dir, server) = picture_server(&[("COMPACT_IMAGE_QUALITY", "0")]).await;
    let response = request(
        server.addr,
        "GET",
        "/data/texture/wall.bmp",
        &[("X-Compact-Images", "1")],
        None,
    )
    .await;
    assert_eq!(response.header("content-type"), Some("image/bmp"));
    assert_eq!(response.body, noisy_bmp());
}
