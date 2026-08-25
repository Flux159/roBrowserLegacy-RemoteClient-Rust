//! Asset resolution: precedence between the local filesystem, the override
//! directory and the archives, and the mojibake spellings of a request.

mod support;

use robrowser_remoteclient::client::Source;
use robrowser_remoteclient::encoding::to_mojibake;
use support::{client_for, write_data_ini, GrfBuilder, TempDir};

const KOREAN: &str = "data\\sprite\\인간족\\검사\\검사_남_1460.act";

fn fixture() -> TempDir {
    let dir = TempDir::new("resolution");
    GrfBuilder::new()
        .file("data\\shared.txt", b"from overlay")
        .file("data\\only-overlay.txt", b"overlay only")
        .write_v200(&dir.join("resources/custom.grf"));
    GrfBuilder::new()
        .file("data\\shared.txt", b"from base")
        .file("data\\only-base.txt", b"base only")
        .file(KOREAN, b"korean payload")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["custom.grf", "data.grf"]);
    dir
}

#[test]
fn the_lower_indexed_archive_wins() {
    let dir = fixture();
    let client = client_for(&dir.path, &[]);

    // custom.grf is listed at index 0 and therefore overrides data.grf.
    let (file, source) = client.resolve("data/shared.txt").unwrap();
    assert_eq!(&*file.data, b"from overlay");
    assert_eq!(source, Source::Grf(0));
}

#[test]
fn reversing_data_ini_order_changes_which_archive_answers() {
    let dir = fixture();
    write_data_ini(&dir.path, &["data.grf", "custom.grf"]);
    let client = client_for(&dir.path, &[]);
    let (file, _) = client.resolve("data/shared.txt").unwrap();
    assert_eq!(&*file.data, b"from base");
}

#[test]
fn both_archives_are_reachable() {
    let dir = fixture();
    let client = client_for(&dir.path, &[]);
    assert_eq!(
        &*client.resolve("data/only-overlay.txt").unwrap().0.data,
        b"overlay only"
    );
    assert_eq!(
        &*client.resolve("data/only-base.txt").unwrap().0.data,
        b"base only"
    );
}

#[test]
fn a_loose_local_file_beats_the_archives() {
    let dir = fixture();
    dir.write("data/shared.txt", b"loose on disk");
    let client = client_for(&dir.path, &[]);

    let (file, source) = client.resolve("data/shared.txt").unwrap();
    assert_eq!(&*file.data, b"loose on disk");
    assert_eq!(source, Source::LocalFile);
}

#[test]
fn the_override_directory_beats_the_archives_but_not_local_files() {
    let dir = fixture();
    let overrides = TempDir::new("override");
    // DATA_OVERRIDE_PATH points at a client's data/ folder, so the request's
    // own data/ prefix is stripped before the lookup.
    overrides.write("shared.txt", b"from override");

    let client = client_for(
        &dir.path,
        &[("DATA_OVERRIDE_PATH", overrides.path.to_str().unwrap())],
    );

    let (file, source) = client.resolve("data/shared.txt").unwrap();
    assert_eq!(&*file.data, b"from override");
    assert_eq!(source, Source::DataOverride);
}

#[test]
fn all_four_spellings_resolve_to_the_same_bytes() {
    let dir = fixture();
    let client = client_for(&dir.path, &[]);

    let forward = KOREAN.replace('\\', "/");
    let spellings = [
        KOREAN.to_string(),
        forward.clone(),
        to_mojibake(KOREAN),
        to_mojibake(&forward),
    ];

    let mut etags = Vec::new();
    for spelling in &spellings {
        let (file, _) = client
            .resolve(spelling)
            .unwrap_or_else(|| panic!("no hit for {spelling}"));
        assert_eq!(&*file.data, b"korean payload");
        etags.push(file.etag.to_string());
    }
    assert!(etags.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn a_second_request_is_served_from_the_cache() {
    let dir = fixture();
    let client = client_for(&dir.path, &[]);

    let (_, first) = client.resolve("data/only-base.txt").unwrap();
    assert_eq!(first, Source::Grf(1));
    let (_, second) = client.resolve("data/only-base.txt").unwrap();
    assert_eq!(second, Source::Cache);

    let stats = client.cache_stats();
    assert_eq!(stats.hits, 1);
}

#[test]
fn a_miss_is_recorded_once_and_reported() {
    let dir = fixture();
    let client = client_for(&dir.path, &[]);

    assert!(client.resolve("data/nope.txt").is_none());
    assert!(client.resolve("data/nope.txt").is_none());
    assert!(client.resolve("data/also-nope.txt").is_none());

    let summary = client.missing_summary();
    assert_eq!(summary.total, 2);
    assert_eq!(summary.files[0].requested_path, "data/nope.txt");
    // The log records the backslash spelling the archives would have used.
    assert_eq!(summary.files[0].grf_path, "data\\nope.txt");
}

#[test]
fn traversal_out_of_the_server_root_is_refused() {
    let dir = fixture();
    std::fs::write(dir.path.parent().unwrap().join("outside.txt"), b"secret").unwrap();
    let client = client_for(&dir.path, &[]);
    assert!(client.resolve("../outside.txt").is_none());
    let _ = std::fs::remove_file(dir.path.parent().unwrap().join("outside.txt"));
}

#[test]
fn listing_and_search_use_archive_spelling() {
    let dir = fixture();
    let client = client_for(&dir.path, &[]);

    let files = client.list_files();
    assert!(files.contains(&KOREAN));
    assert!(files.contains(&"data\\shared.txt"));
    // 'shared.txt' exists in both archives but is only reachable once.
    assert_eq!(
        files.iter().filter(|f| f.ends_with("shared.txt")).count(),
        1
    );

    let regex = regex_lite::Regex::new("(?i)only-base").unwrap();
    assert_eq!(client.search(&regex), vec!["data\\only-base.txt"]);
}

#[test]
fn warm_up_populates_keys_the_browser_will_actually_request() {
    let dir = TempDir::new("warmup");
    GrfBuilder::new()
        .file("data\\texture\\유저인터페이스\\login.bmp", &vec![7u8; 2048])
        .file("data\\ignored.dat", b"not a warm-up target")
        .write_v200(&dir.join("resources/data.grf"));
    write_data_ini(&dir.path, &["data.grf"]);

    let client = client_for(&dir.path, &[]);
    let warmed = client.warm_cache(100);
    assert_eq!(warmed, 1);

    // The request the browser sends is the mojibake spelling with slashes.
    let requested = to_mojibake("data/texture/유저인터페이스/login.bmp");
    assert!(client.cached(&requested).is_some());
}

/// Auto-extract is on by default, matching the reference: an asset pulled out
/// of an archive is written beside the server, and the next request for it is
/// answered from disk rather than from the archive.
#[test]
fn an_extracted_asset_is_written_out_and_served_from_disk_next_time() {
    let dir = fixture();
    let client = client_for(&dir.path, &[]);

    let (first, source) = client.resolve("data/only-base.txt").unwrap();
    assert_eq!(source, Source::Grf(1));
    assert_eq!(&*first.data, b"base only");

    let written = dir.path.join("data/only-base.txt");
    assert!(written.is_file(), "nothing was extracted to {written:?}");
    assert_eq!(std::fs::read(&written).unwrap(), b"base only");

    // A fresh client over the same root now finds it without touching a GRF.
    let second = client_for(&dir.path, &[]);
    let (file, source) = second.resolve("data/only-base.txt").unwrap();
    assert_eq!(source, Source::LocalFile);
    assert_eq!(&*file.data, b"base only");
}

#[test]
fn a_korean_asset_is_extracted_under_the_spelling_it_was_requested_by() {
    let dir = fixture();
    let client = client_for(&dir.path, &[]);

    let requested = to_mojibake(&KOREAN.replace('\\', "/"));
    client.resolve(&requested).unwrap();

    let written = dir.path.join(&requested);
    assert!(written.is_file(), "nothing was extracted to {written:?}");
    assert_eq!(std::fs::read(&written).unwrap(), b"korean payload");
}

#[test]
fn auto_extract_can_be_turned_off() {
    let dir = fixture();
    let client = client_for(&dir.path, &[("CLIENT_AUTOEXTRACT", "false")]);

    client.resolve("data/only-base.txt").unwrap();
    assert!(!dir.path.join("data/only-base.txt").exists());
}

/// The reference writes wherever the request path points.  A request is not a
/// trustworthy filename, so a traversal attempt must resolve to nothing and
/// write nothing.
#[test]
fn auto_extract_will_not_write_outside_the_server_root() {
    let dir = fixture();
    let escaped = dir.path.parent().unwrap().join("escaped.txt");
    let _ = std::fs::remove_file(&escaped);

    let client = client_for(&dir.path, &[]);
    assert!(client.resolve("../escaped.txt").is_none());
    assert!(client.resolve("data/../../escaped.txt").is_none());
    assert!(!escaped.exists(), "wrote outside the server root");
}

/// A read-only server root is the normal case for a signed app bundle or a
/// container image. Extraction must degrade to "served from the archive" rather
/// than turning every asset into a failure.
#[cfg(unix)]
#[test]
fn a_read_only_root_still_serves_assets() {
    use std::os::unix::fs::PermissionsExt;

    let dir = fixture();
    let client = client_for(&dir.path, &[]);

    let mut perms = std::fs::metadata(&dir.path).unwrap().permissions();
    let original = perms.mode();
    perms.set_mode(0o555);
    std::fs::set_permissions(&dir.path, perms).unwrap();

    let served = client.resolve("data/only-base.txt");

    let mut restore = std::fs::metadata(&dir.path).unwrap().permissions();
    restore.set_mode(original);
    std::fs::set_permissions(&dir.path, restore).unwrap();

    let (file, source) = served.expect("a read-only root must not stop assets being served");
    assert_eq!(&*file.data, b"base only");
    assert_eq!(source, Source::Grf(1));
}
