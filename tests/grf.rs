//! GRF parsing and extraction against synthesised archives.

mod support;

use robrowser_remoteclient::encoding::{cp949_encode, to_mojibake};
use robrowser_remoteclient::grf::Grf;
use robrowser_remoteclient::index::AssetIndex;
use support::{GrfBuilder, TempDir};

const KOREAN_PATH: &str = "data\\sprite\\인간족\\검사\\검사_남_1460.act";
const UI_PATH: &str = "data\\texture\\유저인터페이스\\basic_interface\\btn_ok.bmp";

fn sample_archive() -> GrfBuilder {
    GrfBuilder::new()
        .file("data\\plain.txt", b"plain contents")
        .file(KOREAN_PATH, b"korean act payload")
        .file(UI_PATH, &vec![0x42u8; 4096])
        .stored_file("data\\stored.bin", b"stored without compression")
        .directory("data\\somedir")
}

#[test]
fn reads_a_v200_archive() {
    let dir = TempDir::new("grf-v200");
    let path = dir.join("test.grf");
    sample_archive().write_v200(&path);

    let grf = Grf::open(&path).unwrap();
    assert_eq!(grf.version, 0x200);
    // The directory entry is skipped; the four files are not.
    assert_eq!(grf.files.len(), 4);
    assert_eq!(grf.stats.detected_encoding.as_str(), "cp949");

    let plain = grf
        .files
        .iter()
        .find(|f| f.name == "data\\plain.txt")
        .unwrap();
    assert_eq!(grf.read_entry(&plain.entry).unwrap(), b"plain contents");

    let korean = grf.files.iter().find(|f| f.name == KOREAN_PATH).unwrap();
    assert_eq!(
        grf.read_entry(&korean.entry).unwrap(),
        b"korean act payload"
    );
}

#[test]
fn reads_a_v300_archive() {
    let dir = TempDir::new("grf-v300");
    let path = dir.join("test.grf");
    sample_archive().write_v300(&path);

    let grf = Grf::open(&path).unwrap();
    assert_eq!(grf.version, 0x300);
    assert_eq!(grf.files.len(), 4);

    let ui = grf.files.iter().find(|f| f.name == UI_PATH).unwrap();
    assert_eq!(grf.read_entry(&ui.entry).unwrap(), vec![0x42u8; 4096]);
}

#[test]
fn reads_an_event_horizon_archive() {
    // GRF Editor writes 0x300 archives signed "Event Horizon" rather than
    // "Master of Magic". The container is the one already supported -- only
    // the signature differs -- so rejecting it turned away whole modern
    // clients over 13 bytes.
    let dir = TempDir::new("grf-eh3");
    let path = dir.join("eh.grf");
    sample_archive().write_v300_event_horizon(&path);

    let grf = Grf::open(&path).expect("Event Horizon archive should load");
    assert_eq!(grf.version, 0x300);
    assert_eq!(grf.files.len(), 4);
}

#[test]
fn an_uncompressed_entry_is_returned_without_padding() {
    let dir = TempDir::new("grf-stored");
    let path = dir.join("test.grf");
    sample_archive().write_v200(&path);

    let grf = Grf::open(&path).unwrap();
    let stored = grf
        .files
        .iter()
        .find(|f| f.name == "data\\stored.bin")
        .unwrap();
    assert_eq!(
        grf.read_entry(&stored.entry).unwrap(),
        b"stored without compression"
    );
}

#[test]
fn korean_names_decode_to_unicode_not_mojibake() {
    let dir = TempDir::new("grf-names");
    let path = dir.join("test.grf");
    sample_archive().write_v200(&path);

    let grf = Grf::open(&path).unwrap();
    let names: Vec<&str> = grf.files.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&KOREAN_PATH), "got {names:?}");
    assert_eq!(grf.stats.non_utf8_name_count, 2);
    assert!(!grf.stats.non_utf8_samples.is_empty());
}

#[test]
fn a_truncated_archive_is_rejected_rather_than_panicking() {
    let dir = TempDir::new("grf-truncated");
    let path = dir.join("test.grf");
    sample_archive().write_v200(&path);

    let full = std::fs::read(&path).unwrap();
    std::fs::write(&path, &full[..full.len() - 40]).unwrap();

    assert!(Grf::open(&path).is_err());
}

#[test]
fn a_non_grf_file_is_rejected() {
    let dir = TempDir::new("grf-garbage");
    let path = dir.join("not.grf");
    std::fs::write(&path, vec![0u8; 200]).unwrap();
    assert!(Grf::open(&path).is_err());
}

/// The specification's headline failure mode: all four spellings of a Korean
/// path must return identical bytes, or the client renders a world with no
/// sprites in it and reports nothing.
#[test]
fn all_four_spellings_return_identical_bytes() {
    let dir = TempDir::new("grf-spellings");
    let path = dir.join("test.grf");
    sample_archive().write_v200(&path);

    let grf = Grf::open(&path).unwrap();
    let index = AssetIndex::build(std::slice::from_ref(&grf));

    let stored = KOREAN_PATH; // backslashes, Korean
    let forward = stored.replace('\\', "/");
    let moji_back = to_mojibake(stored);
    let moji_forward = to_mojibake(&forward);

    let mut payloads = Vec::new();
    for spelling in [stored, &forward, &moji_back, &moji_forward] {
        let hit = index
            .lookup(spelling)
            .unwrap_or_else(|| panic!("no index hit for {spelling}"));
        payloads.push(grf.read_entry(&hit.entry).unwrap());
    }

    assert!(payloads.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(payloads[0], b"korean act payload");
}

#[test]
fn the_mojibake_spelling_is_the_raw_cp949_bytes_as_latin1() {
    // This is the invariant the whole index rests on.
    let raw = cp949_encode(KOREAN_PATH);
    let as_latin1: String = raw.iter().map(|&b| b as char).collect();
    assert_eq!(to_mojibake(KOREAN_PATH), as_latin1);
}

/// Regression: file tables are usually sorted, and CP949 bytes sort after
/// ASCII.  An archive whose Korean names all live past the first couple of
/// hundred entries must still be recognised as CP949, or every one of those
/// names decodes to replacement characters and the files become unreachable.
#[test]
fn korean_names_late_in_the_table_are_still_detected() {
    let dir = TempDir::new("grf-late-korean");
    let path = dir.join("late.grf");

    let mut builder = GrfBuilder::new();
    for i in 0..400 {
        builder = builder.file(&format!("data\\ascii\\file_{i:04}.txt"), b"ascii");
    }
    builder = builder.file(KOREAN_PATH, b"korean payload");
    builder.write_v200(&path);

    let grf = Grf::open(&path).unwrap();
    assert_eq!(grf.stats.detected_encoding.as_str(), "cp949");
    assert_eq!(grf.stats.bad_name_count, 0);

    let index = AssetIndex::build(std::slice::from_ref(&grf));
    let hit = index.lookup(&to_mojibake(&KOREAN_PATH.replace('\\', "/")));
    assert!(hit.is_some(), "the late Korean name is unreachable");
    assert_eq!(
        grf.read_entry(&hit.unwrap().entry).unwrap(),
        b"korean payload"
    );
}

#[test]
fn a_pure_ascii_archive_reads_as_utf8() {
    let dir = TempDir::new("grf-ascii");
    let path = dir.join("ascii.grf");
    GrfBuilder::new()
        .file("data\\a.txt", b"a")
        .file("data\\b.txt", b"b")
        .write_v200(&path);

    let grf = Grf::open(&path).unwrap();
    assert_eq!(grf.stats.detected_encoding.as_str(), "utf-8");
    assert_eq!(grf.stats.non_utf8_name_count, 0);
}

#[test]
fn des_encrypted_entries_decrypt_in_both_modes() {
    let dir = TempDir::new("grf-des");
    let path = dir.join("enc.grf");

    // Long enough to run past the first twenty blocks, where mode 0 starts
    // interleaving byte-shuffled blocks with DES ones.
    let payload: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8).collect();

    GrfBuilder::new()
        .encrypted_file("data\\mixed.spr", &payload, true)
        .encrypted_file("data\\header.spr", &payload, false)
        .encrypted_file(KOREAN_PATH, b"short encrypted korean entry", true)
        .file("data\\plain.txt", b"unencrypted neighbour")
        .write_v200(&path);

    let grf = Grf::open(&path).unwrap();
    assert_eq!(grf.stats.encrypted_count, 3);

    for name in ["data\\mixed.spr", "data\\header.spr"] {
        let entry = grf.files.iter().find(|f| f.name == name).unwrap();
        assert_eq!(grf.read_entry(&entry.entry).unwrap(), payload, "{name}");
    }

    let korean = grf.files.iter().find(|f| f.name == KOREAN_PATH).unwrap();
    assert_eq!(
        grf.read_entry(&korean.entry).unwrap(),
        b"short encrypted korean entry"
    );

    // The unencrypted entry beside them is unaffected.
    let plain = grf
        .files
        .iter()
        .find(|f| f.name == "data\\plain.txt")
        .unwrap();
    assert_eq!(
        grf.read_entry(&plain.entry).unwrap(),
        b"unencrypted neighbour"
    );
}

/// A GRF entry carries no flag for "stored uncompressed"; the only signal is
/// `real_size == compressed_size`.  A deflate stream that happens to come out
/// the same length as its input is therefore served raw — by this server and by
/// the reference alike.  Writers avoid it by storing whenever deflating does
/// not help.  Pinned here so the ambiguity is not mistaken for a defect.
#[test]
fn equal_sizes_mean_stored_not_deflated() {
    let dir = TempDir::new("grf-ambiguous");
    let path = dir.join("ambiguous.grf");

    // A zlib stream, stored verbatim: sizes match, so it comes back as-is.
    let zlib_stream: &[u8] = &[
        0x78, 0x9c, 0x63, 0x60, 0x80, 0x03, 0x00, 0x00, 0x0b, 0x00, 0x01,
    ];
    GrfBuilder::new()
        .stored_file("data\\looks-compressed.bin", zlib_stream)
        .write_v200(&path);

    let grf = Grf::open(&path).unwrap();
    let entry = &grf.files[0];
    assert_eq!(entry.entry.real_size, entry.entry.compressed_size);
    assert_eq!(grf.read_entry(&entry.entry).unwrap(), zlib_stream);
}

/// A file table is data from a file, and a corrupt entry length would otherwise
/// be believed all the way to a multi-gigabyte allocation for a read that
/// cannot succeed. The failure must be an error about one entry, not an
/// out-of-memory abort that takes the server with it.
#[test]
fn an_entry_pointing_past_the_end_of_the_archive_is_an_error_not_an_allocation() {
    let dir = TempDir::new("grf-oob");
    let path = dir.join("corrupt.grf");
    sample_archive().write_v200(&path);

    let grf = Grf::open(&path).unwrap();
    let good = grf
        .files
        .iter()
        .find(|f| f.name == "data\\plain.txt")
        .unwrap();

    // The entry claims almost the whole 32-bit range.
    let mut corrupt = good.entry;
    corrupt.length_aligned = u32::MAX - 8;
    assert!(grf.read_entry(&corrupt).is_err());

    // So does one whose offset alone is past the end.
    let mut far = good.entry;
    far.offset = u64::MAX - 16;
    assert!(grf.read_entry(&far).is_err());

    // The undamaged entry beside them still reads.
    assert_eq!(grf.read_entry(&good.entry).unwrap(), b"plain contents");
}

#[test]
fn a_file_table_header_pointing_past_the_end_is_rejected() {
    let dir = TempDir::new("grf-bad-table");
    let path = dir.join("bad.grf");
    sample_archive().write_v200(&path);

    let mut bytes = std::fs::read(&path).unwrap();
    // Table offset is a u32 at 30, relative to the end of the 46-byte header.
    let table_offset = u32::from_le_bytes(bytes[30..34].try_into().unwrap()) as usize;
    let table_pos = 46 + table_offset;
    // Claim a compressed table far larger than the file.
    bytes[table_pos..table_pos + 4].copy_from_slice(&(1_000_000_000u32).to_le_bytes());
    std::fs::write(&path, &bytes).unwrap();

    assert!(Grf::open(&path).is_err());
}
