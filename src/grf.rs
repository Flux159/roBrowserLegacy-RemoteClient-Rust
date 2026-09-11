//! GRF archive reader.
//!
//! The file table is parsed once at startup; bodies are read by seeking into
//! the archive per request.  A retail `data.grf` is 2-4 GB — it is never mapped
//! or buffered whole.

use std::fs::File;
use std::io::{self, Read};
use std::ops::Range;
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;

use crate::des;
use crate::encoding::{detect_best_encoding, FilenameEncoding};

pub const HEADER_SIZE: u64 = 46;
/// The two signatures a GRF is written with.
///
/// "Master of Magic" is the retail one and fills all 15 bytes.  "Event
/// Horizon" is what GRF Editor writes for the 0x300 container, and it is
/// shorter — the bytes after its NUL terminator carry other data (observed:
/// `Event Horizon\0c\0` in one archive and `Event Horizon\0RL` in another
/// from the same client), so the signature has to be compared as a
/// NUL-terminated string rather than against a fixed 15 bytes.
const HEADER_SIGNATURES: [&str; 2] = ["Master of Magic", "Event Horizon"];
const FILE_TABLE_HEADER_SIZE: u64 = 8;

const FILELIST_TYPE_FILE: u8 = 0x01;
const FILELIST_TYPE_ENCRYPT_MIXED: u8 = 0x02;
const FILELIST_TYPE_ENCRYPT_HEADER: u8 = 0x04;

/// Biases Gravity added to two of the length fields in a 0x1xx file table.
/// They are not checksums and they mean nothing; they are simply subtracted
/// back off, as every reader of the format does.
const LEGACY_LENGTH_BIAS: i64 = 715;
const LEGACY_ALIGNED_BIAS: i64 = 37579;
/// Fixed part of a 0x1xx entry: the three lengths, the type byte and the
/// offset, all of which follow the filename block.
const LEGACY_ENTRY_DATA_SIZE: usize = 17;

/// Matches the reference loader's guardrails, so an archive that loads there
/// loads here and one that is rejected there is rejected here.
const MAX_FILE_UNCOMPRESSED_BYTES: u32 = 256 * 1024 * 1024;
const MAX_ENTRIES: u64 = 500_000;
const MAX_FILE_TABLE_BYTES: u64 = 512 * 1024 * 1024;
const AUTO_DETECT_THRESHOLD: f64 = 0.01;
const DETECT_SAMPLE_COUNT: usize = 200;

#[derive(Clone, Copy, Debug)]
pub struct GrfEntry {
    pub offset: u64,
    pub compressed_size: u32,
    pub length_aligned: u32,
    pub real_size: u32,
    pub kind: u8,
}

impl GrfEntry {
    pub fn is_encrypted(&self) -> bool {
        self.kind & (FILELIST_TYPE_ENCRYPT_MIXED | FILELIST_TYPE_ENCRYPT_HEADER) != 0
    }
}

/// One parsed entry: the name as the archive spells it, plus where the bytes
/// live.  `raw_name` is kept because the mojibake spelling is derived from the
/// bytes, not from the decoded string.
pub struct GrfFile {
    pub name: String,
    pub entry: GrfEntry,
}

pub struct GrfStats {
    pub file_count: usize,
    pub bad_name_count: usize,
    pub non_utf8_name_count: usize,
    pub non_utf8_samples: Vec<String>,
    pub encrypted_count: usize,
    pub detected_encoding: FilenameEncoding,
    pub table_compressed_size: u32,
    pub table_real_size: u32,
}

pub struct Grf {
    pub path: PathBuf,
    pub file_name: String,
    pub version: u32,
    pub files: Vec<GrfFile>,
    pub stats: GrfStats,
    pub(crate) handle: File,
    /// Kept so a length read out of the file table can be sanity-checked before
    /// it is used to size an allocation.
    pub(crate) size: u64,
}

#[derive(Debug)]
pub enum GrfError {
    Io(io::Error),
    InvalidSignature(String),
    UnsupportedVersion(u32),
    LimitExceeded(String),
    CorruptTable(String),
}

impl std::fmt::Display for GrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrfError::Io(e) => write!(f, "{e}"),
            GrfError::InvalidSignature(s) => write!(f, "Invalid signature: \"{s}\""),
            GrfError::UnsupportedVersion(v) => write!(
                f,
                "Version 0x{v:X} is not supported (expected: 0x1xx, 0x200 or 0x300)"
            ),
            GrfError::LimitExceeded(s) => write!(f, "{s}"),
            GrfError::CorruptTable(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for GrfError {}

impl From<io::Error> for GrfError {
    fn from(e: io::Error) -> Self {
        GrfError::Io(e)
    }
}

fn read_at(file: &File, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    read_exact_at(file, &mut buf, offset)?;
    Ok(buf)
}

#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut total = 0usize;
    while total < buf.len() {
        let n = file.seek_read(&mut buf[total..], offset + total as u64)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }
        total += n;
    }
    Ok(())
}

fn u32_le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

struct Header {
    version: u32,
    file_table_offset: u64,
    file_count: u64,
}

fn parse_header(bytes: &[u8]) -> Result<Header, GrfError> {
    if bytes.len() < HEADER_SIZE as usize {
        return Err(GrfError::CorruptTable(
            "Header too small (<46 bytes)".into(),
        ));
    }

    let signature: String = bytes[0..15]
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect();
    if !HEADER_SIGNATURES.contains(&signature.as_str()) {
        return Err(GrfError::InvalidSignature(signature));
    }

    let version = u32_le(bytes, 42);

    let parse_200 = |bytes: &[u8]| {
        let table_offset = u32_le(bytes, 30) as u64 + HEADER_SIZE;
        let reserved = u32_le(bytes, 34) as i64;
        let count = u32_le(bytes, 38) as i64 - reserved - 7;
        (table_offset, count.max(0) as u64)
    };

    // 0x1xx puts the same three fields in the same three places; only the
    // file table itself is laid out differently.  Accept the whole range,
    // because the client and rAthena both switch on the major byte alone.
    if version >> 8 == 0x01 {
        let (file_table_offset, file_count) = parse_200(bytes);
        return Ok(Header {
            version,
            file_table_offset,
            file_count,
        });
    }

    if version != 0x200 && version != 0x300 {
        return Err(GrfError::UnsupportedVersion(version));
    }

    if version == 0x200 {
        let (file_table_offset, file_count) = parse_200(bytes);
        return Ok(Header {
            version,
            file_table_offset,
            file_count,
        });
    }

    // 0x300: [table_offset:u64][filecount:u32][version:u32].
    let low = u32_le(bytes, 30) as u64;
    let high = u32_le(bytes, 34) as u64;

    // GRF Editor's heuristic: the upper three bytes of the high word must be
    // zero.  Archives mis-tagged as 0x300 but written with the 0x200 layout are
    // common enough that the reference implementation checks for this, and a
    // wrong guess here means the table offset lands in the middle of nowhere.
    if (high >> 8) != 0 {
        let (file_table_offset, file_count) = parse_200(bytes);
        return Ok(Header {
            version: 0x200,
            file_table_offset,
            file_count,
        });
    }

    Ok(Header {
        version,
        file_table_offset: (high << 32) + low + HEADER_SIZE,
        file_count: u32_le(bytes, 38) as u64,
    })
}

/// Collect filenames for encoding detection.
///
/// The reference loader samples the first 200 entries and stops.  That is a
/// coin toss on a sorted file table: ASCII names sort before CP949 ones, so an
/// archive whose Korean paths all live past entry 200 is declared UTF-8, its
/// names decode to a run of U+FFFD, and every Korean asset in it becomes
/// unreachable — the exact silent failure the format is prone to.
///
/// Walking the whole table costs one pass over a few megabytes that has to be
/// read anyway, so this samples names that actually carry high bytes wherever
/// they are.  On an archive where the reference guesses right, this agrees with
/// it; where it guesses blind, this does not.
fn sample_names<'a>(data: &'a [u8], entries: &[(Range<usize>, GrfEntry)]) -> Vec<&'a [u8]> {
    entries
        .iter()
        .map(|(name, _)| &data[name.clone()])
        .filter(|name| name.iter().any(|&b| b > 0x7F))
        .take(DETECT_SAMPLE_COUNT)
        .collect()
}

/// Walk a decompressed 0x200/0x300 file table.
///
/// Names are NUL-terminated and stored in the clear; the fixed-size entry data
/// follows each one.  0x300 widens the offset to 64 bits and nothing else.
fn read_modern_table(
    data: &[u8],
    file_count: u64,
    version: u32,
) -> Result<Vec<(Range<usize>, GrfEntry)>, GrfError> {
    let entry_data_size = if version == 0x300 { 21 } else { 17 };
    let mut out = Vec::with_capacity(file_count as usize);
    let mut p = 0usize;

    for i in 0..file_count {
        if p >= data.len() {
            return Err(GrfError::CorruptTable(format!(
                "Unexpected end of file table at entry {i}"
            )));
        }

        let mut end = p;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }
        let name = p..end;
        p = end + 1;

        if p + entry_data_size > data.len() {
            return Err(GrfError::CorruptTable(format!(
                "Incomplete entry data at entry {i}"
            )));
        }

        let entry = GrfEntry {
            compressed_size: u32_le(data, p),
            length_aligned: u32_le(data, p + 4),
            real_size: u32_le(data, p + 8),
            kind: data[p + 12],
            offset: if version == 0x300 {
                let low = u32_le(data, p + 13) as u64;
                let high = u32_le(data, p + 17) as u64;
                (high << 32) + low
            } else {
                u32_le(data, p + 13) as u64
            },
        };
        p += entry_data_size;
        out.push((name, entry));
    }

    Ok(out)
}

/// Undo the filename obfuscation on a 0x1xx entry, in place.
///
/// Each 8-byte block is nibble-swapped and then put through the same one-round
/// transform the entry bodies use.  A trailing block that does not fit is left
/// alone rather than read past the end of the table.
fn decode_filename(buf: &mut [u8], len: usize) {
    let mut at = 0usize;
    while at < len && at + 8 <= buf.len() {
        let block = &mut buf[at..at + 8];
        for byte in block.iter_mut() {
            *byte = byte.rotate_right(4);
        }
        des::decode_header(block, 8);
        at += 8;
    }
}

/// Which encryption mode a 0x1xx entry was written with.
///
/// The format records no flag for it: every file is encrypted, and the client
/// picks the mode from the extension, so a reader has to do the same.  These
/// four are the ones Gravity streamed rather than decrypted whole.
fn is_full_encrypt(name: &[u8]) -> bool {
    const HEADER_ONLY: [&[u8; 4]; 4] = [b".gnd", b".gat", b".act", b".str"];
    match name.iter().rposition(|&b| b == b'.') {
        Some(dot) => {
            let ext = &name[dot..];
            !HEADER_ONLY.iter().any(|candidate| {
                ext.len() == candidate.len()
                    && ext
                        .iter()
                        .zip(candidate.iter())
                        .all(|(a, b)| a.eq_ignore_ascii_case(b))
            })
        }
        None => true,
    }
}

/// Walk a 0x1xx file table, decoding filenames in place.
///
/// The table is stored in the clear at the end of the archive, and each entry
/// is a length-prefixed obfuscated filename followed by the fixed data:
///
/// ```text
/// u32 name_block_len      whole block, filename included
/// u16 (unused)
/// ..  filename, nibble-swapped and transformed in 8-byte blocks
/// u32 compressed_size + real_size + 715
/// u32 length_aligned + 37579
/// u32 real_size
/// u8  type
/// u32 offset
/// ```
///
/// This is rAthena's `grfio.cpp` reading, field for field, including taking
/// the filename's length from the low byte of the block length.
fn read_legacy_table(
    data: &mut [u8],
    file_count: u64,
) -> Result<Vec<(Range<usize>, GrfEntry)>, GrfError> {
    let mut out = Vec::with_capacity(file_count as usize);
    let mut p = 0usize;

    for i in 0..file_count {
        if p + 4 > data.len() {
            return Err(GrfError::CorruptTable(format!(
                "Unexpected end of file table at entry {i}"
            )));
        }

        let block_len = u32_le(data, p) as usize;
        let name_len = (data[p] as usize).saturating_sub(6);
        let meta = match p.checked_add(4).and_then(|at| at.checked_add(block_len)) {
            Some(meta) if meta + LEGACY_ENTRY_DATA_SIZE <= data.len() => meta,
            _ => {
                return Err(GrfError::CorruptTable(format!(
                    "Incomplete entry data at entry {i}"
                )))
            }
        };

        let name_start = p + 6;
        if name_start + name_len > meta {
            return Err(GrfError::CorruptTable(format!(
                "Filename runs past its own entry at entry {i}"
            )));
        }
        decode_filename(&mut data[name_start..meta], name_len);
        let name_end = data[name_start..name_start + name_len]
            .iter()
            .position(|&b| b == 0)
            .map_or(name_start + name_len, |at| name_start + at);

        let real_size = u32_le(data, meta + 8);
        let compressed_size = u32_le(data, meta) as i64 - real_size as i64 - LEGACY_LENGTH_BIAS;
        let length_aligned = u32_le(data, meta + 4) as i64 - LEGACY_ALIGNED_BIAS;
        let mut kind = data[meta + 12];

        // A length the biases underflow is not a file anyone can read. Drop the
        // file bit rather than the entry, so the name still reaches encoding
        // detection and the startup report still counts it.
        if compressed_size < 0 || length_aligned < 0 {
            kind &= !FILELIST_TYPE_FILE;
        } else if kind & FILELIST_TYPE_FILE != 0 {
            kind |= if is_full_encrypt(&data[name_start..name_end]) {
                FILELIST_TYPE_ENCRYPT_MIXED
            } else {
                FILELIST_TYPE_ENCRYPT_HEADER
            };
        }

        out.push((
            name_start..name_end,
            GrfEntry {
                offset: u32_le(data, meta + 13) as u64,
                compressed_size: compressed_size.max(0) as u32,
                length_aligned: length_aligned.max(0) as u32,
                real_size,
                kind,
            },
        ));
        p = meta + LEGACY_ENTRY_DATA_SIZE;
    }

    Ok(out)
}

impl Grf {
    pub fn open(path: &Path) -> Result<Grf, GrfError> {
        Grf::open_with_encoding(path, None)
    }

    /// `forced_encoding` overrides auto-detection, for a deployment that
    /// knows what its archives contain and does not want it guessed.
    pub fn open_with_encoding(
        path: &Path,
        forced_encoding: Option<FilenameEncoding>,
    ) -> Result<Grf, GrfError> {
        let handle = File::open(path)?;
        let size = handle.metadata()?.len();
        let header_bytes = read_at(&handle, 0, HEADER_SIZE as usize)?;
        let header = parse_header(&header_bytes)?;

        if header.file_count > MAX_ENTRIES {
            return Err(GrfError::LimitExceeded(format!(
                "File count {} exceeds limit {}",
                header.file_count, MAX_ENTRIES
            )));
        }

        // 0x300 puts an extra 4-byte field in front of the table header.
        let table_skip: u64 = if header.version == 0x300 { 4 } else { 0 };
        let table_pos = header.file_table_offset + table_skip;

        // 0x1xx keeps its file table in the clear, running from here to the end
        // of the archive with no size header in front of it. 0x200 and 0x300
        // compress it behind one.
        let legacy = header.version >> 8 == 0x01;

        let (mut data, compressed_size, real_size) = if legacy {
            if table_pos > size {
                return Err(GrfError::CorruptTable(format!(
                    "File table starts past the end of the archive (at {table_pos})"
                )));
            }
            let length = size - table_pos;
            if length == 0 {
                return Err(GrfError::CorruptTable("Empty file table".into()));
            }
            if length > MAX_FILE_TABLE_BYTES {
                return Err(GrfError::CorruptTable(format!(
                    "Uncompressed file table too large ({length} bytes)"
                )));
            }
            let data = read_at(&handle, table_pos, length as usize)?;
            (data, length as u32, length as u32)
        } else {
            let table_header = read_at(&handle, table_pos, FILE_TABLE_HEADER_SIZE as usize)?;
            let compressed_size = u32_le(&table_header, 0);
            let real_size = u32_le(&table_header, 4);

            if compressed_size == 0 || real_size == 0 {
                return Err(GrfError::CorruptTable(
                    "Invalid file table sizes (0)".into(),
                ));
            }
            if real_size as u64 > MAX_FILE_TABLE_BYTES {
                return Err(GrfError::CorruptTable(format!(
                    "Uncompressed file table too large ({real_size} bytes)"
                )));
            }
            // A length out of a corrupt header would otherwise be believed all
            // the way to a multi-gigabyte allocation that the read then fails
            // anyway.
            if table_pos + FILE_TABLE_HEADER_SIZE + compressed_size as u64 > size {
                return Err(GrfError::CorruptTable(format!(
                    "File table runs past the end of the archive ({compressed_size} bytes at {table_pos})"
                )));
            }

            let compressed = read_at(
                &handle,
                table_pos + FILE_TABLE_HEADER_SIZE,
                compressed_size as usize,
            )?;

            let mut data = Vec::with_capacity(real_size as usize);
            ZlibDecoder::new(&compressed[..])
                .read_to_end(&mut data)
                .map_err(|e| {
                    GrfError::CorruptTable(format!("Failed to decompress file table: {e}"))
                })?;

            if data.len() != real_size as usize {
                return Err(GrfError::CorruptTable(format!(
                    "File table size mismatch: expected {}, got {}",
                    real_size,
                    data.len()
                )));
            }
            (data, compressed_size, real_size)
        };

        let entries = if legacy {
            read_legacy_table(&mut data, header.file_count)?
        } else {
            read_modern_table(&data, header.file_count, header.version)?
        };

        let detected_encoding = match forced_encoding {
            Some(encoding) => encoding,
            None => {
                let samples = sample_names(&data, &entries);
                detect_best_encoding(&samples, AUTO_DETECT_THRESHOLD)
            }
        };

        let mut files: Vec<GrfFile> = Vec::with_capacity(entries.len());
        let mut bad_name_count = 0usize;
        let mut non_utf8_name_count = 0usize;
        let mut non_utf8_samples: Vec<String> = Vec::new();
        let mut encrypted_count = 0usize;

        for (name_range, entry) in entries {
            if entry.real_size > MAX_FILE_UNCOMPRESSED_BYTES {
                continue;
            }
            if entry.kind & FILELIST_TYPE_FILE == 0 {
                continue;
            }
            let raw_name = &data[name_range];

            // Non-UTF-8 names are the norm for kRO archives.  Reported, not
            // treated as an error — this is what the startup report shows so
            // that operators do not go looking for a fault that is not there.
            if std::str::from_utf8(raw_name).is_err() {
                non_utf8_name_count += 1;
                if non_utf8_samples.len() < 5 {
                    non_utf8_samples.push(crate::encoding::latin1_decode(raw_name));
                }
            }

            let name = detected_encoding.decode(raw_name);
            if crate::encoding::count_bad_chars(&name) > 0 {
                bad_name_count += 1;
            }

            if entry.is_encrypted() {
                encrypted_count += 1;
            }

            files.push(GrfFile { name, entry });
        }

        let file_name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned());

        let stats = GrfStats {
            file_count: files.len(),
            bad_name_count,
            non_utf8_name_count,
            non_utf8_samples,
            encrypted_count,
            detected_encoding,
            table_compressed_size: compressed_size,
            table_real_size: real_size,
        };

        Ok(Grf {
            path: path.to_path_buf(),
            file_name,
            version: header.version,
            files,
            stats,
            handle,
            size,
        })
    }

    /// Read and decode one entry.  Blocking: call from a blocking context.
    pub fn read_entry(&self, entry: &GrfEntry) -> io::Result<Vec<u8>> {
        if entry.length_aligned == 0 {
            return Ok(Vec::new());
        }

        // `length_aligned` is a 32-bit field out of the archive's own table.  A
        // corrupt one would have us allocate up to 4 GB for a read that cannot
        // succeed, so check the range against the file first.
        let end = entry
            .offset
            .checked_add(HEADER_SIZE)
            .and_then(|start| start.checked_add(entry.length_aligned as u64));
        match end {
            Some(end) if end <= self.size => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "entry at {} runs past the end of {}",
                        entry.offset, self.file_name
                    ),
                ))
            }
        }

        let mut data = read_at(
            &self.handle,
            entry.offset + HEADER_SIZE,
            entry.length_aligned as usize,
        )?;

        if entry.kind & FILELIST_TYPE_ENCRYPT_MIXED != 0 {
            des::decode_full(
                &mut data,
                entry.length_aligned as usize,
                entry.compressed_size,
            );
        } else if entry.kind & FILELIST_TYPE_ENCRYPT_HEADER != 0 {
            des::decode_header(&mut data, entry.length_aligned as usize);
        }

        // Stored uncompressed.  `length_aligned` may carry padding past the
        // real content, which must not reach the client.
        if entry.real_size == entry.compressed_size {
            data.truncate(entry.real_size as usize);
            return Ok(data);
        }

        let mut out = Vec::with_capacity(entry.real_size as usize);
        ZlibDecoder::new(&data[..]).read_to_end(&mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_both_signatures_and_rejects_others() {
        let mut b = header_bytes(0x200, 8, 0, 7);
        assert!(parse_header(&b).is_ok());

        // Shorter than the field, with live bytes after the terminator.
        b[0..15].copy_from_slice(b"Event Horizon\0c");
        assert!(parse_header(&b).is_ok(), "Event Horizon should be accepted");

        b[0..15].copy_from_slice(b"Sword of Chaos!");
        match parse_header(&b) {
            Err(GrfError::InvalidSignature(s)) => assert_eq!(s, "Sword of Chaos!"),
            Err(e) => panic!("expected InvalidSignature, got {e}"),
            Ok(_) => panic!("expected InvalidSignature, got a parsed header"),
        }
    }

    fn header_bytes(version: u32, table_offset: u32, seed: u32, n_files: u32) -> Vec<u8> {
        let mut b = vec![0u8; 46];
        b[0..15].copy_from_slice(HEADER_SIGNATURES[0].as_bytes());
        b[30..34].copy_from_slice(&table_offset.to_le_bytes());
        b[34..38].copy_from_slice(&seed.to_le_bytes());
        b[38..42].copy_from_slice(&n_files.to_le_bytes());
        b[42..46].copy_from_slice(&version.to_le_bytes());
        b
    }

    #[test]
    fn parses_a_0x200_header() {
        let h = parse_header(&header_bytes(0x200, 1000, 0, 110)).unwrap();
        assert_eq!(h.version, 0x200);
        assert_eq!(h.file_table_offset, 1000 + 46);
        // count - seed - 7
        assert_eq!(h.file_count, 103);
    }

    #[test]
    fn rejects_a_bad_signature() {
        let mut b = header_bytes(0x200, 0, 0, 10);
        b[0] = b'X';
        assert!(matches!(
            parse_header(&b),
            Err(GrfError::InvalidSignature(_))
        ));
    }

    #[test]
    fn rejects_unsupported_versions() {
        let b = header_bytes(0x400, 0, 0, 10);
        assert!(matches!(
            parse_header(&b),
            Err(GrfError::UnsupportedVersion(0x400))
        ));
    }

    #[test]
    fn parses_every_0x1xx_header_like_a_0x200_one() {
        // The client and rAthena both switch on the major byte alone, and the
        // three header fields sit where 0x200 puts them.
        for version in [0x100, 0x101, 0x102, 0x103] {
            let h = parse_header(&header_bytes(version, 1000, 0, 110)).unwrap();
            assert_eq!(h.version, version);
            assert_eq!(h.file_table_offset, 1000 + 46);
            assert_eq!(h.file_count, 103);
        }
    }

    #[test]
    fn the_encryption_mode_of_a_0x1xx_entry_comes_from_its_extension() {
        for streamed in ["data\\prontera.gnd", "data\\a.GAT", "x.act", "x.str"] {
            assert!(
                !is_full_encrypt(streamed.as_bytes()),
                "{streamed} is header-encrypted"
            );
        }
        for whole in ["data\\prontera.rsw", "a.bmp", "data\\noextension"] {
            assert!(
                is_full_encrypt(whole.as_bytes()),
                "{whole} is fully encrypted"
            );
        }
    }

    #[test]
    fn a_0x1xx_filename_round_trips_through_the_obfuscation() {
        // The transform is its own inverse applied in the opposite order, which
        // is what the test archive writer relies on.
        let mut buf = *b"data\\prontera.rsw\0\0\0\0\0\0";
        let original = buf;
        let len = buf.len() & !7;
        decode_filename(&mut buf, len);
        assert_ne!(buf[..len], original[..len]);
        // Encoding is the same two steps in the other order.
        let mut at = 0;
        while at + 8 <= len {
            des::decode_header(&mut buf[at..at + 8], 8);
            for byte in &mut buf[at..at + 8] {
                *byte = byte.rotate_right(4);
            }
            at += 8;
        }
        assert_eq!(buf, original);
    }

    #[test]
    fn parses_a_0x300_header_with_a_64_bit_offset() {
        let mut b = header_bytes(0x300, 0, 0, 0);
        b[30..34].copy_from_slice(&5000u32.to_le_bytes()); // low
        b[34..38].copy_from_slice(&0u32.to_le_bytes()); // high
        b[38..42].copy_from_slice(&4242u32.to_le_bytes()); // file count, verbatim
        let h = parse_header(&b).unwrap();
        assert_eq!(h.version, 0x300);
        assert_eq!(h.file_table_offset, 5000 + 46);
        assert_eq!(h.file_count, 4242);
    }

    #[test]
    fn falls_back_to_0x200_layout_when_the_high_word_is_implausible() {
        // Bytes 34..38 are the high half of the 0x300 offset and the seed of a
        // 0x200 header at the same time.  A non-zero value above the low byte
        // means this cannot be a real 64-bit offset, so it is a seed.
        let mut b = header_bytes(0x300, 0, 0, 0);
        b[30..34].copy_from_slice(&1000u32.to_le_bytes());
        b[34..38].copy_from_slice(&0x0000_0100u32.to_le_bytes()); // high >> 8 == 1
        b[38..42].copy_from_slice(&400u32.to_le_bytes());
        let h = parse_header(&b).unwrap();
        assert_eq!(h.version, 0x200);
        assert_eq!(h.file_table_offset, 1000 + 46);
        assert_eq!(h.file_count, 400 - 256 - 7);
    }

    #[test]
    fn a_negative_entry_count_clamps_to_zero() {
        let h = parse_header(&header_bytes(0x200, 0, 100, 10)).unwrap();
        assert_eq!(h.file_count, 0);
    }
}
