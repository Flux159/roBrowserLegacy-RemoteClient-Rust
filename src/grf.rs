//! GRF archive reader.
//!
//! The file table is parsed once at startup; bodies are read by seeking into
//! the archive per request.  A retail `data.grf` is 2-4 GB — it is never mapped
//! or buffered whole.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;

use crate::des;
use crate::encoding::{detect_best_encoding, FilenameEncoding};

pub const HEADER_SIZE: u64 = 46;
const HEADER_SIGNATURE: &[u8; 15] = b"Master of Magic";
const FILE_TABLE_HEADER_SIZE: u64 = 8;

const FILELIST_TYPE_FILE: u8 = 0x01;
const FILELIST_TYPE_ENCRYPT_MIXED: u8 = 0x02;
const FILELIST_TYPE_ENCRYPT_HEADER: u8 = 0x04;

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
                "Version 0x{v:X} is not supported (expected: 0x200 or 0x300)"
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

    if &bytes[0..15] != HEADER_SIGNATURE {
        let shown: String = bytes[0..15]
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        return Err(GrfError::InvalidSignature(shown));
    }

    let version = u32_le(bytes, 42);
    if version != 0x200 && version != 0x300 {
        return Err(GrfError::UnsupportedVersion(version));
    }

    let parse_200 = |bytes: &[u8]| {
        let table_offset = u32_le(bytes, 30) as u64 + HEADER_SIZE;
        let reserved = u32_le(bytes, 34) as i64;
        let count = u32_le(bytes, 38) as i64 - reserved - 7;
        (table_offset, count.max(0) as u64)
    };

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
fn sample_names(data: &[u8], file_count: u64, entry_data_size: usize) -> Vec<&[u8]> {
    let mut samples = Vec::new();
    let mut pos = 0usize;
    for _ in 0..file_count {
        if pos >= data.len() || samples.len() >= DETECT_SAMPLE_COUNT {
            break;
        }
        let mut end = pos;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }
        if data[pos..end].iter().any(|&b| b > 0x7F) {
            samples.push(&data[pos..end]);
        }
        pos = end + 1 + entry_data_size;
    }
    samples
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

        let compressed = read_at(
            &handle,
            table_pos + FILE_TABLE_HEADER_SIZE,
            compressed_size as usize,
        )?;

        let mut data = Vec::with_capacity(real_size as usize);
        ZlibDecoder::new(&compressed[..])
            .read_to_end(&mut data)
            .map_err(|e| GrfError::CorruptTable(format!("Failed to decompress file table: {e}")))?;

        if data.len() != real_size as usize {
            return Err(GrfError::CorruptTable(format!(
                "File table size mismatch: expected {}, got {}",
                real_size,
                data.len()
            )));
        }

        let entry_data_size = if header.version == 0x300 { 21 } else { 17 };
        let detected_encoding = match forced_encoding {
            Some(encoding) => encoding,
            None => {
                let samples = sample_names(&data, header.file_count, entry_data_size);
                detect_best_encoding(&samples, AUTO_DETECT_THRESHOLD)
            }
        };

        let mut files: Vec<GrfFile> = Vec::with_capacity(header.file_count as usize);
        let mut bad_name_count = 0usize;
        let mut non_utf8_name_count = 0usize;
        let mut non_utf8_samples: Vec<String> = Vec::new();
        let mut encrypted_count = 0usize;

        let mut p = 0usize;
        for i in 0..header.file_count {
            if p >= data.len() {
                return Err(GrfError::CorruptTable(format!(
                    "Unexpected end of file table at entry {i}"
                )));
            }

            let mut end = p;
            while end < data.len() && data[end] != 0 {
                end += 1;
            }
            let raw_name = &data[p..end];
            p = end + 1;

            if p + entry_data_size > data.len() {
                return Err(GrfError::CorruptTable(format!(
                    "Incomplete entry data at entry {i}"
                )));
            }

            let compressed_size = u32_le(&data, p);
            let length_aligned = u32_le(&data, p + 4);
            let real_size = u32_le(&data, p + 8);
            let kind = data[p + 12];
            let offset = if header.version == 0x300 {
                let low = u32_le(&data, p + 13) as u64;
                let high = u32_le(&data, p + 17) as u64;
                (high << 32) + low
            } else {
                u32_le(&data, p + 13) as u64
            };
            p += entry_data_size;

            if real_size > MAX_FILE_UNCOMPRESSED_BYTES {
                continue;
            }
            if kind & FILELIST_TYPE_FILE == 0 {
                continue;
            }

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

            let entry = GrfEntry {
                offset,
                compressed_size,
                length_aligned,
                real_size,
                kind,
            };
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
        })
    }

    /// Read and decode one entry.  Blocking: call from a blocking context.
    pub fn read_entry(&self, entry: &GrfEntry) -> io::Result<Vec<u8>> {
        if entry.length_aligned == 0 {
            return Ok(Vec::new());
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

    fn header_bytes(version: u32, table_offset: u32, seed: u32, n_files: u32) -> Vec<u8> {
        let mut b = vec![0u8; 46];
        b[0..15].copy_from_slice(HEADER_SIGNATURE);
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
        let b = header_bytes(0x103, 0, 0, 10);
        assert!(matches!(
            parse_header(&b),
            Err(GrfError::UnsupportedVersion(0x103))
        ));
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
