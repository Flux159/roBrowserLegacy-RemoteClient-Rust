//! Protected-GRF decoding with checked lengths and content hashes.

use crate::grf_ciphers::{
    aes_cbc_decrypt, cham_cbc_decrypt, decrypt_body_tail, decrypt_cham_tail, decrypt_legacy_tail,
    threeway_cfb_decrypt,
};
use flate2::{Decompress, FlushDecompress, Status};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io};
use xxhash_rust::{
    xxh3::{xxh3_128, xxh3_128_with_seed},
    xxh32::xxh32,
};

pub(crate) type ArchiveKeys = BTreeMap<u32, [u8; 60]>;
const MAX_OUTPUT_SIZE: u32 = 256 * 1024 * 1024;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn word(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .expect("validated header word"),
    )
}

pub(crate) fn filename_hash(raw: &[u8]) -> [u8; 16] {
    // Native x86 order is low64 followed by high64, both little endian.
    xxh3_128(raw).to_le_bytes()
}

// Body cipher 1 uses the original filename seeded by the final output size.
pub(crate) fn seeded_filename_hash(raw: &[u8], output_size: u32) -> [u8; 16] {
    xxh3_128_with_seed(raw, u64::from(output_size)).to_le_bytes()
}

pub(crate) fn decode_archive_keys(raw: &[u8]) -> io::Result<ArchiveKeys> {
    if raw.is_empty() {
        return Ok(ArchiveKeys::new());
    }
    if raw.len() < 20 || raw[..4] != [1, 1, 0, 0] {
        return Err(invalid("Unsupported or truncated GRF archive key block"));
    }
    let body_size = word(raw, 12) as usize;
    if body_size == 0
        || body_size % 64 != 0
        || body_size / 64 > 65535
        || raw.len() - 20 != body_size
    {
        return Err(invalid("GRF archive key-block size mismatch"));
    }
    let digest = Sha256::digest(b"uf8E8qAwHthrLxiS");
    let mut decoded = raw[20..].to_vec();
    cham_cbc_decrypt(
        &mut decoded,
        digest[..16].try_into().expect("SHA-256 key"),
        digest[16..].try_into().expect("SHA-256 IV"),
    );
    if xxh32(&decoded, 0) != word(raw, 16) {
        return Err(invalid("GRF archive key-block checksum mismatch"));
    }
    let mut keys = ArchiveKeys::new();
    for record in decoded.chunks_exact(64) {
        let id = word(record, 0);
        if id == 0 || id > 65535 || keys.contains_key(&id) {
            return Err(invalid("Invalid or duplicate GRF archive key-block record"));
        }
        keys.insert(id, record[4..].try_into().expect("60-byte key record"));
    }
    Ok(keys)
}

fn decode_header(payload: &[u8], name_hash: &[u8; 16]) -> io::Result<[u8; 104]> {
    if payload.len() < 104 || payload[0] != 1 {
        return Err(invalid("Unsupported or truncated protected GRF header"));
    }
    let mut header: [u8; 104] = payload[..104].try_into().expect("validated header length");
    match header[1] {
        1 | 2 | 15 => {
            let key = [
                0x56, 0xfd, 0x7e, 0x71, 0x2f, 0x6d, 0x36, 0xf5, 0x5c, 0xa5, 0x99, 0xe6, 0x7b, 0x18,
                0x10, 0x7a,
            ];
            let iv = match header[1] {
                1 => [
                    0x4c, 0xe8, 0xa1, 0xae, 0x45, 0xb3, 0x21, 0x60, 0x7e, 0x4f, 0x26, 0xa4, 0xbb,
                    0x14, 0x0c, 0x96,
                ],
                2 => *name_hash,
                _ => filename_hash(&header[4..8]),
            };
            aes_cbc_decrypt(&mut header[8..], &key, &iv);
        }
        0x71 => {
            let key = [
                0xad, 0x61, 0xae, 0xda, 0xbf, 0x20, 0x3e, 0x1d, 0xfe, 0x1d, 0xb7, 0x2b,
            ];
            let iv = [
                0xa0, 0x95, 0xdf, 0xcf, 0xd0, 0x4b, 0x74, 0xdb, 0x02, 0x7e, 0xde, 0x09,
            ];
            threeway_cfb_decrypt(&mut header[8..], &key, &iv);
        }
        kind => {
            return Err(invalid(format!(
                "Unsupported protected GRF header type {kind:#x}"
            )))
        }
    }
    if xxh32(&header[8..], 0) != word(&header, 4) {
        return Err(invalid("Protected GRF header checksum mismatch"));
    }
    Ok(header)
}

pub(crate) fn decode_entry(
    payload: &[u8],
    name_hash: &[u8; 16],
    seeded_name_hash: &[u8; 16],
    real_size: u32,
    keys: &ArchiveKeys,
) -> io::Result<Vec<u8>> {
    let header = decode_header(payload, name_hash)?;
    let padded_size = word(&header, 12) as usize;
    let compressed_size = word(&header, 16) as usize;
    let output_size = word(&header, 20);
    if output_size > MAX_OUTPUT_SIZE || real_size != output_size {
        return Err(invalid(
            "Protected GRF output size exceeds limit or differs from file table",
        ));
    }
    if padded_size > payload.len() - 104 || compressed_size > padded_size {
        return Err(invalid("Protected GRF body size lies outside payload"));
    }
    let cipher_id = u16::from_le_bytes(header[8..10].try_into().expect("body cipher ID"));
    if !matches!(cipher_id, 1 | 5 | 7 | 128 | 133) {
        return Err(invalid(format!(
            "Unsupported protected GRF body cipher {cipher_id}"
        )));
    }
    let compression = header[10];
    if compression > 2 {
        return Err(invalid(format!(
            "Unsupported protected GRF compression {compression}"
        )));
    }
    if header[11] & !1 != 0 {
        return Err(invalid(format!(
            "Unsupported protected GRF parameter flags {}",
            header[11]
        )));
    }
    let key_id = word(&header, 40);
    let material = if key_id == 0 {
        &header[44..104]
    } else {
        keys.get(&key_id)
            .ok_or_else(|| invalid(format!("Missing GRF archive key {key_id}")))?
    };
    let output_hash: [u8; 16] = header[24..40].try_into().expect("output hash");
    let mut parameters = [0; 64];
    for (i, value) in material.iter().enumerate() {
        parameters[i] = *value
            ^ if header[11] & 1 != 0 {
                output_hash[i % 16]
            } else {
                0
            };
    }
    let mut body = payload[104..104 + padded_size].to_vec();
    if compressed_size > 128 {
        if cipher_id == 1 {
            decrypt_cham_tail(
                &parameters,
                seeded_name_hash,
                &output_hash,
                &mut body[128..],
            );
        } else if matches!(cipher_id, 5 | 7) {
            decrypt_legacy_tail(
                cipher_id,
                &parameters,
                name_hash,
                &output_hash,
                &mut body[128..],
                compressed_size - 128,
            )?;
        } else {
            decrypt_body_tail(
                cipher_id,
                &parameters,
                name_hash,
                &output_hash,
                &mut body[128..],
            );
        }
    }
    body.truncate(compressed_size);
    let expected = output_size as usize;
    let output = match compression {
        0 => {
            if body.len() != expected {
                return Err(invalid("Protected GRF stored output size mismatch"));
            }
            body
        }
        1 => {
            // One sentinel byte detects expansion beyond the declared output;
            // no untrusted stream can grow this allocation.
            let mut output = vec![0; expected + 1];
            let mut inflater = Decompress::new(true);
            let status = inflater
                .decompress(&body, &mut output, FlushDecompress::Finish)
                .map_err(|error| invalid(format!("Invalid protected GRF zlib stream: {error}")))?;
            if status != Status::StreamEnd
                || inflater.total_out() != u64::from(output_size)
                || inflater.total_in() != body.len() as u64
            {
                return Err(invalid(
                    "Protected GRF zlib stream is truncated or its size differs",
                ));
            }
            output.truncate(expected);
            output
        }
        2 => {
            let mut output = vec![0; expected];
            let written = lz4_flex::block::decompress_into(&body, &mut output)
                .map_err(|error| invalid(format!("Invalid protected GRF LZ4 stream: {error}")))?;
            if written != expected {
                return Err(invalid("Protected GRF LZ4 output size mismatch"));
            }
            output
        }
        _ => unreachable!("validated compression"),
    };
    if filename_hash(&output) != output_hash {
        return Err(invalid("Protected GRF output hash mismatch"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic vectors from tests/fixtures/generate.py use independent
    // Python encoders. No game assets or native executables are included.
    struct Fixture {
        tag: String,
        name: Vec<u8>,
        keys: Vec<u8>,
        payload: Vec<u8>,
        output: Vec<u8>,
        size: u32,
    }

    fn fixtures() -> Vec<Fixture> {
        let mut data = &include_bytes!("../tests/fixtures/protected-grf.bin")[..];
        fn number(data: &mut &[u8]) -> u32 {
            let result = u32::from_le_bytes(data[..4].try_into().unwrap());
            *data = &data[4..];
            result
        }
        fn field(data: &mut &[u8]) -> Vec<u8> {
            let size = number(data) as usize;
            let result = data[..size].to_vec();
            *data = &data[size..];
            result
        }
        let count = number(&mut data);
        (0..count)
            .map(|_| Fixture {
                tag: String::from_utf8(field(&mut data)).unwrap(),
                name: field(&mut data),
                keys: field(&mut data),
                payload: field(&mut data),
                output: field(&mut data),
                size: number(&mut data),
            })
            .collect()
    }

    fn decode(fixture: &Fixture) -> io::Result<Vec<u8>> {
        decode_entry(
            &fixture.payload,
            &filename_hash(&fixture.name),
            &seeded_filename_hash(&fixture.name, fixture.size),
            fixture.size,
            &decode_archive_keys(&fixture.keys)?,
        )
    }

    #[test]
    fn footer_records_are_validated_before_use() {
        assert!(decode_archive_keys(&[]).unwrap().is_empty());
        let rows = fixtures();
        let footer = rows.iter().find(|row| !row.keys.is_empty()).unwrap();
        let keys = decode_archive_keys(&footer.keys).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[&7],
            std::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
        );
        for row in rows.iter().filter(|row| row.tag.starts_with("footer-")) {
            assert!(
                decode_archive_keys(&row.keys)
                    .unwrap_err()
                    .to_string()
                    .contains("record"),
                "{}",
                row.tag
            );
        }
        let mut corrupt = footer.keys.clone();
        corrupt[16] ^= 1;
        assert!(decode_archive_keys(&corrupt)
            .unwrap_err()
            .to_string()
            .contains("checksum"));
        assert!(decode_archive_keys(&footer.keys[..footer.keys.len() - 1]).is_err());
    }

    #[test]
    fn headers_parameters_and_compression_match_independent_vectors() {
        let rows = fixtures();
        for tag in [
            "raw-name",
            "zlib-rc6-footer",
            "lz4-aes-checksum",
            "threeway-partial",
            "body1-lz4",
        ] {
            let row = rows.iter().find(|row| row.tag == tag).unwrap();
            assert_eq!(decode(row).unwrap(), row.output, "{}", row.tag);
        }
        let row = fixtures()
            .into_iter()
            .find(|row| row.tag == "raw-name")
            .unwrap();
        // Golden XXH3_128(name, seed=17), independently generated in Python.
        assert_eq!(
            seeded_filename_hash(&row.name, row.size),
            [
                0xc1, 0x07, 0xd6, 0xf2, 0x80, 0x91, 0x6b, 0x5a, 0x7a, 0xa5, 0x92, 0x87, 0xd4, 0xa8,
                0x14, 0x5a
            ]
        );
        assert_ne!(
            filename_hash(&row.name),
            filename_hash(b"data/\xc7\xd1\xb1\xdb/protected.txt")
        );
        let mut corrupted = row.payload.clone();
        corrupted[8] ^= 1;
        assert!(decode_entry(
            &corrupted,
            &filename_hash(&row.name),
            &seeded_filename_hash(&row.name, row.size),
            row.size,
            &ArchiveKeys::new()
        )
        .unwrap_err()
        .to_string()
        .contains("header checksum"));
    }

    #[test]
    fn selective_body_windows_and_partial_blocks_match_independent_vectors() {
        for row in fixtures()
            .iter()
            .filter(|row| row.tag.starts_with("boundary-"))
        {
            assert_eq!(decode(row).unwrap(), row.output, "{}", row.tag);
        }
    }

    #[test]
    fn unsupported_formats_and_missing_keys_fail_explicitly() {
        for (tag, expected) in [
            ("unsupported-body", "body cipher"),
            ("unsupported-compression", "compression"),
            ("missing-key", "archive key"),
            ("parameter-flags", "parameter flags"),
        ] {
            let row = fixtures().into_iter().find(|row| row.tag == tag).unwrap();
            let error = decode(&row).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains(expected), "{tag}: {error}");
        }
    }

    #[test]
    fn corrupted_or_truncated_payloads_and_key_blocks_never_panic() {
        // Every fixture, with each byte flipped and cut at each length.
        fn damaged(original: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
            (0..original.len())
                .map(|at| {
                    let mut bytes = original.to_vec();
                    bytes[at] ^= 0xff;
                    bytes
                })
                .chain((0..original.len()).map(|len| original[..len].to_vec()))
        }
        for row in fixtures() {
            let keys = decode_archive_keys(&row.keys).unwrap_or_default();
            let name = filename_hash(&row.name);
            let seeded = seeded_filename_hash(&row.name, row.size);
            for payload in damaged(&row.payload) {
                let _ = decode_entry(&payload, &name, &seeded, row.size, &keys);
            }
            for key_block in damaged(&row.keys) {
                let _ = decode_archive_keys(&key_block);
            }
        }
    }

    #[test]
    fn lengths_and_output_hashes_are_checked_before_accepting_content() {
        for tag in [
            "oversized-output",
            "padded-outside",
            "compressed-outside",
            "output-hash",
            "zlib-overrun",
            "zlib-truncated",
            "stored-short",
        ] {
            let row = fixtures().into_iter().find(|row| row.tag == tag).unwrap();
            let error = decode(&row).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{tag}");
        }
        let padding = fixtures()
            .into_iter()
            .find(|row| row.tag == "pkcs7-invalid")
            .unwrap();
        assert!(decode(&padding).unwrap_err().to_string().contains("PKCS#7"));
        let row = fixtures()
            .into_iter()
            .find(|row| row.tag == "raw-name")
            .unwrap();
        for size in [0, row.size + 1] {
            assert!(decode_entry(
                &row.payload,
                &filename_hash(&row.name),
                &seeded_filename_hash(&row.name, size),
                size,
                &ArchiveKeys::new()
            )
            .is_err());
        }
        assert!(decode_entry(
            &row.payload[..103],
            &filename_hash(&row.name),
            &seeded_filename_hash(&row.name, row.size),
            row.size,
            &ArchiveKeys::new()
        )
        .is_err());
    }
}
