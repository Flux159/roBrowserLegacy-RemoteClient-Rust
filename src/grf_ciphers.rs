//! Cipher operations used by the protected GRF format.
//!
//! CHAM uses 80 rounds and big-endian words; ThreeWay uses 11 rounds.
//! ThreeWay follows Crypto++'s public-domain implementation. IDEA and RC6
//! only encrypt: the body format uses them to produce XOR masks and CFB streams.

use aes::{
    cipher::{BlockDecrypt, KeyInit},
    Aes128,
};

pub(super) fn aes_cbc_decrypt(data: &mut [u8], key: &[u8; 16], iv: &[u8; 16]) {
    let cipher = Aes128::new(key.into());
    let mut previous = *iv;
    for block in data.chunks_exact_mut(16) {
        let encrypted: [u8; 16] = block.try_into().expect("complete AES block");
        cipher.decrypt_block(block.into());
        for (value, feedback) in block.iter_mut().zip(previous) {
            *value ^= feedback;
        }
        previous = encrypted;
    }
}

pub(super) fn cham_cbc_decrypt(data: &mut [u8], key: &[u8; 16], iv: &[u8; 16]) {
    let mut keys = [0_u32; 8];
    for (i, word) in key.chunks_exact(4).enumerate() {
        let value = u32::from_be_bytes(word.try_into().expect("CHAM key word"));
        keys[i] = value ^ value.rotate_left(1) ^ value.rotate_left(8);
        keys[(i + 4) ^ 1] = value ^ value.rotate_left(1) ^ value.rotate_left(11);
    }
    let mut previous = *iv;
    for block in data.chunks_exact_mut(16) {
        let encrypted: [u8; 16] = block.try_into().expect("complete CHAM block");
        let mut words: [u32; 4] = std::array::from_fn(|i| {
            u32::from_be_bytes(encrypted[i * 4..i * 4 + 4].try_into().expect("CHAM word"))
        });
        for round in (0..80_u32).rev() {
            let i = round as usize % 4;
            let right = if round & 1 == 1 { 1 } else { 8 };
            let neighbor = if round & 1 == 1 { 8 } else { 1 };
            words[i] = words[i]
                .rotate_right(right)
                .wrapping_sub(words[(i + 1) % 4].rotate_left(neighbor) ^ keys[round as usize % 8])
                ^ round;
        }
        for (chunk, word) in block.chunks_exact_mut(4).zip(words) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        for (value, feedback) in block.iter_mut().zip(previous) {
            *value ^= feedback;
        }
        previous = encrypted;
    }
}

fn threeway_theta(a: u32, b: u32, c: u32) -> (u32, u32, u32) {
    let mix = (a ^ b ^ c).rotate_left(16) ^ (a ^ b ^ c).rotate_left(8);
    let u = (a << 24) ^ (c >> 8) ^ (b << 8) ^ (a >> 24);
    let v = (b << 24) ^ (a >> 8) ^ (c << 8) ^ (b >> 24);
    (a ^ mix ^ u, b ^ mix ^ v, c ^ mix ^ (u >> 16) ^ (v << 16))
}

fn threeway_encrypt(key: &[u8; 12], block: &[u8; 12]) -> [u8; 12] {
    let word = |bytes: &[u8], i: usize| {
        u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("ThreeWay word"))
    };
    let (k0, k1, k2) = (word(key, 0), word(key, 1), word(key, 2));
    let (mut a, mut b, mut c) = (word(block, 0), word(block, 1), word(block, 2));
    let mut rc = 0x0b0b;
    for _ in 0..11 {
        (a, b, c) = threeway_theta(a ^ k0 ^ (rc << 16), b ^ k1, c ^ k2 ^ rc);
        let (u, v) = (a.rotate_left(22), c.rotate_left(1));
        (a, b, c) = (
            (u ^ (b | !v)).rotate_left(1),
            b ^ (v | !u),
            (v ^ (u | !b)).rotate_left(22),
        );
        rc <<= 1;
        if rc & 0x10000 != 0 {
            rc ^= 0x11011;
        }
    }
    (a, b, c) = threeway_theta(a ^ k0 ^ (rc << 16), b ^ k1, c ^ k2 ^ rc);
    let mut result = [0; 12];
    for (chunk, value) in result.chunks_exact_mut(4).zip([a, b, c]) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    result
}

pub(super) fn threeway_cfb_decrypt(data: &mut [u8], key: &[u8; 12], iv: &[u8; 12]) {
    let mut previous = *iv;
    for block in data.chunks_exact_mut(12) {
        let encrypted = block.try_into().expect("complete ThreeWay block");
        let stream = threeway_encrypt(key, &previous);
        for (value, mask) in block.iter_mut().zip(stream) {
            *value ^= mask;
        }
        previous = encrypted;
    }
}

fn idea_multiply(a: u16, b: u16) -> u16 {
    let a = if a == 0 { 65536 } else { u64::from(a) };
    let b = if b == 0 { 65536 } else { u64::from(b) };
    ((a * b) % 65537) as u16
}

fn idea_keys(key: &[u8; 16]) -> [u16; 52] {
    let mut value = u128::from_be_bytes(*key);
    let mut keys = [0; 52];
    for (i, word) in keys.iter_mut().enumerate() {
        if i > 0 && i % 8 == 0 {
            value = value.rotate_left(25);
        }
        *word = (value >> (112 - 16 * (i % 8))) as u16;
    }
    keys
}

fn idea_encrypt(block: &[u8; 8], keys: &[u16; 52]) -> [u8; 8] {
    let words: [u16; 4] = std::array::from_fn(|i| {
        u16::from_be_bytes(block[i * 2..i * 2 + 2].try_into().expect("IDEA word"))
    });
    let [mut a, mut b, mut c, mut d] = words;
    for k in keys[..48].chunks_exact(6) {
        a = idea_multiply(a, k[0]);
        b = b.wrapping_add(k[1]);
        c = c.wrapping_add(k[2]);
        d = idea_multiply(d, k[3]);
        let e = idea_multiply(a ^ c, k[4]);
        let f = idea_multiply((b ^ d).wrapping_add(e), k[5]);
        let g = e.wrapping_add(f);
        (a, b, c, d) = (a ^ f, c ^ f, b ^ g, d ^ g);
    }
    let words = [
        idea_multiply(a, keys[48]),
        c.wrapping_add(keys[49]),
        b.wrapping_add(keys[50]),
        idea_multiply(d, keys[51]),
    ];
    let mut result = [0; 8];
    for (chunk, value) in result.chunks_exact_mut(2).zip(words) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    result
}

fn idea_mask(key: &[u8; 16], input: &[u8; 16], iv: &[u8]) -> [u8; 16] {
    let keys = idea_keys(key);
    let first = idea_encrypt(&std::array::from_fn(|i| input[i] ^ iv[i]), &keys);
    let second = idea_encrypt(&std::array::from_fn(|i| input[8 + i] ^ first[i]), &keys);
    let mut mask = [0; 16];
    mask[..8].copy_from_slice(&first);
    mask[8..].copy_from_slice(&second);
    mask
}

fn rc6_keys(key: &[u8]) -> [u32; 44] {
    let mut words: [u32; 4] = std::array::from_fn(|i| {
        u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().expect("RC6 key word"))
    });
    let mut keys: [u32; 44] =
        std::array::from_fn(|i| 0xb7e15163_u32.wrapping_add((i as u32).wrapping_mul(0x9e3779b9)));
    let (mut a, mut b, mut i, mut j) = (0_u32, 0_u32, 0, 0);
    for _ in 0..132 {
        a = keys[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
        keys[i] = a;
        b = words[j]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left(a.wrapping_add(b));
        words[j] = b;
        i = (i + 1) % 44;
        j = (j + 1) % 4;
    }
    keys
}

fn rc6_encrypt(block: &[u8; 16], keys: &[u32; 44]) -> [u8; 16] {
    let words: [u32; 4] = std::array::from_fn(|i| {
        u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().expect("RC6 word"))
    });
    let [mut a, mut b, mut c, mut d] = words;
    b = b.wrapping_add(keys[0]);
    d = d.wrapping_add(keys[1]);
    for i in 1..=20 {
        let t = b
            .wrapping_mul(b.wrapping_mul(2).wrapping_add(1))
            .rotate_left(5);
        let u = d
            .wrapping_mul(d.wrapping_mul(2).wrapping_add(1))
            .rotate_left(5);
        a = (a ^ t).rotate_left(u).wrapping_add(keys[2 * i]);
        c = (c ^ u).rotate_left(t).wrapping_add(keys[2 * i + 1]);
        (a, b, c, d) = (b, c, d, a);
    }
    let words = [a.wrapping_add(keys[42]), b, c.wrapping_add(keys[43]), d];
    let mut result = [0; 16];
    for (chunk, word) in result.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    result
}

pub(super) fn decrypt_body_tail(
    cipher_id: u16,
    parameters: &[u8; 64],
    filename_hash: &[u8; 16],
    output_hash: &[u8; 16],
    tail: &mut [u8],
) {
    let mask = if cipher_id == 128 {
        idea_mask(output_hash, filename_hash, &parameters[49..57])
    } else {
        idea_mask(filename_hash, output_hash, &parameters[49..57])
    };
    if cipher_id == 128 {
        let (start, size) = if tail.len() < 3072 {
            (0, tail.len() / 16 * 16)
        } else {
            (2048, 1024)
        };
        let key = parameters[44..60].try_into().expect("AES body key");
        let iv = parameters[28..44].try_into().expect("AES body IV");
        aes_cbc_decrypt(&mut tail[start..start + size], key, iv);
    } else {
        let keys = rc6_keys(&parameters[24..40]);
        let mut previous = parameters[40..56].try_into().expect("RC6 IV");
        let size = (tail.len() / 16 * 16).min(1024);
        for block in tail[..size].chunks_exact_mut(16) {
            let encrypted = block.try_into().expect("complete RC6 block");
            let stream = rc6_encrypt(&previous, &keys);
            for (value, mask) in block.iter_mut().zip(stream) {
                *value ^= mask;
            }
            previous = encrypted;
        }
    }
    for (i, value) in tail.iter_mut().enumerate() {
        *value ^= mask[i % 16];
    }
}

/// Older protected bodies consume a PKCS#7-padded AES prefix, followed by
/// an IDEA-derived XOR suffix. Padding increases physical input length.
pub(super) fn decrypt_legacy_tail(
    cipher_id: u16,
    parameters: &[u8; 64],
    filename_hash: &[u8; 16],
    output_hash: &[u8; 16],
    tail: &mut [u8],
    compressed_length: usize,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    let invalid = |message| Error::new(ErrorKind::InvalidData, message);
    let length = compressed_length.min(1024);
    let encrypted_length = (length / 16 + 1) * 16;
    if tail.len() < encrypted_length || tail.len() - encrypted_length != compressed_length - length
    {
        return Err(invalid("Protected GRF AES body padding size mismatch"));
    }
    let (key, iv, mask) = if cipher_id == 5 {
        (
            &parameters[..16],
            &parameters[16..32],
            idea_mask(filename_hash, output_hash, &parameters[48..56]),
        )
    } else {
        (
            &parameters[28..44],
            &parameters[44..60],
            idea_mask(output_hash, filename_hash, &parameters[52..60]),
        )
    };
    aes_cbc_decrypt(
        &mut tail[..encrypted_length],
        key.try_into().expect("legacy AES key"),
        iv.try_into().expect("legacy AES IV"),
    );
    let padding = usize::from(tail[encrypted_length - 1]);
    if !(1..=16).contains(&padding)
        || encrypted_length - padding != length
        || tail[length..encrypted_length]
            .iter()
            .any(|byte| usize::from(*byte) != padding)
    {
        return Err(invalid("Invalid protected GRF AES body PKCS#7 padding"));
    }
    tail.copy_within(encrypted_length.., length);
    for (i, byte) in tail[length..compressed_length].iter_mut().enumerate() {
        *byte ^= mask[i % 16];
    }
    Ok(())
}

/// Body 1 first decrypts a bounded CHAM-CBC prefix, then reverses a chained
/// word rotation and XOR over the full tail. Its mask includes output size.
pub(super) fn decrypt_cham_tail(
    parameters: &[u8; 64],
    seeded_name_hash: &[u8; 16],
    output_hash: &[u8; 16],
    tail: &mut [u8],
) {
    let seed = u64::from_le_bytes(
        seeded_name_hash[8..]
            .try_into()
            .expect("native hash high64"),
    );
    let key = xxhash_rust::xxh3::xxh3_128_with_seed(&parameters[..60], seed).to_le_bytes();
    let full_length = tail.len() / 16 * 16;
    let prefix_length = full_length.min(1024);
    cham_cbc_decrypt(&mut tail[..prefix_length], &key, output_hash);
    let mut previous = *output_hash;
    for block in tail[..full_length].chunks_exact_mut(16) {
        let original: [u8; 16] = block.try_into().expect("complete body 1 block");
        for (i, value) in block.iter_mut().enumerate() {
            let rotated = (i + 12) % 16;
            *value = original[rotated] ^ seeded_name_hash[rotated] ^ previous[i];
        }
        previous = original;
    }
    for (i, value) in tail[full_length..].iter_mut().enumerate() {
        *value ^= seeded_name_hash[i] ^ previous[i];
    }
}
