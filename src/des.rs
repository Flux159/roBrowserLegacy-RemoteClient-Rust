//! Ragnarok Online's mangled DES, used for encrypted GRF entries.
//!
//! This is a direct port of the reference loader's `des.ts`.  It is not real
//! DES — one round, a fixed S-box table and a periodic byte shuffle — but it is
//! what the client and every GRF tool implement, bit for bit.
//!
//! The specification suggested skipping this ("repack with GRF Editor's Decrypt
//! option").  It is 150 lines and the JS implementation does support it, so
//! archives that were never repacked keep working.

const MASK: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];

#[rustfmt::skip]
const INITIAL_PERMUTATION_TABLE: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
];

#[rustfmt::skip]
const FINAL_PERMUTATION_TABLE: [u8; 64] = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
];

#[rustfmt::skip]
const TRANSPOSITION_TABLE: [u8; 32] = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
];

#[rustfmt::skip]
const SUBSTITUTION_BOX_TABLE: [[u8; 64]; 4] = [
    [
        0xef, 0x03, 0x41, 0xfd, 0xd8, 0x74, 0x1e, 0x47, 0x26, 0xef, 0xfb, 0x22, 0xb3, 0xd8, 0x84, 0x1e,
        0x39, 0xac, 0xa7, 0x60, 0x62, 0xc1, 0xcd, 0xba, 0x5c, 0x96, 0x90, 0x59, 0x05, 0x3b, 0x7a, 0x85,
        0x40, 0xfd, 0x1e, 0xc8, 0xe7, 0x8a, 0x8b, 0x21, 0xda, 0x43, 0x64, 0x9f, 0x2d, 0x14, 0xb1, 0x72,
        0xf5, 0x5b, 0xc8, 0xb6, 0x9c, 0x37, 0x76, 0xec, 0x39, 0xa0, 0xa3, 0x05, 0x52, 0x6e, 0x0f, 0xd9,
    ],
    [
        0xa7, 0xdd, 0x0d, 0x78, 0x9e, 0x0b, 0xe3, 0x95, 0x60, 0x36, 0x36, 0x4f, 0xf9, 0x60, 0x5a, 0xa3,
        0x11, 0x24, 0xd2, 0x87, 0xc8, 0x52, 0x75, 0xec, 0xbb, 0xc1, 0x4c, 0xba, 0x24, 0xfe, 0x8f, 0x19,
        0xda, 0x13, 0x66, 0xaf, 0x49, 0xd0, 0x90, 0x06, 0x8c, 0x6a, 0xfb, 0x91, 0x37, 0x8d, 0x0d, 0x78,
        0xbf, 0x49, 0x11, 0xf4, 0x23, 0xe5, 0xce, 0x3b, 0x55, 0xbc, 0xa2, 0x57, 0xe8, 0x22, 0x74, 0xce,
    ],
    [
        0x2c, 0xea, 0xc1, 0xbf, 0x4a, 0x24, 0x1f, 0xc2, 0x79, 0x47, 0xa2, 0x7c, 0xb6, 0xd9, 0x68, 0x15,
        0x80, 0x56, 0x5d, 0x01, 0x33, 0xfd, 0xf4, 0xae, 0xde, 0x30, 0x07, 0x9b, 0xe5, 0x83, 0x9b, 0x68,
        0x49, 0xb4, 0x2e, 0x83, 0x1f, 0xc2, 0xb5, 0x7c, 0xa2, 0x19, 0xd8, 0xe5, 0x7c, 0x2f, 0x83, 0xda,
        0xf7, 0x6b, 0x90, 0xfe, 0xc4, 0x01, 0x5a, 0x97, 0x61, 0xa6, 0x3d, 0x40, 0x0b, 0x58, 0xe6, 0x3d,
    ],
    [
        0x4d, 0xd1, 0xb2, 0x0f, 0x28, 0xbd, 0xe4, 0x78, 0xf6, 0x4a, 0x0f, 0x93, 0x8b, 0x17, 0xd1, 0xa4,
        0x3a, 0xec, 0xc9, 0x35, 0x93, 0x56, 0x7e, 0xcb, 0x55, 0x20, 0xa0, 0xfe, 0x6c, 0x89, 0x17, 0x62,
        0x17, 0x62, 0x4b, 0xb1, 0xb4, 0xde, 0xd1, 0x87, 0xc9, 0x14, 0x3c, 0x4a, 0x7e, 0xa8, 0xe2, 0x7d,
        0xa0, 0x9f, 0xf6, 0x5c, 0x6a, 0x09, 0x8d, 0xf0, 0x0f, 0xe3, 0x53, 0x25, 0x95, 0x36, 0x28, 0xcb,
    ],
];

/// Byte substitution used by the de-shuffle step: a handful of swapped pairs,
/// identity everywhere else.
fn shuffle_dec_table() -> [u8; 256] {
    const LIST: [u8; 14] = [
        0x00, 0x2b, 0x6c, 0x80, 0x01, 0x68, 0x48, 0x77, 0x60, 0xff, 0xb9, 0xc0, 0xfe, 0xeb,
    ];
    let mut out = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        out[i] = i as u8;
        i += 1;
    }
    let mut i = 0usize;
    while i < LIST.len() {
        let a = LIST[i] as usize;
        let b = LIST[i + 1] as usize;
        out[a] = b as u8;
        out[b] = a as u8;
        i += 2;
    }
    out
}

fn initial_permutation(block: &mut [u8; 8]) {
    let src = *block;
    let mut tmp = [0u8; 8];
    for i in 0..64 {
        let j = (INITIAL_PERMUTATION_TABLE[i] - 1) as usize;
        if src[(j >> 3) & 7] & MASK[j & 7] != 0 {
            tmp[(i >> 3) & 7] |= MASK[i & 7];
        }
    }
    *block = tmp;
}

fn final_permutation(block: &mut [u8; 8]) {
    let src = *block;
    let mut tmp = [0u8; 8];
    for i in 0..64 {
        let j = (FINAL_PERMUTATION_TABLE[i] - 1) as usize;
        if src[(j >> 3) & 7] & MASK[j & 7] != 0 {
            tmp[(i >> 3) & 7] |= MASK[i & 7];
        }
    }
    *block = tmp;
}

fn transposition(block: &mut [u8; 8]) {
    let src = *block;
    let mut tmp = [0u8; 8];
    for i in 0..32 {
        let j = (TRANSPOSITION_TABLE[i] - 1) as usize;
        if src[j >> 3] & MASK[j & 7] != 0 {
            tmp[(i >> 3) + 4] |= MASK[i & 7];
        }
    }
    *block = tmp;
}

fn expansion(block: &mut [u8; 8]) {
    let s = *block;
    let mut tmp = [0u8; 8];
    tmp[0] = ((s[7] << 5) | (s[4] >> 3)) & 0x3f;
    tmp[1] = ((s[4] << 1) | (s[5] >> 7)) & 0x3f;
    tmp[2] = ((s[4] << 5) | (s[5] >> 3)) & 0x3f;
    tmp[3] = ((s[5] << 1) | (s[6] >> 7)) & 0x3f;
    tmp[4] = ((s[5] << 5) | (s[6] >> 3)) & 0x3f;
    tmp[5] = ((s[6] << 1) | (s[7] >> 7)) & 0x3f;
    tmp[6] = ((s[6] << 5) | (s[7] >> 3)) & 0x3f;
    tmp[7] = ((s[7] << 1) | (s[4] >> 7)) & 0x3f;
    *block = tmp;
}

fn substitution_box(block: &mut [u8; 8]) {
    let s = *block;
    let mut tmp = [0u8; 8];
    for i in 0..4 {
        tmp[i] = (SUBSTITUTION_BOX_TABLE[i][s[i * 2] as usize] & 0xf0)
            | (SUBSTITUTION_BOX_TABLE[i][s[i * 2 + 1] as usize] & 0x0f);
    }
    *block = tmp;
}

fn round_function(block: &mut [u8; 8]) {
    let mut tmp2 = *block;
    expansion(&mut tmp2);
    substitution_box(&mut tmp2);
    transposition(&mut tmp2);

    block[0] ^= tmp2[4];
    block[1] ^= tmp2[5];
    block[2] ^= tmp2[6];
    block[3] ^= tmp2[7];
}

fn decrypt_block(src: &mut [u8], index: usize) {
    let mut block = [0u8; 8];
    block.copy_from_slice(&src[index..index + 8]);
    initial_permutation(&mut block);
    round_function(&mut block);
    final_permutation(&mut block);
    src[index..index + 8].copy_from_slice(&block);
}

/// `out[i] = src[SHUFFLE_PERM[i]]` for the first seven bytes; the eighth is
/// substituted rather than moved.
const SHUFFLE_PERM: [usize; 7] = [3, 4, 6, 0, 1, 2, 5];

fn shuffle_dec(src: &mut [u8], index: usize, table: &[u8; 256]) {
    let s: [u8; 8] = src[index..index + 8].try_into().unwrap();
    let mut tmp = [0u8; 8];
    for i in 0..7 {
        tmp[i] = s[SHUFFLE_PERM[i]];
    }
    tmp[7] = table[s[7] as usize];
    src[index..index + 8].copy_from_slice(&tmp);
}

fn shuffle_enc(src: &mut [u8], index: usize, table: &[u8; 256]) {
    let s: [u8; 8] = src[index..index + 8].try_into().unwrap();
    let mut tmp = [0u8; 8];
    for i in 0..7 {
        tmp[SHUFFLE_PERM[i]] = s[i];
    }
    tmp[7] = table[s[7] as usize];
    src[index..index + 8].copy_from_slice(&tmp);
}

/// Encryption mode 0: DES on the first 20 blocks, then a sparse mix of DES and
/// byte-shuffled blocks whose spacing depends on the entry's compressed size.
fn cycle_for(entry_length: u32) -> usize {
    let digits = entry_length.to_string().len();
    // digits:  0  1  2  3  4  5  6  7  8  9 ...
    //  cycle:  1  1  1  4  5 14 15 22 23 24 ...
    if digits < 3 {
        1
    } else if digits < 5 {
        digits + 1
    } else if digits < 7 {
        digits + 9
    } else {
        digits + 15
    }
}

pub fn decode_full(src: &mut [u8], length: usize, entry_length: u32) {
    let cycle = cycle_for(entry_length);
    let nblocks = (length.min(src.len())) >> 3;
    let table = shuffle_dec_table();

    for i in 0..20.min(nblocks) {
        decrypt_block(src, i * 8);
    }

    // `j` mirrors the reference's `++j && j % 7 === 0` counter, which starts at
    // -1 so the first shuffled block lands on the 8th non-DES block.
    let mut j: i64 = -1;
    for i in 20..nblocks {
        if i % cycle == 0 {
            decrypt_block(src, i * 8);
            continue;
        }
        j += 1;
        if j != 0 && j % 7 == 0 {
            shuffle_dec(src, i * 8, &table);
        }
    }
}

/// Encryption mode 1: DES on the first 20 blocks only; the rest is plaintext.
///
/// The block transform is its own inverse — `F` XORs the left half with a
/// function of the right half and never swaps them, and `FP` is `IP` inverted —
/// so this encrypts as well as it decrypts.
pub fn decode_header(src: &mut [u8], length: usize) {
    let count = (length.min(src.len())) >> 3;
    for i in 0..20.min(count) {
        decrypt_block(src, i * 8);
    }
}

/// Inverse of [`decode_full`].  The server never encrypts, but having the
/// inverse means the decryption path can be tested end to end without a
/// copyrighted archive to read.
pub fn encode_full(src: &mut [u8], length: usize, entry_length: u32) {
    let cycle = cycle_for(entry_length);
    let nblocks = (length.min(src.len())) >> 3;
    let table = shuffle_dec_table();

    for i in 0..20.min(nblocks) {
        decrypt_block(src, i * 8);
    }

    let mut j: i64 = -1;
    for i in 20..nblocks {
        if i % cycle == 0 {
            decrypt_block(src, i * 8);
            continue;
        }
        j += 1;
        if j != 0 && j % 7 == 0 {
            shuffle_enc(src, i * 8, &table);
        }
    }
}

/// Inverse of [`decode_header`], which is [`decode_header`] itself.
pub fn encode_header(src: &mut [u8], length: usize) {
    decode_header(src, length);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffle_table_swaps_the_listed_pairs() {
        let t = shuffle_dec_table();
        assert_eq!(t[0x00], 0x2b);
        assert_eq!(t[0x2b], 0x00);
        assert_eq!(t[0xfe], 0xeb);
        assert_eq!(t[0xeb], 0xfe);
        assert_eq!(t[0x7f], 0x7f);
    }

    #[test]
    fn decode_header_only_touches_the_first_20_blocks() {
        let mut data = vec![0xAAu8; 8 * 30];
        let tail_before = data[8 * 20..].to_vec();
        let len = data.len();
        decode_header(&mut data, len);
        assert_ne!(&data[..8], &[0xAAu8; 8]);
        assert_eq!(&data[8 * 20..], &tail_before[..]);
    }

    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        // A tiny xorshift, so the test data is varied without a dependency.
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn mixed_mode_round_trips() {
        for entry_length in [7u32, 99, 1234, 56_789, 1_234_567] {
            let original = pseudo_random(8 * 200, entry_length as u64);
            let mut data = original.clone();
            encode_full(&mut data, original.len(), entry_length);
            assert_ne!(data, original, "encoding changed nothing");
            decode_full(&mut data, original.len(), entry_length);
            assert_eq!(data, original, "entry_length {entry_length}");
        }
    }

    #[test]
    fn header_mode_round_trips() {
        let original = pseudo_random(8 * 64, 42);
        let mut data = original.clone();
        encode_header(&mut data, original.len());
        assert_ne!(data, original);
        decode_header(&mut data, original.len());
        assert_eq!(data, original);
    }

    #[test]
    fn shuffle_is_reversible() {
        let table = shuffle_dec_table();
        let original = pseudo_random(8, 9);
        let mut data = original.clone();
        shuffle_enc(&mut data, 0, &table);
        shuffle_dec(&mut data, 0, &table);
        assert_eq!(data, original);
    }

    #[test]
    fn a_short_tail_is_left_alone() {
        // Only whole blocks are transformed; five trailing bytes are not one.
        let mut data = vec![1u8, 2, 3, 4, 5];
        let original = data.clone();
        let len = data.len();
        decode_full(&mut data, len, 100);
        assert_eq!(data, original);
    }

    #[test]
    fn permutations_are_inverses() {
        let original: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let mut block = original;
        initial_permutation(&mut block);
        // IP followed by FP is the identity for this table pair.
        final_permutation(&mut block);
        assert_eq!(block, original);
    }
}
