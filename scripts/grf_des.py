#!/usr/bin/env python3
"""Ragnarok Online's mangled DES, as used for encrypted GRF entries.

Written from the same format description as `src/des.rs`, independently, so
that a transcription error in one shows up as a failed decrypt of the other.
Only the encrypt direction is needed here; decrypt is exercised by the server.

Two facts make encryption cheap to express:

* the block transform `FP(F(IP(x)))` is an involution — `F` XORs the left half
  with a function of the right half and never swaps them, and `FP` is `IP`
  inverted — so encrypting a block is the same operation as decrypting it;
* the de-shuffle step is a byte permutation composed with an involutive
  substitution, so it needs its permutation inverted and nothing else.
"""

MASK = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]

INITIAL_PERMUTATION_TABLE = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]

FINAL_PERMUTATION_TABLE = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]

TRANSPOSITION_TABLE = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]

SUBSTITUTION_BOX_TABLE = [
    [
        0xEF, 0x03, 0x41, 0xFD, 0xD8, 0x74, 0x1E, 0x47, 0x26, 0xEF, 0xFB, 0x22, 0xB3, 0xD8, 0x84, 0x1E,
        0x39, 0xAC, 0xA7, 0x60, 0x62, 0xC1, 0xCD, 0xBA, 0x5C, 0x96, 0x90, 0x59, 0x05, 0x3B, 0x7A, 0x85,
        0x40, 0xFD, 0x1E, 0xC8, 0xE7, 0x8A, 0x8B, 0x21, 0xDA, 0x43, 0x64, 0x9F, 0x2D, 0x14, 0xB1, 0x72,
        0xF5, 0x5B, 0xC8, 0xB6, 0x9C, 0x37, 0x76, 0xEC, 0x39, 0xA0, 0xA3, 0x05, 0x52, 0x6E, 0x0F, 0xD9,
    ],
    [
        0xA7, 0xDD, 0x0D, 0x78, 0x9E, 0x0B, 0xE3, 0x95, 0x60, 0x36, 0x36, 0x4F, 0xF9, 0x60, 0x5A, 0xA3,
        0x11, 0x24, 0xD2, 0x87, 0xC8, 0x52, 0x75, 0xEC, 0xBB, 0xC1, 0x4C, 0xBA, 0x24, 0xFE, 0x8F, 0x19,
        0xDA, 0x13, 0x66, 0xAF, 0x49, 0xD0, 0x90, 0x06, 0x8C, 0x6A, 0xFB, 0x91, 0x37, 0x8D, 0x0D, 0x78,
        0xBF, 0x49, 0x11, 0xF4, 0x23, 0xE5, 0xCE, 0x3B, 0x55, 0xBC, 0xA2, 0x57, 0xE8, 0x22, 0x74, 0xCE,
    ],
    [
        0x2C, 0xEA, 0xC1, 0xBF, 0x4A, 0x24, 0x1F, 0xC2, 0x79, 0x47, 0xA2, 0x7C, 0xB6, 0xD9, 0x68, 0x15,
        0x80, 0x56, 0x5D, 0x01, 0x33, 0xFD, 0xF4, 0xAE, 0xDE, 0x30, 0x07, 0x9B, 0xE5, 0x83, 0x9B, 0x68,
        0x49, 0xB4, 0x2E, 0x83, 0x1F, 0xC2, 0xB5, 0x7C, 0xA2, 0x19, 0xD8, 0xE5, 0x7C, 0x2F, 0x83, 0xDA,
        0xF7, 0x6B, 0x90, 0xFE, 0xC4, 0x01, 0x5A, 0x97, 0x61, 0xA6, 0x3D, 0x40, 0x0B, 0x58, 0xE6, 0x3D,
    ],
    [
        0x4D, 0xD1, 0xB2, 0x0F, 0x28, 0xBD, 0xE4, 0x78, 0xF6, 0x4A, 0x0F, 0x93, 0x8B, 0x17, 0xD1, 0xA4,
        0x3A, 0xEC, 0xC9, 0x35, 0x93, 0x56, 0x7E, 0xCB, 0x55, 0x20, 0xA0, 0xFE, 0x6C, 0x89, 0x17, 0x62,
        0x17, 0x62, 0x4B, 0xB1, 0xB4, 0xDE, 0xD1, 0x87, 0xC9, 0x14, 0x3C, 0x4A, 0x7E, 0xA8, 0xE2, 0x7D,
        0xA0, 0x9F, 0xF6, 0x5C, 0x6A, 0x09, 0x8D, 0xF0, 0x0F, 0xE3, 0x53, 0x25, 0x95, 0x36, 0x28, 0xCB,
    ],
]

SHUFFLE_PAIRS = [
    (0x00, 0x2B), (0x6C, 0x80), (0x01, 0x68), (0x48, 0x77),
    (0x60, 0xFF), (0xB9, 0xC0), (0xFE, 0xEB),
]


def _shuffle_table():
    table = list(range(256))
    for a, b in SHUFFLE_PAIRS:
        table[a], table[b] = b, a
    return table


SHUFFLE_TABLE = _shuffle_table()

# out[i] = src[SHUFFLE_PERM[i]] for the first seven bytes; the eighth is
# substituted rather than moved.
SHUFFLE_PERM = [3, 4, 6, 0, 1, 2, 5]
SHUFFLE_PERM_INVERSE = [0] * 7
for _i, _j in enumerate(SHUFFLE_PERM):
    SHUFFLE_PERM_INVERSE[_j] = _i


def _permute(block, table):
    out = bytearray(8)
    for i in range(64):
        j = table[i] - 1
        if block[(j >> 3) & 7] & MASK[j & 7]:
            out[(i >> 3) & 7] |= MASK[i & 7]
    return out


def _transposition(block):
    out = bytearray(8)
    for i in range(32):
        j = TRANSPOSITION_TABLE[i] - 1
        if block[j >> 3] & MASK[j & 7]:
            out[(i >> 3) + 4] |= MASK[i & 7]
    return out


def _expansion(s):
    return bytearray([
        ((s[7] << 5) | (s[4] >> 3)) & 0x3F,
        ((s[4] << 1) | (s[5] >> 7)) & 0x3F,
        ((s[4] << 5) | (s[5] >> 3)) & 0x3F,
        ((s[5] << 1) | (s[6] >> 7)) & 0x3F,
        ((s[5] << 5) | (s[6] >> 3)) & 0x3F,
        ((s[6] << 1) | (s[7] >> 7)) & 0x3F,
        ((s[6] << 5) | (s[7] >> 3)) & 0x3F,
        ((s[7] << 1) | (s[4] >> 7)) & 0x3F,
    ])


def _substitution_box(s):
    out = bytearray(8)
    for i in range(4):
        out[i] = (SUBSTITUTION_BOX_TABLE[i][s[i * 2]] & 0xF0) | (
            SUBSTITUTION_BOX_TABLE[i][s[i * 2 + 1]] & 0x0F
        )
    return out


def _round_function(block):
    tmp = _transposition(_substitution_box(_expansion(bytearray(block))))
    out = bytearray(block)
    for i in range(4):
        out[i] ^= tmp[i + 4]
    return out


def transform_block(block):
    """`FP(F(IP(x)))` — its own inverse, so this both encrypts and decrypts."""
    return _permute(_round_function(_permute(block, INITIAL_PERMUTATION_TABLE)),
                    FINAL_PERMUTATION_TABLE)


def shuffle_encode(block):
    out = bytearray(8)
    for i in range(7):
        out[SHUFFLE_PERM[i]] = block[i]
    out[7] = SHUFFLE_TABLE[block[7]]
    return out


def shuffle_decode(block):
    out = bytearray(8)
    for i in range(7):
        out[i] = block[SHUFFLE_PERM[i]]
    out[7] = SHUFFLE_TABLE[block[7]]
    return out


def _cycle_for(entry_length):
    digits = len(str(entry_length))
    if digits < 3:
        return 1
    if digits < 5:
        return digits + 1
    if digits < 7:
        return digits + 9
    return digits + 15


def encode_full(data, length, entry_length):
    """Inverse of the reference's `decodeFull` (encryption mode 0)."""
    out = bytearray(data)
    cycle = _cycle_for(entry_length)
    nblocks = min(length, len(out)) >> 3

    for i in range(min(20, nblocks)):
        out[i * 8:i * 8 + 8] = transform_block(out[i * 8:i * 8 + 8])

    j = -1
    for i in range(20, nblocks):
        if i % cycle == 0:
            out[i * 8:i * 8 + 8] = transform_block(out[i * 8:i * 8 + 8])
            continue
        j += 1
        if j != 0 and j % 7 == 0:
            out[i * 8:i * 8 + 8] = shuffle_encode(out[i * 8:i * 8 + 8])

    return bytes(out)


def encode_header(data, length):
    """Inverse of the reference's `decodeHeader` (encryption mode 1)."""
    out = bytearray(data)
    count = min(length, len(out)) >> 3
    for i in range(min(20, count)):
        out[i * 8:i * 8 + 8] = transform_block(out[i * 8:i * 8 + 8])
    return bytes(out)


if __name__ == "__main__":
    # Self-check: the transforms must round-trip.
    import os

    block = os.urandom(8)
    assert transform_block(transform_block(block)) == bytearray(block)
    assert shuffle_decode(shuffle_encode(block)) == bytearray(block)

    payload = os.urandom(8 * 64)
    assert encode_full(payload, len(payload), 12345) != payload
    print("grf_des self-check passed")
