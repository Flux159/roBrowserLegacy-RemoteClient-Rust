"""Generate synthetic protected-GRF fixtures using independent Python encoders.

No game files or Rust decoder code are read. Python dependencies are only needed
for regeneration; ordinary cargo tests use the checked-in fixtures. See README.md.
ThreeWay follows Crypto++'s public-domain implementation.
"""

import argparse
import hashlib
import struct
import zlib
from pathlib import Path

import lz4.block
import xxhash
from Crypto.Cipher import AES

MASK32 = MASK = 0xFFFFFFFF
FOOTER_HASH_INPUT = b"uf8E8qAwHthrLxiS"
AES_KEY = bytes.fromhex("56fd7e712f6d36f55ca599e67b18107a")
AES_IV = bytes.fromhex("4ce8a1ae45b321607e4f26a4bb140c96")
THREEWAY_KEY = bytes.fromhex("ad61aedabf203e1dfe1db72b")
THREEWAY_IV = bytes.fromhex("a095dfcfd04b74db027ede09")
PARAM = bytes((i * 31 + 7) % 256 for i in range(60))
NAME = b"data\\\xc7\xd1\xb1\xdb\\protected.txt"


def xxh128_native(data):
    return xxhash.xxh3_128_intdigest(data).to_bytes(16, "little")


def rotate_left(value, count):
    return ((value << count) | (value >> (32 - count))) & MASK32


def cham_keys(key):
    words = struct.unpack(">4I", key)
    keys = [0] * 8
    for index, word in enumerate(words):
        keys[index] = word ^ rotate_left(word, 1) ^ rotate_left(word, 8)
        keys[(index + 4) ^ 1] = word ^ rotate_left(word, 1) ^ rotate_left(word, 11)
    return keys


def _multiply(a, b):
    return (((a or 65536) * (b or 65536)) % 65537) & 0xFFFF


def _idea_keys(key):
    value = int.from_bytes(key, "big")
    words = []
    while len(words) < 52:
        words.extend((value >> (112 - 16 * i)) & 0xFFFF for i in range(8))
        value = ((value << 25) | (value >> 103)) & ((1 << 128) - 1)
    return words[:52]


def idea_encrypt(block, keys):
    a, b, c, d = struct.unpack(">4H", block)
    for off in range(0, 48, 6):
        k = keys[off : off + 6]
        a, b, c, d = (
            _multiply(a, k[0]),
            (b + k[1]) & 0xFFFF,
            (c + k[2]) & 0xFFFF,
            _multiply(d, k[3]),
        )
        e = _multiply(a ^ c, k[4])
        f = _multiply(((b ^ d) + e) & 0xFFFF, k[5])
        g = (e + f) & 0xFFFF
        a, b, c, d = a ^ f, c ^ f, b ^ g, d ^ g
    return struct.pack(
        ">4H",
        _multiply(a, keys[48]),
        (c + keys[49]) & 0xFFFF,
        (b + keys[50]) & 0xFFFF,
        _multiply(d, keys[51]),
    )


def _rol(value, count):
    count &= 31
    return ((value << count) | (value >> ((32 - count) & 31))) & MASK32


def _rc6_keys(key):
    words = list(struct.unpack("<4I", key))
    keys = [(0xB7E15163 + i * 0x9E3779B9) & MASK32 for i in range(44)]
    a = b = i = j = 0
    for _ in range(132):
        a = keys[i] = _rol((keys[i] + a + b) & MASK32, 3)
        b = words[j] = _rol((words[j] + a + b) & MASK32, a + b)
        i, j = (i + 1) % 44, (j + 1) % 4
    return keys


def rc6_encrypt(block, keys):
    a, b, c, d = struct.unpack("<4I", block)
    b = (b + keys[0]) & MASK32
    d = (d + keys[1]) & MASK32
    for i in range(1, 21):
        t = _rol((b * (2 * b + 1)) & MASK32, 5)
        u = _rol((d * (2 * d + 1)) & MASK32, 5)
        a = (_rol(a ^ t, u) + keys[2 * i]) & MASK32
        c = (_rol(c ^ u, t) + keys[2 * i + 1]) & MASK32
        a, b, c, d = b, c, d, a
    a = (a + keys[42]) & MASK32
    c = (c + keys[43]) & MASK32
    return struct.pack("<4I", a, b, c, d)


def rol(value, bits):
    value &= MASK
    return ((value << bits) | (value >> (32 - bits))) & MASK


def theta(a, b, c):
    mix = rol(a ^ b ^ c, 16) ^ rol(a ^ b ^ c, 8)
    u = ((a << 24) ^ (c >> 8) ^ (b << 8) ^ (a >> 24)) & MASK
    v = ((b << 24) ^ (a >> 8) ^ (c << 8) ^ (b >> 24)) & MASK
    return (
        (a ^ mix ^ u) & MASK,
        (b ^ mix ^ v) & MASK,
        (c ^ mix ^ (u >> 16) ^ (v << 16)) & MASK,
    )


def threeway_encrypt(key, block):
    if len(key) != 12 or len(block) != 12:
        raise ValueError("ThreeWay uses 12-byte keys and blocks")
    k0, k1, k2 = struct.unpack(">3I", key)
    a, b, c = struct.unpack(">3I", block)
    rc = 0x0B0B
    for _ in range(11):
        a, b, c = theta(a ^ k0 ^ (rc << 16), b ^ k1, c ^ k2 ^ rc)
        u, v = rol(a, 22), rol(c, 1)
        a, c, b = rol(u ^ (b | ~v), 1), rol(v ^ (u | ~b), 22), (b ^ (v | ~u)) & MASK
        rc <<= 1
        if rc & 0x10000:
            rc ^= 0x11011
    return struct.pack(">3I", *theta(a ^ k0 ^ (rc << 16), b ^ k1, c ^ k2 ^ rc))


def cham_encrypt(block, keys):
    words = list(struct.unpack(">4I", block))
    for r in range(80):
        i = r % 4
        neighbor = rotate_left(words[(i + 1) % 4], 8 if r & 1 else 1)
        words[i] = rotate_left(
            ((words[i] ^ r) + (neighbor ^ keys[r % 8])) & 0xFFFFFFFF, 1 if r & 1 else 8
        )
    return struct.pack(">4I", *words)


def make_footer(records):
    decoded = b"".join(struct.pack("<I", kid) + param for kid, param in records)
    digest = hashlib.sha256(FOOTER_HASH_INPUT).digest()
    keys, prev = cham_keys(digest[:16]), digest[16:]
    out = bytearray(
        b"\x01\x01\0\0"
        + struct.pack("<QII", 1700000000, len(decoded), xxhash.xxh32_intdigest(decoded))
    )
    for i in range(0, len(decoded), 16):
        prev = cham_encrypt(
            bytes(a ^ b for a, b in zip(decoded[i : i + 16], prev)), keys
        )
        out.extend(prev)
    return bytes(out)


FOOTER = make_footer([(7, PARAM)])


def header_encrypt(h, name):
    kind = h[1]
    if kind == 0x71:
        previous = THREEWAY_IV
        out = bytearray(h[:8])
        for i in range(8, 104, 12):
            stream = threeway_encrypt(THREEWAY_KEY, previous)
            previous = bytes(a ^ b for a, b in zip(stream, h[i : i + 12]))
            out.extend(previous)
        return bytes(out)
    iv = AES_IV if kind == 1 else xxh128_native(name if kind == 2 else h[4:8])
    return h[:8] + AES.new(AES_KEY, AES.MODE_CBC, iv).encrypt(h[8:104])


def make_entry(
    out, kind=1, cid=128, comp=0, kid=0, flags=0, edits=None, packed_override=None
):
    packed = (
        (
            out
            if comp == 0
            else zlib.compress(out)
            if comp == 1
            else lz4.block.compress(out, store_size=False)
        )
        if packed_override is None
        else packed_override
    )
    h = bytearray(104)
    h[:2] = bytes([1, kind])
    struct.pack_into(
        "<HBBIII", h, 8, cid, comp, flags, len(packed), len(packed), len(out)
    )
    h[24:40] = xxh128_native(out)
    struct.pack_into("<I", h, 40, kid)
    h[44:104] = PARAM
    if edits:
        for off, val in edits.items():
            h[off : off + len(val)] = val
    struct.pack_into("<I", h, 4, xxhash.xxh32_intdigest(h[8:104]))
    params = bytes(
        value ^ (h[24 + i % 16] if flags == 1 else 0) for i, value in enumerate(PARAM)
    ) + bytes(4)
    tail = packed[128:]
    if tail:
        # Encoding reverses the decoder passes: XOR first, then encrypt.
        maskkeys = _idea_keys(h[24:40] if cid == 128 else xxh128_native(NAME))
        firstsource = xxh128_native(NAME) if cid == 128 else h[24:40]
        first = idea_encrypt(
            bytes(a ^ b for a, b in zip(firstsource[:8], params[49:57])), maskkeys
        )
        second = idea_encrypt(
            bytes(a ^ b for a, b in zip(firstsource[8:], first)), maskkeys
        )
        mask = first + second
        encrypted = bytearray(a ^ mask[i % 16] for i, a in enumerate(tail))
        if cid == 128:
            start, length = (
                (0, len(tail) // 16 * 16) if len(tail) < 3072 else (2048, 1024)
            )
            if length:
                encrypted[start : start + length] = AES.new(
                    params[44:60], AES.MODE_CBC, params[28:44]
                ).encrypt(encrypted[start : start + length])
        elif cid == 133:
            keys, prev = _rc6_keys(params[24:40]), params[40:56]
            for i in range(0, min(1024, len(tail) // 16 * 16), 16):
                stream = rc6_encrypt(prev, keys)
                prev = bytes(a ^ b for a, b in zip(encrypted[i : i + 16], stream))
                encrypted[i : i + 16] = prev
        elif cid in (5, 7):
            key, source, iv, aeskey, aesiv = (
                (
                    xxh128_native(NAME),
                    h[24:40],
                    params[48:56],
                    params[:16],
                    params[16:32],
                )
                if cid == 5
                else (
                    h[24:40],
                    xxh128_native(NAME),
                    params[52:60],
                    params[28:44],
                    params[44:60],
                )
            )
            idea = _idea_keys(key)
            first = idea_encrypt(bytes(a ^ b for a, b in zip(source[:8], iv)), idea)
            second = idea_encrypt(bytes(a ^ b for a, b in zip(source[8:], first)), idea)
            mask = first + second
            length = min(len(tail), 1024)
            pad = 16 - length % 16
            encrypted = AES.new(aeskey, AES.MODE_CBC, aesiv).encrypt(
                tail[:length] + bytes([pad]) * pad
            ) + bytes(a ^ mask[i % 16] for i, a in enumerate(tail[length:]))
        elif cid == 1:
            m = xxhash.xxh3_128_intdigest(NAME, seed=len(out)).to_bytes(16, "little")
            key = xxhash.xxh3_128_intdigest(
                params[:60], seed=int.from_bytes(m[8:], "little")
            ).to_bytes(16, "little")
            keys = cham_keys(key)
            previous = bytes(h[24:40])
            intermediate = bytearray()
            full = len(tail) // 16 * 16
            for i in range(0, full, 16):
                z = bytes(a ^ b for a, b in zip(tail[i : i + 16], previous))
                previous = bytes(a ^ b for a, b in zip(z[4:] + z[:4], m))
                intermediate.extend(previous)
            intermediate.extend(a ^ b ^ c for a, b, c in zip(tail[full:], m, previous))
            encrypted = bytearray(intermediate)
            previous = bytes(h[24:40])
            for i in range(0, min(1024, full), 16):
                previous = cham_encrypt(
                    bytes(a ^ b for a, b in zip(intermediate[i : i + 16], previous)),
                    keys,
                )
                encrypted[i : i + 16] = previous
        packed = packed[:128] + encrypted
    if cid in (5, 7):
        struct.pack_into("<I", h, 12, len(packed))
    struct.pack_into("<I", h, 4, xxhash.xxh32_intdigest(h[8:104]))
    raw = header_encrypt(h, NAME) + packed
    return raw


rows = []


def add(tag, out, **kwargs):
    payload = make_entry(out, **kwargs)
    rows.append(
        (tag, NAME, len(out), FOOTER if kwargs.get("kid") == 7 else b"", payload, out)
    )


add("raw-name", b"protected payload", kind=2)
add(
    "zlib-rc6-footer",
    hashlib.shake_256(b"zlib fixture").digest(1500),
    kind=1,
    cid=133,
    comp=1,
    kid=7,
    flags=1,
)
add("lz4-aes-checksum", hashlib.shake_256(b"lz4 fixture").digest(700), kind=15, comp=2)
add(
    "threeway-partial",
    hashlib.shake_256(b"threeway fixture").digest(143),
    kind=0x71,
    cid=133,
)
for cid, lengths in [(128, [128, 144, 3199, 3200, 3201]), (133, [1151, 1152, 1153])]:
    for length in lengths:
        add(
            f"boundary-{cid}-{length}",
            hashlib.shake_256(f"{cid}-{length}".encode()).digest(length),
            cid=cid,
            flags=length % 2,
        )
for cid, lengths in [(5, [129, 144, 1151, 1152, 1153]), (7, [143, 1153])]:
    for length in lengths:
        add(
            f"boundary-{cid}-{length}",
            hashlib.shake_256(f"{cid}-{length}".encode()).digest(length),
            cid=cid,
            flags=length % 2,
        )
add(
    "body1-lz4",
    hashlib.shake_256(b"body1 lz4 fixture").digest(1400),
    cid=1,
    comp=2,
    kind=0x71,
    kid=7,
    flags=1,
)
for length in [143, 144, 1151, 1152, 1153]:
    add(
        f"boundary-1-{length}",
        hashlib.shake_256(f"1-{length}".encode()).digest(length),
        cid=1,
        flags=length % 2,
    )
for tag, kwargs in [
    ("unsupported-body", {"cid": 6}),
    ("unsupported-compression", {"comp": 9, "packed_override": b"bad"}),
    ("missing-key", {"kid": 9}),
    ("parameter-flags", {"flags": 2}),
    ("oversized-output", {"edits": {20: struct.pack("<I", 0xFFFFFFFF)}}),
    ("padded-outside", {"edits": {12: struct.pack("<I", 0xFFFFFFFF)}}),
    ("compressed-outside", {"edits": {16: struct.pack("<I", 19)}}),
    ("output-hash", {"edits": {24: bytes(16)}}),
    ("zlib-overrun", {"comp": 1, "packed_override": zlib.compress(bytes(1024))}),
    (
        "zlib-truncated",
        {"comp": 1, "packed_override": zlib.compress(b"protected payload")[:-2]},
    ),
    ("stored-short", {"packed_override": b"bad"}),
]:
    add(tag, b"protected payload", **kwargs)

base = next(row for row in rows if row[0] == "boundary-5-144")
payload = bytearray(base[4])
payload[104 + 128 + 15] ^= 1
rows.append(("pkcs7-invalid", NAME, base[2], base[3], bytes(payload), base[5]))
for tag, records in [
    ("footer-duplicate", [(7, PARAM), (7, PARAM)]),
    ("footer-zero", [(0, PARAM)]),
    ("footer-id-overflow", [(65536, PARAM)]),
]:
    rows.append((tag, NAME, 0, make_footer(records), b"", b""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare regenerated bytes without writing files",
    )
    args = parser.parse_args()
    bundle = bytearray(struct.pack("<I", len(rows)))
    for tag, name, size, keys, payload, output in rows:
        for value in (tag.encode(), name, keys, payload, output):
            bundle.extend(struct.pack("<I", len(value)))
            bundle.extend(value)
        bundle.extend(struct.pack("<I", size))
    vectors = {row[0]: row for row in rows}
    generated = {
        "protected-grf.bin": bytes(bundle),
        "protected-clear.bin": make_entry(
            b"protected payload", kind=2, edits={44: bytes(range(60))}
        ),
        "protected-keyed.bin": vectors["body1-lz4"][4],
        "protected-footer.bin": FOOTER,
    }
    dest = Path(__file__).parent
    for name, data in generated.items():
        path = dest / name
        if args.check:
            if path.read_bytes() != data:
                raise SystemExit(f"{name} differs from regenerated bytes")
        else:
            path.write_bytes(data)
    print(
        f"{len(rows)} synthetic vectors; {len(bundle)} bundle bytes; all four fixtures {'match' if args.check else 'written'}"
    )


if __name__ == "__main__":
    main()
