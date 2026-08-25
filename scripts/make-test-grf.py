#!/usr/bin/env python3
"""Write a synthetic GRF archive.

Deliberately implemented from the format description rather than from the Rust
reader, so that a shared misunderstanding between this project's writer and its
reader cannot hide.  The archives it produces are read by both the Rust server
and the JavaScript reference during the differential test.

  usage: make-test-grf.py OUT.grf [--version 0x200|0x300] [--files N] [--seed N]
"""

import argparse
import os
import random
import struct
import sys
import zlib

import grf_des

SIGNATURE = b"Master of Magic"
HEADER_SIZE = 46

# Korean directory and file-name fragments taken from a real client's layout.
KOREAN_DIRS = [
    "유저인터페이스",
    "인간족",
    "몬스터",
    "아이템",
    "악세사리",
    "머리통",
    "이팩트",
    "내부소품",
]
KOREAN_NAMES = [
    "검사",
    "궁수",
    "도둑",
    "마법사",
    "상인",
    "성직자",
    "초보자",
    "남",
    "여",
    "몸통",
    "머리",
]
ASCII_DIRS = ["texture", "sprite", "model", "wav", "luafiles514", "palette"]
ASCII_NAMES = ["basic_interface", "login", "btn_ok", "prontera", "geffen", "item", "cursors"]
EXTENSIONS = [".spr", ".act", ".gat", ".rsw", ".gnd", ".rsm", ".bmp", ".pal", ".txt", ".lub", ".wav"]


def make_paths(count, rng, sort=False):
    """Generate unique CP949-encodable paths, roughly half of them Korean.

    Insertion order is shuffled by default.  A sorted table puts every CP949
    name after every ASCII one, which is a pathological input for filename
    encoding detection; `--sorted` exists to reproduce exactly that.
    """
    paths = set()
    while len(paths) < count:
        korean = rng.random() < 0.5
        depth = rng.randint(1, 3)
        parts = ["data"]
        for _ in range(depth):
            parts.append(rng.choice(KOREAN_DIRS if korean else ASCII_DIRS))
        stem = rng.choice(KOREAN_NAMES if korean else ASCII_NAMES)
        name = f"{stem}_{rng.randint(0, 99999)}{rng.choice(EXTENSIONS)}"
        parts.append(name)
        paths.add("\\".join(parts))
    ordered = sorted(paths)
    if not sort:
        rng.shuffle(ordered)
    return ordered


def make_payload(rng):
    """A mix of sizes and compressibility, including a few large files."""
    roll = rng.random()
    if roll < 0.05:
        size = rng.randint(60_000, 250_000)
    elif roll < 0.30:
        size = rng.randint(4_000, 40_000)
    else:
        size = rng.randint(1, 3_000)

    if rng.random() < 0.5:
        # Compressible: runs of repeated bytes, like real sprite data.
        out = bytearray()
        while len(out) < size:
            out += bytes([rng.randint(0, 255)]) * rng.randint(1, 64)
        return bytes(out[:size])
    return bytes(rng.getrandbits(8) for _ in range(size))


def build(out_path, version, count, seed, sort=False, encrypt=False):
    rng = random.Random(seed)
    paths = make_paths(count, rng, sort)

    body = bytearray()
    table = bytearray()
    manifest = []

    for i, path in enumerate(paths):
        data = make_payload(rng)
        # One entry in twenty is stored rather than deflated.
        stored = (i % 20) == 7
        payload = data if stored else zlib.compress(data, 6)

        # A GRF entry carries no "stored" flag: `real_size == compressed_size`
        # is the only signal a reader has, so a deflate stream that happens to
        # come out the same length as its input is indistinguishable from stored
        # bytes and would be served raw.  Real writers store rather than deflate
        # whenever deflating does not help, which sidesteps this; do the same.
        if not stored and len(payload) >= len(data):
            stored = True
            payload = data

        flags = 0x01  # FILELIST_TYPE_FILE
        compressed_size = len(payload)
        length_aligned = compressed_size

        # DES entries are encrypted in whole 8-byte blocks, so the stored run is
        # padded out and `length_aligned` records the padded length.
        if encrypt and not stored:
            mixed = (i % 2) == 0
            length_aligned = (compressed_size + 7) & ~7
            padded = payload + bytes(length_aligned - compressed_size)
            if mixed:
                flags |= 0x02  # FILELIST_TYPE_ENCRYPT_MIXED
                payload = grf_des.encode_full(padded, length_aligned, compressed_size)
            else:
                flags |= 0x04  # FILELIST_TYPE_ENCRYPT_HEADER
                payload = grf_des.encode_header(padded, length_aligned)

        offset = len(body)
        real_size = compressed_size if stored else len(data)
        body += payload

        table += path.encode("cp949") + b"\x00"
        table += struct.pack("<III", compressed_size, length_aligned, real_size)
        table += bytes([flags])
        table += struct.pack("<Q" if version == 0x300 else "<I", offset)

        manifest.append((path, len(data), zlib.crc32(data)))

    # A directory entry, which a reader must skip rather than serve.
    table += "data\\한글폴더".encode("cp949") + b"\x00"
    table += struct.pack("<III", 0, 0, 0) + bytes([0x00])
    table += struct.pack("<Q" if version == 0x300 else "<I", 0)

    compressed_table = zlib.compress(bytes(table), 6)
    table_offset = len(body)
    entry_count = len(paths) + 1

    header = bytearray(HEADER_SIZE)
    header[0:15] = SIGNATURE
    if version == 0x300:
        header[30:38] = struct.pack("<Q", table_offset)
        header[38:42] = struct.pack("<I", entry_count)
    else:
        header[30:34] = struct.pack("<I", table_offset)
        header[34:38] = struct.pack("<I", 0)  # seed
        header[38:42] = struct.pack("<I", entry_count + 7)
    header[42:46] = struct.pack("<I", version)

    out = bytearray(header)
    out += body
    if version == 0x300:
        out += struct.pack("<I", 0)  # spare field before the table header
    out += struct.pack("<II", len(compressed_table), len(table))
    out += compressed_table

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(out)

    manifest_path = os.path.splitext(out_path)[0] + ".manifest.tsv"
    with open(manifest_path, "w", encoding="utf-8") as f:
        for path, size, crc in manifest:
            f.write(f"{path}\t{size}\t{crc}\n")

    print(
        f"wrote {out_path}: version 0x{version:X}, {len(paths)} files"
        f"{', DES-encrypted' if encrypt else ''}, "
        f"{len(out) / 1024 / 1024:.1f} MB (manifest: {manifest_path})"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out")
    parser.add_argument("--version", default="0x200")
    parser.add_argument("--files", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="DES-encrypt the deflated entries, alternating the two modes",
    )
    parser.add_argument(
        "--sorted",
        action="store_true",
        help="write the file table in sorted order, which starves encoding detection",
    )
    args = parser.parse_args()

    version = int(args.version, 16) if args.version.startswith("0x") else int(args.version)
    if version not in (0x200, 0x300):
        sys.exit("version must be 0x200 or 0x300")
    build(args.out, version, args.files, args.seed, args.sorted, args.encrypt)


if __name__ == "__main__":
    main()
