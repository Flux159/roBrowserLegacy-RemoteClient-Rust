# Protected GRF fixtures

These files contain synthetic data, not game assets. `generate.py` builds them
with independent Python encoders, including deliberately malformed inputs.
Cargo tests read the checked-in bytes and require no Python dependencies.

To reproduce them with Python 3.11 or later:

```sh
python3 -m venv /tmp/grf-fixtures
/tmp/grf-fixtures/bin/pip install pycryptodome==3.24.0 xxhash==4.0.1 lz4==4.4.5
/tmp/grf-fixtures/bin/python tests/fixtures/generate.py --check
```

Omit `--check` to write the regenerated files. The generator reads no archives,
game executables, or decoder source.

| File | Contents |
| --- | --- |
| `protected-grf.bin` | Header types 1, 2, 15, and 113; body ciphers 1, 5, 7, 128, and 133; stored, zlib, and LZ4 data; inline and footer keys; hash-mixed parameters; cipher window and partial-block boundaries; invalid lengths, padding, hashes, and unsupported formats. |
| `protected-clear.bin` | A short stored entry using header type 2 and the original CP949 filename as its IV input. |
| `protected-keyed.bin` | The bundle's `body1-lz4` payload, using header type 113, footer key 7, and a filename hash seeded by output size. |
| `protected-footer.bin` | The matching archive key block. |

The bundle starts with a little-endian `u32` record count. Each record has five
fields: UTF-8 tag, original filename bytes, archive key block, protected payload,
and expected output. Each field starts with a little-endian `u32` byte length;
a final little-endian `u32` gives the declared output size. The filename is
`data\한글\protected.txt` encoded as CP949, with backslash separators.

The generator uses encryption to construct inputs rather than calling the Rust
decoder. ThreeWay follows Crypto++'s public-domain implementation; the other
custom primitives implement the CHAM, IDEA, and RC6 operations used by this
format. AES, compression, and hashes come from the dependencies above.
