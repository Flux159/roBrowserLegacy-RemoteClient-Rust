# roBrowserLegacy Remote Client — Rust

A single-binary reimplementation of
[roBrowserLegacy-RemoteClient-JS](https://github.com/FranciscoWallison/roBrowserLegacy-RemoteClient-JS):
the unified server that lets [roBrowserLegacy](https://github.com/MrAntares/roBrowserLegacy)
run a Ragnarok Online client in a browser.

It does three jobs on one port:

1. **Serves the client** — the built roBrowserLegacy bundle as static files.
2. **Serves game assets** — extracted from GRF archives on demand, cached in memory.
3. **Proxies the game socket** — WebSocket to raw TCP, because browsers cannot
   speak TCP and rAthena speaks nothing else.

Everything is same-origin by design. That is not incidental — it is why the
client needs no CORS handling, no second port and no mixed-content exemption.

## Why

The JS implementation is good and this is not a criticism of it. The motivation
is embedding: shipping it inside a desktop app means shipping Node — around
38 MB compressed and a whole second language runtime — for a server that is
mostly file I/O and a socket pump.

The release binary is **1.8 MB**, statically linked against nothing but libc.

## Building

```sh
cargo build --release
# target/release/robrowser-remoteclient
```

Rust 1.75 or newer (developed and tested on 1.96). No C toolchain, no
system libraries, no build script.

## Running

```sh
cp .env.example .env      # CLIENT_PUBLIC_URL is required
mkdir -p resources        # put your GRFs and DATA.INI here
./robrowser-remoteclient
```

`resources/DATA.INI` names the archives, in priority order:

```ini
[Data]
0=custom.grf
1=rdata.grf
2=data.grf
```

**Lower index wins.** Overlay archives are listed first on purpose; reversing
this silently serves the base client's assets instead of the overrides.

Configuration is entirely by environment variable, with the same names and
defaults as the JS implementation — see [`.env.example`](.env.example). The
only additions are `SERVER_ROOT`, `HOST`, `ENABLE_COMPRESSION` and
`GRF_FILENAME_ENCODING`.

Pointing a client at it needs two lines of `Config.local.js`:

```js
window.ROConfigLocal = {
    remoteClient: '/',
    servers: [{ /* ... */ socketProxy: 'ws://127.0.0.1:3338/ws' }]
};
```

## HTTP surface

| Route | Method | Behaviour |
|---|---|---|
| `/api/health` | GET | startup validation, archives, cache and index counters |
| `/api/cache-stats` | GET | live cache and index counters |
| `/api/missing-files` | GET | every asset that was asked for and not found |
| `/list-files` | GET | every indexed path, `Cache-Control: public, max-age=300` |
| `/search` | POST | `{"filter": "<regex>"}` or `filter=<regex>` → newline-separated paths |
| `/` | POST | the same handler — see [differences](#deliberate-differences) |
| `/batch` | POST | `{"files": [...]}`, 1–50 entries → `{path: base64}` |
| `/*` | GET | a static file, then an asset |
| `/ws/<host>:<port>` | WS | proxied to rAthena, when enabled |

Assets in the game formats (`.spr .act .gat .rsw .gnd .rsm .str .pal .bmp .tga
.jpg .png .gif .wav .mp3 .ogg .txt .xml .lub .lua .grf`) are served with an ETag
— the first 16 hex characters of the content's MD5, computed once when the entry
is cached — and `Cache-Control: public, max-age=86400, immutable`.
`If-None-Match` is answered with a 304.

## How an asset is found

For any request path, in order — first hit wins:

1. the in-memory LRU cache;
2. the local filesystem, `<root>/<path>`, for the loose files that ship beside
   the server (`System/`, `BGM/`, `AI/`);
3. `DATA_OVERRIDE_PATH`, with a leading `data/` stripped — this is how a
   translation is applied without repacking a 2.4 GB archive, which is why it
   comes before the archives;
4. the GRF index, first archive wins;
5. the Korean reading of the request path, looked up again;
6. otherwise a 404, recorded at `/api/missing-files`.

### Auto-extract

Assets pulled out of an archive are written to `<root>/<path>` as they are
served, so the next request for them is answered by step 2 rather than by
seeking into a multi-gigabyte file. This is on by default, matching the
reference; the write is handed to a background thread so it stays off the
response path.

Two consequences worth knowing before you ship it:

- it is a second copy of everything the client has ever touched, so plan for
  roughly the size of the archives you serve;
- **replacing a GRF does not change what the server serves** until the extracted
  tree is deleted, because the copies win. Clear `<root>/data` when you swap an
  archive.

`CLIENT_AUTOEXTRACT=false` turns it off, which is the right setting when disk
matters more than warm-start latency.

If the server root is read-only — a signed app bundle, a container image — the
writes fail and assets continue to be served straight from the archives. That is
reported once, with the reason, rather than once per asset. Point `SERVER_ROOT`
at a writable directory if you want the extracted copies.

### Names are CP949, and this is the hard part

GRF entry names are CP949 (Korean) bytes with backslash separators:

```
data\sprite\ÀÎ°£Á·\°Ë»ç\°Ë»ç_³²_1460.act
```

roBrowser asks for them as those same bytes reinterpreted as ISO-8859-1 —
mojibake — with forward slashes and percent-encoded as UTF-8. So the index
answers to four spellings of every entry, lowercased, first wins:

1. the name as stored, `\` → `/`
2. the name as stored, `/` → `\`
3. the mojibake form, `\` → `/`
4. the mojibake form, `/` → `\`

Get this wrong and the game loads, walks around, and is missing every sprite
whose name contains Hangul — which is most of them. It does not look like an
encoding bug.

## GRF support

Versions **0x200** and **0x300**, including **DES-encrypted entries** in both
encryption modes. Archives are never loaded into memory: the file table is
parsed once at startup, then bodies are read by seeking into the archive per
request. A retail `data.grf` is 2–4 GB.

Filename encoding is detected per archive by sampling names that carry high
bytes and comparing a UTF-8 against a CP949 decode.

## Testing

```sh
cargo test          # 118 unit and integration tests
```

CI runs the full suite plus `cargo fmt`, `cargo clippy -D warnings` and a
release build on **Linux, macOS and Windows**, and fails the build if the binary
grows past 8 MB.

The integration tests build GRF archives in-process, so they cover the 0x200 and
0x300 layouts, DES entries in both modes, the four-way mojibake index, archive
precedence, cache eviction, every HTTP route, and the proxy — including a real
`CA_LOGIN` handshake and a sustained-traffic run.

Three scripts under [`scripts/`](scripts/) cover what unit tests cannot:

```sh
# Build a synthetic archive, written from the format description rather than
# from this project's reader, so a shared misunderstanding cannot hide.
python3 scripts/make-test-grf.py fixture/resources/data.grf --files 2500
python3 scripts/make-test-grf.py fixture/resources/enc.grf --files 1200 --encrypt

# Every entry, checked against the CRC its writer recorded.
python3 scripts/verify-manifest.py --fixture fixture

# Both servers over the same archives, every path in every spelling.
python3 scripts/differential-test.py --js-dir ../roBrowserLegacy-RemoteClient-JS --fixture fixture
```

The differential run is the most valuable test available and it is cheap. As of
the last run it compares **11,210 responses across 2,800 paths** — every file in
the fixture, in all four spellings, plus `/list-files`, `/batch` and `/search` —
and finds no difference in status, body or content type. Both servers run with
their default configuration, so it also covers the extract-then-serve-from-disk
path: each ends the run having written the same 4,244 files.

## Deliberate differences

Everything below was found by running the two servers side by side, and each one
is a considered choice rather than an oversight.

- **Filename encoding is detected from names that actually have high bytes**,
  wherever they are in the file table, rather than from the first 200 entries.
  File tables are usually sorted and CP949 names sort after ASCII ones, so an
  archive whose Korean paths all live past entry 200 is declared UTF-8 by the
  reference; its names then decode to runs of U+FFFD and every Korean asset in
  it becomes unreachable. Where the reference guesses right, this agrees with it.
- **`POST /` is answered as a search.** roBrowser's own `FileManager.search`
  posts `filter=<regex>` to the remote-client base URL, not to `/search`. The
  reference has no POST route there at all, so nothing depends on the 404 this
  replaces.
- **`/search` responses are `text/plain`** rather than Express's `text/html`.
  The client overrides the type on its side regardless.
- **Path traversal is refused** on the local-filesystem and static-file lookups,
  and on the auto-extract write path.
- **Gzip runs at level 1.** Game assets are already deflate-compressed inside the
  archive, so the wire saving comes cheap or not at all; spending 40 ms on level 6
  for a sprite the client wanted five milliseconds ago is a bad trade.

Two bugs in the reference are worth knowing about because they are *not*
reproduced here:

- its startup validator cannot read a GRF 0x300 file table — it omits the 4-byte
  field that its own loader skips — so it refuses to start on an archive it would
  otherwise serve correctly;
- `.wav` aside, its encoding detection failure above is silent.

## Out of scope

The ESRGAN upscaling middleware, the `tools/` encoding utilities, `prepare.js`'s
generated `path-mapping.json` (the four-way index covers the same ground), and
BMP conversion, which exists in the reference but is not wired into any route.

## Licence

GPL-3.0, matching roBrowserLegacy and RemoteClient-JS. Game assets are
copyright Gravity Co., Ltd. and are never included here.
