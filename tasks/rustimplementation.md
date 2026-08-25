# Reimplementing the roBrowserLegacy Remote Client in Rust

The reference implementation is
[roBrowserLegacy-RemoteClient-JS](https://github.com/FranciscoWallison/roBrowserLegacy-RemoteClient-JS)
(GPL-3.0). Read it. This document is a specification of observable behaviour,
not a description of its code, and where the two disagree **the JS
implementation is correct** — it is what roBrowserLegacy is tested against.

Success is a browser pointed at this binary loading and playing the game with a
client build that was never told which server it is talking to.

---

## 0. What this thing is

Three jobs on one HTTP port (default **3338**):

| Job | Why it exists |
|---|---|
| Static file server | serves the built roBrowserLegacy client |
| GRF asset server | the client asks for `data/sprite/…`; the bytes live inside multi-gigabyte GRF archives |
| WebSocket→TCP proxy | browsers cannot open TCP sockets; rAthena speaks nothing else |

Everything is same-origin by design. That is not incidental — it is why the
client needs no CORS handling, no second port and no mixed-content exemption.

## 1. Non-negotiables

- **Drop-in.** Same routes, same environment variables, same `DATA.INI`
  semantics. An existing deployment swaps the binary and notices nothing.
- **Single static binary**, no runtime dependency. This is the entire point.
- **Never load a GRF into memory.** They are 2–4 GB. Read the file table at
  startup, then seek and read per request.
- **GPL-3.0.**

---

## 2. GRF archives

### Format

Version **0x200** and **0x300**, DES encryption **not** supported (the JS
implementation refuses those too, and the ecosystem repacks with GRF Editor's
"Decrypt" option).

Header, 46 bytes:

| Offset | Size | Meaning |
|---|---|---|
| 0 | 15 | signature `Master of Magic` |
| 15 | 15 | encryption key (unused for the versions we support) |
| 30 | 4 | file table offset, **relative to the end of the header** |
| 34 | 4 | seed |
| 38 | 4 | file count (entries = `count - seed - 7`) |
| 42 | 4 | version |

At `46 + table_offset`: two `u32` (compressed size, uncompressed size), then a
zlib stream. Inflated, it is a flat sequence of entries:

```
<NUL-terminated name bytes> <17-byte struct>
```

The struct is `u32 packed_size, u32 packed_size_aligned, u32 real_size,
u8 flags, u32 offset`. `offset` is again relative to the end of the header.
`flags & 1` marks a file; directories and non-file entries should be skipped.
Body bytes are zlib-deflated.

A working parser is about 30 lines. Verify against a real client: a full kRO
`data.grf` has ~103,000 entries and ~850 `.rsw` files.

### Names are CP949, and this is the hard part

Entry names are **CP949 (Korean) bytes** with **backslash** separators:

```
data\sprite\ÀÎ°£Á·\°Ë»ç\°Ë»ç_³²_1460.act
```

roBrowser requests them as **CP949 bytes reinterpreted as Latin-1** — mojibake.
So the index must answer to several spellings of the same file. For each entry,
insert **all** of these, lowercased, first-wins:

1. the name as stored, `\` → `/`
2. the name as stored, `/` → `\`
3. mojibake form (`cp949_encode(name)` decoded as ISO-8859-1), `\` → `/`
4. mojibake form, `/` → `\`

Get this wrong and the game loads, walks around, and is missing every sprite
whose name contains Hangul — which is most of them. It will not look like an
encoding bug.

### Load order

`DATA.INI` in `CLIENT_RESPATH` (default `resources/`):

```ini
[Data]
0=custom.grf
1=rdata.grf
2=data.grf
```

**Lower index wins.** Build one merged index in file order, keeping the *first*
occurrence of each normalised path. Overlay GRFs are listed first deliberately;
reversing this silently serves the base client's assets instead of the
overrides, which again does not look like a bug.

---

## 3. Request resolution

For any asset path, in order — first hit wins:

1. **In-memory LRU cache.**
2. **Local filesystem**, `<server root>/<path>` — loose files shipped beside the
   server (`System/`, `BGM/`, `AI/`).
3. **`DATA_OVERRIDE_PATH`**, with a leading `data/` stripped from the request.
   This is how translations are applied without repacking a 2.4 GB archive, so
   it must come *before* the GRFs.
4. **GRF index**, first archive wins.
5. Try the mojibake decode of the request path, then look up again.
6. 404, and record the miss (see `/api/missing-files`).

---

## 4. HTTP surface

| Route | Method | Behaviour |
|---|---|---|
| `/api/health` | GET | JSON: startup validation results, GRF list with versions and encoding findings, env summary, cache stats, index size. Used as a readiness probe — must answer before assets are warm. |
| `/api/cache-stats` | GET | `{cache: {size, maxSize, memoryUsedMB, maxMemoryMB, hits, misses, hitRate}, index: {totalFiles, grfCount, indexBuilt}}` |
| `/api/missing-files` | GET | `{total, files: [{timestamp, requestedPath, grfPath, mappedPath}], logFile}`. Invaluable for diagnosis — keep it. |
| `/search` | POST | `{filter}` → newline-separated matching paths. Gated by `CLIENT_ENABLESEARCH`. |
| `/batch` | POST | `{files: [...]}`, **1–50** entries → `{path: base64}`. Over 50 is a 400. Failures are omitted, not errored. |
| `/list-files` | GET | every indexed path as JSON, `Cache-Control: public, max-age=300` |
| `/*` | GET | static file, then asset resolution |

### Caching headers

For these extensions — `.grf .gat .rsw .gnd .rsm .str .spr .act .pal .bmp .tga
.jpg .jpeg .png .gif .wav .mp3 .ogg .txt .xml .lub .lua` — send:

```
ETag: "<first 16 hex chars of the MD5 of the content>"
Cache-Control: public, max-age=86400, immutable
```

Honour `If-None-Match` with **304**. The ETag should be computed once and stored
with the cache entry, not recomputed per request. `index.html` gets
`max-age=60`; everything else is uncached.

Gzip text-ish responses. Do **not** gzip `.spr`/`.act` bodies on the fly if it
costs measurable latency — they are already deflate-compressed inside the GRF.

### Static serving

When `ENABLE_STATIC_SERVE=true`, serve `ROBROWSER_PATH` at `/`, **before** asset
resolution. Note the JS implementation also handles Vite-style `?raw` imports;
that only matters for serving an unbuilt source tree, and can be skipped if
`ROBROWSER_PATH` is documented as pointing at a build.

---

## 5. WebSocket proxy

Upgrade requests to `/ws/<host>:<port>`; anything else destroys the socket.

- Parse the target with **`rfind(':')`**, not `split`, so IPv6 literals survive.
- Reject a malformed target, or one absent from the allowlist, by closing the
  WebSocket — not by erroring the HTTP request.
- **`WS_ALLOWED_TARGETS`** is a comma-separated `host:port` allowlist, default
  `127.0.0.1:6900,127.0.0.1:6121,127.0.0.1:5121`. This is a security boundary:
  without it the server is an open TCP relay to anything it can route to.
- On connect: `TCP_NODELAY`. RO is a latency-sensitive stream of small packets;
  Nagle makes it feel broken.
- Buffer frames that arrive before the TCP connection completes, bounded
  (**64** in the reference), and flush on connect.
- Binary frames both ways, byte-for-byte. No framing of your own.
- Either side closing tears down the other, exactly once.

The client opens three of these in sequence — login, char, map — so reconnection
churn is normal, not an error condition.

---

## 6. Configuration

Environment, `.env` honoured:

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `3338` | |
| `CLIENT_PUBLIC_URL` | — | **required**; the JS server refuses to start without it |
| `NODE_ENV` | `development` | keep the name for drop-in compatibility, or accept both |
| `ENABLE_STATIC_SERVE` | `false` | |
| `ENABLE_WSPROXY` | `false` | |
| `ROBROWSER_PATH` | `../roBrowserLegacy` | point at a build |
| `WS_ALLOWED_TARGETS` | loopback trio | |
| `DATA_OVERRIDE_PATH` | unset | loose files that beat the GRFs |
| `CACHE_MAX_FILES` | `5000` | |
| `CACHE_MAX_MEMORY_MB` | `1024` | |
| `CACHE_WARM_UP` / `CACHE_WARM_UP_LIMIT` | `false` / `500` | preload common assets |

Also `CLIENT_RESPATH` (`resources/`), `CLIENT_DATAINI` (`DATA.INI`),
`CLIENT_ENABLESEARCH`.

### Cache

LRU by size **and** bytes. Two details from the reference worth keeping: an
entry larger than **10% of the memory budget is never cached** (one map file
should not evict everything), and eviction continues until both limits are
satisfied.

---

## 7. Startup validation

The reference spends a thousand lines here and it earns them — most support
questions are answered by this output. At minimum:

- `resources/` exists and `DATA.INI` is present and parses
- every listed GRF exists, has a valid signature, a supported version, and a
  file table that inflates
- report **non-UTF-8 filename** findings with examples; this is normal for kRO
  and users must not be alarmed by it, but it must be visible
- warn when `data/` is empty, and when `BGM/`/`System/` are absent
- **fail** on missing `CLIENT_PUBLIC_URL`
- print a readable report in development, stay quiet in production unless
  something failed, and expose the same data at `/api/health`

---

## 8. Suggested crates

`tokio`, `axum` (or `hyper`), `tokio-tungstenite`, `flate2`, `encoding_rs`
(CP949 = `EUC-KR`), `serde`/`serde_json`, `md-5`, `dotenvy`, `tracing`. Nothing
exotic; the work is in the details above, not the plumbing.

---

## 9. Testing

Do not trust "it starts".

1. **Parser** — against a real `data.grf`: entry count, and a known file's bytes
   matching what the JS server returns for the same path.
2. **Mojibake** — request a Hangul path in all four spellings; all four must
   return identical bytes.
3. **Precedence** — same path in two GRFs returns the lower-indexed one; a file
   in `DATA_OVERRIDE_PATH` beats both.
4. **Differential** — run both servers over the same GRFs and diff responses for
   a few thousand paths from `/list-files`. This is the single most valuable
   test available and it is cheap to write.
5. **Proxy** — a real login handshake. Send `CA_LOGIN` (`0x0064`, 55 bytes:
   `u16` id, `u32` version, `char[24]` user, `char[24]` pass, `u8` clienttype)
   and expect `AC_ACCEPT_LOGIN` (`0x0ac4`). Then hold the socket open under
   traffic for a minute — proxies that work briefly and die are the norm.
6. **End to end** — point a real roBrowserLegacy build at it and reach the
   character select screen. Nothing below this proves much.

## 10. Out of scope

The ESRGAN upscaling middleware, the `tools/` encoding utilities, and
`prepare.js`'s generated `path-mapping.json` (the four-way index above covers
the same ground). BMP conversion exists in the reference but is not wired into
any route — do not port it without establishing what it was for.
