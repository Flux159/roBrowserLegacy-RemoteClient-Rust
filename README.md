# roBrowserLegacy Remote Client — Rust

A Rust implementation of the Remote Client for
[**roBrowserLegacy**](https://github.com/MrAntares/roBrowserLegacy) — the
project that runs a Ragnarok Online client in a browser.

It is a single binary replacing
[roBrowserLegacy-RemoteClient-JS](https://github.com/FranciscoWallison/roBrowserLegacy-RemoteClient-JS),
and does that project's three jobs on one port:

1. **Serves the client** — the built roBrowserLegacy bundle as static files.
2. **Serves game assets** — extracted from GRF archives on demand, cached in memory.
3. **Proxies the game socket** — WebSocket to raw TCP, because browsers cannot
   speak TCP and rAthena speaks nothing else.

Start with roBrowserLegacy's own documentation; this is a drop-in replacement
for one part of it, not a separate thing to learn.

roBrowserLegacy-RemoteClient-Rust is used by [ragnarokoffline.app](https://github.com/Flux159/ragnarokoffline.app).

## Building

```sh
cargo build --release
# target/release/robrowser-remoteclient
```

Rust 1.75 or newer. No C toolchain, no system libraries, no build script.

## Running

```sh
cp .env.example .env      # CLIENT_PUBLIC_URL is required
mkdir -p resources        # put your GRFs and DATA.INI here
./robrowser-remoteclient
```

`.env.example` documents every setting.

## Licence

GPL-3.0-or-later, matching roBrowserLegacy and RemoteClient-JS. Game assets are
copyright Gravity Co., Ltd. and are never included here.
