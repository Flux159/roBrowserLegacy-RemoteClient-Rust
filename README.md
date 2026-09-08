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

## Embedded process ownership

Embedders can use `--managed` (protocol 1, discoverable with
`--capabilities`). The first stdin line is JSON with `secret` and `launchId`
(each 32 random bytes encoded as hex), an absolute `stateRoot`, and an
`environment` object containing the exact environment values the parent set.
The binary checks those values after loading `.env`. The parent must specify
all configuration values, including defaults, so the fingerprint covers the
complete launch configuration. Keep the secret outside the served root and
out of arguments, environment variables and logs.

After binding HTTP, stdout emits `RAGNAROK_ASSET_READY ` followed by JSON:
protocol/service/version, PID, launch ID, state root, executable path and
SHA-256, SHA-256 of the sorted environment JSON, and HTTP/control ports. Keep
draining stdout as the server logs there too. Keep stdin open for the life of
the parent; EOF requests shutdown after a parent crash. Shutdown is bounded to
five seconds even if a WebSocket client stays connected.

The control socket is a separate ephemeral loopback TCP listener, **not a
public HTTP route**. Send one newline-delimited JSON envelope with `payload`
(a JSON string containing `launchId`, `challenge` and `action`) and `mac`
(hex HMAC-SHA256 over the UTF-8 payload, using the decoded secret). The
challenge is a fresh 32-byte hex nonce; actions are `status` and `shutdown`.
The response uses the same envelope format; its signed payload contains
`identity`, `challenge` and `action`. Verify the MAC, challenge, action and
every identity field before accepting it. Messages are limited to 16 KiB,
eight simultaneous control clients and a two-second deadline. Unauthenticated
or stale-launch messages get no response and cannot trigger shutdown.

This challenge-bound protocol never sends the secret to a process that has
reused a stale control port. `hmac` and `sha2` provide the standard primitives
and constant-time MAC verification. The public `/api/health` returns only
service/version/status; it is not ownership evidence. Embedders should retain
OS creation-time/executable identity alongside the signed record and never
kill an unrelated listener or adopt a process merely because health is 200.

Run `cargo test --locked` for binary-level startup/authentication/EOF tests as
well as the existing real-socket HTTP, GRF resolution and WS suites.

## Licence

GPL-3.0-or-later, matching roBrowserLegacy and RemoteClient-JS. Game assets are
copyright Gravity Co., Ltd. and are never included here.
