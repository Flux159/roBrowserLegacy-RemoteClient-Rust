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

## Why

The JS implementation is good and this is not a criticism of it. The motivation
is embedding: shipping it inside a desktop app means shipping Node — around
38 MB compressed and a whole second language runtime — for a server that is
mostly file I/O and a socket pump. A static Rust binary is a few MB and drops
into an app bundle with no runtime at all.

The intent is to be a **drop-in replacement**: same routes, same environment
variables, same `DATA.INI` handling, same on-the-wire behaviour. If it needs
its own client build or its own config, it has failed.

## Status

Not implemented. `tasks/rustimplementation.md` is the specification — it
enumerates the behaviour to match, including the parts that are easy to miss and
expensive to get wrong.

## Licence

GPL-3.0, matching roBrowserLegacy and RemoteClient-JS. Game assets are
copyright Gravity Co., Ltd. and are never included here.
