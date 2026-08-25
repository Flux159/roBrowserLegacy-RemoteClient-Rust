#!/usr/bin/env python3
"""Check every file in an archive against the manifest its writer recorded.

The differential test samples paths and trusts that both servers agree.  This
checks the other thing: that what comes out of the archive is exactly what went
in, for every entry, verified against a CRC recorded by an independent writer.

It is the only check that covers GRF 0x300, because the JavaScript reference's
validator refuses to load a 0x300 archive its own loader reads fine.

  usage: verify-manifest.py --fixture DIR [--rust-bin PATH]
"""

import argparse
import http.client
import os
import subprocess
import sys
import time
import urllib.parse
import zlib

PORT = 3411
_CONN = None


def fetch(path):
    global _CONN
    for attempt in range(2):
        if _CONN is None:
            _CONN = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
        try:
            _CONN.request("GET", path)
            response = _CONN.getresponse()
            return response.status, response.read()
        except Exception:
            try:
                _CONN.close()
            except Exception:
                pass
            _CONN = None
            if attempt == 1:
                raise
    raise RuntimeError("unreachable")


def wait_for_health(timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
            conn.request("GET", "/api/health")
            response = conn.getresponse()
            response.read()
            conn.close()
            if response.status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--rust-bin", default="target/release/robrowser-remoteclient")
    args = parser.parse_args()

    fixture = os.path.abspath(args.fixture)
    rust_bin = os.path.abspath(args.rust_bin)

    # Manifests must be walked in DATA.INI order, not alphabetically: when two
    # archives hold the same path the lower-indexed one wins, so its manifest is
    # the one that records the bytes the server will actually serve.
    resources = os.path.join(fixture, "resources")
    manifests = []
    with open(os.path.join(resources, "DATA.INI"), encoding="utf-8") as f:
        in_data = False
        for line in f:
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                in_data = line[1:-1].strip().lower() == "data"
                continue
            if not in_data or "=" not in line:
                continue
            name = line.split("=", 1)[1].strip()
            candidate = os.path.join(resources, os.path.splitext(name)[0] + ".manifest.tsv")
            if os.path.exists(candidate):
                manifests.append(candidate)

    if not manifests:
        sys.exit(f"no manifests for the archives listed in {resources}/DATA.INI")

    env = dict(
        os.environ,
        SERVER_ROOT=fixture,
        PORT=str(PORT),
        CLIENT_PUBLIC_URL="http://127.0.0.1:8000",
        CACHE_WARM_UP="false",
    )
    process = subprocess.Popen(
        [rust_bin],
        cwd=fixture,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for_health():
            sys.exit("the server never became healthy")

        # Later archives in DATA.INI lose collisions, so only the winning
        # spelling of a duplicated path can be checked against its own CRC.
        seen = set()
        checked = 0
        failures = []

        for manifest in manifests:
            with open(manifest, encoding="utf-8") as f:
                for line in f:
                    stored, size, crc = line.rstrip("\n").split("\t")
                    key = stored.lower()
                    if key in seen:
                        continue
                    seen.add(key)

                    # Ask the way the browser does: mojibake, forward slashes.
                    requested = stored.replace("\\", "/").encode("cp949").decode("latin-1")
                    status, body = fetch("/" + urllib.parse.quote(requested, safe="/"))
                    checked += 1

                    if status != 200:
                        failures.append(f"status {status} for {stored!r}")
                    elif len(body) != int(size):
                        failures.append(
                            f"size {len(body)} != {size} for {stored!r}"
                        )
                    elif zlib.crc32(body) != int(crc):
                        failures.append(f"crc mismatch for {stored!r}")

                    if len(failures) > 20:
                        break
            print(f"{os.path.basename(manifest)}: {checked} entries checked so far")

        print(f"checked {checked} entries across {len(manifests)} archive(s)")
        if failures:
            print(f"  {len(failures)} FAILURE(S):")
            for line in failures[:20]:
                print(f"    {line}")
            return 1
        print("  every entry extracted byte-for-byte")
        return 0
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    sys.exit(main())
