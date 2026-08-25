#!/usr/bin/env python3
"""Diff this server's responses against the JavaScript reference.

The single most valuable test available: point both implementations at the same
archives and compare what they return for a few thousand paths, in every
spelling the client might use.

  usage: differential-test.py --js-dir DIR --fixture DIR [--paths N]

`--js-dir` is a checkout of roBrowserLegacy-RemoteClient-JS with `npm install`
already run.  `--fixture` is a directory containing `resources/DATA.INI` and the
archives it names; its `resources/` is copied into the JS checkout, because that
server resolves everything relative to its own root.
"""

import argparse
import http.client
import json
import os
import random
import shutil
import subprocess
import sys
import time
import urllib.parse

RUST_PORT = 3401
JS_PORT = 3402


def wait_for_health(port, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
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


_CONNECTIONS = {}


def fetch(port, path, headers=None):
    """Send `path` verbatim; never let a URL library re-encode it.

    Connections are kept alive between requests: a sweep of ten thousand paths
    opening a socket each time exhausts the ephemeral port range long before it
    exhausts the file list.
    """
    for attempt in range(2):
        conn = _CONNECTIONS.get(port)
        if conn is None:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
            _CONNECTIONS[port] = conn
        try:
            conn.request("GET", path, headers=headers or {})
            response = conn.getresponse()
            body = response.read()
            return response.status, body, response.getheader("Content-Type")
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            _CONNECTIONS.pop(port, None)
            if attempt == 1:
                raise
    raise RuntimeError("unreachable")


def post(port, path, payload):
    """POST JSON and return (status, body)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    body = json.dumps(payload).encode()
    conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    out = response.read()
    status = response.status
    conn.close()
    return status, out


def encode(path):
    """Percent-encode as a browser would: UTF-8 bytes, reserved set escaped."""
    return "/" + urllib.parse.quote(path, safe="/")


def spellings(stored_path):
    """The four ways roBrowser might ask for one archive entry."""
    korean_back = stored_path
    korean_fwd = stored_path.replace("\\", "/")
    moji_back = korean_back.encode("cp949").decode("latin-1")
    moji_fwd = korean_fwd.encode("cp949").decode("latin-1")
    return [korean_fwd, korean_back, moji_fwd, moji_back]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--js-dir", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--rust-bin", default="target/release/robrowser-remoteclient")
    parser.add_argument("--paths", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    js_dir = os.path.abspath(args.js_dir)
    fixture = os.path.abspath(args.fixture)
    rust_bin = os.path.abspath(args.rust_bin)

    # The JS server reads resources/ from its own directory.
    js_resources = os.path.join(js_dir, "resources")
    shutil.rmtree(js_resources, ignore_errors=True)
    shutil.copytree(os.path.join(fixture, "resources"), js_resources)

    # Both servers extract every asset they serve to disk and then prefer those
    # copies on the next request, so a leftover extraction from an earlier
    # fixture is served in place of the archive's current contents.  In the
    # reference, backslash-spelled requests land as single files at the root
    # rather than inside data/, which is why this is not just an `rm -rf data`.
    for directory in (js_dir, fixture):
        shutil.rmtree(os.path.join(directory, "data"), ignore_errors=True)
        shutil.rmtree(os.path.join(directory, "logs"), ignore_errors=True)
        for name in os.listdir(directory):
            if "\\" in name:
                path = os.path.join(directory, name)
                shutil.rmtree(path, ignore_errors=True) if os.path.isdir(path) else os.remove(path)

    env_common = {
        "CLIENT_PUBLIC_URL": "http://127.0.0.1:8000",
        "NODE_ENV": "development",
        "CACHE_WARM_UP": "false",
    }

    rust_env = dict(os.environ, SERVER_ROOT=fixture, PORT=str(RUST_PORT), **env_common)
    js_env = dict(os.environ, PORT=str(JS_PORT), **env_common)

    processes = []
    try:
        processes.append(
            subprocess.Popen(
                [rust_bin],
                cwd=fixture,
                env=rust_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        processes.append(
            subprocess.Popen(
                ["node", "index.js"],
                cwd=js_dir,
                env=js_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )

        if not wait_for_health(RUST_PORT):
            sys.exit("the Rust server never became healthy")
        if not wait_for_health(JS_PORT):
            sys.exit("the JavaScript server never became healthy")

        _, body, _ = fetch(RUST_PORT, "/list-files")
        rust_files = json.loads(body)
        _, body, _ = fetch(JS_PORT, "/list-files")
        js_files = json.loads(body)

        print(f"index: rust {len(rust_files)} files, js {len(js_files)} files")
        only_rust = set(rust_files) - set(js_files)
        only_js = set(js_files) - set(rust_files)
        if only_rust or only_js:
            print(f"  MISMATCH: {len(only_rust)} only in rust, {len(only_js)} only in js")
            for path in list(only_rust)[:5]:
                print(f"    rust only: {path!r}")
            for path in list(only_js)[:5]:
                print(f"    js only:   {path!r}")
        else:
            print("  index sets are identical")

        rng = random.Random(args.seed)
        sample = rng.sample(rust_files, min(args.paths, len(rust_files)))

        compared = 0
        mismatches = []
        missing_both = 0

        for stored in sample:
            for spelling in spellings(stored):
                url = encode(spelling)
                rust_status, rust_body, rust_ctype = fetch(RUST_PORT, url)
                js_status, js_body, js_ctype = fetch(JS_PORT, url)
                compared += 1

                if rust_status != js_status:
                    mismatches.append(
                        f"status {rust_status} != {js_status} for {spelling!r}"
                    )
                elif rust_body != js_body:
                    mismatches.append(
                        f"body differs ({len(rust_body)} vs {len(js_body)} bytes) for {spelling!r}"
                    )
                elif rust_ctype != js_ctype:
                    mismatches.append(
                        f"content-type {rust_ctype!r} != {js_ctype!r} for {spelling!r}"
                    )
                if rust_status == 404 and js_status == 404:
                    missing_both += 1

                if len(mismatches) > 40:
                    break
            if len(mismatches) > 40:
                break

        # /batch: the same paths in one round trip must produce the same map.
        batch_paths = [p.replace("\\", "/").encode("cp949").decode("latin-1") for p in sample[:40]]
        batch_paths.append("data/definitely-not-here.spr")
        rust_status, rust_body = post(RUST_PORT, "/batch", {"files": batch_paths})
        js_status, js_body = post(JS_PORT, "/batch", {"files": batch_paths})
        compared += 1
        if rust_status != js_status:
            mismatches.append(f"/batch status {rust_status} != {js_status}")
        elif json.loads(rust_body) != json.loads(js_body):
            rust_keys = set(json.loads(rust_body))
            js_keys = set(json.loads(js_body))
            mismatches.append(
                f"/batch payload differs (only-rust {len(rust_keys - js_keys)}, "
                f"only-js {len(js_keys - rust_keys)})"
            )

        # /batch bounds.
        for count in (0, 51):
            paths = [f"data/f{i}.txt" for i in range(count)]
            rust_status, _ = post(RUST_PORT, "/batch", {"files": paths})
            js_status, _ = post(JS_PORT, "/batch", {"files": paths})
            compared += 1
            if rust_status != js_status:
                mismatches.append(
                    f"/batch with {count} files: status {rust_status} != {js_status}"
                )

        # /search: the reference sends the list as text/html and this sends it as
        # text/plain, so only the body is compared.
        for pattern in [r"\\.lub$", r"\\.spr$", "prontera", "^data.luafiles"]:
            rust_status, rust_body = post(RUST_PORT, "/search", {"filter": pattern})
            js_status, js_body = post(JS_PORT, "/search", {"filter": pattern})
            compared += 1
            if rust_status != js_status:
                mismatches.append(
                    f"/search {pattern!r}: status {rust_status} != {js_status}"
                )
            elif set(rust_body.split(b"\n")) != set(js_body.split(b"\n")):
                rust_lines = rust_body.split(b"\n")
                js_lines = js_body.split(b"\n")
                mismatches.append(
                    f"/search {pattern!r}: {len(rust_lines)} vs {len(js_lines)} results"
                )

        # A handful of paths that should be missing from both.
        for absent in ["data/definitely-not-here.spr", "data/한글없음.txt", "../../etc/passwd"]:
            url = encode(absent)
            rust_status, _, _ = fetch(RUST_PORT, url)
            js_status, _, _ = fetch(JS_PORT, url)
            compared += 1
            if rust_status != js_status:
                mismatches.append(f"status {rust_status} != {js_status} for {absent!r}")

        print(f"compared {compared} responses across {len(sample)} paths")
        print(f"  both 404: {missing_both}")
        if mismatches:
            print(f"  {len(mismatches)} MISMATCH(ES):")
            for line in mismatches[:40]:
                print(f"    {line}")
            return 1

        print("  all responses identical")
        return 0
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    sys.exit(main())
