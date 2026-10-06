#!/usr/bin/env python3
"""Compile byte-identical DNS source copies and their original tests.

This focused diagnostic is not whole-workspace or release-ABI evidence. It
retains the real source layout and the core crate's existing proptest dependency;
no implementation, assertion, or cfg gate is rewritten to make the subset build.
All inputs, the dependency lock and command logs are retained in the artifact dir.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib


def execute(command: list[str], cwd: Path, log: Path) -> str:
    env = dict(os.environ, CARGO_TERM_COLOR="never")
    # The diagnostic must not share/alter the full workspace's build artifacts.
    env.pop("CARGO_TARGET_DIR", None)
    result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=600)
    log.write_text("$ " + " ".join(command) + "\n" + result.stdout)
    print(result.stdout, end="", flush=True)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}); see {log}")
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts/raw-resolver"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    core = root / "crates/frankenlibc-core"
    inputs = ["src/dns_transport.rs", "src/dns_transport/raw.rs",
              "src/resolv/config.rs", "src/resolv/dns.rs", "src/resolv/dns_name.rs",
              "tests/raw_dns_transport.rs", "tests/dns_nameserver_failover.rs"]
    toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    dep = tomllib.loads((core / "Cargo.toml").read_text())["dev-dependencies"]["proptest"]
    if not isinstance(dep, str):
        raise RuntimeError("proptest dependency shape changed: review diagnostic dependency wiring")
    harness = Path(tempfile.mkdtemp(prefix="frankenlibc-dns-source-"))
    hashes = {}
    for name in inputs:
        source = core / name
        data = source.read_bytes()
        target = harness / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        assert target.read_bytes() == data
        hashes[str(source.relative_to(root))] = {
            "git_blob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    # Ordinary module declarations retain dns_transport/raw.rs resolution.
    # #[path=".../dns_transport.rs"] changed its child search directory to
    # src/raw.rs in the earlier failing harness (E0583).
    (harness / "src/lib.rs").write_text("#![deny(unsafe_code)]\npub mod resolv;\npub mod dns_transport;\n")
    (harness / "src/resolv/mod.rs").write_text(
        "pub mod config;\npub mod dns_name;\npub mod dns;\npub use config::ResolverConfig;\n")
    (harness / "Cargo.toml").write_text(
        '[package]\nname = "frankenlibc-core"\nversion = "0.0.0"\nedition = "2024"\n'
        '[workspace]\n[dev-dependencies]\nproptest = ' + json.dumps(dep) + '\n')
    (artifacts / "source-blobs.json").write_text(json.dumps(hashes, indent=2) + "\n")
    (artifacts / "diagnostic-harness.txt").write_text(str(harness) + "\n")
    (artifacts / "source-commit.txt").write_bytes(
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root))
    cargo = ["cargo", "+" + toolchain]
    execute(cargo + ["generate-lockfile"], harness, artifacts / "dependency-resolution.log")
    (artifacts / "diagnostic-Cargo.lock").write_bytes((harness / "Cargo.lock").read_bytes())
    execute(cargo + ["fetch", "--locked"], harness, artifacts / "dependency-fetch.log")
    for label, selection in [("source-unit", ["--lib"]),
                             ("source-failover", ["--test", "dns_nameserver_failover"]),
                             ("source-raw-sockets", ["--test", "raw_dns_transport"])]:
        output = execute(cargo + ["test", "--locked", "--offline"] + selection + ["--", "--nocapture"],
                         harness, artifacts / (label + ".log"))
        if not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed;", output):
            raise RuntimeError(f"{label}: no nonzero passing test execution")
    for name in inputs:
        if (harness / name).read_bytes() != (core / name).read_bytes():
            raise RuntimeError("source changed during validation: " + name)
    print("PASS: original DNS unit, failover and raw-socket suites (source subset only)")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, KeyError, ValueError) as error:
        print(f"native DNS diagnostic failed: {error}", file=sys.stderr)
        sys.exit(1)
