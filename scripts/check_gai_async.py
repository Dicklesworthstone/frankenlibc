#!/usr/bin/env python3
"""Execute public asynchronous-DNS exports in isolated bounded processes.

Numeric/batch/callback cases are host differential. Loopback DNS cases use
private native-resolver configuration paths, not global /etc changes or kernel
filters; they are independent GNU-contract checks, not host parity claims.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

BASIC = ["wait-v4", "wait-v6", "nowait-v4", "nowait-v6", "wait-mixed",
         "nowait-mixed", "signal-batch", "thread-free", "thread-nested",
         "thread-exit", "thread-attributes", "reuse", "wait-ignores-event",
         "zero-request", "controls"]
BLOCKED = ["dns-v4", "dns-v6", "blocked-timeout", "mixed-pending", "blocked-signal",
           "cancel-one", "cancel-all", "cancel-retire", "cancel-reuse",
           "suspend-cancel", "suspend-pending-cancel", "wait-cancel"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    parser.add_argument("--output", type=Path, default=Path("artifacts/gai-async"))
    parser.add_argument("--host-only", action="store_true")
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    binaries = {}
    source_hashes = {}
    for suite, suffix in (("basic", ""), ("blocked", "_blocked")):
        source = root / f"tests/integration/fixture_gai_async{suffix}.c"
        source_hashes[str(source.relative_to(root))] = hashlib.sha256(source.read_bytes()).hexdigest()
        binary = output / f"fixture-{suite}"
        command = [os.environ.get("CC", "cc"), "-std=c11", "-O2", "-g", "-Wall", "-Wextra",
                   "-Werror", "-pthread", str(source), "-o", str(binary), "-lanl", "-ldl"]
        build = subprocess.run(command, capture_output=True, timeout=60)
        (output / f"build-{suite}.log").write_bytes(build.stdout + build.stderr)
        if build.returncode:
            raise SystemExit(build.stderr.decode(errors="replace"))
        binaries[suite] = binary
    resolv = output / "resolv.conf"
    resolv.write_text("nameserver 127.0.0.77\noptions timeout:30 attempts:1\n")
    nsswitch = output / "nsswitch.conf"
    nsswitch.write_text("hosts: dns\n")
    clean = {key: value for key, value in os.environ.items()
             if key != "LD_PRELOAD" and not key.startswith("FRANKENLIBC_")}
    results = []
    provenance = dict(library=str(library), library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
                      source_sha256=source_hashes,
                      host_libc=subprocess.run(["getconf", "GNU_LIBC_VERSION"], capture_output=True,
                                               text=True, check=True, env=clean).stdout.strip())

    def run(mode: str, suite: str, case: str, negative: bool = False) -> None:
        env = dict(clean)
        if mode != "host":
            env.update(LD_PRELOAD=str(library), FRANKENLIBC_TEST_LIBRARY=str(library),
                       FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE="0")
        if suite == "blocked":
            env.update(FRANKENLIBC_RESOLV_CONF=str(resolv), FRANKENLIBC_NSSWITCH_CONF=str(nsswitch))
        if negative:
            env["FRANKENLIBC_TEST_LIBRARY"] = str(library)
        try:
            process = subprocess.run([str(binaries[suite]), case], env=env,
                                     capture_output=True, timeout=18)
            rc, stdout, stderr = process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired as exc:
            rc, stdout, stderr = -999, exc.stdout or b"", (exc.stderr or b"") + b"\nTIMEOUT\n"
        passed = (rc == 1 and b"FAIL provider mismatch" in stderr) if negative else (
            rc == 0 and stdout == f"PASS {case}\n".encode() and not stderr)
        tag = f"{'negative-' if negative else ''}{mode}-{case}"
        (output / f"{tag}.out").write_bytes(stdout)
        (output / f"{tag}.err").write_bytes(stderr)
        results.append(dict(mode=mode, suite=suite, case=case, negative=negative,
                            oracle_kind="gnu_contract_loopback" if suite == "blocked" else "host_differential",
                            returncode=rc, passed=passed))
        (output / "results.json").write_text(json.dumps(dict(provenance, results=results), indent=2) + "\n")
        print(f"{'PASS' if passed else 'FAIL'} {tag}: rc={rc}", flush=True)

    for case in BASIC:
        run("host", "basic", case)
    for suite, case in (("basic", BASIC[0]), ("blocked", BLOCKED[0])):
        run("host", suite, case, negative=True)
    if not args.host_only:
        for mode in ("strict", "hardened"):
            for suite, cases in (("basic", BASIC), ("blocked", BLOCKED)):
                for case in cases:
                    run(mode, suite, case)
    passed = sum(row["passed"] for row in results)
    print(f"Required checks: {passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
