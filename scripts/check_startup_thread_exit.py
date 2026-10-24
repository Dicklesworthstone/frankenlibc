#!/usr/bin/env python3
"""Compare initial-thread exit/cancellation with live GNU C and C++ runtimes."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

CASES = {
    "return": 23, "negative-return": 151, "exit": 23, "thread-exit": 0,
    "self-cancel": 0, "disabled-cancel": 0, "worker-exit": 0,
    "worker-cancel": 0, "worker-self-cancel": 0, "fork-exit": 23,
    "constructor-exit": 29,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", nargs="?", type=Path)
    parser.add_argument("--reference-only", action="store_true")
    parser.add_argument("--startup-adapter", type=Path,
                        help="diagnostic runner only; this does not qualify a full candidate DSO")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.reference_only and args.library is None:
        parser.error("supply a candidate library or --reference-only")
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = root / "tests/integration/fixture_startup_thread_exit.c"
    builds = {
        "c": [os.environ.get("CC", "cc"), "-std=c11"],
        "c-exceptions": [os.environ.get("CC", "cc"), "-std=c11", "-fexceptions"],
        "cpp": [os.environ.get("CXX", "c++"), "-x", "c++", "-std=c++17"],
    }
    for name, command in builds.items():
        subprocess.run(command + ["-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
                       str(source), "-ldl", "-o", str(out / name)], check=True)
    clean = {key: value for key, value in os.environ.items()
             if key != "LD_PRELOAD" and not key.startswith("FRANKENLIBC_")}
    clean["FRANKENLIBC_MAIN_CTOR_DROP"] = "removed-by-constructor"
    results = []
    failures = []
    references = {}

    def run(label, build, case, env, reference=None, negative=False):
        if case == "constructor-exit":
            env = dict(env, FRANKENLIBC_MAIN_CTOR_EXIT="1")
        try:
            proc = subprocess.run([str(out / build), case], env=env,
                                  capture_output=True, timeout=15)
            actual = (proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as error:
            actual = (124, error.stdout or b"", error.stderr or b"")
        rc, stdout, stderr = actual
        if negative:
            passed = actual == (117, b"", b"WRONG STARTUP/THREAD PROVIDER\n")
        elif reference is not None:
            passed = actual == reference
        else:
            passed = rc == CASES[case] and not stderr
            passed &= stdout.count(b"I") == 1
            passed &= stdout.count(b"D") == (2 if case == "fork-exit" else 1)
            passed &= stdout.count(b"A") == (2 if case == "fork-exit" else 1)
            passed &= stdout.count(b"J") == int(case.startswith("worker-"))
            expected_keys = 3 if case in (
                "thread-exit", "self-cancel", "disabled-cancel", "worker-exit",
                "worker-cancel", "worker-self-cancel", "fork-exit") else 0
            passed &= stdout.count(b"K") == expected_keys
        prefix = f"{label}-{build}-{case}"
        (out / f"{prefix}.out").write_bytes(stdout)
        (out / f"{prefix}.err").write_bytes(stderr)
        results.append({"provider": label, "build": build, "case": case,
                        "returncode": rc, "stdout": stdout.decode(errors="replace"),
                        "stderr": stderr.decode(errors="replace"), "passed": bool(passed)})
        if not passed:
            failures.append(prefix)
            print(f"FAIL {prefix}: {actual!r}", flush=True)
        return actual

    for build in builds:
        for case in CASES:
            references[build, case] = run("host", build, case, clean)
    library = args.library.resolve(strict=True) if args.library else None
    adapter = args.startup_adapter.resolve(strict=True) if args.startup_adapter else None
    if library:
        run("provider-negative", "c", "thread-exit",
            dict(clean, FRANKENLIBC_TEST_LIBRARY=str(library)), negative=True)
        for mode in ("strict", "hardened"):
            env = dict(clean, LD_PRELOAD=f"{adapter}:{library}" if adapter else str(library),
                       FRANKENLIBC_TEST_LIBRARY=str(library), FRANKENLIBC_MODE=mode,
                       FRANKENLIBC_THREAD_NATIVE="0", FRANKENLIBC_STARTUP_DELEGATE="0")
            if adapter:
                env["FRANKENLIBC_TEST_STARTUP_LIBRARY"] = str(adapter)
            for build in builds:
                for case in CASES:
                    run(mode, build, case, env, references[build, case])
    report = {"diagnostic": adapter is not None, "results": results, "failures": failures,
              "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest() if library else None,
              "adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest() if adapter else None}
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Initial-thread lifecycle: {len(results) - len(failures)}/{len(results)} checks passed",
          flush=True)
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
