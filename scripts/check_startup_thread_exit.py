#!/usr/bin/env python3
"""Compare initial-thread exit/cancellation with live GNU C and C++ runtimes."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

CASES = {
    "return": 23, "negative-return": 151, "exit": 23, "thread-exit": 0,
    "self-cancel": 0, "disabled-cancel": 0, "worker-exit": 0,
    "worker-cancel": 0, "worker-self-cancel": 0, "worker-last-exit": 0,
    "worker-last-detached": 0, "fork-exit": 23,
    "constructor-exit": 29,
}


def build_fixed_executables(source: Path, out: Path) -> tuple[str, str]:
    """Keep the normal CRT handoff and remove only the optional PT_PHDR tag."""
    names = ("c-exec-with-phdr", "c-exec-without-phdr")
    control, variant = (out / name for name in names)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall",
                    "-Wextra", "-Werror", "-pthread", "-fno-pie", "-no-pie",
                    str(source), "-ldl", "-o", str(control)], check=True)
    original = control.read_bytes()
    if (len(original) < 64 or original[:7] != b"\x7fELF\x02\x01\x01"
            or struct.unpack_from("<H", original, 16)[0] != 2):
        raise ValueError("fixed executable fixture must be ELF64 little-endian ET_EXEC")
    phoff = struct.unpack_from("<Q", original, 32)[0]
    phent, phnum = struct.unpack_from("<HH", original, 54)
    if phent != 56 or not phnum or phoff < 64 or phoff + phnum * phent > len(original):
        raise ValueError("fixed executable fixture has an invalid program-header table")
    offsets = [phoff + index * phent for index in range(phnum)]
    types = [struct.unpack_from("<I", original, offset)[0] for offset in offsets]
    if types.count(6) != 1 or 2 not in types:
        raise ValueError("fixed executable fixture requires PT_PHDR and PT_DYNAMIC")
    modified = bytearray(original)
    struct.pack_into("<I", modified, offsets[types.index(6)], 0)
    variant.write_bytes(modified)
    variant.chmod(control.stat().st_mode & 0o777)
    return names


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
    fixed_builds = build_fixed_executables(source, out)
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
                "worker-cancel", "worker-self-cancel", "worker-last-exit",
                "worker-last-detached", "fork-exit") else 0
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
    for build in fixed_builds:
        references[build, "return"] = run("host", build, "return", clean,
                                          references["c", "return"])
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
            for backend in ("0", "1"):
                fixed_env = dict(env, FRANKENLIBC_THREAD_NATIVE=backend)
                for build in fixed_builds:
                    run(f"{mode}-fixed-{backend}", build, "return", fixed_env,
                        references[build, "return"])
            # The last native clone used to discard its handle/TLS before
            # process callbacks. Hosted workers cannot exercise that path.
            # C++ compiler TLS remains a separate native integration boundary.
            native_env = dict(env, FRANKENLIBC_THREAD_NATIVE="1")
            for build in ("c", "c-exceptions"):
                for case in ("worker-last-exit", "worker-last-detached"):
                    run(f"{mode}-native", build, case, native_env,
                        references[build, case])
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
