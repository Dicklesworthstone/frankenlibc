#!/usr/bin/env python3
"""Execute real exported memory/string operations in fresh preload processes.

Usage: python3 scripts/check_membrane_access.py LIBRARY [--output DIRECTORY]
No missing compiler, missing library, timeout, wrong provider, or failed case is
counted as a pass. The gate never uses a reference libc for invalid accesses.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

OPERATIONS = (
    "memcpy-dst", "memcpy-src", "memmove-dst", "memmove-src", "memset",
    "strlen", "strnlen", "memcmp-lhs", "memcmp-rhs",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    parser.add_argument("--output", type=Path, default=Path("target/membrane-access"))
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    if not library.is_file():
        raise ValueError("library must be a regular file")
    root = Path(__file__).resolve().parent.parent
    source = root / "tests/integration/fixture_membrane_access.c"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    executable = output / "fixture_membrane_access"
    env = os.environ.copy()
    env.pop("LD_PRELOAD", None)
    env.pop("FRANKENLIBC_LOG", None)
    env.pop("FRANKENLIBC_INTEGRITY_BOUNDS_CHILD", None)
    build = subprocess.run(
        ["cc", "-std=c11", "-O2", "-fno-builtin", "-Wall", "-Wextra", "-Werror", str(source), "-ldl", "-o", str(executable)],
        env=env, capture_output=True, text=True, timeout=120,
    )
    (output / "compile.log").write_text(build.stdout + build.stderr)
    if build.returncode:
        print(build.stdout + build.stderr, file=sys.stderr)
        return 2
    cases = []
    for math in ("on", "off"):
        for mode in ("strict", "hardened"):
            cases.extend((mode, math, op, "valid") for op in OPERATIONS)
        for fault in ("header", "canary"):
            cases.extend(("hardened", math, op, fault) for op in OPERATIONS)
        cases.extend(("hardened", math, op, "end") for op in OPERATIONS if op not in ("strlen", "strnlen"))
        cases.extend(("hardened", math, op, "quarantine") for op in (
            "memcpy-src", "memmove-src", "strlen", "strnlen", "memcmp-lhs", "memcmp-rhs",
        ))
    assert len(cases) == 98
    records = []
    for mode, math, operation, fault in cases:
        case_env = dict(env, LD_PRELOAD=str(library), FRANKENLIBC_MODE=mode, FRANKENLIBC_RUNTIME_MATH=math)
        command = [str(executable), str(library), operation, fault]
        try:
            result = subprocess.run(command, env=case_env, capture_output=True, text=True, timeout=20)
            expected = f"operation={operation} fault={fault} result=pass\n"
            record = dict(mode=mode, math=math, operation=operation, fault=fault,
                          returncode=result.returncode, stdout=result.stdout, stderr=result.stderr,
                          passed=result.returncode == 0 and result.stdout == expected, timeout=False)
        except subprocess.TimeoutExpired as exc:
            def decoded(value: bytes | str | None) -> str:
                return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")
            record = dict(mode=mode, math=math, operation=operation, fault=fault,
                          returncode=None, stdout=decoded(exc.stdout), stderr=decoded(exc.stderr),
                          passed=False, timeout=True)
        records.append(record)
        print(json.dumps(record), flush=True)
    # A caller without the preload must reject the expected candidate before
    # touching allocator metadata; the failure must be provider-specific.
    control = subprocess.run([str(executable), str(library), "memcpy-dst", "valid"],
                             env=env, capture_output=True, text=True, timeout=20)
    provider_rejected = control.returncode == 2 and "provider rejection" in control.stderr
    passed = sum(row["passed"] for row in records)
    report = dict(library=str(library), library_sha256=sha256(library),
                  fixture_sha256=sha256(source), total=len(cases), passed=passed,
                  failed=len(cases)-passed, provider_control=dict(passed=provider_rejected,
                  returncode=control.returncode, stdout=control.stdout, stderr=control.stderr), cases=records)
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"membrane access ABI: {passed}/{len(cases)} passed; wrong provider rejected={provider_rejected}")
    return 0 if passed == len(cases) and provider_rejected else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"membrane access gate error: {exc}", file=sys.stderr)
        raise SystemExit(2)
