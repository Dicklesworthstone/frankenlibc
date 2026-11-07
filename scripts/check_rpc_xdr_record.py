#!/usr/bin/env python3
"""Provider-bound XDR record-stream checks against independent GNU/wire oracles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

CASES = (
    "create", "split-1", "split-2", "split-3", "split-5", "coalesced",
    "zero-nonterminal", "navigation", "eof-consumes", "record-boundary",
    "read-error-marker", "read-error-body", "read-error-retry", "batch", "destroy-deferred",
    "output-fragments", "buffer-sizes", "odd-batch", "write-errors", "inline",
    "position-encode", "position-decode", "socket",
)
NATIVE_CASES = ("native-boundaries",)
MODES = ("strict", "hardened")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_environment() -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "LD_PRELOAD", "FRANKENLIBC_MODE", "FRANKENLIBC_TEST_LIBRARY",
        "RPC_TEST_FORCE_HOST", "RPC_TEST_FORCE_HOST_OPS",
    ):
        env.pop(key, None)
    return env


def execute(argv: list[str], env: dict[str, str], timeout: int = 15) -> dict:
    try:
        run = subprocess.run(argv, env=env, text=True, capture_output=True, timeout=timeout)
        return {"argv": argv, "exit": run.returncode, "stdout": run.stdout,
                "stderr": run.stderr, "timeout": False}
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")
        return {"argv": argv, "exit": None, "stdout": text(error.stdout),
                "stderr": text(error.stderr), "timeout": True}


def main() -> int:
    # Required assertions in this gate must never disappear under python -O.
    if not __debug__:
        raise RuntimeError("XDR record gate requires Python assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", nargs="?", type=Path)
    parser.add_argument("--host-only", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.host_only and args.library is None:
        parser.error("provide the candidate shared library or --host-only")
    if args.host_only and args.library is not None:
        parser.error("--host-only cannot accept a candidate library")
    root = Path(__file__).resolve().parents[1]
    fixture = root / "tests/integration/fixture_rpc_xdr_record.c"
    source = root / "crates/frankenlibc-abi/src/rpc_abi.rs"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = output / "fixture_rpc_xdr_record"
    env = clean_environment()
    library = args.library.resolve() if args.library is not None else None
    if library is not None and not library.is_file():
        parser.error(f"candidate library does not exist: {library}")
    identities = {"fixture": digest(fixture), "runner": digest(Path(__file__)),
                  "source": digest(source)}
    if library is not None:
        identities["library"] = digest(library)
    compile_result = execute(
        [os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
         str(fixture), "-ldl", "-o", str(binary)], env, timeout=60)
    report = {"scope": "exported XDR record callbacks, bounded wire, memfd and socketpair",
              "platform": platform.platform(), "library": str(library) if library else None,
              "host_only": args.host_only, "hashes": identities,
              "compile": compile_result, "cases": [], "passed": False}
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    if compile_result["exit"] != 0 or compile_result["timeout"]:
        print(json.dumps(compile_result, indent=2), file=sys.stderr)
        return 1
    report["fixture_binary_sha256"] = digest(binary)

    def check(provider: str, case: str, case_env: dict[str, str], negative: bool = False):
        row = execute([str(binary), case], case_env)
        row.update(provider=provider, case=case, negative=negative)
        if negative:
            row["passed"] = (row["exit"] == 113 and not row["timeout"]
                             and "WRONG XDR RECORD PROVIDER" in row["stderr"])
        else:
            row["passed"] = (row["exit"] == 0 and not row["timeout"]
                             and row["stdout"] == f"PASS {case}\n"
                             and row["stderr"] == "")
        report["cases"].append(row)
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{'PASS' if row['passed'] else 'FAIL'} {provider} {case}", flush=True)

    for case in CASES:
        check("gnu", case, env)
    if library is not None:
        for mode in MODES:
            candidate_env = dict(env, LD_PRELOAD=str(library), FRANKENLIBC_MODE=mode,
                                 FRANKENLIBC_TEST_LIBRARY=str(library))
            for case in CASES + NATIVE_CASES:
                check(mode, case, candidate_env)
            for switch in ("RPC_TEST_FORCE_HOST", "RPC_TEST_FORCE_HOST_OPS"):
                check(f"{mode}/{switch}", "create", dict(candidate_env, **{switch: "1"}), True)
    expected = len(CASES)
    if library is not None:
        expected += len(MODES) * (len(CASES) + len(NATIVE_CASES) + 2)
    hashes_stable = (digest(fixture) == identities["fixture"]
                     and digest(source) == identities["source"]
                     and digest(Path(__file__)) == identities["runner"]
                     and (library is None or digest(library) == identities["library"]))
    report["counts"] = {
        "required_gnu": len(CASES),
        "required_candidate": 0 if library is None else len(MODES) * (len(CASES) + len(NATIVE_CASES)),
        "required_provider_negative": 0 if library is None else len(MODES) * 2,
        "observed": len(report["cases"]),
        "passed": sum(row["passed"] for row in report["cases"]),
    }
    report["hashes_stable"] = hashes_stable
    report["passed"] = (len(report["cases"]) == expected and hashes_stable
                        and all(row["passed"] for row in report["cases"]))
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["counts"], sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
