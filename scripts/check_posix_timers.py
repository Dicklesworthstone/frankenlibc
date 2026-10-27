#!/usr/bin/env python3
"""Compare POSIX timer behavior with live GNU libc and the deployed candidate."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CASES = (
    "thread-monotonic", "thread-realtime", "thread-absolute",
    "thread-process-cpu", "thread-thread-cpu", "periodic-disarm", "overlap",
    "attributes-snapshot", "foreign-attributes", "callback-exit", "callback-cancel",
    "pending-sigpipe", "self-delete",
    "signal", "none", "default-signal", "fork-reset", "invalid", "lifetime",
    "concurrent",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, default=os.environ.get(
        "FRANKENLIBC_TEST_LIBRARY",
        str(Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
            / "release/libfrankenlibc_abi.so")))
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--require-kernel-accounting", action="store_true",
                        help="fail if /proc/self/timers is unavailable (used in CI)")
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = args.out_dir or ROOT / "target/conformance/posix_timers" / stamp
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve()
    executable = output / "fixture"
    clean_env = dict(os.environ)
    for name in ("LD_PRELOAD", "FRANKENLIBC_MODE", "FRANKENLIBC_THREAD_NATIVE"):
        clean_env.pop(name, None)
    clean_env["FRANKENLIBC_RUNTIME_MATH"] = "off"
    if args.require_kernel_accounting:
        clean_env["FRANKENLIBC_REQUIRE_TIMER_ACCOUNTING"] = "1"
    compile_command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c11", "-O2", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
        str(ROOT / "tests/integration/fixture_posix_timers.c"),
        "-pthread", "-ldl", "-lrt", "-o", str(executable),
    ]
    compiled = subprocess.run(compile_command, env=clean_env,
                              capture_output=True, text=True, timeout=120)
    (output / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print(compiled.stdout + compiled.stderr, file=sys.stderr)
        return 1
    discovered = subprocess.run([str(executable), "--provider"], env=clean_env,
                                capture_output=True, text=True, timeout=15,
                                check=True)
    host = Path(discovered.stdout.strip()).resolve(strict=True)
    if library.samefile(host):
        raise ValueError("candidate library is the live GNU provider")

    records = []
    reference = {}

    def run_case(label, case, environment, expected, negative=False):
        command = [str(executable), case, str(expected), str(host)]
        try:
            result = subprocess.run(command, env=environment, capture_output=True,
                                    text=True, timeout=15)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            code = 124
            stdout = (error.stdout or b"").decode(errors="replace")
            stderr = (error.stderr or b"").decode(errors="replace") + "\nTIMEOUT\n"
        prefix = f"{label}-{case}"
        (output / f"{prefix}.stdout").write_text(stdout)
        (output / f"{prefix}.stderr").write_text(stderr)
        if negative:
            passed = (code == 86 and not stdout and
                      stderr == "posix-timers:provider-mismatch:timer_create\n")
        elif label == "gnu":
            expected = f"posix-timers:{case}:PASS\n"
            accepted = (expected,)
            if case == "none":
                accepted = tuple(f"posix-timers:none:disarmed-expiry-zero={value}\n"
                                 + expected for value in (0, 1))
            passed = code == 0 and stdout in accepted
            if passed:
                reference[case] = stdout
        else:
            passed = code == 0 and case in reference and stdout == reference[case]
        records.append({"provider": label, "case": case,
                        "returncode": code, "passed": passed,
                        "kernel_accounting_unavailable":
                            "posix-timers:kernel-accounting-unavailable" in stderr})
        print(f"{prefix}: {'PASS' if passed else 'FAIL'}")
        if not passed:
            print((stdout + stderr)[-4000:], file=sys.stderr)

    for case in CASES:
        run_case("gnu", case, clean_env, host)
    for mode in ("strict", "hardened"):
        environment = dict(clean_env, LD_PRELOAD=str(library),
                           FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE="0")
        for case in CASES:
            run_case(mode, case, environment, library)
    run_case("provider-negative", CASES[0], clean_env, library, negative=True)
    report = {
        "library": str(library),
        "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
        "gnu_library": str(host),
        "thread_backend": "hosted",
        "kernel_accounting_required": args.require_kernel_accounting,
        "records": records,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    passed = all(record["passed"] for record in records)
    print(f"POSIX timers: {'PASS' if passed else 'FAIL'} "
          f"({len(CASES)} live GNU cases, {2 * len(CASES)} candidate cases, "
          "1 provider negative)")
    print(f"artifacts={output}")
    if any(record["kernel_accounting_unavailable"] for record in records):
        print("Kernel timer accounting unavailable; creation/deletion cases still ran. "
              "CI requires /proc/self/timers.")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
