#!/usr/bin/env python3
"""Compare owned native errno/cancellation settings with live GNU pthreads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess


CASES = (
    "errno-siblings", "errno-signals", "errno-return", "errno-exit",
    "cancel-settings", "cancel-reuse", "cancel-invalid", "cooperative-cancel",
    "cancel-pending-reuse",
)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path,
                        default=Path(os.environ.get("FRANKENLIBC_TEST_LIBRARY",
                                                    root / "target/release/libfrankenlibc_abi.so")))
    parser.add_argument("--out-dir", type=Path,
                        default=root / "target/conformance/pthread_native_state")
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    output = args.out_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = root / "tests/integration/fixture_pthread_native_state.c"
    binary = output / "fixture_pthread_native_state"
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("LD_PRELOAD", "LD_AUDIT") and not key.startswith("FRANKENLIBC_")}
    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c11", "-O2", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
        str(source), "-o", str(binary), "-pthread", "-ldl",
    ]
    compiled = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=60)
    (output / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise SystemExit(f"fixture compilation failed: {output / 'compile.log'}")
    provider = subprocess.run([str(binary), "--provider"], env=environment,
                              capture_output=True, text=True, timeout=15)
    if provider.returncode or provider.stderr:
        raise SystemExit(f"GNU provider discovery failed: {provider.stderr}")
    host = str(Path(provider.stdout.strip()).resolve(strict=True))
    records = []
    failures = []

    def execute(label, case, expected, extra):
        try:
            run = subprocess.run([str(binary), case, expected],
                                 env=dict(environment, **extra), capture_output=True,
                                 text=True, timeout=15)
            code, stdout, stderr = run.returncode, run.stdout, run.stderr
        except subprocess.TimeoutExpired as error:
            code = 124
            stdout = (error.stdout or b"").decode(errors="replace")
            stderr = (error.stderr or b"").decode(errors="replace") + "\nfixture timeout\n"
        record = {"lane": label, "case": case, "returncode": code,
                  "stdout": stdout, "stderr": stderr}
        records.append(record)
        (output / f"{label}-{case}.log").write_text(stdout + stderr)
        return record

    negative = execute("provider-negative", CASES[0], str(library), {})
    if not (negative["returncode"] == 86 and negative["stdout"] == "" and
            negative["stderr"] == "pthread-native-state:provider-mismatch:__errno_location\n"):
        failures.append("provider-negative")

    for case in CASES:
        reference = execute("gnu", case, host, {})
        expected = f"pthread-native-state:{case}:PASS\n"
        if reference["returncode"] or reference["stdout"] != expected or reference["stderr"]:
            failures.append(f"gnu:{case}")
        for mode in ("strict", "hardened"):
            for native in ("0", "1"):
                label = f"{'native' if native == '1' else 'hosted'}-{mode}"
                candidate = execute(label, case, str(library), {
                    "LD_PRELOAD": str(library), "FRANKENLIBC_MODE": mode,
                    "FRANKENLIBC_THREAD_NATIVE": native, "FRANKENLIBC_RUNTIME_MATH": "off",
                })
                passed = (candidate["returncode"] == 0 and candidate["stdout"] == expected
                          and candidate["stderr"] == "")
                print(f"{label} {case}: {'PASS' if passed else 'FAIL'}", flush=True)
                if not passed:
                    failures.append(f"{label}:{case}")

    report = {"library": str(library), "library_sha256": sha256(library),
              "fixture_sha256": sha256(source), "binary_sha256": sha256(binary),
              "gnu_provider": host, "gnu_cases": len(CASES),
              "candidate_cases": 4 * len(CASES), "failures": failures, "runs": records}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        raise SystemExit("pthread native state: FAIL " + ", ".join(failures))
    print(f"pthread native state: PASS ({len(CASES)} live GNU cases, "
          f"{4 * len(CASES)} candidate cases, provider negative)")


if __name__ == "__main__":
    main()
