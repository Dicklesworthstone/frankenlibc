#!/usr/bin/env python3
"""Compare real mount-table FILE operations against the live GNU provider."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess


CASES = (
    "setmntent-file", "fopen-input", "memory-input", "host-file", "truncated-input",
    "append-update", "append-fopen", "append-memory", "cookie-input", "non-utf8-path",
    "error-paths", "append-pipe", "concurrent-readers", "cancel-ordinary",
    "cancel-setmntent", "fopen-c-read", "fopen-c-write", "fdopen-c-ignored",
)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, default=root / "target/conformance/mntent-file")
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    output = args.out_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = root / "tests/integration/fixture_mntent_file.c"
    binary = output / "fixture_mntent_file"
    env = {key: value for key, value in os.environ.items()
           if key not in ("LD_PRELOAD", "LD_AUDIT") and not key.startswith("FRANKENLIBC_")}
    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c11", "-O2", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
        str(source), "-o", str(binary), "-pthread", "-ldl",
    ]
    compile_result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
    (output / "compile.log").write_text(compile_result.stdout + compile_result.stderr)
    if compile_result.returncode:
        raise SystemExit(f"fixture compilation failed: {output / 'compile.log'}")
    provider = subprocess.run([str(binary), "--provider"], env=env,
                              capture_output=True, text=True, timeout=10)
    if provider.returncode or provider.stderr:
        raise SystemExit("GNU provider discovery failed")
    host = str(Path(provider.stdout.strip()).resolve(strict=True))
    records, failures = [], []

    def execute(lane, case, expected, extra):
        try:
            result = subprocess.run([str(binary), case, expected], env=dict(env, **extra),
                                    capture_output=True, text=True, timeout=10)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            code = 124
            stdout = (error.stdout or b"").decode(errors="replace")
            stderr = (error.stderr or b"").decode(errors="replace") + "\nfixture timeout\n"
        record = dict(lane=lane, case=case, returncode=code, stdout=stdout, stderr=stderr)
        records.append(record)
        (output / f"{lane}-{case}.log").write_text(stdout + stderr)
        return record

    negative = execute("provider-negative", CASES[0], str(library), {})
    if (negative["returncode"] != 86 or negative["stdout"] or
            negative["stderr"] != "mntent-file:provider-mismatch:setmntent\n"):
        failures.append("provider-negative")
    for case in CASES:
        expected = f"mntent-file:{case}:PASS\n"
        reference = execute("gnu", case, host, {})
        if reference["returncode"] or reference["stderr"] or reference["stdout"] != expected:
            failures.append(f"gnu:{case}")
        for mode in ("strict", "hardened"):
            result = execute(mode, case, str(library), {
                "LD_PRELOAD": str(library), "FRANKENLIBC_MODE": mode,
                "FRANKENLIBC_THREAD_NATIVE": "0",
            })
            passed = result["returncode"] == 0 and result["stdout"] == expected and not result["stderr"]
            print(f"{mode} {case}: {'PASS' if passed else 'FAIL'}", flush=True)
            if not passed:
                failures.append(f"{mode}:{case}")
    report = dict(library=str(library), library_sha256=digest(library),
                  fixture_sha256=digest(source), binary_sha256=digest(binary),
                  gnu_provider=host, gnu_cases=len(CASES), candidate_cases=2 * len(CASES),
                  failures=failures, runs=records)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        raise SystemExit("mount-table FILE: FAIL " + ", ".join(failures))
    print(f"mount-table FILE: PASS ({len(CASES)} GNU cases, "
          f"{2 * len(CASES)} candidate cases, 1 provider negative)")


if __name__ == "__main__":
    main()
