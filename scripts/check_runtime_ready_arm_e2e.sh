#!/usr/bin/env bash
# Constructor arming and owned-cache allocation reentry. The timeout supervisor
# is never preloaded, so even a constructor deadlock is terminated and reported.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
exec env -u LD_PRELOAD -u LD_AUDIT python3 - "$REPO_ROOT" "$@" <<'PY'
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

root = Path(sys.argv[1])
target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target"))
parser = argparse.ArgumentParser(description="Runtime arming and fresh-thread reentry contract")
parser.add_argument("--library", type=Path, default=Path(os.environ.get(
    "FRANKENLIBC_TEST_LIBRARY", os.environ.get("FRANKENLIBC_SMOKE_LIB_PATH",
                                              target / "release/libfrankenlibc_abi.so"))))
parser.add_argument("--out-dir", type=Path, default=root / "target/runtime_ready_arm_e2e")
parser.add_argument("--timeout", type=float, default=20)
parser.add_argument("--thread-backend", choices=("hosted", "native", "all"), default="hosted",
                    help="fresh-thread backends to exercise (default: hosted)")
parser.add_argument("--case", dest="cases", action="append",
                    choices=("startup", "fresh-serial", "fresh-parallel"),
                    help="case to run; repeat to select several (default: all)")
args = parser.parse_args(sys.argv[2:])
if args.timeout <= 0:
    parser.error("--timeout must be positive")
library = args.library.resolve(strict=True)
output = args.out_dir.resolve()
output.mkdir(parents=True, exist_ok=True)
source = root / "tests/integration/fixture_runtime_ready_arm.cpp"
binary = output / "fixture_runtime_ready_arm"
environment = {key: value for key, value in os.environ.items()
               if key not in ("LD_PRELOAD", "LD_AUDIT") and not key.startswith("FRANKENLIBC_")}
command = shlex.split(os.environ.get("CXX", "c++")) + [
    "-std=c++17", "-O2", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
    str(source), "-o", str(binary), "-pthread", "-ldl",
]
compiled = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=60)
(output / "compile.log").write_text(compiled.stdout + compiled.stderr)
if compiled.returncode:
    raise SystemExit(f"fixture compilation failed: {output / 'compile.log'}")


def run(label, case, arguments, extra=None):
    invocation = [str(binary)] + arguments
    try:
        result = subprocess.run(invocation, env=dict(environment, **(extra or {})),
                                capture_output=True, text=True, timeout=args.timeout)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code = 124
        stdout = (error.stdout or b"").decode(errors="replace")
        stderr = (error.stderr or b"").decode(errors="replace") + "fixture timeout\n"
    record = {"lane": label, "case": case, "command": invocation, "returncode": code,
              "stdout": stdout, "stderr": stderr}
    (output / f"{label}-{case}.log").write_text(stdout + stderr)
    return record


provider = run("gnu", "provider", ["--provider"])
if provider["returncode"] or provider["stderr"]:
    raise SystemExit("GNU provider discovery failed")
host = str(Path(provider["stdout"].strip()).resolve(strict=True))
records = []
failures = []


def check(record, code, stdout, stderr=""):
    passed = (record["returncode"] == code and record["stdout"] == stdout and
              record["stderr"] == stderr)
    record["passed"] = passed
    records.append(record)
    label = f"{record['lane']}:{record['case']}"
    print(f"{label}: {'PASS' if passed else 'FAIL'}", flush=True)
    if not passed:
        failures.append(label)


# An absent provider must produce the intended diagnostic, not any failure,
# timeout, abort, or crash. Also reject a valid GNU run claimed as candidate.
check(run("negative", "missing-runtime", []), 2, "",
      "FAIL: FFI symbols not resolved (check LD_PRELOAD)\n")
check(run("negative", "wrong-provider", ["--case", "startup", str(library)]), 86, "",
      "runtime-ready-arm:provider-mismatch:malloc\n")

counts = {"startup": 0, "fresh-serial": 40, "fresh-parallel": 48}
cases = list(dict.fromkeys(args.cases or counts))
backends = {"hosted": ("0",), "native": ("1",), "all": ("0", "1")}[args.thread_backend]
# Native raw-clone threads still share host TLS; completing native TLS remains
# open. Keep the parallel workload available as an explicit diagnostic, with
# the same assertions and failure status as every supported hosted run.
# Startup has no worker threads, so do not duplicate it for --thread-backend all.
startup_backend = "1" if args.thread_backend == "native" else "0"


def expected(case):
    return f"runtime-ready-arm:{case}:PASS workers={counts[case]} iterations=12\n"


def candidate_environment(mode, native="0"):
    return {"LD_PRELOAD": str(library), "FRANKENLIBC_MODE": mode,
            "FRANKENLIBC_THREAD_NATIVE": native, "FRANKENLIBC_RUNTIME_MATH": "on"}


for case in cases:
    reference = run("gnu", case, ["--case", case, host, "--reference"])
    check(reference, 0, expected(case))
    for mode in ("strict", "hardened"):
        for native in (startup_backend,) if case == "startup" else backends:
            label = f"{'native' if native == '1' else 'hosted'}-{mode}"
            result = run(label, case, ["--case", case, str(library)],
                         candidate_environment(mode, native))
            check(result, 0, expected(case))

# Retain the original eight-process arming stress check with the supervisor
# outside LD_PRELOAD and inspect every child result individually.
def parallel_startup(index):
    return run(f"parallel-{index}", "startup", ["--case", "startup", str(library)],
               candidate_environment("strict", startup_backend))


if "startup" in cases:
    with ThreadPoolExecutor(max_workers=8) as pool:
        for result in pool.map(parallel_startup, range(8)):
            check(result, 0, expected("startup"))


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


gnu_count = sum(record["lane"] == "gnu" for record in records)
negative_count = sum(record["lane"] == "negative" for record in records)
candidate_count = len(records) - gnu_count - negative_count
report = {
    "schema_version": "runtime_ready_arm_e2e.v2",
    "library": str(library), "library_sha256": sha256(library),
    "fixture_sha256": sha256(source), "binary_sha256": sha256(binary),
    "gnu_provider": host, "thread_backend": args.thread_backend, "selected_cases": cases,
    "gnu_cases": gnu_count, "candidate_cases": candidate_count, "negative_cases": negative_count,
    "failures": failures, "runs": records,
}
(output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
if failures:
    raise SystemExit("runtime-ready-arm: FAIL " + ", ".join(failures))
print(f"runtime-ready-arm: PASS ({gnu_count} GNU, {candidate_count} candidate, "
      f"{negative_count} negative cases)")
PY
