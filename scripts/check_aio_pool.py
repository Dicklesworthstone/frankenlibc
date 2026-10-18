#!/usr/bin/env python3
"""Execute bounded-worker contracts against live glibc and exact release exports."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

CASES = ["backlog", "limit", "clamp", "default-limit", "idle-restart",
         "callback-progress", "canceled-notifications", "retirement-race"]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", nargs="?", type=Path, help="omit for host-only execution")
    parser.add_argument("--output", type=Path, default=Path("artifacts/aio-pool"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items()
           if k not in ("LD_PRELOAD", "FRANKENLIBC_TEST_LIBRARY", "FRANKENLIBC_MODE")}
    records = []
    library = str(args.library.resolve(strict=True)) if args.library else None
    provenance = {"fixture_sha256": hashlib.sha256((root / "tests/integration/fixture_aio_pool.c").read_bytes()).hexdigest()}
    if library:
        provenance["library_sha256"] = hashlib.sha256(Path(library).read_bytes()).hexdigest()
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")

    def run(binary, abi, case, kind, mode, iteration, environment):
        start = time.monotonic()
        try:
            result = subprocess.run([str(binary), case], env=environment,
                                    capture_output=True, timeout=30, check=False)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, code = exc.stdout or b"", exc.stderr or b"", None
        passed = (code == 0 and stdout == f"PASS {case}\n".encode() and not stderr)
        if kind == "provider-negative":
            passed = code == 1 and b"expected.st_dev==actual.st_dev" in stderr
        stem = f"{kind}-{mode}-{abi}-{iteration}-{case}"
        (out / f"{stem}.out").write_bytes(stdout)
        (out / f"{stem}.err").write_bytes(stderr)
        records.append(dict(kind=kind, mode=mode, abi=abi, case=case, iteration=iteration,
                            passed=passed, returncode=code, seconds=time.monotonic()-start))
        (out / "results.json").write_text(json.dumps(records, indent=2) + "\n")
        if not passed:
            raise SystemExit(f"FAIL {stem}: rc={code} {stderr.decode(errors='replace')}")

    for abi in ("native", "large"):
        binary = out / f"fixture-{abi}"
        command = ["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread"]
        if abi == "large":
            command.append("-D_FILE_OFFSET_BITS=64")
        command += [str(root / "tests/integration/fixture_aio_pool.c"), "-ldl", "-lrt", "-o", str(binary)]
        subprocess.run(command, check=True, env=env)
        for case in CASES:
            run(binary, abi, case, "host", "host", 0, env)
        if library:
            run(binary, abi, "backlog", "provider-negative", "host", 0,
                dict(env, FRANKENLIBC_TEST_LIBRARY=library))
            for mode in ("strict", "hardened"):
                candidate = dict(env, LD_PRELOAD=library, FRANKENLIBC_TEST_LIBRARY=library,
                                 FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE="0", RUST_BACKTRACE="1")
                for iteration in range(2):
                    for case in CASES:
                        run(binary, abi, case, "candidate", mode, iteration, candidate)
    print(f"PASS AIO pool: {len(records)} executions; "
          f"{sum(r['kind']=='candidate' for r in records)} candidate, "
          f"{sum(r['kind']=='host' for r in records)} host, "
          f"{sum(r['kind']=='provider-negative' for r in records)} provider controls")

if __name__ == "__main__":
    main()
