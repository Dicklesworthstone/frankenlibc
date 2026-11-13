#!/usr/bin/env python3
"""Check real-host heap initialization before constructor-created threads."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", default=os.environ.get(
        "FRANKENLIBC_TEST_LIBRARY", str(root / "target/release/libfrankenlibc_abi.so")))
    parser.add_argument("--out-dir", default=str(root / "target/host-allocator-startup"))
    parser.add_argument("--unprimed-library", help="Optional prior DSO for cold-heap negative controls")
    args = parser.parse_args()
    library = Path(args.library).resolve(strict=True)
    output = Path(args.out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    environment = {
        key: value for key, value in os.environ.items()
        if key not in ("LD_PRELOAD", "LD_AUDIT", "GLIBC_TUNABLES")
        and not key.startswith(("FRANKENLIBC_", "MALLOC_"))
    }
    compiler = shlex.split(os.environ.get("CC", "cc"))
    flags = ["-std=c11", "-O2", "-fno-builtin"]
    fixtures = {
        "cold": root / "tests/integration/fixture_host_allocator_startup.c",
        "recursive": root / "tests/integration/fixture_app_malloc_spawns_thread.c",
    }
    binaries = {}
    for name, source in fixtures.items():
        binary = output / f"fixture-{name}"
        # Keep the existing recursive-allocator fixture's smoke-build flags;
        # enforce the full warning gate on the new cold-start fixture.
        warnings = ["-Wall", "-Wextra", "-Werror"] if name == "cold" else []
        result = subprocess.run(compiler + flags + warnings + [str(source), "-o", str(binary),
                                "-pthread", "-ldl"], env=environment,
                                capture_output=True, text=True, timeout=60)
        (output / f"compile-{name}.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            raise SystemExit(f"fixture compilation failed: {output / f'compile-{name}.log'}")
        binaries[name] = binary

    discovery = subprocess.run([str(binaries["cold"]), "--provider"], env=environment,
                               capture_output=True, text=True, timeout=15)
    (output / "gnu-provider.log").write_text(discovery.stdout + discovery.stderr)
    if discovery.returncode or discovery.stderr:
        raise SystemExit(f"GNU provider discovery failed: {output / 'gnu-provider.log'}")
    host = Path(discovery.stdout.strip()).resolve(strict=True)
    records = []

    def run(name, fixture, arguments, env, expected_stdout, expected_stderr="", expected_code=0):
        try:
            result = subprocess.run([str(binaries[fixture]), *map(str, arguments)], env=env,
                                    capture_output=True, text=True, timeout=15)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            code = "timeout"
            stdout = error.stdout or ""
            stderr = error.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
        (output / f"{name}.stdout").write_text(stdout)
        (output / f"{name}.stderr").write_text(stderr)
        passed = code == expected_code and stdout == expected_stdout and stderr == expected_stderr
        records.append({"case": name, "fixture": fixture, "returncode": code, "passed": passed})
        return stdout

    workers_output = "host-allocator-startup:workers-and-application-allocator:PASS\n"
    recursive_output = "".join(f"worker {index} joined\n" for index in range(4))
    recursive_output += "helper started=1 ran=1\n"
    # A fully interposed GNU application need not use glibc's heap. Its oracle
    # covers ordinary worker/custom-allocator behavior; only FrankenLibC needs
    # the additional prime witness before its hidden host allocation paths.
    run("gnu-workers", "cold", [host, "reference"], environment, workers_output)
    run("gnu-recursive-allocator", "recursive", [], environment, recursive_output)

    def candidate_environment(path, mode, delegate, native="0"):
        return environment | {
            "LD_PRELOAD": str(path), "FRANKENLIBC_MODE": mode,
            "FRANKENLIBC_THREAD_NATIVE": native, "FRANKENLIBC_RUNTIME_MATH": "off",
            "FRANKENLIBC_STARTUP_DELEGATE": delegate,
        }

    for mode in ("strict", "hardened"):
        for delegate, phase in (("0", "startup"), ("1", "constructor")):
            env = candidate_environment(library, mode, delegate)
            run(f"{mode}-{phase}-prime", "cold", [library, phase], env,
                workers_output + f"host-allocator-startup:{phase}-prime:PASS\n")
            run(f"{mode}-{phase}-recursive-allocator", "recursive", [], env, recursive_output)

    # Provider admission must fail without the DSO; requesting a native worker
    # must also fail the hosted hardware-thread-pointer witness.
    run("provider-negative", "cold", [library, "reference"], environment, "",
        "host-allocator-startup:provider-mismatch\n", 86)
    run("backend-negative", "cold", [library, "startup"],
        candidate_environment(library, "strict", "0", native="1"), "",
        "host-allocator-startup:host-backend-mismatch\n", 89)

    unprimed = None
    if args.unprimed_library:
        unprimed = Path(args.unprimed_library).resolve(strict=True)
        for mode in ("strict", "hardened"):
            for delegate, phase in (("0", "startup"), ("1", "constructor")):
                run(f"unprimed-negative-{mode}-{phase}", "cold", [unprimed, phase],
                    candidate_environment(unprimed, mode, delegate), "",
                    "host-allocator-startup:host-heap-remained-cold\n", 88)

    failures = [record["case"] for record in records if not record["passed"]]
    report = {
        "schema_version": 1,
        "library": str(library),
        "library_sha256": hashlib.file_digest(library.open("rb"), "sha256").hexdigest(),
        "gnu_provider": str(host),
        "unprimed_library": str(unprimed) if unprimed else None,
        "gnu_cases": 2,
        "candidate_cases": 8,
        "negative_controls": 6 if unprimed else 2,
        "passed": not failures,
        "records": records,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        print("host allocator startup: FAIL: " + ", ".join(failures), file=sys.stderr)
        print(f"artifacts={output}", file=sys.stderr)
        return 1
    print(f"host allocator startup: PASS (2 GNU cases, 8 candidate cases, "
          f"{report['negative_controls']} negative controls)")
    print(f"artifacts={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
