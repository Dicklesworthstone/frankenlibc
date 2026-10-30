#!/usr/bin/env python3
"""Compare native errno, cancellation and C/C++ cleanup with live GNU pthreads."""
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
    "cleanup-exit", "cleanup-cancel", "cleanup-reentry", "cleanup-siblings",
    "cleanup-defer", "cleanup-cancel-reentry", "cleanup-initial", "cleanup-return-reentry",
)
CLEANUP_CASES = tuple(case for case in CASES if case.startswith("cleanup-"))
CPP_CASES = (
    "native-exit", "native-cancel", "native-exit-catch-all", "native-cancel-catch-all",
    "native-mixed-exit", "native-mixed-cancel", "native-mixed-cancel-siblings",
    "native-cancel-read", "native-cancel-write", "native-cancel-nanosleep",
    "native-cancel-sem", "native-cancel-sem-timed", "native-mixed-cancel-read",
    "native-cancel-read-disabled", "native-cancel-write-disabled",
    "native-cancel-nanosleep-disabled", "native-cancel-sem-disabled",
    "native-cancel-sem-timed-disabled", "native-cancel-read-internal",
    "native-cancel-join", "native-cancel-join-alias", "native-cancel-join-timed",
    "native-cancel-join-timed-null", "native-cancel-join-clock-real",
    "native-cancel-join-clock-mono", "native-cancel-join-clock-null", "native-mixed-cancel-join",
    "native-cancel-join-disabled", "native-cancel-join-alias-disabled",
    "native-cancel-join-timed-disabled", "native-cancel-join-timed-null-disabled",
    "native-cancel-join-clock-real-disabled", "native-cancel-join-clock-mono-disabled",
    "native-cancel-join-clock-null-disabled", "native-cancel-tryjoin",
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
    cpp_source = root / "tests/integration/fixture_cancel_forced_unwind.cpp"
    binary = output / "fixture_pthread_native_state"
    exceptions_binary = output / "fixture_pthread_native_state_exceptions"
    cpp_binary = output / "fixture_pthread_native_unwind"
    c_frame_object = output / "native_cleanup_c_frame.o"
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("LD_PRELOAD", "LD_AUDIT") and not key.startswith("FRANKENLIBC_")}
    c_flags = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c11", "-O2", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
    ]

    def compile_fixture(name, command):
        compiled = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=60)
        log = output / f"compile-{name}.log"
        log.write_text(compiled.stdout + compiled.stderr)
        if compiled.returncode:
            raise SystemExit(f"fixture compilation failed: {log}")

    compile_fixture("c", c_flags + ["-fno-exceptions", str(source), "-o", str(binary),
                                   "-pthread", "-ldl"])
    compile_fixture("exceptions", c_flags + ["-fexceptions", str(source), "-o",
                                            str(exceptions_binary), "-pthread", "-ldl"])
    compile_fixture("c-frame", c_flags + ["-fno-exceptions", "-c", str(source),
                                         "-Dmain=frankenlibc_native_state_unused_main",
                                         "-o", str(c_frame_object)])
    compile_fixture("cpp", shlex.split(os.environ.get("CXX", "c++")) + [
        "-std=c++17", "-O2", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
        str(cpp_source), str(c_frame_object), "-o", str(cpp_binary), "-pthread", "-ldl",
    ])
    provider = subprocess.run([str(binary), "--provider"], env=environment,
                              capture_output=True, text=True, timeout=15)
    if provider.returncode or provider.stderr:
        raise SystemExit(f"GNU provider discovery failed: {provider.stderr}")
    host = str(Path(provider.stdout.strip()).resolve(strict=True))
    records = []
    failures = []

    def execute(label, case, expected, extra, executable=binary, oracle_for=None):
        try:
            run = subprocess.run([str(executable), case, expected],
                                 env=dict(environment, **extra), capture_output=True,
                                 text=True, timeout=15)
            code, stdout, stderr = run.returncode, run.stdout, run.stderr
        except subprocess.TimeoutExpired as error:
            code = 124
            stdout = (error.stdout or b"").decode(errors="replace")
            stderr = (error.stderr or b"").decode(errors="replace") + "\nfixture timeout\n"
        record = {"lane": label, "case": case, "returncode": code,
                  "stdout": stdout, "stderr": stderr}
        if oracle_for is not None:
            record["oracle_for"] = oracle_for
        records.append(record)
        log_case = oracle_for if oracle_for is not None else case
        (output / f"{label}-{log_case}.log").write_text(stdout + stderr)
        return record

    negative = execute("provider-negative", CASES[0], str(library), {})
    if not (negative["returncode"] == 86 and negative["stdout"] == "" and
            negative["stderr"] == "pthread-native-state:provider-mismatch:__errno_location\n"):
        failures.append("provider-negative")

    cpp_negative = execute("cpp-provider-negative", CPP_CASES[0], str(library), {}, cpp_binary)
    if not (cpp_negative["returncode"] == 86 and cpp_negative["stdout"] == "" and
            cpp_negative["stderr"] == "pthread-native-unwind:provider-mismatch:pthread_create\n"):
        failures.append("cpp-provider-negative")

    variants = (("", CASES, binary, "pthread-native-state"),
                ("exceptions-", CLEANUP_CASES, exceptions_binary, "pthread-native-state"),
                ("cpp-", CPP_CASES, cpp_binary, "pthread-native-unwind"))
    for prefix, cases, executable, output_prefix in variants:
        for case in cases:
            # __pthread_join is a candidate alias, absent from the GNU export
            # surface. Compare its behavior to the public GNU contract while
            # requiring the candidate alias's actual provider in the fixture.
            oracle_case = case.replace("-join-alias", "-join") if prefix == "cpp-" else case
            reference = execute(f"{prefix}gnu", oracle_case, host, {}, executable,
                                oracle_for=case if oracle_case != case else None)
            expected = f"{output_prefix}:{case}:PASS\n"
            oracle_expected = f"{output_prefix}:{oracle_case}:PASS\n"
            if reference["returncode"] or reference["stdout"] != oracle_expected or reference["stderr"]:
                failures.append(f"{prefix}gnu:{case}")
            for mode in ("strict", "hardened"):
                for native in ("0", "1"):
                    label = f"{prefix}{'native' if native == '1' else 'hosted'}-{mode}"
                    candidate = execute(label, case, str(library), {
                        "LD_PRELOAD": str(library), "FRANKENLIBC_MODE": mode,
                        "FRANKENLIBC_THREAD_NATIVE": native, "FRANKENLIBC_RUNTIME_MATH": "off",
                    }, executable)
                    passed = (candidate["returncode"] == 0 and candidate["stdout"] == expected
                              and candidate["stderr"] == "")
                    print(f"{label} {case}: {'PASS' if passed else 'FAIL'}", flush=True)
                    if not passed:
                        failures.append(f"{label}:{case}")

    gnu_cases = sum(len(cases) for _, cases, _, _ in variants)
    report = {"library": str(library), "library_sha256": sha256(library),
              "fixture_sha256": sha256(source), "binary_sha256": sha256(binary),
              "cpp_fixture_sha256": sha256(cpp_source), "cpp_binary_sha256": sha256(cpp_binary),
              "exceptions_binary_sha256": sha256(exceptions_binary),
              "gnu_provider": host, "gnu_cases": gnu_cases,
              "candidate_cases": 4 * gnu_cases, "provider_negative_cases": 2,
              "failures": failures, "runs": records}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        raise SystemExit("pthread native state: FAIL " + ", ".join(failures))
    print(f"pthread native state: PASS ({gnu_cases} live GNU cases, "
          f"{4 * gnu_cases} candidate cases, two provider negatives)")


if __name__ == "__main__":
    main()
