#!/usr/bin/env python3
"""Execute real exported memory/string operations in fresh preload processes.

Usage: python3 scripts/check_membrane_access.py LIBRARY [--output DIRECTORY]
Add --benchmark for the deployed overhead group (also used by the bench crate
and ld_preload_smoke.sh). It returns 1 on unmet performance targets, 2 on setup
or behavior/provider failure, and never calls a partial measurement a pass.
No missing compiler, missing library, timeout, wrong provider, or failed case is
counted as a pass. The gate never uses a reference libc for invalid accesses.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import statistics
import subprocess
import sys
import time

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


def deployed_benchmark(args, library, source, executable, output, env) -> int:
    """Measure the deployed ABI, not representative Rust or an rlib.

    A failed budget is a real gate failure. Raw warmups, order, checksums and
    timings remain available even when no performance claim can be made.
    """
    if args.samples < 3 or not 1 <= args.iterations <= 100_000_000:
        raise ValueError("benchmark needs >=3 samples and 1..100000000 iterations")
    if sys.platform != "linux":
        raise ValueError("deployed benchmark requires Linux/GNU libc")
    allowed = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {allowed[0]})
    sort = shutil.which("sort")
    if not sort:
        raise ValueError("sort executable is required")
    env = dict(env, LC_ALL="C")
    env.pop("LD_DEBUG", None)
    env.pop("LD_AUDIT", None)
    arms = [("glibc", None, "strict"), ("strict", library, "strict"),
            ("hardened", library, "hardened")]
    if args.incumbent:
        incumbent = args.incumbent.resolve(strict=True)
        if not incumbent.is_file():
            raise ValueError("incumbent must be a regular file")
        arms.extend((("incumbent-strict", incumbent, "strict"),
                     ("incumbent-hardened", incumbent, "hardened")))
    # An unpreloaded process must reject the requested artifact, not merely
    # return an arbitrary nonzero status or time out.
    control = subprocess.run(
        [str(executable), str(library), "benchmark", "memcmp-heap", "7", "100"],
        env=env, capture_output=True, text=True, timeout=20,
    )
    provider_rejected = control.returncode == 2 and "provider rejection" in control.stderr
    if not provider_rejected:
        raise ValueError(f"wrong-provider control failed: {control}")
    invalid_controls = []
    for operation, length, iterations in (("invalid", "7", "100"),
                                           ("strlen-stack", "64", "100"),
                                           ("memcmp-heap", "7", "0")):
        result = subprocess.run([str(executable), "host", "benchmark", operation, length, iterations],
                                env=env, capture_output=True, text=True, timeout=20)
        invalid_controls.append(dict(operation=operation, length=length, iterations=iterations,
                                     returncode=result.returncode, stderr=result.stderr))
        if result.returncode != 2:
            raise ValueError(f"invalid benchmark arguments accepted: {result}")
    rng = random.Random(20261022)
    corpus = output / "sort100k.txt"
    corpus.write_text("".join(f"{rng.uniform(-1e6, 1e6):.17g}\n" for _ in range(100_000)))
    operations = ("strlen-stack", "strlen-heap", "memcmp-stack", "memcmp-heap")
    lengths = (0, 1, 7, 15, 31, 63)
    samples = {}
    raw_count = 0
    providers = {}
    versions = {}
    bindings = []
    load_before = Path("/proc/loadavg").read_text().strip()

    def host_sample():
        clock = Path(f"/sys/devices/system/cpu/cpu{allowed[0]}/cpufreq/scaling_cur_freq")
        return dict(loadavg=list(os.getloadavg()),
                    cpu_khz=clock.read_text().strip() if clock.is_file() else None)

    def arm_env(path, mode):
        child_env = dict(env, FRANKENLIBC_MODE=mode, FRANKENLIBC_RUNTIME_MATH="on")
        if path is not None:
            child_env["LD_PRELOAD"] = str(path)
        return child_env

    with (output / "benchmark.raw.jsonl").open("w") as raw:
        for round_index in range(-2, args.samples):
            warmup = round_index < 0
            offset = round_index % len(arms)
            order = arms[offset:] + arms[:offset]
            for operation in operations:
                for length in lengths:
                    for arm, path, mode in order:
                        host = host_sample()
                        result = subprocess.run(
                            [str(executable), str(path) if path else "host", "benchmark",
                             operation, str(length), str(args.iterations)],
                            env=arm_env(path, mode), capture_output=True, text=True, timeout=30,
                        )
                        if result.returncode or result.stderr:
                            raise ValueError(f"benchmark child failed ({arm}/{operation}/{length}): {result}")
                        row = json.loads(result.stdout)
                        expected_checksum = length * args.iterations if operation.startswith("strlen") else (
                            args.iterations // 2 if length else 0)
                        if (row.get("operation") != operation or row.get("length") != length or
                            row.get("iterations") != args.iterations or
                            row.get("checksum") != expected_checksum or
                            not isinstance(row.get("elapsed_ns"), int) or row["elapsed_ns"] <= 0):
                            raise ValueError(f"invalid measured result: {row}")
                        provider = Path(row["provider"]).resolve(strict=True)
                        if path is not None and not provider.samefile(path):
                            raise ValueError(f"measured provider differs from requested artifact: {row}")
                        if arm in providers and providers[arm] != str(provider):
                            raise ValueError("provider changed within invocation")
                        providers[arm] = str(provider)
                        versions[arm] = row["glibc_version"]
                        row.update(arm=arm, round=round_index, warmup=warmup,
                                   ns_per_call=row["elapsed_ns"] / args.iterations, host=host)
                        raw.write(json.dumps(row) + "\n")
                        raw.flush()
                        raw_count += 1
                        if not warmup:
                            samples.setdefault((operation, length, arm), []).append(row["ns_per_call"])
            for kind, flags in (("lexical", []), ("numeric", ["-g"])):
                reference = subprocess.run([sort, *flags, str(corpus)], env=env,
                                           capture_output=True, timeout=30)
                if reference.returncode or reference.stderr:
                    raise ValueError(f"host sort failed: {reference}")
                reference_hash = hashlib.sha256(reference.stdout).hexdigest()
                if round_index == -2:
                    (output / f"sort100k-{kind}.expected").write_bytes(reference.stdout)
                for arm, path, mode in order:
                    child_env = arm_env(path, mode)
                    if round_index == -2:
                        child_env["LD_DEBUG"] = "bindings"
                    host = host_sample()
                    start = time.perf_counter_ns()
                    result = subprocess.run([sort, *flags, str(corpus)], env=child_env,
                                            capture_output=True, timeout=30)
                    elapsed = time.perf_counter_ns() - start
                    if result.returncode or result.stdout != reference.stdout:
                        (output / f"sort100k-{kind}-{arm}-failure.stdout").write_bytes(result.stdout)
                        (output / f"sort100k-{kind}-{arm}-failure.stderr").write_bytes(result.stderr)
                        raise ValueError(f"sort parity failed: {kind}/{arm}, returncode={result.returncode}")
                    if round_index == -2:
                        (output / f"sort100k-{kind}-{arm}.bindings").write_bytes(result.stderr)
                        found = {}
                        for line in result.stderr.decode(errors="replace").splitlines():
                            match = re.search(r"binding file (.*?) \[.*?\] to (.*?) \[.*?\]: normal symbol `([^']+)'", line)
                            if match and Path(match[1]).name == Path(sort).name and match[3] in (
                                "malloc", "free", "memcmp", "strlen", "memcpy",
                            ):
                                provider = Path(match[2]).resolve(strict=True)
                                if not provider.samefile(providers[arm]):
                                    raise ValueError(f"sort provider mismatch: {line}")
                                found[match[3]] = str(provider)
                        if not {"malloc", "free"} <= found.keys():
                            raise ValueError(f"sort allocation bindings not observed: {kind}/{arm}")
                        bindings.append(dict(kind=kind, arm=arm, symbols=found))
                    elif result.stderr:
                        raise ValueError(f"unexpected sort stderr: {result.stderr!r}")
                    row = dict(operation=f"sort100k-{kind}", arm=arm, round=round_index,
                               warmup=warmup, elapsed_ns=elapsed, output_sha256=reference_hash, host=host)
                    raw.write(json.dumps(row) + "\n")
                    raw.flush()
                    raw_count += 1
                    if not warmup:
                        samples.setdefault((row["operation"], 100_000, arm), []).append(elapsed)
            print(f"deployed overhead: round {round_index + 1}/{args.samples}", flush=True)
    summaries = []
    failures = []
    for (operation, length, arm), values in sorted(samples.items()):
        if len(values) != args.samples:
            raise ValueError("missing measured samples")
        summary = dict(operation=operation, length=length, arm=arm, samples=len(values),
                       median=statistics.median(values), maximum=max(values), minimum=min(values))
        summaries.append(summary)
        if arm == "hardened" and not operation.startswith("sort100k") and max(values) > 200:
            failures.append(dict(operation=operation, length=length,
                                 target="max_batch_mean_ns<=200", observed=max(values)))
    macro_ratios = []
    for kind in ("lexical", "numeric"):
        operation = f"sort100k-{kind}"
        medians = {arm: statistics.median(samples[(operation, 100_000, arm)]) for arm, _, _ in arms}
        ratios = dict(kind=kind, hardened_over_glibc=medians["hardened"] / medians["glibc"],
                      hardened_over_strict=medians["hardened"] / medians["strict"])
        macro_ratios.append(ratios)
        for target, maximum in (("hardened_over_glibc", 3), ("hardened_over_strict", 2)):
            if ratios[target] > maximum:
                failures.append(dict(operation=operation, target=f"{target}<={maximum}", observed=ratios[target]))
    report = dict(schema="frankenlibc.deployed_overhead.v1", passed=not failures,
                  scope="warmed deployed short-call batch means and 100k sort; not universal latency or safety",
                  library=str(library), library_sha256=sha256(library),
                  fixture_sha256=sha256(source), runner_sha256=sha256(Path(__file__)),
                  executable_sha256=sha256(executable), sort=str(Path(sort).resolve()),
                  sort_sha256=sha256(Path(sort)), corpus_sha256=sha256(corpus), corpus_rows=100_000,
                  seed=20261022, samples=args.samples, warmups=2, iterations=args.iterations,
                  lengths=lengths, operations=operations, runtime_math="on", cpu=allowed[0],
                  allowed_cpus_before=allowed, platform=list(os.uname()),
                  cpuinfo=Path("/proc/cpuinfo").read_text(),
                  compiler=subprocess.check_output(["cc", "--version"], env=env, text=True).splitlines()[0],
                  load_before=load_before, load_after=Path("/proc/loadavg").read_text().strip(),
                  raw_records=raw_count, providers=providers, glibc_versions=versions, bindings=bindings,
                  arm_libraries={arm: dict(path=str(path), sha256=sha256(path))
                                 for arm, path, _ in arms if path is not None},
                  provider_control=dict(passed=provider_rejected, returncode=control.returncode,
                                        stdout=control.stdout, stderr=control.stderr),
                  invalid_controls=invalid_controls, summaries=summaries, macro_ratios=macro_ratios,
                  failures=failures)
    (output / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(deployed_overhead_passed=not failures, raw_records=raw_count,
                         macro_ratios=macro_ratios, failures=failures)), flush=True)
    return 0 if not failures else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    parser.add_argument("--output", type=Path, default=Path("target/membrane-access"))
    parser.add_argument("--benchmark", action="store_true", help="enforce deployed short-call and sort100k budgets")
    parser.add_argument("--samples", type=int, default=9)
    parser.add_argument("--iterations", type=int, default=200_000)
    parser.add_argument("--incumbent", type=Path, help="optional same-invocation comparison artifact")
    args = parser.parse_args()
    library = args.library.resolve(strict=True)
    if not library.is_file():
        raise ValueError("library must be a regular file")
    root = Path(__file__).resolve().parent.parent
    source = root / "tests/integration/fixture_membrane_access.c"
    output = args.output.resolve()
    if args.benchmark and output.exists() and any(output.iterdir()):
        raise ValueError("benchmark output directory must be empty; preserve earlier evidence")
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
    if args.benchmark:
        return deployed_benchmark(args, library, source, executable, output, env)
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
