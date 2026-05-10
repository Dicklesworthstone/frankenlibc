#!/usr/bin/env python3
"""Run Gentoo package test suites baseline vs FrankenLibC instrumented."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize(atom: str) -> str:
    return atom.replace("/", "__")


@dataclass
class ModeResult:
    total_tests: int
    passed: int
    failed: int
    skipped: int
    duration_seconds: float
    failed_tests: List[str]
    log_file: str
    frankenlibc_log: str = ""
    healing_actions: int = 0
    healing_breakdown: Dict[str, int] | None = None


def compare_mode_results(baseline: ModeResult, instrumented: ModeResult) -> Dict[str, object]:
    base_failed = set(baseline.failed_tests)
    inst_failed = set(instrumented.failed_tests)
    new_failures = sorted(inst_failed - base_failed)
    new_passes = sorted(base_failed - inst_failed)

    overhead = 0.0
    if baseline.duration_seconds > 0:
        overhead = ((instrumented.duration_seconds - baseline.duration_seconds) / baseline.duration_seconds) * 100.0

    verdict = "PASS"
    if new_failures:
        verdict = "REGRESSION"
    elif new_passes:
        verdict = "IMPROVEMENT"
    elif base_failed == inst_failed:
        verdict = "NEUTRAL"

    return {
        "new_failures": new_failures,
        "new_passes": new_passes,
        "overhead_percent": round(overhead, 2),
        "verdict": verdict,
    }


def parse_test_log(log_path: Path, exit_code: int, duration_seconds: float) -> ModeResult:
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines() if log_path.exists() else []
    failed_tests = [line.strip() for line in lines if line.strip().startswith("FAIL:")]
    passed_tests = [line.strip() for line in lines if line.strip().startswith("PASS:")]
    skipped_tests = [line.strip() for line in lines if line.strip().startswith("SKIP:")]

    if not passed_tests and not failed_tests and not skipped_tests:
        # Fallback for non-standard logs.
        if exit_code == 0:
            passed_tests = ["PASS: implicit"]
        else:
            failed_tests = ["FAIL: implicit"]

    total = len(passed_tests) + len(failed_tests) + len(skipped_tests)
    return ModeResult(
        total_tests=total,
        passed=len(passed_tests),
        failed=len(failed_tests),
        skipped=len(skipped_tests),
        duration_seconds=round(duration_seconds, 2),
        failed_tests=failed_tests,
        log_file=str(log_path),
    )


def run_mode(
    image: str,
    package: str,
    mode: str,
    out_dir: Path,
    timeout_seconds: int,
    franken_mode: str,
    dry_run: bool,
) -> ModeResult:
    log_file = out_dir / f"{mode}.log"
    franken_log = out_dir / "frankenlibc.jsonl"

    if dry_run:
        if mode == "baseline":
            return ModeResult(
                total_tests=10,
                passed=10,
                failed=0,
                skipped=0,
                duration_seconds=30.0,
                failed_tests=[],
                log_file=str(log_file),
            )
        return ModeResult(
            total_tests=10,
            passed=10,
            failed=0,
            skipped=0,
            duration_seconds=33.0,
            failed_tests=[],
            log_file=str(log_file),
            frankenlibc_log=str(franken_log),
            healing_actions=0,
            healing_breakdown={},
        )

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{out_dir.resolve()}:/results",
        image,
        "bash",
        "-lc",
    ]

    if mode == "baseline":
        env_prefix = "FRANKENLIBC_PORTAGE_ENABLE=0"
    else:
        env_prefix = f"FRANKENLIBC_PORTAGE_ENABLE=1 FRANKENLIBC_MODE={shlex.quote(franken_mode)} FRANKENLIBC_LOG_FILE=/results/frankenlibc.jsonl"

    emerge_cmd = f"{env_prefix} timeout --signal=TERM --kill-after=30 {int(timeout_seconds)} emerge --test {shlex.quote(package)} > /results/{mode}.log 2>&1"
    started = time.time()
    proc = subprocess.run(cmd + [emerge_cmd], capture_output=True, text=True)
    duration = time.time() - started

    parsed = parse_test_log(log_file, proc.returncode, duration)
    if mode == "instrumented":
        parsed.frankenlibc_log = str(franken_log)
        parsed.healing_breakdown = {}
        if franken_log.exists():
            try:
                actions: Dict[str, int] = {}
                for line in franken_log.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    payload = json.loads(line)
                    action = payload.get("action")
                    if not action:
                        continue
                    key = str(action)
                    actions[key] = actions.get(key, 0) + 1
                parsed.healing_breakdown = actions
                parsed.healing_actions = sum(actions.values())
            except Exception:
                parsed.healing_breakdown = {}
                parsed.healing_actions = 0

    return parsed


def run_package(
    image: str,
    package: str,
    output_root: Path,
    timeout_seconds: int,
    franken_mode: str,
    dry_run: bool,
) -> Dict[str, object]:
    package_dir = output_root / sanitize(package)
    package_dir.mkdir(parents=True, exist_ok=True)

    baseline = run_mode(image, package, "baseline", package_dir, timeout_seconds, franken_mode, dry_run)
    instrumented = run_mode(image, package, "instrumented", package_dir, timeout_seconds, franken_mode, dry_run)
    comparison = compare_mode_results(baseline, instrumented)
    telemetry = {
        "schema_version": "gentoo_test_execution_telemetry.v1",
        "package": package,
        "frankenlibc_mode": franken_mode,
        "baseline_log": baseline.log_file,
        "instrumented_log": instrumented.log_file,
        "frankenlibc_log": instrumented.frankenlibc_log,
        "healing_actions": instrumented.healing_actions,
        "healing_breakdown": instrumented.healing_breakdown or {},
        "new_failures": comparison["new_failures"],
        "new_passes": comparison["new_passes"],
        "overhead_percent": comparison["overhead_percent"],
        "verdict": comparison["verdict"],
    }

    result = {
        "package": package,
        "version": "",
        "baseline": asdict(baseline),
        "instrumented": asdict(instrumented),
        "comparison": comparison,
        "telemetry": telemetry,
        "timestamp": utc_now(),
    }
    (package_dir / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Gentoo package test baseline vs FrankenLibC instrumented.")
    parser.add_argument("--image", default="frankenlibc/gentoo-frankenlibc:latest")
    parser.add_argument("--package", action="append", default=[])
    parser.add_argument("--package-file", default="data/gentoo/build-order.txt")
    parser.add_argument("--output", default="artifacts/gentoo-tests")
    parser.add_argument("--baseline-dir", default="data/gentoo/test-baselines")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--frankenlibc-mode", default="hardened")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--write-baseline", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_root = Path(args.output).resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    if args.package:
        packages = args.package
    else:
        package_lines = Path(args.package_file).read_text(encoding="utf-8").splitlines()
        packages = [line.strip() for line in package_lines if line.strip() and not line.strip().startswith("#")]

    all_results = []
    for package in packages:
        result = run_package(
            image=args.image,
            package=package,
            output_root=output_root,
            timeout_seconds=args.timeout_seconds,
            franken_mode=args.frankenlibc_mode,
            dry_run=args.dry_run,
        )
        all_results.append(result)

        if args.write_baseline:
            baseline_dir = Path(args.baseline_dir).resolve()
            baseline_dir.mkdir(parents=True, exist_ok=True)
            baseline_path = baseline_dir / f"{sanitize(package)}.json"
            baseline_path.write_text(json.dumps(result["baseline"], indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = {
        "timestamp": utc_now(),
        "package_count": len(all_results),
        "regressions": sum(1 for item in all_results if item["comparison"]["verdict"] == "REGRESSION"),
        "improvements": sum(1 for item in all_results if item["comparison"]["verdict"] == "IMPROVEMENT"),
        "neutral_or_pass": sum(1 for item in all_results if item["comparison"]["verdict"] in {"PASS", "NEUTRAL"}),
        "telemetry": {
            "schema_version": "gentoo_test_execution_summary_telemetry.v1",
            "packages": [
                {
                    "package": item["package"],
                    "frankenlibc_mode": item["telemetry"]["frankenlibc_mode"],
                    "verdict": item["telemetry"]["verdict"],
                    "baseline_total_tests": item["baseline"]["total_tests"],
                    "instrumented_total_tests": item["instrumented"]["total_tests"],
                    "new_failures": item["telemetry"]["new_failures"],
                    "healing_actions": item["telemetry"]["healing_actions"],
                    "frankenlibc_log": item["telemetry"]["frankenlibc_log"],
                }
                for item in all_results
            ],
        },
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
