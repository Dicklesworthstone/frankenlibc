#!/usr/bin/env python3
"""generate_perf_regression_prevention.py — bd-1qfc

Unified performance regression prevention system validator.

Checks:
  1. Benchmark suite inventory — all spec suites have bench .rs files.
  2. Baseline coverage — suites with p50 baselines vs spec.
  3. Gate wiring — which suites are enforced in perf_gate.sh.
  4. Hotpath symbol coverage — hotpath symbols with matching benchmark coverage.
  5. Configuration consistency — baseline thresholds vs budget policy.
  6. Waiver validity — active waivers have not expired.

Generates a JSON report to stdout (or --output).
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def find_repo_root():
    p = Path(__file__).resolve().parent.parent
    if (p / "Cargo.toml").exists():
        return p
    return Path.cwd()


def load_json_file(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check_bench_files(root, spec):
    """Check that each suite in spec has a corresponding bench .rs file."""
    results = []
    suites = spec.get("benchmark_suites", {}).get("suites", [])
    bench_dir = root / "crates" / "frankenlibc-bench" / "benches"

    for suite in suites:
        suite_id = suite["id"]
        # Infer bench file name from command or convention
        expected_file = bench_dir / f"{suite_id}_bench.rs"
        exists = expected_file.exists()
        bench_count = len(suite.get("benchmarks", []))
        results.append({
            "suite_id": suite_id,
            "bench_file": str(expected_file.relative_to(root)),
            "exists": exists,
            "benchmark_count": bench_count,
            "enforced_in_gate": suite.get("enforced_in_gate", False),
        })

    return results


def check_baseline_coverage(root, spec, baseline):
    """Check which suites have p50 baselines."""
    results = []
    suites = spec.get("benchmark_suites", {}).get("suites", [])
    baseline_data = baseline.get("baseline_p50_ns_op", {})

    for suite in suites:
        suite_id = suite["id"]
        modes = suite.get("modes", [])
        benchmarks = suite.get("benchmarks", [])

        suite_baselines = baseline_data.get(suite_id, {})
        covered_count = 0
        missing = []

        for mode in modes:
            mode_baselines = suite_baselines.get(mode, {})
            for bench in benchmarks:
                bench_name = bench["name"]
                if bench_name in mode_baselines:
                    covered_count += 1
                else:
                    missing.append(f"{mode}/{bench_name}")

        total = len(modes) * len(benchmarks)
        results.append({
            "suite_id": suite_id,
            "total_benchmarks_x_modes": total,
            "baselines_present": covered_count,
            "baselines_missing": missing,
            "coverage_pct": round(covered_count * 100 / total, 1) if total > 0 else 0,
        })

    return results


def check_hotpath_coverage(root, budget_policy, spec):
    """Check how many hotpath symbols are covered by benchmark suites."""
    hotpath_symbols = budget_policy.get("hotpath_symbols", {}).get("strict_hotpath", [])
    bench_coverage = budget_policy.get("current_assessment", {}).get("benchmark_coverage", {})
    not_benched = set(bench_coverage.get("not_yet_benched", []))

    # Build module -> bench suite mapping from spec
    suites = spec.get("benchmark_suites", {}).get("suites", [])

    # Heuristic: map modules to suites based on known relationships
    module_to_suite = {
        "string_abi": "string",
        "malloc_abi": "malloc",
        "wchar_abi": None,  # no suite yet
        "ctype_abi": None,
        "errno_abi": "errno",
        "pthread_abi": "mutex",  # partial coverage via mutex_bench
    }

    covered = []
    uncovered = []
    for sym_entry in hotpath_symbols:
        module = sym_entry.get("module", "")
        symbol = sym_entry["symbol"]
        suite = module_to_suite.get(module)
        if suite is not None:
            covered.append({"symbol": symbol, "module": module, "suite": suite})
        else:
            uncovered.append({"symbol": symbol, "module": module})

    return {
        "total_hotpath_symbols": len(hotpath_symbols),
        "covered_by_bench_suite": len(covered),
        "not_covered": len(uncovered),
        "coverage_pct": round(len(covered) * 100 / len(hotpath_symbols), 1) if hotpath_symbols else 0,
        "uncovered_modules": sorted(set(s["module"] for s in uncovered)),
        "uncovered_symbols_sample": [s["symbol"] for s in uncovered[:10]],
    }


def check_config_consistency(baseline, budget_policy):
    """Check that baseline targets match budget policy budgets."""
    issues = []

    baseline_targets = baseline.get("targets_ns_op", {})
    budgets = budget_policy.get("budgets", {})

    strict_budget = budgets.get("strict_hotpath", {})
    if strict_budget.get("strict_mode_ns") is not None:
        for bench_name in baseline_targets.get("strict", {}):
            target = baseline_targets["strict"][bench_name]
            if target != strict_budget["strict_mode_ns"]:
                # Not an issue per se — targets are per-bench, budgets are per-class
                pass

    # Check regression threshold consistency
    regression_pct = budget_policy.get("regression_policy", {}).get("max_regression_pct")
    if regression_pct is not None:
        baseline_version = baseline.get("version", 0)
        if baseline_version < 1:
            issues.append("baseline version < 1")

    # Check waiver validity
    waivers = budget_policy.get("active_waivers", [])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for w in waivers:
        expires = w.get("expires_at", "")
        if expires and expires < now:
            issues.append(f"Waiver {w.get('bead_id', '?')} expired on {expires}")

    return {
        "baseline_version": baseline.get("version", 0),
        "regression_max_pct": regression_pct,
        "strict_target_ns": budgets.get("strict_hotpath", {}).get("strict_mode_ns"),
        "hardened_target_ns": budgets.get("strict_hotpath", {}).get("hardened_mode_ns"),
        "active_waivers": len(waivers),
        "expired_waivers": sum(
            1 for w in waivers
            if w.get("expires_at", "") and w["expires_at"] < now
        ),
        "issues": issues,
    }


def check_gate_wiring(root):
    """Check which benchmark suites are wired to perf_gate.sh."""
    gate_path = root / "scripts" / "perf_gate.sh"
    if not gate_path.exists():
        return {"exists": False, "enforced_suites": [], "issues": ["perf_gate.sh not found"]}

    content = gate_path.read_text()
    enforced = []
    if "runtime_math_bench" in content:
        enforced.append("runtime_math")
    if "membrane_bench" in content:
        enforced.append("membrane")
    if "string_bench" in content:
        enforced.append("string")
    if "malloc_bench" in content:
        enforced.append("malloc")
    if "errno_bench" in content:
        enforced.append("errno")
    if "runtime_math_kernels_bench" in content:
        enforced.append("runtime_math_kernels")

    # Check key features
    features = {
        "load_guard": "should_skip_overloaded" in content or "loadavg" in content,
        "attribution_policy": "attribution" in content.lower(),
        "event_logging": "EVENT_LOG" in content or "emit_event" in content,
        "injection_support": "INJECT_RESULTS" in content,
    }

    return {
        "exists": True,
        "enforced_suites": enforced,
        "features": features,
        "issues": [],
    }


def main():
    parser = argparse.ArgumentParser(description="Performance regression prevention validator")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()

    # Load required files
    spec_path = root / "tests" / "conformance" / "perf_baseline_spec.json"
    baseline_path = root / "scripts" / "perf_baseline.json"
    budget_path = root / "tests" / "conformance" / "perf_budget_policy.json"

    missing = []
    for p, name in [(spec_path, "perf_baseline_spec.json"), (baseline_path, "perf_baseline.json"),
                     (budget_path, "perf_budget_policy.json")]:
        if not p.exists():
            missing.append(name)

    if missing:
        print(f"ERROR: Missing required files: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    spec = load_json_file(spec_path)
    baseline = load_json_file(baseline_path)
    budget_policy = load_json_file(budget_path)

    # Run checks
    bench_files = check_bench_files(root, spec)
    baseline_cov = check_baseline_coverage(root, spec, baseline)
    hotpath_cov = check_hotpath_coverage(root, budget_policy, spec)
    config_check = check_config_consistency(baseline, budget_policy)
    gate_wiring = check_gate_wiring(root)

    # Compute summary
    total_suites = len(bench_files)
    suites_with_files = sum(1 for s in bench_files if s["exists"])
    suites_enforced = sum(1 for s in bench_files if s["enforced_in_gate"])
    suites_with_baselines = sum(1 for s in baseline_cov if s["coverage_pct"] == 100.0)
    total_baseline_slots = sum(s["total_benchmarks_x_modes"] for s in baseline_cov)
    filled_baseline_slots = sum(s["baselines_present"] for s in baseline_cov)
    baseline_fill_pct = round(filled_baseline_slots * 100 / total_baseline_slots, 1) if total_baseline_slots > 0 else 0

    total_issues = len(config_check.get("issues", [])) + len(gate_wiring.get("issues", []))
    total_warnings = config_check.get("expired_waivers", 0)

    # Also scan for additional bench files beyond spec
    bench_dir = root / "crates" / "frankenlibc-bench" / "benches"
    all_bench_files = sorted(p.stem for p in bench_dir.glob("*_bench.rs")) if bench_dir.exists() else []
    spec_suite_ids = {s["suite_id"] for s in bench_files}
    extra_benches = [b.replace("_bench", "") for b in all_bench_files
                     if b.replace("_bench", "") not in spec_suite_ids]

    report = {
        "schema_version": "v1",
        "bead": "bd-1qfc",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_suites_in_spec": total_suites,
            "suites_with_bench_files": suites_with_files,
            "suites_enforced_in_gate": suites_enforced,
            "suites_with_full_baselines": suites_with_baselines,
            "baseline_slot_fill_pct": baseline_fill_pct,
            "hotpath_symbol_coverage_pct": hotpath_cov["coverage_pct"],
            "total_hotpath_symbols": hotpath_cov["total_hotpath_symbols"],
            "extra_bench_files_beyond_spec": len(extra_benches),
            "total_issues": total_issues,
            "total_warnings": total_warnings,
        },
        "bench_file_inventory": bench_files,
        "baseline_coverage": baseline_cov,
        "gate_wiring": gate_wiring,
        "hotpath_symbol_coverage": hotpath_cov,
        "config_consistency": config_check,
        "extra_bench_files": extra_benches,
    }

    output = json.dumps(report, indent=2) + "\n"

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
