#!/usr/bin/env python3
"""Generate the benchmark coverage inventory for bd-bp8fl.8.1.

The report is intentionally derived from current repo artifacts instead of
hand-maintained prose:
  * support_matrix.json for perf-class and hot-path symbol pressure,
  * perf_baseline_spec.json and scripts/perf_baseline.json for baseline slots,
  * crates/frankenlibc-bench for actual benchmark targets,
  * workload/smoke manifests for externally visible evidence.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

BEAD_ID = "bd-bp8fl.8.1"
REQUIRED_MODES = ("strict", "hardened")
HOT_PERF_CLASSES = {
    "strict_hotpath",
    "hardened_hotpath",
    "hotpath",
    "fast",
    "O1",
    "syscall",
    "syscall_veneer",
}

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]

FAMILIES = [
    {
        "id": "string",
        "modules": ["string_abi", "wchar_abi"],
        "bench_files": ["string_bench", "baseline_capture_bench"],
        "baseline_suites": ["string"],
        "smoke_artifacts": [
            "tests/conformance/ld_preload_smoke_summary.v1.json",
            "tests/conformance/workload_matrix.json",
        ],
        "required": True,
    },
    {
        "id": "malloc",
        "modules": ["malloc_abi"],
        "bench_files": ["malloc_bench"],
        "baseline_suites": ["malloc"],
        "smoke_artifacts": [
            "tests/conformance/ld_preload_smoke_summary.v1.json",
            "tests/conformance/workload_matrix.json",
        ],
        "required": True,
    },
    {
        "id": "stdio",
        "modules": ["stdio_abi"],
        "bench_files": ["stdio_bench"],
        "baseline_suites": ["stdio"],
        "smoke_artifacts": [
            "tests/conformance/ld_preload_smoke_summary.v1.json",
            "tests/conformance/workload_matrix.json",
            "tests/conformance/user_workload_acceptance_matrix.v1.json",
        ],
        "required": True,
    },
    {
        "id": "pthread",
        "modules": ["pthread_abi", "c11threads_abi"],
        "bench_files": ["mutex_bench", "condvar_bench", "baseline_capture_bench"],
        "baseline_suites": ["pthread_mutex", "pthread_condvar"],
        "smoke_artifacts": [
            "tests/conformance/workload_matrix.json",
            "tests/conformance/condvar_perf_validation.v1.json",
            "tests/conformance/thread_hotpath_optimization.v1.json",
        ],
        "required": True,
    },
    {
        "id": "syscall",
        "modules": [
            "unistd_abi",
            "io_abi",
            "dirent_abi",
            "resource_abi",
            "socket_abi",
            "poll_abi",
            "time_abi",
        ],
        "bench_files": [],
        "baseline_suites": ["syscall"],
        "smoke_artifacts": [
            "tests/conformance/ld_preload_smoke_summary.v1.json",
            "tests/conformance/e2e_scenario_manifest.v1.json",
            "tests/conformance/workload_matrix.json",
        ],
        "required": True,
    },
    {
        "id": "membrane",
        "modules": [],
        "bench_files": ["membrane_bench"],
        "baseline_suites": ["membrane"],
        "smoke_artifacts": [
            "tests/conformance/perf_budget_policy.json",
            "tests/conformance/hardened_repair_deny_matrix.v1.json",
        ],
        "required": True,
    },
    {
        "id": "runtime_math",
        "modules": [],
        "bench_files": ["runtime_math_bench", "runtime_math_kernels_bench"],
        "baseline_suites": ["runtime_math"],
        "smoke_artifacts": [
            "tests/runtime_math/runtime_math_classification_matrix.v1.json",
            "tests/runtime_math/golden/kernel_snapshot_smoke.v1.json",
        ],
        "required": False,
    },
]


def repo_root() -> Path:
    root = Path(__file__).resolve().parent.parent
    if not (root / "Cargo.toml").exists():
        raise SystemExit(f"Could not locate repo root from {__file__}")
    return root


def load_json(path: Path) -> object:
    try:
        content = path.read_text(encoding="utf-8")
        return json.JSONDecoder().decode(content)
    except OSError as exc:
        raise SystemExit(f"{path}: could not read JSON input: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc


def source_commit(root: Path) -> str:
    git_dir = root / ".git"
    head_path = git_dir / "HEAD"
    try:
        head = head_path.read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    if not head.startswith("ref: "):
        return head[:8] if head else "unknown"

    ref_name = head.removeprefix("ref: ").strip()
    ref_path = git_dir / ref_name
    try:
        ref_value = ref_path.read_text(encoding="utf-8").strip()
        return ref_value[:8] if ref_value else "unknown"
    except OSError:
        pass

    packed_refs = git_dir / "packed-refs"
    try:
        for line in packed_refs.read_text(encoding="utf-8").splitlines():
            if line.startswith("#") or line.startswith("^"):
                continue
            fields = line.split()
            if len(fields) == 2 and fields[1] == ref_name:
                return fields[0][:8]
    except OSError:
        pass
    return "unknown"


def relative(path: Path, root: Path) -> str:
    return str(path.relative_to(root))


def read_bench_targets(root: Path) -> dict[str, dict[str, object]]:
    bench_dir = root / "crates" / "frankenlibc-bench" / "benches"
    targets: dict[str, dict[str, object]] = {}
    for path in sorted(bench_dir.glob("*_bench.rs")):
        stem = path.stem
        text = path.read_text(encoding="utf-8")
        targets[stem] = {
            "bench_file": relative(path, root),
            "exists": True,
            "benchmark_function_count": text.count("fn bench_"),
            "emits_structured_marker": "_BENCH" in text or "BASELINE_CAPTURE_BENCH" in text,
            "mentions_strict_or_hardened": "FRANKENLIBC_MODE" in text or "mode_label" in text,
        }
    return targets


def spec_suites(perf_spec: dict[str, object]) -> dict[str, dict[str, object]]:
    suites = perf_spec.get("benchmark_suites", {}).get("suites", [])
    return {suite["id"]: suite for suite in suites}


def baseline_slots(
    suite_id: str,
    suite: dict[str, object] | None,
    baseline: dict[str, object],
) -> dict[str, object]:
    if suite is None:
        return {
            "suite_id": suite_id,
            "status": "missing_spec_suite",
            "total_slots": 0,
            "present_slots": 0,
            "missing_slots": [f"{mode}/<suite-missing>" for mode in REQUIRED_MODES],
            "coverage_pct": 0.0,
        }

    baseline_data = baseline.get("baseline_p50_ns_op", {}).get(suite_id, {})
    missing: list[str] = []
    present = 0
    total = 0
    for mode in suite.get("modes", []):
        mode_name = str(mode)
        mode_baselines = baseline_data.get(mode_name, {})
        for bench in suite.get("benchmarks", []):
            total += 1
            bench_name = bench["name"]
            if bench_name in mode_baselines:
                present += 1
            else:
                missing.append(f"{mode_name}/{bench_name}")

    coverage_pct = round(present * 100 / total, 1) if total else 0.0
    return {
        "suite_id": suite_id,
        "status": "complete" if total and not missing else "incomplete",
        "total_slots": total,
        "present_slots": present,
        "missing_slots": missing,
        "coverage_pct": coverage_pct,
    }


def support_symbols_by_module(support_matrix: dict[str, object]) -> dict[str, list[dict[str, object]]]:
    by_module: dict[str, list[dict[str, object]]] = {}
    for symbol in support_matrix.get("symbols", []):
        module = str(symbol.get("module", "unknown"))
        by_module.setdefault(module, []).append(symbol)
    return by_module


def perf_class(symbol: dict[str, object]) -> str:
    return str(symbol.get("perf_class", symbol.get("performance_class", "unspecified")))


def workload_artifact(path: Path, root: Path) -> dict[str, object]:
    rel = relative(path, root)
    if not path.exists():
        return {"path": rel, "exists": False, "row_count": 0}

    try:
        data = load_json(path)
    except json.JSONDecodeError as exc:
        return {"path": rel, "exists": True, "row_count": 0, "parse_error": str(exc)}

    row_count = 0
    for key in ("workloads", "scenarios", "rows", "cases", "validation_rows"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, list):
            row_count = len(value)
            break
    if row_count == 0 and isinstance(data, dict):
        summary = data.get("summary", {})
        if isinstance(summary, dict):
            row_count = int(summary.get("total_cases", 0) or summary.get("total_workloads", 0) or 0)

    return {"path": rel, "exists": True, "row_count": row_count}


def family_report(
    family: dict[str, object],
    root: Path,
    bench_targets: dict[str, dict[str, object]],
    suites: dict[str, dict[str, object]],
    baseline: dict[str, object],
    symbols_by_module: dict[str, list[dict[str, object]]],
) -> dict[str, object]:
    modules = list(family["modules"])
    symbols = [symbol for module in modules for symbol in symbols_by_module.get(module, [])]
    hot_symbols = [symbol for symbol in symbols if perf_class(symbol) in HOT_PERF_CLASSES]
    bench_files = [
        {
            "bench": bench,
            "exists": bench in bench_targets,
            "path": bench_targets.get(bench, {}).get("bench_file"),
            "benchmark_function_count": bench_targets.get(bench, {}).get("benchmark_function_count", 0),
            "mode_aware": bench_targets.get(bench, {}).get("mentions_strict_or_hardened", False),
        }
        for bench in family["bench_files"]
    ]
    baseline_coverage = [
        baseline_slots(suite_id, suites.get(suite_id), baseline)
        for suite_id in family["baseline_suites"]
    ]
    artifacts = [
        workload_artifact(root / artifact, root)
        for artifact in family["smoke_artifacts"]
    ]

    has_bench_file = all(item["exists"] for item in bench_files) if bench_files else False
    has_mode_aware_bench = any(item["mode_aware"] for item in bench_files)
    full_baseline = bool(baseline_coverage) and all(
        item["status"] == "complete" for item in baseline_coverage
    )
    missing_baseline_slots = [
        f"{item['suite_id']}:{slot}"
        for item in baseline_coverage
        for slot in item["missing_slots"]
    ]
    missing_spec_suites = [
        item["suite_id"] for item in baseline_coverage if item["status"] == "missing_spec_suite"
    ]
    coverage_state = "complete" if has_bench_file and full_baseline else "gap"

    return {
        "family": family["id"],
        "required_for_bd_bp8fl_8_1": bool(family["required"]),
        "support_modules": modules,
        "support_symbol_count": len(symbols),
        "hot_symbol_count": len(hot_symbols),
        "hot_symbol_sample": [symbol["symbol"] for symbol in hot_symbols[:12]],
        "bench_files": bench_files,
        "has_bench_file": has_bench_file,
        "has_mode_aware_bench": has_mode_aware_bench,
        "baseline_coverage": baseline_coverage,
        "full_strict_hardened_baseline": full_baseline,
        "missing_spec_suites": missing_spec_suites,
        "missing_baseline_slots": missing_baseline_slots,
        "workload_artifacts": artifacts,
        "coverage_state": coverage_state,
        "next_action": next_action(family["id"], has_bench_file, missing_spec_suites, missing_baseline_slots),
    }


def next_action(
    family_id: str,
    has_bench_file: bool,
    missing_spec_suites: list[str],
    missing_baseline_slots: list[str],
) -> str:
    if not has_bench_file:
        return f"Add a Criterion benchmark target for {family_id} before collecting baselines."
    if missing_spec_suites:
        return f"Add perf_baseline_spec suites for {', '.join(missing_spec_suites)} and collect strict/hardened baselines."
    if missing_baseline_slots:
        return f"Collect p50 baselines for {len(missing_baseline_slots)} strict/hardened {family_id} slots."
    return "Keep current bench and baseline slots wired into regression gates."


def event_for_family(
    family: dict[str, object],
    commit: str,
    target_dir: str,
    elapsed_ns: int,
) -> dict[str, object]:
    missing = family["missing_baseline_slots"] or [
        f"{suite}:<missing spec suite>" for suite in family["missing_spec_suites"]
    ]
    sample = family.get("hot_symbol_sample", [])
    return {
        "trace_id": f"{BEAD_ID}:{family['family']}",
        "bead_id": BEAD_ID,
        "scenario_id": f"benchmark_coverage_inventory:{family['family']}",
        "runtime_mode": "strict+hardened",
        "replacement_level": "L0-interpose/L1-replace-planning",
        "api_family": family["family"],
        "symbol": ",".join(sample[:3]) if sample else "*",
        "oracle_kind": "derived_inventory_gate",
        "expected": {
            "bench_file": True,
            "strict_hardened_baselines": True,
            "structured_workload_artifacts": True,
        },
        "actual": {
            "coverage_state": family["coverage_state"],
            "has_bench_file": family["has_bench_file"],
            "full_strict_hardened_baseline": family["full_strict_hardened_baseline"],
            "missing_baseline_count": len(missing),
        },
        "errno": None,
        "decision_path": [
            "support_matrix",
            "bench_target_inventory",
            "perf_baseline_spec",
            "perf_baseline",
            "workload_artifacts",
        ],
        "healing_action": "none",
        "latency_ns": elapsed_ns,
        "artifact_refs": [
            "support_matrix.json",
            "tests/conformance/perf_baseline_spec.json",
            "scripts/perf_baseline.json",
            "crates/frankenlibc-bench/benches",
        ],
        "source_commit": commit,
        "target_dir": target_dir,
        "failure_signature": None if not missing else f"missing_benchmark_baselines:{family['family']}",
    }


def build_report(root: Path, target_dir: str) -> tuple[dict[str, object], list[dict[str, object]]]:
    start = time.perf_counter_ns()
    support_matrix = load_json(root / "support_matrix.json")
    perf_spec = load_json(root / "tests/conformance/perf_baseline_spec.json")
    baseline = load_json(root / "scripts/perf_baseline.json")

    bench_targets = read_bench_targets(root)
    suites = spec_suites(perf_spec)
    symbols_by_module = support_symbols_by_module(support_matrix)

    families = [
        family_report(family, root, bench_targets, suites, baseline, symbols_by_module)
        for family in FAMILIES
    ]
    elapsed_ns = time.perf_counter_ns() - start
    commit = source_commit(root)

    actual_bench_targets = sorted(bench_targets)
    mapped_benches = sorted(
        {bench for family in FAMILIES for bench in family["bench_files"]}
    )
    unmapped = [bench for bench in actual_bench_targets if bench not in mapped_benches]
    required_families = [family for family in families if family["required_for_bd_bp8fl_8_1"]]
    missing_required = [
        family["family"]
        for family in required_families
        if not family["full_strict_hardened_baseline"]
    ]
    families_without_benches = [
        family["family"] for family in required_families if not family["has_bench_file"]
    ]
    hot_symbol_total = sum(family["hot_symbol_count"] for family in families)

    report = {
        "schema_version": "v1",
        "bead": BEAD_ID,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_commit": commit,
        "purpose": "Inventory current benchmark coverage for ported hot paths and membrane gates before optimization work advances.",
        "inputs": {
            "support_matrix": "support_matrix.json",
            "perf_baseline_spec": "tests/conformance/perf_baseline_spec.json",
            "perf_baseline": "scripts/perf_baseline.json",
            "bench_dir": "crates/frankenlibc-bench/benches",
            "smoke_workload_artifacts": [
                "tests/conformance/ld_preload_smoke_summary.v1.json",
                "tests/conformance/workload_matrix.json",
                "tests/conformance/e2e_scenario_manifest.v1.json",
                "tests/conformance/user_workload_acceptance_matrix.v1.json",
            ],
        },
        "required_log_fields": REQUIRED_LOG_FIELDS,
        "summary": {
            "family_count": len(families),
            "required_family_count": len(required_families),
            "actual_bench_target_count": len(actual_bench_targets),
            "mapped_bench_target_count": len(mapped_benches),
            "unmapped_bench_target_count": len(unmapped),
            "hot_symbol_count_in_scope": hot_symbol_total,
            "fully_baselined_families": [
                family["family"] for family in families if family["full_strict_hardened_baseline"]
            ],
            "missing_required_baseline_families": missing_required,
            "required_families_without_bench_files": families_without_benches,
            "strict_hardened_modes_required": list(REQUIRED_MODES),
        },
        "families": families,
        "bench_targets": [
            {"bench": name, **bench_targets[name]} for name in actual_bench_targets
        ],
        "unmapped_bench_targets": unmapped,
        "closure_evidence": {
            "generator": "scripts/generate_benchmark_coverage_inventory.py",
            "gate": "scripts/check_benchmark_coverage_inventory.sh",
            "committed_artifact": "tests/conformance/benchmark_coverage_inventory.v1.json",
            "target_report": "target/conformance/benchmark_coverage_inventory.report.json",
            "target_log": "target/conformance/benchmark_coverage_inventory.log.jsonl",
        },
    }
    events = [
        event_for_family(family, commit, target_dir, elapsed_ns)
        for family in families
    ]
    return report, events


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", help="report output path")
    parser.add_argument("--log", help="JSONL event log output path")
    parser.add_argument(
        "--target-dir",
        default="target/conformance",
        help="target dir label stored in structured log rows",
    )
    args = parser.parse_args()

    root = repo_root()
    report, events = build_report(root, args.target_dir)

    if args.output:
        write_json(root / args.output if not Path(args.output).is_absolute() else Path(args.output), report)
    else:
        print(json.dumps(report, indent=2, sort_keys=False))

    if args.log:
        write_jsonl(root / args.log if not Path(args.log).is_absolute() else Path(args.log), events)


if __name__ == "__main__":
    main()
