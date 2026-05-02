#!/usr/bin/env python3
"""Generate the benchmark coverage inventory for bd-bp8fl.8.1.

The report is intentionally derived from current repo artifacts instead of
hand-maintained prose:
  * support_matrix.json for perf-class and hot-path symbol pressure,
  * tests/conformance/perf_baseline_spec.json and scripts/perf_baseline.json for baseline slots,
  * crates/frankenlibc-bench for actual benchmark targets,
  * workload/smoke manifests for externally visible evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BEAD_ID = "bd-bp8fl.8.1"
SCHEMA_VERSION = "v1"
REQUIRED_MODES = ("strict", "hardened")
TARGET_STATUSES = {"Implemented", "RawSyscall"}
HOT_PERF_CLASSES = {
    "strict_hotpath",
    "hardened_hotpath",
    "hotpath",
    "fast",
    "O1",
    "syscall",
    "syscall_veneer",
}

OWNER_BEAD_BY_FAMILY = {
    "string": "bd-bp8fl.8.3",
    "malloc": "bd-bp8fl.8.3",
    "stdio": "bd-bp8fl.8.3",
    "pthread": "bd-bp8fl.8.3",
    "syscall": "bd-bp8fl.8.3",
    "membrane": "bd-bp8fl.8.2",
    "runtime_math": "bd-bp8fl.8.2",
}

REQUIRED_INVENTORY_ROW_FIELDS = [
    "row_id",
    "api_family",
    "symbol",
    "crate/module",
    "current_benchmark",
    "missing_benchmark_reason",
    "runtime_mode",
    "replacement_level",
    "user_workload_exposure",
    "baseline_artifact",
    "owner_bead",
    "benchmark_id",
    "coverage_state",
    "artifact_refs",
    "failure_signature",
]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "benchmark_id",
    "coverage_state",
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


class BenchmarkInventoryError(ValueError):
    """Raised when benchmark inventory inputs cannot produce trustworthy rows."""


def repo_root() -> Path:
    root = Path(__file__).resolve().parent.parent
    if not (root / "Cargo.toml").exists():
        raise SystemExit(f"Could not locate repo root from {__file__}")
    return root


def load_json(path: Path) -> Any:
    try:
        content = path.read_text(encoding="utf-8")
        return json.JSONDecoder().decode(content)
    except OSError as exc:
        raise BenchmarkInventoryError(f"{path}: could not read JSON input: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BenchmarkInventoryError(f"{path}: invalid JSON: {exc}") from exc


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise BenchmarkInventoryError(f"{path}: could not hash input: {exc}") from exc


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


def is_target_symbol(symbol: dict[str, object]) -> bool:
    return str(symbol.get("status", "")) in TARGET_STATUSES


def is_hot_symbol(symbol: dict[str, object]) -> bool:
    return perf_class(symbol) in HOT_PERF_CLASSES


def support_symbol_rows(
    family: dict[str, object],
    symbols_by_module: dict[str, list[dict[str, object]]],
) -> list[dict[str, object]]:
    modules = list(family["modules"])
    rows = [
        symbol
        for module in modules
        for symbol in symbols_by_module.get(module, [])
        if is_target_symbol(symbol) and is_hot_symbol(symbol)
    ]
    return sorted(rows, key=lambda row: (str(row.get("module", "")), str(row.get("symbol", ""))))


def validate_source_inputs(
    support_matrix: dict[str, object],
    perf_spec: dict[str, object],
    baseline: dict[str, object],
    bench_targets: dict[str, dict[str, object]],
) -> None:
    errors: list[str] = []
    seen_symbols: dict[str, str] = {}
    for row in support_matrix.get("symbols", []):
        symbol = row.get("symbol")
        module = str(row.get("module", "<unknown>"))
        if not isinstance(symbol, str) or not symbol:
            errors.append(f"support_matrix symbol row missing symbol in {module}")
            continue
        if symbol in seen_symbols:
            errors.append(f"duplicate symbol row: support_matrix:{symbol}")
        seen_symbols[symbol] = module

    suite_ids: set[str] = set()
    for suite in perf_spec.get("benchmark_suites", {}).get("suites", []):
        suite_id = suite.get("id")
        if not isinstance(suite_id, str) or not suite_id:
            errors.append("perf_baseline_spec suite missing id")
            continue
        if suite_id in suite_ids:
            errors.append(f"duplicate benchmark suite: {suite_id}")
        suite_ids.add(suite_id)

    baseline_suites = baseline.get("baseline_p50_ns_op", {})
    if not isinstance(baseline_suites, dict):
        errors.append("perf_baseline baseline_p50_ns_op must be an object")
    else:
        for suite_id, by_mode in baseline_suites.items():
            if not isinstance(by_mode, dict):
                errors.append(f"perf_baseline suite {suite_id} must map modes to benchmarks")

    required_bench_files = {
        bench for family in FAMILIES for bench in family["bench_files"]
    }
    for bench in sorted(required_bench_files):
        if bench not in bench_targets:
            errors.append(f"missing benchmark target file: {bench}")

    missing_owner_families = sorted(
        family["id"] for family in FAMILIES if family["id"] not in OWNER_BEAD_BY_FAMILY
    )
    if missing_owner_families:
        errors.append("missing owner bead mapping: " + ",".join(missing_owner_families))

    if errors:
        raise BenchmarkInventoryError("; ".join(errors))


def workload_artifact(path: Path, root: Path) -> dict[str, object]:
    rel = relative(path, root)
    if not path.exists():
        return {"path": rel, "exists": False, "row_count": 0}

    try:
        data = load_json(path)
    except BenchmarkInventoryError as exc:
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
    symbols = [
        symbol
        for module in modules
        for symbol in symbols_by_module.get(module, [])
        if is_target_symbol(symbol)
    ]
    hot_symbols = support_symbol_rows(family, symbols_by_module)
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


def module_exposure(
    family_id: str,
    module: str,
    symbol: str,
    workload_matrix: dict[str, object],
    user_workloads: dict[str, object],
) -> dict[str, object]:
    workloads: list[dict[str, object]] = []
    for row in workload_matrix.get("workloads", []):
        if not isinstance(row, dict):
            continue
        required_modules = set(row.get("required_modules", []))
        critical_symbols = set(row.get("critical_symbols", []))
        if module in required_modules or symbol in critical_symbols:
            workloads.append(
                {
                    "id": row.get("id"),
                    "binary": row.get("binary"),
                    "priority_impact": row.get("priority_impact", "unspecified"),
                    "critical_symbol": symbol in critical_symbols,
                }
            )

    user_rows: list[dict[str, object]] = []
    for row in user_workloads.get("workloads", []):
        if not isinstance(row, dict):
            continue
        subsystems = {str(item) for item in row.get("subsystems", [])}
        coverage_domains = {str(item) for item in row.get("coverage_domains", [])}
        if family_id in subsystems or family_id in coverage_domains:
            user_rows.append(
                {
                    "id": row.get("id"),
                    "primary_domain": row.get("primary_domain"),
                    "runtime_modes": row.get("runtime_modes", []),
                    "replacement_levels": row.get("replacement_levels", []),
                }
            )

    critical_count = sum(1 for row in workloads if row["critical_symbol"])
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unspecified": 4}
    top_priorities = sorted(
        {str(row.get("priority_impact", "unspecified")) for row in workloads},
        key=lambda item: priority_order.get(item, 99),
    )
    return {
        "workload_count": len(workloads),
        "critical_symbol_workload_count": critical_count,
        "user_workload_count": len(user_rows),
        "top_priority_impacts": top_priorities[:3],
        "workload_ids": [row["id"] for row in workloads[:8]],
        "user_workload_ids": [row["id"] for row in user_rows[:8]],
        "artifact_refs": [
            "tests/conformance/workload_matrix.json",
            "tests/conformance/user_workload_acceptance_matrix.v1.json",
        ],
    }


def suite_benchmark_names(suite: dict[str, object] | None) -> list[str]:
    if suite is None:
        return []
    return [
        str(bench.get("name"))
        for bench in suite.get("benchmarks", [])
        if isinstance(bench, dict) and bench.get("name")
    ]


def benchmark_matches_symbol(family_id: str, symbol: str, benchmark_name: str) -> bool:
    if benchmark_name == symbol or benchmark_name.startswith(f"{symbol}_"):
        return True
    aliases = {
        "string": {
            "bcopy": ("memcpy",),
            "bzero": ("memset", "memcpy"),
            "memmove": ("memcpy",),
            "rawmemchr": ("memchr",),
            "rindex": ("strrchr",),
            "index": ("strchr",),
        },
        "malloc": {
            "malloc": ("alloc_free_cycle", "alloc_burst"),
            "calloc": ("alloc_free_cycle", "alloc_burst"),
            "free": ("alloc_free_cycle",),
            "realloc": ("alloc_burst",),
        },
        "pthread": {
            "pthread_mutex_lock": ("mutex", "pthread_mutex"),
            "pthread_mutex_unlock": ("mutex", "pthread_mutex"),
            "pthread_cond_wait": ("condvar", "pthread_condvar"),
            "pthread_cond_signal": ("condvar", "pthread_condvar"),
        },
    }
    for prefix in aliases.get(family_id, {}).get(symbol, ()):
        if benchmark_name == prefix or benchmark_name.startswith(f"{prefix}_"):
            return True
    return False


def select_symbol_benchmark(
    family_id: str,
    symbol: str,
    suite_ids: list[str],
    suites: dict[str, dict[str, object]],
) -> tuple[str | None, str | None]:
    for suite_id in suite_ids:
        suite = suites.get(suite_id)
        for benchmark_name in suite_benchmark_names(suite):
            if benchmark_matches_symbol(family_id, symbol, benchmark_name):
                return suite_id, benchmark_name
    return None, None


def baseline_value(
    baseline: dict[str, object],
    suite_id: str | None,
    mode: str,
    benchmark_name: str | None,
) -> float | int | None:
    if suite_id is None or benchmark_name is None:
        return None
    by_suite = baseline.get("baseline_p50_ns_op", {})
    if not isinstance(by_suite, dict):
        return None
    by_mode = by_suite.get(suite_id, {})
    if not isinstance(by_mode, dict):
        return None
    slots = by_mode.get(mode, {})
    if not isinstance(slots, dict):
        return None
    value = slots.get(benchmark_name)
    return value if isinstance(value, (int, float)) else None


def missing_reason(
    family: dict[str, object],
    family_row: dict[str, object],
    suite_id: str | None,
    benchmark_name: str | None,
    baseline_present: bool,
) -> str:
    if not family_row["has_bench_file"]:
        return "missing_benchmark_target"
    if family_row["missing_spec_suites"]:
        return "missing_perf_baseline_spec_suite"
    if suite_id is None or benchmark_name is None:
        return "missing_symbol_specific_benchmark"
    if not baseline_present:
        return "missing_p50_baseline"
    if not family_row["has_mode_aware_bench"]:
        return "benchmark_not_strict_hardened_mode_aware"
    return "none"


def replacement_level(symbol: dict[str, object] | None, family_id: str) -> str:
    if family_id in {"membrane", "runtime_math"}:
        return "internal-control-plane"
    status = str((symbol or {}).get("status", "unknown"))
    if status == "RawSyscall":
        return "L1-native-raw-syscall"
    if status == "Implemented":
        return "L1-native-rust"
    return "L0-interpose"


def artifact_refs_for_row(family: dict[str, object], family_row: dict[str, object]) -> list[str]:
    refs = {
        "support_matrix.json",
        "tests/conformance/perf_baseline_spec.json",
        "scripts/perf_baseline.json",
        "crates/frankenlibc-bench/benches",
    }
    for item in family_row.get("workload_artifacts", []):
        if item.get("exists"):
            refs.add(str(item["path"]))
    for artifact in family.get("smoke_artifacts", []):
        refs.add(str(artifact))
    return sorted(refs)


def inventory_row(
    family: dict[str, object],
    family_row: dict[str, object],
    symbol: dict[str, object],
    mode: str,
    suites: dict[str, dict[str, object]],
    baseline: dict[str, object],
    workload_matrix: dict[str, object],
    user_workloads: dict[str, object],
) -> dict[str, object]:
    family_id = str(family["id"])
    symbol_name = str(symbol.get("symbol"))
    module = str(symbol.get("module", "unknown"))
    suite_id, benchmark_name = select_symbol_benchmark(
        family_id, symbol_name, list(family["baseline_suites"]), suites
    )
    baseline_p50 = baseline_value(baseline, suite_id, mode, benchmark_name)
    baseline_present = baseline_p50 is not None
    reason = missing_reason(family, family_row, suite_id, benchmark_name, baseline_present)
    coverage_state = "covered" if reason == "none" else "gap"
    owner = OWNER_BEAD_BY_FAMILY.get(family_id, "")
    if coverage_state == "covered":
        owner = BEAD_ID

    bench_file = next(
        (item for item in family_row["bench_files"] if item.get("exists")),
        None,
    )
    benchmark_id = (
        f"{suite_id}/{benchmark_name}"
        if suite_id and benchmark_name
        else f"{family_id}/<missing-symbol-specific-benchmark>"
    )
    if reason == "missing_perf_baseline_spec_suite":
        benchmark_id = f"{family_id}/<missing-spec-suite>"
    elif reason == "missing_benchmark_target":
        benchmark_id = f"{family_id}/<missing-benchmark-target>"

    return {
        "row_id": f"{family_id}:{mode}:{symbol_name}",
        "api_family": family_id,
        "symbol": symbol_name,
        "crate/module": module,
        "current_benchmark": {
            "benchmark_id": benchmark_id,
            "bench_file": bench_file.get("path") if bench_file else None,
            "bench_exists": bool(bench_file),
            "mode_aware": bool(bench_file and bench_file.get("mode_aware")),
            "spec_suite": suite_id,
            "spec_benchmark": benchmark_name,
        },
        "missing_benchmark_reason": reason,
        "runtime_mode": mode,
        "replacement_level": replacement_level(symbol, family_id),
        "user_workload_exposure": module_exposure(
            family_id, module, symbol_name, workload_matrix, user_workloads
        ),
        "baseline_artifact": {
            "path": "scripts/perf_baseline.json",
            "suite_id": suite_id,
            "benchmark_name": benchmark_name,
            "runtime_mode": mode,
            "present": baseline_present,
            "p50_ns_op": baseline_p50,
        },
        "owner_bead": owner,
        "benchmark_id": benchmark_id,
        "coverage_state": coverage_state,
        "artifact_refs": artifact_refs_for_row(family, family_row),
        "failure_signature": None if coverage_state == "covered" else f"{reason}:{family_id}:{symbol_name}:{mode}",
    }


def pseudo_inventory_rows(
    family: dict[str, object],
    family_row: dict[str, object],
    suites: dict[str, dict[str, object]],
    baseline: dict[str, object],
    workload_matrix: dict[str, object],
    user_workloads: dict[str, object],
) -> list[dict[str, object]]:
    family_id = str(family["id"])
    rows: list[dict[str, object]] = []
    for suite_id in family["baseline_suites"]:
        suite = suites.get(str(suite_id))
        benchmark_names = suite_benchmark_names(suite)
        if not benchmark_names:
            benchmark_names = ["<missing-spec-suite>"]
        for benchmark_name in benchmark_names:
            for mode in REQUIRED_MODES:
                baseline_p50 = baseline_value(baseline, str(suite_id), mode, benchmark_name)
                baseline_present = baseline_p50 is not None
                reason = "none" if baseline_present else "missing_p50_baseline"
                if suite is None:
                    reason = "missing_perf_baseline_spec_suite"
                if not family_row["has_bench_file"]:
                    reason = "missing_benchmark_target"
                coverage_state = "covered" if reason == "none" else "gap"
                owner = BEAD_ID if coverage_state == "covered" else OWNER_BEAD_BY_FAMILY.get(family_id, "")
                bench_file = next(
                    (item for item in family_row["bench_files"] if item.get("exists")),
                    None,
                )
                benchmark_id = (
                    f"{suite_id}/{benchmark_name}"
                    if benchmark_name != "<missing-spec-suite>"
                    else f"{family_id}/<missing-spec-suite>"
                )
                symbol_name = f"{family_id}::{benchmark_name}"
                rows.append(
                    {
                        "row_id": f"{family_id}:{mode}:{benchmark_name}",
                        "api_family": family_id,
                        "symbol": symbol_name,
                        "crate/module": "frankenlibc-membrane",
                        "current_benchmark": {
                            "benchmark_id": benchmark_id,
                            "bench_file": bench_file.get("path") if bench_file else None,
                            "bench_exists": bool(bench_file),
                            "mode_aware": bool(bench_file and bench_file.get("mode_aware")),
                            "spec_suite": suite_id if suite is not None else None,
                            "spec_benchmark": benchmark_name if suite is not None else None,
                        },
                        "missing_benchmark_reason": reason,
                        "runtime_mode": mode,
                        "replacement_level": replacement_level(None, family_id),
                        "user_workload_exposure": module_exposure(
                            family_id, "frankenlibc-membrane", symbol_name, workload_matrix, user_workloads
                        ),
                        "baseline_artifact": {
                            "path": "scripts/perf_baseline.json",
                            "suite_id": suite_id if suite is not None else None,
                            "benchmark_name": benchmark_name if suite is not None else None,
                            "runtime_mode": mode,
                            "present": baseline_present,
                            "p50_ns_op": baseline_p50,
                        },
                        "owner_bead": owner,
                        "benchmark_id": benchmark_id,
                        "coverage_state": coverage_state,
                        "artifact_refs": artifact_refs_for_row(family, family_row),
                        "failure_signature": None if coverage_state == "covered" else f"{reason}:{family_id}:{benchmark_name}:{mode}",
                    }
                )
    return rows


def inventory_rows(
    families: list[dict[str, object]],
    suites: dict[str, dict[str, object]],
    baseline: dict[str, object],
    symbols_by_module: dict[str, list[dict[str, object]]],
    workload_matrix: dict[str, object],
    user_workloads: dict[str, object],
) -> list[dict[str, object]]:
    family_by_id = {str(row["family"]): row for row in families}
    rows: list[dict[str, object]] = []
    for family in FAMILIES:
        family_id = str(family["id"])
        family_row = family_by_id[family_id]
        symbols = support_symbol_rows(family, symbols_by_module)
        if symbols:
            for symbol in symbols:
                for mode in REQUIRED_MODES:
                    rows.append(
                        inventory_row(
                            family,
                            family_row,
                            symbol,
                            mode,
                            suites,
                            baseline,
                            workload_matrix,
                            user_workloads,
                        )
                    )
        else:
            rows.extend(
                pseudo_inventory_rows(
                    family,
                    family_row,
                    suites,
                    baseline,
                    workload_matrix,
                    user_workloads,
                )
            )
    rows.sort(key=lambda row: row["row_id"])
    validate_inventory_rows(rows)
    return rows


def validate_inventory_rows(rows: list[dict[str, object]]) -> None:
    errors: list[str] = []
    seen: set[str] = set()
    for row in rows:
        missing_fields = [field for field in REQUIRED_INVENTORY_ROW_FIELDS if field not in row]
        if missing_fields:
            errors.append(f"{row.get('row_id', '<unknown>')}: missing fields {missing_fields}")
        row_id = str(row.get("row_id", ""))
        if row_id in seen:
            errors.append(f"duplicate inventory row: {row_id}")
        seen.add(row_id)
        owner = row.get("owner_bead")
        if not isinstance(owner, str) or not owner.startswith("bd-"):
            errors.append(f"{row_id}: missing owner bead")
        benchmark = row.get("current_benchmark", {})
        if not isinstance(benchmark, dict) or "benchmark_id" not in benchmark:
            errors.append(f"{row_id}: current_benchmark missing benchmark_id")
    if errors:
        raise BenchmarkInventoryError("; ".join(errors))


def event_for_family(
    family: dict[str, object],
    rows: list[dict[str, object]],
    commit: str,
    target_dir: str,
    elapsed_ns: int,
) -> dict[str, object]:
    missing = family["missing_baseline_slots"] or [
        f"{suite}:<missing spec suite>" for suite in family["missing_spec_suites"]
    ]
    sample = family.get("hot_symbol_sample", [])
    representative = next((row for row in rows if row["coverage_state"] == "gap"), rows[0] if rows else {})
    return {
        "trace_id": f"{BEAD_ID}:{family['family']}",
        "bead_id": BEAD_ID,
        "scenario_id": f"benchmark_coverage_inventory:{family['family']}",
        "runtime_mode": "strict+hardened",
        "replacement_level": "L0-interpose/L1-replace-planning",
        "api_family": family["family"],
        "symbol": representative.get("symbol") or (",".join(sample[:3]) if sample else "*"),
        "benchmark_id": representative.get("benchmark_id", "*"),
        "coverage_state": family["coverage_state"],
        "oracle_kind": "derived_inventory_gate",
        "expected": {
            "bench_file": True,
            "strict_hardened_baselines": True,
            "structured_workload_artifacts": True,
            "owned_symbol_mode_rows": True,
        },
        "actual": {
            "coverage_state": family["coverage_state"],
            "has_bench_file": family["has_bench_file"],
            "full_strict_hardened_baseline": family["full_strict_hardened_baseline"],
            "missing_baseline_count": len(missing),
            "inventory_rows": len(rows),
            "gap_inventory_rows": sum(1 for row in rows if row["coverage_state"] != "covered"),
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


def input_digests(root: Path) -> dict[str, str]:
    paths = {
        "support_matrix": root / "support_matrix.json",
        "perf_baseline_spec": root / "tests/conformance/perf_baseline_spec.json",
        "perf_baseline": root / "scripts/perf_baseline.json",
        "workload_matrix": root / "tests/conformance/workload_matrix.json",
        "user_workload_acceptance_matrix": root / "tests/conformance/user_workload_acceptance_matrix.v1.json",
    }
    digests = {name: sha256_file(path) for name, path in sorted(paths.items())}
    bench_dir = root / "crates" / "frankenlibc-bench" / "benches"
    bench_parts: list[str] = []
    for path in sorted(bench_dir.glob("*_bench.rs")):
        bench_parts.append(f"{relative(path, root)}:{sha256_file(path)}")
    digests["bench_targets"] = sha256_bytes("\n".join(bench_parts).encode("utf-8"))
    return digests


def normalized_report(report: dict[str, object]) -> dict[str, object]:
    normalized = deepcopy(report)
    normalized.pop("generated_at_utc", None)
    normalized.pop("source_commit", None)
    return normalized


def attach_artifact_hash(report: dict[str, object]) -> None:
    stable = normalized_report(report)
    stable.pop("artifact_hash", None)
    report["artifact_hash"] = sha256_bytes(stable_json(stable).encode("utf-8"))


def reports_match(generated: dict[str, object], current: dict[str, object]) -> bool:
    return normalized_report(generated) == normalized_report(current)


def build_report(root: Path, target_dir: str) -> tuple[dict[str, object], list[dict[str, object]]]:
    start = time.perf_counter_ns()
    support_matrix = load_json(root / "support_matrix.json")
    perf_spec = load_json(root / "tests/conformance/perf_baseline_spec.json")
    baseline = load_json(root / "scripts/perf_baseline.json")
    workload_matrix = load_json(root / "tests/conformance/workload_matrix.json")
    user_workloads = load_json(root / "tests/conformance/user_workload_acceptance_matrix.v1.json")

    bench_targets = read_bench_targets(root)
    suites = spec_suites(perf_spec)
    symbols_by_module = support_symbols_by_module(support_matrix)
    validate_source_inputs(support_matrix, perf_spec, baseline, bench_targets)

    families = [
        family_report(family, root, bench_targets, suites, baseline, symbols_by_module)
        for family in FAMILIES
    ]
    rows = inventory_rows(
        families,
        suites,
        baseline,
        symbols_by_module,
        workload_matrix,
        user_workloads,
    )
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
    covered_rows = [row for row in rows if row["coverage_state"] == "covered"]
    gap_rows = [row for row in rows if row["coverage_state"] != "covered"]
    missing_owner_rows = [
        row["row_id"]
        for row in rows
        if not isinstance(row.get("owner_bead"), str) or not str(row.get("owner_bead")).startswith("bd-")
    ]
    prioritized_hot_paths = [
        {
            "api_family": row["api_family"],
            "symbol": row["symbol"],
            "runtime_mode": row["runtime_mode"],
            "benchmark_id": row["benchmark_id"],
            "missing_benchmark_reason": row["missing_benchmark_reason"],
            "owner_bead": row["owner_bead"],
            "workload_count": row["user_workload_exposure"]["workload_count"],
            "user_workload_count": row["user_workload_exposure"]["user_workload_count"],
        }
        for row in sorted(
            gap_rows,
            key=lambda item: (
                -int(item["user_workload_exposure"]["critical_symbol_workload_count"]),
                -int(item["user_workload_exposure"]["workload_count"]),
                str(item["api_family"]),
                str(item["symbol"]),
                str(item["runtime_mode"]),
            ),
        )[:25]
    ]

    report = {
        "schema_version": SCHEMA_VERSION,
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
        "input_digests": input_digests(root),
        "required_log_fields": REQUIRED_LOG_FIELDS,
        "required_inventory_row_fields": REQUIRED_INVENTORY_ROW_FIELDS,
        "summary": {
            "family_count": len(families),
            "required_family_count": len(required_families),
            "actual_bench_target_count": len(actual_bench_targets),
            "mapped_bench_target_count": len(mapped_benches),
            "unmapped_bench_target_count": len(unmapped),
            "hot_symbol_count_in_scope": hot_symbol_total,
            "inventory_row_count": len(rows),
            "covered_inventory_row_count": len(covered_rows),
            "missing_inventory_row_count": len(gap_rows),
            "missing_owner_row_count": len(missing_owner_rows),
            "inventory_row_coverage_pct": round(len(covered_rows) * 100 / len(rows), 2) if rows else 0.0,
            "fully_baselined_families": [
                family["family"] for family in families if family["full_strict_hardened_baseline"]
            ],
            "missing_required_baseline_families": missing_required,
            "required_families_without_bench_files": families_without_benches,
            "strict_hardened_modes_required": list(REQUIRED_MODES),
        },
        "families": families,
        "inventory_rows": rows,
        "prioritized_hot_paths": prioritized_hot_paths,
        "follow_up_beads": [
            {
                "bead": "bd-bp8fl.8.2",
                "scope": "capture strict/hardened membrane and runtime control-plane overhead baselines",
                "owned_families": ["membrane", "runtime_math"],
            },
            {
                "bead": "bd-bp8fl.8.3",
                "scope": "profile and baseline top ported libc hot paths against host glibc",
                "owned_families": ["string", "malloc", "stdio", "pthread", "syscall"],
            },
        ],
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
    attach_artifact_hash(report)
    rows_by_family: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        rows_by_family.setdefault(str(row["api_family"]), []).append(row)
    events = [
        event_for_family(family, rows_by_family.get(str(family["family"]), []), commit, target_dir, elapsed_ns)
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


def synthetic_family(id_: str, modules: list[str], bench_files: list[str], baseline_suites: list[str]) -> dict[str, object]:
    return {
        "id": id_,
        "modules": modules,
        "bench_files": bench_files,
        "baseline_suites": baseline_suites,
        "smoke_artifacts": ["synthetic/workload.json"],
        "required": True,
    }


def self_test() -> None:
    support_matrix = {
        "symbols": [
            {
                "symbol": "memcpy",
                "status": "Implemented",
                "module": "string_abi",
                "perf_class": "strict_hotpath",
            },
            {
                "symbol": "pthread_mutex_lock",
                "status": "Implemented",
                "module": "pthread_abi",
                "perf_class": "strict_hotpath",
            },
        ]
    }
    perf_spec = {
        "benchmark_suites": {
            "suites": [
                {
                    "id": "string",
                    "benchmarks": [{"name": "memcpy_16"}],
                    "modes": ["strict", "hardened"],
                }
            ]
        }
    }
    baseline = {
        "baseline_p50_ns_op": {
            "string": {
                "strict": {"memcpy_16": 1.0},
                "hardened": {},
            }
        }
    }
    bench_targets = {
        "string_bench": {
            "bench_file": "crates/frankenlibc-bench/benches/string_bench.rs",
            "exists": True,
            "benchmark_function_count": 1,
            "emits_structured_marker": True,
            "mentions_strict_or_hardened": True,
        },
        "mutex_bench": {
            "bench_file": "crates/frankenlibc-bench/benches/mutex_bench.rs",
            "exists": True,
            "benchmark_function_count": 1,
            "emits_structured_marker": True,
            "mentions_strict_or_hardened": True,
        },
    }
    symbols_by_module = support_symbols_by_module(support_matrix)
    suites = spec_suites(perf_spec)
    families = [
        synthetic_family("string", ["string_abi"], ["string_bench"], ["string"]),
        synthetic_family("pthread", ["pthread_abi"], ["mutex_bench"], ["pthread_mutex"]),
    ]
    saved_families = deepcopy(FAMILIES)
    saved_owners = deepcopy(OWNER_BEAD_BY_FAMILY)
    try:
        FAMILIES[:] = families
        OWNER_BEAD_BY_FAMILY.clear()
        OWNER_BEAD_BY_FAMILY.update({"string": "bd-test.1", "pthread": "bd-test.2"})
        validate_source_inputs(support_matrix, perf_spec, baseline, bench_targets)
        family_rows = [
            family_report(family, Path("."), bench_targets, suites, baseline, symbols_by_module)
            for family in FAMILIES
        ]
        rows = inventory_rows(
            family_rows,
            suites,
            baseline,
            symbols_by_module,
            {
                "workloads": [
                    {
                        "id": "wl-test",
                        "binary": "coreutils",
                        "required_modules": ["string_abi"],
                        "critical_symbols": ["memcpy"],
                        "priority_impact": "critical",
                    }
                ]
            },
            {
                "workloads": [
                    {
                        "id": "uwm-test",
                        "subsystems": ["string"],
                        "coverage_domains": ["performance_sensitive"],
                        "runtime_modes": ["strict", "hardened"],
                        "replacement_levels": ["L0", "L1"],
                    }
                ]
            },
        )
        grouped = {(row["api_family"], row["symbol"], row["runtime_mode"]): row for row in rows}
        assert ("string", "memcpy", "strict") in grouped, "parser/grouping lost strict memcpy row"
        assert grouped[("string", "memcpy", "strict")]["coverage_state"] == "covered"
        assert grouped[("string", "memcpy", "hardened")]["missing_benchmark_reason"] == "missing_p50_baseline"
        assert grouped[("pthread", "pthread_mutex_lock", "strict")]["missing_benchmark_reason"] == "missing_perf_baseline_spec_suite"

        duplicate = deepcopy(support_matrix)
        duplicate["symbols"].append(deepcopy(duplicate["symbols"][0]))
        try:
            validate_source_inputs(duplicate, perf_spec, baseline, bench_targets)
        except BenchmarkInventoryError as exc:
            assert "duplicate symbol row" in str(exc)
        else:
            raise AssertionError("duplicate symbol handling did not reject duplicate support row")

        OWNER_BEAD_BY_FAMILY.pop("pthread")
        try:
            validate_source_inputs(support_matrix, perf_spec, baseline, bench_targets)
        except BenchmarkInventoryError as exc:
            assert "missing owner bead mapping" in str(exc)
        else:
            raise AssertionError("missing-owner detection did not reject missing family owner")

        generated = {
            "schema_version": SCHEMA_VERSION,
            "bead": BEAD_ID,
            "input_digests": {"support_matrix": "new"},
            "inventory_rows": rows,
        }
        attach_artifact_hash(generated)
        stale = deepcopy(generated)
        stale["input_digests"]["support_matrix"] = "old"
        attach_artifact_hash(stale)
        assert not reports_match(generated, stale), "stale benchmark artifact was not rejected"
    finally:
        FAMILIES[:] = saved_families
        OWNER_BEAD_BY_FAMILY.clear()
        OWNER_BEAD_BY_FAMILY.update(saved_owners)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", help="report output path")
    parser.add_argument("--log", help="JSONL event log output path")
    parser.add_argument(
        "--target-dir",
        default="target/conformance",
        help="target dir label stored in structured log rows",
    )
    parser.add_argument("--check", action="store_true", help="Compare generated report to --output")
    parser.add_argument("--self-test", action="store_true", help="Run generator unit self-tests")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    root = repo_root()
    try:
        report, events = build_report(root, args.target_dir)
    except BenchmarkInventoryError as exc:
        raise SystemExit(f"benchmark coverage inventory input error: {exc}") from exc

    output_path = root / args.output if args.output and not Path(args.output).is_absolute() else Path(args.output) if args.output else None
    if args.check:
        if output_path is None:
            raise SystemExit("--check requires --output")
        try:
            current = load_json(output_path)
        except BenchmarkInventoryError as exc:
            raise SystemExit(f"benchmark coverage inventory check failed: {exc}") from exc
        if not isinstance(current, dict) or not reports_match(report, current):
            print(f"ERROR: {output_path} is stale; regenerate with {Path(__file__).name}", file=sys.stderr)
            raise SystemExit(1)
        return

    if output_path is not None:
        write_json(output_path, report)
    else:
        print(json.dumps(report, indent=2, sort_keys=False))

    if args.log:
        write_jsonl(root / args.log if not Path(args.log).is_absolute() else Path(args.log), events)


if __name__ == "__main__":
    main()
