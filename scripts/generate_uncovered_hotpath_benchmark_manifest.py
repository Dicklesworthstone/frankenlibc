#!/usr/bin/env python3
"""Generate the uncovered hot-path benchmark manifest for bd-b92jd.2.2."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BEAD_ID = "bd-b92jd.2.2"
SCHEMA_VERSION = "v1"
REQUIRED_MODES = ["strict", "hardened"]
CURRENT_COVERED_MODULES = {
    "string_abi": "string",
    "malloc_abi": "malloc",
    "pthread_abi": "pthread",
}
REQUIRED_ROW_FIELDS = [
    "row_id",
    "symbol",
    "module",
    "status",
    "perf_class",
    "benchmark_assignment",
    "coverage_gap",
    "safety",
    "priority",
    "artifact_refs",
    "failure_signature",
]
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "scenario_id",
    "api_family",
    "module",
    "symbol",
    "benchmark_id",
    "runtime_modes",
    "expected",
    "actual",
    "decision_path",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]

MODULE_PLANS: dict[str, dict[str, object]] = {
    "c11threads_abi": {
        "api_family": "pthread",
        "suite_id": "pthread_threads",
        "benchmark_file": "crates/frankenlibc-bench/benches/mutex_bench.rs",
        "plan_kind": "extend_existing_thread_benches",
        "coverage_blocker": "missing_pthread_baseline_spec_suite",
        "unsafe_to_benchmark_reason": None,
        "next_action": "Add c11 thread lifecycle cases to the pthread benchmark suite and collect strict/hardened baselines.",
    },
    "ctype_abi": {
        "api_family": "ctype",
        "suite_id": "ctype",
        "benchmark_file": "crates/frankenlibc-bench/benches/ctype_bench.rs",
        "plan_kind": "new_benchmark_family",
        "coverage_blocker": "missing_benchmark_target_and_spec_suite",
        "unsafe_to_benchmark_reason": None,
        "next_action": "Create a table/classification benchmark target for ctype lookup-table and locale-free paths.",
    },
    "errno_abi": {
        "api_family": "errno",
        "suite_id": "errno",
        "benchmark_file": "crates/frankenlibc-bench/benches/errno_bench.rs",
        "plan_kind": "new_benchmark_family",
        "coverage_blocker": "missing_benchmark_target_and_spec_suite",
        "unsafe_to_benchmark_reason": None,
        "next_action": "Create a TLS errno/h_errno accessor benchmark family with strict/hardened mode attribution.",
    },
    "resolv_abi": {
        "api_family": "resolver",
        "suite_id": "resolver",
        "benchmark_file": "crates/frankenlibc-bench/benches/resolver_bench.rs",
        "plan_kind": "new_hermetic_benchmark_family",
        "coverage_blocker": "requires_hermetic_resolver_lab_before_benchmark_target",
        "unsafe_to_benchmark_reason": "real_dns_network_io_disallowed",
        "next_action": "Use the hermetic NSS/resolver lab before timing resolver paths; real network/DNS is not an acceptable benchmark dependency.",
    },
    "stdio_abi": {
        "api_family": "stdio",
        "suite_id": "stdio",
        "benchmark_file": "crates/frankenlibc-bench/benches/stdio_bench.rs",
        "plan_kind": "extend_existing_benchmark_family",
        "coverage_blocker": "missing_stdio_perf_baseline_spec_suite",
        "unsafe_to_benchmark_reason": None,
        "next_action": "Add unlocked stream-operation cases to stdio_bench and wire the stdio suite into perf_baseline_spec.",
    },
    "stdlib_abi": {
        "api_family": "stdlib",
        "suite_id": "stdlib",
        "benchmark_file": "crates/frankenlibc-bench/benches/stdlib_bench.rs",
        "plan_kind": "new_benchmark_family",
        "coverage_blocker": "missing_benchmark_target_and_spec_suite",
        "unsafe_to_benchmark_reason": None,
        "next_action": "Create conversion/search/random hot-path benchmarks with deterministic inputs and no process-global mutation leaks.",
    },
    "time_abi": {
        "api_family": "time",
        "suite_id": "time",
        "benchmark_file": "crates/frankenlibc-bench/benches/time_bench.rs",
        "plan_kind": "new_controlled_time_benchmark_family",
        "coverage_blocker": "requires_time_fixture_before_wall_clock_sensitive_benchmarks",
        "unsafe_to_benchmark_reason": "wall_clock_discontinuity_must_be_isolated",
        "next_action": "Benchmark pure conversion paths directly and gate wall-clock-sensitive paths behind controlled fixtures.",
    },
    "wchar_abi": {
        "api_family": "wchar",
        "suite_id": "string",
        "benchmark_file": "crates/frankenlibc-bench/benches/string_bench.rs",
        "plan_kind": "extend_existing_string_benchmark_family",
        "coverage_blocker": "missing_wchar_symbol_specific_benchmarks",
        "unsafe_to_benchmark_reason": None,
        "next_action": "Extend string_bench with wchar/wctype symbol-specific cases and baselines.",
    },
}


class ManifestError(ValueError):
    """Raised when manifest inputs or rows are not trustworthy."""


def repo_root() -> Path:
    root = Path(__file__).resolve().parent.parent
    if not (root / "Cargo.toml").exists():
        raise ManifestError(f"could not locate repo root from {__file__}")
    return root


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"{path}: could not read JSON: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{path}: invalid JSON: {exc}") from exc


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise ManifestError(f"{path}: could not hash input: {exc}") from exc


def source_commit(root: Path) -> str:
    head_path = root / ".git" / "HEAD"
    try:
        head = head_path.read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    if not head.startswith("ref: "):
        return head[:8] if head else "unknown"
    ref_name = head.removeprefix("ref: ").strip()
    ref_path = root / ".git" / ref_name
    try:
        value = ref_path.read_text(encoding="utf-8").strip()
        return value[:8] if value else "unknown"
    except OSError:
        return "unknown"


def symbol_slug(symbol: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", symbol).strip("_")
    return slug or "symbol"


def support_by_symbol(support_matrix: dict[str, object]) -> dict[str, dict[str, object]]:
    rows = support_matrix.get("symbols", [])
    if not isinstance(rows, list):
        raise ManifestError("support_matrix.symbols must be an array")
    out: dict[str, dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        symbol = row.get("symbol")
        if isinstance(symbol, str):
            out[symbol] = row
    return out


def strict_hotpath_symbols(policy: dict[str, object]) -> list[dict[str, object]]:
    rows = policy.get("hotpath_symbols", {}).get("strict_hotpath", [])
    if not isinstance(rows, list):
        raise ManifestError("perf_budget_policy.hotpath_symbols.strict_hotpath must be an array")
    valid: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ManifestError("strict_hotpath entry must be an object")
        for field in ("symbol", "module", "status"):
            if not isinstance(row.get(field), str) or not row.get(field):
                raise ManifestError(f"strict_hotpath entry missing {field}: {row!r}")
        valid.append(row)
    return valid


def current_uncovered_symbols(policy: dict[str, object]) -> list[dict[str, object]]:
    return [
        row
        for row in strict_hotpath_symbols(policy)
        if str(row["module"]) not in CURRENT_COVERED_MODULES
    ]


def input_digests(root: Path) -> dict[str, str]:
    paths = {
        "support_matrix": root / "support_matrix.json",
        "perf_budget_policy": root / "tests/conformance/perf_budget_policy.json",
        "perf_regression_prevention": root / "tests/conformance/perf_regression_prevention.v1.json",
        "benchmark_coverage_inventory": root / "tests/conformance/benchmark_coverage_inventory.v1.json",
        "perf_baseline_spec": root / "tests/conformance/perf_baseline_spec.json",
        "perf_baseline": root / "scripts/perf_baseline.json",
    }
    return {name: sha256_file(path) for name, path in sorted(paths.items())}


def row_for_symbol(symbol: dict[str, object], support: dict[str, object], index: int) -> dict[str, object]:
    module = str(symbol["module"])
    plan = MODULE_PLANS.get(module)
    if plan is None:
        raise ManifestError(f"missing module plan for uncovered module {module}")
    name = str(symbol["symbol"])
    api_family = str(plan["api_family"])
    benchmark_id = f"{api_family}.{symbol_slug(name)}"
    coverage_blocker = str(plan["coverage_blocker"])
    unsafe_reason = plan["unsafe_to_benchmark_reason"]
    return {
        "row_id": f"{module}:{name}",
        "symbol": name,
        "module": module,
        "status": str(symbol["status"]),
        "perf_class": "strict_hotpath",
        "support_matrix_status": str(support.get("status", "")),
        "support_matrix_perf_class": str(support.get("perf_class", "")),
        "benchmark_assignment": {
            "api_family": api_family,
            "suite_id": plan["suite_id"],
            "benchmark_id": benchmark_id,
            "benchmark_file": plan["benchmark_file"],
            "plan_kind": plan["plan_kind"],
            "next_action": plan["next_action"],
        },
        "coverage_gap": {
            "current_coverage_source": "tests/conformance/perf_regression_prevention.v1.json",
            "current_coverage_state": "uncovered",
            "current_coverage_blocker": coverage_blocker,
            "current_covered_modules": CURRENT_COVERED_MODULES,
        },
        "safety": {
            "can_benchmark_without_real_network": module != "resolv_abi",
            "can_benchmark_without_system_mutation": True,
            "unsafe_to_benchmark_reason": unsafe_reason,
            "required_fixture": "hermetic" if unsafe_reason else "deterministic_inputs",
        },
        "priority": {
            "rank": index + 1,
            "reason": "strict_hotpath_uncovered_by_current_perf_regression_gate",
        },
        "artifact_refs": [
            "support_matrix.json",
            "tests/conformance/perf_budget_policy.json",
            "tests/conformance/perf_regression_prevention.v1.json",
            "tests/conformance/benchmark_coverage_inventory.v1.json",
            "tests/conformance/perf_baseline_spec.json",
            "scripts/perf_baseline.json",
        ],
        "failure_signature": f"uncovered_hotpath_benchmark:{module}:{name}",
    }


def validate_rows(
    rows: list[dict[str, object]],
    expected_symbols: list[dict[str, object]],
    support_rows: dict[str, dict[str, object]],
    prevention: dict[str, object],
) -> None:
    errors: list[str] = []
    seen: set[str] = set()
    expected_keys = {f"{row['module']}:{row['symbol']}" for row in expected_symbols}
    actual_keys: set[str] = set()

    for row in rows:
        row_id = str(row.get("row_id", ""))
        if not row_id:
            errors.append("row missing row_id")
            continue
        if row_id in seen:
            errors.append(f"duplicate row_id:{row_id}")
        seen.add(row_id)
        missing_fields = [field for field in REQUIRED_ROW_FIELDS if field not in row]
        if missing_fields:
            errors.append(f"{row_id}: missing fields {','.join(missing_fields)}")
        actual_keys.add(row_id)

        module = str(row.get("module", ""))
        symbol = str(row.get("symbol", ""))
        if module not in MODULE_PLANS:
            errors.append(f"{row_id}: missing module plan")
        if module in CURRENT_COVERED_MODULES:
            errors.append(f"{row_id}: covered module leaked into uncovered manifest")
        support = support_rows.get(symbol)
        if support is None:
            errors.append(f"{row_id}: missing support_matrix row")
        else:
            if support.get("module") != module:
                errors.append(f"{row_id}: stale support_matrix module")
            if support.get("perf_class") != "strict_hotpath":
                errors.append(f"{row_id}: stale support_matrix perf_class")
            if support.get("status") != row.get("status"):
                errors.append(f"{row_id}: stale support_matrix status")
        assignment = row.get("benchmark_assignment", {})
        if not isinstance(assignment, dict):
            errors.append(f"{row_id}: benchmark_assignment must be object")
        else:
            if not assignment.get("api_family") or not assignment.get("benchmark_id"):
                errors.append(f"{row_id}: missing benchmark assignment")
            if not str(assignment.get("benchmark_file", "")).startswith("crates/frankenlibc-bench/benches/"):
                errors.append(f"{row_id}: benchmark_file must live under frankenlibc-bench/benches")
        safety = row.get("safety", {})
        if isinstance(safety, dict) and module == "resolv_abi":
            if not safety.get("unsafe_to_benchmark_reason"):
                errors.append(f"{row_id}: resolver row must record real-network blocker")

    missing = sorted(expected_keys - actual_keys)
    extra = sorted(actual_keys - expected_keys)
    if missing:
        errors.append("missing expected rows:" + ",".join(missing[:10]))
    if extra:
        errors.append("unexpected rows:" + ",".join(extra[:10]))

    hotpath = prevention.get("hotpath_symbol_coverage", {})
    expected_count = hotpath.get("not_covered")
    if isinstance(expected_count, int) and expected_count != len(rows):
        errors.append(f"prevention not_covered mismatch: prevention={expected_count} manifest={len(rows)}")
    expected_modules = sorted(hotpath.get("uncovered_modules", []))
    actual_modules = sorted({str(row.get("module")) for row in rows})
    if expected_modules and expected_modules != actual_modules:
        errors.append(f"prevention uncovered_modules mismatch: prevention={expected_modules} manifest={actual_modules}")

    if errors:
        raise ManifestError("; ".join(errors))


def module_summary(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    modules = sorted({str(row["module"]) for row in rows})
    summary: list[dict[str, object]] = []
    for module in modules:
        module_rows = [row for row in rows if row["module"] == module]
        plan = MODULE_PLANS[module]
        blockers = sorted({str(row["coverage_gap"]["current_coverage_blocker"]) for row in module_rows})
        unsafe_blockers = sorted(
            {
                str(row["safety"]["unsafe_to_benchmark_reason"])
                for row in module_rows
                if row["safety"]["unsafe_to_benchmark_reason"]
            }
        )
        summary.append(
            {
                "module": module,
                "api_family": plan["api_family"],
                "symbol_count": len(module_rows),
                "benchmark_file": plan["benchmark_file"],
                "suite_id": plan["suite_id"],
                "plan_kind": plan["plan_kind"],
                "coverage_blockers": blockers,
                "unsafe_benchmark_blockers": unsafe_blockers,
                "next_action": plan["next_action"],
            }
        )
    return summary


def build_report(root: Path, target_dir: str) -> tuple[dict[str, object], list[dict[str, object]]]:
    start = time.perf_counter_ns()
    policy = load_json(root / "tests/conformance/perf_budget_policy.json")
    support_matrix = load_json(root / "support_matrix.json")
    prevention = load_json(root / "tests/conformance/perf_regression_prevention.v1.json")
    support_rows = support_by_symbol(support_matrix)
    uncovered = current_uncovered_symbols(policy)

    rows = []
    for index, symbol in enumerate(sorted(uncovered, key=lambda row: (str(row["module"]), str(row["symbol"])))):
        support = support_rows.get(str(symbol["symbol"]), {})
        rows.append(row_for_symbol(symbol, support, index))
    validate_rows(rows, uncovered, support_rows, prevention)

    elapsed_ns = time.perf_counter_ns() - start
    modules = module_summary(rows)
    unsafe_count = sum(1 for row in rows if row["safety"]["unsafe_to_benchmark_reason"])
    coverage_blockers = sorted({str(row["coverage_gap"]["current_coverage_blocker"]) for row in rows})
    commit = source_commit(root)

    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "bead": BEAD_ID,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_commit": commit,
        "purpose": "Fail-closed manifest for strict hot-path symbols not covered by the current benchmark suite map.",
        "inputs": {
            "support_matrix": "support_matrix.json",
            "perf_budget_policy": "tests/conformance/perf_budget_policy.json",
            "perf_regression_prevention": "tests/conformance/perf_regression_prevention.v1.json",
            "benchmark_coverage_inventory": "tests/conformance/benchmark_coverage_inventory.v1.json",
            "perf_baseline_spec": "tests/conformance/perf_baseline_spec.json",
            "perf_baseline": "scripts/perf_baseline.json",
        },
        "input_digests": input_digests(root),
        "required_row_fields": REQUIRED_ROW_FIELDS,
        "required_log_fields": REQUIRED_LOG_FIELDS,
        "current_covered_module_map": CURRENT_COVERED_MODULES,
        "summary": {
            "total_strict_hotpath_symbols": len(strict_hotpath_symbols(policy)),
            "current_uncovered_symbol_count": len(rows),
            "current_covered_symbol_count": len(strict_hotpath_symbols(policy)) - len(rows),
            "module_count": len(modules),
            "modules": [row["module"] for row in modules],
            "coverage_blockers": coverage_blockers,
            "unsafe_benchmark_blocker_count": unsafe_count,
            "duplicate_row_count": 0,
            "missing_expected_row_count": 0,
            "stale_support_matrix_row_count": 0,
        },
        "modules": modules,
        "rows": rows,
        "follow_up_beads": [
            {
                "bead": "bd-b92jd.2.3",
                "scope": "Retire or narrow active perf waiver after this manifest and follow-up benchmark rows reduce risk.",
            },
            {
                "bead": "bd-b92jd.5.1",
                "scope": "Provide hermetic resolver lab required before resolver hot-path timing avoids real DNS/network dependency.",
            },
            {
                "bead": "bd-b92jd.5.3",
                "scope": "Provide deterministic pthread/malloc/stdio stress fixtures that can feed high-contention hot-path benchmarks.",
            },
        ],
        "closure_evidence": {
            "generator": "scripts/generate_uncovered_hotpath_benchmark_manifest.py",
            "gate": "scripts/check_uncovered_hotpath_benchmark_manifest.sh",
            "committed_artifact": "tests/conformance/uncovered_hotpath_benchmark_manifest.v1.json",
            "target_report": "target/conformance/uncovered_hotpath_benchmark_manifest.report.json",
            "target_log": "target/conformance/uncovered_hotpath_benchmark_manifest.log.jsonl",
        },
    }
    attach_artifact_hash(report)
    events = [
        {
            "trace_id": f"{BEAD_ID}:{module['module']}",
            "bead_id": BEAD_ID,
            "scenario_id": f"uncovered_hotpath_benchmark_manifest:{module['module']}",
            "api_family": module["api_family"],
            "module": module["module"],
            "symbol": ",".join(row["symbol"] for row in rows if row["module"] == module["module"]),
            "benchmark_id": module["suite_id"],
            "runtime_modes": REQUIRED_MODES,
            "expected": {"all_current_uncovered_symbols_present": True, "duplicate_rows": 0},
            "actual": {
                "symbol_count": module["symbol_count"],
                "coverage_blockers": module["coverage_blockers"],
                "unsafe_benchmark_blockers": module["unsafe_benchmark_blockers"],
            },
            "decision_path": [
                "perf_budget_policy.hotpath_symbols.strict_hotpath",
                "current_covered_module_map",
                "support_matrix",
                "perf_regression_prevention.hotpath_symbol_coverage",
            ],
            "latency_ns": elapsed_ns,
            "artifact_refs": list(report["inputs"].values()) + [report["closure_evidence"]["committed_artifact"]],
            "source_commit": commit,
            "target_dir": target_dir,
            "failure_signature": None,
        }
        for module in modules
    ]
    return report, events


def normalized_report(report: dict[str, object]) -> dict[str, object]:
    normalized = deepcopy(report)
    normalized.pop("generated_at_utc", None)
    normalized.pop("source_commit", None)
    normalized.pop("artifact_hash", None)
    return normalized


def attach_artifact_hash(report: dict[str, object]) -> None:
    report["artifact_hash"] = sha256_bytes(stable_json(normalized_report(report)).encode("utf-8"))


def validate_manifest(root: Path, path: Path) -> None:
    policy = load_json(root / "tests/conformance/perf_budget_policy.json")
    support_matrix = load_json(root / "support_matrix.json")
    prevention = load_json(root / "tests/conformance/perf_regression_prevention.v1.json")
    manifest = load_json(path)
    rows = manifest.get("rows", [])
    if not isinstance(rows, list):
        raise ManifestError("manifest rows must be an array")
    validate_rows(rows, current_uncovered_symbols(policy), support_by_symbol(support_matrix), prevention)


def compare_current(root: Path, generated: dict[str, object], committed_path: Path) -> None:
    committed = load_json(committed_path)
    if normalized_report(generated) != normalized_report(committed):
        raise ManifestError(f"{committed_path}: stale committed uncovered-hotpath manifest")


def self_test(root: Path) -> None:
    report, _events = build_report(root, "target/conformance/self-test")
    validate_manifest_data = deepcopy(report)
    validate_rows(
        validate_manifest_data["rows"],
        current_uncovered_symbols(load_json(root / "tests/conformance/perf_budget_policy.json")),
        support_by_symbol(load_json(root / "support_matrix.json")),
        load_json(root / "tests/conformance/perf_regression_prevention.v1.json"),
    )
    duplicate = deepcopy(report)
    duplicate["rows"].append(deepcopy(duplicate["rows"][0]))
    try:
        validate_rows(
            duplicate["rows"],
            current_uncovered_symbols(load_json(root / "tests/conformance/perf_budget_policy.json")),
            support_by_symbol(load_json(root / "support_matrix.json")),
            load_json(root / "tests/conformance/perf_regression_prevention.v1.json"),
        )
    except ManifestError as exc:
        if "duplicate row_id" not in str(exc):
            raise
    else:
        raise ManifestError("self-test duplicate row was accepted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", "-o", type=Path, help="Write generated manifest JSON here")
    parser.add_argument("--log", type=Path, help="Write structured JSONL events here")
    parser.add_argument("--target-dir", default="target/conformance", help="Target directory recorded in log events")
    parser.add_argument("--self-test", action="store_true", help="Run generator self-tests")
    parser.add_argument("--validate-manifest", type=Path, help="Validate an existing manifest against current inputs")
    parser.add_argument("--check-current", action="store_true", help="Compare generated manifest with committed artifact")
    args = parser.parse_args()

    try:
        root = repo_root()
        if args.self_test:
            self_test(root)
        if args.validate_manifest:
            validate_manifest(root, args.validate_manifest)
            return 0
        report, events = build_report(root, args.target_dir)
        if args.check_current:
            compare_current(root, report, root / "tests/conformance/uncovered_hotpath_benchmark_manifest.v1.json")
        if args.output:
            write_json(args.output, report)
        else:
            print(json.dumps(report, indent=2, sort_keys=False))
        if args.log:
            write_jsonl(args.log, events)
        return 0
    except ManifestError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
