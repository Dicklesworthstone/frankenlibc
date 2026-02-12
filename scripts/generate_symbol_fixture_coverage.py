#!/usr/bin/env python3
"""
Deterministic exported-symbol <-> fixture coverage matrix generator (bd-15n.1).

Inputs:
- support_matrix.json
- tests/conformance/fixtures/*.json
- tests/conformance/c_fixture_spec.json
- tests/conformance/workload_matrix.json

Output:
- tests/conformance/symbol_fixture_coverage.v1.json
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

TARGET_STATUSES = {"Implemented", "RawSyscall"}
WEAK_FAMILY_THRESHOLD_PCT = 80.0

TRACK_BY_MODULE = {
    "ctype_abi": "ctype",
    "dirent_abi": "dirent",
    "dlfcn_abi": "rtld/dlfcn",
    "errno_abi": "errno",
    "grp_abi": "identity",
    "iconv_abi": "i18n/iconv",
    "inet_abi": "network/inet",
    "io_abi": "io",
    "locale_abi": "locale",
    "malloc_abi": "allocator",
    "math_abi": "math",
    "mmap_abi": "vm/mmap",
    "poll_abi": "poll",
    "process_abi": "process",
    "pthread_abi": "threading",
    "pwd_abi": "identity",
    "resolv_abi": "resolver",
    "resource_abi": "resource",
    "signal_abi": "signal",
    "socket_abi": "network/socket",
    "startup_abi": "startup",
    "stdio_abi": "stdio",
    "stdlib_abi": "stdlib",
    "string_abi": "string",
    "termios_abi": "termios",
    "time_abi": "time",
    "unistd_abi": "unistd/syscall",
    "wchar_abi": "string/wide",
}


@dataclass
class FixtureCoverage:
    fixture_case_count: int = 0
    c_fixture_mentions: int = 0
    sources: set[str] = field(default_factory=set)
    fixture_files: set[str] = field(default_factory=set)
    fixture_ids: set[str] = field(default_factory=set)
    families: set[str] = field(default_factory=set)
    modes: set[str] = field(default_factory=set)


def _pct(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 100.0
    return round((numerator * 100.0) / denominator, 2)


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _track_for_module(module: str) -> str:
    if module in TRACK_BY_MODULE:
        return TRACK_BY_MODULE[module]
    return module.removesuffix("_abi")


def _collect_fixture_index(
    fixtures_dir: str, c_fixture_spec_path: str
) -> tuple[dict[str, FixtureCoverage], dict[str, Any]]:
    fixture_index: dict[str, FixtureCoverage] = {}

    fixture_files = sorted(glob.glob(os.path.join(fixtures_dir, "*.json")))
    total_cases = 0
    fixture_functions: set[str] = set()

    for fixture_path in fixture_files:
        fixture = _load_json(fixture_path)
        family = str(fixture.get("family", os.path.basename(fixture_path)))
        for case in fixture.get("cases", []):
            function = case.get("function")
            if not isinstance(function, str) or not function:
                continue
            total_cases += 1
            fixture_functions.add(function)

            cov = fixture_index.setdefault(function, FixtureCoverage())
            cov.fixture_case_count += 1
            cov.sources.add("fixture_json")
            cov.fixture_files.add(os.path.basename(fixture_path))
            cov.families.add(family)
            mode = case.get("mode")
            if isinstance(mode, str) and mode:
                cov.modes.add(mode)

    c_fixture_spec = _load_json(c_fixture_spec_path)
    c_spec_fixture_count = 0
    c_spec_symbol_mentions = 0
    c_spec_symbols: set[str] = set()
    for fixture in c_fixture_spec.get("fixtures", []):
        fixture_id = fixture.get("id")
        if not isinstance(fixture_id, str) or not fixture_id:
            continue
        c_spec_fixture_count += 1
        for symbol in fixture.get("covered_symbols", []):
            if not isinstance(symbol, str) or not symbol:
                continue
            c_spec_symbol_mentions += 1
            c_spec_symbols.add(symbol)
            fixture_functions.add(symbol)
            cov = fixture_index.setdefault(symbol, FixtureCoverage())
            cov.c_fixture_mentions += 1
            cov.sources.add("c_fixture_spec")
            cov.fixture_ids.add(fixture_id)
            cov.families.add("c_fixture_suite")

    inventory = {
        "fixture_json_files": len(fixture_files),
        "fixture_json_cases": total_cases,
        "fixture_json_unique_functions": len(
            {fn for fn, cov in fixture_index.items() if cov.fixture_case_count > 0}
        ),
        "c_fixture_spec_fixtures": c_spec_fixture_count,
        "c_fixture_spec_symbol_mentions": c_spec_symbol_mentions,
        "c_fixture_spec_unique_symbols": len(c_spec_symbols),
        "unique_fixture_functions_total": len(fixture_functions),
    }
    return fixture_index, inventory


def _load_workload_impact(
    workload_matrix_path: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
    if not os.path.isfile(workload_matrix_path):
        return {}, {}

    data = _load_json(workload_matrix_path)
    subsystem_impact = data.get("subsystem_impact", {})
    impact_map: dict[str, dict[str, Any]] = {}
    for module, body in subsystem_impact.items():
        if module == "description" or not isinstance(body, dict):
            continue
        impact_map[module] = {
            "blocked_workloads": int(body.get("blocked_workloads", 0)),
            "workload_ids": sorted(
                [wid for wid in body.get("workload_ids", []) if isinstance(wid, str)]
            ),
        }

    milestone_mapping = data.get("milestone_mapping", {})
    module_to_beads: dict[str, set[str]] = defaultdict(set)
    for row in milestone_mapping.get("milestones", []):
        bead = row.get("bead")
        if not isinstance(bead, str) or not bead:
            continue
        for module in row.get("unblocks_modules", []):
            if isinstance(module, str) and module:
                module_to_beads[module].add(bead)

    out_beads = {module: sorted(list(beads)) for module, beads in module_to_beads.items()}
    return impact_map, out_beads


def _severity_for_target(target_total: int, target_covered: int, target_pct: float) -> str:
    if target_total <= 0:
        return "n/a"
    if target_covered == target_total:
        return "covered"
    if target_covered == 0:
        return "critical"
    if target_pct < WEAK_FAMILY_THRESHOLD_PCT:
        return "high"
    return "medium"


def _severity_weight(severity: str) -> int:
    return {"critical": 3, "high": 2, "medium": 1, "covered": 0, "n/a": 0}.get(severity, 0)


def generate_matrix(
    support_matrix_path: str,
    fixtures_dir: str,
    c_fixture_spec_path: str,
    workload_matrix_path: str,
    emit_logs: bool,
) -> dict[str, Any]:
    started = time.time()
    trace_id = f"bd-15n.1-{int(started * 1000)}"

    support = _load_json(support_matrix_path)
    symbols = support.get("symbols", [])
    if not isinstance(symbols, list):
        raise ValueError("support_matrix.json: symbols must be a list")

    fixture_index, fixture_inventory = _collect_fixture_index(fixtures_dir, c_fixture_spec_path)
    impact_map, module_to_beads = _load_workload_impact(workload_matrix_path)

    symbol_names = {
        row.get("symbol")
        for row in symbols
        if isinstance(row, dict) and isinstance(row.get("symbol"), str)
    }
    non_symbol_fixture_functions = sorted(
        [name for name in fixture_index.keys() if name not in symbol_names]
    )

    symbol_rows = []
    status_summary: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "covered": 0, "uncovered": 0}
    )
    module_summary: dict[str, dict[str, Any]] = {}

    for row in sorted(symbols, key=lambda r: (str(r.get("module", "")), str(r.get("symbol", "")))):
        symbol = str(row.get("symbol", ""))
        module = str(row.get("module", "unknown"))
        status = str(row.get("status", "Unknown"))
        perf_class = str(row.get("perf_class", "unknown"))
        cov = fixture_index.get(symbol)
        covered = cov is not None

        status_summary[status]["total"] += 1
        if covered:
            status_summary[status]["covered"] += 1
        else:
            status_summary[status]["uncovered"] += 1

        mod = module_summary.setdefault(
            module,
            {
                "module": module,
                "track": _track_for_module(module),
                "total_symbols": 0,
                "covered_symbols": 0,
                "uncovered_symbols": 0,
                "target_total": 0,
                "target_covered": 0,
                "target_uncovered": 0,
                "target_uncovered_symbols": [],
                "statuses": defaultdict(int),
            },
        )

        mod["total_symbols"] += 1
        mod["statuses"][status] += 1
        if covered:
            mod["covered_symbols"] += 1
        else:
            mod["uncovered_symbols"] += 1

        if status in TARGET_STATUSES:
            mod["target_total"] += 1
            if covered:
                mod["target_covered"] += 1
            else:
                mod["target_uncovered"] += 1
                mod["target_uncovered_symbols"].append(symbol)

        symbol_rows.append(
            {
                "symbol": symbol,
                "module": module,
                "status": status,
                "perf_class": perf_class,
                "covered": covered,
                "fixture_case_count": 0 if cov is None else cov.fixture_case_count,
                "c_fixture_mentions": 0 if cov is None else cov.c_fixture_mentions,
                "fixture_sources": [] if cov is None else sorted(cov.sources),
                "fixture_files": [] if cov is None else sorted(cov.fixture_files),
                "fixture_ids": [] if cov is None else sorted(cov.fixture_ids),
                "fixture_families": [] if cov is None else sorted(cov.families),
                "fixture_modes": [] if cov is None else sorted(cov.modes),
            }
        )

    module_rows = []
    uncovered_target_families = []
    weak_target_families = []
    ownership_rows = []

    for module in sorted(module_summary.keys()):
        row = module_summary[module]
        target_total = int(row["target_total"])
        target_covered = int(row["target_covered"])
        target_uncovered = int(row["target_uncovered"])
        target_pct = _pct(target_covered, target_total)
        severity = _severity_for_target(target_total, target_covered, target_pct)

        impact = impact_map.get(module, {"blocked_workloads": 0, "workload_ids": []})
        milestone_beads = module_to_beads.get(module, [])
        severity_score = (
            target_uncovered * 100
            + int(impact["blocked_workloads"]) * 10
            + _severity_weight(severity)
        )

        module_row = {
            "module": module,
            "track": row["track"],
            "total_symbols": row["total_symbols"],
            "covered_symbols": row["covered_symbols"],
            "uncovered_symbols": row["uncovered_symbols"],
            "target_statuses": sorted(TARGET_STATUSES),
            "target_total": target_total,
            "target_covered": target_covered,
            "target_uncovered": target_uncovered,
            "target_coverage_pct": target_pct,
            "target_uncovered_symbols": sorted(row["target_uncovered_symbols"]),
            "severity": severity,
            "severity_score": severity_score,
            "workload_blocked_count": int(impact["blocked_workloads"]),
            "workload_ids": impact["workload_ids"],
            "milestone_beads": milestone_beads,
            "recommended_bead": None if not milestone_beads else milestone_beads[0],
            "status_breakdown": dict(sorted(row["statuses"].items())),
        }
        module_rows.append(module_row)

        if target_total > 0 and target_covered == 0:
            uncovered_target_families.append(module_row)
        if target_total > 0 and 0 < target_pct < WEAK_FAMILY_THRESHOLD_PCT:
            weak_target_families.append(module_row)
        if target_uncovered > 0:
            ownership_rows.append(
                {
                    "module": module,
                    "track": row["track"],
                    "target_uncovered_symbols": sorted(row["target_uncovered_symbols"]),
                    "target_uncovered_count": target_uncovered,
                    "severity": severity,
                    "workload_blocked_count": int(impact["blocked_workloads"]),
                    "workload_ids": impact["workload_ids"],
                    "milestone_beads": milestone_beads,
                    "recommended_bead": None if not milestone_beads else milestone_beads[0],
                }
            )

        if emit_logs:
            log_record = {
                "trace_id": trace_id,
                "mode": "coverage_matrix_generation",
                "family": module,
                "covered_count": target_covered,
                "uncovered_count": target_uncovered,
                "severity": severity,
            }
            print(json.dumps(log_record, separators=(",", ":")))

    ownership_rows.sort(
        key=lambda row: (
            -row["target_uncovered_count"],
            -row["workload_blocked_count"],
            row["module"],
        )
    )
    module_rows.sort(key=lambda row: (-row["severity_score"], row["module"]))

    total_symbols = len(symbol_rows)
    covered_symbols = sum(1 for row in symbol_rows if row["covered"])

    target_total = sum(
        int(info["total"])
        for status, info in status_summary.items()
        if status in TARGET_STATUSES
    )
    target_covered = sum(
        int(info["covered"])
        for status, info in status_summary.items()
        if status in TARGET_STATUSES
    )

    status_rows = {}
    for status in sorted(status_summary.keys()):
        info = status_summary[status]
        status_rows[status] = {
            "total": int(info["total"]),
            "covered": int(info["covered"]),
            "uncovered": int(info["uncovered"]),
            "coverage_pct": _pct(int(info["covered"]), int(info["total"])),
        }

    finished = time.time()
    timing_ms = int((finished - started) * 1000)
    generated_at = str(support.get("generated_at_utc", "unknown"))

    return {
        "schema_version": 1,
        "bead": "bd-15n.1",
        "description": (
            "Exported symbol <-> conformance fixture coverage matrix. "
            "Targets Implemented/RawSyscall coverage gaps and maps them to subsystem tracks."
        ),
        "trace_id": trace_id,
        "generated_at_utc": generated_at,
        "timing_ms": timing_ms,
        "inputs": {
            "support_matrix": support_matrix_path,
            "fixtures_dir": fixtures_dir,
            "c_fixture_spec": c_fixture_spec_path,
            "workload_matrix": workload_matrix_path,
        },
        "summary": {
            "total_exported_symbols": total_symbols,
            "covered_exported_symbols": covered_symbols,
            "uncovered_exported_symbols": total_symbols - covered_symbols,
            "coverage_pct": _pct(covered_symbols, total_symbols),
            "target_statuses": sorted(TARGET_STATUSES),
            "target_total_symbols": target_total,
            "target_covered_symbols": target_covered,
            "target_uncovered_symbols": target_total - target_covered,
            "target_coverage_pct": _pct(target_covered, target_total),
            "weak_family_threshold_pct": WEAK_FAMILY_THRESHOLD_PCT,
            "uncovered_target_families": len(uncovered_target_families),
            "weak_target_families": len(weak_target_families),
        },
        "fixture_inventory": {
            **fixture_inventory,
            "non_symbol_fixture_functions": non_symbol_fixture_functions,
            "non_symbol_fixture_function_count": len(non_symbol_fixture_functions),
        },
        "status_coverage": status_rows,
        "families": module_rows,
        "uncovered_target_families": [
            {
                "module": row["module"],
                "track": row["track"],
                "target_uncovered_symbols": row["target_uncovered_symbols"],
                "target_uncovered_count": row["target_uncovered"],
                "severity": row["severity"],
                "workload_blocked_count": row["workload_blocked_count"],
                "workload_ids": row["workload_ids"],
                "recommended_bead": row["recommended_bead"],
            }
            for row in sorted(uncovered_target_families, key=lambda r: r["module"])
        ],
        "weak_target_families": [
            {
                "module": row["module"],
                "track": row["track"],
                "target_coverage_pct": row["target_coverage_pct"],
                "target_uncovered_symbols": row["target_uncovered_symbols"],
                "target_uncovered_count": row["target_uncovered"],
                "severity": row["severity"],
                "workload_blocked_count": row["workload_blocked_count"],
                "workload_ids": row["workload_ids"],
                "recommended_bead": row["recommended_bead"],
            }
            for row in sorted(weak_target_families, key=lambda r: r["module"])
        ],
        "ownership_map": ownership_rows,
        "symbols": symbol_rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic exported symbol ↔ fixture coverage matrix."
    )
    parser.add_argument(
        "--support-matrix", default="support_matrix.json", help="Path to support_matrix.json"
    )
    parser.add_argument(
        "--fixtures-dir",
        default="tests/conformance/fixtures",
        help="Directory containing conformance fixture JSON files",
    )
    parser.add_argument(
        "--c-fixture-spec",
        default="tests/conformance/c_fixture_spec.json",
        help="Path to C fixture suite specification",
    )
    parser.add_argument(
        "--workload-matrix",
        default="tests/conformance/workload_matrix.json",
        help="Path to workload matrix for subsystem impact hints",
    )
    parser.add_argument(
        "--output",
        default="tests/conformance/symbol_fixture_coverage.v1.json",
        help="Output JSON artifact path",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress structured progress logs",
    )
    args = parser.parse_args()

    artifact = generate_matrix(
        support_matrix_path=args.support_matrix,
        fixtures_dir=args.fixtures_dir,
        c_fixture_spec_path=args.c_fixture_spec,
        workload_matrix_path=args.workload_matrix,
        emit_logs=not args.quiet,
    )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(artifact, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print(
        json.dumps(
            {
                "trace_id": artifact["trace_id"],
                "mode": "coverage_matrix_generation",
                "family": "all",
                "covered_count": artifact["summary"]["target_covered_symbols"],
                "uncovered_count": artifact["summary"]["target_uncovered_symbols"],
                "severity": "pass",
                "artifact_ref": args.output,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
