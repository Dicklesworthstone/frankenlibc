#!/usr/bin/env python3
"""
Deterministic symbol latency baseline inventory generator (bd-3h1u.1).

This artifact does not fabricate per-symbol latency measurements. Instead, it
produces a machine-checkable inventory across all exported symbols and marks
mode/percentile coverage as measured vs pending so capture waves can be tracked
without ambiguity.

Inputs:
- support_matrix.json
- scripts/perf_baseline.json
- tests/conformance/symbol_fixture_coverage.v1.json

Output:
- tests/conformance/symbol_latency_baseline.v1.json
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from typing import Any

TARGET_STATUSES = {"Implemented", "RawSyscall", "GlibcCallThrough"}
MODES = ("raw", "strict", "hardened")
PERCENTILES = ("p50", "p95", "p99")
HOT_PERF_CLASS = "strict_hotpath"
TRACE_ID = "bd-3h1u.1-symbol-latency-baseline-v1"


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_optional_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    return _load_json(path)


def _safe_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _mode_record() -> dict[str, Any]:
    return {
        "p50_ns": None,
        "p95_ns": None,
        "p99_ns": None,
        "capture_state": "pending_symbol_benchmark",
        "source": None,
    }


def _read_fixture_coverage(path: str) -> dict[str, bool]:
    doc = _load_json(path)
    out: dict[str, bool] = {}
    for row in doc.get("symbols", []):
        symbol = row.get("symbol")
        covered = row.get("covered")
        if isinstance(symbol, str):
            out[symbol] = bool(covered)
    return out


def _shared_overhead_reference(perf_baseline: dict[str, Any]) -> dict[str, Any]:
    p50 = perf_baseline.get("baseline_p50_ns_op", {})

    def _p50(suite: str, mode: str, bench: str) -> float | None:
        return _safe_float(p50.get(suite, {}).get(mode, {}).get(bench))

    return {
        "strict": {
            "runtime_math_decide_p50_ns": _p50("runtime_math", "strict", "decide"),
            "runtime_math_observe_fast_p50_ns": _p50("runtime_math", "strict", "observe_fast"),
            "runtime_math_decide_observe_p50_ns": _p50("runtime_math", "strict", "decide_observe"),
            "membrane_validate_known_p50_ns": _p50("membrane", "strict", "validate_known"),
        },
        "hardened": {
            "runtime_math_decide_p50_ns": _p50("runtime_math", "hardened", "decide"),
            "runtime_math_observe_fast_p50_ns": _p50("runtime_math", "hardened", "observe_fast"),
            "runtime_math_decide_observe_p50_ns": _p50("runtime_math", "hardened", "decide_observe"),
            "membrane_validate_known_p50_ns": _p50("membrane", "hardened", "validate_known"),
        },
    }


def _priority_score(row: dict[str, Any], fixture_covered: bool) -> int:
    score = 0
    if row.get("perf_class") == HOT_PERF_CLASS:
        score += 100
    if fixture_covered:
        score += 40

    status = row.get("status")
    if status == "Implemented":
        score += 30
    elif status == "RawSyscall":
        score += 20
    elif status == "GlibcCallThrough":
        score += 10

    return score


def generate_inventory(
    support_matrix_path: str,
    perf_baseline_path: str,
    symbol_fixture_coverage_path: str,
) -> dict[str, Any]:
    support = _load_json(support_matrix_path)
    perf_baseline = _load_optional_json(perf_baseline_path, {})
    fixture_cov = _read_fixture_coverage(symbol_fixture_coverage_path)

    symbols = support.get("symbols", [])
    if not isinstance(symbols, list):
        raise ValueError("support_matrix.json: symbols must be a list")

    shared_ref = _shared_overhead_reference(perf_baseline)

    symbol_rows: list[dict[str, Any]] = []
    status_breakdown: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "total": 0,
            "fixture_covered": 0,
            "fixture_uncovered": 0,
            "strict_hotpath": 0,
        }
    )
    module_breakdown: dict[str, dict[str, Any]] = {}

    for row in sorted(symbols, key=lambda r: (str(r.get("module", "")), str(r.get("symbol", "")))):
        symbol = str(row.get("symbol", ""))
        module = str(row.get("module", "unknown"))
        status = str(row.get("status", "Unknown"))
        perf_class = str(row.get("perf_class", "unknown"))

        covered = bool(fixture_cov.get(symbol, False))

        mode_records = {mode: _mode_record() for mode in MODES}

        score = _priority_score(
            {
                "status": status,
                "perf_class": perf_class,
            },
            covered,
        )

        symbol_rows.append(
            {
                "symbol": symbol,
                "module": module,
                "status": status,
                "perf_class": perf_class,
                "fixture_covered": covered,
                "capture_priority_score": score,
                "baseline": mode_records,
                "shared_overhead_reference": shared_ref,
            }
        )

        st = status_breakdown[status]
        st["total"] += 1
        if covered:
            st["fixture_covered"] += 1
        else:
            st["fixture_uncovered"] += 1
        if perf_class == HOT_PERF_CLASS:
            st["strict_hotpath"] += 1

        module_row = module_breakdown.setdefault(
            module,
            {
                "module": module,
                "total": 0,
                "fixture_covered": 0,
                "fixture_uncovered": 0,
                "strict_hotpath": 0,
                "status_breakdown": defaultdict(int),
            },
        )
        module_row["total"] += 1
        if covered:
            module_row["fixture_covered"] += 1
        else:
            module_row["fixture_uncovered"] += 1
        if perf_class == HOT_PERF_CLASS:
            module_row["strict_hotpath"] += 1
        module_row["status_breakdown"][status] += 1

    total_symbols = len(symbol_rows)
    target_symbols = sum(1 for row in symbol_rows if row["status"] in TARGET_STATUSES)
    fixture_covered = sum(1 for row in symbol_rows if row["fixture_covered"])

    measured_counts: dict[str, dict[str, int]] = {
        mode: {pct: 0 for pct in PERCENTILES} for mode in MODES
    }
    for row in symbol_rows:
        baseline = row["baseline"]
        for mode in MODES:
            mode_row = baseline[mode]
            if mode_row["p50_ns"] is not None:
                measured_counts[mode]["p50"] += 1
            if mode_row["p95_ns"] is not None:
                measured_counts[mode]["p95"] += 1
            if mode_row["p99_ns"] is not None:
                measured_counts[mode]["p99"] += 1

    pending_counts: dict[str, dict[str, int]] = {
        mode: {
            pct: total_symbols - measured_counts[mode][pct] for pct in PERCENTILES
        }
        for mode in MODES
    }

    queue_rows = sorted(
        symbol_rows,
        key=lambda row: (
            -int(row["capture_priority_score"]),
            row["module"],
            row["symbol"],
        ),
    )

    capture_queue = [
        {
            "symbol": row["symbol"],
            "module": row["module"],
            "status": row["status"],
            "perf_class": row["perf_class"],
            "fixture_covered": row["fixture_covered"],
            "capture_priority_score": row["capture_priority_score"],
        }
        for row in queue_rows
    ]

    module_rows = []
    for module in sorted(module_breakdown.keys()):
        row = module_breakdown[module]
        status_row = {
            status: int(count)
            for status, count in sorted(row["status_breakdown"].items(), key=lambda item: item[0])
        }
        module_rows.append(
            {
                "module": module,
                "total": int(row["total"]),
                "fixture_covered": int(row["fixture_covered"]),
                "fixture_uncovered": int(row["fixture_uncovered"]),
                "strict_hotpath": int(row["strict_hotpath"]),
                "status_breakdown": status_row,
            }
        )

    status_rows = {
        status: {
            "total": int(info["total"]),
            "fixture_covered": int(info["fixture_covered"]),
            "fixture_uncovered": int(info["fixture_uncovered"]),
            "strict_hotpath": int(info["strict_hotpath"]),
        }
        for status, info in sorted(status_breakdown.items(), key=lambda item: item[0])
    }

    return {
        "schema_version": 1,
        "bead": "bd-3h1u.1",
        "description": (
            "Symbol-level latency baseline inventory across all exported symbols. "
            "Tracks strict/hardened/raw p50/p95/p99 capture coverage and pending gaps "
            "without fabricating measurements."
        ),
        "trace_id": TRACE_ID,
        "generated_at_utc": str(support.get("generated_at_utc", "unknown")),
        "inputs": {
            "support_matrix": support_matrix_path,
            "perf_baseline": perf_baseline_path,
            "symbol_fixture_coverage": symbol_fixture_coverage_path,
        },
        "source_baseline_snapshot": {
            "version": perf_baseline.get("version"),
            "generated_at_utc": perf_baseline.get("generated_at_utc"),
            "available_percentiles": {
                "p50": bool(perf_baseline.get("baseline_p50_ns_op")),
                "p95": bool(perf_baseline.get("baseline_p95_ns_op")),
                "p99": bool(perf_baseline.get("baseline_p99_ns_op")),
            },
        },
        "summary": {
            "total_symbols": total_symbols,
            "target_statuses": sorted(TARGET_STATUSES),
            "target_symbols": target_symbols,
            "fixture_covered_symbols": fixture_covered,
            "fixture_uncovered_symbols": total_symbols - fixture_covered,
            "mode_percentile_measured_counts": measured_counts,
            "mode_percentile_pending_counts": pending_counts,
            "strict_hotpath_symbols": sum(
                1 for row in symbol_rows if row["perf_class"] == HOT_PERF_CLASS
            ),
            "capture_queue_size": len(capture_queue),
        },
        "status_breakdown": status_rows,
        "module_breakdown": module_rows,
        "capture_queue": capture_queue,
        "symbols": symbol_rows,
        "next_actions": [
            "Wire symbol-level benchmark harnesses per ABI family and populate baseline.raw/strict/hardened p50/p95/p99 fields.",
            "Use capture_queue ordering (strict_hotpath + fixture-covered first) for deterministic wave execution.",
            "Promote pending entries to measured only with explicit source references and reproducible command logs.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic symbol latency baseline inventory artifact."
    )
    parser.add_argument(
        "--support-matrix",
        default="support_matrix.json",
        help="Path to support_matrix.json",
    )
    parser.add_argument(
        "--perf-baseline",
        default="scripts/perf_baseline.json",
        help="Path to perf baseline JSON",
    )
    parser.add_argument(
        "--symbol-fixture-coverage",
        default="tests/conformance/symbol_fixture_coverage.v1.json",
        help="Path to symbol fixture coverage artifact",
    )
    parser.add_argument(
        "--output",
        default="tests/conformance/symbol_latency_baseline.v1.json",
        help="Output artifact path",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress structured completion log line",
    )
    args = parser.parse_args()

    artifact = generate_inventory(
        support_matrix_path=args.support_matrix,
        perf_baseline_path=args.perf_baseline,
        symbol_fixture_coverage_path=args.symbol_fixture_coverage,
    )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(artifact, handle, indent=2, sort_keys=True)
        handle.write("\n")

    if not args.quiet:
        print(
            json.dumps(
                {
                    "trace_id": TRACE_ID,
                    "mode": "symbol_latency_baseline_generation",
                    "symbols": artifact["summary"]["total_symbols"],
                    "fixture_covered": artifact["summary"]["fixture_covered_symbols"],
                    "artifact_ref": args.output,
                },
                separators=(",", ":"),
            )
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
