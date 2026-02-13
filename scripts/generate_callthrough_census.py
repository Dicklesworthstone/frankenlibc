#!/usr/bin/env python3
"""Generate callthrough census + decommission sequencing artifact (bd-7ef9).

Input: support_matrix.json
Output: tests/conformance/callthrough_census.v1.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

RUNTIME_IMPACT_WEIGHTS = {
    "strict_hotpath": 5,
    "hardened_hotpath": 3,
    "coldpath": 1,
}

REPLACEMENT_COMPLEXITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


def runtime_impact_class(perf_class: str) -> str:
    weight = RUNTIME_IMPACT_WEIGHTS.get(perf_class, 2)
    if weight >= 5:
        return "high"
    if weight >= 3:
        return "medium"
    return "low"


def replacement_complexity(symbol: str, module: str) -> str:
    if module == "pthread_abi":
        if symbol in {"pthread_self", "pthread_equal"}:
            return "low"
        if symbol.startswith("pthread_cond_") or symbol.startswith("pthread_rwlock_"):
            return "medium"
        return "high"
    if module == "dlfcn_abi":
        return "medium"
    if module == "stdio_abi":
        return "high"
    return "medium"


def priority_score(perf_class: str, complexity: str) -> int:
    impact = RUNTIME_IMPACT_WEIGHTS.get(perf_class, 2)
    complexity_cost = REPLACEMENT_COMPLEXITY_WEIGHTS[complexity]
    return impact * 100 - complexity_cost * 10


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _wave(
    wave_number: int,
    wave_id: str,
    title: str,
    symbols: list[str],
    depends_on: list[str],
    rollback: str,
    rationale: str,
) -> dict[str, Any]:
    return {
        "wave": wave_number,
        "wave_id": wave_id,
        "title": title,
        "depends_on": depends_on,
        "symbols": sorted(symbols),
        "rationale": rationale,
        "rollback_strategy": rollback,
    }


def build_decommission_waves(symbol_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    symbol_by_name = {row["symbol"]: row for row in symbol_rows}
    remaining = set(symbol_by_name.keys())
    waves: list[dict[str, Any]] = []
    wave_id_order: list[str] = []

    def add_wave(
        wave_id: str,
        title: str,
        picked: set[str],
        depends_on: list[str],
        rationale: str,
        rollback: str,
    ) -> None:
        nonlocal waves, wave_id_order, remaining
        chosen = sorted(picked & remaining)
        if not chosen:
            return
        wave_number = len(waves) + 1
        waves.append(
            _wave(
                wave_number,
                wave_id,
                title,
                chosen,
                depends_on,
                rollback,
                rationale,
            )
        )
        wave_id_order.append(wave_id)
        remaining -= set(chosen)

    pthread_low = {
        sym
        for sym, row in symbol_by_name.items()
        if row["module"] == "pthread_abi" and row["replacement_complexity"] == "low"
    }
    pthread_medium = {
        sym
        for sym, row in symbol_by_name.items()
        if row["module"] == "pthread_abi" and row["replacement_complexity"] == "medium"
    }
    pthread_high = {
        sym
        for sym, row in symbol_by_name.items()
        if row["module"] == "pthread_abi" and row["replacement_complexity"] == "high"
    }
    dlfcn = {sym for sym, row in symbol_by_name.items() if row["module"] == "dlfcn_abi"}
    stdio = {sym for sym, row in symbol_by_name.items() if row["module"] == "stdio_abi"}

    add_wave(
        "pthread-foundation",
        "Pthread foundation primitives (low complexity)",
        pthread_low,
        [],
        "Low-complexity, high-impact thread identity calls unblock later synchronization work.",
        "Revert to host passthrough for foundation symbols only; keep remaining waves untouched.",
    )
    add_wave(
        "pthread-synchronization",
        "Pthread condvar/rwlock synchronization surface",
        pthread_medium,
        ["pthread-foundation"],
        "Synchronization primitives carry strict-hotpath impact with bounded state-machine scope.",
        "Rollback to host-backed cond/rwlock while retaining foundation replacements.",
    )
    add_wave(
        "pthread-lifecycle",
        "Pthread lifecycle operations (create/join/detach)",
        pthread_high,
        ["pthread-synchronization"],
        "Lifecycle transitions are highest complexity and depend on prior synchronization correctness.",
        "Disable native lifecycle path behind routing flag and fall back to host calls.",
    )
    add_wave(
        "loader-boundary",
        "dlfcn boundary migration",
        dlfcn,
        ["pthread-foundation"],
        "Loader boundary is coldpath but security-sensitive; migrate after core thread identity stability.",
        "Re-enable host dlfcn call-through via module-scoped routing switch.",
    )
    add_wave(
        "stdio-surface",
        "stdio callthrough surface consolidation",
        stdio,
        ["pthread-lifecycle", "loader-boundary"],
        "Largest callthrough surface; schedule last to avoid masking independent high-risk migrations.",
        "Rollback by restoring stdio family call-through while keeping completed non-stdio waves.",
    )

    if remaining:
        by_module: dict[str, list[str]] = defaultdict(list)
        for symbol in sorted(remaining):
            by_module[symbol_by_name[symbol]["module"]].append(symbol)
        for module in sorted(by_module):
            fallback_id = f"fallback-{module}"
            add_wave(
                fallback_id,
                f"Fallback migration wave for {module}",
                set(by_module[module]),
                wave_id_order[-1:] if wave_id_order else [],
                "Covers residual callthrough symbols not matched by primary module sequencing.",
                f"Rollback by restoring {module} call-through routing table entries.",
            )

    return waves


def build_payload(support_matrix_path: Path) -> dict[str, Any]:
    matrix = _load_json(support_matrix_path)
    symbols = matrix.get("symbols", [])
    callthrough_rows = [row for row in symbols if row.get("status") == "GlibcCallThrough"]

    symbol_rows = []
    for row in callthrough_rows:
        symbol = str(row.get("symbol", ""))
        module = str(row.get("module", ""))
        perf_class = str(row.get("perf_class", "coldpath"))
        complexity = replacement_complexity(symbol, module)
        symbol_rows.append(
            {
                "symbol": symbol,
                "module": module,
                "perf_class": perf_class,
                "runtime_impact": runtime_impact_class(perf_class),
                "replacement_complexity": complexity,
                "priority_score": priority_score(perf_class, complexity),
            }
        )

    symbol_rows.sort(
        key=lambda row: (
            -row["priority_score"],
            row["module"],
            row["symbol"],
        )
    )

    by_module: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in symbol_rows:
        by_module[row["module"]].append(row)

    module_rows = []
    for module, rows in by_module.items():
        perf_counts = Counter(row["perf_class"] for row in rows)
        complexity_counts = Counter(row["replacement_complexity"] for row in rows)
        avg_complexity_weight = sum(
            REPLACEMENT_COMPLEXITY_WEIGHTS[row["replacement_complexity"]] for row in rows
        ) / len(rows)
        total_impact_weight = sum(
            RUNTIME_IMPACT_WEIGHTS.get(row["perf_class"], 2) for row in rows
        )
        module_rows.append(
            {
                "module": module,
                "count": len(rows),
                "strict_hotpath_count": int(perf_counts.get("strict_hotpath", 0)),
                "hardened_hotpath_count": int(perf_counts.get("hardened_hotpath", 0)),
                "coldpath_count": int(perf_counts.get("coldpath", 0)),
                "runtime_impact_weight": total_impact_weight,
                "avg_complexity_weight": round(avg_complexity_weight, 2),
                "complexity_mix": {
                    "low": int(complexity_counts.get("low", 0)),
                    "medium": int(complexity_counts.get("medium", 0)),
                    "high": int(complexity_counts.get("high", 0)),
                },
            }
        )

    module_rows.sort(
        key=lambda row: (
            -row["runtime_impact_weight"],
            row["avg_complexity_weight"],
            row["module"],
        )
    )
    for index, row in enumerate(module_rows, 1):
        row["runtime_impact_rank"] = index

    waves = build_decommission_waves(symbol_rows)

    summary_counts = matrix.get("summary", {})
    status_summary_callthrough = int(summary_counts.get("GlibcCallThrough", 0))
    symbol_count = len(symbol_rows)
    strict_hotpath_count = sum(1 for row in symbol_rows if row["perf_class"] == "strict_hotpath")
    coldpath_count = sum(1 for row in symbol_rows if row["perf_class"] == "coldpath")

    payload = {
        "schema_version": "v1",
        "bead": "bd-7ef9",
        "description": "Current glibc callthrough census from support_matrix plus dependency-aware decommission sequencing.",
        "source": {
            "support_matrix_path": support_matrix_path.as_posix(),
            "support_matrix_sha256": _sha256(support_matrix_path),
            "total_exported": int(matrix.get("total_exported", 0)),
            "status_summary_callthrough": status_summary_callthrough,
            "derived_callthrough_symbols": symbol_count,
            "summary_delta": status_summary_callthrough - symbol_count,
        },
        "ranking_policy": {
            "runtime_impact_weights": RUNTIME_IMPACT_WEIGHTS,
            "replacement_complexity_weights": REPLACEMENT_COMPLEXITY_WEIGHTS,
            "priority_formula": "priority_score = runtime_impact_weight(perf_class)*100 - replacement_complexity_weight*10",
        },
        "module_census": module_rows,
        "symbol_census": symbol_rows,
        "decommission_waves": waves,
        "summary": {
            "module_count": len(module_rows),
            "symbol_count": symbol_count,
            "strict_hotpath_count": strict_hotpath_count,
            "coldpath_count": coldpath_count,
            "wave_count": len(waves),
        },
    }
    return payload


def _json_canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--support-matrix",
        type=Path,
        default=Path("support_matrix.json"),
        help="Path to support_matrix.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tests/conformance/callthrough_census.v1.json"),
        help="Output artifact path",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check mode: fail if existing output differs from generated payload",
    )
    args = parser.parse_args()

    payload = build_payload(args.support_matrix)

    if args.check:
        if not args.output.exists():
            print(f"FAIL: missing artifact {args.output}")
            return 1
        existing = _load_json(args.output)
        if _json_canonical(existing) != _json_canonical(payload):
            print(f"FAIL: {args.output} is stale. Regenerate with:")
            print(
                f"  {Path(__file__).as_posix()} --support-matrix {args.support_matrix.as_posix()} --output {args.output.as_posix()}"
            )
            return 1
        print(
            "PASS: callthrough census artifact is current "
            f"(symbols={payload['summary']['symbol_count']}, modules={payload['summary']['module_count']}, waves={payload['summary']['wave_count']})"
        )
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        f"Wrote {args.output} "
        f"(symbols={payload['summary']['symbol_count']}, modules={payload['summary']['module_count']}, waves={payload['summary']['wave_count']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
