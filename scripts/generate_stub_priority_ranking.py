#!/usr/bin/env python3
"""Generate stub/call-through priority ranking artifact (bd-4ia).

Input:
- support_matrix.json
- tests/conformance/workload_matrix.json

Output:
- tests/conformance/stub_priority_ranking.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

BEAD_ID = "bd-4ia"

SEVERITY_WEIGHTS = {
    "Stub": 3.0,
    "GlibcCallThrough_hotpath": 2.0,
    "GlibcCallThrough_coldpath": 1.0,
}

IMPLEMENTATION_BEADS = {
    "dlfcn_abi": "bd-h5x.3",
    "glibc_internal_abi": "bd-h5x.3",
    "io_internal_abi": "bd-w2c3.2.1.1",
    "pthread_abi": "bd-h5x.2",
    "rpc_abi": "bd-w2c3.2",
    "stdio_abi": "bd-h5x.3",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def normalized_perf_class(status: str, raw_perf_class: Any) -> str:
    if status != "GlibcCallThrough":
        return "coldpath"
    return "strict_hotpath" if str(raw_perf_class or "").strip() == "strict_hotpath" else "coldpath"


def severity_weight(status: str, perf_class: str) -> float:
    if status == "Stub":
        return SEVERITY_WEIGHTS["Stub"]
    if perf_class == "strict_hotpath":
        return SEVERITY_WEIGHTS["GlibcCallThrough_hotpath"]
    return SEVERITY_WEIGHTS["GlibcCallThrough_coldpath"]


def quick_win_reason(module_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    candidates = [row for row in module_rows if row["symbols_remaining"] > 0]
    if not candidates:
        return None
    workloads = [row for row in candidates if row["workloads_blocked"] > 0]
    pool = workloads if workloads else candidates
    best = min(
        pool,
        key=lambda row: (
            row["symbols_remaining"],
            -row["workloads_blocked"],
            row["module"],
        ),
    )
    reason = (
        "Smallest remaining non-implemented module with direct workload impact."
        if best["workloads_blocked"] > 0
        else "Smallest remaining non-implemented module by symbol count."
    )
    return {"module": best["module"], "reason": reason}


def build_payload(support_matrix_path: Path, workload_matrix_path: Path) -> dict[str, Any]:
    matrix = load_json(support_matrix_path)
    workload_matrix = load_json(workload_matrix_path)

    subsystem_impact = workload_matrix.get("subsystem_impact", {})
    workloads_by_module = {
        module: int(info.get("blocked_workloads", 0))
        for module, info in subsystem_impact.items()
        if module != "description" and isinstance(info, dict)
    }

    symbol_rows: list[dict[str, Any]] = []
    module_counts: dict[str, int] = defaultdict(int)
    for row in matrix.get("symbols", []):
        status = str(row.get("status", ""))
        if status not in {"Stub", "GlibcCallThrough"}:
            continue
        symbol = str(row.get("symbol", ""))
        module = str(row.get("module", "") or "unknown")
        perf_class = normalized_perf_class(status, row.get("perf_class"))
        score = severity_weight(status, perf_class) * float(workloads_by_module.get(module, 0))
        symbol_rows.append(
            {
                "symbol": symbol,
                "module": module,
                "status": status,
                "perf_class": perf_class,
                "score": score,
            }
        )
        module_counts[module] += 1

    symbol_rows.sort(key=lambda row: (-row["score"], row["module"], row["symbol"]))

    tiers = [
        {
            "tier": "T1_critical",
            "criteria": "status == Stub",
            "description": "Stub symbols returning error/no-op. Blocks workload functionality entirely.",
            "symbols": [row for row in symbol_rows if row["status"] == "Stub"],
        },
        {
            "tier": "T2_hotpath",
            "criteria": "status == GlibcCallThrough AND perf_class == strict_hotpath",
            "description": "Hotpath callthroughs defeating safety membrane on performance-critical paths.",
            "symbols": [
                row
                for row in symbol_rows
                if row["status"] == "GlibcCallThrough" and row["perf_class"] == "strict_hotpath"
            ],
        },
        {
            "tier": "T3_coldpath",
            "criteria": "status == GlibcCallThrough AND perf_class == coldpath",
            "description": "Coldpath callthroughs. Functional passthrough, no safety membrane coverage.",
            "symbols": [
                row
                for row in symbol_rows
                if row["status"] == "GlibcCallThrough" and row["perf_class"] == "coldpath"
            ],
        },
    ]
    for tier in tiers:
        tier["count"] = len(tier["symbols"])

    module_rows: list[dict[str, Any]] = []
    for module, count in sorted(module_counts.items()):
        workloads_blocked = workloads_by_module.get(module, 0)
        module_symbol_rows = [row for row in symbol_rows if row["module"] == module]
        has_stub = any(row["status"] == "Stub" for row in module_symbol_rows)
        perf_class = (
            "strict_hotpath"
            if any(row["perf_class"] == "strict_hotpath" for row in module_symbol_rows)
            else "coldpath"
        )
        status = "Stub" if has_stub else "GlibcCallThrough"
        per_symbol_score = severity_weight(status, perf_class) * float(workloads_blocked)
        module_rows.append(
            {
                "module": module,
                "symbols_remaining": count,
                "status": status,
                "perf_class": perf_class,
                "severity_weight": per_symbol_score / float(workloads_blocked)
                if workloads_blocked
                else severity_weight(status, perf_class),
                "workloads_blocked": workloads_blocked,
                "per_symbol_score": per_symbol_score,
                "total_urgency": sum(row["score"] for row in module_symbol_rows),
                "implementation_bead": IMPLEMENTATION_BEADS.get(module),
                "note": "Auto-generated from support_matrix/workload_matrix.",
            }
        )

    module_rows.sort(key=lambda row: (-row["total_urgency"], row["module"]))
    for rank, row in enumerate(module_rows, start=1):
        row["rank"] = rank

    by_status_counter = Counter(row["status"] for row in symbol_rows)
    by_perf_counter = Counter(row["perf_class"] for row in symbol_rows)

    wave_plan = []
    for index, row in enumerate(module_rows, start=1):
        wave_plan.append(
            {
                "wave": index,
                "bead": row["implementation_bead"],
                "module": row["module"],
                "scope": "non-implemented surface remediation",
                "symbols": row["symbols_remaining"],
                "status": "unscheduled",
            }
        )

    top_symbol = symbol_rows[0] if symbol_rows else None
    top_module = module_rows[0] if module_rows else None
    quick_win = quick_win_reason(module_rows)

    return {
        "schema_version": 1,
        "bead": BEAD_ID,
        "description": "Stub priority ranking for frankenlibc remediation. Ranks non-implemented symbols (Stub + GlibcCallThrough) by severity and workload impact to guide implementation priority. Auto-generated from support_matrix/workload_matrix.",
        "scoring": {
            "description": "Per-symbol priority score combining status severity and workload impact.",
            "formula": "score = severity_weight * workloads_blocked",
            "severity_weights": {
                "Stub": {
                    "weight": SEVERITY_WEIGHTS["Stub"],
                    "rationale": "Returns error or no-op. Binary cannot function if this symbol is critical.",
                },
                "GlibcCallThrough_hotpath": {
                    "weight": SEVERITY_WEIGHTS["GlibcCallThrough_hotpath"],
                    "rationale": "Passes through to host glibc on strict_hotpath. Performance-critical, defeats safety membrane purpose.",
                },
                "GlibcCallThrough_coldpath": {
                    "weight": SEVERITY_WEIGHTS["GlibcCallThrough_coldpath"],
                    "rationale": "Passes through to host glibc on coldpath. Functional but no safety membrane coverage.",
                },
            },
            "workloads_blocked_source": "tests/conformance/workload_matrix.json subsystem_impact",
        },
        "module_ranking": {
            "description": "Modules ranked by total remediation urgency (sum of per-symbol scores).",
            "entries": module_rows,
        },
        "symbol_ranking": {
            "description": f"All {len(symbol_rows)} non-implemented symbols ranked by priority score (severity_weight * workloads_blocked). Higher score = implement first.",
            "tiers": tiers,
        },
        "burn_down": {
            "description": "Burn-down tracking for stub/callthrough remediation waves.",
            "total_non_implemented": len(symbol_rows),
            "by_status": {
                "Stub": by_status_counter.get("Stub", 0),
                "GlibcCallThrough": by_status_counter.get("GlibcCallThrough", 0),
            },
            "by_perf_class": {
                "strict_hotpath": by_perf_counter.get("strict_hotpath", 0),
                "coldpath": by_perf_counter.get("coldpath", 0),
            },
            "wave_plan": wave_plan,
            "waves_in_progress": 0,
            "symbols_in_progress": 0,
            "symbols_planned": 0,
            "symbols_unscheduled": len(symbol_rows),
        },
        "summary": {
            "total_non_implemented": len(symbol_rows),
            "stubs": by_status_counter.get("Stub", 0),
            "callthroughs": by_status_counter.get("GlibcCallThrough", 0),
            "modules_affected": len(module_rows),
            "tier_counts": {tier["tier"]: tier["count"] for tier in tiers},
            "highest_per_symbol_score": (
                {"symbol": top_symbol["symbol"], "score": top_symbol["score"]}
                if top_symbol
                else None
            ),
            "highest_total_urgency": (
                {"module": top_module["module"], "urgency": top_module["total_urgency"]}
                if top_module
                else None
            ),
            "most_impactful_quick_win": quick_win,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--support-matrix",
        type=Path,
        default=Path("support_matrix.json"),
    )
    parser.add_argument(
        "--workload-matrix",
        type=Path,
        default=Path("tests/conformance/workload_matrix.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tests/conformance/stub_priority_ranking.json"),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the output file does not match freshly generated content.",
    )
    args = parser.parse_args()

    payload = build_payload(args.support_matrix, args.workload_matrix)
    rendered = json.dumps(payload, indent=2) + "\n"

    if args.check:
        existing = args.output.read_text(encoding="utf-8")
        if canonical_json(json.loads(existing)) != canonical_json(payload):
            print(
                f"FAIL: {args.output} is stale. Regenerate with:\n"
                f"  {Path(sys.argv[0]).resolve()} --support-matrix {args.support_matrix} "
                f"--workload-matrix {args.workload_matrix} --output {args.output}",
                file=sys.stderr,
            )
            return 1
        return 0

    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
