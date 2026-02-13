#!/usr/bin/env python3
"""Generate workload-ranked top-N API enablement wave plan (bd-3mam)."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PRIORITY_WEIGHTS = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
}

SEVERITY_WEIGHTS = {
    "Stub": 3.0,
    "GlibcCallThrough:strict_hotpath": 2.0,
    "GlibcCallThrough:hardened_hotpath": 1.5,
    "GlibcCallThrough:coldpath": 1.0,
}

MODULE_BEAD_OVERRIDES = {
    "stdio_abi": ["bd-24ug"],
    "pthread_abi": ["bd-z84", "bd-yos", "bd-rth1", "bd-1f35", "bd-3hud"],
    "dlfcn_abi": ["bd-3rn", "bd-33zg"],
}

INTEGRATION_HOOKS = {
    "setjmp": ["bd-1gh"],
    "tls": ["bd-rth1", "bd-yos"],
    "threading": ["bd-z84", "bd-yos", "bd-3hud", "bd-1f35"],
    "hard_parts": ["bd-24ug", "bd-3rn", "bd-66s", "bd-3pe"],
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def severity_weight(status: str, perf_class: str) -> float:
    if status == "Stub":
        return SEVERITY_WEIGHTS["Stub"]
    return SEVERITY_WEIGHTS.get(f"{status}:{perf_class}", 1.0)


def build_plan(
    workload_matrix: dict[str, Any],
    support_matrix: dict[str, Any],
    callthrough_census: dict[str, Any],
    top_n: int,
) -> dict[str, Any]:
    symbols = support_matrix.get("symbols", [])
    candidates = [
        row
        for row in symbols
        if row.get("status") in {"GlibcCallThrough", "Stub"}
    ]

    workloads = workload_matrix.get("workloads", [])
    module_workload_ids: dict[str, set[str]] = defaultdict(set)
    module_weighted_impact: dict[str, float] = defaultdict(float)
    module_critical_symbols: dict[str, Counter[str]] = defaultdict(Counter)

    for workload in workloads:
        w_id = str(workload.get("id"))
        weight = PRIORITY_WEIGHTS.get(str(workload.get("priority_impact", "medium")).lower(), 1.0)
        blocked_modules = [str(m) for m in workload.get("blocked_by", [])]
        critical_symbols = [str(s) for s in workload.get("critical_symbols", [])]
        for module in blocked_modules:
            module_workload_ids[module].add(w_id)
            module_weighted_impact[module] += weight
            for symbol in critical_symbols:
                module_critical_symbols[module][symbol] += 1

    wave_rows = callthrough_census.get("decommission_waves", [])
    symbol_to_wave: dict[str, str] = {}
    wave_by_id: dict[str, dict[str, Any]] = {}
    for wave in wave_rows:
        wave_id = str(wave.get("wave_id"))
        wave_by_id[wave_id] = wave
        for symbol in wave.get("symbols", []):
            symbol_to_wave[str(symbol)] = wave_id

    milestone_rows = workload_matrix.get("milestone_mapping", {}).get("milestones", [])
    module_to_beads: dict[str, list[str]] = defaultdict(list)
    for row in milestone_rows:
        bead = row.get("bead")
        if not bead:
            continue
        for module in row.get("unblocks_modules", []):
            module_to_beads[str(module)].append(str(bead))

    for module, beads in MODULE_BEAD_OVERRIDES.items():
        merged = list(dict.fromkeys(module_to_beads.get(module, []) + beads))
        module_to_beads[module] = merged

    symbol_rows: list[dict[str, Any]] = []
    for row in candidates:
        symbol = str(row.get("symbol"))
        module = str(row.get("module"))
        status = str(row.get("status"))
        perf_class = str(row.get("perf_class"))
        sev = severity_weight(status, perf_class)
        workload_weight = float(module_weighted_impact.get(module, 0.0))
        blocked_count = len(module_workload_ids.get(module, set()))
        critical_mentions = int(module_critical_symbols.get(module, Counter()).get(symbol, 0))
        score = round(sev * (1.0 + workload_weight + (0.5 * critical_mentions)), 3)

        symbol_rows.append(
            {
                "symbol": symbol,
                "module": module,
                "status": status,
                "perf_class": perf_class,
                "severity_weight": sev,
                "blocked_workloads": blocked_count,
                "weighted_workload_impact": round(workload_weight, 3),
                "critical_symbol_mentions": critical_mentions,
                "score": score,
                "wave_id": symbol_to_wave.get(symbol, "unplanned"),
                "recommended_beads": module_to_beads.get(module, []),
            }
        )

    symbol_rows.sort(key=lambda r: (-r["score"], r["module"], r["symbol"]))

    top_symbol_rows = []
    for rank, row in enumerate(symbol_rows[:top_n], start=1):
        entry = dict(row)
        entry["rank"] = rank
        top_symbol_rows.append(entry)

    module_scores: dict[str, dict[str, Any]] = {}
    for row in symbol_rows:
        module = row["module"]
        agg = module_scores.setdefault(
            module,
            {
                "module": module,
                "symbols_remaining": 0,
                "blocked_workloads": len(module_workload_ids.get(module, set())),
                "weighted_workload_impact": round(module_weighted_impact.get(module, 0.0), 3),
                "total_symbol_score": 0.0,
                "critical_symbol_hits": 0,
                "recommended_beads": module_to_beads.get(module, []),
            },
        )
        agg["symbols_remaining"] += 1
        agg["total_symbol_score"] = round(agg["total_symbol_score"] + row["score"], 3)
        agg["critical_symbol_hits"] += row["critical_symbol_mentions"]

    module_ranking = sorted(
        module_scores.values(),
        key=lambda r: (-r["total_symbol_score"], -r["blocked_workloads"], r["module"]),
    )
    for rank, row in enumerate(module_ranking, start=1):
        row["rank"] = rank

    wave_plan = []
    for wave in sorted(wave_rows, key=lambda w: int(w.get("wave", 0))):
        wave_id = str(wave.get("wave_id"))
        wave_symbols = [s for s in wave.get("symbols", []) if s in {r["symbol"] for r in symbol_rows}]
        scored = [r for r in symbol_rows if r["symbol"] in set(wave_symbols)]
        scored.sort(key=lambda r: (-r["score"], r["symbol"]))
        modules = sorted({r["module"] for r in scored})

        wave_plan.append(
            {
                "wave": int(wave.get("wave", 0)),
                "wave_id": wave_id,
                "title": wave.get("title"),
                "depends_on": sorted(str(dep) for dep in wave.get("depends_on", [])),
                "modules": modules,
                "symbol_count": len(scored),
                "top_symbols": [r["symbol"] for r in scored[:10]],
                "avg_score": round(sum(r["score"] for r in scored) / max(len(scored), 1), 3),
                "max_score": round(max((r["score"] for r in scored), default=0.0), 3),
                "recommended_beads": sorted(
                    {
                        bead
                        for module in modules
                        for bead in module_to_beads.get(module, [])
                    }
                ),
                "success_criteria": [
                    "target module symbols no longer classified as GlibcCallThrough/Stub in support_matrix",
                    "replacement guard emits zero forbidden call-throughs for symbols in this wave",
                    "fixture/gate artifacts updated with deterministic logs",
                ],
            }
        )

    top_blocker = module_ranking[0]["module"] if module_ranking else None

    return {
        "schema_version": "v1",
        "bead": "bd-3mam",
        "description": "Workload-ranked top-N API enablement wave plan from real workload blockers and support-matrix obligations.",
        "generated_utc": "2026-02-13T00:00:00Z",
        "inputs": {
            "workload_matrix": {
                "path": "tests/conformance/workload_matrix.json",
                "sha256": sha256_file(Path("tests/conformance/workload_matrix.json")),
            },
            "support_matrix": {
                "path": "support_matrix.json",
                "sha256": sha256_file(Path("support_matrix.json")),
            },
            "callthrough_census": {
                "path": "tests/conformance/callthrough_census.v1.json",
                "sha256": sha256_file(Path("tests/conformance/callthrough_census.v1.json")),
            },
        },
        "scoring": {
            "priority_weights": PRIORITY_WEIGHTS,
            "severity_weights": {
                "Stub": SEVERITY_WEIGHTS["Stub"],
                "GlibcCallThrough_strict_hotpath": SEVERITY_WEIGHTS["GlibcCallThrough:strict_hotpath"],
                "GlibcCallThrough_hardened_hotpath": SEVERITY_WEIGHTS["GlibcCallThrough:hardened_hotpath"],
                "GlibcCallThrough_coldpath": SEVERITY_WEIGHTS["GlibcCallThrough:coldpath"],
            },
            "formula": "score = severity_weight * (1 + weighted_workload_impact + 0.5 * critical_symbol_mentions)",
        },
        "module_ranking": module_ranking,
        "symbol_ranking_top_n": top_symbol_rows,
        "wave_plan": wave_plan,
        "integration_hooks": INTEGRATION_HOOKS,
        "summary": {
            "top_n": top_n,
            "candidate_symbols": len(symbol_rows),
            "module_count": len(module_ranking),
            "wave_count": len(wave_plan),
            "top_blocker_module": top_blocker,
            "top_symbol": top_symbol_rows[0]["symbol"] if top_symbol_rows else None,
            "baseline_unresolved_symbols": len(symbol_rows),
            "remaining_after_top_n": max(len(symbol_rows) - top_n, 0),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workload-matrix",
        default="tests/conformance/workload_matrix.json",
        type=Path,
    )
    parser.add_argument("--support-matrix", default="support_matrix.json", type=Path)
    parser.add_argument(
        "--callthrough-census",
        default="tests/conformance/callthrough_census.v1.json",
        type=Path,
    )
    parser.add_argument(
        "--output",
        default="tests/conformance/workload_api_wave_plan.v1.json",
        type=Path,
    )
    parser.add_argument("--top-n", default=25, type=int)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    workload_matrix = load_json(args.workload_matrix)
    support_matrix = load_json(args.support_matrix)
    callthrough_census = load_json(args.callthrough_census)

    plan = build_plan(
        workload_matrix=workload_matrix,
        support_matrix=support_matrix,
        callthrough_census=callthrough_census,
        top_n=args.top_n,
    )

    rendered = json.dumps(plan, indent=2, sort_keys=False) + "\n"

    if args.check:
        if not args.output.exists():
            raise SystemExit(f"ERROR: output artifact missing for --check: {args.output}")
        current = args.output.read_text(encoding="utf-8")
        if current != rendered:
            raise SystemExit(
                f"ERROR: workload API wave plan drift detected. regenerate with: {Path(__file__).name}"
            )
        print(
            "OK: workload API wave plan is up-to-date "
            f"(top_n={args.top_n}, candidates={plan['summary']['candidate_symbols']})"
        )
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(
        f"Wrote {args.output} "
        f"(top_n={args.top_n}, candidates={plan['summary']['candidate_symbols']}, waves={plan['summary']['wave_count']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
