#!/usr/bin/env python3
"""generate_symbol_tiers_roadmap.py — bd-2vv.10

Trace-weighted symbol tiers and family wave roadmap:
  1. Tiering — rank all 250 symbols by priority score into tiers (Top50/Top100/Top200/All).
  2. Wave roadmap — group symbols into implementation waves by family readiness.
  3. Acceptance checklist — mandatory requirements per wave milestone.
  4. Dependencies — inter-wave dependencies based on family coupling.

Uses bd-2vv.9 normalized symbol universe as input.
Generates a JSON report to stdout (or --output).
"""
import argparse
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def find_repo_root():
    p = Path(__file__).resolve().parent.parent
    if (p / "Cargo.toml").exists():
        return p
    return Path.cwd()


def load_json_file(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"ERROR: failed to read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ERROR: invalid JSON in {path}: {exc}") from exc


# Tier boundaries
TIER_BOUNDARIES = [
    ("top50", 50),
    ("top100", 100),
    ("top200", 200),
    ("all", 999),
]

# Wave definitions: each wave targets specific families and readiness levels
WAVE_DEFINITIONS = [
    {
        "wave": 1,
        "name": "Core Safety Surface",
        "description": "String, malloc, errno — highest-impact, lowest-complexity families "
                       "that form the foundation for safe memory operations.",
        "target_families": ["string", "malloc", "errno", "ctype"],
        "target_classification": "native",
        "rationale": "These families are called on virtually every code path and have "
                     "the highest ROI for native implementation.",
    },
    {
        "wave": 2,
        "name": "Numeric & stdlib Foundation",
        "description": "Math, stdlib, wchar — medium-complexity families needed for "
                       "numeric computing and wide-string support.",
        "target_families": ["math", "stdlib", "wchar"],
        "target_classification": "native",
        "rationale": "Widely used in scientific and text-processing workloads; "
                     "currently many symbols are native.",
    },
    {
        "wave": 3,
        "name": "Threading & Synchronization",
        "description": "Pthread family — high-complexity but critical for multi-threaded "
                       "applications.",
        "target_families": ["pthread"],
        "target_classification": "native",
        "rationale": "Thread safety is a key differentiator; migrating from GlibcCallThrough "
                     "to native eliminates host-libc dependency for concurrency.",
    },
    {
        "wave": 4,
        "name": "I/O & Networking",
        "description": "stdio, socket, unistd, poll, io, mmap — I/O-heavy families "
                       "that require syscall expertise.",
        "target_families": ["stdio", "socket", "unistd", "poll", "io", "mmap"],
        "target_classification": "native",
        "rationale": "I/O families have high symbol count and complex state; "
                     "wave 4 tackles them after safety and threading foundations are solid.",
    },
    {
        "wave": 5,
        "name": "System Integration & Remaining",
        "description": "All remaining families: process, signal, time, dirent, dlfcn, "
                       "resolv, inet, locale, iconv, grp, pwd, termios, resource, startup.",
        "target_families": [
            "process", "signal", "time", "dirent", "dlfcn", "resolv",
            "inet", "locale", "iconv", "grp", "pwd", "termios",
            "resource", "startup", "membrane",
        ],
        "target_classification": "native",
        "rationale": "Lower-frequency families needed for full glibc replacement; "
                     "completed last to minimize risk to core functionality.",
    },
]

# Wave acceptance checklist
WAVE_ACCEPTANCE_CHECKLIST = [
    {
        "requirement": "native_implementation",
        "description": "All wave symbols must be natively implemented (not host-delegated)",
        "mandatory": True,
    },
    {
        "requirement": "fixture_coverage",
        "description": "Every symbol must have at least 1 conformance fixture case",
        "mandatory": True,
    },
    {
        "requirement": "latency_budget",
        "description": "Hotpath symbols: p99 < 20ns strict, < 200ns hardened",
        "mandatory": True,
    },
    {
        "requirement": "regression_test",
        "description": "Each symbol must have regression tests in the harness",
        "mandatory": True,
    },
    {
        "requirement": "dual_mode_verification",
        "description": "Both strict and hardened modes tested for each symbol",
        "mandatory": True,
    },
    {
        "requirement": "evidence_logging",
        "description": "Structured JSONL evidence for each symbol's validation outcome",
        "mandatory": False,
    },
    {
        "requirement": "fuzz_coverage",
        "description": "Family-level fuzz target exercises the symbol (waves 1-3)",
        "mandatory": False,
    },
]


def assign_tier(rank, total):
    """Assign tier based on rank position."""
    for tier_name, boundary in TIER_BOUNDARIES:
        if rank <= boundary:
            return tier_name
    return "all"


def compute_roadmap_hash(tiers):
    """Deterministic hash for the roadmap output."""
    canonical = json.dumps(
        [(t["symbol"], t["tier"], t["wave"]) for t in tiers],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def main():
    parser = argparse.ArgumentParser(
        description="Symbol tiers and family wave roadmap generator")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    norm_path = root / "tests" / "conformance" / "symbol_universe_normalization.v1.json"

    if not norm_path.exists():
        print("ERROR: symbol_universe_normalization.v1.json not found "
              "(run bd-2vv.9 first)", file=sys.stderr)
        sys.exit(1)

    norm_data = load_json_file(norm_path)
    normalized_symbols = norm_data.get("normalized_symbols", [])

    if not normalized_symbols:
        print("ERROR: No normalized symbols found", file=sys.stderr)
        sys.exit(1)

    # Build family-to-wave mapping
    family_wave_map = {}
    for wave_def in WAVE_DEFINITIONS:
        for fam in wave_def["target_families"]:
            family_wave_map[fam] = wave_def["wave"]

    # Sort symbols by priority_score (descending) for tier assignment
    ranked = sorted(normalized_symbols,
                    key=lambda s: s["priority_score"], reverse=True)

    # Assign tiers and waves
    tiered_symbols = []
    for rank_idx, sym in enumerate(ranked):
        rank = rank_idx + 1
        tier = assign_tier(rank, len(ranked))
        wave = family_wave_map.get(sym["family"], 5)

        tiered_symbols.append({
            "symbol": sym["symbol"],
            "family": sym["family"],
            "module": sym["module"],
            "classification": sym["classification"],
            "perf_class": sym["perf_class"],
            "priority_score": sym["priority_score"],
            "rank": rank,
            "tier": tier,
            "wave": wave,
            "confidence": sym["confidence"],
            "replacement_complexity": sym["replacement_complexity"],
        })

    # Sort for output stability
    tiered_symbols.sort(key=lambda s: (s["wave"], -s["priority_score"], s["symbol"]))

    # Tier statistics
    tier_stats = defaultdict(lambda: {"count": 0, "native": 0, "symbols": []})
    for t in tiered_symbols:
        tier_stats[t["tier"]]["count"] += 1
        if t["classification"] == "native":
            tier_stats[t["tier"]]["native"] += 1
        tier_stats[t["tier"]]["symbols"].append(t["symbol"])

    # Wave statistics
    wave_stats = {}
    for wave_def in WAVE_DEFINITIONS:
        wave_num = wave_def["wave"]
        wave_syms = [t for t in tiered_symbols if t["wave"] == wave_num]
        native_count = sum(1 for s in wave_syms if s["classification"] == "native")
        families_in_wave = sorted(set(s["family"] for s in wave_syms))

        wave_stats[str(wave_num)] = {
            "name": wave_def["name"],
            "description": wave_def["description"],
            "rationale": wave_def["rationale"],
            "total_symbols": len(wave_syms),
            "native_symbols": native_count,
            "native_pct": round(native_count / len(wave_syms) * 100, 1)
            if wave_syms else 0,
            "families": families_in_wave,
            "family_count": len(families_in_wave),
            "symbols": [s["symbol"] for s in wave_syms],
            "readiness": "complete" if native_count == len(wave_syms)
            else "in-progress" if native_count > 0 else "planned",
        }

    # Family readiness per wave
    family_readiness = {}
    for t in tiered_symbols:
        fam = t["family"]
        if fam not in family_readiness:
            family_readiness[fam] = {
                "wave": t["wave"],
                "total": 0,
                "native": 0,
                "symbols": [],
            }
        family_readiness[fam]["total"] += 1
        if t["classification"] == "native":
            family_readiness[fam]["native"] += 1
        family_readiness[fam]["symbols"].append(t["symbol"])

    for fam, info in family_readiness.items():
        info["native_pct"] = round(info["native"] / info["total"] * 100, 1) \
            if info["total"] else 0
        info["readiness"] = "complete" if info["native"] == info["total"] \
            else "in-progress" if info["native"] > 0 else "planned"

    roadmap_hash = compute_roadmap_hash(tiered_symbols)

    report = {
        "schema_version": "v1",
        "bead": "bd-2vv.10",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "roadmap_hash": roadmap_hash,
        "summary": {
            "total_symbols": len(tiered_symbols),
            "tier_counts": {k: v["count"] for k, v in sorted(tier_stats.items())},
            "wave_count": len(WAVE_DEFINITIONS),
            "families_complete": sum(
                1 for f in family_readiness.values() if f["readiness"] == "complete"),
            "families_in_progress": sum(
                1 for f in family_readiness.values() if f["readiness"] == "in-progress"),
            "families_planned": sum(
                1 for f in family_readiness.values() if f["readiness"] == "planned"),
            "overall_native_pct": round(
                sum(1 for t in tiered_symbols if t["classification"] == "native")
                / len(tiered_symbols) * 100, 1
            ) if tiered_symbols else 0,
        },
        "tiered_symbols": tiered_symbols,
        "tier_statistics": {k: {"count": v["count"], "native": v["native"]}
                           for k, v in sorted(tier_stats.items())},
        "wave_roadmap": wave_stats,
        "family_readiness": {k: v for k, v in sorted(family_readiness.items())},
        "wave_acceptance_checklist": WAVE_ACCEPTANCE_CHECKLIST,
        "wave_dependencies": {
            "wave_2": ["wave_1"],
            "wave_3": ["wave_1"],
            "wave_4": ["wave_1", "wave_2", "wave_3"],
            "wave_5": ["wave_1", "wave_2", "wave_3", "wave_4"],
        },
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
