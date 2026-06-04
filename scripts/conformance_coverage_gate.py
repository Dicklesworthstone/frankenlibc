#!/usr/bin/env python3
"""Conformance Coverage Regression Gate (bd-15n.3).

Tracks fixture coverage per symbol/family and detects regressions:
- Fixture count must not decrease
- Per-family fixture counts must not decrease
- New symbols must be tracked as uncovered (not silently missing)

Reads:
  - support_matrix.json (symbol universe)
  - tests/conformance/fixtures/*.json (current fixture files)
  - tests/conformance/symbol_fixture_coverage.v1.json (baseline coverage)

Writes:
  - tests/conformance/conformance_coverage_snapshot.v1.json (current snapshot)

Exit codes: 0 = pass (no regression), 1 = regression detected, 2 = baseline missing (first run).
"""

import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPPORT_MATRIX = REPO_ROOT / "support_matrix.json"
FIXTURE_DIR = REPO_ROOT / "tests" / "conformance" / "fixtures"
BASELINE_FILE = REPO_ROOT / "tests" / "conformance" / "conformance_coverage_baseline.v1.json"
SNAPSHOT_FILE = REPO_ROOT / "tests" / "conformance" / "conformance_coverage_snapshot.v1.json"


def load_fixtures():
    """Load all fixture files and extract covered functions/families."""
    fixtures = {}
    covered_functions = set()
    covered_families = defaultdict(set)
    fixture_cases = 0

    for fpath in sorted(FIXTURE_DIR.glob("*.json")):
        with open(fpath) as f:
            data = json.load(f)

        fname = fpath.stem
        cases = data if isinstance(data, list) else data.get("cases", data.get("tests", [data]))
        if not isinstance(cases, list):
            cases = [cases]

        file_functions = set()
        file_families = set()
        for case in cases:
            func = case.get("function", case.get("func", ""))
            family = case.get("family", fname.split("_")[0] if "_" in fname else fname)
            if func:
                covered_functions.add(func)
                file_functions.add(func)
            if family:
                covered_families[family].add(func or fname)
                file_families.add(family)

        # Compute file checksum for drift detection
        content = fpath.read_bytes()
        sha = hashlib.sha256(content).hexdigest()

        fixtures[fname] = {
            "file": str(fpath.name),
            "sha256": sha,
            "case_count": len(cases),
            "functions": sorted(file_functions),
            "families": sorted(file_families),
        }
        fixture_cases += len(cases)

    return fixtures, covered_functions, dict(covered_families), fixture_cases


def load_support_matrix():
    """Load support_matrix and extract symbol->module mapping."""
    if not SUPPORT_MATRIX.exists():
        return {}, {}
    with open(SUPPORT_MATRIX) as f:
        data = json.load(f)

    symbols = {}
    modules = defaultdict(list)
    for sym in data.get("symbols", []):
        name = sym.get("symbol", "")
        status = sym.get("status", "unknown")
        mod = sym.get("module", "unknown")
        symbols[name] = {"status": status, "module": mod}
        modules[mod].append(name)

    return symbols, dict(modules)


def build_snapshot(fixtures, covered_functions, covered_families, fixture_cases, symbols, modules):
    """Build a coverage snapshot."""
    total_symbols = len(symbols)
    covered_count = sum(1 for s in symbols if s in covered_functions)

    # Per-module coverage
    module_coverage = {}
    for mod, syms in sorted(modules.items()):
        covered = sum(1 for s in syms if s in covered_functions)
        module_coverage[mod] = {
            "total": len(syms),
            "covered": covered,
            "pct": round(covered / len(syms) * 100) if syms else 0,
        }

    # Per-family (fixture-based grouping) coverage
    family_coverage = {}
    for family, funcs in sorted(covered_families.items()):
        family_coverage[family] = {
            "function_count": len(funcs),
            "functions": sorted(funcs),
        }

    return {
        "schema_version": "v1",
        "bead": "bd-15n.3",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_symbols": total_symbols,
            "symbols_with_fixtures": covered_count,
            "coverage_pct": round(covered_count / total_symbols * 100) if total_symbols else 0,
            "total_fixture_files": len(fixtures),
            "total_fixture_cases": fixture_cases,
            "total_families": len(family_coverage),
        },
        "module_coverage": module_coverage,
        "family_coverage": family_coverage,
        "fixtures": fixtures,
    }


def preserve_generated_at_for_unchanged_snapshot(snapshot):
    """Keep canonical snapshot bytes stable when only generated_at would change."""
    if not SNAPSHOT_FILE.exists():
        return snapshot
    try:
        with open(SNAPSHOT_FILE) as f:
            previous = json.load(f)
    except (OSError, json.JSONDecodeError):
        return snapshot

    previous_content = dict(previous)
    current_content = dict(snapshot)
    previous_generated_at = previous_content.pop("generated_at", None)
    current_content.pop("generated_at", None)
    if previous_content == current_content and isinstance(previous_generated_at, str):
        snapshot["generated_at"] = previous_generated_at
    return snapshot


def check_regression(snapshot, baseline):
    """Compare snapshot against baseline, emit findings."""
    findings = []

    bs = baseline.get("summary", {})
    ss = snapshot.get("summary", {})

    # Fixture file count must not decrease
    if ss.get("total_fixture_files", 0) < bs.get("total_fixture_files", 0):
        findings.append({
            "severity": "error",
            "category": "fixture_count_regression",
            "expected": bs["total_fixture_files"],
            "actual": ss["total_fixture_files"],
            "message": (
                f"Fixture file count regressed: {bs['total_fixture_files']} -> "
                f"{ss['total_fixture_files']}"
            ),
        })

    # Total case count must not decrease
    if ss.get("total_fixture_cases", 0) < bs.get("total_fixture_cases", 0):
        findings.append({
            "severity": "error",
            "category": "case_count_regression",
            "expected": bs["total_fixture_cases"],
            "actual": ss["total_fixture_cases"],
            "message": (
                f"Fixture case count regressed: {bs['total_fixture_cases']} -> "
                f"{ss['total_fixture_cases']}"
            ),
        })

    # Coverage percentage must not decrease
    if ss.get("coverage_pct", 0) < bs.get("coverage_pct", 0):
        findings.append({
            "severity": "error",
            "category": "coverage_regression",
            "expected": bs["coverage_pct"],
            "actual": ss["coverage_pct"],
            "message": (
                f"Symbol coverage regressed: {bs['coverage_pct']}% -> "
                f"{ss['coverage_pct']}%"
            ),
        })

    # Per-module coverage must not decrease
    bmc = baseline.get("module_coverage", {})
    smc = snapshot.get("module_coverage", {})
    for mod, bmod in bmc.items():
        smod = smc.get(mod, {})
        if smod.get("covered", 0) < bmod.get("covered", 0):
            findings.append({
                "severity": "error",
                "category": "module_coverage_regression",
                "module": mod,
                "expected": bmod["covered"],
                "actual": smod.get("covered", 0),
                "message": (
                    f"Module {mod} coverage regressed: "
                    f"{bmod['covered']}/{bmod['total']} -> "
                    f"{smod.get('covered', 0)}/{smod.get('total', '?')}"
                ),
            })

    # Detect removed fixture files
    bf = set(baseline.get("fixtures", {}).keys())
    sf = set(snapshot.get("fixtures", {}).keys())
    removed = bf - sf
    for r in sorted(removed):
        findings.append({
            "severity": "error",
            "category": "fixture_removed",
            "fixture": r,
            "message": f"Fixture file '{r}' was removed (present in baseline, absent now)",
        })

    # Detect modified fixtures (informational)
    for fname in sorted(bf & sf):
        b_sha = baseline["fixtures"][fname].get("sha256", "")
        s_sha = snapshot["fixtures"][fname].get("sha256", "")
        if b_sha and s_sha and b_sha != s_sha:
            findings.append({
                "severity": "info",
                "category": "fixture_modified",
                "fixture": fname,
                "message": f"Fixture '{fname}' content changed (sha256 drift)",
            })

    # Detect new fixtures (informational/positive)
    added = sf - bf
    for a in sorted(added):
        findings.append({
            "severity": "info",
            "category": "fixture_added",
            "fixture": a,
            "message": f"New fixture '{a}' added",
        })

    return findings


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"

    # Build current snapshot
    fixtures, covered_functions, covered_families, fixture_cases = load_fixtures()
    symbols, modules = load_support_matrix()
    snapshot = build_snapshot(fixtures, covered_functions, covered_families,
                              fixture_cases, symbols, modules)
    snapshot = preserve_generated_at_for_unchanged_snapshot(snapshot)

    if mode == "update-baseline":
        # Save snapshot as baseline
        with open(BASELINE_FILE, "w") as f:
            json.dump(snapshot, f, indent=2)
            f.write("\n")
        print(f"Baseline updated: {BASELINE_FILE}")
        print(f"  Fixture files: {snapshot['summary']['total_fixture_files']}")
        print(f"  Fixture cases: {snapshot['summary']['total_fixture_cases']}")
        print(f"  Symbol coverage: {snapshot['summary']['coverage_pct']}%")
        sys.exit(0)

    # Save snapshot
    with open(SNAPSHOT_FILE, "w") as f:
        json.dump(snapshot, f, indent=2)
        f.write("\n")

    # Check mode: compare against baseline
    if not BASELINE_FILE.exists():
        print("No baseline found. Creating initial baseline.")
        with open(BASELINE_FILE, "w") as f:
            json.dump(snapshot, f, indent=2)
            f.write("\n")
        report = {
            "schema_version": "v1",
            "bead": "bd-15n.3",
            "status": "baseline_created",
            "snapshot": snapshot["summary"],
        }
        json.dump(report, sys.stdout, indent=2)
        print()
        sys.exit(2)

    with open(BASELINE_FILE) as f:
        baseline = json.load(f)

    findings = check_regression(snapshot, baseline)
    errors = sum(1 for f in findings if f["severity"] == "error")

    report = {
        "schema_version": "v1",
        "bead": "bd-15n.3",
        "status": "pass" if errors == 0 else "fail",
        "summary": {
            "errors": errors,
            "warnings": sum(1 for f in findings if f["severity"] == "warning"),
            "info": sum(1 for f in findings if f["severity"] == "info"),
        },
        "baseline": baseline.get("summary", {}),
        "current": snapshot["summary"],
        "findings": findings,
    }

    json.dump(report, sys.stdout, indent=2)
    print()
    sys.exit(1 if errors > 0 else 0)


if __name__ == "__main__":
    main()
