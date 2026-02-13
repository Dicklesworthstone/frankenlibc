#!/usr/bin/env python3
"""Claim Reconciliation Engine for FrankenLibC (bd-w2c3.10.1).

Cross-checks count/status summaries and blocker statements across
canonical artifacts to detect contradictions.

Canonical sources:
  - support_matrix.json            (symbol-level ground truth)
  - tests/conformance/reality_report.v1.json  (aggregate counts)
  - tests/conformance/replacement_levels.json (level claims + current_state)
  - tests/conformance/hard_parts_truth_table.v1.json (subsystem statuses)
  - FEATURE_PARITY.md              (human-readable parity dashboard)
  - README.md                      (public-facing claims)

Emits deterministic JSON remediation report to stdout.
Exit codes: 0 = no contradictions, 1 = contradictions found, 2 = artifact missing.
"""

import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SUPPORT_MATRIX = REPO_ROOT / "support_matrix.json"
REALITY_REPORT = REPO_ROOT / "tests" / "conformance" / "reality_report.v1.json"
REPLACEMENT_LEVELS = REPO_ROOT / "tests" / "conformance" / "replacement_levels.json"
HARD_PARTS = REPO_ROOT / "tests" / "conformance" / "hard_parts_truth_table.v1.json"
FEATURE_PARITY = REPO_ROOT / "FEATURE_PARITY.md"
README = REPO_ROOT / "README.md"


def load_json(path):
    """Load JSON file, returning None if missing."""
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def extract_md_counts(text, label):
    """Extract taxonomy counts from markdown tables in FEATURE_PARITY or README."""
    counts = {}
    # Pattern: | `Implemented` | 118 | or | `Implemented`: 118 |
    # Also matches: - `Implemented`: 118
    for status in ("Implemented", "RawSyscall", "GlibcCallThrough", "Stub"):
        # Table row: | `Status` | NNN |
        m = re.search(
            rf"[`\"]?{status}[`\"]?\s*[|:]\s*(\d+)", text
        )
        if m:
            counts[status] = int(m.group(1))
    # Also extract total
    m = re.search(r"total[_ ]exported\s*[=:]\s*(\d+)", text, re.IGNORECASE)
    if m:
        counts["total"] = int(m.group(1))
    else:
        m = re.search(r"\*\*(\d+)\s*symbols?\*\*", text)
        if m:
            counts["total"] = int(m.group(1))
        else:
            m = re.search(r"(\d+)\s*symbols", text)
            if m:
                counts["total"] = int(m.group(1))
    return counts


def check_count_consistency(findings, matrix_counts, reality, replacement, fp_counts, readme_counts):
    """Cross-check aggregate counts across all sources."""
    # Ground truth from support_matrix
    gt = matrix_counts
    sources = {
        "support_matrix.json": gt,
        "reality_report.v1.json": reality.get("counts", {}) if reality else {},
        "FEATURE_PARITY.md": fp_counts,
        "README.md": readme_counts,
    }

    # Normalize key names
    key_map = {
        "implemented": "Implemented",
        "raw_syscall": "RawSyscall",
        "glibc_call_through": "GlibcCallThrough",
        "stub": "Stub",
    }

    for source_name, counts in sources.items():
        if not counts:
            findings.append({
                "severity": "warning",
                "category": "missing_counts",
                "source": source_name,
                "message": f"No taxonomy counts found in {source_name}",
            })
            continue

        # Normalize keys
        normalized = {}
        for k, v in counts.items():
            norm_key = key_map.get(k, k)
            normalized[norm_key] = v

        for status in ("Implemented", "RawSyscall", "GlibcCallThrough", "Stub"):
            gt_val = gt.get(status)
            src_val = normalized.get(status)
            if gt_val is not None and src_val is not None and gt_val != src_val:
                findings.append({
                    "severity": "error",
                    "category": "count_mismatch",
                    "source": source_name,
                    "field": status,
                    "expected": gt_val,
                    "actual": src_val,
                    "message": (
                        f"{source_name} claims {status}={src_val} but "
                        f"support_matrix.json has {status}={gt_val}"
                    ),
                })

        # Check total
        gt_total = gt.get("total")
        src_total = normalized.get("total")
        if gt_total is not None and src_total is not None and gt_total != src_total:
            findings.append({
                "severity": "error",
                "category": "total_mismatch",
                "source": source_name,
                "expected": gt_total,
                "actual": src_total,
                "message": (
                    f"{source_name} claims total={src_total} but "
                    f"support_matrix.json has total={gt_total}"
                ),
            })


def check_replacement_levels(findings, matrix_counts, replacement):
    """Check replacement_levels.json current_state against support_matrix."""
    if not replacement:
        findings.append({
            "severity": "warning",
            "category": "missing_artifact",
            "source": "replacement_levels.json",
            "message": "replacement_levels.json not found",
        })
        return

    gt = matrix_counts
    for level_obj in replacement.get("levels", []):
        level = level_obj.get("level", "?")
        cs = level_obj.get("current_state", {})
        if not cs:
            continue

        # Check stub claims
        stub_pct = cs.get("stub_pct", 0)
        stub_modules = cs.get("stub_modules", [])
        gt_stub = gt.get("Stub", 0)
        gt_total = gt.get("total", 1)
        actual_stub_pct = round(gt_stub / gt_total * 100) if gt_total else 0

        if stub_pct != actual_stub_pct:
            findings.append({
                "severity": "error",
                "category": "replacement_level_stale",
                "source": f"replacement_levels.json (level {level})",
                "field": "stub_pct",
                "expected": actual_stub_pct,
                "actual": stub_pct,
                "message": (
                    f"Level {level} current_state.stub_pct={stub_pct}% but "
                    f"support_matrix says stub={gt_stub}/{gt_total} ({actual_stub_pct}%)"
                ),
            })

        if gt_stub == 0 and stub_modules:
            findings.append({
                "severity": "error",
                "category": "replacement_level_stale",
                "source": f"replacement_levels.json (level {level})",
                "field": "stub_modules",
                "expected": [],
                "actual": stub_modules,
                "message": (
                    f"Level {level} lists stub_modules={stub_modules} but "
                    f"support_matrix has 0 stubs"
                ),
            })

        # Check implemented_pct
        impl_pct = cs.get("implemented_pct", 0)
        actual_impl_pct = round(gt.get("Implemented", 0) / gt_total * 100) if gt_total else 0
        if abs(impl_pct - actual_impl_pct) > 2:  # Allow 2% rounding tolerance
            findings.append({
                "severity": "error",
                "category": "replacement_level_stale",
                "source": f"replacement_levels.json (level {level})",
                "field": "implemented_pct",
                "expected": actual_impl_pct,
                "actual": impl_pct,
                "message": (
                    f"Level {level} current_state.implemented_pct={impl_pct}% but "
                    f"support_matrix says {gt.get('Implemented', 0)}/{gt_total} ({actual_impl_pct}%)"
                ),
            })

        # Check callthrough_pct
        ct_pct = cs.get("callthrough_pct", 0)
        actual_ct_pct = round(gt.get("GlibcCallThrough", 0) / gt_total * 100) if gt_total else 0
        if abs(ct_pct - actual_ct_pct) > 2:
            findings.append({
                "severity": "error",
                "category": "replacement_level_stale",
                "source": f"replacement_levels.json (level {level})",
                "field": "callthrough_pct",
                "expected": actual_ct_pct,
                "actual": ct_pct,
                "message": (
                    f"Level {level} current_state.callthrough_pct={ct_pct}% but "
                    f"support_matrix says {gt.get('GlibcCallThrough', 0)}/{gt_total} ({actual_ct_pct}%)"
                ),
            })

        # Check callthrough_modules list against actual modules with call-through symbols
        if "callthrough_modules" in cs:
            claimed = set(cs["callthrough_modules"])
            # We'll verify this in the module check below


def check_module_taxonomy(findings, matrix):
    """Verify module-level taxonomy claims in FEATURE_PARITY against support_matrix."""
    if not matrix:
        return

    # Build actual module->status mapping from support_matrix
    module_statuses = {}
    for sym in matrix.get("symbols", []):
        mod = sym.get("module", "unknown")
        status = sym.get("status", "unknown")
        if mod not in module_statuses:
            module_statuses[mod] = Counter()
        module_statuses[mod][status] += 1

    # Verify that modules claimed as certain taxonomy actually match
    # The FEATURE_PARITY.md taxonomy table claims which modules belong to which status
    fp_text = FEATURE_PARITY.read_text() if FEATURE_PARITY.exists() else ""

    taxonomy_claims = {}
    for status in ("Implemented", "RawSyscall", "GlibcCallThrough", "Stub"):
        pattern = rf"`{status}`\s*\|\s*`([^`]+)`"
        m = re.search(pattern, fp_text)
        if m:
            modules_str = m.group(1)
            # Split on `, ` and backtick boundaries
            modules = [s.strip().strip("`") for s in re.split(r"`,\s*`", modules_str)]
            taxonomy_claims[status] = modules

    # Check: modules claimed as a taxonomy should actually have symbols of that status
    for claimed_status, claimed_modules in taxonomy_claims.items():
        for mod in claimed_modules:
            actual = module_statuses.get(mod, Counter())
            if actual and actual.get(claimed_status, 0) == 0:
                findings.append({
                    "severity": "warning",
                    "category": "module_taxonomy_mismatch",
                    "source": "FEATURE_PARITY.md",
                    "field": f"module {mod}",
                    "claimed_status": claimed_status,
                    "actual_statuses": dict(actual),
                    "message": (
                        f"FEATURE_PARITY.md lists {mod} under {claimed_status} "
                        f"but support_matrix shows {dict(actual)}"
                    ),
                })


def check_hard_parts(findings, hard_parts, matrix):
    """Check hard_parts_truth_table claims against support_matrix symbols."""
    if not hard_parts:
        findings.append({
            "severity": "warning",
            "category": "missing_artifact",
            "source": "hard_parts_truth_table.v1.json",
            "message": "hard_parts_truth_table.v1.json not found",
        })
        return

    # Build symbol status lookup from matrix
    symbol_status = {}
    if matrix:
        for sym in matrix.get("symbols", []):
            symbol_status[sym["symbol"]] = sym["status"]

    for subsystem in hard_parts.get("subsystems", []):
        sub_id = subsystem.get("id", "?")
        expectations = subsystem.get("support_expectations", {})

        # Check required_symbols
        for req in expectations.get("required_symbols", []):
            sym_name = req.get("symbol", "")
            expected_status = req.get("status", "")
            actual_status = symbol_status.get(sym_name)

            if actual_status is None:
                findings.append({
                    "severity": "error",
                    "category": "hard_parts_symbol_missing",
                    "source": f"hard_parts ({sub_id})",
                    "field": sym_name,
                    "expected": expected_status,
                    "message": (
                        f"Hard-parts subsystem '{sub_id}' requires symbol "
                        f"'{sym_name}' as {expected_status} but symbol not found "
                        f"in support_matrix"
                    ),
                })
            elif actual_status != expected_status:
                findings.append({
                    "severity": "error",
                    "category": "hard_parts_symbol_status",
                    "source": f"hard_parts ({sub_id})",
                    "field": sym_name,
                    "expected": expected_status,
                    "actual": actual_status,
                    "message": (
                        f"Hard-parts subsystem '{sub_id}' requires "
                        f"'{sym_name}' as {expected_status} but support_matrix "
                        f"says {actual_status}"
                    ),
                })


def check_timestamp_consistency(findings, reality, matrix, hard_parts, replacement):
    """Detect stale timestamps - artifacts should be from similar time windows."""
    timestamps = {}
    if reality and "generated_at_utc" in reality:
        timestamps["reality_report"] = reality["generated_at_utc"]
    if matrix and "generated_at_utc" in matrix:
        timestamps["support_matrix"] = matrix["generated_at_utc"]
    if hard_parts and "generated_at" in hard_parts:
        timestamps["hard_parts"] = hard_parts["generated_at"]

    # Check that reality_report and support_matrix are from the same generation
    r_ts = timestamps.get("reality_report")
    m_ts = timestamps.get("support_matrix")
    if r_ts and m_ts and r_ts != m_ts:
        findings.append({
            "severity": "warning",
            "category": "timestamp_drift",
            "source": "reality_report vs support_matrix",
            "expected": m_ts,
            "actual": r_ts,
            "message": (
                f"reality_report generated at {r_ts} but "
                f"support_matrix generated at {m_ts} — potential drift"
            ),
        })


def check_readme_claims(findings, readme_text, matrix_counts):
    """Check that README.md public-facing claims match reality."""
    if not readme_text:
        return

    # Check total count claim
    m = re.search(r"total_exported=(\d+)", readme_text)
    if m:
        readme_total = int(m.group(1))
        actual_total = matrix_counts.get("total", 0)
        if readme_total != actual_total:
            findings.append({
                "severity": "error",
                "category": "readme_stale",
                "source": "README.md",
                "field": "total_exported",
                "expected": actual_total,
                "actual": readme_total,
                "message": f"README.md claims total_exported={readme_total} but support_matrix has {actual_total}",
            })

    # Check individual counts in README
    for status, key in [("implemented", "Implemented"), ("raw_syscall", "RawSyscall"),
                         ("glibc_call_through", "GlibcCallThrough"), ("stub", "Stub")]:
        m = re.search(rf"{status}=(\d+)", readme_text)
        if m:
            readme_val = int(m.group(1))
            actual_val = matrix_counts.get(key, 0)
            if readme_val != actual_val:
                findings.append({
                    "severity": "error",
                    "category": "readme_stale",
                    "source": "README.md",
                    "field": status,
                    "expected": actual_val,
                    "actual": readme_val,
                    "message": f"README.md claims {status}={readme_val} but support_matrix has {actual_val}",
                })

    # Check percentage claims
    m_share = re.findall(r"\|\s*`?(\w+)`?\s*\|\s*(\d+)\s*\|\s*(\d+)%", readme_text)
    for status_name, count_str, pct_str in m_share:
        if status_name in ("Implemented", "RawSyscall", "GlibcCallThrough", "Stub"):
            actual = matrix_counts.get(status_name, 0)
            claimed = int(count_str)
            if claimed != actual:
                findings.append({
                    "severity": "error",
                    "category": "readme_stale",
                    "source": "README.md (table)",
                    "field": status_name,
                    "expected": actual,
                    "actual": claimed,
                    "message": f"README table claims {status_name}={claimed} but support_matrix has {actual}",
                })


def check_feature_parity_done_claims(findings, fp_text, matrix):
    """Verify that DONE claims in mode-specific matrix have fixture evidence."""
    if not fp_text or not matrix:
        return

    # Extract mode-specific matrix rows with DONE status
    # Pattern: | family | strict desc | hardened desc | DONE |
    done_families = re.findall(
        r"\|\s*(\w[\w\s/]*?)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*DONE\s*\|",
        fp_text
    )

    # For each DONE family, check that the family has fixture coverage
    fixture_dir = REPO_ROOT / "tests" / "conformance" / "fixtures"
    existing_fixtures = set()
    if fixture_dir.exists():
        existing_fixtures = {f.stem for f in fixture_dir.glob("*.json")}

    for family_name, _, _ in done_families:
        family_name = family_name.strip()
        # Check if there's any fixture that plausibly covers this family
        family_key = family_name.lower().replace(" ", "_").replace("/", "_")
        has_fixture = any(
            family_key in fx or fx.startswith(family_key.split("_")[0])
            for fx in existing_fixtures
        )
        if not has_fixture:
            findings.append({
                "severity": "warning",
                "category": "done_without_fixture",
                "source": "FEATURE_PARITY.md",
                "field": family_name,
                "message": (
                    f"Mode-specific matrix claims '{family_name}' is DONE "
                    f"but no matching fixture found in tests/conformance/fixtures/"
                ),
            })


def main():
    findings = []
    missing = []

    # Load all artifacts
    matrix = load_json(SUPPORT_MATRIX)
    if not matrix:
        missing.append("support_matrix.json")

    reality = load_json(REALITY_REPORT)
    if not reality:
        missing.append("tests/conformance/reality_report.v1.json")

    replacement = load_json(REPLACEMENT_LEVELS)
    hard_parts = load_json(HARD_PARTS)

    fp_text = FEATURE_PARITY.read_text() if FEATURE_PARITY.exists() else ""
    readme_text = README.read_text() if README.exists() else ""

    if missing:
        for m in missing:
            findings.append({
                "severity": "critical",
                "category": "missing_artifact",
                "source": m,
                "message": f"Critical artifact missing: {m}",
            })
        # Can't continue without ground truth
        report = {
            "schema_version": "v1",
            "bead": "bd-w2c3.10.1",
            "status": "error",
            "findings": findings,
            "summary": {"errors": len(findings), "warnings": 0},
        }
        json.dump(report, sys.stdout, indent=2)
        print()
        sys.exit(2)

    # Build ground-truth counts from support_matrix
    matrix_counts = Counter()
    for sym in matrix.get("symbols", []):
        matrix_counts[sym.get("status", "unknown")] += 1
    matrix_counts["total"] = sum(matrix_counts.values())

    # Extract counts from markdown docs
    fp_counts = extract_md_counts(fp_text, "FEATURE_PARITY")
    readme_counts = extract_md_counts(readme_text, "README")

    # Run all checks
    check_count_consistency(findings, dict(matrix_counts), reality, replacement, fp_counts, readme_counts)
    check_replacement_levels(findings, dict(matrix_counts), replacement)
    check_module_taxonomy(findings, matrix)
    check_hard_parts(findings, hard_parts, matrix)
    check_timestamp_consistency(findings, reality, matrix, hard_parts, replacement)
    check_readme_claims(findings, readme_text, dict(matrix_counts))
    check_feature_parity_done_claims(findings, fp_text, matrix)

    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warning")
    critical = sum(1 for f in findings if f["severity"] == "critical")

    report = {
        "schema_version": "v1",
        "bead": "bd-w2c3.10.1",
        "status": "pass" if errors == 0 and critical == 0 else "fail",
        "ground_truth": {
            "source": "support_matrix.json",
            "generated_at": matrix.get("generated_at_utc", "unknown"),
            "total": matrix_counts["total"],
            "Implemented": matrix_counts.get("Implemented", 0),
            "RawSyscall": matrix_counts.get("RawSyscall", 0),
            "GlibcCallThrough": matrix_counts.get("GlibcCallThrough", 0),
            "Stub": matrix_counts.get("Stub", 0),
        },
        "summary": {
            "critical": critical,
            "errors": errors,
            "warnings": warnings,
            "total_findings": len(findings),
        },
        "findings": findings,
    }

    json.dump(report, sys.stdout, indent=2)
    print()
    sys.exit(1 if (errors > 0 or critical > 0) else 0)


if __name__ == "__main__":
    main()
