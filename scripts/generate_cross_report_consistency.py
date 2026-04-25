#!/usr/bin/env python3
"""generate_cross_report_consistency.py — bd-2vv.11

Cross-report consistency gate for support/reality/replacement claims:
  1. Symbol count consistency — verify totals match across all reports.
  2. Status distribution — verify classification counts are aligned.
  3. Replacement level gates — verify current level satisfies its criteria.
  4. Claim-to-reality alignment — check replacement_profile vs support_matrix.
  5. Drift detection — flag inconsistencies that would block release.

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
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_first_json(paths):
    """Load the first existing JSON file from an ordered list of paths."""
    for path in paths:
        loaded = load_json_file(path)
        if loaded is not None:
            return loaded, path
    return None, None


# Severity levels for findings
SEVERITY_CRITICAL = "critical"
SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"


def check_symbol_count_consistency(support_matrix, reality_report, replacement_levels):
    """Rule 1: Symbol totals must match across reports."""
    findings = []

    sm_total = support_matrix.get("total_exported", 0)
    sm_symbols = len(support_matrix.get("symbols", []))

    # support_matrix total_exported vs actual symbol count
    if sm_total != sm_symbols:
        findings.append({
            "rule": "symbol_count_internal",
            "severity": SEVERITY_ERROR,
            "report_pair": "support_matrix (total_exported vs symbols array)",
            "expected": sm_total,
            "actual": sm_symbols,
            "affected_symbols": [],
            "verdict": "fail",
            "description": f"support_matrix total_exported ({sm_total}) != "
                           f"symbols array length ({sm_symbols})",
        })

    # reality_report total
    if reality_report:
        rr_total = reality_report.get("total_exported", 0)
        if rr_total != sm_total:
            findings.append({
                "rule": "symbol_count_cross",
                "severity": SEVERITY_ERROR,
                "report_pair": "support_matrix vs reality_report",
                "expected": sm_total,
                "actual": rr_total,
                "affected_symbols": [],
                "verdict": "fail",
                "description": f"support_matrix total ({sm_total}) != "
                               f"reality_report total ({rr_total})",
            })

    # replacement_levels total
    if replacement_levels:
        rl_assess = replacement_levels.get("current_assessment", {})
        rl_total = rl_assess.get("total_symbols", 0)
        if rl_total != sm_total:
            findings.append({
                "rule": "symbol_count_cross",
                "severity": SEVERITY_ERROR,
                "report_pair": "support_matrix vs replacement_levels",
                "expected": sm_total,
                "actual": rl_total,
                "affected_symbols": [],
                "verdict": "fail",
                "description": f"support_matrix total ({sm_total}) != "
                               f"replacement_levels total ({rl_total})",
            })

    if not findings:
        findings.append({
            "rule": "symbol_count",
            "severity": SEVERITY_INFO,
            "report_pair": "all",
            "verdict": "pass",
            "description": f"All reports agree on {sm_total} symbols",
        })

    return findings


def check_status_distribution(support_matrix, reality_report, replacement_levels):
    """Rule 2: Status counts must be consistent."""
    findings = []

    # Compute counts from support_matrix
    sm_counts = defaultdict(int)
    for sym in support_matrix.get("symbols", []):
        status = sym.get("status", "Unknown")
        sm_counts[status] += 1

    # Check reality_report counts
    if reality_report:
        rr_counts = reality_report.get("counts", {})
        status_map = {
            "Implemented": "implemented",
            "RawSyscall": "raw_syscall",
            "GlibcCallThrough": "glibc_call_through",
            "Stub": "stub",
        }
        for sm_status, rr_key in status_map.items():
            sm_val = sm_counts.get(sm_status, 0)
            rr_val = rr_counts.get(rr_key, 0)
            if sm_val != rr_val:
                findings.append({
                    "rule": "status_distribution",
                    "severity": SEVERITY_WARNING,
                    "report_pair": "support_matrix vs reality_report",
                    "expected": sm_val,
                    "actual": rr_val,
                    "affected_symbols": [],
                    "verdict": "drift",
                    "description": f"Status '{sm_status}': support_matrix={sm_val}, "
                                   f"reality_report={rr_val}",
                })

    # Check replacement_levels assessment
    if replacement_levels:
        rl_assess = replacement_levels.get("current_assessment", {})
        rl_map = {
            "Implemented": "implemented",
            "RawSyscall": "raw_syscall",
            "GlibcCallThrough": "callthrough",
            "Stub": "stub",
        }
        for sm_status, rl_key in rl_map.items():
            sm_val = sm_counts.get(sm_status, 0)
            rl_val = rl_assess.get(rl_key, 0)
            if sm_val != rl_val:
                findings.append({
                    "rule": "status_distribution",
                    "severity": SEVERITY_WARNING,
                    "report_pair": "support_matrix vs replacement_levels",
                    "expected": sm_val,
                    "actual": rl_val,
                    "affected_symbols": [],
                    "verdict": "drift",
                    "description": f"Status '{sm_status}': support_matrix={sm_val}, "
                                   f"replacement_levels={rl_val}",
                })

    if not findings:
        findings.append({
            "rule": "status_distribution",
            "severity": SEVERITY_INFO,
            "report_pair": "all",
            "verdict": "pass",
            "description": "Status distributions consistent across reports",
        })

    return findings


def check_level_gates(replacement_levels, support_matrix):
    """Rule 3: Current level must satisfy its own gate criteria."""
    findings = []

    if not replacement_levels:
        findings.append({
            "rule": "level_gates",
            "severity": SEVERITY_WARNING,
            "verdict": "skip",
            "description": "replacement_levels.json not found",
        })
        return findings

    current_level = replacement_levels.get("current_level", "")
    levels = replacement_levels.get("levels", [])
    assess = replacement_levels.get("current_assessment", {})

    total = assess.get("total_symbols", 1)
    impl_count = assess.get("implemented", 0)
    callthrough = assess.get("callthrough", 0)
    stub = assess.get("stub", 0)

    impl_pct = round(impl_count / total * 100, 1) if total else 0
    ct_pct = round(callthrough / total * 100, 1) if total else 0
    stub_pct = round(stub / total * 100, 1) if total else 0

    for level in levels:
        level_name = level.get("name", "")
        if level_name != current_level:
            continue

        gate = level.get("gate", {})
        max_ct = gate.get("max_callthrough_pct", 100)
        max_stub = gate.get("max_stub_pct", 100)
        min_impl = gate.get("min_implemented_pct", 0)

        if ct_pct > max_ct:
            findings.append({
                "rule": "level_gate_callthrough",
                "severity": SEVERITY_ERROR,
                "verdict": "fail",
                "description": f"Level {current_level}: callthrough {ct_pct}% "
                               f"> max {max_ct}%",
            })
        if stub_pct > max_stub:
            findings.append({
                "rule": "level_gate_stub",
                "severity": SEVERITY_ERROR,
                "verdict": "fail",
                "description": f"Level {current_level}: stub {stub_pct}% "
                               f"> max {max_stub}%",
            })
        if impl_pct < min_impl:
            findings.append({
                "rule": "level_gate_implemented",
                "severity": SEVERITY_ERROR,
                "verdict": "fail",
                "description": f"Level {current_level}: implemented {impl_pct}% "
                               f"< min {min_impl}%",
            })

        if not findings:
            findings.append({
                "rule": "level_gates",
                "severity": SEVERITY_INFO,
                "verdict": "pass",
                "description": f"Level {current_level} gate criteria satisfied "
                               f"(impl={impl_pct}%, ct={ct_pct}%, stub={stub_pct}%)",
            })
        break

    return findings


def check_claim_alignment(support_matrix, replacement_profile, stub_census):
    """Rule 4: Claims must align with reality."""
    findings = []

    # Build symbol status lookup
    sm_lookup = {}
    for sym in support_matrix.get("symbols", []):
        sm_lookup[sym.get("symbol", "")] = sym.get("status", "")

    # Check stub_census inconsistencies
    if stub_census:
        inconsistencies = stub_census.get("inconsistencies", [])
        for inc in inconsistencies:
            symbol = inc.get("symbol", "")
            severity_val = inc.get("severity", "medium")
            sev = SEVERITY_ERROR if severity_val == "high" else SEVERITY_WARNING
            findings.append({
                "rule": "claim_alignment",
                "severity": sev,
                "report_pair": "support_matrix vs stub_census",
                "affected_symbols": [symbol],
                "verdict": "inconsistent",
                "description": inc.get("description",
                                       f"Symbol {symbol}: classification mismatch"),
            })

    # Check replacement_profile call-through census
    if replacement_profile:
        census = replacement_profile.get("call_through_census", {})
        for module, count in census.items():
            if not isinstance(count, int):
                continue
            # Count actual callthrough symbols in this module from support_matrix
            actual_ct = sum(
                1 for sym in support_matrix.get("symbols", [])
                if sym.get("module") == module
                and sym.get("status") == "GlibcCallThrough"
            )
            if actual_ct != count and count > 0:
                # Only flag significant mismatches
                diff = abs(actual_ct - count)
                if diff > 0:
                    findings.append({
                        "rule": "census_alignment",
                        "severity": SEVERITY_WARNING,
                        "report_pair": "support_matrix vs replacement_profile",
                        "affected_symbols": [],
                        "verdict": "drift",
                        "description": f"Module {module}: support_matrix has "
                                       f"{actual_ct} callthrough, profile census "
                                       f"claims {count}",
                    })

    if not findings:
        findings.append({
            "rule": "claim_alignment",
            "severity": SEVERITY_INFO,
            "verdict": "pass",
            "description": "All claims align with reality",
        })

    return findings


def check_no_unknown_symbols(support_matrix):
    """Rule 5: No symbols with unknown/ambiguous status in declared tiers."""
    findings = []
    valid_statuses = {
        "Implemented",
        "RawSyscall",
        "WrapsHostLibc",
        "GlibcCallThrough",
        "Stub",
    }

    unknown_symbols = []
    for sym in support_matrix.get("symbols", []):
        name = sym.get("symbol", "")
        status = sym.get("status", "")
        if status not in valid_statuses:
            unknown_symbols.append(name)

    if unknown_symbols:
        findings.append({
            "rule": "no_unknown_status",
            "severity": SEVERITY_CRITICAL,
            "affected_symbols": unknown_symbols,
            "verdict": "fail",
            "description": f"{len(unknown_symbols)} symbols with unknown status",
        })
    else:
        findings.append({
            "rule": "no_unknown_status",
            "severity": SEVERITY_INFO,
            "verdict": "pass",
            "description": "All symbols have valid status classification",
        })

    return findings


def compute_consistency_hash(findings):
    """Deterministic hash of findings for reproducibility check."""
    canonical = json.dumps(
        [(f["rule"], f["verdict"]) for f in findings],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def main():
    parser = argparse.ArgumentParser(
        description="Cross-report consistency gate")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()

    # Load all reports
    support_matrix = load_json_file(root / "support_matrix.json")
    if not support_matrix:
        print("ERROR: support_matrix.json not found", file=sys.stderr)
        sys.exit(1)

    reality_report = load_json_file(
        root / "tests" / "conformance" / "reality_report.v1.json")
    replacement_levels = load_json_file(
        root / "tests" / "conformance" / "replacement_levels.json")
    replacement_profile = load_json_file(
        root / "tests" / "conformance" / "replacement_profile.json")
    stub_census, stub_census_path = load_first_json([
        root / "tests" / "conformance" / "stub_census.json",
    ])

    # Run all consistency checks
    all_findings = []
    all_findings.extend(
        check_symbol_count_consistency(support_matrix, reality_report,
                                       replacement_levels))
    all_findings.extend(
        check_status_distribution(support_matrix, reality_report,
                                  replacement_levels))
    all_findings.extend(
        check_level_gates(replacement_levels, support_matrix))
    all_findings.extend(
        check_claim_alignment(support_matrix, replacement_profile, stub_census))
    all_findings.extend(
        check_no_unknown_symbols(support_matrix))

    # Compute summary
    by_severity = defaultdict(int)
    by_verdict = defaultdict(int)
    for f in all_findings:
        by_severity[f.get("severity", "unknown")] += 1
        by_verdict[f.get("verdict", "unknown")] += 1
    by_severity_summary = {
        severity: by_severity.get(severity, 0)
        for severity in [
            SEVERITY_CRITICAL,
            SEVERITY_ERROR,
            SEVERITY_WARNING,
            SEVERITY_INFO,
        ]
    }
    for severity in sorted(set(by_severity) - set(by_severity_summary)):
        by_severity_summary[severity] = by_severity[severity]

    # Reports loaded
    reports_loaded = {
        "support_matrix": support_matrix is not None,
        "reality_report": reality_report is not None,
        "replacement_levels": replacement_levels is not None,
        "replacement_profile": replacement_profile is not None,
        "stub_census": stub_census is not None,
    }
    report_sources = {
        "support_matrix": str(root / "support_matrix.json"),
        "reality_report": str(root / "tests" / "conformance" / "reality_report.v1.json"),
        "replacement_levels": str(root / "tests" / "conformance" / "replacement_levels.json"),
        "replacement_profile": str(root / "tests" / "conformance" / "replacement_profile.json"),
        "stub_census": str(stub_census_path) if stub_census_path else None,
    }

    overall_pass = (by_severity.get(SEVERITY_CRITICAL, 0) == 0
                    and by_severity.get(SEVERITY_ERROR, 0) == 0)

    consistency_hash = compute_consistency_hash(all_findings)

    report = {
        "schema_version": "v1",
        "bead": "bd-2vv.11",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "consistency_hash": consistency_hash,
        "summary": {
            "overall_verdict": "pass" if overall_pass else "fail",
            "total_findings": len(all_findings),
            "by_severity": by_severity_summary,
            "by_verdict": dict(sorted(by_verdict.items())),
            "reports_loaded": sum(1 for v in reports_loaded.values() if v),
            "reports_total": len(reports_loaded),
        },
        "reports_loaded": reports_loaded,
        "report_sources": report_sources,
        "findings": all_findings,
        "consistency_rules": {
            "symbol_count": "Symbol totals must match across all reports",
            "status_distribution": "Status counts must be consistent",
            "level_gates": "Current replacement level must satisfy gate criteria",
            "claim_alignment": "Claims in profiles must match support_matrix reality",
            "no_unknown_status": "No symbols with unknown/ambiguous status",
        },
        "ci_policy": {
            "critical_findings": "Block release; must be resolved",
            "error_findings": "Block CI merge; require investigation",
            "warning_findings": "Informational; track as drift",
            "info_findings": "Passing checks; no action needed",
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
