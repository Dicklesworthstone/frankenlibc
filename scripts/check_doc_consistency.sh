#!/usr/bin/env bash
# check_doc_consistency.sh — RC-WS4.5: Doc-vs-artifact consistency gate.
#
# Verifies user-facing claim docs agree with machine artifacts.
# Two document classes:
#   - LIVE-CLAIM docs: README.md, DEPLOYMENT.md, FEATURE_PARITY.md, SECURITY.md
#     Their factual claims MUST match freshly regenerated artifacts.
#   - PLANNING docs: PLAN_TO_PORT_GLIBC_TO_RUST.md, PROPOSED_ARCHITECTURE.md,
#     REALITY_CHECK_BRIDGE_PLAN.md. These are aspirational/historical and must
#     carry a header declaring them planning artifacts.
#
# Exit codes:
#   0 - All checks pass
#   1 - Consistency failures found
#   2 - Script error
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPORT="${FRANKENLIBC_DOC_CONSISTENCY_REPORT:-$ROOT/target/conformance/doc_consistency.report.json}"
TRACE_ID="doc-consistency-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "$(dirname "$REPORT")"

python3 - "$ROOT" "$REPORT" "$TRACE_ID" <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
REPORT_PATH = pathlib.Path(sys.argv[2])
TRACE_ID = sys.argv[3]

REPORT_SCHEMA = "doc_consistency.v1"

LIVE_CLAIM_DOCS = [
    "README.md",
    "DEPLOYMENT.md",
    "FEATURE_PARITY.md",
    # "SECURITY.md",  # Optional - check if exists
]

PLANNING_DOCS = [
    "PLAN_TO_PORT_GLIBC_TO_RUST.md",
    "PROPOSED_ARCHITECTURE.md",
    "REALITY_CHECK_BRIDGE_PLAN.md",
]

PLANNING_HEADER_PATTERNS = [
    r"planning\s*(artifact|document)",
    r"aspirational",
    r"point.in.time",
    r"design\s*document",
    r"roadmap",
    r"(generated|created)\s*\d{4}",
]

findings: list[dict[str, Any]] = []
checks: list[dict[str, Any]] = []


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "unknown"


def load_json(path: pathlib.Path) -> dict[str, Any] | list | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def read_doc(name: str) -> str:
    path = ROOT / name
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def extract_claims_from_doc(content: str) -> dict[str, Any]:
    """Extract factual claims from doc content."""
    claims = {}

    # Replacement level
    m = re.search(r"(?:current.*?release|replacement.*?level|declared.*?level)[^`]*`?L(\d)`?", content, re.I)
    if m:
        claims["replacement_level"] = f"L{m.group(1)}"

    # Symbol counts
    m = re.search(r"(\d{1,5})\s*(?:exported\s*)?symbols?\s*(?:classified|all)", content, re.I)
    if m:
        claims["total_symbols"] = int(m.group(1))

    m = re.search(r"Implemented[:\s]*(\d{1,5})", content)
    if m:
        claims["implemented_count"] = int(m.group(1))

    m = re.search(r"RawSyscall[:\s]*(\d{1,5})", content)
    if m:
        claims["raw_syscall_count"] = int(m.group(1))

    m = re.search(r"GlibcCallThrough[:\s]*(\d+)", content)
    if m:
        claims["glibc_callthrough_count"] = int(m.group(1))

    m = re.search(r"WrapsHostLibc[:\s]*(\d+)", content)
    if m:
        claims["wraps_host_count"] = int(m.group(1))

    m = re.search(r"Stub[:\s]*(\d+)", content)
    if m:
        claims["stub_count"] = int(m.group(1))

    # Native coverage
    m = re.search(r"(\d{1,3}(?:\.\d+)?)\s*%\s*native", content, re.I)
    if m:
        claims["native_coverage_pct"] = float(m.group(1))

    return claims


def load_artifact_truth() -> dict[str, Any]:
    """Load canonical artifact values."""
    truth = {}

    # replacement_levels.json
    rl = load_json(ROOT / "tests/conformance/replacement_levels.json")
    if rl and isinstance(rl, dict):
        truth["replacement_level"] = rl.get("current_level", "unknown")

    # support_matrix.json is the canonical live support-taxonomy artifact.
    # Older reality reports are generated snapshots and can lag taxonomy
    # reclassification work, so use them only as a compatibility fallback.
    sm = load_json(ROOT / "support_matrix.json")
    if sm and isinstance(sm, dict):
        symbols = sm.get("symbols", [])
        if isinstance(symbols, list):
            counts = {
                "Implemented": 0,
                "RawSyscall": 0,
                "GlibcCallThrough": 0,
                "WrapsHostLibc": 0,
                "Stub": 0,
            }
            for symbol in symbols:
                if not isinstance(symbol, dict):
                    continue
                status = symbol.get("status")
                if status in counts:
                    counts[status] += 1
            truth["total_symbols"] = len(symbols)
            truth["implemented_count"] = counts["Implemented"]
            truth["raw_syscall_count"] = counts["RawSyscall"]
            truth["glibc_callthrough_count"] = counts["GlibcCallThrough"]
            truth["wraps_host_count"] = counts["WrapsHostLibc"]
            truth["stub_count"] = counts["Stub"]

    if "total_symbols" not in truth:
        rr = load_json(ROOT / "tests/conformance/reality_report.v1.json")
        if rr and isinstance(rr, dict):
            truth["total_symbols"] = rr.get("total_exported", 0)
            counts = rr.get("counts", rr)
            truth["implemented_count"] = counts.get("implemented", 0)
            truth["raw_syscall_count"] = counts.get("raw_syscall", 0)
            truth["glibc_callthrough_count"] = counts.get("glibc_call_through", 0)
            truth["wraps_host_count"] = counts.get("wraps_host_libc", 0)
            truth["stub_count"] = counts.get("stub", 0)

    # Compute native coverage
    impl = truth.get("implemented_count", 0)
    raw = truth.get("raw_syscall_count", 0)
    total = truth.get("total_symbols", 0)
    if total > 0:
        truth["native_coverage_pct"] = round((impl + raw) / total * 100, 1)

    return truth


def check_live_claim_doc(name: str, truth: dict[str, Any]) -> None:
    content = read_doc(name)
    if not content:
        findings.append({
            "type": "missing_doc",
            "doc": name,
            "severity": "warning",
            "message": f"Live-claim doc {name} not found",
        })
        checks.append({"doc": name, "outcome": "missing"})
        return

    claims = extract_claims_from_doc(content)
    doc_findings = []

    for key, doc_val in claims.items():
        if key in truth:
            truth_val = truth[key]
            if doc_val != truth_val:
                doc_findings.append({
                    "claim": key,
                    "doc_value": doc_val,
                    "artifact_value": truth_val,
                    "mismatch": True,
                })
                findings.append({
                    "type": "claim_mismatch",
                    "doc": name,
                    "claim": key,
                    "doc_value": doc_val,
                    "artifact_value": truth_val,
                    "severity": "error",
                })

    outcome = "pass" if not doc_findings else "mismatch"
    checks.append({
        "doc": name,
        "doc_class": "live-claim",
        "outcome": outcome,
        "claims_checked": list(claims.keys()),
        "mismatches": doc_findings,
    })


def check_planning_doc(name: str) -> None:
    content = read_doc(name)
    if not content:
        findings.append({
            "type": "missing_doc",
            "doc": name,
            "severity": "warning",
            "message": f"Planning doc {name} not found",
        })
        checks.append({"doc": name, "outcome": "missing"})
        return

    # Check first 500 chars for planning header
    header = content[:500].lower()
    has_planning_header = any(
        re.search(pattern, header, re.I) for pattern in PLANNING_HEADER_PATTERNS
    )

    if not has_planning_header:
        findings.append({
            "type": "missing_planning_header",
            "doc": name,
            "severity": "warning",
            "message": f"Planning doc {name} lacks planning-artifact header in first 500 chars",
        })
        checks.append({
            "doc": name,
            "doc_class": "planning",
            "outcome": "missing_header",
        })
    else:
        checks.append({
            "doc": name,
            "doc_class": "planning",
            "outcome": "pass",
        })


def main() -> int:
    timestamp = now_utc()
    commit = git_head()

    truth = load_artifact_truth()

    # Check live-claim docs
    for doc in LIVE_CLAIM_DOCS:
        check_live_claim_doc(doc, truth)

    # Check planning docs
    for doc in PLANNING_DOCS:
        check_planning_doc(doc)

    errors = [f for f in findings if f.get("severity") == "error"]
    warnings = [f for f in findings if f.get("severity") == "warning"]

    outcome = "pass" if not errors else "fail"
    exit_code = 0 if not errors else 1

    report = {
        "schema_version": REPORT_SCHEMA,
        "generated_at_utc": timestamp,
        "source_commit": commit,
        "trace_id": TRACE_ID,
        "outcome": outcome,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "artifact_truth": truth,
        "checks": checks,
        "findings": findings,
        "manifest": {
            "live_claim_docs": LIVE_CLAIM_DOCS,
            "planning_docs": PLANNING_DOCS,
        },
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    # Output summary
    print("=== Doc Consistency Gate ===")
    print(f"Trace ID: {TRACE_ID}")
    print()
    print(f"Live-claim docs checked: {len(LIVE_CLAIM_DOCS)}")
    print(f"Planning docs checked: {len(PLANNING_DOCS)}")
    print()

    for check in checks:
        status = "PASS" if check["outcome"] == "pass" else "FAIL" if check["outcome"] == "mismatch" else "WARN"
        print(f"  [{status}] {check['doc']}")
        if check.get("mismatches"):
            for m in check["mismatches"]:
                print(f"       {m['claim']}: doc={m['doc_value']} artifact={m['artifact_value']}")

    print()
    if errors:
        print(f"FAILED: {len(errors)} error(s)")
        for e in errors:
            print(f"  - {e['doc']}: {e.get('claim', e.get('message', 'unknown'))}")
    else:
        print("PASSED: All live-claim docs consistent with artifacts")

    if warnings:
        print(f"Warnings: {len(warnings)}")

    print()
    print(f"Report: {REPORT_PATH}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
PY
