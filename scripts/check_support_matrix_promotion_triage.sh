#!/usr/bin/env bash
# check_support_matrix_promotion_triage.sh - bd-w1ro19
#
# Builds a deterministic triage manifest for support-matrix native promotions.
# The manifest is generated from the maintenance report and does not rewrite
# support_matrix.json classifications.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${FRANKENLIBC_PROMOTION_TRIAGE_OUT_DIR:-$ROOT/target/conformance}"
MAINTENANCE_REPORT="${FRANKENLIBC_PROMOTION_TRIAGE_MAINTENANCE_REPORT:-$OUT_DIR/support_matrix_maintenance.generated.json}"
REPORT="${FRANKENLIBC_PROMOTION_TRIAGE_REPORT:-$OUT_DIR/support_matrix_promotion_triage.v1.json}"
LOG="${FRANKENLIBC_PROMOTION_TRIAGE_LOG:-$OUT_DIR/support_matrix_promotion_triage.log.jsonl}"

mkdir -p "$OUT_DIR"

python3 "$ROOT/scripts/generate_support_matrix_maintenance.py" -o "$MAINTENANCE_REPORT" >/dev/null

python3 - "$ROOT" "$MAINTENANCE_REPORT" "$REPORT" "$LOG" <<'PY'
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1])
maintenance_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

ALLOWED_CATEGORIES = {
    "prove-now",
    "downgrade-now",
    "scanner-false-positive",
    "blocked-by-harness",
}

TRACE_ID = "bd-w1ro19-support-matrix-promotion-triage-v1"


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def rel(path):
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def symbol_to_module():
    matrix = load_json(ROOT / "support_matrix.json")
    return {
        str(row.get("symbol")): str(row.get("module", "unknown"))
        for row in matrix.get("symbols", [])
        if isinstance(row, dict) and row.get("symbol") is not None
    }


def issue_index(report):
    issues = defaultdict(list)
    for issue in report.get("status_validation_issues", []):
        if isinstance(issue, dict) and issue.get("symbol") is not None:
            issues[str(issue["symbol"])].append(issue)
    return issues


def all_source_files():
    roots = [
        ROOT / "crates" / "frankenlibc-abi" / "src",
        ROOT / "crates" / "frankenlibc-core" / "src",
    ]
    files = []
    for root in roots:
        if root.is_dir():
            files.extend(sorted(path for path in root.rglob("*.rs") if path.is_file()))
    files.append(ROOT / "support_matrix.json")
    return files


def candidate_files(module):
    paths = []
    if module and module != "unknown":
        paths.append(ROOT / "crates" / "frankenlibc-abi" / "src" / f"{module}.rs")
        paths.append(ROOT / "crates" / "frankenlibc-core" / "src" / f"{module}.rs")
        paths.append(ROOT / "crates" / "frankenlibc-core" / "src" / module / "mod.rs")
    seen = set()
    ordered = []
    for path in paths + all_source_files():
        if path.is_file() and path not in seen:
            ordered.append(path)
            seen.add(path)
    return ordered


def first_source_location(symbol, module):
    escaped = re.escape(symbol)
    patterns = [
        re.compile(rf"\bfn\s+{escaped}\b"),
        re.compile(rf"\b{escaped}\b"),
    ]
    for path in candidate_files(module):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for idx, line in enumerate(lines, start=1):
            if any(pattern.search(line) for pattern in patterns):
                start = max(0, idx - 1)
                end = min(len(lines), idx + 18)
                context = "\n".join(lines[start:end])
                return {
                    "path": rel(path),
                    "line": idx,
                    "snippet": line.strip(),
                    "context": context,
                }
    return {
        "path": None,
        "line": None,
        "snippet": None,
        "context": "",
    }


def source_traits(location):
    text = (location.get("context") or "").lower()
    return {
        "has_native_syscall": any(
            token in text
            for token in [
                "raw_syscall::",
                "syscall::sys_",
                "native syscall",
                "native via",
                "linux syscall",
            ]
        ),
        "has_host_delegation": any(
            token in text
            for token in [
                "host libc",
                "libc::",
                "dlsym",
                "dlopen",
                "resolve_host",
                "call_host",
            ]
        ),
    }


def validation_command(category, symbol):
    if category == "blocked-by-harness":
        return "bash scripts/check_symbol_fixture_coverage.sh && bash scripts/check_per_symbol_fixture_tests.sh --validate-only"
    if category == "downgrade-now":
        return "bash scripts/check_ws3_taxonomy_honesty_e2e.sh"
    if category == "scanner-false-positive":
        return "bash scripts/check_support_matrix_promotion_triage.sh"
    return "bash scripts/check_support_matrix_maintenance.sh --strict"


def classify(row, findings, traits):
    missing = set(row.get("missing_evidence", []))
    has_missing_fixture = bool(
        missing & {"missing_strict_fixture", "missing_hardened_fixture"}
    )
    has_body_host = "Implemented but host delegation detected" in findings
    has_census_host = "Implemented but host delegation census detected" in findings

    if has_body_host or (has_census_host and traits["has_host_delegation"]):
        return "downgrade-now", "host delegation is visible in the implementation source"
    if has_census_host and traits["has_native_syscall"] and not traits["has_host_delegation"]:
        return "scanner-false-positive", "census reports host delegation, but the source anchors to native syscall code"
    if has_missing_fixture:
        return "blocked-by-harness", "strict or hardened fixture evidence is missing"
    return "prove-now", "fixture rows exist; run or repair strict+hardened conformance proof"


def main():
    report = load_json(maintenance_path)
    modules = symbol_to_module()
    issues = issue_index(report)
    promotions = [
        row
        for row in report.get("reclassified_symbols", [])
        if isinstance(row, dict)
        and row.get("previous_status") == "WrapsHostLibc"
        and row.get("current_status") == "Implemented"
    ]

    rows = []
    errors = []
    for row in sorted(promotions, key=lambda item: str(item.get("symbol", ""))):
        symbol = str(row.get("symbol", ""))
        module = modules.get(symbol, "unknown")
        symbol_issues = issues.get(symbol, [])
        findings = sorted(
            {
                str(finding)
                for issue in symbol_issues
                for finding in issue.get("findings", [])
            }
        )
        location = first_source_location(symbol, module)
        traits = source_traits(location)
        category, reason = classify(row, findings, traits)
        if category not in ALLOWED_CATEGORIES:
            errors.append(f"{symbol}: invalid category {category}")
        rows.append(
            {
                "symbol": symbol,
                "module": module,
                "previous_status": row.get("previous_status"),
                "current_status": row.get("current_status"),
                "category": category,
                "category_reason": reason,
                "promotion_requires_evidence": bool(row.get("promotion_requires_evidence")),
                "conformance_evidence_passed": bool(row.get("conformance_evidence_passed")),
                "missing_evidence": list(row.get("missing_evidence", [])),
                "strict_fixture_count": int(row.get("strict_fixture_count", 0)),
                "hardened_fixture_count": int(row.get("hardened_fixture_count", 0)),
                "findings": findings,
                "source_location": {
                    "path": location.get("path"),
                    "line": location.get("line"),
                    "snippet": location.get("snippet"),
                },
                "first_validation_command": validation_command(category, symbol),
            }
        )

    if len(rows) != len(promotions):
        errors.append(
            f"promotion row accounting drift: rows={len(rows)} promotions={len(promotions)}"
        )

    by_category = Counter(row["category"] for row in rows)
    by_module = defaultdict(Counter)
    for row in rows:
        by_module[row["module"]][row["category"]] += 1

    unclassified = [
        row["symbol"]
        for row in rows
        if row["category"] not in ALLOWED_CATEGORIES
    ]
    if unclassified:
        errors.append(f"unclassified promotions: {', '.join(unclassified[:20])}")

    output = {
        "schema_version": "support_matrix_promotion_triage.v1",
        "bead": "bd-w1ro19",
        "trace_id": TRACE_ID,
        "source_artifacts": {
            "support_matrix": "support_matrix.json",
            "maintenance_report": rel(maintenance_path),
        },
        "policy": {
            "allowed_categories": sorted(ALLOWED_CATEGORIES),
            "support_matrix_classifications_changed": False,
            "required_fields": [
                "symbol",
                "module",
                "previous_status",
                "current_status",
                "category",
                "missing_evidence",
                "strict_fixture_count",
                "hardened_fixture_count",
                "source_location",
                "first_validation_command",
            ],
        },
        "summary": {
            "promotion_count": len(promotions),
            "classified_count": len(rows),
            "unclassified_count": len(unclassified),
            "category_counts": dict(sorted(by_category.items())),
            "module_count": len(by_module),
            "status": "pass" if not errors else "fail",
        },
        "module_category_counts": {
            module: dict(sorted(counts.items()))
            for module, counts in sorted(by_module.items())
        },
        "promotions": rows,
        "errors": errors,
    }

    report_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    log_rows = [
        {
            "trace_id": TRACE_ID,
            "event": "promotion_triage_summary",
            "status": output["summary"]["status"],
            "promotion_count": len(promotions),
            "classified_count": len(rows),
            "unclassified_count": len(unclassified),
            "category_counts": dict(sorted(by_category.items())),
            "artifact_refs": [rel(maintenance_path), rel(report_path), rel(log_path)],
        }
    ]
    for category, count in sorted(by_category.items()):
        log_rows.append(
            {
                "trace_id": TRACE_ID,
                "event": "promotion_triage_category",
                "status": "pass",
                "category": category,
                "count": count,
                "artifact_refs": [rel(report_path)],
            }
        )
    if errors:
        for error in errors:
            log_rows.append(
                {
                    "trace_id": TRACE_ID,
                    "event": "promotion_triage_error",
                    "status": "fail",
                    "error": error,
                    "artifact_refs": [rel(report_path)],
                }
            )

    log_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows),
        encoding="utf-8",
    )

    print(
        "PASS" if not errors else "FAIL",
        f"support_matrix_promotion_triage promotions={len(promotions)}",
        f"classified={len(rows)}",
        f"unclassified={len(unclassified)}",
        f"report={rel(report_path)}",
        f"log={rel(log_path)}",
    )
    if errors:
        for error in errors[:20]:
            print(f"  - {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
PY
