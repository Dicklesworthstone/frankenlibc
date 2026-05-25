#!/usr/bin/env bash
# check_support_matrix_promotion_proof_runner.sh - bd-m2xl0y
#
# Builds a strict+hardened proof report for a small support-matrix promotion
# tranche. Cargo/harness execution is intentionally external to this checker:
# pass a freshly generated conformance matrix via
# FRANKENLIBC_PROMOTION_PROOF_CONFORMANCE_MATRIX when replaying fixtures.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${FRANKENLIBC_PROMOTION_PROOF_OUT_DIR:-$ROOT/target/conformance}"
TRIAGE_REPORT="${FRANKENLIBC_PROMOTION_TRIAGE_REPORT:-$OUT_DIR/support_matrix_promotion_triage.v1.json}"
CONFORMANCE_MATRIX="${FRANKENLIBC_PROMOTION_PROOF_CONFORMANCE_MATRIX:-$ROOT/tests/conformance/conformance_matrix.v1.json}"
REPORT="${FRANKENLIBC_PROMOTION_PROOF_REPORT:-$OUT_DIR/support_matrix_promotion_proof_runner.v1.json}"
LOG="${FRANKENLIBC_PROMOTION_PROOF_LOG:-$OUT_DIR/support_matrix_promotion_proof_runner.log.jsonl}"

mkdir -p "$OUT_DIR"

bash "$ROOT/scripts/check_support_matrix_promotion_triage.sh" >/dev/null

python3 - "$ROOT" "$TRIAGE_REPORT" "$CONFORMANCE_MATRIX" "$REPORT" "$LOG" <<'PY'
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1])
triage_path = Path(sys.argv[2])
matrix_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])

TRACE_ID = "bd-m2xl0y-support-matrix-promotion-proof-runner-v1"
REQUIRED_MODES = ("strict", "hardened")


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def rel(path):
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def selected_symbols(triage_rows, cases_by_symbol_mode):
    requested = [
        symbol.strip()
        for symbol in os.environ.get("FRANKENLIBC_PROMOTION_PROOF_SYMBOLS", "").split(",")
        if symbol.strip()
    ]
    if requested:
        return requested

    proven = None
    for row in triage_rows:
        symbol = row.get("symbol")
        if row.get("category") != "prove-now":
            continue
        if not row.get("conformance_evidence_passed"):
            continue
        if all(cases_by_symbol_mode.get((symbol, mode)) for mode in REQUIRED_MODES):
            proven = symbol
            break

    blocked = None
    for row in triage_rows:
        if row.get("category") == "blocked-by-harness":
            blocked = row.get("symbol")
            break

    result = []
    for symbol in [proven, blocked]:
        if symbol and symbol not in result:
            result.append(symbol)
    return result


def index_cases(matrix):
    cases_by_symbol_mode = defaultdict(list)
    for case in matrix.get("cases", []):
        if not isinstance(case, dict):
            continue
        symbol = case.get("symbol")
        mode = case.get("mode")
        if symbol and mode:
            cases_by_symbol_mode[(str(symbol), str(mode))].append(case)
    return cases_by_symbol_mode


def matrix_mode_summary(cases):
    if not cases:
        return {
            "case_count": 0,
            "passed_count": 0,
            "failed_count": 0,
            "error_count": 0,
            "pass_rate_percent": 0.0,
            "trace_ids": [],
            "api_family": "unknown",
        }
    passed = sum(1 for case in cases if bool(case.get("passed")))
    failed = sum(1 for case in cases if case.get("status") == "fail")
    errors = sum(1 for case in cases if case.get("status") == "error")
    return {
        "case_count": len(cases),
        "passed_count": passed,
        "failed_count": failed,
        "error_count": errors,
        "pass_rate_percent": round((passed / len(cases)) * 100.0, 1),
        "trace_ids": sorted(str(case.get("trace_id")) for case in cases if case.get("trace_id")),
        "api_family": str(cases[0].get("family", "unknown")),
    }


def proof_rows_for_symbol(symbol, triage_row, cases_by_symbol_mode):
    category = triage_row.get("category", "unknown")
    missing_evidence = list(triage_row.get("missing_evidence", []))
    rows = []
    mode_outcomes = {}

    for mode in REQUIRED_MODES:
        cases = cases_by_symbol_mode.get((symbol, mode), [])
        summary = matrix_mode_summary(cases)
        if category == "blocked-by-harness":
            outcome = "fail"
            failure_signature = "missing_fixture_evidence"
            reason = "triage category blocked-by-harness: fixture or conformance evidence is missing"
        elif not cases:
            outcome = "fail"
            failure_signature = "missing_conformance_mode_row"
            reason = f"conformance matrix has no {mode} rows for promotion symbol"
        elif summary["case_count"] == summary["passed_count"]:
            outcome = "pass"
            failure_signature = "none"
            reason = "strict/hardened conformance cases passed"
        else:
            outcome = "fail"
            failure_signature = "conformance_divergence"
            reason = "one or more conformance cases failed or errored"

        mode_outcomes[mode] = outcome
        rows.append(
            {
                "trace_id": f"{TRACE_ID}::{symbol}::{mode}",
                "mode": mode,
                "api_family": summary["api_family"] if summary["api_family"] != "unknown" else triage_row.get("module", "unknown"),
                "symbol": symbol,
                "outcome": outcome,
                "failure_signature": failure_signature,
                "reason": reason,
                "category": category,
                "missing_evidence": missing_evidence,
                "case_count": summary["case_count"],
                "passed_count": summary["passed_count"],
                "failed_count": summary["failed_count"],
                "error_count": summary["error_count"],
                "pass_rate_percent": summary["pass_rate_percent"],
                "matrix_trace_ids": summary["trace_ids"],
                "artifact_refs": [rel(triage_path), rel(matrix_path), rel(report_path), rel(log_path)],
            }
        )

    if all(mode_outcomes.get(mode) == "pass" for mode in REQUIRED_MODES):
        proof_status = "proven"
    elif category == "blocked-by-harness":
        proof_status = "blocked-by-harness"
    else:
        proof_status = "divergent"

    return proof_status, rows


def main():
    triage = load_json(triage_path)
    matrix = load_json(matrix_path)
    triage_rows = triage.get("promotions", [])
    triage_by_symbol = {
        row.get("symbol"): row
        for row in triage_rows
        if isinstance(row, dict) and row.get("symbol")
    }
    cases_by_symbol_mode = index_cases(matrix)
    symbols = selected_symbols(triage_rows, cases_by_symbol_mode)

    errors = []
    if not symbols:
        errors.append("no promotion symbols selected")

    symbol_results = []
    evidence_rows = []
    for symbol in symbols:
        triage_row = triage_by_symbol.get(symbol)
        if triage_row is None:
            errors.append(f"{symbol}: missing from promotion triage manifest")
            continue
        proof_status, rows = proof_rows_for_symbol(symbol, triage_row, cases_by_symbol_mode)
        modes = {row["mode"] for row in rows}
        if modes != set(REQUIRED_MODES):
            errors.append(f"{symbol}: evidence rows must include strict and hardened modes")
        if proof_status == "divergent":
            errors.append(f"{symbol}: promotion proof diverged")
        evidence_rows.extend(rows)
        symbol_results.append(
            {
                "symbol": symbol,
                "module": triage_row.get("module"),
                "category": triage_row.get("category"),
                "proof_status": proof_status,
                "strict_outcome": next(row["outcome"] for row in rows if row["mode"] == "strict"),
                "hardened_outcome": next(row["outcome"] for row in rows if row["mode"] == "hardened"),
                "missing_evidence": list(triage_row.get("missing_evidence", [])),
                "artifact_refs": [rel(triage_path), rel(matrix_path), rel(report_path), rel(log_path)],
            }
        )

    proven_count = sum(1 for row in symbol_results if row["proof_status"] == "proven")
    blocked_count = sum(1 for row in symbol_results if row["proof_status"] == "blocked-by-harness")
    divergent_count = sum(1 for row in symbol_results if row["proof_status"] == "divergent")

    if proven_count == 0:
        errors.append("sample tranche must prove at least one already-fixtured promotion")

    output = {
        "schema_version": "support_matrix_promotion_proof_runner.v1",
        "bead": "bd-m2xl0y",
        "trace_id": TRACE_ID,
        "source_artifacts": {
            "triage_report": rel(triage_path),
            "conformance_matrix": rel(matrix_path),
        },
        "policy": {
            "required_modes": list(REQUIRED_MODES),
            "cargo_execution_policy": "cargo commands must be run through rch outside this checker",
            "mode_row_requirement": "each selected symbol must emit strict and hardened evidence rows",
        },
        "summary": {
            "selected_symbol_count": len(symbol_results),
            "evidence_row_count": len(evidence_rows),
            "proven_count": proven_count,
            "blocked_by_harness_count": blocked_count,
            "divergent_count": divergent_count,
            "status": "pass" if not errors else "fail",
        },
        "symbols": symbol_results,
        "evidence_rows": evidence_rows,
        "errors": errors,
    }

    report_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in evidence_rows),
        encoding="utf-8",
    )

    print(
        "PASS" if not errors else "FAIL",
        f"support_matrix_promotion_proof_runner symbols={len(symbol_results)}",
        f"evidence_rows={len(evidence_rows)}",
        f"proven={proven_count}",
        f"blocked={blocked_count}",
        f"divergent={divergent_count}",
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
