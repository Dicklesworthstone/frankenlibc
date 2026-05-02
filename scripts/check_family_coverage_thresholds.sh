#!/usr/bin/env bash
# check_family_coverage_thresholds.sh — deterministic gate for bd-bp8fl.4.3
#
# Validates that per-family fixture coverage thresholds are regenerated from
# current coverage artifacts, that every exported target family has a threshold
# row, and that structured JSONL logs expose each family pass/fail decision.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_family_coverage_thresholds.py"
CANONICAL="${ROOT}/tests/conformance/family_coverage_thresholds.v1.json"
SYMBOL_COVERAGE="${ROOT}/tests/conformance/symbol_fixture_coverage.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REGENERATED="${OUT_DIR}/family_coverage_thresholds.regenerated.v1.json"
REPORT="${OUT_DIR}/family_coverage_thresholds.report.json"
LOG="${OUT_DIR}/family_coverage_thresholds.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 "${GEN}" --self-test
python3 "${GEN}" --output "${REGENERATED}"

if ! cmp -s "${CANONICAL}" "${REGENERATED}"; then
    echo "ERROR: family coverage threshold artifact drift detected" >&2
    echo "Regenerate with:" >&2
    echo "  python3 scripts/generate_family_coverage_thresholds.py --output tests/conformance/family_coverage_thresholds.v1.json" >&2
    exit 1
fi

python3 "${GEN}" --check --output "${CANONICAL}"
python3 "${GEN}" --emit-logs --output "${REGENERATED}" > "${LOG}"

python3 - "${CANONICAL}" "${SYMBOL_COVERAGE}" "${LOG}" "${REPORT}" <<'PY'
import json
import sys
from pathlib import Path

canonical_path, symbol_coverage_path, log_path, report_path = [Path(arg) for arg in sys.argv[1:5]]
doc = json.loads(canonical_path.read_text(encoding="utf-8"))
symbol_coverage = json.loads(symbol_coverage_path.read_text(encoding="utf-8"))

errors = []
required_top = {
    "schema_version",
    "bead",
    "purpose",
    "inputs",
    "input_digests",
    "required_log_fields",
    "coverage_model",
    "threshold_policy",
    "summary",
    "threshold_records",
    "gaps_requiring_fixture_beads",
    "artifact_hash",
}
missing_top = sorted(required_top - set(doc))
if missing_top:
    errors.append(f"missing top-level keys: {missing_top}")

if doc.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if doc.get("bead") != "bd-bp8fl.4.3":
    errors.append("bead must be bd-bp8fl.4.3")

records = doc.get("threshold_records", [])
summary = doc.get("summary", {})
if not isinstance(records, list) or not records:
    errors.append("threshold_records must be a non-empty array")
else:
    required_record = {
        "family_id",
        "threshold_id",
        "symbol_count",
        "fixture_count",
        "coverage",
        "thresholds",
        "mode_coverage",
        "replacement_level_coverage",
        "hard_parts_risk",
        "user_workload_exposure",
        "freshness_state",
        "decision",
        "failure_signature",
        "artifact_refs",
    }
    for row in records:
        missing = sorted(required_record - set(row))
        if missing:
            errors.append(f"{row.get('family_id', '<unknown>')}: missing record keys {missing}")
        for level in ["L0", "L1", "L2", "L3"]:
            if level not in row.get("replacement_level_coverage", {}):
                errors.append(f"{row.get('family_id')}: missing replacement level {level}")
        decision = row.get("decision")
        if decision not in {"pass", "fail", "not_applicable"}:
            errors.append(f"{row.get('family_id')}: invalid decision {decision!r}")
        if decision == "fail" and row.get("failure_signature") in {"", "none", None}:
            errors.append(f"{row.get('family_id')}: failing row lacks failure_signature")

family_ids = {row.get("family_id") for row in records}
expected_families = {
    row.get("module")
    for row in symbol_coverage.get("families", [])
    if int(row.get("target_total", 0)) > 0
}
missing_families = sorted(family for family in expected_families if family not in family_ids)
if missing_families:
    errors.append(f"target families missing threshold rows: {missing_families}")

pass_count = sum(1 for row in records if row.get("decision") == "pass")
fail_count = sum(1 for row in records if row.get("decision") == "fail")
na_count = sum(1 for row in records if row.get("decision") == "not_applicable")
if summary.get("family_count") != len(records):
    errors.append("summary.family_count mismatch")
if summary.get("pass_count") != pass_count:
    errors.append("summary.pass_count mismatch")
if summary.get("fail_count") != fail_count:
    errors.append("summary.fail_count mismatch")
if summary.get("not_applicable_count") != na_count:
    errors.append("summary.not_applicable_count mismatch")
if fail_count and summary.get("claim_gate_decision") != "blocked":
    errors.append("claim_gate_decision must be blocked when family thresholds fail")

fail_ids = {row["family_id"] for row in records if row.get("decision") == "fail"}
gap_ids = {row.get("family_id") for row in doc.get("gaps_requiring_fixture_beads", [])}
if fail_ids != gap_ids:
    errors.append("gaps_requiring_fixture_beads must match failing threshold records")

required_logs = set(doc.get("required_log_fields", []))
expected_logs = {
    "trace_id",
    "bead_id",
    "family_id",
    "threshold_id",
    "expected_coverage",
    "actual_coverage",
    "decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
}
if not expected_logs.issubset(required_logs):
    errors.append("required_log_fields missing accepted bd-bp8fl.4.3 fields")

log_rows = []
for line_no, line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), start=1):
    if not line.strip():
        continue
    try:
        row = json.loads(line)
    except json.JSONDecodeError as exc:
        errors.append(f"log line {line_no}: invalid JSON: {exc}")
        continue
    missing = sorted(required_logs - set(row))
    if missing:
        errors.append(f"log line {line_no}: missing fields {missing}")
    log_rows.append(row)

if len(log_rows) != len(records):
    errors.append(f"log row count mismatch: logs={len(log_rows)} records={len(records)}")
if {row.get("family_id") for row in log_rows} != family_ids:
    errors.append("log family set does not match threshold records")

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.4.3",
    "status": "fail" if errors else "pass",
    "artifact_refs": [
        str(canonical_path),
        str(symbol_coverage_path),
        str(log_path),
        str(report_path),
    ],
    "checks": {
        "artifact_regenerated": "pass",
        "generator_self_test": "pass",
        "required_schema": "pass" if not missing_top else "fail",
        "family_inventory_complete": "pass" if not missing_families else "fail",
        "summary_counts": "pass" if summary.get("family_count") == len(records) else "fail",
        "claim_gate_blocks_failed_thresholds": "pass"
        if not fail_count or summary.get("claim_gate_decision") == "blocked"
        else "fail",
        "structured_log_fields": "pass" if len(log_rows) == len(records) else "fail",
    },
    "summary": summary,
    "pass_count": pass_count,
    "fail_count": fail_count,
    "not_applicable_count": na_count,
    "top_failed_families": [
        {
            "family_id": row["family_id"],
            "failure_signature": row["failure_signature"],
            "target_uncovered": row["symbol_count"]["uncovered"],
        }
        for row in sorted(
            [row for row in records if row.get("decision") == "fail"],
            key=lambda row: (-row["symbol_count"]["uncovered"], row["family_id"]),
        )[:10]
    ],
    "self_test_scenarios": [
        "positive family passes thresholds",
        "negative family fails thresholds",
        "stale snapshot rejected",
        "missing family row rejected",
        "duplicate symbol row rejected",
        "coverage regression rejected",
    ],
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    raise SystemExit(1)
PY
