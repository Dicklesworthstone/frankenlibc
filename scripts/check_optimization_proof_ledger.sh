#!/usr/bin/env bash
# check_optimization_proof_ledger.sh — CI gate for bd-30o.2
#
# Validates that:
#   1. Optimization proof ledger exists and is valid JSON.
#   2. Proof template/checklist/rejection criteria are complete.
#   3. Candidate records satisfy parser + validator requirements.
#   4. E2E sample replay emits structured logs with required fields.
#   5. Summary statistics are internally consistent.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER="${ROOT}/tests/conformance/optimization_proof_ledger.v1.json"
TMP_DIR="$(mktemp -d)"
LOG_PATH="${TMP_DIR}/optimization_proof_ledger.log.jsonl"

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

failures=0

echo "=== Optimization Proof Ledger Gate (bd-30o.2) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Ledger exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Ledger exists and is valid ---"

if [[ ! -f "${LEDGER}" ]]; then
    echo "FAIL: tests/conformance/optimization_proof_ledger.v1.json not found"
    echo ""
    echo "check_optimization_proof_ledger: FAILED"
    exit 1
fi

valid_check="$(python3 - "${LEDGER}" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    v = doc.get("schema_version", 0)
    candidates = doc.get("candidates", [])
    template = doc.get("proof_template", {})
    if v < 1:
        print("INVALID: schema_version < 1")
    elif not isinstance(candidates, list) or not candidates:
        print("INVALID: empty candidates")
    elif not isinstance(template, dict) or not template:
        print("INVALID: missing proof_template")
    else:
        print(f"VALID version={v} candidates={len(candidates)}")
except Exception as exc:
    print(f"INVALID: {exc}")
PY
)"

if [[ "${valid_check}" == INVALID* ]]; then
    echo "FAIL: ${valid_check}"
    failures=$((failures + 1))
else
    echo "PASS: ${valid_check}"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: Template/checklist/rejection criteria completeness
# ---------------------------------------------------------------------------
echo "--- Check 2: Template and rejection criteria ---"

template_check="$(python3 - "${LEDGER}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    doc = json.load(f)

errors = []
template = doc.get("proof_template", {})

required_fields = set(template.get("required_fields", []))
required_minimum = {
    "trace_id",
    "candidate_id",
    "bead_id",
    "module",
    "symbol",
    "proof_status",
    "measurement",
    "behavior_checks",
    "acceptance_reason",
}
for field in sorted(required_minimum):
    if field not in required_fields:
        errors.append(f"required_fields missing: {field}")

statuses = set(template.get("proof_statuses", []))
for status in ("pending", "verified", "rejected", "waived"):
    if status not in statuses:
        errors.append(f"proof_statuses missing: {status}")

check_statuses = set(template.get("behavior_check_statuses", []))
for status in ("pass", "fail", "skipped"):
    if status not in check_statuses:
        errors.append(f"behavior_check_statuses missing: {status}")

min_cov = template.get("minimum_input_class_coverage", [])
if len(min_cov) < 4:
    errors.append("minimum_input_class_coverage must list >= 4 classes")

checklist = template.get("checklist", [])
checklist_ids = {item.get("id") for item in checklist if isinstance(item, dict)}
for required_id in (
    "equivalence_invariants",
    "input_class_coverage",
    "before_after_measurement_binding",
    "strict_hardened_guardrail",
):
    if required_id not in checklist_ids:
        errors.append(f"checklist missing: {required_id}")

criteria = template.get("rejection_criteria", [])
criteria_ids = {item.get("id") for item in criteria if isinstance(item, dict)}
for required_id in (
    "missing_required_fields",
    "missing_behavior_coverage",
    "behavior_check_failure",
    "ambiguous_perf_delta",
    "missing_evidence_links",
):
    if required_id not in criteria_ids:
        errors.append(f"rejection_criteria missing: {required_id}")

print(f"TEMPLATE_ERRORS={len(errors)}")
for err in errors:
    print(f"  {err}")
PY
)"

template_errs="$(echo "${template_check}" | grep '^TEMPLATE_ERRORS=' | cut -d= -f2)"
if [[ "${template_errs}" -gt 0 ]]; then
    echo "FAIL: ${template_errs} template error(s):"
    echo "${template_check}" | grep '^  '
    failures=$((failures + 1))
else
    echo "PASS: Template/checklist/rejection criteria are complete"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Candidate parser + validator requirements
# ---------------------------------------------------------------------------
echo "--- Check 3: Candidate parser + validator ---"

candidate_check="$(python3 - "${LEDGER}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    doc = json.load(f)

errors = []
template = doc["proof_template"]
required_fields = set(template.get("required_fields", []))
statuses = set(template.get("proof_statuses", []))
check_statuses = set(template.get("behavior_check_statuses", []))
minimum_coverage = set(template.get("minimum_input_class_coverage", []))
min_improve = float(template.get("minimum_improvement_pct_for_verified", 0.0))

seen = set()
candidates = doc.get("candidates", [])
for cand in candidates:
    cid = cand.get("candidate_id", "?")
    if cid in seen:
        errors.append(f"{cid}: duplicate candidate_id")
    seen.add(cid)

    for field in sorted(required_fields):
        if field not in cand:
            errors.append(f"{cid}: missing required field {field}")

    proof_status = cand.get("proof_status")
    if proof_status not in statuses:
        errors.append(f"{cid}: invalid proof_status {proof_status!r}")

    if not str(cand.get("trace_id", "")).count("::") >= 2:
        errors.append(f"{cid}: trace_id must contain scope separators (::)")

    acceptance_reason = str(cand.get("acceptance_reason", "")).strip()
    if not acceptance_reason:
        errors.append(f"{cid}: acceptance_reason is required")

    measurement = cand.get("measurement", {})
    for key in ("metric", "mode", "before", "after", "perf_delta_pct", "evidence_refs"):
        if key not in measurement:
            errors.append(f"{cid}: measurement missing {key}")
    evidence_refs = measurement.get("evidence_refs", [])
    if not isinstance(evidence_refs, list) or len(evidence_refs) < 2:
        errors.append(f"{cid}: measurement.evidence_refs must contain before+after artifacts")

    checks = cand.get("behavior_checks", [])
    if not isinstance(checks, list) or not checks:
        errors.append(f"{cid}: behavior_checks must be non-empty")
        checks = []

    coverage = set()
    failed_checks = 0
    for idx, check in enumerate(checks):
        if not isinstance(check, dict):
            errors.append(f"{cid}: behavior_checks[{idx}] must be object")
            continue
        for key in ("check_id", "check_command", "artifact_ref", "input_classes", "status"):
            if key not in check:
                errors.append(f"{cid}: behavior_checks[{idx}] missing {key}")
        status = check.get("status")
        if status not in check_statuses:
            errors.append(f"{cid}: behavior_checks[{idx}] invalid status {status!r}")
        if status == "fail":
            failed_checks += 1
        for cls in check.get("input_classes", []):
            coverage.add(cls)

    if proof_status == "verified":
        missing_cov = sorted(minimum_coverage - coverage)
        if missing_cov:
            errors.append(f"{cid}: verified candidate missing coverage for {missing_cov}")
        if failed_checks:
            errors.append(f"{cid}: verified candidate contains failed behavior checks")
        delta = measurement.get("perf_delta_pct")
        if not isinstance(delta, (int, float)):
            errors.append(f"{cid}: perf_delta_pct must be numeric")
        elif delta > -min_improve:
            errors.append(
                f"{cid}: verified candidate perf_delta_pct={delta} does not meet <= -{min_improve}"
            )

    if proof_status == "rejected":
        reasons = cand.get("rejection_reasons", [])
        if not isinstance(reasons, list) or not reasons:
            errors.append(f"{cid}: rejected candidate must provide rejection_reasons")

print(f"CANDIDATE_ERRORS={len(errors)}")
print(f"TOTAL_CANDIDATES={len(candidates)}")
for err in errors:
    print(f"  {err}")
PY
)"

candidate_errs="$(echo "${candidate_check}" | grep '^CANDIDATE_ERRORS=' | cut -d= -f2)"
if [[ "${candidate_errs}" -gt 0 ]]; then
    echo "FAIL: ${candidate_errs} candidate validation error(s):"
    echo "${candidate_check}" | grep '^  '
    failures=$((failures + 1))
else
    candidate_count="$(echo "${candidate_check}" | grep '^TOTAL_CANDIDATES=' | cut -d= -f2)"
    echo "PASS: ${candidate_count} candidates pass parser/validator constraints"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: E2E sample replay + structured logs
# ---------------------------------------------------------------------------
echo "--- Check 4: E2E sample replay and logging ---"

e2e_check="$(python3 - "${LEDGER}" "${LOG_PATH}" <<'PY'
import json
import sys
from datetime import datetime, timezone

ledger_path, log_path = sys.argv[1:3]
with open(ledger_path, encoding="utf-8") as f:
    doc = json.load(f)

errors = []
required_log_fields = doc.get("logging_contract", {}).get("required_fields", [])
rows = []

for cand in doc.get("candidates", []):
    row = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "trace_id": cand.get("trace_id"),
        "candidate_id": cand.get("candidate_id"),
        "proof_status": cand.get("proof_status"),
        "perf_delta": cand.get("measurement", {}).get("perf_delta_pct"),
        "acceptance_reason": cand.get("acceptance_reason"),
    }
    rows.append(row)

with open(log_path, "w", encoding="utf-8") as f:
    for row in rows:
        f.write(json.dumps(row, sort_keys=True) + "\n")

for idx, row in enumerate(rows):
    for field in required_log_fields:
        value = row.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            errors.append(f"log row {idx}: missing/empty {field}")

print(f"E2E_ERRORS={len(errors)}")
print(f"LOG_ROWS={len(rows)}")
print(f"LOG_PATH={log_path}")
for err in errors:
    print(f"  {err}")
PY
)"

e2e_errs="$(echo "${e2e_check}" | grep '^E2E_ERRORS=' | cut -d= -f2)"
if [[ "${e2e_errs}" -gt 0 ]]; then
    echo "FAIL: ${e2e_errs} e2e log validation error(s):"
    echo "${e2e_check}" | grep '^  '
    failures=$((failures + 1))
else
    log_rows="$(echo "${e2e_check}" | grep '^LOG_ROWS=' | cut -d= -f2)"
    echo "PASS: E2E replay emitted ${log_rows} structured log row(s)"
fi
echo "${e2e_check}" | grep '^LOG_PATH=' || true
echo ""

# ---------------------------------------------------------------------------
# Check 5: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 5: Summary consistency ---"

summary_check="$(python3 - "${LEDGER}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    doc = json.load(f)

errors = []
candidates = doc.get("candidates", [])
summary = doc.get("summary", {})
statuses = ["verified", "rejected", "pending", "waived"]

if summary.get("total_candidates", 0) != len(candidates):
    errors.append(
        f"total_candidates mismatch: claimed={summary.get('total_candidates')} actual={len(candidates)}"
    )

for status in statuses:
    actual = sum(1 for cand in candidates if cand.get("proof_status") == status)
    claimed = summary.get(status, 0)
    if claimed != actual:
        errors.append(f"{status} mismatch: claimed={claimed} actual={actual}")

required_log_fields = doc.get("logging_contract", {}).get("required_fields", [])
claimed_required_log_fields = summary.get("required_log_fields")
if claimed_required_log_fields != len(required_log_fields):
    errors.append(
        "required_log_fields mismatch: "
        f"claimed={claimed_required_log_fields} actual={len(required_log_fields)}"
    )

required_input_classes = doc.get("proof_template", {}).get("minimum_input_class_coverage", [])
claimed_required_input_classes = summary.get("required_input_classes")
if claimed_required_input_classes != len(required_input_classes):
    errors.append(
        "required_input_classes mismatch: "
        f"claimed={claimed_required_input_classes} actual={len(required_input_classes)}"
    )

print(f"SUMMARY_ERRORS={len(errors)}")
for err in errors:
    print(f"  {err}")
PY
)"

summary_errs="$(echo "${summary_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)"
if [[ "${summary_errs}" -gt 0 ]]; then
    echo "FAIL: ${summary_errs} summary inconsistency(ies):"
    echo "${summary_check}" | grep '^  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics are consistent"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_optimization_proof_ledger: FAILED"
    exit 1
fi

echo ""
echo "check_optimization_proof_ledger: PASS"
