#!/usr/bin/env bash
# check_crypt_dashboard_reconciliation.sh -- deterministic replay gate for bd-bp8fl.2.4
#
# Replays the crypt divergence tracker/dashboard reconciliation scenarios and
# emits a report plus structured logs. The gate fails closed when a zero-open
# dashboard hides a known crypt divergence or stale evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_CRYPT_DASHBOARD_ARTIFACT:-${ROOT}/tests/conformance/crypt_dashboard_reconciliation.v1.json}"
OUT_DIR="${FRANKENLIBC_CRYPT_DASHBOARD_TARGET_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_CRYPT_DASHBOARD_REPORT:-${OUT_DIR}/crypt_dashboard_reconciliation.report.json}"
LOG="${FRANKENLIBC_CRYPT_DASHBOARD_LOG:-${OUT_DIR}/crypt_dashboard_reconciliation.log.jsonl}"
MODE="${1:---fixture-replay}"

case "${MODE}" in
  --fixture-replay|--validate-only)
    ;;
  *)
    echo "usage: $0 [--fixture-replay|--validate-only]" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
mode = sys.argv[5]

REQUIRED_REPORT_FIELDS = [
    "schema_version",
    "bead",
    "generated_at_utc",
    "trace_id",
    "source_commit",
    "status",
    "scenario_count",
    "scenario_results",
    "summary",
    "artifact_refs",
]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "crypt_issue_id",
    "source",
    "expected_state",
    "actual_state",
    "dashboard_state",
    "tracker_state",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]

REQUIRED_STATES = {
    "crypt_gap_visible",
    "reconciled_closed",
    "crypt_gap_untracked",
    "stale_evidence",
    "duplicate_conflict",
    "exact_id_split_brain",
}

REQUIRED_FAILURE_SIGNATURES = {
    "ok",
    "dashboard_zero_open_with_open_crypt_gap",
    "missing_crypt_issue_record",
    "stale_crypt_evidence",
    "duplicate_crypt_issue_rows",
    "exact_id_lookup_failure",
}


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"FAIL: cannot load {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def source_commit():
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def crypt_row_statuses(inputs, crypt_issue_id):
    rows = inputs.get("br_open_rows", [])
    return [
        row.get("status")
        for row in rows
        if row.get("id") == crypt_issue_id and row.get("status")
    ]


def classify(scenario):
    crypt_issue_id = scenario.get("crypt_issue_id")
    inputs = scenario.get("inputs", {})
    statuses = crypt_row_statuses(inputs, crypt_issue_id)
    show_status = inputs.get("br_show_status")
    show_exit = inputs.get("br_show_exit_status")
    evidence_state = inputs.get("crypt_evidence_state")
    divergence_count = inputs.get("crypt_divergence_count")
    evidence_current = bool(inputs.get("evidence_current"))
    dashboard_open = inputs.get("dashboard_open_count")

    has_open_row = "open" in statuses or show_status == "open"
    has_closed_row = "closed" in statuses or show_status == "closed"

    if len(set(statuses)) > 1 or show_status == "duplicate":
        return (
            "duplicate_conflict",
            "duplicate_conflict",
            "tracker_failure",
            "duplicate_crypt_issue_rows",
            "dedupe_crypt_issue_rows_before_dashboard_claim",
        )
    if has_open_row and show_status == "missing" and show_exit != 0:
        return (
            "exact_id_split_brain",
            "exact_id_failure",
            "tracker_failure",
            "exact_id_lookup_failure",
            "repair_exact_id_lookup_before_claim_or_close",
        )
    if evidence_state == "parity" and divergence_count == 0 and not evidence_current:
        return (
            "stale_evidence",
            "stale_claim",
            "tracker_failure",
            "stale_crypt_evidence",
            "refresh_crypt_conformance_before_closure",
        )
    if show_status == "missing" and evidence_state == "known_divergence":
        return (
            "crypt_gap_untracked",
            "contradictory_zero_open",
            "tracker_failure",
            "missing_crypt_issue_record",
            "create_or_reopen_crypt_divergence_bead",
        )
    if has_open_row and evidence_state == "known_divergence":
        dashboard_state = (
            "contradictory_zero_open" if dashboard_open == 0 else "crypt_gap_visible"
        )
        return (
            "crypt_gap_visible",
            dashboard_state,
            "tracker_failure" if dashboard_state == "contradictory_zero_open" else "healthy",
            "dashboard_zero_open_with_open_crypt_gap"
            if dashboard_state == "contradictory_zero_open"
            else "ok",
            "keep_crypt_issue_open_and_block_zero_open_dashboard"
            if dashboard_state == "contradictory_zero_open"
            else "keep_crypt_issue_claimable",
        )
    if has_closed_row and evidence_state == "parity" and divergence_count == 0 and evidence_current:
        return (
            "reconciled_closed",
            "consistent",
            "healthy",
            "ok",
            "allow_zero_open_dashboard_for_crypt",
        )
    return (
        "stale_evidence",
        "stale_claim",
        "tracker_failure",
        "stale_crypt_evidence",
        "refresh_crypt_conformance_before_closure",
    )


artifact = load_json(artifact_path)
errors = []

if artifact.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if artifact.get("bead") != "bd-bp8fl.2.4":
    errors.append("bead must be bd-bp8fl.2.4")
if artifact.get("crypt_issue_id") != "bd-fd42da":
    errors.append("crypt_issue_id must be bd-fd42da")
if artifact.get("required_report_fields") != REQUIRED_REPORT_FIELDS:
    errors.append("required_report_fields drifted")
if artifact.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_log_fields drifted")
if set(artifact.get("required_states", [])) != REQUIRED_STATES:
    errors.append("required_states drifted")
if set(artifact.get("required_failure_signatures", [])) != REQUIRED_FAILURE_SIGNATURES:
    errors.append("required_failure_signatures drifted")

commit = source_commit()
artifact_ref = rel(artifact_path)
scenario_results = []
log_rows = []
covered_states = set()
covered_signatures = set()

for scenario in artifact.get("scenarios", []):
    scenario_id = scenario.get("scenario_id")
    actual_state, dashboard_state, tracker_state, failure_signature, action = classify(scenario)
    covered_states.add(actual_state)
    covered_signatures.add(failure_signature)

    expected_state = scenario.get("expected_state")
    expected_dashboard_state = scenario.get("expected_dashboard_state")
    expected_tracker_state = scenario.get("expected_tracker_state")
    expected_failure_signature = scenario.get("expected_failure_signature")
    expected_action = scenario.get("expected_next_safe_action")

    if actual_state != expected_state:
        errors.append(f"{scenario_id}: expected state {expected_state}, got {actual_state}")
    if dashboard_state != expected_dashboard_state:
        errors.append(
            f"{scenario_id}: expected dashboard {expected_dashboard_state}, got {dashboard_state}"
        )
    if tracker_state != expected_tracker_state:
        errors.append(
            f"{scenario_id}: expected tracker {expected_tracker_state}, got {tracker_state}"
        )
    if failure_signature != expected_failure_signature:
        errors.append(
            f"{scenario_id}: expected signature {expected_failure_signature}, got {failure_signature}"
        )
    if action != expected_action:
        errors.append(f"{scenario_id}: expected action {expected_action}, got {action}")
    if actual_state == "reconciled_closed" and tracker_state != "healthy":
        errors.append(f"{scenario_id}: reconciled closure must be healthy")
    if dashboard_state == "contradictory_zero_open" and failure_signature == "ok":
        errors.append(f"{scenario_id}: contradictory zero-open dashboard must not be ok")

    result = {
        "scenario_id": scenario_id,
        "crypt_issue_id": scenario.get("crypt_issue_id"),
        "source": "fixture",
        "expected_state": expected_state,
        "actual_state": actual_state,
        "dashboard_state": dashboard_state,
        "tracker_state": tracker_state,
        "crypt_evidence_state": scenario.get("inputs", {}).get("crypt_evidence_state"),
        "crypt_divergence_count": scenario.get("inputs", {}).get("crypt_divergence_count"),
        "implementation_may_proceed_on_unrelated_beads": bool(
            scenario.get("implementation_may_proceed_on_unrelated_beads")
        ),
        "artifact_refs": [artifact_ref],
        "failure_signature": failure_signature,
        "next_safe_action": action,
    }
    scenario_results.append(result)

    log_row = {
        "trace_id": f"{artifact.get('trace_id')}::{scenario_id}",
        "bead_id": "bd-bp8fl.2.4",
        "crypt_issue_id": scenario.get("crypt_issue_id"),
        "source": "fixture",
        "expected_state": expected_state,
        "actual_state": actual_state,
        "dashboard_state": dashboard_state,
        "tracker_state": tracker_state,
        "artifact_refs": [artifact_ref],
        "source_commit": commit,
        "failure_signature": failure_signature,
    }
    missing = [field for field in REQUIRED_LOG_FIELDS if field not in log_row]
    if missing:
        errors.append(f"{scenario_id}: missing log fields {missing}")
    log_rows.append(log_row)

missing_states = REQUIRED_STATES - covered_states
if missing_states:
    errors.append(f"missing state coverage: {sorted(missing_states)}")
missing_signatures = REQUIRED_FAILURE_SIGNATURES - covered_signatures
if missing_signatures:
    errors.append(f"missing failure-signature coverage: {sorted(missing_signatures)}")

status = "pass" if not errors else "fail"
summary = {
    "crypt_issue_id": artifact.get("crypt_issue_id"),
    "states": sorted(covered_states),
    "failure_signatures": sorted(covered_signatures),
    "zero_open_dashboard_blocked_for_known_crypt_gap": any(
        row["dashboard_state"] == "contradictory_zero_open"
        and row["tracker_state"] == "tracker_failure"
        for row in scenario_results
    ),
    "current_parity_required_before_closure": any(
        row["actual_state"] == "reconciled_closed" and row["tracker_state"] == "healthy"
        for row in scenario_results
    ),
    "stale_or_missing_evidence_fails_closed": all(
        row["tracker_state"] == "tracker_failure"
        for row in scenario_results
        if row["actual_state"]
        in {"crypt_gap_untracked", "stale_evidence", "duplicate_conflict", "exact_id_split_brain"}
    ),
    "current_repo_next_safe_action": artifact.get("current_repo_observation", {}).get(
        "next_safe_action"
    ),
}

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.2.4",
    "generated_at_utc": utc_now(),
    "trace_id": artifact.get("trace_id"),
    "source_commit": commit,
    "status": status,
    "mode": mode,
    "scenario_count": len(scenario_results),
    "scenario_results": scenario_results,
    "summary": summary,
    "artifact_refs": [artifact_ref],
    "errors": errors,
}

for field in REQUIRED_REPORT_FIELDS:
    if field not in report:
        errors.append(f"report missing field {field}")
        report["status"] = "fail"

if mode == "--fixture-replay":
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with log_path.open("w", encoding="utf-8") as handle:
        for row in log_rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

if errors:
    print("FAIL: crypt dashboard reconciliation replay found errors", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    sys.exit(1)

if mode == "--fixture-replay":
    print(f"PASS: crypt dashboard reconciliation replay classified {len(scenario_results)} scenarios")
    print(f"report: {rel(report_path)}")
    print(f"log: {rel(log_path)}")
else:
    print("PASS: crypt dashboard reconciliation artifact validates")
PY
