#!/usr/bin/env bash
# Validate the architecture TODO reconciliation report created for bd-0agsk.1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${ARCH_TODO_RECONCILIATION_ARTIFACT:-${ROOT}/tests/conformance/architecture_todo_reconciliation.v1.json}"
LEDGER="${ARCH_TODO_RECONCILIATION_LEDGER:-${ROOT}/docs/architecture_investigation_todo.md}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/architecture_todo_reconciliation.report.json"
LOG="${OUT_DIR}/architecture_todo_reconciliation.log.jsonl"

TRACE_ID="bd-0agsk.2::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"
START_NS="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"

mkdir -p "${OUT_DIR}"

for path in "${ARTIFACT}" "${LEDGER}"; do
  if [[ ! -f "${path}" ]]; then
    echo "FAIL: required file missing: ${path}" >&2
    exit 1
  fi
done

python3 - "${ARTIFACT}" "${LEDGER}" "${REPORT}" "${LOG}" "${TRACE_ID}" "${START_NS}" <<'PY'
import json
import pathlib
import re
import sys
import time
from collections import Counter

artifact_path = pathlib.Path(sys.argv[1])
ledger_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
trace_id = sys.argv[5]
start_ns = int(sys.argv[6])


def first_or_none(values):
    if not isinstance(values, list):
        return None
    for value in values:
        if value is not None:
            return str(value)
    return None


def first_bead_ref(values):
    if not isinstance(values, list):
        return None
    for value in values:
        value = str(value)
        if value.startswith("bd-"):
            return value
    return None


def emit_failure(
    signature: str,
    message: str,
    todo_id=None,
    evidence_ref=None,
    br_issue_ref=None,
    classification=None,
) -> None:
    duration_ms = (time.time_ns() - start_ns) // 1_000_000
    report = {
        "schema_version": "architecture_todo_reconciliation.report.v1",
        "bead": "bd-0agsk.2",
        "trace_id": trace_id,
        "outcome": "fail",
        "failure_signature": signature,
        "failure_message": message,
        "todo_id": todo_id,
        "evidence_ref": evidence_ref,
        "br_issue_ref": br_issue_ref,
        "classification": classification,
        "artifact": str(artifact_path),
        "ledger": str(ledger_path),
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trace_id": trace_id,
        "level": "error",
        "event": "architecture_todo_reconciliation_failed",
        "bead_id": "bd-0agsk.2",
        "artifact_refs": [str(artifact_path), str(ledger_path), str(report_path)],
        "outcome": "fail",
        "duration_ms": duration_ms,
        "failure_signature": signature,
        "failure_message": message,
        "todo_id": todo_id,
        "evidence_ref": evidence_ref,
        "br_issue_ref": br_issue_ref,
        "classification": classification,
        "details": {},
    }
    log_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")


def fail(
    signature: str,
    message: str,
    todo_id=None,
    evidence_ref=None,
    br_issue_ref=None,
    classification=None,
) -> None:
    emit_failure(signature, message, todo_id, evidence_ref, br_issue_ref, classification)
    raise SystemExit(f"FAIL[{signature}]: {message}")


artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
ledger_text = ledger_path.read_text(encoding="utf-8").splitlines()

if artifact.get("schema_version") != "architecture_todo_reconciliation.v1":
    fail("schema_version", "schema_version must be architecture_todo_reconciliation.v1")
if artifact.get("generated_by_bead") != "bd-0agsk.1":
    fail("bead_id", "generated_by_bead must be bd-0agsk.1")
if artifact.get("claim_status") != "report_only":
    fail("claim_status", "claim_status must remain report_only")

promotion = artifact.get("promotion_policy", {})
if promotion.get("replacement_level_change") != "forbidden":
    fail("promotion_policy", "replacement_level_change must be forbidden")

row_re = re.compile(r"^\s*-\s*\[(?P<status>[x~ !])\]\s+`(?P<id>(?:TODO|NEXT)-[0-9A-Za-z]+)`")
ledger_rows = {}
for line_number, raw_line in enumerate(ledger_text, start=1):
    match = row_re.search(raw_line)
    if not match:
        continue
    raw_status = match.group("status")
    if raw_status == "x":
        status = "completed"
    elif raw_status == "~":
        status = "in_progress"
    elif raw_status == "!":
        status = "blocked"
    else:
        status = "pending"
    row_id = match.group("id")
    ledger_rows[row_id] = {"line": line_number, "status": status}

if not ledger_rows:
    fail("ledger_rows_missing", "no TODO/NEXT rows found in architecture ledger")

row_mappings = artifact.get("row_mappings")
if not isinstance(row_mappings, list) or not row_mappings:
    fail("row_mappings_missing", "row_mappings must be a non-empty array")

mapped_ids = []
classification_counter = Counter()
for mapping in row_mappings:
    ids = mapping.get("ids")
    if not isinstance(ids, list) or not ids:
        fail("mapping_ids_missing", "each row mapping must list one or more ids")
    classification = str(mapping.get("live_classification", ""))
    if not classification:
        fail("classification_missing", f"mapping {ids} missing live_classification")
    classification_counter[classification] += len(ids)
    mapped_ids.extend(str(row_id) for row_id in ids)

duplicates = sorted(row_id for row_id, count in Counter(mapped_ids).items() if count > 1)
if duplicates:
    fail("duplicate_mapping", f"duplicate mapped row ids: {duplicates}")

ledger_id_set = set(ledger_rows)
mapped_id_set = set(mapped_ids)
if ledger_id_set != mapped_id_set:
    missing = sorted(ledger_id_set - mapped_id_set)
    extra = sorted(mapped_id_set - ledger_id_set)
    fail("ledger_id_set_mismatch", f"missing={missing} extra={extra}")

counts = artifact.get("ledger_counts", {})
actual_status_counter = Counter(row["status"] for row in ledger_rows.values())
if int(counts.get("row_count", -1)) != len(ledger_rows):
    fail("row_count_mismatch", "ledger_counts.row_count does not match parsed ledger rows")
if int(counts.get("status_completed", -1)) != actual_status_counter["completed"]:
    fail("completed_count_mismatch", "status_completed does not match parsed ledger rows")
if int(counts.get("status_pending", -1)) != actual_status_counter["pending"]:
    fail("pending_count_mismatch", "status_pending does not match parsed ledger rows")
if int(counts.get("status_in_progress", -1)) != actual_status_counter["in_progress"]:
    fail("in_progress_count_mismatch", "status_in_progress does not match parsed ledger rows")
if int(counts.get("status_completed", 0)) + int(counts.get("status_pending", 0)) + int(counts.get("status_in_progress", 0)) != int(counts.get("row_count", -1)):
    fail("row_count_arithmetic", "row_count must equal completed + pending + in_progress")

new_bead_ids = {
    str(row.get("id"))
    for row in artifact.get("new_beads", [])
    if isinstance(row, dict) and row.get("id")
}
required_new = {"bd-0agsk", "bd-0agsk.1", "bd-0agsk.2", "bd-0agsk.18"}
if not required_new.issubset(new_bead_ids):
    fail("new_beads_missing", f"new_beads missing required ids {sorted(required_new - new_bead_ids)}")

for mapping in row_mappings:
    ids = [str(row_id) for row_id in mapping["ids"]]
    classification = str(mapping.get("live_classification", ""))
    ledger_statuses = {ledger_rows[row_id]["status"] for row_id in ids}
    evidence_refs = mapping.get("evidence_refs")
    target_beads = mapping.get("target_beads")
    evidence_ref = first_or_none(evidence_refs)
    br_issue_ref = first_bead_ref((evidence_refs or []) + (target_beads or []))
    if classification == "already_closed_by_ledger_or_closed_bead_evidence":
        if ledger_statuses != {"completed"}:
            fail(
                "closed_mapping_status_mismatch",
                f"closed mapping has non-completed ids: {ids}",
                todo_id=ids[0],
                evidence_ref=evidence_ref,
                br_issue_ref=br_issue_ref,
                classification=classification,
            )
        if not mapping.get("evidence_refs"):
            fail(
                "closed_mapping_missing_evidence",
                f"closed mapping missing evidence_refs: {ids}",
                todo_id=ids[0],
                evidence_ref=evidence_ref,
                br_issue_ref=br_issue_ref,
                classification=classification,
            )
    elif classification == "routed_to_new_open_bead":
        if "completed" in ledger_statuses:
            fail(
                "routed_mapping_status_mismatch",
                f"routed mapping contains completed ids: {ids}",
                todo_id=ids[0],
                evidence_ref=evidence_ref,
                br_issue_ref=br_issue_ref,
                classification=classification,
            )
        targets = mapping.get("target_beads")
        if not isinstance(targets, list) or not targets:
            fail(
                "routed_mapping_missing_targets",
                f"routed mapping missing target_beads: {ids}",
                todo_id=ids[0],
                evidence_ref=evidence_ref,
                br_issue_ref=br_issue_ref,
                classification=classification,
            )
        unknown = sorted(str(target) for target in targets if str(target) not in new_bead_ids)
        if unknown:
            fail(
                "routed_mapping_unknown_target",
                f"unknown target bead(s) {unknown} for ids {ids}",
                todo_id=ids[0],
                evidence_ref=evidence_ref,
                br_issue_ref=br_issue_ref,
                classification=classification,
            )
    else:
        fail(
            "unknown_classification",
            f"unknown live_classification {classification!r}",
            todo_id=ids[0],
            evidence_ref=evidence_ref,
            br_issue_ref=br_issue_ref,
            classification=classification,
        )

for finding in artifact.get("scan_findings", []):
    targets = finding.get("target_beads")
    if not isinstance(targets, list) or not targets:
        fail("scan_finding_missing_targets", "scan finding missing target_beads")
    unknown = sorted(str(target) for target in targets if str(target) not in new_bead_ids)
    if unknown:
        fail("scan_finding_unknown_target", f"unknown scan target bead(s): {unknown}")

declared_classifications = artifact.get("classification_counts", {})
for key, actual_count in classification_counter.items():
    if int(declared_classifications.get(key, -1)) != actual_count:
        fail("classification_count_mismatch", f"classification_counts.{key} mismatch")
for key in ["stale_doc_only", "blocked_by_missing_artifact"]:
    if int(declared_classifications.get(key, -1)) != 0:
        fail("unexpected_unresolved_classification", f"classification_counts.{key} must be zero")

checks = {
    "schema_valid": "pass",
    "ledger_rows_exhaustive": "pass",
    "ledger_counts_consistent": "pass",
    "classification_counts_consistent": "pass",
    "target_beads_known": "pass",
    "promotion_policy_report_only": "pass",
}
duration_ms = (time.time_ns() - start_ns) // 1_000_000
row_events = []
for mapping in row_mappings:
    classification = str(mapping.get("live_classification", ""))
    evidence_refs = mapping.get("evidence_refs")
    target_beads = mapping.get("target_beads")
    evidence_ref = first_or_none(evidence_refs)
    br_issue_ref = first_bead_ref((evidence_refs or []) + (target_beads or []))
    for row_id in mapping["ids"]:
        row_id = str(row_id)
        row_events.append({
            "trace_id": trace_id,
            "todo_id": row_id,
            "ledger_status": ledger_rows[row_id]["status"],
            "classification": classification,
            "evidence_ref": evidence_ref,
            "br_issue_ref": br_issue_ref,
            "evidence_refs": evidence_refs or [],
            "br_issue_refs": [
                str(value)
                for value in (evidence_refs or []) + (target_beads or [])
                if str(value).startswith("bd-")
            ],
            "failure_signature": None,
        })

report = {
    "schema_version": "architecture_todo_reconciliation.report.v1",
    "bead": "bd-0agsk.2",
    "source_bead": artifact.get("generated_by_bead"),
    "trace_id": trace_id,
    "artifact": str(artifact_path),
    "ledger": str(ledger_path),
    "checks": checks,
    "summary": {
        "row_count": len(ledger_rows),
        "completed": actual_status_counter["completed"],
        "pending": actual_status_counter["pending"],
        "in_progress": actual_status_counter["in_progress"],
        "mapped_rows": len(mapped_ids),
        "new_bead_count": len(new_bead_ids),
        "scan_finding_count": len(artifact.get("scan_findings", [])),
    },
    "row_events": row_events,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

event = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "trace_id": trace_id,
    "level": "info",
    "event": "architecture_todo_reconciliation_validated",
    "bead_id": "bd-0agsk.2",
    "artifact_refs": [str(artifact_path), str(ledger_path), str(report_path)],
    "outcome": "pass",
    "duration_ms": duration_ms,
    "details": report["summary"],
    "failure_signature": None,
    "todo_id": None,
    "evidence_ref": None,
    "br_issue_ref": None,
    "classification": None,
}
log_events = [event]
for row_event in row_events:
    log_events.append({
        "timestamp": event["timestamp"],
        "trace_id": trace_id,
        "level": "info",
        "event": "architecture_todo_reconciliation_row_validated",
        "bead_id": "bd-0agsk.2",
        "artifact_refs": [str(artifact_path), str(ledger_path), str(report_path)],
        "outcome": "pass",
        "duration_ms": duration_ms,
        "details": row_event,
        "failure_signature": row_event["failure_signature"],
        "todo_id": row_event["todo_id"],
        "evidence_ref": row_event["evidence_ref"],
        "br_issue_ref": row_event["br_issue_ref"],
        "classification": row_event["classification"],
    })
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_events), encoding="utf-8")
print(f"PASS: architecture TODO reconciliation validated rows={len(ledger_rows)} trace_id={trace_id}")
PY
