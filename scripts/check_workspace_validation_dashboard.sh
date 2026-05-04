#!/usr/bin/env bash
# check_workspace_validation_dashboard.sh -- gate for bd-bp8fl.7.3
#
# Validates the workspace validation dashboard artifact and emits deterministic
# report/log rows. This gate validates the dashboard record, not the broad cargo
# commands themselves.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_WORKSPACE_VALIDATION_DASHBOARD:-${ROOT}/tests/conformance/workspace_validation_dashboard.v1.json}"
OUT_DIR="${FRANKENLIBC_WORKSPACE_VALIDATION_TARGET_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_WORKSPACE_VALIDATION_REPORT:-${OUT_DIR}/workspace_validation_dashboard.report.json}"
LOG="${FRANKENLIBC_WORKSPACE_VALIDATION_LOG:-${OUT_DIR}/workspace_validation_dashboard.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

BEAD = "bd-bp8fl.7.3"
TRACE_ID = "bd-bp8fl-7-3-workspace-validation-dashboard-v1"
REQUIRED_RECORD_FIELDS = [
    "trace_id",
    "bead_id",
    "command",
    "exit_status",
    "validation_scope",
    "owner",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_SCOPES = {
    "workspace-fmt",
    "workspace-check",
    "workspace-clippy",
    "workspace-test",
    "changed-surface-ubs",
    "br-bv-health",
}
REQUIRED_SCENARIOS = {
    "clean",
    "unrelated_failure",
    "bead_owned_failure",
    "stale_report",
    "timeout",
}
REQUIRED_FAILURE_CLASSES = {
    "unrelated_failure",
    "stale_report",
    "not_run",
}


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


errors = []
try:
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"FAIL: cannot load {artifact_path}: {exc}")

if artifact.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if artifact.get("bead") != BEAD:
    errors.append(f"bead must be {BEAD}")
if artifact.get("trace_id") != TRACE_ID:
    errors.append(f"trace_id must be {TRACE_ID}")
if artifact.get("required_record_fields") != REQUIRED_RECORD_FIELDS:
    errors.append("required_record_fields mismatch")

records = artifact.get("dashboard_records")
if not isinstance(records, list) or not records:
    errors.append("dashboard_records must be a non-empty array")
    records = []

scopes = set()
status_counts = {}
for idx, record in enumerate(records):
    context = f"dashboard_records[{idx}]"
    for key in [
        "id",
        "status",
        "command",
        "validation_scope",
        "owner",
        "expected",
        "actual",
        "artifact_refs",
        "source_commit",
        "target_dir",
        "failure_signature",
    ]:
        if key not in record:
            errors.append(f"{context}.{key} missing")
    if "exit_status" not in record:
        errors.append(f"{context}.exit_status missing")
    if not isinstance(record.get("artifact_refs", []), list) or not record.get("artifact_refs"):
        errors.append(f"{context}.artifact_refs must be non-empty")
    scope = record.get("validation_scope")
    if isinstance(scope, str):
        scopes.add(scope)
    status = record.get("status")
    if isinstance(status, str):
        status_counts[status] = status_counts.get(status, 0) + 1

missing_scopes = sorted(REQUIRED_SCOPES - scopes)
if missing_scopes:
    errors.append(f"missing required scopes: {missing_scopes}")
if not any(record.get("status") == "fail" for record in records):
    errors.append("dashboard must preserve at least one current failure row")
if not any(record.get("status") == "pass" for record in records):
    errors.append("dashboard must preserve passing rows")

ledger = artifact.get("failure_ledger")
if not isinstance(ledger, list) or not ledger:
    errors.append("failure_ledger must be a non-empty array")
    ledger = []
ledger_classes = set()
for idx, entry in enumerate(ledger):
    context = f"failure_ledger[{idx}]"
    for key in [
        "failure_id",
        "classification",
        "severity",
        "owner",
        "validation_scope",
        "expected",
        "actual",
        "next_safe_action",
        "artifact_refs",
        "failure_signature",
    ]:
        if key not in entry:
            errors.append(f"{context}.{key} missing")
    if not isinstance(entry.get("artifact_refs", []), list) or not entry.get("artifact_refs"):
        errors.append(f"{context}.artifact_refs must be non-empty")
    classification = entry.get("classification")
    if isinstance(classification, str):
        ledger_classes.add(classification)

missing_classes = sorted(REQUIRED_FAILURE_CLASSES - ledger_classes)
if missing_classes:
    errors.append(f"missing failure classes: {missing_classes}")

scenarios = artifact.get("fixture_replay_scenarios")
if not isinstance(scenarios, list) or not scenarios:
    errors.append("fixture_replay_scenarios must be a non-empty array")
    scenarios = []
scenario_classes = set()
for idx, scenario in enumerate(scenarios):
    context = f"fixture_replay_scenarios[{idx}]"
    for key in [
        "scenario_id",
        "classification",
        "expected_overall_status",
        "expected_next_safe_action",
    ]:
        if key not in scenario:
            errors.append(f"{context}.{key} missing")
    classification = scenario.get("classification")
    if isinstance(classification, str):
        scenario_classes.add(classification)

missing_scenarios = sorted(REQUIRED_SCENARIOS - scenario_classes)
if missing_scenarios:
    errors.append(f"missing scenario classes: {missing_scenarios}")

current_commit = source_commit()
overall_status = "pass" if not errors else "fail"
current_gate_state = "degraded"
if errors:
    current_gate_state = "invalid_dashboard"
elif all(record.get("status") == "pass" for record in records):
    current_gate_state = "pass"
elif any(record.get("status") == "fail" for record in records):
    current_gate_state = "degraded"

report = {
    "schema_version": "v1",
    "bead": BEAD,
    "generated_at_utc": utc_now(),
    "status": overall_status,
    "current_gate_state": current_gate_state,
    "trace_id": TRACE_ID,
    "source_commit": current_commit,
    "dashboard_record_count": len(records),
    "failure_ledger_count": len(ledger),
    "scenario_count": len(scenarios),
    "status_counts": status_counts,
    "covered_scopes": sorted(scopes),
    "failure_classes": sorted(ledger_classes),
    "scenario_classes": sorted(scenario_classes),
    "next_safe_action": artifact.get("next_safe_action"),
    "artifact_refs": [rel(artifact_path), rel(log_path)],
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with log_path.open("w", encoding="utf-8") as log:
    for record in records:
        row = {
            "trace_id": TRACE_ID,
            "bead_id": BEAD,
            "command": record.get("command"),
            "exit_status": record.get("exit_status"),
            "validation_scope": record.get("validation_scope"),
            "owner": record.get("owner"),
            "expected": record.get("expected"),
            "actual": record.get("actual"),
            "artifact_refs": record.get("artifact_refs"),
            "source_commit": record.get("source_commit"),
            "target_dir": record.get("target_dir"),
            "failure_signature": record.get("failure_signature"),
            "dashboard_record_id": record.get("id"),
            "status": record.get("status"),
        }
        log.write(json.dumps(row, sort_keys=True) + "\n")
    for entry in ledger:
        row = {
            "trace_id": TRACE_ID,
            "bead_id": BEAD,
            "command": "workspace_validation_dashboard.failure_ledger",
            "exit_status": 0,
            "validation_scope": entry.get("validation_scope"),
            "owner": entry.get("owner"),
            "expected": entry.get("expected"),
            "actual": entry.get("actual"),
            "artifact_refs": entry.get("artifact_refs"),
            "source_commit": current_commit,
            "target_dir": "target/conformance",
            "failure_signature": entry.get("failure_signature"),
            "failure_id": entry.get("failure_id"),
            "classification": entry.get("classification"),
            "severity": entry.get("severity"),
            "next_safe_action": entry.get("next_safe_action"),
        }
        log.write(json.dumps(row, sort_keys=True) + "\n")

if errors:
    print("FAIL: workspace validation dashboard invalid")
    for error in errors:
        print(f"  - {error}")
    sys.exit(1)

print(f"PASS: workspace validation dashboard valid ({len(records)} records, {len(ledger)} ledger rows)")
print(f"report: {rel(report_path)}")
print(f"log: {rel(log_path)}")
PY
