#!/usr/bin/env bash
# check_feature_parity_targeted_closure_beads.sh -- bd-bp8fl.3.3 closure-bead map gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${FRANKENLIBC_TARGETED_CLOSURE_BEADS:-${ROOT}/tests/conformance/feature_parity_targeted_closure_beads.v1.json}"
GAP_GROUPS_PATH="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_groups.v1.json}"
OWNER_MD="${FRANKENLIBC_FEATURE_PARITY_OWNER_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_owner_family_groups.v1.md}"
ISSUES="${FRANKENLIBC_BEADS_JSONL:-${ROOT}/.beads/issues.jsonl}"
OUT_DIR="${FRANKENLIBC_TARGETED_CLOSURE_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_TARGETED_CLOSURE_REPORT:-${OUT_DIR}/feature_parity_targeted_closure_beads.report.json}"
LOG="${FRANKENLIBC_TARGETED_CLOSURE_LOG:-${OUT_DIR}/feature_parity_targeted_closure_beads.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${CONFIG}" "${GAP_GROUPS_PATH}" "${OWNER_MD}" "${ISSUES}" "${REPORT}" "${LOG}" <<'PY'
import json
import sys
import time
from pathlib import Path

config_path = Path(sys.argv[1])
groups_path = Path(sys.argv[2])
owner_md_path = Path(sys.argv[3])
issues_path = Path(sys.argv[4])
report_path = Path(sys.argv[5])
log_path = Path(sys.argv[6])

REQUIRED_LOG_FIELDS = [
    "timestamp",
    "trace_id",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "event",
    "outcome",
    "source_row_id",
    "created_issue_id",
    "missing_evidence_type",
    "expected",
    "actual",
    "artifact_refs",
    "failure_signature",
]
COMPLETION_DEBT_BEAD = "bd-bp8fl.3.3.1"
ORIGINAL_BEAD = "bd-bp8fl.3.3"
EXPECTED_TELEMETRY_EVENTS = {
    "feature_parity_targeted_closure_validated",
    "feature_parity_targeted_closure_failed",
    "feature_parity_targeted_closure_row_validated",
    "feature_parity_targeted_closure_row_failed",
}
EXPECTED_REPORT_FIELDS = {
    "schema_version",
    "bead",
    "completion_debt_bead",
    "original_bead",
    "event",
    "status",
    "summary",
    "rows",
    "errors",
    "artifact_refs",
}

errors: list[str] = []
logs: list[dict[str, object]] = []


def load_json(path: Path, name: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{name}: cannot load {path}: {exc}")
        return {}


config = load_json(config_path, "config")
groups = load_json(groups_path, "feature_parity_gap_groups")
try:
    owner_md = owner_md_path.read_text(encoding="utf-8")
except Exception as exc:
    owner_md = ""
    errors.append(f"owner_family_groups: cannot load {owner_md_path}: {exc}")

issues: dict[str, dict[str, object]] = {}
try:
    for line_no, raw in enumerate(issues_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        issue = json.loads(raw)
        issue_id = str(issue.get("id", ""))
        if issue_id:
            issues[issue_id] = issue
except Exception as exc:
    errors.append(f"issues_jsonl: cannot load {issues_path}: {exc}")

group_by_id = {
    str(group.get("batch_id")): group
    for group in groups.get("batches", [])
    if isinstance(group, dict) and group.get("batch_id")
}


def append_log(
    *,
    source_row_id: str,
    created_issue_id: str,
    missing_evidence_type: str,
    expected: object,
    actual: object,
    artifact_refs: list[str],
    failure_signature: str,
) -> None:
    logs.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": f"bd-bp8fl.3.3::{source_row_id}::{created_issue_id}",
            "bead_id": "bd-bp8fl.3.3",
            "completion_debt_bead": COMPLETION_DEBT_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "event": (
                "feature_parity_targeted_closure_row_validated"
                if failure_signature == "none"
                else "feature_parity_targeted_closure_row_failed"
            ),
            "outcome": "pass" if failure_signature == "none" else "fail",
            "source_row_id": source_row_id,
            "created_issue_id": created_issue_id,
            "missing_evidence_type": missing_evidence_type,
            "expected": expected,
            "actual": actual,
            "artifact_refs": artifact_refs,
            "failure_signature": failure_signature,
        }
    )


if not isinstance(config, dict):
    errors.append("config must be a JSON object")
    config = {}
if not isinstance(groups, dict):
    errors.append("feature_parity_gap_groups must be a JSON object")
    groups = {}

if config.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if config.get("bead") != "bd-bp8fl.3.3":
    errors.append("bead must be bd-bp8fl.3.3")
if config.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")
if config.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_log_fields must match bd-bp8fl.3.3 contract")

rows = config.get("closure_rows", [])
if not isinstance(rows, list):
    errors.append("closure_rows must be an array")
    rows = []

source_ids: list[str] = []
created_ids: list[str] = []
total_gap_count = 0
source_reports: list[dict[str, object]] = []

for row in rows:
    if not isinstance(row, dict):
        errors.append("closure row must be an object")
        continue
    source_row_id = str(row.get("source_row_id", ""))
    created_issue_id = str(row.get("created_issue_id", ""))
    missing_evidence_type = str(row.get("missing_evidence_type", ""))
    source_ids.append(source_row_id)
    created_ids.append(created_issue_id)
    group = group_by_id.get(source_row_id)
    issue = issues.get(created_issue_id)
    artifact_refs = [
        str(config_path),
        str(groups_path),
        str(owner_md_path),
        str(issues_path),
    ]
    row_errors: list[str] = []
    if group is None:
        row_errors.append("missing_source_group")
        gap_ids: list[str] = []
    else:
        gap_ids = [str(gap_id) for gap_id in group.get("gap_ids", [])]
        total_gap_count += len(gap_ids)
        if missing_evidence_type != str(group.get("oracle_kind", "")):
            row_errors.append("oracle_kind_mismatch")
        if created_issue_id not in owner_md or source_row_id not in owner_md:
            row_errors.append("owner_family_md_missing_citation")

    if issue is None:
        row_errors.append("missing_created_issue")
        issue_status = "missing"
        dependency_ids: list[str] = []
    else:
        issue_status = str(issue.get("status", "unknown"))
        dependency_ids = [
            str(dep.get("depends_on_id", ""))
            for dep in issue.get("dependencies", [])
            if isinstance(dep, dict)
        ]
        if str(row.get("parent_issue_id", "")) not in dependency_ids:
            row_errors.append("parent_dependency_missing")

    if not row.get("required_unit_tests"):
        row_errors.append("missing_unit_tests")
    if not row.get("required_e2e_scripts"):
        row_errors.append("missing_e2e_scripts")
    if not row.get("br_commands"):
        row_errors.append("missing_br_commands")
    elif not all(created_issue_id in str(command) for command in row.get("br_commands", [])):
        row_errors.append("br_command_missing_issue_id")

    expected = {
        "source_group": "present",
        "created_issue": "present",
        "parent_issue_id": row.get("parent_issue_id"),
        "missing_evidence_type": group.get("oracle_kind") if isinstance(group, dict) else None,
        "gap_ids": len(gap_ids),
    }
    actual = {
        "source_group": "present" if group else "missing",
        "created_issue": issue_status,
        "parent_dependencies": dependency_ids,
        "missing_evidence_type": missing_evidence_type,
        "gap_ids": len(gap_ids),
    }
    failure_signature = "none" if not row_errors else ",".join(row_errors)
    append_log(
        source_row_id=source_row_id,
        created_issue_id=created_issue_id,
        missing_evidence_type=missing_evidence_type,
        expected=expected,
        actual=actual,
        artifact_refs=artifact_refs,
        failure_signature=failure_signature,
    )
    if row_errors:
        errors.append(f"{source_row_id}/{created_issue_id}: {failure_signature}")
    source_reports.append(
        {
            "source_row_id": source_row_id,
            "created_issue_id": created_issue_id,
            "issue_status": issue_status,
            "missing_evidence_type": missing_evidence_type,
            "gap_count": len(gap_ids),
            "failure_signature": failure_signature,
        }
    )

duplicates = sorted({source_id for source_id in source_ids if source_ids.count(source_id) > 1})
if duplicates:
    errors.append(f"duplicate source_row_id values: {duplicates}")
duplicate_issues = sorted({issue_id for issue_id in created_ids if created_ids.count(issue_id) > 1})
if duplicate_issues:
    errors.append(f"duplicate created_issue_id values: {duplicate_issues}")

summary = config.get("summary", {}) if isinstance(config.get("summary"), dict) else {}
if len(rows) != summary.get("expected_source_rows"):
    errors.append("closure row count does not match expected_source_rows")
if total_gap_count != summary.get("expected_gap_count"):
    errors.append(f"gap count mismatch: expected {summary.get('expected_gap_count')} actual {total_gap_count}")
if len(created_ids) != summary.get("created_issue_count"):
    errors.append("created issue count does not match summary")

completion = config.get("completion_debt_evidence")
if not isinstance(completion, dict):
    errors.append("completion_debt_evidence must be an object")
    completion = {}
if completion.get("bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD}")
if completion.get("original_bead") != ORIGINAL_BEAD:
    errors.append(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
if int(completion.get("next_audit_score_threshold", 0)) < 800:
    errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")

workspace_root = Path.cwd()
test_source = completion.get("test_source")
if not isinstance(test_source, str) or not test_source:
    errors.append("completion_debt_evidence.test_source must be non-empty")
    test_source_text = ""
else:
    test_source_path = Path(test_source)
    if not test_source_path.is_absolute():
        test_source_path = workspace_root / test_source_path
    if not test_source_path.is_file():
        errors.append(f"completion_debt_evidence.test_source missing: {test_source}")
        test_source_text = ""
    else:
        test_source_text = test_source_path.read_text(encoding="utf-8")

for evidence_key in ["unit_primary", "e2e_primary"]:
    section = completion.get(evidence_key)
    if not isinstance(section, dict):
        errors.append(f"completion_debt_evidence.{evidence_key} must be an object")
        continue
    required_tests = section.get("required_test_names")
    if not isinstance(required_tests, list) or not required_tests:
        errors.append(
            f"completion_debt_evidence.{evidence_key}.required_test_names must be non-empty"
        )
        continue
    for test_name in required_tests:
        if not isinstance(test_name, str) or not test_name:
            errors.append(f"completion_debt_evidence.{evidence_key} has invalid test name")
            continue
        if f"fn {test_name}(" not in test_source_text:
            errors.append(
                f"completion_debt_evidence.{evidence_key} references missing test {test_name}"
            )

e2e = completion.get("e2e_primary")
if isinstance(e2e, dict):
    required_script = e2e.get("required_script")
    if required_script != "scripts/check_feature_parity_targeted_closure_beads.sh":
        errors.append("completion_debt_evidence.e2e_primary.required_script drifted")
    else:
        required_script_path = workspace_root / required_script
        if not required_script_path.is_file():
            errors.append(f"completion_debt_evidence.e2e_primary.required_script missing: {required_script}")

telemetry = completion.get("telemetry_primary")
if not isinstance(telemetry, dict):
    errors.append("completion_debt_evidence.telemetry_primary must be an object")
    telemetry = {}
if telemetry.get("default_report_path") != "target/conformance/feature_parity_targeted_closure_beads.report.json":
    errors.append("completion_debt_evidence.telemetry_primary.default_report_path drifted")
if telemetry.get("default_log_path") != "target/conformance/feature_parity_targeted_closure_beads.log.jsonl":
    errors.append("completion_debt_evidence.telemetry_primary.default_log_path drifted")
required_events = telemetry.get("required_events")
if not isinstance(required_events, list) or set(str(event) for event in required_events) != EXPECTED_TELEMETRY_EVENTS:
    errors.append("completion_debt_evidence.telemetry_primary.required_events drifted")
required_fields = telemetry.get("required_fields")
if not isinstance(required_fields, list) or [str(field) for field in required_fields] != REQUIRED_LOG_FIELDS:
    errors.append("completion_debt_evidence.telemetry_primary.required_fields mismatch")
required_report_fields = telemetry.get("required_report_fields")
if not isinstance(required_report_fields, list) or set(str(field) for field in required_report_fields) != EXPECTED_REPORT_FIELDS:
    errors.append("completion_debt_evidence.telemetry_primary.required_report_fields drifted")

for log in logs:
    missing = [field for field in REQUIRED_LOG_FIELDS if field not in log]
    if missing:
        errors.append(f"log row missing required fields: {missing}")

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.3.3",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "event": (
        "feature_parity_targeted_closure_validated"
        if not errors
        else "feature_parity_targeted_closure_failed"
    ),
    "status": "pass" if not errors else "fail",
    "summary": {
        "source_rows": len(rows),
        "created_issues": len(set(created_ids)),
        "gap_count": total_gap_count,
        "duplicate_source_rows": duplicates,
        "duplicate_created_issues": duplicate_issues,
    },
    "rows": source_reports,
    "errors": errors,
    "artifact_refs": [
        str(config_path),
        str(groups_path),
        str(owner_md_path),
        str(issues_path),
        str(report_path),
        str(log_path),
    ],
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(log, sort_keys=True) + "\n" for log in logs), encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if not errors else 1)
PY
