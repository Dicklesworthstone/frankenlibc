#!/usr/bin/env bash
# check_test_obligation_dashboard_completion_contract.sh - bd-3cco.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_TEST_OBLIGATION_DASHBOARD_CONTRACT:-${ROOT}/tests/conformance/test_obligation_dashboard_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_TEST_OBLIGATION_DASHBOARD_REPORT:-${OUT_DIR}/test_obligation_dashboard_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_TEST_OBLIGATION_DASHBOARD_LOG:-${OUT_DIR}/test_obligation_dashboard_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}"

export FLC_ROOT="${ROOT}"
export FLC_CONTRACT_PATH="${CONTRACT_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"
export FLC_LOG_PATH="${LOG_PATH}"

python3 - <<'PY'
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

root = Path(os.environ["FLC_ROOT"])
contract_path = Path(os.environ["FLC_CONTRACT_PATH"])
report_path = Path(os.environ["FLC_REPORT_PATH"])
log_path = Path(os.environ["FLC_LOG_PATH"])
ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

errors: list[str] = []
events: list[dict[str, Any]] = []

REQUIRED_EVENTS = {
    "test_obligation_dashboard_units_validated",
    "test_obligation_dashboard_e2e_validated",
    "test_obligation_dashboard_telemetry_validated",
}

REQUIRED_FIELDS = {
    "timestamp",
    "trace_id",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "event",
    "status",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "dashboard_entry_count",
    "dashboard_blocker_count",
    "dashboard_subsystem_count",
    "closed_blocker_count",
    "required_category_count",
    "artifact_refs",
    "failure_signature",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def rel_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay under workspace root: {value}")
    return root / path


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


SOURCE_COMMIT = source_commit()


def check_file_line_ref(ref: str) -> None:
    if ":" not in ref:
        errors.append(f"implementation ref missing line separator: {ref}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        errors.append(f"implementation ref has invalid line: {ref}")
        return
    try:
        path = rel_path(path_text)
    except ValueError as exc:
        errors.append(str(exc))
        return
    if not path.is_file():
        errors.append(f"implementation ref path missing: {ref}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no < 1 or line_no > len(lines) or not lines[line_no - 1].strip():
        errors.append(f"implementation ref does not point to non-empty line: {ref}")


def require_contains(label: str, text: str, needle: str) -> None:
    if needle not in text:
        errors.append(f"{label} missing required text: {needle}")


def require_test_fn(path: Path, name: str) -> None:
    text = path.read_text(encoding="utf-8")
    if f"def {name}" not in text and f"fn {name}" not in text:
        errors.append(f"{path.relative_to(root)} missing test function {name}")


def run_existing_gate(checker: Path) -> tuple[bool, str]:
    proc = subprocess.run(
        ["bash", str(checker)],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    message = f"stdout={proc.stdout}\nstderr={proc.stderr}"
    return proc.returncode == 0, message


def emit_event(event: str, status: str, *, summary: dict[str, Any], details: dict[str, Any] | None = None) -> None:
    events.append(
        {
            "timestamp": ts,
            "trace_id": f"bd-3cco.1:{event}",
            "completion_debt_bead": "bd-3cco.1",
            "original_bead": "bd-3cco",
            "source_commit": SOURCE_COMMIT,
            "event": event,
            "status": status,
            "mode": "completion-contract",
            "api_family": "harness",
            "symbol": "test_obligation_dashboard",
            "decision_path": "contract+generator+dashboard+checker+ci+telemetry",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "dashboard_entry_count": int(summary.get("dashboard_entry_count", 0)),
            "dashboard_blocker_count": int(summary.get("dashboard_blocker_count", 0)),
            "dashboard_subsystem_count": int(summary.get("dashboard_subsystem_count", 0)),
            "closed_blocker_count": int(summary.get("closed_blocker_count", 0)),
            "required_category_count": int(summary.get("required_category_count", 0)),
            "artifact_refs": [
                "tests/conformance/test_obligation_dashboard_completion_contract.v1.json",
                "scripts/check_test_obligation_dashboard_completion_contract.sh",
                "scripts/generate_test_obligation_dashboard.py",
                "scripts/check_test_obligation_dashboard.sh",
                "tests/conformance/test_obligation_dashboard.v1.json",
                "crates/frankenlibc-harness/tests/test_obligation_dashboard_test.rs",
            ],
            "failure_signature": "none" if status == "pass" else "test_obligation_dashboard_completion_contract_failed",
            "details": details or {},
        }
    )


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})
policy = evidence.get("dashboard_policy", {})

if contract.get("schema") != "test_obligation_dashboard_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != "bd-3cco":
    errors.append("bead must be bd-3cco")
if contract.get("completion_debt_bead") != "bd-3cco.1":
    errors.append("completion_debt_bead must be bd-3cco.1")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}:
    errors.append(f"missing_items mismatch: {sorted(missing_items)}")

artifact_paths: dict[str, Path] = {}
for name, value in artifacts.items():
    try:
        path = rel_path(str(value))
    except ValueError as exc:
        errors.append(str(exc))
        continue
    artifact_paths[name] = path
    if not path.is_file():
        errors.append(f"artifact {name} missing: {value}")

for ref in evidence.get("implementation_refs", []):
    check_file_line_ref(str(ref))

generator_text = artifact_paths["dashboard_generator"].read_text(encoding="utf-8")
checker_text = artifact_paths["dashboard_checker"].read_text(encoding="utf-8")
test_text = artifact_paths["dashboard_harness_test"].read_text(encoding="utf-8")
ci_text = artifact_paths["ci_gate"].read_text(encoding="utf-8")
dashboard = load_json(artifact_paths["dashboard_artifact"])

if policy.get("required_schema_version") != "v1":
    errors.append("required_schema_version must be v1")
if policy.get("required_bead") != "bd-3cco":
    errors.append("required_bead must be bd-3cco")
if policy.get("required_source") != "tests/conformance/verification_matrix.json":
    errors.append("required_source must be tests/conformance/verification_matrix.json")

for function in policy.get("required_generator_functions", []):
    require_contains("dashboard generator", generator_text, f"def {function}")

for fragment in policy.get("required_checker_fragments", []):
    require_contains("dashboard checker", checker_text, str(fragment))

require_contains("CI gate", ci_text, str(policy.get("required_ci_fragment", "")))
for required_test in [
    "artifact_exists_and_has_expected_schema",
    "blockers_have_required_fields_and_no_closed_bead_blockers",
    "gate_script_exists_and_succeeds",
]:
    require_contains("dashboard harness test", test_text, f"fn {required_test}")

for key in policy.get("required_top_level_fields", []):
    if key not in dashboard:
        errors.append(f"dashboard missing top-level field: {key}")

if dashboard.get("schema_version") != policy.get("required_schema_version"):
    errors.append("dashboard schema_version mismatch")
if dashboard.get("bead") != policy.get("required_bead"):
    errors.append("dashboard bead mismatch")
if dashboard.get("source") != policy.get("required_source"):
    errors.append("dashboard source mismatch")

summary = dashboard.get("summary", {})
coverage_by_subsystem = dashboard.get("coverage_by_subsystem", [])
blockers = dashboard.get("blockers", [])
by_bead = dashboard.get("by_bead", [])

for key in policy.get("required_summary_fields", []):
    if key not in summary:
        errors.append(f"dashboard summary missing field: {key}")

if not isinstance(coverage_by_subsystem, list) or len(coverage_by_subsystem) < int(policy.get("minimum_subsystems", 0)):
    errors.append("coverage_by_subsystem must satisfy minimum_subsystems")
if not isinstance(by_bead, list) or len(by_bead) < int(policy.get("minimum_dashboard_entries", 0)):
    errors.append("by_bead must satisfy minimum_dashboard_entries")
if not isinstance(blockers, list):
    errors.append("blockers must be an array")

if int(summary.get("entry_count", -1)) != len(by_bead):
    errors.append("summary.entry_count mismatch")
if int(summary.get("subsystem_count", -1)) != len(coverage_by_subsystem):
    errors.append("summary.subsystem_count mismatch")
if int(summary.get("blocker_count", -1)) != len(blockers):
    errors.append("summary.blocker_count mismatch")
if int(summary.get("blocked_bead_count", -1)) != sum(1 for row in by_bead if int(row.get("blocker_count", 0)) > 0):
    errors.append("summary.blocked_bead_count mismatch")

required_categories = set(policy.get("required_categories", []))
for group in coverage_by_subsystem:
    categories = group.get("categories", {})
    missing = required_categories - set(categories)
    if missing:
        errors.append(f"coverage subsystem {group.get('subsystem')} missing categories: {sorted(missing)}")
    for category in required_categories & set(categories):
        category_counts = categories.get(category, {})
        for count_field in ("required", "complete", "partial", "missing"):
            if count_field not in category_counts:
                errors.append(f"coverage category {category} missing count field {count_field}")

closed_blocker_count = 0
allowed_statuses = set(policy.get("tracked_statuses", []))
allowed_categories = required_categories
required_blocker_fields = set(policy.get("required_blocker_fields", []))
for row in blockers:
    missing = required_blocker_fields - set(row)
    if missing:
        errors.append(f"blocker row missing fields for {row.get('bead_id')}: {sorted(missing)}")
    if row.get("bead_status") == "closed":
        closed_blocker_count += 1
    if row.get("bead_status") not in allowed_statuses:
        errors.append(f"blocker row has untracked status: {row.get('bead_status')}")
    if row.get("category") not in allowed_categories:
        errors.append(f"blocker row has unknown category: {row.get('category')}")

if closed_blocker_count:
    errors.append(f"closed blockers must be zero, found {closed_blocker_count}")

required_by_bead_fields = set(policy.get("required_by_bead_fields", []))
for row in by_bead:
    missing = required_by_bead_fields - set(row)
    if missing:
        errors.append(f"by_bead row missing fields for {row.get('bead_id')}: {sorted(missing)}")
    if row.get("status") not in allowed_statuses:
        errors.append(f"by_bead row has untracked status: {row.get('status')}")

sources = evidence.get("test_sources", {})
source_paths = {name: rel_path(str(path)) for name, path in sources.items()}
for section_name in ("unit_primary", "e2e_primary"):
    for test_ref in evidence.get(section_name, {}).get("required_test_refs", []):
        source = str(test_ref.get("source", ""))
        name = str(test_ref.get("name", ""))
        path = source_paths.get(source)
        if path is None:
            errors.append(f"unknown test source: {source}")
            continue
        require_test_fn(path, name)

for script in evidence.get("e2e_primary", {}).get("required_scripts", []):
    if not rel_path(str(script).split()[0]).is_file():
        errors.append(f"required script missing: {script}")

for section in ("unit_primary", "e2e_primary"):
    for command in evidence.get(section, {}).get("required_commands", []):
        if "cargo test" in command and "rch exec" not in command:
            errors.append(f"{section} cargo command must be rch-backed: {command}")

telemetry = evidence.get("telemetry_primary", {})
if set(telemetry.get("required_events", [])) != REQUIRED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != REQUIRED_FIELDS:
    errors.append("telemetry required_fields mismatch")

gate_ok, gate_message = run_existing_gate(artifact_paths["dashboard_checker"])
if not gate_ok:
    errors.append(f"existing dashboard gate failed: {gate_message}")

event_summary = {
    "dashboard_entry_count": int(summary.get("entry_count", 0)),
    "dashboard_blocker_count": int(summary.get("blocker_count", 0)),
    "dashboard_subsystem_count": int(summary.get("subsystem_count", 0)),
    "closed_blocker_count": closed_blocker_count,
    "required_category_count": len(required_categories),
}

status = "pass" if not errors else "fail"
emit_event(
    "test_obligation_dashboard_units_validated",
    status,
    summary=event_summary,
    details={"tests": evidence.get("unit_primary", {}).get("required_test_refs", [])},
)
emit_event(
    "test_obligation_dashboard_e2e_validated",
    status,
    summary=event_summary,
    details={"scripts": evidence.get("e2e_primary", {}).get("required_scripts", []), "gate_ok": gate_ok},
)
emit_event(
    "test_obligation_dashboard_telemetry_validated",
    status,
    summary=event_summary,
    details={"required_fields": sorted(REQUIRED_FIELDS)},
)

report = {
    "schema": "test_obligation_dashboard_completion_contract.report.v1",
    "status": status,
    "bead": "bd-3cco",
    "completion_debt_bead": "bd-3cco.1",
    "source_commit": SOURCE_COMMIT,
    "summary": event_summary,
    "required_events": sorted(REQUIRED_EVENTS),
    "required_fields": sorted(REQUIRED_FIELDS),
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)

if errors:
    print("FAIL: test obligation dashboard completion contract failed")
    for error in errors:
        print(f"  - {error}")
    raise SystemExit(1)

print(
    "PASS: test obligation dashboard completion contract "
    f"(entries={event_summary['dashboard_entry_count']}, blockers={event_summary['dashboard_blocker_count']}, "
    f"subsystems={event_summary['dashboard_subsystem_count']})"
)
PY
