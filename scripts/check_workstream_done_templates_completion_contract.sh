#!/usr/bin/env bash
# check_workstream_done_templates_completion_contract.sh - bd-bp8fl.11.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_WORKSTREAM_DONE_TEMPLATES_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/workstream_done_templates_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_WORKSTREAM_DONE_TEMPLATES_COMPLETION_REPORT:-${OUT_DIR}/workstream_done_templates_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_WORKSTREAM_DONE_TEMPLATES_COMPLETION_LOG:-${OUT_DIR}/workstream_done_templates_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}"

export FLC_ROOT="${ROOT}"
export FLC_CONTRACT_PATH="${CONTRACT_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"
export FLC_LOG_PATH="${LOG_PATH}"

python3 - <<'PY'
from __future__ import annotations

import json
import os
import shlex
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

REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}

REQUIRED_EVENTS = {
    "workstream_done_templates_units_validated",
    "workstream_done_templates_e2e_validated",
    "workstream_done_templates_telemetry_validated",
}

REQUIRED_FIELDS = {
    "timestamp",
    "trace_id",
    "completion_debt_bead",
    "original_bead",
    "event",
    "status",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "template_count",
    "dry_run_example_count",
    "checklist_replay_scenario_count",
    "handoff_branch_count",
    "handoff_transcript_count",
    "base_log_row_count",
    "artifact_refs",
    "failure_signature",
}

REQUIRED_TEMPLATE_SECTIONS = [
    "start_conditions",
    "blocked_by_checks",
    "expected_touched_files",
    "required_unit_test_classes",
    "required_e2e_fixture_harness_scripts",
    "structured_log_fields",
    "artifact_freshness_rules",
    "user_facing_claim_gates",
    "closure_commands",
    "known_limitations_policy",
    "non_goals",
]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "workstream",
    "scenario_id",
    "required_evidence",
    "present_evidence",
    "missing_evidence",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]

REQUIRED_HANDOFF_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "dependency_state",
    "tracker_state",
    "workstream",
    "required_tests",
    "required_e2e",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
    "next_safe_action",
]

REQUIRED_BASE_REPORT_CHECKS = {
    "template_sections_complete",
    "closure_commands_complete",
    "checklist_replay_is_fail_closed",
    "implementation_handoff_checklist_complete",
    "handoff_transcripts_choose_next_safe_action",
    "rch_cargo_target_dir_contract",
}

REQUIRED_BASE_LOG_EVENTS = {
    "workstream_done_template",
    "workstream_done_checklist_replay",
    "implementation_handoff_branch",
    "implementation_handoff_transcript",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def rel_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay under workspace root: {value}")
    return root / path


def rel(value: Path) -> str:
    try:
        return str(value.relative_to(root))
    except ValueError:
        return str(value)


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
    if f"fn {name}" not in text:
        errors.append(f"{rel(path)} missing test function {name}")


def non_empty_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def run_base_gate(path: Path) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    proc = subprocess.run(
        ["bash", str(path)],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        errors.append(
            "base workstream_done_templates gate failed: "
            f"stdout={proc.stdout.strip()} stderr={proc.stderr.strip()}"
        )
        return None, []
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        errors.append(f"base gate stdout is not JSON: {exc}")
        report = None

    log_rows: list[dict[str, Any]] = []
    log_path = root / "target/conformance/workstream_done_templates.log.jsonl"
    try:
        for line in log_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                if isinstance(row, dict):
                    log_rows.append(row)
    except Exception as exc:
        errors.append(f"base gate log unreadable: {exc}")
    return report, log_rows


def command_contract_failures(command: str) -> list[str]:
    if command.startswith("scripts/") or command.startswith("bash scripts/"):
        return []
    if "cargo" not in command:
        return []

    if "rch exec --" not in command:
        return [f"required command must use rch or a repo script, not bare cargo: {command}"]

    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        return [f"required command is not shell-parseable: {command}: {exc}"]

    failures: list[str] = []
    saw_rch_cargo = False
    for index in range(max(0, len(tokens) - 2)):
        if tokens[index:index + 3] != ["rch", "exec", "--"]:
            continue
        payload = tokens[index + 3:]
        if "cargo" not in payload:
            continue
        saw_rch_cargo = True
        cargo_index = payload.index("cargo")
        cargo_prefix = payload[:cargo_index]
        has_target_dir = (
            cargo_prefix
            and cargo_prefix[0] == "env"
            and any(
                token.startswith("CARGO_TARGET_DIR=") and token != "CARGO_TARGET_DIR="
                for token in cargo_prefix[1:]
            )
        )
        if "RCH_REQUIRE_REMOTE=1" not in tokens[:index]:
            failures.append(f"required command must set RCH_REQUIRE_REMOTE=1: {command}")
        if not has_target_dir:
            failures.append(f"required command must set isolated CARGO_TARGET_DIR: {command}")

    if not saw_rch_cargo:
        failures.append(f"required cargo command must use an rch exec -- payload containing cargo: {command}")
    return failures


def emit_event(
    event: str,
    status: str,
    *,
    summary: dict[str, Any],
    base_log_row_count: int,
) -> None:
    events.append(
        {
            "timestamp": ts,
            "trace_id": f"bd-bp8fl.11.1:{event}",
            "completion_debt_bead": "bd-bp8fl.11.1",
            "original_bead": "bd-bp8fl.11",
            "source_commit": SOURCE_COMMIT,
            "event": event,
            "status": status,
            "mode": "completion-contract",
            "api_family": "harness",
            "symbol": "workstream_done_templates",
            "decision_path": "contract+base_gate+handoff_replay+telemetry",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "template_count": summary.get("template_count", 0),
            "dry_run_example_count": summary.get("dry_run_example_count", 0),
            "checklist_replay_scenario_count": summary.get("checklist_replay_scenario_count", 0),
            "handoff_branch_count": summary.get("handoff_branch_count", 0),
            "handoff_transcript_count": summary.get("handoff_transcript_count", 0),
            "base_log_row_count": base_log_row_count,
            "artifact_refs": [
                "tests/conformance/workstream_done_templates_completion_contract.v1.json",
                "scripts/check_workstream_done_templates_completion_contract.sh",
                "tests/conformance/workstream_done_templates.v1.json",
                "scripts/check_workstream_done_templates.sh",
                "crates/frankenlibc-harness/tests/workstream_done_templates_test.rs",
            ],
            "failure_signature": "none" if status == "pass" else "workstream_done_templates_completion_contract_failed",
        }
    )


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})
policy = evidence.get("template_policy", {})

if contract.get("schema") != "workstream_done_templates_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != "bd-bp8fl.11":
    errors.append("bead must be bd-bp8fl.11")
if contract.get("completion_debt_bead") != "bd-bp8fl.11.1":
    errors.append("completion_debt_bead must be bd-bp8fl.11.1")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != REQUIRED_MISSING_ITEMS:
    errors.append(f"missing_items mismatch: {sorted(missing_items)}")

required_artifacts = {
    "base_artifact",
    "base_checker",
    "base_harness_test",
    "completion_contract",
    "completion_checker",
    "completion_harness_test",
}
artifact_paths: dict[str, Path] = {}
for name in required_artifacts:
    value = artifacts.get(name)
    if not isinstance(value, str):
        errors.append(f"artifact {name} must be a string path")
        continue
    try:
        path = rel_path(value)
    except ValueError as exc:
        errors.append(str(exc))
        continue
    artifact_paths[name] = path
    if not path.is_file():
        errors.append(f"artifact {name} missing: {value}")

for ref in evidence.get("implementation_refs", []):
    check_file_line_ref(str(ref))

if policy.get("required_workstream_count") != 10:
    errors.append("required_workstream_count must be 10")
if policy.get("minimum_dry_run_examples", 0) < 3:
    errors.append("minimum_dry_run_examples must be >= 3")
if policy.get("minimum_checklist_replay_scenarios", 0) < 3:
    errors.append("minimum_checklist_replay_scenarios must be >= 3")
if policy.get("minimum_handoff_branches", 0) < 7:
    errors.append("minimum_handoff_branches must be >= 7")
if policy.get("minimum_handoff_transcripts", 0) < 2:
    errors.append("minimum_handoff_transcripts must be >= 2")
if policy.get("required_template_sections") != REQUIRED_TEMPLATE_SECTIONS:
    errors.append("required_template_sections mismatch")
if policy.get("required_structured_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_structured_log_fields mismatch")
if policy.get("required_handoff_log_fields") != REQUIRED_HANDOFF_LOG_FIELDS:
    errors.append("required_handoff_log_fields mismatch")
if set(policy.get("required_base_report_checks", [])) != REQUIRED_BASE_REPORT_CHECKS:
    errors.append("required_base_report_checks mismatch")
if set(policy.get("required_base_log_events", [])) != REQUIRED_BASE_LOG_EVENTS:
    errors.append("required_base_log_events mismatch")

base_artifact = load_json(artifact_paths.get("base_artifact", contract_path))
base_checker_text = artifact_paths.get("base_checker", contract_path).read_text(encoding="utf-8")
base_test_text = artifact_paths.get("base_harness_test", contract_path).read_text(encoding="utf-8")
completion_test_path = artifact_paths.get("completion_harness_test", contract_path)
completion_test_text = completion_test_path.read_text(encoding="utf-8")

if base_artifact.get("schema_version") != "v1" or base_artifact.get("bead") != "bd-bp8fl.11":
    errors.append("base artifact must remain schema_version=v1 and bead=bd-bp8fl.11")
if base_artifact.get("required_template_sections") != REQUIRED_TEMPLATE_SECTIONS:
    errors.append("base artifact required_template_sections drifted")
if base_artifact.get("required_structured_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("base artifact required_structured_log_fields drifted")

templates = base_artifact.get("templates", [])
dry_runs = base_artifact.get("dry_run_examples", [])
replays = base_artifact.get("checklist_replay_scenarios", [])
handoff = base_artifact.get("implementation_handoff_checklist", {})
handoff_branches = handoff.get("branches", []) if isinstance(handoff, dict) else []
handoff_transcripts = handoff.get("dry_run_transcripts", []) if isinstance(handoff, dict) else []

if not isinstance(templates, list) or len(templates) != policy.get("required_workstream_count"):
    errors.append("base artifact must keep 10 workstream templates")
if not isinstance(dry_runs, list) or len(dry_runs) < policy.get("minimum_dry_run_examples", 3):
    errors.append("base artifact must keep at least three dry_run_examples")
if not isinstance(replays, list) or len(replays) < policy.get("minimum_checklist_replay_scenarios", 3):
    errors.append("base artifact must keep at least three checklist_replay_scenarios")
if not isinstance(handoff_branches, list) or len(handoff_branches) < policy.get("minimum_handoff_branches", 7):
    errors.append("handoff checklist must keep at least seven branches")
if not isinstance(handoff_transcripts, list) or len(handoff_transcripts) < policy.get("minimum_handoff_transcripts", 2):
    errors.append("handoff checklist must keep at least two transcripts")

for required in [
    "required_workstreams",
    "required_template_sections",
    "required_log_fields",
    "implementation_handoff_checklist_complete",
    "handoff_transcripts_choose_next_safe_action",
    "workstream_done_template",
    "implementation_handoff_branch",
    "rch_cargo_target_dir_contract",
    "RCH_REQUIRE_REMOTE=1",
    "CARGO_TARGET_DIR",
]:
    require_contains("base checker", base_checker_text, required)

for required in [
    "artifact_covers_every_workstream_with_required_sections",
    "gate_script_passes_and_emits_structured_report_and_log",
    "gate_script_rejects_missing_template_sections",
    "gate_script_rejects_toothless_blocked_replay",
    "gate_script_rejects_handoff_without_next_safe_action",
    "gate_script_rejects_bare_rch_cargo_without_target_dir",
]:
    require_contains("base harness test", base_test_text, required)

for section_name in ["unit_primary", "e2e_primary"]:
    section = evidence.get(section_name, {})
    for test_ref in section.get("required_test_refs", []):
        source = test_ref.get("source")
        name = test_ref.get("name")
        if not isinstance(source, str) or source not in artifact_paths:
            errors.append(f"{section_name} test ref has unknown source: {test_ref}")
            continue
        if not isinstance(name, str) or not name:
            errors.append(f"{section_name} test ref has missing name: {test_ref}")
            continue
        require_test_fn(artifact_paths[source], name)
    for command in section.get("required_commands", []):
        errors.extend(command_contract_failures(str(command)))

for script in evidence.get("e2e_primary", {}).get("required_scripts", []):
    try:
        script_path = rel_path(str(script))
    except ValueError as exc:
        errors.append(str(exc))
        continue
    if not script_path.is_file():
        errors.append(f"required script missing: {script}")

telemetry = evidence.get("telemetry_primary", {})
if set(telemetry.get("required_events", [])) != REQUIRED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != REQUIRED_FIELDS:
    errors.append("telemetry required_fields mismatch")

base_report, base_log_rows = run_base_gate(artifact_paths.get("base_checker", contract_path))
base_summary: dict[str, Any] = {}
if isinstance(base_report, dict):
    if base_report.get("status") != "pass":
        errors.append("base gate report must pass")
    checks = base_report.get("checks", {})
    for check in REQUIRED_BASE_REPORT_CHECKS:
        if checks.get(check) != "pass":
            errors.append(f"base gate check must pass: {check}")
    base_summary = base_report.get("summary", {}) if isinstance(base_report.get("summary"), dict) else {}
    if base_summary.get("template_count") != 10:
        errors.append("base gate report template_count must be 10")
    if base_summary.get("handoff_branch_count", 0) < 7:
        errors.append("base gate report must include handoff branches")

base_events_seen = {str(row.get("event")) for row in base_log_rows}
if not REQUIRED_BASE_LOG_EVENTS <= base_events_seen:
    errors.append(f"base gate log missing events: {sorted(REQUIRED_BASE_LOG_EVENTS - base_events_seen)}")
for index, row in enumerate(base_log_rows):
    for field in REQUIRED_LOG_FIELDS:
        if field not in row:
            errors.append(f"base log row {index} missing field {field}")
    if row.get("event") in {"implementation_handoff_branch", "implementation_handoff_transcript"}:
        for field in REQUIRED_HANDOFF_LOG_FIELDS:
            if field not in row:
                errors.append(f"handoff base log row {index} missing field {field}")

status = "fail" if errors else "pass"
summary = {
    "template_count": base_summary.get("template_count", len(templates) if isinstance(templates, list) else 0),
    "dry_run_example_count": base_summary.get("dry_run_example_count", len(dry_runs) if isinstance(dry_runs, list) else 0),
    "checklist_replay_scenario_count": base_summary.get(
        "checklist_replay_scenario_count",
        len(replays) if isinstance(replays, list) else 0,
    ),
    "handoff_branch_count": base_summary.get("handoff_branch_count", len(handoff_branches) if isinstance(handoff_branches, list) else 0),
    "handoff_transcript_count": base_summary.get(
        "handoff_transcript_count",
        len(handoff_transcripts) if isinstance(handoff_transcripts, list) else 0,
    ),
    "base_log_row_count": len(base_log_rows),
}

for event in sorted(REQUIRED_EVENTS):
    emit_event(event, status, summary=summary, base_log_row_count=len(base_log_rows))

for event in events:
    for field in REQUIRED_FIELDS:
        if field not in event:
            errors.append(f"completion event {event.get('event')} missing field {field}")

status = "fail" if errors else "pass"
for event in events:
    event["status"] = status
    event["errno"] = 0 if status == "pass" else 1
    event["failure_signature"] = (
        "none" if status == "pass" else "workstream_done_templates_completion_contract_failed"
    )

report = {
    "schema": "workstream_done_templates_completion_contract.report.v1",
    "status": status,
    "completion_debt_bead": "bd-bp8fl.11.1",
    "original_bead": "bd-bp8fl.11",
    "source_commit": SOURCE_COMMIT,
    "summary": summary,
    "required_events": sorted(REQUIRED_EVENTS),
    "required_fields": sorted(REQUIRED_FIELDS),
    "base_report": "target/conformance/workstream_done_templates.report.json",
    "base_log": "target/conformance/workstream_done_templates.log.jsonl",
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    raise SystemExit(1)
PY
