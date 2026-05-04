#!/usr/bin/env bash
# check_agent_handoff_checklist.sh -- CI gate for bd-bp8fl.12
#
# Validates the one-bead-at-a-time implementation handoff checklist. The gate
# is intentionally plan-space: it makes workflow branches and evidence
# contracts executable without editing tracker state or running cargo locally.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_AGENT_HANDOFF_CHECKLIST:-${ROOT}/tests/conformance/agent_handoff_checklist.v1.json}"
OUT_DIR="${FRANKENLIBC_AGENT_HANDOFF_TARGET_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_AGENT_HANDOFF_REPORT:-${OUT_DIR}/agent_handoff_checklist.report.json}"
LOG="${FRANKENLIBC_AGENT_HANDOFF_LOG:-${OUT_DIR}/agent_handoff_checklist.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" <<'PY'
import copy
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
out_dir = Path(sys.argv[5])

REQUIRED_SECTIONS = [
    "onboarding_docs",
    "br_ready_list_show_state",
    "bv_robot_triage_insights",
    "dependency_parent_checks",
    "stale_db_jsonl_symptoms",
    "file_reservations",
    "exact_work_surface",
    "expected_artifacts",
    "unit_tests",
    "e2e_or_harness_scripts",
    "structured_logs",
    "rch_target_dir_policy",
    "commit_push_expectations",
    "closure_notes",
]

REQUIRED_LOG_FIELDS = [
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

REQUIRED_BRANCHES = [
    "normal_tracker_state",
    "stale_tracker_state",
    "no_db_fallback",
    "already_shipped_but_open_dotted_id",
    "unrelated_dirty_files",
    "pre_existing_workspace_failures",
    "blocked_bead",
]

REQUIRED_COMMAND_PHRASES = [
    "/dp/AGENTS.md",
    "AGENTS.md",
    "README.md",
    "br --no-db ready --json",
    "br --no-db list --status open --json",
    "br --no-db show <bead-id> --json",
    "br --no-db list --status in_progress --json",
    "bv --robot-triage",
    "bv --robot-insights",
    "file_reservation_paths",
    "ubs <changed-files>",
    "rch exec -- cargo",
    "CARGO_TARGET_DIR",
    "AGENT_NAME",
    "git push origin main",
    "git push origin main:master",
]


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"FAIL: cannot load {path}: {exc}") from exc


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


def non_empty_string_list(value):
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item for item in value)


def validate_log_payload(row):
    missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
    if missing:
        return [f"log row missing fields: {missing}"]
    errors = []
    for field in ("required_tests", "required_e2e", "artifact_refs"):
        if not non_empty_string_list(row.get(field)):
            errors.append(f"log row {field} must be a non-empty string list")
    for field in (
        "trace_id",
        "bead_id",
        "dependency_state",
        "tracker_state",
        "workstream",
        "source_commit",
        "target_dir",
        "failure_signature",
        "next_safe_action",
    ):
        if not isinstance(row.get(field), str) or not row.get(field):
            errors.append(f"log row {field} must be a non-empty string")
    return errors


def branch_to_log_row(artifact, branch, commit):
    return {
        "trace_id": f"{artifact['trace_id']}::{branch['branch_id']}",
        "bead_id": artifact["bead"],
        "dependency_state": branch["dependency_state"],
        "tracker_state": branch["tracker_state"],
        "workstream": branch["workstream"],
        "required_tests": branch["required_tests"],
        "required_e2e": branch["required_e2e"],
        "artifact_refs": branch["artifact_refs"],
        "source_commit": commit,
        "target_dir": branch["target_dir"],
        "failure_signature": branch["failure_signature"],
        "next_safe_action": branch["next_safe_action"],
    }


def transcript_to_log_row(artifact, transcript, commit):
    return {
        "trace_id": f"{artifact['trace_id']}::{transcript['scenario_id']}",
        "bead_id": transcript["bead_id"],
        "dependency_state": transcript["dependency_state"],
        "tracker_state": transcript["tracker_state"],
        "workstream": transcript["workstream"],
        "required_tests": transcript["required_tests"],
        "required_e2e": transcript["required_e2e"],
        "artifact_refs": transcript["artifact_refs"],
        "source_commit": commit,
        "target_dir": transcript["target_dir"],
        "failure_signature": transcript["failure_signature"],
        "next_safe_action": transcript["next_safe_action"],
    }


def closure_decision(branch):
    if not non_empty_string_list(branch.get("required_tests")):
        return "close_blocked", "missing_required_tests"
    if not non_empty_string_list(branch.get("required_e2e")):
        return "close_blocked", "missing_required_e2e"
    if not non_empty_string_list(branch.get("artifact_refs")):
        return "close_blocked", "missing_artifact_refs"
    if branch.get("next_safe_action") in ("ask_user_to_decide", "", None):
        return "close_blocked", "stale_source_of_truth_no_next_action"
    if branch.get("tracker_state") == "blocked" and branch.get("dependency_state") != "blocked":
        return "close_blocked", "blocked_tracker_dependency_mismatch"
    return "close_allowed", "ok"


def mutate_branch(branch, mutation):
    mutated = copy.deepcopy(branch)
    if mutation == "clear required_tests":
        mutated["required_tests"] = []
    elif mutation == "clear artifact_refs":
        mutated["artifact_refs"] = []
    elif mutation == "replace next_safe_action with ask_user_to_decide":
        mutated["next_safe_action"] = "ask_user_to_decide"
    else:
        raise AssertionError(f"unknown mutation {mutation}")
    return mutated


artifact = load_json(artifact_path)
errors = []
checks = {}


def record(condition, name, message):
    checks[name] = "pass" if condition else "fail"
    if not condition:
        errors.append(message)


record(artifact.get("schema_version") == "v1", "schema_version", "schema_version must be v1")
record(artifact.get("bead") == "bd-bp8fl.12", "bead_id", "bead must be bd-bp8fl.12")
record(
    artifact.get("required_checklist_sections") == REQUIRED_SECTIONS,
    "required_sections_declared",
    "required_checklist_sections drifted",
)
record(
    artifact.get("required_structured_log_fields") == REQUIRED_LOG_FIELDS,
    "required_log_fields_declared",
    "required_structured_log_fields drifted",
)

sections = artifact.get("checklist_sections", [])
section_ids = [row.get("section_id") for row in sections if isinstance(row, dict)]
record(
    section_ids == REQUIRED_SECTIONS,
    "checklist_sections_complete",
    f"checklist_sections must exactly match required sections, got {section_ids}",
)

section_errors = []
for row in sections:
    if not isinstance(row, dict):
        section_errors.append("section row is not object")
        continue
    sid = row.get("section_id", "<missing>")
    if not non_empty_string_list(row.get("required_evidence")):
        section_errors.append(f"{sid}: required_evidence must be a non-empty string list")
    if not isinstance(row.get("closure_rule"), str) or not row.get("closure_rule"):
        section_errors.append(f"{sid}: closure_rule must be non-empty")
record(not section_errors, "checklist_section_shape", f"section errors: {section_errors}")

branches = artifact.get("branch_dispatch", [])
branches_by_id = {
    row.get("branch_id"): row
    for row in branches
    if isinstance(row, dict) and isinstance(row.get("branch_id"), str)
}
record(
    list(branches_by_id) == REQUIRED_BRANCHES,
    "branch_coverage",
    f"branch_dispatch must exactly cover {REQUIRED_BRANCHES}, got {list(branches_by_id)}",
)
record(len(branches_by_id) == len(branches), "unique_branches", "branch identifiers must be unique")

branch_errors = []
for branch_id in REQUIRED_BRANCHES:
    branch = branches_by_id.get(branch_id)
    if not branch:
        continue
    for field in (
        "tracker_state",
        "dependency_state",
        "workstream",
        "target_dir",
        "failure_signature",
        "next_safe_action",
    ):
        if not isinstance(branch.get(field), str) or not branch.get(field):
            branch_errors.append(f"{branch_id}: {field} must be non-empty")
    for field in ("commands", "required_tests", "required_e2e", "artifact_refs"):
        if not non_empty_string_list(branch.get(field)):
            branch_errors.append(f"{branch_id}: {field} must be a non-empty string list")
    decision, signature = closure_decision(branch)
    if decision != "close_allowed":
        branch_errors.append(f"{branch_id}: positive branch must allow closure, got {signature}")
record(not branch_errors, "branch_shape_and_positive_tests", f"branch errors: {branch_errors}")

blob = json.dumps(artifact, sort_keys=True)
missing_phrases = [phrase for phrase in REQUIRED_COMMAND_PHRASES if phrase not in blob]
record(not missing_phrases, "required_command_coverage", f"missing required command phrases: {missing_phrases}")

transcripts = artifact.get("dry_run_transcripts", [])
transcript_ids = {row.get("scenario_id") for row in transcripts if isinstance(row, dict)}
record(
    {"clean_ready_handoff", "stale_tracker_handoff"} <= transcript_ids,
    "required_transcripts_present",
    "dry_run_transcripts must include clean_ready_handoff and stale_tracker_handoff",
)

transcript_errors = []
for transcript in transcripts:
    if not isinstance(transcript, dict):
        transcript_errors.append("transcript row is not object")
        continue
    scenario = transcript.get("scenario_id", "<missing>")
    if transcript.get("branch_id") not in branches_by_id:
        transcript_errors.append(f"{scenario}: branch_id is unknown")
    row_errors = validate_log_payload(transcript_to_log_row(artifact, transcript, "source-commit-placeholder"))
    transcript_errors.extend(f"{scenario}: {error}" for error in row_errors)
    commands = transcript.get("commands")
    if not isinstance(commands, list) or len(commands) < 3:
        transcript_errors.append(f"{scenario}: commands must include at least three deterministic steps")
    else:
        for command in commands:
            for field in ("command", "exit_status", "expected", "actual", "failure_signature"):
                if field not in command:
                    transcript_errors.append(f"{scenario}: command missing {field}")
        if transcript.get("next_safe_action") in ("ask_user_to_decide", "", None):
            transcript_errors.append(f"{scenario}: next_safe_action must not ask the user to decide")
record(not transcript_errors, "dry_run_transcripts_valid", f"transcript errors: {transcript_errors}")

negative_errors = []
negative_results = []
for case in artifact.get("negative_test_cases", []):
    branch = branches_by_id.get(case.get("branch_id"))
    if not branch:
        negative_errors.append(f"{case.get('case_id')}: unknown branch")
        continue
    mutated = mutate_branch(branch, case.get("mutation"))
    decision, signature = closure_decision(mutated)
    result = {
        "case_id": case.get("case_id"),
        "expected_decision": case.get("expected_decision"),
        "actual_decision": decision,
        "expected_failure_signature": case.get("failure_signature"),
        "actual_failure_signature": signature,
    }
    negative_results.append(result)
    if decision != case.get("expected_decision"):
        negative_errors.append(f"{case.get('case_id')}: expected {case.get('expected_decision')}, got {decision}")
    if signature != case.get("failure_signature"):
        negative_errors.append(f"{case.get('case_id')}: expected signature {case.get('failure_signature')}, got {signature}")
record(
    len(negative_results) >= 3 and not negative_errors,
    "negative_tests_block_closure",
    f"negative test failures: {negative_errors}",
)

contract = artifact.get("closure_contract", {})
generated_artifacts = contract.get("generated_artifacts", [])
record(
    "tests/conformance/agent_handoff_checklist.v1.json" in generated_artifacts
    and "target/conformance/agent_handoff_checklist.report.json" in generated_artifacts
    and "target/conformance/agent_handoff_checklist.log.jsonl" in generated_artifacts,
    "generated_artifacts_declared",
    "closure_contract must declare canonical and generated artifact paths",
)
record(
    "not reverted" in contract.get("unrelated_changes_note", ""),
    "unrelated_change_policy_declared",
    "closure_contract must say unrelated changes were not reverted",
)

commit = source_commit()
log_rows = []
for branch_id in REQUIRED_BRANCHES:
    if branch_id in branches_by_id:
        log_rows.append(branch_to_log_row(artifact, branches_by_id[branch_id], commit))
for transcript in transcripts:
    if isinstance(transcript, dict):
        log_rows.append(transcript_to_log_row(artifact, transcript, commit))

log_errors = []
for row in log_rows:
    log_errors.extend(validate_log_payload(row))
record(not log_errors, "generated_log_rows_valid", f"log row errors: {log_errors}")

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.12",
    "generated_at_utc": utc_now(),
    "trace_id": artifact.get("trace_id", "unknown"),
    "source_commit": commit,
    "status": status,
    "checks": checks,
    "branch_count": len(branches_by_id),
    "section_count": len(section_ids),
    "dry_run_transcripts": sorted(transcript_ids),
    "negative_test_results": negative_results,
    "artifact_refs": [rel(artifact_path), rel(report_path), rel(log_path)],
    "target_dir": rel(out_dir),
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as handle:
    for row in log_rows:
        handle.write(json.dumps(row, sort_keys=True) + "\n")

if errors:
    print(f"agent_handoff_checklist: FAIL ({len(errors)} error(s))", file=sys.stderr)
    for error in errors:
        print(f"  {error}", file=sys.stderr)
    sys.exit(1)

print("agent_handoff_checklist: PASS")
print(f"report: {rel(report_path)}")
print(f"log: {rel(log_path)}")
PY
