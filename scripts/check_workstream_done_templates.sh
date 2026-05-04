#!/usr/bin/env bash
# check_workstream_done_templates.sh -- CI gate for bd-bp8fl.11
#
# Validates the reusable per-workstream definition-of-done templates and emits
# deterministic report/log artifacts. This gate is intentionally plan-space:
# it does not close implementation beads, but it blocks closure templates that
# lack tests, replay scenarios, structured logs, artifact freshness rules, or
# user-facing claim gates.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FLC_WORKSTREAM_DONE_TEMPLATES:-${ROOT}/tests/conformance/workstream_done_templates.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/workstream_done_templates.report.json"
LOG="${OUT_DIR}/workstream_done_templates.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

errors = []
checks = {}

required_workstreams = [
    "semantic_overlay",
    "tracker_repair",
    "feature_parity_audit",
    "fixture_packs",
    "hard_parts_parity",
    "replacement_levels",
    "validation_hygiene",
    "performance_optimization",
    "formal_runtime_math_evidence",
    "user_workload_diagnostics",
]

required_template_sections = [
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

required_log_fields = [
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

required_handoff_sections = [
    "onboarding_docs",
    "br_ready_list_show_state",
    "bv_robot_triage_insights",
    "dependency_and_parent_checks",
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

required_handoff_commands = [
    "br --no-db ready --json",
    "br --no-db list --status open --json",
    "br --no-db list --status in_progress --json",
    "br --no-db show <bead-id> --json",
    "br --no-db update <bead-id> --status=in_progress --json",
    "bv --robot-triage",
    "bv --robot-insights",
]

required_handoff_log_fields = [
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

required_handoff_branch_ids = [
    "normal_tracker_state",
    "stale_tracker_state",
    "no_db_fallback",
    "already_shipped_but_open_dotted_id",
    "unrelated_dirty_files",
    "pre_existing_workspace_failures",
    "blocked_bead",
]


def rel(path):
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return str(path)


def load_json(path):
    try:
        with Path(path).open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        errors.append(f"json_parse: failed to parse {path}: {exc}")
        return None


def sha256(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def git_head():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def non_empty_list(value):
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def record(condition, check_name, message):
    checks[check_name] = "pass" if condition else "fail"
    if not condition:
        errors.append(message)


artifact = load_json(artifact_path)
record(artifact is not None, "json_parse", "artifact must parse as JSON")

if isinstance(artifact, dict):
    record(
        artifact.get("schema_version") == "v1" and artifact.get("bead") == "bd-bp8fl.11",
        "artifact_identity",
        "artifact must declare schema_version=v1 and bead=bd-bp8fl.11",
    )
else:
    artifact = {}
    checks["artifact_identity"] = "fail"

declared_sections = artifact.get("required_template_sections", [])
record(
    declared_sections == required_template_sections,
    "section_contract_declared",
    f"required_template_sections must exactly match {required_template_sections}",
)

declared_log_fields = artifact.get("required_structured_log_fields", [])
record(
    declared_log_fields == required_log_fields,
    "structured_log_contract_declared",
    f"required_structured_log_fields must exactly match {required_log_fields}",
)

templates = artifact.get("templates", [])
templates_by_workstream = {
    row.get("workstream"): row
    for row in templates
    if isinstance(row, dict) and isinstance(row.get("workstream"), str)
}
record(
    sorted(templates_by_workstream) == sorted(required_workstreams),
    "required_workstream_coverage",
    f"templates must cover exactly {required_workstreams}, got {sorted(templates_by_workstream)}",
)
record(
    len(templates_by_workstream) == len(templates),
    "unique_workstream_templates",
    "template workstream identifiers must be unique and non-empty",
)

section_failures = []
command_failures = []
for workstream in required_workstreams:
    template = templates_by_workstream.get(workstream)
    if not template:
        continue
    for section in required_template_sections:
        if not non_empty_list(template.get(section)):
            section_failures.append(f"{workstream}:{section}")
    template_log_fields = template.get("structured_log_fields", [])
    if template_log_fields != required_log_fields:
        section_failures.append(f"{workstream}:structured_log_fields")
    commands = "\n".join(template.get("closure_commands", []))
    if "ubs <changed-files>" not in commands:
        command_failures.append(f"{workstream}:missing_ubs")
    if "br --no-db close <bead-id>" not in commands:
        command_failures.append(f"{workstream}:missing_no_db_close")
    if "rch exec -- cargo" not in commands and workstream not in {"tracker_repair"}:
        command_failures.append(f"{workstream}:missing_rch_cargo")

record(
    not section_failures,
    "template_sections_complete",
    f"template sections missing or malformed: {section_failures}",
)
record(
    not command_failures,
    "closure_commands_complete",
    f"closure command contract failures: {command_failures}",
)

examples = artifact.get("dry_run_examples", [])
example_workstreams = {
    row.get("workstream")
    for row in examples
    if isinstance(row, dict) and isinstance(row.get("workstream"), str)
}
example_outcomes = {
    row.get("expected_outcome")
    for row in examples
    if isinstance(row, dict) and isinstance(row.get("expected_outcome"), str)
}
record(
    isinstance(examples, list) and len(examples) >= 3 and len(example_workstreams) >= 3,
    "dry_run_examples_cover_multiple_workstreams",
    "dry_run_examples must include at least three examples across at least three workstreams",
)
record(
    {"close_allowed", "close_blocked"} <= example_outcomes,
    "dry_run_examples_cover_pass_and_block",
    "dry_run_examples must include close_allowed and close_blocked outcomes",
)

scenario_errors = []
for section_name in ("dry_run_examples", "checklist_replay_scenarios"):
    for row in artifact.get(section_name, []):
        if not isinstance(row, dict):
            scenario_errors.append(f"{section_name}: row is not object")
            continue
        scenario = row.get("scenario_id", "<missing>")
        workstream = row.get("workstream")
        if workstream not in templates_by_workstream:
            scenario_errors.append(f"{section_name}:{scenario}: unknown workstream {workstream}")
        required = row.get("required_evidence", [])
        present = row.get("present_evidence", [])
        missing = row.get("missing_evidence", [])
        outcome = row.get("expected_outcome")
        if not isinstance(required, list) or not required:
            scenario_errors.append(f"{section_name}:{scenario}: required_evidence must be non-empty")
        if not isinstance(present, list):
            scenario_errors.append(f"{section_name}:{scenario}: present_evidence must be a list")
        if not isinstance(missing, list):
            scenario_errors.append(f"{section_name}:{scenario}: missing_evidence must be a list")
        if outcome == "close_allowed" and missing:
            scenario_errors.append(f"{section_name}:{scenario}: close_allowed cannot have missing evidence")
        if outcome == "close_blocked" and not missing:
            scenario_errors.append(f"{section_name}:{scenario}: close_blocked must name missing evidence")
        if outcome not in {"close_allowed", "close_blocked"}:
            scenario_errors.append(f"{section_name}:{scenario}: unexpected expected_outcome {outcome}")

record(
    not scenario_errors,
    "checklist_replay_is_fail_closed",
    f"checklist replay scenarios are malformed: {scenario_errors}",
)

policy = artifact.get("claim_policy", {})
record(
    all(policy.get(key) is True for key in [
        "templates_are_minimums_not_scope_reductions",
        "missing_required_evidence_blocks_closure",
        "user_facing_claims_require_current_machine_evidence",
        "known_limitations_must_be_recorded_not_hidden",
    ]),
    "claim_policy_preserves_ambition",
    "claim_policy must preserve ambition and fail closed on missing evidence",
)

handoff = artifact.get("implementation_handoff_checklist", {})
handoff_errors = []
handoff_transcript_errors = []
if not isinstance(handoff, dict):
    handoff_errors.append("implementation_handoff_checklist must be an object")
else:
    if handoff.get("bead") != "bd-bp8fl.12":
        handoff_errors.append("implementation_handoff_checklist.bead must be bd-bp8fl.12")
    if handoff.get("required_sections") != required_handoff_sections:
        handoff_errors.append("handoff required_sections must match the pre-claim contract")
    if handoff.get("required_br_bv_commands") != required_handoff_commands:
        handoff_errors.append("handoff required_br_bv_commands must list exact no-db br and robot bv commands")
    if handoff.get("required_log_fields") != required_handoff_log_fields:
        handoff_errors.append("handoff required_log_fields must include tracker/dependency/next_safe_action fields")
    handoff_policy = handoff.get("policy", {})
    for key in [
        "one_bead_at_a_time",
        "no_idle_on_stale_tracker",
        "unrelated_dirty_files_are_preserved",
        "bare_cargo_forbidden",
        "rch_exec_cargo_required",
        "workspace_cargo_gates_forbidden_by_default",
        "agent_name_required_for_commit_push",
    ]:
        if handoff_policy.get(key) is not True:
            handoff_errors.append(f"handoff policy {key} must be true")

    branches = handoff.get("branches", [])
    branches_by_id = {
        row.get("branch_id"): row
        for row in branches
        if isinstance(row, dict) and isinstance(row.get("branch_id"), str)
    }
    if sorted(branches_by_id) != sorted(required_handoff_branch_ids):
        handoff_errors.append(
            f"handoff branches must cover {required_handoff_branch_ids}, got {sorted(branches_by_id)}"
        )
    if len(branches_by_id) != len(branches):
        handoff_errors.append("handoff branch identifiers must be unique and non-empty")
    for branch_id in required_handoff_branch_ids:
        branch = branches_by_id.get(branch_id)
        if not branch:
            continue
        for key in [
            "dependency_state",
            "tracker_state",
            "workstream",
            "next_safe_action",
            "source_commit_policy",
            "target_dir_policy",
            "commit_push_expectations",
            "closure_notes",
            "failure_signature",
        ]:
            if not isinstance(branch.get(key), str) or not branch.get(key):
                handoff_errors.append(f"{branch_id}: {key} must be a non-empty string")
        for key in ["pre_claim_checks", "required_tests", "required_e2e", "artifact_refs"]:
            if not non_empty_list(branch.get(key)):
                handoff_errors.append(f"{branch_id}: {key} must be a non-empty string list")
        action = str(branch.get("next_safe_action", "")).lower()
        if "idle" in action or "pause" in action or "ask user" in action:
            handoff_errors.append(f"{branch_id}: next_safe_action must proceed or surface concrete blockers")

    transcripts = handoff.get("dry_run_transcripts", [])
    transcript_ids = {
        row.get("scenario_id")
        for row in transcripts
        if isinstance(row, dict) and isinstance(row.get("scenario_id"), str)
    }
    if len(transcripts) < 2 or not {"clean_ready_handoff", "stale_tracker_handoff"} <= transcript_ids:
        handoff_transcript_errors.append("handoff dry_run_transcripts must include clean_ready_handoff and stale_tracker_handoff")
    for row in transcripts:
        if not isinstance(row, dict):
            handoff_transcript_errors.append("handoff transcript row must be an object")
            continue
        scenario = row.get("scenario_id", "<missing>")
        for key in [
            "bead_id",
            "dependency_state",
            "tracker_state",
            "workstream",
            "source_commit",
            "target_dir",
            "failure_signature",
            "next_safe_action",
        ]:
            if not isinstance(row.get(key), str) or not row.get(key):
                handoff_transcript_errors.append(f"{scenario}: {key} must be a non-empty string")
        for key in ["commands", "observations", "required_tests", "required_e2e", "artifact_refs"]:
            if not non_empty_list(row.get(key)):
                handoff_transcript_errors.append(f"{scenario}: {key} must be a non-empty string list")
        action = str(row.get("next_safe_action", "")).lower()
        if "idle" in action or "pause" in action or "ask user" in action:
            handoff_transcript_errors.append(f"{scenario}: next_safe_action must not idle")

record(
    not handoff_errors,
    "implementation_handoff_checklist_complete",
    f"implementation handoff checklist is malformed: {handoff_errors}",
)
record(
    not handoff_transcript_errors,
    "handoff_transcripts_choose_next_safe_action",
    f"handoff transcripts are malformed: {handoff_transcript_errors}",
)

source_commit = git_head()
artifact_refs = [rel(artifact_path), rel(report_path), rel(log_path)]
status = "fail" if errors else "pass"
summary = {
    "template_count": len(templates_by_workstream),
    "dry_run_example_count": len(examples) if isinstance(examples, list) else 0,
    "checklist_replay_scenario_count": len(artifact.get("checklist_replay_scenarios", []))
    if isinstance(artifact.get("checklist_replay_scenarios", []), list)
    else 0,
    "blocked_replay_scenarios": sum(
        1
        for row in artifact.get("checklist_replay_scenarios", [])
        if isinstance(row, dict) and row.get("expected_outcome") == "close_blocked"
    ),
    "handoff_branch_count": len(handoff.get("branches", [])) if isinstance(handoff, dict) else 0,
    "handoff_transcript_count": len(handoff.get("dry_run_transcripts", []))
    if isinstance(handoff, dict)
    else 0,
}

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.11",
    "status": status,
    "artifact": rel(artifact_path),
    "artifact_sha256": sha256(artifact_path),
    "source_commit": source_commit,
    "checks": checks,
    "summary": summary,
    "errors": errors,
}

log_rows = []
seq = 1
for workstream in required_workstreams:
    template = templates_by_workstream.get(workstream, {})
    required = [
        "unit tests",
        "e2e/fixture/harness scripts",
        "structured logs",
        "artifact freshness",
        "user-facing claim gates",
        "closure commands",
        "known limitations policy",
    ]
    present = [
        key
        for key in [
            "required_unit_test_classes",
            "required_e2e_fixture_harness_scripts",
            "structured_log_fields",
            "artifact_freshness_rules",
            "user_facing_claim_gates",
            "closure_commands",
            "known_limitations_policy",
        ]
        if non_empty_list(template.get(key))
    ]
    missing = []
    if len(present) != len(required):
        missing = sorted(set([
            "required_unit_test_classes",
            "required_e2e_fixture_harness_scripts",
            "structured_log_fields",
            "artifact_freshness_rules",
            "user_facing_claim_gates",
            "closure_commands",
            "known_limitations_policy",
        ]) - set(present))
    log_rows.append(
        {
            "timestamp": "2026-05-03T00:00:00.000Z",
            "trace_id": f"bd-bp8fl.11::workstream_done_templates::{seq:03d}",
            "level": "info" if not missing else "error",
            "event": "workstream_done_template",
            "bead_id": "bd-bp8fl.11",
            "workstream": workstream,
            "scenario_id": f"{workstream}_template",
            "required_evidence": required,
            "present_evidence": present,
            "missing_evidence": missing,
            "artifact_refs": artifact_refs,
            "source_commit": source_commit,
            "target_dir": rel(report_path.parent),
            "failure_signature": "none" if not missing else "template_missing_required_evidence",
            "outcome": "pass" if not missing else "fail",
        }
    )
    seq += 1

for row in artifact.get("checklist_replay_scenarios", []):
    if not isinstance(row, dict):
        continue
    missing = row.get("missing_evidence", [])
    log_rows.append(
        {
            "timestamp": "2026-05-03T00:00:00.000Z",
            "trace_id": f"bd-bp8fl.11::workstream_done_templates::{seq:03d}",
            "level": "info" if not missing else "warn",
            "event": "workstream_done_checklist_replay",
            "bead_id": "bd-bp8fl.11",
            "workstream": row.get("workstream", "unknown"),
            "scenario_id": row.get("scenario_id", "unknown"),
            "required_evidence": row.get("required_evidence", []),
            "present_evidence": row.get("present_evidence", []),
            "missing_evidence": missing,
            "artifact_refs": artifact_refs,
            "source_commit": source_commit,
            "target_dir": rel(report_path.parent),
            "failure_signature": "none" if not missing else "done_checklist_missing_evidence",
            "outcome": row.get("expected_outcome", "unknown"),
        }
    )
    seq += 1

for branch in handoff.get("branches", []) if isinstance(handoff, dict) else []:
    if not isinstance(branch, dict):
        continue
    log_rows.append(
        {
            "timestamp": "2026-05-03T00:00:00.000Z",
            "trace_id": f"bd-bp8fl.12::implementation_handoff::{seq:03d}",
            "level": "info" if branch.get("failure_signature") == "none" else "warn",
            "event": "implementation_handoff_branch",
            "bead_id": "bd-bp8fl.12",
            "workstream": branch.get("workstream", "unknown"),
            "scenario_id": branch.get("branch_id", "unknown"),
            "dependency_state": branch.get("dependency_state", "unknown"),
            "tracker_state": branch.get("tracker_state", "unknown"),
            "required_evidence": branch.get("pre_claim_checks", []),
            "present_evidence": branch.get("artifact_refs", []),
            "missing_evidence": [],
            "required_tests": branch.get("required_tests", []),
            "required_e2e": branch.get("required_e2e", []),
            "artifact_refs": artifact_refs,
            "source_commit": source_commit,
            "target_dir": branch.get("target_dir_policy", rel(report_path.parent)),
            "failure_signature": branch.get("failure_signature", "unknown"),
            "next_safe_action": branch.get("next_safe_action", "unknown"),
            "outcome": "pass",
        }
    )
    seq += 1

for transcript in handoff.get("dry_run_transcripts", []) if isinstance(handoff, dict) else []:
    if not isinstance(transcript, dict):
        continue
    log_rows.append(
        {
            "timestamp": "2026-05-03T00:00:00.000Z",
            "trace_id": f"bd-bp8fl.12::implementation_handoff::{seq:03d}",
            "level": "info" if transcript.get("failure_signature") == "none" else "warn",
            "event": "implementation_handoff_transcript",
            "bead_id": "bd-bp8fl.12",
            "workstream": transcript.get("workstream", "unknown"),
            "scenario_id": transcript.get("scenario_id", "unknown"),
            "dependency_state": transcript.get("dependency_state", "unknown"),
            "tracker_state": transcript.get("tracker_state", "unknown"),
            "required_evidence": transcript.get("commands", []),
            "present_evidence": transcript.get("observations", []),
            "missing_evidence": [],
            "required_tests": transcript.get("required_tests", []),
            "required_e2e": transcript.get("required_e2e", []),
            "artifact_refs": artifact_refs,
            "source_commit": source_commit,
            "target_dir": transcript.get("target_dir", rel(report_path.parent)),
            "failure_signature": transcript.get("failure_signature", "unknown"),
            "next_safe_action": transcript.get("next_safe_action", "unknown"),
            "outcome": "pass",
        }
    )
    seq += 1

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as fh:
    for row in log_rows:
        fh.write(json.dumps(row, sort_keys=True) + "\n")

print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    sys.exit(1)
PY
