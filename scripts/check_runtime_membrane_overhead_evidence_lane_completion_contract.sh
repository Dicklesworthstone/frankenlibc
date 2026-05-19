#!/usr/bin/env bash
# Replay and validate the runtime membrane overhead evidence lane closeout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/runtime_membrane_overhead_evidence_lane_completion_contract.v1.json}"
ISSUES="${FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_COMPLETION_ISSUES:-${ROOT}/.beads/issues.jsonl}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/runtime_membrane_overhead_completion}"
REPORT="${FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_COMPLETION_REPORT:-${OUT_DIR}/runtime_membrane_overhead_completion.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_COMPLETION_LOG:-${OUT_DIR}/runtime_membrane_overhead_completion.log.jsonl}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT}" "${ISSUES}" "${OUT_DIR}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
ISSUES = pathlib.Path(sys.argv[3])
OUT_DIR = pathlib.Path(sys.argv[4])
REPORT = pathlib.Path(sys.argv[5])
LOG = pathlib.Path(sys.argv[6])

EXPECTED_SCHEMA = "runtime_membrane_overhead_evidence_lane_completion_contract.v1"
BEAD = "bd-owqho"
LOCAL_FALLBACK_MARKERS = ["[RCH] local", "remote execution failed", "local fallback"]
REQUIRED_EVENTS = [
    "runtime_membrane_overhead_completion_children_verified",
    "runtime_membrane_overhead_completion_checkers_replayed",
    "runtime_membrane_overhead_completion_claim_policy_verified",
    "runtime_membrane_overhead_completion_rch_proof_verified",
    "runtime_membrane_overhead_completion_contract_validated",
]

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []
replay_reports: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def repo_path(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def add_error(signature: str, path: str, message: str) -> None:
    errors.append({"failure_signature": signature, "path": path, "message": message})


def add_event(event: str, details: dict[str, Any]) -> None:
    events.append({"event": event, "details": details})


def load_json(path: pathlib.Path, label: str) -> Any | None:
    if not path.exists():
        add_error("missing_evidence", label, f"missing file {rel(path)}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("invalid_json", label, f"invalid JSON in {rel(path)}: {exc}")
        return None


def load_issues(path: pathlib.Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        add_error("missing_evidence", ".beads/issues.jsonl", f"missing issues file {rel(path)}")
        return {}
    issues: dict[str, dict[str, Any]] = {}
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            add_error("invalid_json", f"{rel(path)}:{line_no}", f"invalid issue JSONL row: {exc}")
            continue
        if isinstance(row, dict) and isinstance(row.get("id"), str):
            issues[row["id"]] = row
    return issues


def has_local_fallback(value: Any) -> bool:
    if isinstance(value, str):
        return any(marker in value for marker in LOCAL_FALLBACK_MARKERS)
    if isinstance(value, list):
        return any(has_local_fallback(item) for item in value)
    if isinstance(value, dict):
        return any(has_local_fallback(item) for item in value.values())
    return False


def run_child_checker(child: dict[str, Any], artifact: pathlib.Path) -> dict[str, Any]:
    bead = str(child.get("bead"))
    checker = repo_path(str(child.get("checker_path", "")))
    out_dir = OUT_DIR / "replay" / bead
    out_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    if bead == "bd-e1eko":
        report_path = out_dir / "strict_hardened_membrane_overhead_budget.report.json"
        env.update(
            {
                "FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_EVIDENCE": str(artifact),
                "FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_OUT_DIR": str(out_dir),
                "FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_REPORT": str(report_path),
                "FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_LOG": str(out_dir / "strict_hardened_membrane_overhead_budget.log.jsonl"),
            }
        )
    elif bead == "bd-rakj1":
        report_path = out_dir / "tsm_contention_e2e_lane.report.json"
        env.update(
            {
                "FRANKENLIBC_TSM_CONTENTION_E2E_LANE": str(artifact),
                "FRANKENLIBC_TSM_CONTENTION_E2E_OUT_DIR": str(out_dir),
                "FRANKENLIBC_TSM_CONTENTION_E2E_REPORT": str(report_path),
                "FRANKENLIBC_TSM_CONTENTION_E2E_LOG": str(out_dir / "tsm_contention_e2e_lane.log.jsonl"),
            }
        )
    elif bead == "bd-hdflr":
        report_path = out_dir / "tsm_overhead_evidence_report.json"
        env.update(
            {
                "FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_MANIFEST": str(artifact),
                "FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_OUT_DIR": str(out_dir),
                "FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_JSON": str(report_path),
                "FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_MD": str(out_dir / "tsm_overhead_evidence_report.md"),
                "FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_LOG": str(out_dir / "tsm_overhead_evidence_report.log.jsonl"),
            }
        )
    else:
        report_path = out_dir / "unknown.report.json"

    proc = subprocess.run(
        ["bash", str(checker)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    replay = {
        "bead": bead,
        "checker": rel(checker),
        "exit_code": proc.returncode,
        "stdout": proc.stdout[-2000:],
        "stderr": proc.stderr[-2000:],
        "report": rel(report_path),
    }
    if proc.returncode != 0:
        add_error("checker_replay_failed", rel(checker), f"{bead} checker replay failed with exit {proc.returncode}")
    if report_path.exists():
        replay["report_json"] = load_json(report_path, f"{bead}.replay_report")
    else:
        add_error("missing_evidence", rel(report_path), f"{bead} checker did not emit replay report")
    return replay


def validate_strict_overhead(artifact: dict[str, Any], child: dict[str, Any], path: str) -> None:
    if artifact.get("schema_version") != child.get("artifact_schema"):
        add_error("invalid_contract", path, "strict/hardened overhead artifact schema mismatch")
    expected_failures = set(child.get("required_failure_signatures", []))
    observed_failures = set(artifact.get("required_failure_signatures", []))
    missing = sorted(expected_failures - observed_failures)
    if missing:
        add_error("negative_control_missing", path, f"strict/hardened artifact missing failure signatures {missing}")
    required_modes = set(artifact.get("required_modes", []))
    required_families = set(artifact.get("required_families", []))
    pairs = {
        (row.get("runtime_mode"), row.get("api_family"))
        for row in artifact.get("records", [])
        if isinstance(row, dict)
    }
    for mode in required_modes:
        for family in required_families:
            if (mode, family) not in pairs:
                add_error("missing_budget_row", path, f"missing strict/hardened row {mode}/{family}")
    if has_local_fallback(artifact):
        add_error("local_fallback_seen", path, "strict/hardened artifact contains local fallback marker")


def validate_contention(artifact: dict[str, Any], child: dict[str, Any], path: str) -> None:
    if artifact.get("schema_version") != child.get("artifact_schema"):
        add_error("invalid_contention_lane", path, "contention artifact schema mismatch")
    lanes = artifact.get("lanes", [])
    if not isinstance(lanes, list):
        add_error("invalid_contention_lane", path, "contention lanes must be an array")
        return
    by_id = {lane.get("id"): lane for lane in lanes if isinstance(lane, dict)}
    smoke = by_id.get("smoke_small_host")
    permissioned = by_id.get("permissioned_large_host")
    if not isinstance(smoke, dict) or not isinstance(permissioned, dict):
        add_error("invalid_contention_lane", path, "smoke and permissioned contention lanes are required")
        return
    if smoke.get("can_upgrade_public_readiness") is not False:
        add_error("smoke_claim_upgrade", path, "smoke lane must not upgrade public readiness")
    if permissioned.get("can_upgrade_public_readiness") is not True:
        add_error("invalid_contention_lane", path, "permissioned lane must be the only upgrade-capable lane")
    smoke_fixture = artifact.get("smoke_fixture", {})
    if not isinstance(smoke_fixture, dict) or smoke_fixture.get("can_upgrade_public_readiness") is not False or smoke_fixture.get("readiness_claim") != "shape_only":
        add_error("smoke_claim_upgrade", path, "smoke fixture must remain shape_only and non-upgrade")
    validation_commands = artifact.get("validation_commands", [])
    if isinstance(validation_commands, list) and has_local_fallback(validation_commands):
        add_error("local_fallback_seen", path, "contention validation command contains local fallback marker")


def validate_report_manifest(artifact: dict[str, Any], child: dict[str, Any], path: str) -> None:
    if artifact.get("schema_version") != child.get("artifact_schema"):
        add_error("invalid_contract", path, "reviewer report manifest schema mismatch")
    failures = set(artifact.get("fail_closed_signatures", []))
    missing = sorted(set(child.get("required_failure_signatures", [])) - failures)
    if missing:
        add_error("negative_control_missing", path, f"reviewer report missing fail-closed signatures {missing}")


contract = load_json(CONTRACT, "contract")
if not isinstance(contract, dict):
    contract = {}
    add_error("invalid_contract", "contract", "contract root must be object")
elif contract.get("schema_version") != EXPECTED_SCHEMA or contract.get("bead") != BEAD:
    add_error("invalid_contract", "contract", "unexpected runtime membrane overhead completion contract identity")

policy = contract.get("closure_policy", {})
if not isinstance(policy, dict):
    policy = {}
    add_error("invalid_contract", "closure_policy", "closure_policy must be object")
for key in [
    "child_beads_must_be_closed",
    "replay_child_checkers",
    "public_claim_must_remain_blocked_without_permissioned_evidence",
    "schema_golden_must_not_upgrade_public_claim",
    "smoke_evidence_must_not_upgrade_public_claim",
    "no_local_cargo_proof_counted",
    "br_dep_cycles_required_empty",
]:
    if policy.get(key) is not True:
        add_error("invalid_contract_policy", f"closure_policy.{key}", "completion policy boolean must be true")

issues = load_issues(ISSUES)
children = contract.get("child_artifacts", [])
if not isinstance(children, list) or not children:
    add_error("invalid_contract", "child_artifacts", "child_artifacts must be a non-empty array")
    children = []

children_verified = []
for index, child in enumerate(children):
    if not isinstance(child, dict):
        add_error("invalid_contract", f"child_artifacts[{index}]", "child artifact row must be object")
        continue
    bead = child.get("bead")
    if not isinstance(bead, str) or not bead:
        add_error("invalid_contract", f"child_artifacts[{index}].bead", "child bead id is required")
        continue
    issue = issues.get(bead)
    if policy.get("child_beads_must_be_closed") is True:
        if not issue:
            add_error("child_not_closed", bead, "child bead is missing from issues JSONL")
        elif issue.get("status") != child.get("status_required", "closed"):
            add_error("child_not_closed", bead, f"child bead status is {issue.get('status')!r}")
    artifact_path = repo_path(str(child.get("artifact_path", "")))
    checker_path = repo_path(str(child.get("checker_path", "")))
    test_path = repo_path(str(child.get("test_path", "")))
    artifact = load_json(artifact_path, f"{bead}.artifact")
    if not checker_path.exists():
        add_error("missing_evidence", rel(checker_path), f"{bead} checker path is missing")
    if not test_path.exists():
        add_error("missing_evidence", rel(test_path), f"{bead} test path is missing")
    if isinstance(artifact, dict):
        if bead == "bd-e1eko":
            validate_strict_overhead(artifact, child, rel(artifact_path))
        elif bead == "bd-rakj1":
            validate_contention(artifact, child, rel(artifact_path))
        elif bead == "bd-hdflr":
            validate_report_manifest(artifact, child, rel(artifact_path))
    children_verified.append({"bead": bead, "artifact": rel(artifact_path), "checker": rel(checker_path), "test": rel(test_path)})

add_event("runtime_membrane_overhead_completion_children_verified", {"children": len(children_verified)})

commands = contract.get("required_remote_validation_commands", [])
if not isinstance(commands, list) or not commands:
    add_error("missing_rch_remote", "required_remote_validation_commands", "remote validation command list is required")
    commands = []
for index, command in enumerate(commands):
    if not isinstance(command, str):
        add_error("missing_rch_remote", f"required_remote_validation_commands[{index}]", "command must be string")
        continue
    if "RCH_REQUIRE_REMOTE=1" not in command or "rch exec -- cargo" not in command:
        add_error("missing_rch_remote", f"required_remote_validation_commands[{index}]", "command must use RCH_REQUIRE_REMOTE=1 rch exec -- cargo")
    if has_local_fallback(command):
        add_error("local_fallback_seen", f"required_remote_validation_commands[{index}]", "command contains local fallback marker")
for required in ["cargo test", "cargo check", "cargo clippy"]:
    if not any(required in command for command in commands if isinstance(command, str)):
        add_error("missing_rch_remote", "required_remote_validation_commands", f"missing {required} proof command")
add_event("runtime_membrane_overhead_completion_rch_proof_verified", {"commands": len(commands)})

if policy.get("replay_child_checkers") is True:
    for child in children:
        if not isinstance(child, dict):
            continue
        artifact_path = repo_path(str(child.get("artifact_path", "")))
        checker_path = repo_path(str(child.get("checker_path", "")))
        if artifact_path.exists() and checker_path.exists():
            replay_reports.append(run_child_checker(child, artifact_path))
add_event("runtime_membrane_overhead_completion_checkers_replayed", {"replays": len(replay_reports)})

report_replay = next((row for row in replay_reports if row.get("bead") == "bd-hdflr"), {})
report_json = report_replay.get("report_json")
if isinstance(report_json, dict):
    if report_json.get("status") != "pass":
        add_error("checker_replay_failed", "bd-hdflr.report", "reviewer report replay did not pass")
    if report_json.get("public_claim_allowed") is not False:
        add_error("public_claim_upgrade", "bd-hdflr.report.public_claim_allowed", "partial evidence must not allow public performance claim")
    blockers = set(str(item) for item in report_json.get("claim_blockers", []))
    expected_blockers = set(str(item) for item in contract.get("claim_blockers_expected_without_live_permissioned_evidence", []))
    missing_blockers = sorted(expected_blockers - blockers)
    if missing_blockers:
        add_error("public_claim_upgrade", "bd-hdflr.report.claim_blockers", f"missing expected claim blockers {missing_blockers}")
    checklist = {row.get("id"): row for row in report_json.get("reviewer_checklist", []) if isinstance(row, dict)}
    if checklist.get("permissioned_large_host_evidence_present", {}).get("status") != "block":
        add_error("public_claim_upgrade", "bd-hdflr.report.reviewer_checklist", "permissioned evidence checklist item must block")
    if checklist.get("current_source_for_public_claims", {}).get("status") != "block":
        add_error("public_claim_upgrade", "bd-hdflr.report.reviewer_checklist", "current source checklist item must block schema-golden evidence")
else:
    add_error("missing_evidence", "bd-hdflr.report", "reviewer report replay JSON missing")
add_event("runtime_membrane_overhead_completion_claim_policy_verified", {"public_claim_allowed": False})

expected_events = contract.get("structured_log_events", [])
if expected_events != REQUIRED_EVENTS:
    add_error("invalid_contract", "structured_log_events", "structured log events must match completion contract event order")
add_event("runtime_membrane_overhead_completion_contract_validated", {"status": "pass" if not errors else "fail"})

status = "pass" if not errors else "fail"
report = {
    "schema_version": "runtime_membrane_overhead_evidence_lane_completion_contract.report.v1",
    "bead": BEAD,
    "generated_at_utc": utc_now(),
    "contract": rel(CONTRACT),
    "issues": rel(ISSUES),
    "status": status,
    "children_verified": children_verified,
    "replay_reports": replay_reports,
    "events": events,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_rows = []
for index, event in enumerate(events, start=1):
    log_rows.append(
        {
            "timestamp": utc_now(),
            "trace_id": f"{BEAD}::runtime_membrane_overhead_completion::{index:03d}",
            "level": "info" if status == "pass" else "error",
            "event": event["event"],
            "bead_id": BEAD,
            "stream": "release",
            "gate": "runtime_membrane_overhead_completion",
            "outcome": "pass" if status == "pass" else "fail",
            "failure_signature": "none" if status == "pass" else errors[0]["failure_signature"],
            "source_commit": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
            "artifact_refs": [rel(REPORT)],
            "details": event["details"],
        }
    )
LOG.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in log_rows), encoding="utf-8")

print(json.dumps({"status": status, "children": len(children_verified), "replays": len(replay_reports)}, sort_keys=True))
if errors:
    raise SystemExit(1)
PY
