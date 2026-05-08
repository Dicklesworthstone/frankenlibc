#!/usr/bin/env bash
# check_workload_evidence_loop_handoff.sh -- machine-checkable workload loop recipe for bd-fp4tm.6
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RECIPE="${FRANKENLIBC_WORKLOAD_LOOP_HANDOFF_RECIPE:-${ROOT}/tests/conformance/workload_evidence_loop_handoff.v1.json}"
OUT_DIR="${FRANKENLIBC_WORKLOAD_LOOP_HANDOFF_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_WORKLOAD_LOOP_HANDOFF_REPORT:-${OUT_DIR}/workload_evidence_loop_handoff.report.json}"
LOG="${FRANKENLIBC_WORKLOAD_LOOP_HANDOFF_LOG:-${OUT_DIR}/workload_evidence_loop_handoff.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${RECIPE}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
recipe_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

BEAD_ID = "bd-fp4tm.6"
REQUIRED_STAGE_IDS = {"freshness", "reproducer", "latency_join", "dossier", "epic_closeout"}
REQUIRED_CLOSEOUT_FIELDS = {
    "bead_id",
    "commit",
    "pushed_main",
    "mirrored_master",
    "validation",
    "ubs_critical_count",
    "br_cycles_count",
    "bv_robot_triage_status",
    "next_ready",
    "reservations_released",
}
BARE_CARGO_RE = re.compile(r"(^|[;&|]\s*|\s)cargo\s+(build|check|test|clippy)\b")
BR_RE = re.compile(r"(^|\s)br\s+")
BV_RE = re.compile(r"(^|\s)bv(\s|$)")


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"recipe: handoff_missing_failure_signature: cannot read {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append("recipe: handoff_missing_failure_signature: recipe must be a JSON object")
        return {}
    return value


def string_field(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return value if isinstance(value, str) else ""


def list_of_dicts(row: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = row.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def list_of_strings(row: dict[str, Any], key: str) -> list[str]:
    value = row.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def command_strings(value: Any) -> list[str]:
    result: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str) and "command" in key:
                result.append(item)
            else:
                result.extend(command_strings(item))
    elif isinstance(value, list):
        for item in value:
            result.extend(command_strings(item))
    return result


errors: list[str] = []
recipe = load_json(recipe_path, errors)

if recipe.get("schema_version") != "v1":
    errors.append("recipe: handoff_missing_failure_signature: schema_version must be v1")
if recipe.get("bead") != BEAD_ID:
    errors.append(f"recipe: handoff_missing_failure_signature: bead must be {BEAD_ID}")

required_stage_ids = set(list_of_strings(recipe, "required_stage_ids")) or REQUIRED_STAGE_IDS
stage_rows = list_of_dicts(recipe, "stages")
stage_ids = {string_field(stage, "id") for stage in stage_rows if string_field(stage, "id")}
for stage_id in sorted(required_stage_ids):
    if stage_id not in stage_ids:
        errors.append(f"{stage_id}: handoff_missing_stage: required stage is absent")
for stage_id in sorted(REQUIRED_STAGE_IDS):
    if stage_id not in stage_ids:
        errors.append(f"{stage_id}: handoff_missing_stage: bead acceptance stage is absent")

log_rows: list[dict[str, Any]] = []
for stage in stage_rows:
    stage_id = string_field(stage, "id") or "<missing-stage>"
    validators = {
        string_field(validator, "id"): validator
        for validator in list_of_dicts(stage, "validators")
        if string_field(validator, "id")
    }
    if not validators:
        errors.append(f"{stage_id}: handoff_artifact_missing_validator: no validators declared")

    for validator_id, validator in validators.items():
        if not string_field(validator, "failure_signature"):
            errors.append(f"{stage_id}:{validator_id}: handoff_validator_missing_failure_signature: validator lacks failure_signature")
        if not string_field(validator, "command"):
            errors.append(f"{stage_id}:{validator_id}: handoff_missing_failure_signature: validator lacks command")

    for artifact in list_of_dicts(stage, "generated_artifacts"):
        artifact_path = string_field(artifact, "path")
        validator_id = string_field(artifact, "validator")
        failure_signature = string_field(artifact, "failure_signature")
        if not artifact_path:
            errors.append(f"{stage_id}: handoff_artifact_missing_validator: generated artifact lacks path")
        if not validator_id:
            errors.append(f"{stage_id}:{artifact_path}: handoff_artifact_missing_validator: artifact lacks validator")
        elif validator_id not in validators:
            errors.append(f"{stage_id}:{artifact_path}: handoff_artifact_unknown_validator: unknown validator {validator_id}")
        if not failure_signature:
            errors.append(f"{stage_id}:{artifact_path}: handoff_missing_failure_signature: artifact lacks failure_signature")

    log_rows.append(
        {
            "trace_id": f"{BEAD_ID}::{stage_id}",
            "bead_id": BEAD_ID,
            "stage_id": stage_id,
            "command": string_field(stage, "command"),
            "generated_artifact_count": len(list_of_dicts(stage, "generated_artifacts")),
            "validator_count": len(validators),
            "failure_signature": "none",
        }
    )

for lane in list_of_dicts(recipe, "cargo_validation_lanes"):
    if not string_field(lane, "failure_signature"):
        errors.append(f"{string_field(lane, 'id') or 'cargo_lane'}: handoff_missing_failure_signature: cargo lane lacks failure_signature")
    command = string_field(lane, "command")
    if "rch exec -- cargo" not in command:
        errors.append(f"{string_field(lane, 'id') or 'cargo_lane'}: handoff_bare_cargo_command: cargo lane must use rch exec -- cargo")

for command in command_strings(recipe):
    if BARE_CARGO_RE.search(command) and "rch exec -- cargo" not in command:
        errors.append(f"{command}: handoff_bare_cargo_command: bare cargo build/check/test/clippy is forbidden")
    if BR_RE.search(command) and "--no-db" not in command:
        errors.append(f"{command}: handoff_missing_no_db_command: br commands must use --no-db")
    if BV_RE.search(command) and "--robot-" not in command:
        errors.append(f"{command}: handoff_bare_bv_command: bv commands must use --robot-*")

agent_mail = recipe.get("agent_mail") if isinstance(recipe.get("agent_mail"), dict) else {}
reservations = list_of_strings(agent_mail, "required_reservations")
if ".beads/issues.jsonl" not in reservations:
    errors.append("agent_mail: handoff_missing_agent_mail_reservation: .beads/issues.jsonl reservation required")
if not reservations:
    errors.append("agent_mail: handoff_missing_agent_mail_reservation: no reservations declared")
for reservation in reservations:
    if any(marker in reservation for marker in ["*", "?", "["]):
        errors.append(f"{reservation}: handoff_missing_agent_mail_reservation: reservations must be exact paths")

structured_closeout = recipe.get("structured_closeout") if isinstance(recipe.get("structured_closeout"), dict) else {}
closeout_fields = set(list_of_strings(structured_closeout, "required_fields"))
for field in sorted(REQUIRED_CLOSEOUT_FIELDS):
    if field not in closeout_fields:
        errors.append(f"{field}: handoff_missing_closeout_field: structured closeout field missing")

failure_counts = Counter(error.split(": ", 2)[1] for error in errors if error.count(": ") >= 2)
report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "status": "pass" if not errors else "fail",
    "generated_at_utc": utc_now(),
    "source_commit": source_commit(),
    "recipe": rel(recipe_path),
    "summary": {
        "stage_count": len(stage_rows),
        "cargo_lane_count": len(list_of_dicts(recipe, "cargo_validation_lanes")),
        "reservation_count": len(reservations),
        "closeout_field_count": len(closeout_fields),
        "failure_signature_counts": dict(sorted(failure_counts.items())),
    },
    "required_stage_ids": sorted(required_stage_ids),
    "stage_ids": sorted(stage_ids),
    "errors": errors,
    "artifact_refs": [
        rel(recipe_path),
        rel(log_path),
    ],
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if report["status"] == "pass" else 1)
PY
