#!/usr/bin/env bash
# check_changed_surface_validation_checklist.sh -- gate for bd-bp8fl.7.4
#
# Validates the changed-surface closure checklist artifact and emits a
# deterministic report plus JSONL log rows. The gate checks the checklist
# contract; cargo/rch commands are recorded as closure evidence and run by the
# bead owner.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_CHANGED_SURFACE_VALIDATION_CHECKLIST:-${ROOT}/tests/conformance/changed_surface_validation_checklist.v1.json}"
OUT_DIR="${FRANKENLIBC_CHANGED_SURFACE_VALIDATION_TARGET_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_CHANGED_SURFACE_VALIDATION_REPORT:-${OUT_DIR}/changed_surface_validation_checklist.report.json}"
LOG="${FRANKENLIBC_CHANGED_SURFACE_VALIDATION_LOG:-${OUT_DIR}/changed_surface_validation_checklist.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" <<'PY'
import json
import subprocess
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
target_dir = sys.argv[5]

BEAD = "bd-bp8fl.7.4"
TRACE_ID = "bd-bp8fl-7-4-changed-surface-validation-checklist-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "changed_file",
    "validation_command",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_CHANGED_FILES = {
    ".beads/issues.jsonl",
    "crates/frankenlibc-harness/tests/changed_surface_validation_checklist_test.rs",
    "scripts/check_changed_surface_validation_checklist.sh",
    "tests/conformance/changed_surface_validation_checklist.v1.json",
}
REQUIRED_SCENARIOS = {
    "complete",
    "missing_changed_file",
    "missing_targeted_test",
    "stale_artifact",
    "skipped_ubs_without_justification",
    "missing_unrelated_failure_note",
    "missing_log_artifact_refs",
}


def now_utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def current_commit():
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


def rel(path):
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def nonempty_list(value):
    return isinstance(value, list) and any(str(item).strip() for item in value)


def nonempty_string(value):
    return isinstance(value, str) and bool(value.strip())


def commands_for(row):
    commands = []
    for key in [
        "targeted_cargo_commands",
        "fixture_e2e_scripts",
        "artifact_regeneration_commands",
        "br_bv_commands",
    ]:
        value = row.get(key, [])
        if isinstance(value, list):
            commands.extend(str(item) for item in value if str(item).strip())
    if nonempty_string(row.get("ubs_command")):
        commands.append(str(row["ubs_command"]))
    return commands


errors = []
logs = []

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
if artifact.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_log_fields mismatch")

freshness = artifact.get("artifact_freshness", {})
if not isinstance(freshness, dict):
    errors.append("artifact_freshness must be an object")
    freshness = {}
if freshness.get("freshness_state") != "current":
    errors.append("changed_surface_stale_artifact: freshness_state must be current")
if not nonempty_string(freshness.get("source_commit")):
    errors.append("changed_surface_stale_artifact: source_commit must be present")

declared_required = artifact.get("required_changed_files", [])
if set(str(item) for item in declared_required if str(item).strip()) != REQUIRED_CHANGED_FILES:
    errors.append("required_changed_files mismatch")

rows = artifact.get("changed_files")
if not isinstance(rows, list) or not rows:
    errors.append("changed_files must be a non-empty array")
    rows = []

rows_by_file = {}
for idx, row in enumerate(rows):
    context = f"changed_files[{idx}]"
    changed_file = str(row.get("changed_file", "")).strip()
    if not changed_file:
        errors.append(f"{context}: changed_file missing")
        continue
    if changed_file in rows_by_file:
        errors.append(f"{context}: duplicate changed_file {changed_file}")
    rows_by_file[changed_file] = row

    if changed_file.startswith("/") or ".." in Path(changed_file).parts:
        errors.append(f"{context}: changed_file must stay repo-relative")
    if not nonempty_list(row.get("affected_crates")):
        errors.append(f"{changed_file}: affected_crates missing")
    if not nonempty_list(row.get("targeted_cargo_commands")) and not nonempty_string(
        row.get("targeted_cargo_skip_justification")
    ):
        errors.append(f"{changed_file}: changed_surface_missing_targeted_cargo")
    if not nonempty_string(row.get("ubs_command")) and not nonempty_string(
        row.get("ubs_skip_justification")
    ):
        errors.append(f"{changed_file}: changed_surface_missing_ubs")
    if not nonempty_list(row.get("fixture_e2e_scripts")) and not nonempty_string(
        row.get("fixture_e2e_skip_justification")
    ):
        errors.append(f"{changed_file}: fixture/e2e proof missing")
    if not nonempty_list(row.get("artifact_regeneration_commands")):
        errors.append(f"{changed_file}: artifact regeneration command missing")
    if not nonempty_list(row.get("br_bv_commands")):
        errors.append(f"{changed_file}: br/bv graph command missing")
    if not nonempty_string(row.get("unrelated_failure_note")):
        errors.append(f"{changed_file}: changed_surface_missing_unrelated_failure_note")
    if not nonempty_list(row.get("artifact_refs")):
        errors.append(f"{changed_file}: changed_surface_missing_artifact_refs")
    if not nonempty_string(row.get("source_commit")):
        errors.append(f"{changed_file}: source_commit missing")
    if not nonempty_string(row.get("target_dir")):
        errors.append(f"{changed_file}: target_dir missing")
    if not nonempty_string(row.get("failure_signature")):
        errors.append(f"{changed_file}: failure_signature missing")

missing_files = sorted(REQUIRED_CHANGED_FILES - set(rows_by_file))
if missing_files:
    errors.append(f"changed_surface_missing_changed_file: {missing_files}")

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
        "expected_decision",
        "expected_failure_signature",
    ]:
        if key not in scenario:
            errors.append(f"{context}.{key} missing")
    classification = scenario.get("classification")
    if isinstance(classification, str):
        scenario_classes.add(classification)

missing_scenarios = sorted(REQUIRED_SCENARIOS - scenario_classes)
if missing_scenarios:
    errors.append(f"missing fixture replay scenario classes: {missing_scenarios}")

for row in rows:
    changed_file = str(row.get("changed_file", "")).strip()
    if not changed_file:
        continue
    file_errors = [err for err in errors if changed_file in err]
    actual = "complete" if not file_errors else "; ".join(file_errors)
    failure_signature = row.get("failure_signature", "")
    if file_errors:
        failure_signature = "changed_surface_row_invalid"
    logs.append(
        {
            "timestamp": now_utc(),
            "trace_id": TRACE_ID,
            "bead_id": BEAD,
            "changed_file": changed_file,
            "validation_command": " && ".join(commands_for(row)),
            "expected": row.get("expected", ""),
            "actual": actual,
            "artifact_refs": row.get("artifact_refs", []),
            "source_commit": row.get("source_commit", freshness.get("source_commit", "unknown")),
            "target_dir": row.get("target_dir", target_dir),
            "failure_signature": failure_signature,
            "affected_crates": row.get("affected_crates", []),
            "owner_bead": row.get("owner_bead", BEAD),
            "unrelated_failure_note": row.get("unrelated_failure_note", ""),
        }
    )

for scenario in scenarios:
    logs.append(
        {
            "timestamp": now_utc(),
            "trace_id": TRACE_ID,
            "bead_id": BEAD,
            "changed_file": f"scenario:{scenario.get('scenario_id', 'unknown')}",
            "validation_command": "fixture replay classification",
            "expected": scenario.get("expected_decision", ""),
            "actual": scenario.get("classification", ""),
            "artifact_refs": [rel(artifact_path)],
            "source_commit": freshness.get("source_commit", "unknown"),
            "target_dir": target_dir,
            "failure_signature": scenario.get("expected_failure_signature", ""),
        }
    )

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": BEAD,
    "trace_id": TRACE_ID,
    "generated_at_utc": now_utc(),
    "status": status,
    "source_commit": current_commit(),
    "artifact_source_commit": freshness.get("source_commit", "unknown"),
    "target_dir": target_dir,
    "changed_file_count": len(rows),
    "required_changed_files": sorted(REQUIRED_CHANGED_FILES),
    "covered_changed_files": sorted(rows_by_file),
    "scenario_classes": sorted(scenario_classes),
    "artifact_refs": [rel(artifact_path), rel(log_path)],
    "next_safe_action": artifact.get("next_safe_action"),
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with log_path.open("w", encoding="utf-8") as log:
    for row in logs:
        log.write(json.dumps(row, sort_keys=True) + "\n")

if errors:
    print(f"FAIL: changed-surface validation checklist has {len(errors)} error(s)", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    sys.exit(1)

print(
    "OK: changed-surface validation checklist covers "
    f"{len(rows)} changed files and {len(scenarios)} replay scenarios"
)
print(f"Report: {report_path}")
print(f"Log: {log_path}")
PY
