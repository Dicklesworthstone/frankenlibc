#!/usr/bin/env bash
# check_tracker_health_report.sh -- deterministic tracker-health replay gate for bd-bp8fl.2.3
#
# Replays tracker-health scenarios from the conformance artifact and emits a
# report plus JSONL command log. The gate separates tracker/tooling failures
# from code/evidence failures so JSONL-visible work cannot be hidden by stale
# DB, bv, or dashboard state.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_TRACKER_HEALTH_ARTIFACT:-${ROOT}/tests/conformance/tracker_health_report.v1.json}"
OUT_DIR="${FRANKENLIBC_TRACKER_HEALTH_TARGET_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_TRACKER_HEALTH_REPORT:-${OUT_DIR}/tracker_health_report.report.json}"
LOG="${FRANKENLIBC_TRACKER_HEALTH_LOG:-${OUT_DIR}/tracker_health_report.log.jsonl}"
MODE="${1:---fixture-replay}"

case "${MODE}" in
  --fixture-replay|--validate-only)
    ;;
  *)
    echo "usage: $0 [--fixture-replay|--validate-only]" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
mode = sys.argv[5]

errors = []

REQUIRED_REPORT_FIELDS = [
    "schema_version",
    "bead",
    "generated_at_utc",
    "trace_id",
    "source_commit",
    "status",
    "scenario_count",
    "scenario_results",
    "summary",
    "artifact_refs",
]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "command",
    "exit_status",
    "duration_ms",
    "tracker_state",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"FAIL: cannot load {path}: {exc}", file=sys.stderr)
        sys.exit(1)


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


def classify(snapshot, commands):
    signatures = {cmd.get("failure_signature") for cmd in commands}
    exit_statuses = [cmd.get("exit_status") for cmd in commands]
    if "timeout" in signatures or 124 in exit_statuses:
        return "tool_timeout"
    if snapshot.get("exact_id_split_brain") or "exact_id_split_brain" in signatures:
        return "split_brain"
    if snapshot.get("cycles_count") not in (0, None):
        return "graph_failure"
    if (
        snapshot.get("stale_blocked_cache")
        or snapshot.get("jsonl_records") != snapshot.get("db_records")
        or "conflicting_ready_lists" in signatures
        or (
            snapshot.get("open_count", 0) not in (0, None)
            and snapshot.get("br_ready_count") == 0
            and snapshot.get("bv_open_count") == 0
        )
    ):
        return "tracker_failure"
    return "healthy"


def next_safe_action(state, snapshot):
    if state == "healthy":
        return "continue_claimable_jsonl_beads"
    if state == "tool_timeout":
        return "retry_with_tighter_scope_or_no_db_show"
    if state == "split_brain":
        return "prefer_br_no_db_show_for_named_bead_and_file_tracker_bug"
    if state == "graph_failure":
        return "fix_dependency_cycles_before_claiming"
    if snapshot.get("open_count", 0) not in (0, None) and snapshot.get("br_ready_count") == 0:
        return "show_open_jsonl_beads_to_agents"
    if snapshot.get("open_count", 0):
        return "use_jsonl_no_db_and_file_tracker_repair_bead"
    return "surface_tracker_blocker"


def discrepancy_types(snapshot, commands):
    result = set()
    signatures = {cmd.get("failure_signature") for cmd in commands}
    if snapshot.get("jsonl_records") != snapshot.get("db_records"):
        result.add("db_jsonl_count_mismatch")
    if snapshot.get("exact_id_split_brain") or "exact_id_split_brain" in signatures:
        result.add("exact_id_split_brain")
    if "timeout" in signatures:
        result.add("timeout")
    if snapshot.get("stale_blocked_cache"):
        result.add("stale_blocked_cache")
    if snapshot.get("already_shipped_but_open"):
        result.add("already_shipped_but_open")
    if "conflicting_ready_lists" in signatures:
        result.add("conflicting_ready_lists")
    if snapshot.get("cycles_count") not in (0, None):
        result.add("cycle_report_disagreement")
    if "missing_issue_record" in signatures:
        result.add("missing_issue_record")
    return sorted(result)


artifact = load_json(artifact_path)
if artifact.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if artifact.get("bead") != "bd-bp8fl.2.3":
    errors.append("bead must be bd-bp8fl.2.3")
if artifact.get("required_report_fields") != REQUIRED_REPORT_FIELDS:
    errors.append("required_report_fields drifted")
if artifact.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_log_fields drifted")

scenario_results = []
log_rows = []
commit = source_commit()
target_dir = rel(report_path.parent)

for scenario in artifact.get("scenarios", []):
    scenario_id = scenario.get("scenario_id")
    snapshot = scenario.get("snapshot", {})
    commands = scenario.get("commands", [])
    state = classify(snapshot, commands)
    expected_state = scenario.get("expected_tracker_state")
    action = next_safe_action(state, snapshot)
    expected_action = scenario.get("expected_next_safe_action")
    discrepancies = discrepancy_types(snapshot, commands)
    may_proceed = bool(scenario.get("implementation_may_proceed"))

    if state != expected_state:
        errors.append(f"{scenario_id}: expected state {expected_state}, got {state}")
    if action != expected_action:
        errors.append(f"{scenario_id}: expected next action {expected_action}, got {action}")
    if state == "healthy" and not may_proceed:
        errors.append(f"{scenario_id}: healthy state must allow implementation")
    if state == "tool_timeout" and may_proceed:
        errors.append(f"{scenario_id}: timeout-only state must not allow implementation")
    if snapshot.get("open_count", 0) not in (0, None) and snapshot.get("br_ready_count") == 0:
        if "zero_ready_nonzero_open" not in {cmd.get("failure_signature") for cmd in commands}:
            errors.append(f"{scenario_id}: zero-ready/nonzero-open needs explicit signature")

    scenario_results.append(
        {
            "scenario_id": scenario_id,
            "tracker_state": state,
            "expected_tracker_state": expected_state,
            "discrepancy_types": discrepancies,
            "jsonl_records": snapshot.get("jsonl_records"),
            "db_records": snapshot.get("db_records"),
            "open_count": snapshot.get("open_count"),
            "actionable_count": snapshot.get("actionable_count"),
            "cycles_count": snapshot.get("cycles_count"),
            "known_degraded_commands": snapshot.get("known_degraded_commands", []),
            "implementation_may_proceed": may_proceed,
            "next_safe_action": action,
        }
    )

    for command in commands:
        row = {
            "trace_id": f"{artifact.get('trace_id')}::{scenario_id}::{command.get('name')}",
            "bead_id": "bd-bp8fl.2.3",
            "command": command.get("command"),
            "exit_status": command.get("exit_status"),
            "duration_ms": command.get("duration_ms"),
            "tracker_state": state,
            "expected": command.get("expected"),
            "actual": command.get("actual"),
            "artifact_refs": [rel(artifact_path)],
            "source_commit": commit,
            "target_dir": target_dir,
            "failure_signature": command.get("failure_signature"),
        }
        missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
        if missing:
            errors.append(f"{scenario_id}/{command.get('name')}: missing log fields {missing}")
        log_rows.append(row)

states = {}
for result in scenario_results:
    states[result["tracker_state"]] = states.get(result["tracker_state"], 0) + 1

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.2.3",
    "generated_at_utc": utc_now(),
    "trace_id": artifact.get("trace_id"),
    "source_commit": commit,
    "status": status,
    "mode": mode,
    "scenario_count": len(scenario_results),
    "scenario_results": scenario_results,
    "summary": {
        "states": states,
        "open_work_visible_in_degraded_modes": any(
            (result.get("open_count") or 0) > 0 and result["tracker_state"] != "healthy"
            for result in scenario_results
        ),
        "tool_failures_are_not_code_failures": all(
            result["tracker_state"] in {"healthy", "tracker_failure", "graph_failure", "tool_timeout", "split_brain"}
            for result in scenario_results
        ),
        "implementation_allowed_scenarios": [
            result["scenario_id"]
            for result in scenario_results
            if result["implementation_may_proceed"]
        ],
    },
    "artifact_refs": [rel(artifact_path), rel(log_path)],
    "errors": errors,
}

missing_report = [field for field in REQUIRED_REPORT_FIELDS if field not in report]
if missing_report:
    errors.append(f"report missing required fields {missing_report}")
    report["status"] = "fail"
    report["errors"] = errors

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as log:
    for row in log_rows:
        log.write(json.dumps(row, sort_keys=True) + "\n")

if errors:
    print("FAIL: tracker health replay mismatch")
    for error in errors:
        print(f"  - {error}")
    sys.exit(1)

print(f"PASS: tracker health replay classified {len(scenario_results)} scenarios")
print(f"report: {rel(report_path)}")
print(f"log: {rel(log_path)}")
PY
