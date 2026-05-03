#!/usr/bin/env bash
# check_br_bv_disagreement_dashboard.sh -- deterministic dashboard replay for bd-bp8fl.2.7
#
# Replays frozen br/bv disagreement scenarios and emits a dashboard report plus
# structured command logs. The gate makes stale tracker state actionable without
# allowing prose dashboards to hide JSONL-visible work.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_BR_BV_DASHBOARD_ARTIFACT:-${ROOT}/tests/conformance/br_bv_disagreement_dashboard.v1.json}"
OUT_DIR="${FRANKENLIBC_BR_BV_DASHBOARD_TARGET_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_BR_BV_DASHBOARD_REPORT:-${OUT_DIR}/br_bv_disagreement_dashboard.report.json}"
LOG="${FRANKENLIBC_BR_BV_DASHBOARD_LOG:-${OUT_DIR}/br_bv_disagreement_dashboard.log.jsonl}"
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

REQUIRED_REPORT_FIELDS = [
    "schema_version",
    "bead",
    "generated_at_utc",
    "trace_id",
    "source_commit",
    "status",
    "dashboard_rows",
    "summary",
    "artifact_refs",
]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "tracker_run_id",
    "command",
    "exit_status",
    "duration_ms",
    "source",
    "bead_id",
    "discrepancy_type",
    "expected",
    "actual",
    "source_commit",
    "artifact_refs",
    "failure_signature",
]

REQUIRED_DISCREPANCIES = {
    "db_jsonl_count_mismatch",
    "exact_id_split_brain",
    "timeout",
    "stale_blocked_cache",
    "already_shipped_but_open_bead",
    "conflicting_ready_lists",
    "cycle_report_disagreement",
    "missing_issue_record",
}

SIGNATURE_ALIASES = {
    "zero_ready_nonzero_open": "conflicting_ready_lists",
}


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


def command_signatures(commands):
    signatures = set()
    for command in commands:
        signature = command.get("failure_signature")
        if not signature or signature == "ok":
            continue
        signature = SIGNATURE_ALIASES.get(signature, signature)
        if signature in REQUIRED_DISCREPANCIES:
            signatures.add(signature)
    return signatures


def detect_discrepancies(inputs, commands):
    discrepancies = set(command_signatures(commands))
    if inputs.get("jsonl_records") != inputs.get("db_records"):
        discrepancies.add("db_jsonl_count_mismatch")
    if inputs.get("exact_id_split_brain"):
        discrepancies.add("exact_id_split_brain")
    if inputs.get("stale_blocked_cache"):
        discrepancies.add("stale_blocked_cache")
    if inputs.get("already_shipped_but_open"):
        discrepancies.add("already_shipped_but_open_bead")
    if inputs.get("missing_records"):
        discrepancies.add("missing_issue_record")
    if inputs.get("cycles_count") not in (0, None):
        discrepancies.add("cycle_report_disagreement")

    br_open = inputs.get("br_open_count")
    bv_open = inputs.get("bv_open_count")
    br_ready = inputs.get("br_ready_count")
    if br_open not in (None, bv_open) and bv_open is not None:
        discrepancies.add("conflicting_ready_lists")
    if br_open not in (0, None) and br_ready == 0 and bv_open == 0:
        discrepancies.add("conflicting_ready_lists")
    if any(command.get("exit_status") == 124 for command in commands):
        discrepancies.add("timeout")
    return sorted(discrepancies)


def current_source_of_truth(discrepancies, inputs):
    discrepancy_set = set(discrepancies)
    if not discrepancy_set:
        return "agreement"
    if discrepancy_set == {"timeout"}:
        return "inconclusive"
    if "cycle_report_disagreement" in discrepancy_set:
        return "blocked_graph"
    if "exact_id_split_brain" in discrepancy_set or "missing_issue_record" in discrepancy_set:
        return "br_no_db_show"
    return "br_no_db_jsonl"


def next_safe_action(discrepancies, inputs):
    discrepancy_set = set(discrepancies)
    if not discrepancy_set:
        return "continue_claimable_jsonl_beads"
    if discrepancy_set == {"timeout"}:
        return "retry_timed_out_command_with_tighter_scope"
    if "cycle_report_disagreement" in discrepancy_set:
        return "fix_dependency_cycles_before_dashboard_claims"
    if "exact_id_split_brain" in discrepancy_set:
        return "prefer_named_no_db_show_and_reconcile_duplicate_rows"
    if "missing_issue_record" in discrepancy_set:
        return "repair_missing_issue_or_dependency_record"
    if "already_shipped_but_open_bead" in discrepancy_set:
        return "close_shipped_bead_or_reopen_with_current_blocker"
    if "db_jsonl_count_mismatch" in discrepancy_set or "stale_blocked_cache" in discrepancy_set:
        return "use_no_db_jsonl_and_repair_tracker_db"
    if "conflicting_ready_lists" in discrepancy_set:
        return "render_open_jsonl_rows_and_file_tracker_repair"
    return "surface_tracker_disagreement"


def implementation_failure_class(discrepancies, may_proceed):
    if not discrepancies:
        return "none"
    if may_proceed:
        return "tracker_failure"
    return "plan_or_tracker_blocker"


artifact = load_json(artifact_path)
errors = []

if artifact.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if artifact.get("bead") != "bd-bp8fl.2.7":
    errors.append("bead must be bd-bp8fl.2.7")
if artifact.get("required_report_fields") != REQUIRED_REPORT_FIELDS:
    errors.append("required_report_fields drifted")
if artifact.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_log_fields drifted")
if set(artifact.get("discrepancy_types", [])) != REQUIRED_DISCREPANCIES:
    errors.append("discrepancy_types drifted")

commit = source_commit()
artifact_ref = rel(artifact_path)
dashboard_rows = []
log_rows = []
covered = set()

for scenario in artifact.get("scenarios", []):
    scenario_id = scenario.get("scenario_id")
    inputs = scenario.get("inputs", {})
    commands = scenario.get("commands", [])
    discrepancies = detect_discrepancies(inputs, commands)
    covered.update(discrepancies)
    expected = sorted(scenario.get("expected_discrepancies", []))
    source = current_source_of_truth(discrepancies, inputs)
    action = next_safe_action(discrepancies, inputs)
    may_proceed = bool(scenario.get("implementation_may_proceed"))

    if discrepancies != expected:
        errors.append(f"{scenario_id}: expected discrepancies {expected}, got {discrepancies}")
    if source != scenario.get("expected_current_source_of_truth"):
        errors.append(
            f"{scenario_id}: expected source {scenario.get('expected_current_source_of_truth')}, got {source}"
        )
    if action != scenario.get("expected_next_safe_action"):
        errors.append(
            f"{scenario_id}: expected action {scenario.get('expected_next_safe_action')}, got {action}"
        )
    if source == "agreement" and not may_proceed:
        errors.append(f"{scenario_id}: agreement must allow implementation")
    if source == "inconclusive" and may_proceed:
        errors.append(f"{scenario_id}: timeout-only input must not allow implementation")

    dashboard_rows.append(
        {
            "scenario_id": scenario_id,
            "bead_id": scenario.get("bead_id", "multiple"),
            "current_source_of_truth": source,
            "discrepancy_types": discrepancies,
            "evidence_age": scenario.get("evidence_age", "fixture"),
            "affected_bead_ids": inputs.get("missing_records", [])
            + inputs.get("already_shipped_but_open", []),
            "user_impact": "dashboard_claim_blocked" if discrepancies else "dashboard_claim_allowed",
            "failure_class": implementation_failure_class(discrepancies, may_proceed),
            "implementation_may_proceed": may_proceed,
            "next_safe_action": action,
            "artifact_refs": [artifact_ref],
        }
    )

    row_discrepancy = discrepancies[0] if discrepancies else "none"
    for command in commands:
        log_row = {
            "trace_id": f"{artifact.get('trace_id')}::{scenario_id}::{command.get('name')}",
            "tracker_run_id": scenario_id,
            "command": command.get("command"),
            "exit_status": command.get("exit_status"),
            "duration_ms": command.get("duration_ms"),
            "source": command.get("source"),
            "bead_id": scenario.get("bead_id", "multiple"),
            "discrepancy_type": command.get("failure_signature")
            if command.get("failure_signature") != "ok"
            else row_discrepancy,
            "expected": command.get("expected"),
            "actual": command.get("actual"),
            "source_commit": commit,
            "artifact_refs": [artifact_ref],
            "failure_signature": command.get("failure_signature"),
        }
        missing = [field for field in REQUIRED_LOG_FIELDS if field not in log_row]
        if missing:
            errors.append(f"{scenario_id}/{command.get('name')}: missing log fields {missing}")
        log_rows.append(log_row)

missing_coverage = REQUIRED_DISCREPANCIES - covered
if missing_coverage:
    errors.append(f"missing discrepancy coverage: {sorted(missing_coverage)}")

status = "pass" if not errors else "fail"
summary = {
    "dashboard_row_count": len(dashboard_rows),
    "discrepancy_coverage": sorted(covered),
    "blocked_claim_rows": sum(1 for row in dashboard_rows if row["user_impact"] == "dashboard_claim_blocked"),
    "implementation_may_continue_on_unrelated_jsonl_beads": any(
        row["failure_class"] == "tracker_failure" and row["implementation_may_proceed"]
        for row in dashboard_rows
    ),
    "tool_failures_are_not_code_failures": all(
        row["failure_class"] != "code_failure" for row in dashboard_rows
    ),
    "required_commands": [command["command"] for command in artifact.get("command_contract", [])],
}

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.2.7",
    "generated_at_utc": utc_now(),
    "trace_id": artifact.get("trace_id"),
    "source_commit": commit,
    "status": status,
    "mode": mode,
    "dashboard_rows": dashboard_rows,
    "summary": summary,
    "artifact_refs": [artifact_ref],
    "errors": errors,
}

for field in REQUIRED_REPORT_FIELDS:
    if field not in report:
        errors.append(f"report missing field {field}")
        report["status"] = "fail"

if mode == "--fixture-replay":
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with log_path.open("w", encoding="utf-8") as handle:
        for row in log_rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

if errors:
    print("FAIL: br/bv disagreement dashboard replay found errors", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    sys.exit(1)

if mode == "--fixture-replay":
    print(f"PASS: br/bv disagreement dashboard replay classified {len(dashboard_rows)} scenarios")
    print(f"report: {rel(report_path)}")
    print(f"log: {rel(log_path)}")
else:
    print("PASS: br/bv disagreement dashboard artifact validates")
PY
