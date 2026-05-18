#!/usr/bin/env bash
# generate_high_core_validation_operator_report.sh -- operator report for bd-2syj4.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${HIGH_CORE_VALIDATION_OPERATOR_CONTRACT:-$ROOT/tests/conformance/high_core_validation_operator_report.v1.json}"
MERGE_REPORT="${HIGH_CORE_VALIDATION_MERGE_REPORT:-$ROOT/target/conformance/high_core_validation/merge.report.json}"
COST_REPORT="${HIGH_CORE_VALIDATION_COST_REPORT:-$ROOT/target/conformance/high_core_validation/costs.report.json}"
OPERATOR_JSON="${HIGH_CORE_VALIDATION_OPERATOR_JSON:-$ROOT/target/conformance/high_core_validation/operator.report.json}"
OPERATOR_MARKDOWN="${HIGH_CORE_VALIDATION_OPERATOR_MARKDOWN:-$ROOT/target/conformance/high_core_validation/operator.report.md}"
OPERATOR_EVENTS="${HIGH_CORE_VALIDATION_OPERATOR_EVENTS:-$ROOT/target/conformance/high_core_validation/operator.events.log.jsonl}"

cd "${ROOT}"

python3 - "${ROOT}" "${CONTRACT}" "${MERGE_REPORT}" "${COST_REPORT}" "${OPERATOR_JSON}" "${OPERATOR_MARKDOWN}" "${OPERATOR_EVENTS}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
merge_path = Path(sys.argv[3])
cost_path = Path(sys.argv[4])
json_path = Path(sys.argv[5])
markdown_path = Path(sys.argv[6])
events_path = Path(sys.argv[7])


def rel(path):
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return path.name


def normalize_rel(value):
    if not isinstance(value, str) or not value:
        return ""
    path = Path(value)
    if path.is_absolute():
        return rel(path)
    return path.as_posix()


def configured_report_fields(contract):
    report_contract = contract.get("report_contract")
    if not isinstance(report_contract, dict):
        return []
    fields = report_contract.get("must_materialize")
    if not isinstance(fields, list):
        return []
    return [field for field in fields if isinstance(field, str) and field]


def validate_report_contract(contract, report):
    report_contract = contract.get("report_contract")
    if not isinstance(report_contract, dict):
        return ["missing_report_contract"]
    errors = []
    fields = report_contract.get("must_materialize")
    if not isinstance(fields, list) or not all(isinstance(field, str) and field for field in fields):
        errors.append("report_contract.must_materialize must be a non-empty string list")
        fields = []
    outputs = contract.get("outputs", {})
    if not isinstance(outputs, dict):
        outputs = {}
    expected_report = normalize_rel(report_contract.get("output_path"))
    expected_markdown = normalize_rel(report_contract.get("markdown_path"))
    expected_log = normalize_rel(report_contract.get("log_path"))
    if expected_report != normalize_rel(outputs.get("json_report")):
        errors.append("report_contract.output_path must match outputs.json_report")
    if expected_markdown != normalize_rel(outputs.get("markdown_report")):
        errors.append("report_contract.markdown_path must match outputs.markdown_report")
    if expected_log != normalize_rel(outputs.get("event_log")):
        errors.append("report_contract.log_path must match outputs.event_log")
    missing = [field for field in fields if field not in report]
    if missing:
        errors.append("report_contract missing materialized fields: " + ", ".join(missing))
    return errors


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def as_list(value):
    return value if isinstance(value, list) else []


def as_dict(value):
    return value if isinstance(value, dict) else {}


def command_string(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(str(part) for part in value)
    return ""


def artifact_path(item):
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for key in ["path", "artifact", "artifact_ref"]:
            candidate = item.get(key)
            if isinstance(candidate, str):
                return candidate
    return None


def artifact_status(item):
    if isinstance(item, dict):
        status = item.get("status")
        if isinstance(status, str):
            return status
    return "present"


def stable_key(row):
    return (str(row.get("unit_id", "")), str(row.get("shard_id", "")))


contract = load_json(contract_path)
merge = load_json(merge_path)
cost = load_json(cost_path)

if contract.get("schema_version") != "v1" or contract.get("bead") != "bd-2syj4":
    raise SystemExit("operator contract must be schema_version=v1 and bead=bd-2syj4")

cost_by_unit = {}
for row in as_list(cost.get("per_unit")):
    if isinstance(row, dict) and isinstance(row.get("unit_id"), str):
        cost_by_unit[row["unit_id"]] = row

lane_map = {}
results = as_list(merge.get("results"))
failure_index = as_list(merge.get("failure_index"))
for row in results:
    if not isinstance(row, dict):
        continue
    shard_id = str(row.get("shard_id", ""))
    lane_index = row.get("lane_index")
    lane_key = (lane_index, shard_id)
    lane = lane_map.setdefault(
        lane_key,
        {
            "lane_index": lane_index,
            "shard_id": shard_id,
            "unit_count": 0,
            "passed_count": 0,
            "failed_count": 0,
            "skipped_count": 0,
            "stale_artifact_count": 0,
            "max_recent_p95_ms": 0,
            "status": "passed",
        },
    )
    unit_id = str(row.get("unit_id", ""))
    status = str(row.get("status", "unknown"))
    lane["unit_count"] += 1
    if status == "passed":
        lane["passed_count"] += 1
    elif status == "skipped":
        lane["skipped_count"] += 1
    else:
        lane["failed_count"] += 1
    unit_cost = as_dict(cost_by_unit.get(unit_id))
    p95 = int(unit_cost.get("duration_ms_p95", 0) or 0)
    lane["max_recent_p95_ms"] = max(lane["max_recent_p95_ms"], p95)
    for artifact in as_list(row.get("artifact_refs")):
        if artifact_status(artifact) == "stale":
            lane["stale_artifact_count"] += 1

for lane in lane_map.values():
    if lane["failed_count"] > 0:
        lane["status"] = "failed"
    elif lane["skipped_count"] > 0:
        lane["status"] = "skipped"
    elif lane["stale_artifact_count"] > 0:
        lane["status"] = "warning"

failed_units = []
for row in failure_index:
    if not isinstance(row, dict):
        continue
    failed_units.append(
        {
            "unit_id": row.get("unit_id"),
            "shard_id": row.get("shard_id"),
            "failure_signature": row.get("failure_signature") or "result_failed",
            "first_failing_artifact": row.get("first_failing_artifact"),
            "reproduction_command": command_string(row.get("reproduction_command") or row.get("command_template")),
            "detail": row.get("detail"),
        }
    )

known_failures = {(row.get("unit_id"), row.get("shard_id")) for row in failed_units}
for row in results:
    if not isinstance(row, dict):
        continue
    status = str(row.get("status", "unknown"))
    unit_id = row.get("unit_id")
    shard_id = row.get("shard_id")
    if status in ("passed", "skipped") or (unit_id, shard_id) in known_failures:
        continue
    first_artifact = None
    for artifact in as_list(row.get("artifact_refs")):
        first_artifact = artifact_path(artifact)
        if first_artifact is not None:
            break
    failed_units.append(
        {
            "unit_id": unit_id,
            "shard_id": shard_id,
            "failure_signature": row.get("failure_signature") or "result_failed",
            "first_failing_artifact": first_artifact,
            "reproduction_command": command_string(row.get("reproduction_command") or row.get("command_template")),
            "detail": f"exit_code={row.get('exit_code')} duration_ms={row.get('duration_ms')}",
        }
    )

skipped_units = []
stale_artifact_warnings = []
recent_p95_cost = []
rerun_commands = []
threshold = int(contract.get("status_policy", {}).get("expensive_p95_ms_threshold", 600000))

for row in results:
    if not isinstance(row, dict):
        continue
    unit_id = str(row.get("unit_id", ""))
    shard_id = str(row.get("shard_id", ""))
    status = str(row.get("status", "unknown"))
    command = command_string(row.get("reproduction_command") or row.get("command_template"))
    unit_cost = as_dict(cost_by_unit.get(unit_id))
    p95 = int(unit_cost.get("duration_ms_p95", 0) or 0)
    recent_p95_cost.append(
        {
            "unit_id": unit_id,
            "shard_id": shard_id,
            "duration_ms_p95": p95,
            "cost_class": unit_cost.get("current_cost_class") or unit_cost.get("suggested_cost_class"),
            "expensive": p95 >= threshold or unit_cost.get("current_cost_class") == "expensive",
        }
    )
    if status == "skipped":
        skipped_units.append(
            {
                "unit_id": unit_id,
                "shard_id": shard_id,
                "failure_signature": row.get("failure_signature") or "skipped",
                "rch_command": command,
            }
        )
    if status != "passed" or status == "skipped":
        rerun_commands.append(
            {
                "unit_id": unit_id,
                "shard_id": shard_id,
                "status": status,
                "rch_command": command,
            }
        )
    for artifact in as_list(row.get("artifact_refs")):
        if artifact_status(artifact) == "stale":
            stale_artifact_warnings.append(
                {
                    "unit_id": unit_id,
                    "shard_id": shard_id,
                    "artifact": artifact_path(artifact),
                    "status": "stale",
                    "rch_command": command,
                }
            )

failed_units.sort(key=stable_key)
skipped_units.sort(key=stable_key)
stale_artifact_warnings.sort(key=stable_key)
recent_p95_cost.sort(key=lambda row: (not row["expensive"], row["unit_id"], row["shard_id"]))
rerun_commands.sort(key=stable_key)
lane_health = sorted(lane_map.values(), key=lambda row: (row["lane_index"], row["shard_id"]))

status = "failed" if failed_units else "passed"
if skipped_units and status == "passed":
    status = "warning"
if stale_artifact_warnings and status == "passed":
    status = "warning"

report = {
    "schema_version": "v1",
    "bead": "bd-2syj4",
    "status": status,
    "source_merge_report": rel(merge_path),
    "source_cost_report": rel(cost_path),
    "sections": contract.get("required_sections", []),
    "summary": {
        "lane_count": len(lane_health),
        "result_count": len(results),
        "failed_unit_count": len(failed_units),
        "skipped_unit_count": len(skipped_units),
        "stale_artifact_warning_count": len(stale_artifact_warnings),
        "expensive_unit_count": sum(1 for row in recent_p95_cost if row["expensive"]),
        "rerun_command_count": len(rerun_commands),
    },
    "lane_health": lane_health,
    "recent_p95_cost": recent_p95_cost,
    "failed_units": failed_units,
    "skipped_units": skipped_units,
    "stale_artifact_warnings": stale_artifact_warnings,
    "rch_rerun_commands": rerun_commands,
    "report_path": normalize_rel(contract.get("outputs", {}).get("json_report")),
    "markdown_path": normalize_rel(contract.get("outputs", {}).get("markdown_report")),
    "log_path": normalize_rel(contract.get("outputs", {}).get("event_log")),
    "report_contract_fields": configured_report_fields(contract),
    "contract_status": "pending",
    "contract_errors": [],
}
contract_errors = validate_report_contract(contract, report)
report["contract_errors"] = contract_errors
report["contract_status"] = "pass" if not contract_errors else "fail"
if contract_errors and status == "passed":
    report["status"] = "failed"

json_path.parent.mkdir(parents=True, exist_ok=True)
markdown_path.parent.mkdir(parents=True, exist_ok=True)
events_path.parent.mkdir(parents=True, exist_ok=True)
json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    "# High-Core Validation Operator Report",
    "",
    f"status: {status}",
    f"results: {len(results)}",
    f"failed_units: {len(failed_units)}",
    f"skipped_units: {len(skipped_units)}",
    f"stale_artifacts: {len(stale_artifact_warnings)}",
    "",
    "## Lane Health",
]
for lane in lane_health:
    lines.append(
        f"- {lane['shard_id']}: {lane['status']} units={lane['unit_count']} "
        f"passed={lane['passed_count']} failed={lane['failed_count']} "
        f"skipped={lane['skipped_count']} p95_ms={lane['max_recent_p95_ms']}"
    )
lines.append("")
lines.append("## Failed Units")
for row in failed_units:
    lines.append(f"- {row['unit_id']} {row['failure_signature']} {row['reproduction_command']}")
if not failed_units:
    lines.append("- none")
lines.append("")
lines.append("## Skipped Units")
for row in skipped_units:
    lines.append(f"- {row['unit_id']} {row['failure_signature']} {row['rch_command']}")
if not skipped_units:
    lines.append("- none")
lines.append("")
lines.append("## Stale Artifact Warnings")
for row in stale_artifact_warnings:
    lines.append(f"- {row['unit_id']} {row['artifact']} {row['rch_command']}")
if not stale_artifact_warnings:
    lines.append("- none")
lines.append("")
lines.append("## Rerun Commands")
for row in rerun_commands:
    lines.append(f"- {row['unit_id']} [{row['status']}]: {row['rch_command']}")
if not rerun_commands:
    lines.append("- none")
markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

events_path.write_text(
    json.dumps(
        {
            "event": "operator_report_generated",
            "bead": "bd-2syj4",
            "status": status,
            "failed_unit_count": len(failed_units),
            "skipped_unit_count": len(skipped_units),
            "stale_artifact_warning_count": len(stale_artifact_warnings),
            "artifact_refs": [rel(json_path), rel(markdown_path)],
        },
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)

print(
    "high_core_validation_operator_report: PASS "
    f"status={status} failed={len(failed_units)} skipped={len(skipped_units)} "
    f"stale={len(stale_artifact_warnings)}"
)
PY
