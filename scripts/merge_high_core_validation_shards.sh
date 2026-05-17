#!/usr/bin/env bash
# merge_high_core_validation_shards.sh -- deterministic shard result merger for bd-31d38.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN="${HIGH_CORE_VALIDATION_SHARD_PLAN:-$ROOT/target/conformance/high_core_validation/shard_plan.report.json}"
MERGE_REPORT="${HIGH_CORE_VALIDATION_MERGE_REPORT:-$ROOT/target/conformance/high_core_validation/merge.report.json}"
MERGE_LOG="${HIGH_CORE_VALIDATION_MERGE_LOG:-$ROOT/target/conformance/high_core_validation/merge.log.jsonl}"
RESULT_INPUTS="${HIGH_CORE_VALIDATION_RESULT_INPUTS:-}"

if [[ -z "${RESULT_INPUTS}" && "$#" -gt 0 ]]; then
    RESULT_INPUTS="$(IFS=:; echo "$*")"
fi

cd "${ROOT}"

python3 - "${ROOT}" "${PLAN}" "${MERGE_REPORT}" "${MERGE_LOG}" "${RESULT_INPUTS}" <<'PY'
import json
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
plan_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
result_inputs_raw = sys.argv[5]

required_result_fields = [
    "run_id",
    "unit_id",
    "shard_id",
    "command_template",
    "status",
    "exit_code",
    "duration_ms",
    "artifact_refs",
    "failure_signature",
]

errors = []
failure_signatures = []
events = []


def fail(message, signature):
    errors.append(message)
    failure_signatures.append(signature)


def relative_path(path):
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def load_json(path, signature):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{relative_path(path)}: {exc}", signature)
        return {}


def write_report(report):
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_log(rows):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def is_string_array(value):
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def result_inputs():
    if not result_inputs_raw:
        fail("HIGH_CORE_VALIDATION_RESULT_INPUTS or positional result paths are required", "result_inputs_missing")
        return []
    paths = [Path(item) for item in result_inputs_raw.split(os.pathsep) if item]
    if not paths:
        fail("no non-empty result input paths provided", "result_inputs_missing")
    return paths


def load_plan():
    plan = load_json(plan_path, "plan_unreadable")
    if plan.get("schema_version") != "v1":
        fail("plan.schema_version must be v1", "invalid_plan")
    if plan.get("bead") != "bd-qa87u":
        fail("plan.bead must be bd-qa87u", "invalid_plan")
    if plan.get("status") != "passed":
        fail("plan.status must be passed", "invalid_plan")

    manifest_fields = plan.get("required_result_fields")
    if isinstance(manifest_fields, list) and manifest_fields:
        required_result_fields[:] = manifest_fields

    planned = {}
    lanes = plan.get("lanes")
    if not isinstance(lanes, list):
        fail("plan.lanes must be an array", "invalid_plan")
        lanes = []
    for lane_index, lane in enumerate(lanes):
        if not isinstance(lane, dict):
            fail(f"plan.lanes[{lane_index}] must be an object", "invalid_plan")
            continue
        shard_id = lane.get("shard_id")
        lane_number = lane.get("lane_index")
        if not isinstance(shard_id, str) or not shard_id:
            fail(f"plan.lanes[{lane_index}].shard_id must be a non-empty string", "invalid_plan")
            continue
        units = lane.get("units")
        if not isinstance(units, list):
            fail(f"{shard_id}: lane.units must be an array", "invalid_plan")
            continue
        for unit_index, unit in enumerate(units):
            if not isinstance(unit, dict):
                fail(f"{shard_id}.units[{unit_index}] must be an object", "invalid_plan")
                continue
            unit_id = unit.get("unit_id")
            command = unit.get("command_template")
            artifacts = unit.get("required_artifacts")
            if not isinstance(unit_id, str) or not unit_id:
                fail(f"{shard_id}.units[{unit_index}].unit_id missing", "invalid_plan")
                continue
            if not is_string_array(command):
                fail(f"{unit_id}: command_template must be non-empty string array", "invalid_plan")
                continue
            if not is_string_array(artifacts):
                fail(f"{unit_id}: required_artifacts must be non-empty string array", "invalid_plan")
                continue
            key = (unit_id, shard_id)
            if key in planned:
                fail(f"duplicate planned unit/shard pair {unit_id}/{shard_id}", "duplicate_planned_unit")
                continue
            planned[key] = {
                "unit_id": unit_id,
                "shard_id": shard_id,
                "lane_index": lane_number,
                "command_template": command,
                "reproduction_command": unit.get("reproduction_command") or " ".join(command),
                "required_artifacts": sorted(set(artifacts)),
            }
    return planned


def load_result_rows_from_json(path, value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and isinstance(value.get("results"), list):
        return value["results"]
    if isinstance(value, dict) and "unit_id" in value:
        return [value]
    fail(f"{relative_path(path)} must be a result object, array, or object with results[]", "invalid_result_container")
    return []


def load_result_rows(paths):
    rows = []
    for path in sorted(paths, key=lambda item: relative_path(item)):
        if not path.exists():
            fail(f"{relative_path(path)} does not exist", "result_input_missing")
            continue
        if path.suffix == ".jsonl":
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except Exception as exc:
                fail(f"{relative_path(path)}: {exc}", "result_input_unreadable")
                continue
            for line_number, line in enumerate(lines, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except Exception as exc:
                    fail(f"{relative_path(path)}:{line_number}: malformed JSONL row: {exc}", "malformed_jsonl")
                    continue
                rows.append((path, line_number, value))
        else:
            value = load_json(path, "malformed_json")
            for index, row in enumerate(load_result_rows_from_json(path, value), start=1):
                rows.append((path, index, row))
    return rows


def artifact_path(item):
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        candidate = item.get("path") or item.get("artifact") or item.get("artifact_ref")
        if isinstance(candidate, str):
            return candidate
    return None


def artifact_status(item):
    if isinstance(item, dict):
        status = item.get("status")
        if isinstance(status, str):
            return status
    return None


def artifact_paths(refs):
    paths = []
    if not isinstance(refs, list):
        return paths
    for item in refs:
        path = artifact_path(item)
        if path:
            paths.append(path)
    return paths


def first_bad_artifact(refs):
    if not isinstance(refs, list):
        return None
    for item in refs:
        status = artifact_status(item)
        if status and status not in {"ok", "pass", "passed", "present", "success"}:
            return artifact_path(item)
    return None


def validate_result(path, line_number, row):
    if not isinstance(row, dict):
        fail(f"{relative_path(path)}:{line_number}: result row must be an object", "invalid_result_row")
        return None
    missing = [field for field in required_result_fields if field not in row]
    if missing:
        fail(f"{relative_path(path)}:{line_number}: missing result field(s) {missing}", "invalid_result_field")
        return None

    run_id = row.get("run_id")
    unit_id = row.get("unit_id")
    shard_id = row.get("shard_id")
    command = row.get("command_template")
    status = row.get("status")
    exit_code = row.get("exit_code")
    duration_ms = row.get("duration_ms")
    artifact_refs = row.get("artifact_refs")
    failure_signature = row.get("failure_signature")

    valid = True
    if not isinstance(run_id, str) or not run_id:
        fail(f"{relative_path(path)}:{line_number}: run_id must be a non-empty string", "invalid_result_field")
        valid = False
    if not isinstance(unit_id, str) or not unit_id:
        fail(f"{relative_path(path)}:{line_number}: unit_id must be a non-empty string", "invalid_result_field")
        valid = False
    if not isinstance(shard_id, str) or not shard_id:
        fail(f"{relative_path(path)}:{line_number}: shard_id must be a non-empty string", "invalid_result_field")
        valid = False
    if not is_string_array(command):
        fail(f"{relative_path(path)}:{line_number}: command_template must be non-empty string array", "invalid_result_field")
        valid = False
    if not isinstance(status, str) or not status:
        fail(f"{relative_path(path)}:{line_number}: status must be a non-empty string", "invalid_result_field")
        valid = False
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        fail(f"{relative_path(path)}:{line_number}: exit_code must be an integer", "invalid_result_field")
        valid = False
    if not isinstance(duration_ms, (int, float)) or isinstance(duration_ms, bool) or duration_ms < 0:
        fail(f"{relative_path(path)}:{line_number}: duration_ms must be non-negative number", "invalid_result_field")
        valid = False
    if not isinstance(artifact_refs, list):
        fail(f"{relative_path(path)}:{line_number}: artifact_refs must be an array", "invalid_result_field")
        valid = False
    if failure_signature is not None and not isinstance(failure_signature, str):
        fail(f"{relative_path(path)}:{line_number}: failure_signature must be string or null", "invalid_result_field")
        valid = False
    if not valid:
        return None

    normalized = {
        "run_id": run_id,
        "unit_id": unit_id,
        "shard_id": shard_id,
        "command_template": command,
        "status": status,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "artifact_refs": artifact_refs,
        "failure_signature": failure_signature or "",
        "source": {"path": relative_path(path), "line": line_number},
    }
    return normalized


def canonical_result(row):
    comparable = {field: row[field] for field in required_result_fields if field in row}
    comparable["failure_signature"] = comparable.get("failure_signature") or ""
    return json.dumps(comparable, sort_keys=True, separators=(",", ":"))


def failure_row(planned, status, failure_signature, first_failing_artifact, detail):
    return {
        "unit_id": planned["unit_id"],
        "shard_id": planned["shard_id"],
        "lane_index": planned.get("lane_index"),
        "command_template": planned["command_template"],
        "reproduction_command": planned["reproduction_command"],
        "status": status,
        "failure_signature": failure_signature,
        "first_failing_artifact": first_failing_artifact,
        "detail": detail,
    }


planned = load_plan()
paths = result_inputs()
raw_rows = load_result_rows(paths)

results_by_key = {}
duplicate_result_count = 0
duplicate_disagreement_count = 0
unplanned_rows = []
for path, line_number, row in raw_rows:
    result = validate_result(path, line_number, row)
    if result is None:
        continue
    key = (result["unit_id"], result["shard_id"])
    if key not in planned:
        unplanned_rows.append(result)
        fail(f"{result['unit_id']}/{result['shard_id']} is not present in the shard plan", "unplanned_result")
        continue
    planned_row = planned[key]
    if result["command_template"] != planned_row["command_template"]:
        fail(f"{result['unit_id']}/{result['shard_id']} command_template does not match plan", "command_template_mismatch")
    prior = results_by_key.get(key)
    if prior is not None:
        duplicate_result_count += 1
        if canonical_result(prior) != canonical_result(result):
            duplicate_disagreement_count += 1
            fail(f"{result['unit_id']}/{result['shard_id']} duplicate results disagree", "duplicate_result_disagreement")
        continue
    results_by_key[key] = result

failure_index = []
result_records = []
passed_count = 0
failed_count = 0
missing_result_count = 0
missing_artifact_count = 0

for key in sorted(planned):
    planned_row = planned[key]
    result = results_by_key.get(key)
    if result is None:
        missing_result_count += 1
        fail(f"{planned_row['unit_id']}/{planned_row['shard_id']} has no result row", "missing_result")
        failure_index.append(
            failure_row(
                planned_row,
                "missing",
                "missing_result",
                planned_row["required_artifacts"][0] if planned_row["required_artifacts"] else None,
                "planned unit has no corresponding result row",
            )
        )
        continue

    result_paths = set(artifact_paths(result["artifact_refs"]))
    missing_artifacts = [path for path in planned_row["required_artifacts"] if path not in result_paths]
    first_failing_artifact = first_bad_artifact(result["artifact_refs"])
    if missing_artifacts:
        missing_artifact_count += len(missing_artifacts)
        first_failing_artifact = missing_artifacts[0]
        fail(f"{planned_row['unit_id']}/{planned_row['shard_id']} missing required artifact {missing_artifacts[0]}", "missing_required_artifact")

    status_passed = result["status"] == "passed" and result["exit_code"] == 0 and not missing_artifacts
    if status_passed:
        passed_count += 1
    else:
        failed_count += 1
        signature = result["failure_signature"] or "result_failed"
        if missing_artifacts:
            signature = "missing_required_artifact"
        if first_failing_artifact is None:
            paths_seen = artifact_paths(result["artifact_refs"])
            first_failing_artifact = paths_seen[0] if paths_seen else (planned_row["required_artifacts"][0] if planned_row["required_artifacts"] else None)
        failure_index.append(
            failure_row(
                planned_row,
                result["status"],
                signature,
                first_failing_artifact,
                f"exit_code={result['exit_code']} duration_ms={result['duration_ms']}",
            )
        )

    record = {
        "run_id": result["run_id"],
        "unit_id": result["unit_id"],
        "shard_id": result["shard_id"],
        "lane_index": planned_row.get("lane_index"),
        "status": result["status"],
        "exit_code": result["exit_code"],
        "duration_ms": result["duration_ms"],
        "command_template": result["command_template"],
        "reproduction_command": planned_row["reproduction_command"],
        "artifact_refs": result["artifact_refs"],
        "failure_signature": result["failure_signature"],
        "source": result["source"],
    }
    result_records.append(record)
    events.append(
        {
            "event": "merge_result_recorded",
            "bead": "bd-31d38",
            "unit_id": result["unit_id"],
            "shard_id": result["shard_id"],
            "status": result["status"],
            "exit_code": result["exit_code"],
            "failure_signature": result["failure_signature"],
        }
    )

for result in sorted(unplanned_rows, key=lambda row: (row["unit_id"], row["shard_id"], row["run_id"])):
    failure_index.append(
        {
            "unit_id": result["unit_id"],
            "shard_id": result["shard_id"],
            "lane_index": None,
            "command_template": result["command_template"],
            "reproduction_command": " ".join(result["command_template"]),
            "status": result["status"],
            "failure_signature": "unplanned_result",
            "first_failing_artifact": None,
            "detail": "result row does not appear in the shard plan",
        }
    )

failure_index.sort(key=lambda row: (row.get("unit_id") or "", row.get("shard_id") or ""))
result_records.sort(key=lambda row: (row["unit_id"], row["shard_id"], row["run_id"]))

for failure in failure_index:
    events.append(
        {
            "event": "merge_failure_indexed",
            "bead": "bd-31d38",
            "unit_id": failure["unit_id"],
            "shard_id": failure["shard_id"],
            "status": failure["status"],
            "failure_signature": failure["failure_signature"],
            "first_failing_artifact": failure["first_failing_artifact"],
        }
    )

summary = {
    "planned_unit_count": len(planned),
    "result_row_count": len(raw_rows),
    "accepted_result_count": len(result_records),
    "passed_count": passed_count,
    "failed_count": failed_count,
    "missing_result_count": missing_result_count,
    "unplanned_result_count": len(unplanned_rows),
    "duplicate_result_count": duplicate_result_count,
    "duplicate_disagreement_count": duplicate_disagreement_count,
    "missing_required_artifact_count": missing_artifact_count,
    "failure_index_count": len(failure_index),
    "malformed_or_invalid_row_count": sum(1 for signature in failure_signatures if signature in {"malformed_jsonl", "malformed_json", "invalid_result_row", "invalid_result_field"}),
}

status = "passed" if not failure_signatures and not failure_index else "failed"
events.append(
    {
        "event": "merge_summary",
        "bead": "bd-31d38",
        "status": status,
        "planned_unit_count": summary["planned_unit_count"],
        "accepted_result_count": summary["accepted_result_count"],
        "failure_index_count": summary["failure_index_count"],
        "failure_signatures": sorted(set(failure_signatures)),
    }
)

report = {
    "schema_version": "v1",
    "bead": "bd-31d38",
    "status": status,
    "source_plan": relative_path(plan_path),
    "result_inputs": sorted(relative_path(path) for path in paths),
    "merge_algorithm": "stable_unit_id_then_shard_id",
    "required_result_fields": required_result_fields,
    "summary": summary,
    "failure_signatures": sorted(set(failure_signatures)),
    "results": result_records,
    "failure_index": failure_index,
}

write_report(report)
write_log(events)

print(
    "high_core_validation_merge: "
    f"{status.upper()} planned={summary['planned_unit_count']} "
    f"accepted={summary['accepted_result_count']} failures={summary['failure_index_count']}"
)
if status != "passed":
    raise SystemExit(1)
PY
