#!/usr/bin/env bash
# plan_high_core_validation_shards.sh -- deterministic shard planner for bd-qa87u.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${HIGH_CORE_VALIDATION_SHARD_MANIFEST:-$ROOT/tests/conformance/high_core_validation_shards.v1.json}"
CONTRACT="${HIGH_CORE_VALIDATION_RCH_LANE_CONTRACT:-$ROOT/tests/conformance/high_core_validation_rch_lane_contract.v1.json}"
PLAN="${HIGH_CORE_VALIDATION_SHARD_PLAN:-$ROOT/target/conformance/high_core_validation/shard_plan.report.json}"
LOG="${HIGH_CORE_VALIDATION_SHARD_LOG:-$ROOT/target/conformance/high_core_validation/events.log.jsonl}"
LANES="${HIGH_CORE_VALIDATION_SHARD_LANES:-8}"

cd "${ROOT}"

python3 - "${ROOT}" "${MANIFEST}" "${PLAN}" "${LOG}" "${LANES}" "${CONTRACT}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
plan_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
lane_text = sys.argv[5]
contract_path = Path(sys.argv[6])

errors = []
failure_signatures = []


def fail(message, signature):
    errors.append(message)
    failure_signatures.append(signature)


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{path}: {exc}", "manifest_unreadable")
        return {}


def write_report(report):
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_log(rows):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def relative_path(path):
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def positive_int(value, context, signature):
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(f"{context} must be a positive integer", signature)
        return 0
    return value


manifest = load_json(manifest_path)
contract = load_json(contract_path)

if contract.get("schema_version") != "v1":
    fail("rch lane contract schema_version must be v1", "invalid_rch_lane_contract")
if contract.get("bead") != "bd-brysl":
    fail("rch lane contract bead must be bd-brysl", "invalid_rch_lane_contract")

proof_classes = contract.get("proof_classes")
if not isinstance(proof_classes, dict):
    fail("rch lane contract proof_classes must be an object", "invalid_rch_lane_contract")
    proof_classes = {}


def proof_annotation(unit_id, execution_kind):
    policy = proof_classes.get(execution_kind)
    if not isinstance(policy, dict):
        fail(f"{unit_id}: missing proof class policy for {execution_kind}", "missing_proof_class")
        policy = {}
    proof_class = policy.get("proof_class")
    if not isinstance(proof_class, str) or not proof_class:
        fail(f"{unit_id}: proof_class missing for {execution_kind}", "missing_proof_class")
        proof_class = "unknown"
    return {
        "proof_class": proof_class,
        "required_env": policy.get("required_env", []) if execution_kind == "remote_rch" else [],
        "required_rch_args": policy.get("required_rch_args", []) if execution_kind == "remote_rch" else [],
        "forbidden_output_markers": policy.get("forbidden_output_markers", []) if execution_kind == "remote_rch" else [],
        "local_fallback_invalid": bool(policy.get("local_fallback_invalid", False)),
        "cargo_allowed": bool(policy.get("cargo_allowed", execution_kind == "remote_rch")),
    }

try:
    lane_count = int(lane_text)
except ValueError:
    lane_count = -1
    fail(f"lane count must be an integer: {lane_text!r}", "unsupported_lane_count")

supported_lanes = manifest.get("planner_contract", {}).get("supported_lane_counts", [])
if lane_count not in supported_lanes:
    fail(
        f"lane count {lane_count} is not in supported_lane_counts {supported_lanes}",
        "unsupported_lane_count",
    )

if manifest.get("schema_version") != "v1":
    fail("schema_version must be v1", "invalid_schema_version")
if manifest.get("bead") != "bd-z71ti":
    fail("source manifest bead must be bd-z71ti", "invalid_manifest_bead")

units = manifest.get("units")
if not isinstance(units, list) or not units:
    fail("manifest.units must be a non-empty array", "manifest_units_missing")
    units = []

seen_unit_ids = set()
validated_units = []
for index, unit in enumerate(units):
    context = f"units[{index}]"
    if not isinstance(unit, dict):
        fail(f"{context} must be an object", "invalid_unit")
        continue

    unit_id = unit.get("unit_id")
    if not isinstance(unit_id, str) or not unit_id:
        fail(f"{context}.unit_id must be a non-empty string", "invalid_unit_id")
        continue
    if unit_id in seen_unit_ids:
        fail(f"duplicate unit_id {unit_id}", "duplicate_unit_id")
        continue
    seen_unit_ids.add(unit_id)

    command = unit.get("command_template")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        fail(f"{unit_id}: command_template must be non-empty string array", "invalid_command_template")
        continue

    artifacts = unit.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        fail(f"{unit_id}: artifacts must be non-empty", "missing_artifacts")
        continue
    required_artifacts = []
    for artifact_index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            fail(f"{unit_id}: artifacts[{artifact_index}] must be an object", "invalid_artifact")
            continue
        artifact_path = artifact.get("path")
        if not isinstance(artifact_path, str) or not artifact_path:
            fail(f"{unit_id}: artifacts[{artifact_index}].path missing", "invalid_artifact")
            continue
        if artifact.get("required") is True:
            required_artifacts.append(artifact_path)
    if not required_artifacts:
        fail(f"{unit_id}: at least one artifact must be required", "missing_required_artifact")

    cost = unit.get("estimated_cost")
    if not isinstance(cost, dict):
        fail(f"{unit_id}: estimated_cost must be object", "invalid_cost")
        continue
    cost_points = positive_int(cost.get("cost_points"), f"{unit_id}.estimated_cost.cost_points", "invalid_cost")
    wall_seconds = positive_int(
        cost.get("estimated_wall_seconds"),
        f"{unit_id}.estimated_cost.estimated_wall_seconds",
        "invalid_cost",
    )
    parallelism = positive_int(cost.get("parallelism"), f"{unit_id}.estimated_cost.parallelism", "invalid_cost")

    execution_kind = unit.get("execution_kind")
    proof = proof_annotation(unit_id, execution_kind)
    validated_units.append(
        {
            "unit_id": unit_id,
            "category": unit.get("category"),
            "description": unit.get("description"),
            "execution_kind": execution_kind,
            "command_template": command,
            "proof_class": proof["proof_class"],
            "proof_annotation": proof,
            "local_fallback_invalid": proof["local_fallback_invalid"],
            "rerun_command": " ".join(command),
            "estimated_cost": {
                "cost_class": cost.get("cost_class"),
                "cost_points": cost_points,
                "estimated_wall_seconds": wall_seconds,
                "parallelism": parallelism,
            },
            "resource_hints": unit.get("resource_hints", {}),
            "required_artifacts": required_artifacts,
        }
    )

if errors:
    failure_report = {
        "schema_version": "v1",
        "bead": "bd-qa87u",
        "status": "failed",
        "source_manifest": relative_path(manifest_path),
        "lane_count": lane_count,
        "failure_signatures": sorted(set(failure_signatures)),
        "errors": errors,
    }
    write_report(failure_report)
    write_log(
        [
            {
                "event": "planner_failed",
                "bead": "bd-qa87u",
                "lane_count": lane_count,
                "failure_signatures": sorted(set(failure_signatures)),
            }
        ]
    )
    raise SystemExit(1)

lanes = [
    {
        "shard_id": f"shard-{lane_index:02d}",
        "lane_index": lane_index,
        "estimated_cost": {"cost_points": 0, "estimated_wall_seconds": 0},
        "units": [],
        "required_artifacts": [],
    }
    for lane_index in range(lane_count)
]

events = []
assignment_order = sorted(
    validated_units,
    key=lambda item: (-item["estimated_cost"]["cost_points"], item["unit_id"]),
)
for assignment_index, unit in enumerate(assignment_order):
    lane = min(
        lanes,
        key=lambda item: (
            item["estimated_cost"]["cost_points"],
            item["estimated_cost"]["estimated_wall_seconds"],
            item["lane_index"],
        ),
    )
    unit_entry = {
        "unit_id": unit["unit_id"],
        "category": unit["category"],
        "execution_kind": unit["execution_kind"],
        "proof_class": unit["proof_class"],
        "proof_annotation": unit["proof_annotation"],
        "local_fallback_invalid": unit["local_fallback_invalid"],
        "estimated_cost": unit["estimated_cost"],
        "required_artifacts": unit["required_artifacts"],
        "command_template": unit["command_template"],
        "reproduction_command": unit["rerun_command"],
        "rerun_command": unit["rerun_command"],
    }
    lane["units"].append(unit_entry)
    lane["required_artifacts"].extend(unit["required_artifacts"])
    lane["estimated_cost"]["cost_points"] += unit["estimated_cost"]["cost_points"]
    lane["estimated_cost"]["estimated_wall_seconds"] += unit["estimated_cost"]["estimated_wall_seconds"]
    events.append(
        {
            "event": "unit_assigned",
            "bead": "bd-qa87u",
            "assignment_index": assignment_index,
            "unit_id": unit["unit_id"],
            "category": unit["category"],
            "shard_id": lane["shard_id"],
            "lane_index": lane["lane_index"],
            "unit_cost_points": unit["estimated_cost"]["cost_points"],
            "lane_cost_points_after": lane["estimated_cost"]["cost_points"],
            "artifact_refs": unit["required_artifacts"],
            "command_template": unit["command_template"],
            "proof_class": unit["proof_class"],
            "local_fallback_invalid": unit["local_fallback_invalid"],
        }
    )

for lane in lanes:
    lane["required_artifacts"] = sorted(set(lane["required_artifacts"]))
    lane["units"].sort(key=lambda item: item["unit_id"])

lane_costs = [lane["estimated_cost"]["cost_points"] for lane in lanes]
summary = {
    "unit_count": len(validated_units),
    "lane_count": lane_count,
    "total_cost_points": sum(lane_costs),
    "max_lane_cost_points": max(lane_costs) if lane_costs else 0,
    "min_lane_cost_points": min(lane_costs) if lane_costs else 0,
    "cost_spread_points": (max(lane_costs) - min(lane_costs)) if lane_costs else 0,
    "empty_lane_count": sum(1 for lane in lanes if not lane["units"]),
    "planned_unit_ids": sorted(unit["unit_id"] for unit in validated_units),
}
events.append(
    {
        "event": "planner_summary",
        "bead": "bd-qa87u",
        "lane_count": lane_count,
        "unit_count": summary["unit_count"],
        "total_cost_points": summary["total_cost_points"],
        "max_lane_cost_points": summary["max_lane_cost_points"],
        "min_lane_cost_points": summary["min_lane_cost_points"],
        "cost_spread_points": summary["cost_spread_points"],
    }
)

report = {
    "schema_version": "v1",
    "bead": "bd-qa87u",
    "status": "passed",
    "source_manifest": relative_path(manifest_path),
    "source_rch_lane_contract": relative_path(contract_path),
    "planner_algorithm": "stable_lpt_cost_points_unit_id_tiebreak",
    "stable_ordering": "lane_index_ascending_units_by_unit_id",
    "required_result_fields": manifest.get("planner_contract", {}).get("required_result_fields", []),
    "rch_lane_contract": {
        "contract_id": contract.get("contract_id"),
        "bead": contract.get("bead"),
        "required_plan_annotations": contract.get("required_plan_annotations", []),
    },
    "summary": summary,
    "lanes": lanes,
}

write_report(report)
write_log(events)

print(
    "high_core_validation_shards: PASS "
    f"lanes={lane_count} units={summary['unit_count']} "
    f"cost_spread={summary['cost_spread_points']}"
)
PY
