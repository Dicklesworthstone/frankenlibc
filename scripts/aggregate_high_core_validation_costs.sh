#!/usr/bin/env bash
# aggregate_high_core_validation_costs.sh -- validate and aggregate high-core cost telemetry for bd-whlqo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${HIGH_CORE_VALIDATION_SHARD_MANIFEST:-$ROOT/tests/conformance/high_core_validation_shards.v1.json}"
CONTRACT="${HIGH_CORE_VALIDATION_COST_CONTRACT:-$ROOT/tests/conformance/high_core_validation_cost_telemetry.v1.json}"
COST_LOG="${HIGH_CORE_VALIDATION_COST_LOG:-$ROOT/target/conformance/high_core_validation/costs.log.jsonl}"
REPORT="${HIGH_CORE_VALIDATION_COST_REPORT:-$ROOT/target/conformance/high_core_validation/costs.report.json}"
EVENT_LOG="${HIGH_CORE_VALIDATION_COST_EVENTS:-$ROOT/target/conformance/high_core_validation/costs.events.log.jsonl}"

if [[ "$#" -gt 0 ]]; then
    COST_LOG="$1"
fi

cd "${ROOT}"

python3 - "${ROOT}" "${MANIFEST}" "${CONTRACT}" "${COST_LOG}" "${REPORT}" "${EVENT_LOG}" <<'PY'
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
contract_path = Path(sys.argv[3])
cost_log_path = Path(sys.argv[4])
report_path = Path(sys.argv[5])
event_log_path = Path(sys.argv[6])

errors = []
failure_signatures = []
events = []


def relative_path(path):
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def fail(message, signature):
    errors.append(message)
    failure_signatures.append(signature)


def load_json(path, signature):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{relative_path(path)}: {exc}", signature)
        return {}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_events(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def string_array(value):
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def integer_value(value, context, signature, minimum=None, maximum=None):
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{context} must be an integer", signature)
        return None
    if minimum is not None and value < minimum:
        fail(f"{context} must be >= {minimum}", signature)
        return None
    if maximum is not None and value > maximum:
        fail(f"{context} must be <= {maximum}", signature)
        return None
    return value


def finite_positive_number(value, context, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        fail(f"{context} must be a finite number", "invalid_duration")
        return None
    if value <= 0:
        fail(f"{context} must be positive", "invalid_duration")
        return None
    if value > maximum:
        fail(f"{context} exceeds max_duration_ms {maximum}", "invalid_duration")
        return None
    return float(value)


def run_ordinal(run_id, context):
    if not isinstance(run_id, str) or not re.fullmatch(r"run-[0-9]+", run_id):
        fail(f"{context}.run_id must match run-[0-9]+", "invalid_run_id")
        return None
    return int(run_id.split("-", 1)[1])


def nearest_rank(values, percentile):
    if not values:
        return None
    ordered = sorted(values)
    rank = math.ceil((percentile / 100.0) * len(ordered))
    rank = max(1, min(rank, len(ordered)))
    value = ordered[rank - 1]
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def suggested_cost_class(duration_ms_p95):
    seconds = duration_ms_p95 / 1000.0
    if seconds <= 60:
        return "cheap"
    if seconds <= 300:
        return "medium"
    return "expensive"


contract = load_json(contract_path, "contract_unreadable")
log_contract = contract.get("log_contract", {})
if contract.get("schema_version") != "v1":
    fail("contract.schema_version must be v1", "invalid_contract")
if contract.get("bead") != "bd-whlqo":
    fail("contract.bead must be bd-whlqo", "invalid_contract")
if not isinstance(log_contract, dict):
    fail("contract.log_contract must be an object", "invalid_contract")
    log_contract = {}

required_fields = log_contract.get("required_row_fields", [])
if not string_array(required_fields):
    fail("log_contract.required_row_fields must be a non-empty string array", "invalid_contract")
    required_fields = []
allowed_statuses = set(log_contract.get("allowed_statuses", []))
if not allowed_statuses:
    fail("log_contract.allowed_statuses must be non-empty", "invalid_contract")
allowed_cache_states = set(log_contract.get("allowed_cache_states", []))
if not allowed_cache_states:
    fail("log_contract.allowed_cache_states must be non-empty", "invalid_contract")

max_duration_ms = integer_value(
    log_contract.get("max_duration_ms"),
    "log_contract.max_duration_ms",
    "invalid_contract",
    minimum=1,
)
max_artifact_count = integer_value(
    log_contract.get("max_artifact_count"),
    "log_contract.max_artifact_count",
    "invalid_contract",
    minimum=0,
)
max_artifact_bytes = integer_value(
    log_contract.get("max_artifact_bytes"),
    "log_contract.max_artifact_bytes",
    "invalid_contract",
    minimum=0,
)
max_failure_count = integer_value(
    log_contract.get("max_failure_count"),
    "log_contract.max_failure_count",
    "invalid_contract",
    minimum=0,
)

manifest = load_json(manifest_path, "manifest_unreadable")
if manifest.get("schema_version") != "v1":
    fail("manifest.schema_version must be v1", "invalid_manifest")
units = manifest.get("units")
if not isinstance(units, list) or not units:
    fail("manifest.units must be a non-empty array", "invalid_manifest")
    units = []

manifest_units = {}
for index, unit in enumerate(units):
    if not isinstance(unit, dict):
        fail(f"manifest.units[{index}] must be an object", "invalid_manifest")
        continue
    unit_id = unit.get("unit_id")
    if not isinstance(unit_id, str) or not unit_id:
        fail(f"manifest.units[{index}].unit_id missing", "invalid_manifest")
        continue
    estimated_cost = unit.get("estimated_cost", {})
    cost_class = estimated_cost.get("cost_class") if isinstance(estimated_cost, dict) else None
    manifest_units[unit_id] = cost_class if isinstance(cost_class, str) else "unknown"

rows = []
if not cost_log_path.exists():
    fail(f"{relative_path(cost_log_path)} does not exist", "cost_log_missing")
else:
    try:
        lines = cost_log_path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        fail(f"{relative_path(cost_log_path)}: {exc}", "cost_log_missing")
        lines = []
    last_ordinal = None
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        context = f"{relative_path(cost_log_path)}:{line_number}"
        try:
            row = json.loads(line)
        except Exception as exc:
            fail(f"{context}: malformed JSONL row: {exc}", "malformed_jsonl")
            continue
        if not isinstance(row, dict):
            fail(f"{context}: row must be an object", "invalid_row")
            continue

        missing = [field for field in required_fields if field not in row]
        if missing:
            fail(f"{context}: missing row field(s) {missing}", "missing_row_field")
            continue

        ordinal = run_ordinal(row.get("run_id"), context)
        if ordinal is not None and last_ordinal is not None and ordinal <= last_ordinal:
            fail(f"{context}: run_id must increase strictly", "nonmonotonic_run_id")
        if ordinal is not None:
            last_ordinal = ordinal

        unit_id = row.get("unit_id")
        if not isinstance(unit_id, str) or not unit_id:
            fail(f"{context}.unit_id must be a non-empty string", "invalid_row")
            continue
        if unit_id not in manifest_units:
            fail(f"{context}: unknown unit_id {unit_id}", "unknown_unit_id")
            continue

        shard_id = row.get("shard_id")
        if not isinstance(shard_id, str) or not shard_id:
            fail(f"{context}.shard_id must be a non-empty string", "invalid_row")
            continue

        status = row.get("status")
        if status not in allowed_statuses:
            fail(f"{context}.status must be one of {sorted(allowed_statuses)}", "invalid_row")
            continue

        exit_code = integer_value(row.get("exit_code"), f"{context}.exit_code", "invalid_row")
        duration_ms = finite_positive_number(row.get("duration_ms"), f"{context}.duration_ms", max_duration_ms or 0)
        worker_id = row.get("worker_id")
        if not isinstance(worker_id, str) or not worker_id:
            fail(f"{context}.worker_id must be a non-empty string", "invalid_row")
            continue
        cache_state = row.get("cache_state")
        if cache_state not in allowed_cache_states:
            fail(f"{context}.cache_state must be one of {sorted(allowed_cache_states)}", "invalid_row")
            continue
        artifact_count = integer_value(
            row.get("artifact_count"),
            f"{context}.artifact_count",
            "invalid_artifact_count",
            minimum=0,
            maximum=max_artifact_count,
        )
        artifact_bytes = integer_value(
            row.get("artifact_bytes"),
            f"{context}.artifact_bytes",
            "unbounded_artifact_size",
            minimum=0,
            maximum=max_artifact_bytes,
        )
        failure_count = integer_value(
            row.get("failure_count"),
            f"{context}.failure_count",
            "invalid_failure_count",
            minimum=0,
            maximum=max_failure_count,
        )

        if None in {ordinal, exit_code, duration_ms, artifact_count, artifact_bytes, failure_count}:
            continue
        if status == "passed" and exit_code != 0:
            fail(f"{context}: passed status requires exit_code 0", "invalid_row")
            continue
        if status == "failed" and failure_count == 0:
            fail(f"{context}: failed status requires failure_count > 0", "invalid_failure_count")
            continue

        normalized = {
            "run_id": row["run_id"],
            "run_ordinal": ordinal,
            "unit_id": unit_id,
            "shard_id": shard_id,
            "status": status,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "worker_id": worker_id,
            "cache_state": cache_state,
            "artifact_count": artifact_count,
            "artifact_bytes": artifact_bytes,
            "failure_count": failure_count,
        }
        rows.append(normalized)
        events.append(
            {
                "event": "cost_row_recorded",
                "bead": "bd-whlqo",
                "run_id": normalized["run_id"],
                "unit_id": unit_id,
                "shard_id": shard_id,
                "duration_ms": duration_ms,
                "worker_id": worker_id,
                "cache_state": cache_state,
                "artifact_count": artifact_count,
                "artifact_bytes": artifact_bytes,
                "failure_count": failure_count,
            }
        )

if not rows and not errors:
    fail("cost log contains no rows", "invalid_row")

if errors:
    report = {
        "schema_version": "v1",
        "bead": "bd-whlqo",
        "status": "failed",
        "source_manifest": relative_path(manifest_path),
        "source_contract": relative_path(contract_path),
        "failure_signatures": sorted(set(failure_signatures)),
        "errors": errors,
    }
    events.append(
        {
            "event": "cost_telemetry_failed",
            "bead": "bd-whlqo",
            "failure_signatures": sorted(set(failure_signatures)),
            "error_count": len(errors),
        }
    )
    write_json(report_path, report)
    write_events(event_log_path, events)
    raise SystemExit(1)

by_unit = defaultdict(list)
for row in rows:
    by_unit[row["unit_id"]].append(row)

per_unit = []
suggestions = []
status_counts = Counter()
total_failure_count = 0
total_artifact_bytes = 0
for unit_id in sorted(by_unit):
    unit_rows = by_unit[unit_id]
    unit_status_counts = Counter(row["status"] for row in unit_rows)
    durations = [row["duration_ms"] for row in unit_rows]
    artifact_sizes = [row["artifact_bytes"] for row in unit_rows]
    failure_count = sum(row["failure_count"] for row in unit_rows)
    sample_count = len(unit_rows)
    duration_p95 = nearest_rank(durations, 95)
    current_class = manifest_units.get(unit_id, "unknown")
    suggested_class = suggested_cost_class(duration_p95)
    if current_class != suggested_class:
        suggestions.append(
            {
                "unit_id": unit_id,
                "current_cost_class": current_class,
                "suggested_cost_class": suggested_class,
                "duration_ms_p95": duration_p95,
            }
        )

    status_counts.update(unit_status_counts)
    total_failure_count += failure_count
    total_artifact_bytes += sum(artifact_sizes)
    per_unit.append(
        {
            "unit_id": unit_id,
            "sample_count": sample_count,
            "status_counts": dict(sorted(unit_status_counts.items())),
            "failure_count": failure_count,
            "failure_frequency": round(failure_count / sample_count, 6),
            "duration_ms_p50": nearest_rank(durations, 50),
            "duration_ms_p95": duration_p95,
            "artifact_bytes_p95": nearest_rank(artifact_sizes, 95),
            "worker_ids": sorted(set(row["worker_id"] for row in unit_rows)),
            "cache_states": dict(sorted(Counter(row["cache_state"] for row in unit_rows).items())),
            "current_cost_class": current_class,
            "suggested_cost_class": suggested_class,
        }
    )

summary = {
    "sample_count": len(rows),
    "unit_count": len(per_unit),
    "failed_sample_count": status_counts.get("failed", 0),
    "failure_count": total_failure_count,
    "status_counts": dict(sorted(status_counts.items())),
    "total_artifact_bytes": total_artifact_bytes,
    "max_artifact_bytes": max(row["artifact_bytes"] for row in rows),
    "suggested_cost_update_count": len(suggestions),
}
events.append(
    {
        "event": "cost_telemetry_summary",
        "bead": "bd-whlqo",
        "sample_count": summary["sample_count"],
        "unit_count": summary["unit_count"],
        "failed_sample_count": summary["failed_sample_count"],
        "failure_count": summary["failure_count"],
        "suggested_cost_update_count": summary["suggested_cost_update_count"],
    }
)

report = {
    "schema_version": "v1",
    "bead": "bd-whlqo",
    "status": "passed",
    "source_manifest": relative_path(manifest_path),
    "source_contract": relative_path(contract_path),
    "aggregation_algorithm": "nearest_rank_percentiles_unit_id_ascending",
    "summary": summary,
    "per_unit": per_unit,
    "suggested_cost_updates": suggestions,
}
write_json(report_path, report)
write_events(event_log_path, events)
PY
