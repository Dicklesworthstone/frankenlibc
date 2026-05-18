#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PLAN="${FRANKENLIBC_TSM_CONTENTION_E2E_LANE:-$ROOT/tests/conformance/tsm_contention_e2e_lane.v1.json}"
OUT_DIR="${FRANKENLIBC_TSM_CONTENTION_E2E_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_TSM_CONTENTION_E2E_REPORT:-$OUT_DIR/tsm_contention_e2e_lane.report.json}"
LOG="${FRANKENLIBC_TSM_CONTENTION_E2E_LOG:-$OUT_DIR/tsm_contention_e2e_lane.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" PLAN="$PLAN" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
PLAN = pathlib.Path(os.environ["PLAN"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "tsm_contention_e2e_lane.v1"
EXPECTED_EVIDENCE_SCHEMA = "tsm_contention_e2e_evidence.v1"
EXPECTED_BEAD = "bd-rakj1"
REQUIRED_LANES = {"smoke_small_host", "permissioned_large_host"}
REQUIRED_OPERATION_MIX = {
    "abi_malloc_free",
    "abi_memcpy_memset",
    "tls_cache_validation",
    "bloom_page_oracle_lookup",
    "runtime_math_decision",
    "metrics_counter_sample",
}
REQUIRED_EVIDENCE_FIELDS = {
    "schema_version",
    "bead_id",
    "lane_id",
    "evidence_class",
    "can_upgrade_public_readiness",
    "worker_identity",
    "cpu_logical_cores",
    "memory_gib",
    "numa_topology",
    "thread_count",
    "duration_ms",
    "operation_mix",
    "p50_latency_ns",
    "p95_latency_ns",
    "p99_latency_ns",
    "repair_count",
    "deny_count",
    "tls_cache_hits",
    "tls_cache_misses",
    "bloom_positive_count",
    "page_oracle_hits",
    "runtime_decision_count",
    "source_commit",
    "target_dir",
    "raw_log_paths",
    "artifact_refs",
    "readiness_claim",
}
REQUIRED_FAILURE_SIGNATURES = {
    "tsm_contention_missing_field",
    "tsm_contention_smoke_claim_upgrade",
    "tsm_contention_local_execution",
    "tsm_contention_insufficient_host",
    "tsm_contention_latency_regression",
}

errors: list[str] = []
checks: dict[str, str] = {}


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def fail(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        fail(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            fail(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def nonnegative_int(value: Any, context: str) -> int:
    if not isinstance(value, int) or value < 0:
        fail(f"{context} must be a non-negative integer")
        return 0
    return value


def positive_int(value: Any, context: str) -> int:
    value = nonnegative_int(value, context)
    require(value > 0, f"{context} must be positive")
    return value


def validate_sources(plan: dict[str, Any]) -> None:
    sources = plan.get("source_inputs", {})
    if not isinstance(sources, dict) or len(sources) < 4:
        fail("source_inputs must include existing workload and membrane evidence surfaces")
        return
    for source_id, path_text in sources.items():
        if not isinstance(path_text, str) or not path_text:
            fail(f"source_inputs.{source_id} must be a non-empty string")
            continue
        require((ROOT / path_text).exists(), f"source input missing: {source_id}: {path_text}")


def validate_readiness_policy(plan: dict[str, Any]) -> None:
    policy = plan.get("readiness_claim_policy", {})
    if not isinstance(policy, dict):
        fail("readiness_claim_policy must be an object")
        return
    require(policy.get("smoke_evidence_claim_level") == "shape_only", "smoke evidence must stay shape_only")
    require(
        policy.get("permissioned_evidence_claim_level") == "large_host_release_candidate",
        "permissioned evidence claim level must be large_host_release_candidate",
    )
    require(policy.get("smoke_must_not_upgrade_public_claims") is True, "smoke must not upgrade public claims")
    require(policy.get("required_release_evidence_lane") == "permissioned_large_host", "release evidence lane must be permissioned_large_host")
    require(policy.get("reject_public_readiness_when_lane") == "smoke_small_host", "smoke lane must be rejected for public readiness")


def validate_common_fields(plan: dict[str, Any]) -> None:
    operation_mix = set(string_list(plan.get("operation_mix"), "operation_mix"))
    require(operation_mix == REQUIRED_OPERATION_MIX, f"operation_mix must be {sorted(REQUIRED_OPERATION_MIX)}")
    evidence_fields = set(string_list(plan.get("required_evidence_fields"), "required_evidence_fields"))
    missing = sorted(REQUIRED_EVIDENCE_FIELDS - evidence_fields)
    extra = sorted(evidence_fields - REQUIRED_EVIDENCE_FIELDS)
    require(not missing, f"required_evidence_fields missing: {missing}")
    require(not extra, f"required_evidence_fields has unexpected fields: {extra}")


def lane_map(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    lanes = plan.get("lanes", [])
    if not isinstance(lanes, list) or not lanes:
        fail("lanes must be a non-empty array")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for index, lane in enumerate(lanes):
        if not isinstance(lane, dict):
            fail(f"lanes[{index}] must be an object")
            continue
        lane_id = lane.get("id")
        if not isinstance(lane_id, str) or not lane_id:
            fail(f"lanes[{index}].id must be a non-empty string")
            continue
        result[lane_id] = lane
    missing = sorted(REQUIRED_LANES - set(result))
    extra = sorted(set(result) - REQUIRED_LANES)
    require(not missing, f"missing lanes: {missing}")
    require(not extra, f"unexpected lanes: {extra}")
    return result


def validate_smoke_lane(lane: dict[str, Any]) -> None:
    require(lane.get("evidence_class") == "smoke_shape_only", "smoke lane evidence_class must be smoke_shape_only")
    require(lane.get("can_upgrade_public_readiness") is False, "smoke lane must not upgrade public readiness")
    require(lane.get("not_readiness_evidence") is True, "smoke lane must be marked not_readiness_evidence")
    policy = lane.get("execution_policy", {})
    if not isinstance(policy, dict):
        fail("smoke execution_policy must be an object")
        return
    require(policy.get("required_launcher") == "rch", "smoke lane must still use rch launcher")
    require(policy.get("requires_remote") is True, "smoke lane must require remote execution")
    forbidden = set(string_list(policy.get("forbidden_markers"), "smoke.execution_policy.forbidden_markers"))
    require("[RCH] local" in forbidden, "smoke lane must reject [RCH] local")
    require("public_readiness" in forbidden, "smoke lane must reject public_readiness markers")
    require(positive_int(policy.get("thread_count_max"), "smoke.thread_count_max") <= 8, "smoke thread_count_max must stay <= 8")
    require(positive_int(policy.get("duration_ms_max"), "smoke.duration_ms_max") <= 1000, "smoke duration must stay small")


def validate_permissioned_lane(lane: dict[str, Any]) -> None:
    require(lane.get("evidence_class") == "permissioned_large_host_release", "permissioned lane evidence_class mismatch")
    require(lane.get("can_upgrade_public_readiness") is True, "permissioned lane may upgrade public readiness")
    require(lane.get("not_readiness_evidence") is False, "permissioned lane must not be marked not_readiness_evidence")
    policy = lane.get("execution_policy", {})
    if not isinstance(policy, dict):
        fail("permissioned execution_policy must be an object")
        return
    require(policy.get("required_launcher") == "rch", "permissioned lane must use rch")
    require(policy.get("requires_remote") is True, "permissioned lane must require remote")
    env = policy.get("required_env", {})
    if not isinstance(env, dict):
        fail("permissioned required_env must be an object")
    else:
        require(env.get("FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD") == "1", "permissioned env must enable swarm workload")
        require(
            env.get("FFS_TSM_CONTENTION_REAL_RUN_ACK") == "tsm-contention-may-use-permissioned-large-host",
            "permissioned env must require explicit TSM contention ack",
        )
    prefix = set(string_list(policy.get("required_command_prefix"), "permissioned.required_command_prefix"))
    require("RCH_REQUIRE_REMOTE=1" in prefix, "permissioned command must require RCH_REQUIRE_REMOTE=1")
    require("rch" in prefix and "exec" in prefix, "permissioned command must use rch exec")
    forbidden = set(string_list(policy.get("forbidden_markers"), "permissioned.forbidden_markers"))
    require("[RCH] local" in forbidden and "local fallback" in forbidden, "permissioned lane must reject local fallback")
    require(positive_int(policy.get("thread_count_min"), "permissioned.thread_count_min") >= 64, "permissioned lane must require >=64 threads")
    require(positive_int(policy.get("duration_ms_min"), "permissioned.duration_ms_min") >= 10000, "permissioned lane must run long enough for p99 evidence")
    host = policy.get("host_profile", {})
    if not isinstance(host, dict):
        fail("permissioned host_profile must be an object")
    else:
        require(positive_int(host.get("cpu_cores_min"), "permissioned.cpu_cores_min") >= 64, "permissioned host must require >=64 logical CPUs")
        require(positive_int(host.get("memory_gib_min"), "permissioned.memory_gib_min") >= 256, "permissioned host must require >=256 GiB RAM")
        require(host.get("numa_topology_required") is True, "permissioned host must require NUMA topology")
    target_dir = policy.get("target_dir_policy", {})
    if not isinstance(target_dir, dict):
        fail("permissioned target_dir_policy must be an object")
    else:
        require(target_dir.get("required") is True, "permissioned target_dir must be required")
        pattern = target_dir.get("isolation_pattern")
        require(isinstance(pattern, str) and "rch_target_frankenlibc" in pattern, "permissioned target_dir must use isolated rch target")


def validate_lanes(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    lanes = lane_map(plan)
    if "smoke_small_host" in lanes:
        validate_smoke_lane(lanes["smoke_small_host"])
    if "permissioned_large_host" in lanes:
        validate_permissioned_lane(lanes["permissioned_large_host"])
    return lanes


def validate_smoke_fixture(plan: dict[str, Any], lanes: dict[str, dict[str, Any]]) -> dict[str, int]:
    fixture = plan.get("smoke_fixture", {})
    if not isinstance(fixture, dict):
        fail("smoke_fixture must be an object")
        return {"thread_count": 0, "duration_ms": 0}
    for field in REQUIRED_EVIDENCE_FIELDS:
        require(field in fixture, f"smoke_fixture missing {field}")
    require(fixture.get("schema_version") == EXPECTED_EVIDENCE_SCHEMA, f"smoke_fixture schema_version must be {EXPECTED_EVIDENCE_SCHEMA}")
    require(fixture.get("bead_id") == EXPECTED_BEAD, f"smoke_fixture bead_id must be {EXPECTED_BEAD}")
    require(fixture.get("lane_id") == "smoke_small_host", "smoke_fixture lane_id must be smoke_small_host")
    require(fixture.get("evidence_class") == "smoke_shape_only", "smoke_fixture evidence_class must be smoke_shape_only")
    require(fixture.get("can_upgrade_public_readiness") is False, "smoke_fixture must not upgrade public readiness")
    require(fixture.get("readiness_claim") == "shape_only", "smoke_fixture readiness_claim must be shape_only")
    thread_count = positive_int(fixture.get("thread_count"), "smoke_fixture.thread_count")
    duration_ms = positive_int(fixture.get("duration_ms"), "smoke_fixture.duration_ms")
    smoke_policy = lanes.get("smoke_small_host", {}).get("execution_policy", {})
    if isinstance(smoke_policy, dict):
        max_threads = smoke_policy.get("thread_count_max")
        max_duration = smoke_policy.get("duration_ms_max")
        if isinstance(max_threads, int):
            require(thread_count <= max_threads, "smoke_fixture thread_count exceeds smoke lane max")
        if isinstance(max_duration, int):
            require(duration_ms <= max_duration, "smoke_fixture duration_ms exceeds smoke lane max")
    p50 = positive_int(fixture.get("p50_latency_ns"), "smoke_fixture.p50_latency_ns")
    p95 = positive_int(fixture.get("p95_latency_ns"), "smoke_fixture.p95_latency_ns")
    p99 = positive_int(fixture.get("p99_latency_ns"), "smoke_fixture.p99_latency_ns")
    require(p50 <= p95 <= p99, "smoke_fixture latency percentiles must be monotone p50<=p95<=p99")
    for field in [
        "repair_count",
        "deny_count",
        "tls_cache_hits",
        "tls_cache_misses",
        "bloom_positive_count",
        "page_oracle_hits",
        "runtime_decision_count",
    ]:
        nonnegative_int(fixture.get(field), f"smoke_fixture.{field}")
    mix = set(string_list(fixture.get("operation_mix"), "smoke_fixture.operation_mix"))
    require(mix == REQUIRED_OPERATION_MIX, "smoke_fixture operation_mix must cover all required operations")
    string_list(fixture.get("raw_log_paths"), "smoke_fixture.raw_log_paths")
    string_list(fixture.get("artifact_refs"), "smoke_fixture.artifact_refs")
    return {"thread_count": thread_count, "duration_ms": duration_ms}


def validate_failures(plan: dict[str, Any]) -> None:
    failures = plan.get("failure_signatures", {})
    if not isinstance(failures, dict):
        fail("failure_signatures must be an object")
        failures = {}
    missing = sorted(REQUIRED_FAILURE_SIGNATURES - set(failures))
    extra = sorted(set(failures) - REQUIRED_FAILURE_SIGNATURES)
    require(not missing, f"missing failure signatures: {missing}")
    require(not extra, f"unexpected failure signatures: {extra}")
    for signature, row in failures.items():
        if not isinstance(row, dict):
            fail(f"failure_signatures.{signature} must be an object")
            continue
        require(row.get("decision") in {"fail", "skip"}, f"{signature}: decision must be fail or skip")
        require(isinstance(row.get("class"), str) and row["class"], f"{signature}: class must be non-empty")
        require(isinstance(row.get("next_safe_action"), str) and row["next_safe_action"], f"{signature}: next_safe_action must be non-empty")


def validate_outputs_and_commands(plan: dict[str, Any]) -> None:
    outputs = plan.get("evidence_outputs", {})
    if not isinstance(outputs, dict):
        fail("evidence_outputs must be an object")
    else:
        for key in ["report", "jsonl_log", "smoke_evidence", "permissioned_evidence"]:
            value = outputs.get(key)
            require(isinstance(value, str) and value.startswith("target/conformance/"), f"evidence_outputs.{key} must be under target/conformance")
    commands = string_list(plan.get("validation_commands"), "validation_commands")
    joined = "\n".join(commands)
    require("jq empty tests/conformance/tsm_contention_e2e_lane.v1.json" in joined, "validation_commands must include jq empty")
    require("bash -n scripts/check_tsm_contention_e2e_lane.sh" in joined, "validation_commands must include bash -n")
    require("bash scripts/check_tsm_contention_e2e_lane.sh" in joined, "validation_commands must include checker execution")
    require("RCH_REQUIRE_REMOTE=1" in joined, "validation_commands must require RCH_REQUIRE_REMOTE=1")
    require("rch exec" in joined, "validation_commands must use rch exec")
    require("[RCH] local" not in joined, "validation_commands must not accept local fallback proof")


start_ns = time.time_ns()
plan = load_json(PLAN, "TSM contention E2E lane")
checks["json_parse"] = "pass" if plan else "fail"

require(plan.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(plan.get("bead") == EXPECTED_BEAD, f"bead must be {EXPECTED_BEAD}")
require(plan.get("claim_status") == "lane_contract_only", "claim_status must stay lane_contract_only")
checks["top_level"] = "pass" if not errors else "fail"

validate_sources(plan)
checks["source_inputs"] = "pass" if not errors else "fail"
validate_readiness_policy(plan)
checks["readiness_claim_policy"] = "pass" if not errors else "fail"
validate_common_fields(plan)
checks["common_fields"] = "pass" if not errors else "fail"
lanes = validate_lanes(plan)
checks["lanes"] = "pass" if not errors else "fail"
smoke_summary = validate_smoke_fixture(plan, lanes)
checks["smoke_fixture"] = "pass" if not errors else "fail"
validate_failures(plan)
checks["failure_signatures"] = "pass" if not errors else "fail"
validate_outputs_and_commands(plan)
checks["outputs_and_commands"] = "pass" if not errors else "fail"

status = "fail" if errors else "pass"
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
trace_id = f"{EXPECTED_BEAD}::tsm-contention-e2e-lane::{int(start_ns)}"
failure_signature = "none" if not errors else "tsm_contention_missing_field"
report = {
    "schema_version": "tsm_contention_e2e_lane.report.v1",
    "bead": EXPECTED_BEAD,
    "status": status,
    "plan": rel(PLAN),
    "summary": {
        "lane_count": len(lanes),
        "smoke_thread_count": smoke_summary["thread_count"],
        "smoke_duration_ms": smoke_summary["duration_ms"],
        "permissioned_min_thread_count": lanes.get("permissioned_large_host", {})
        .get("execution_policy", {})
        .get("thread_count_min", 0),
        "required_operation_count": len(REQUIRED_OPERATION_MIX),
        "smoke_can_upgrade_public_readiness": plan.get("smoke_fixture", {}).get("can_upgrade_public_readiness"),
        "required_release_evidence_lane": plan.get("readiness_claim_policy", {}).get("required_release_evidence_lane"),
    },
    "checks": checks,
    "failure_signature": failure_signature,
    "errors": errors,
    "elapsed_ms": int((time.time_ns() - start_ns) / 1_000_000),
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

events = [
    {
        "timestamp": timestamp,
        "trace_id": trace_id,
        "level": "info" if status == "pass" else "error",
        "event": "tsm_contention_e2e_lane_checked",
        "bead_id": EXPECTED_BEAD,
        "status": status,
        "lane_count": len(lanes),
        "failure_signature": failure_signature,
        "artifact_refs": [rel(PLAN), rel(REPORT)],
    },
    {
        "timestamp": timestamp,
        "trace_id": trace_id,
        "level": "info" if status == "pass" else "error",
        "event": "tsm_contention_smoke_shape_validated",
        "bead_id": EXPECTED_BEAD,
        "status": status,
        "lane_id": "smoke_small_host",
        "readiness_claim": plan.get("smoke_fixture", {}).get("readiness_claim"),
        "can_upgrade_public_readiness": plan.get("smoke_fixture", {}).get("can_upgrade_public_readiness"),
        "failure_signature": failure_signature,
        "artifact_refs": [rel(PLAN), rel(REPORT)],
    },
    {
        "timestamp": timestamp,
        "trace_id": trace_id,
        "level": "info" if status == "pass" else "error",
        "event": "tsm_contention_permissioned_large_host_policy_pinned",
        "bead_id": EXPECTED_BEAD,
        "status": status,
        "lane_id": "permissioned_large_host",
        "required_remote": True,
        "min_thread_count": lanes.get("permissioned_large_host", {})
        .get("execution_policy", {})
        .get("thread_count_min"),
        "failure_signature": failure_signature,
        "artifact_refs": [rel(PLAN), rel(REPORT)],
    },
]
LOG.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: TSM contention E2E lane has {len(errors)} error(s)")
    for error in errors:
        print(f"  - {error}")
    raise SystemExit(1)

print(
    "check_tsm_contention_e2e_lane: PASS "
    f"(lanes={len(lanes)}, smoke_threads={smoke_summary['thread_count']})"
)
PY
