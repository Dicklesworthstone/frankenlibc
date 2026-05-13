#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PLAN="${FRANKENLIBC_SWARM_SCALE_INTERPOSE_PLAN:-$ROOT/tests/conformance/swarm_scale_interpose_workload_evidence_plan.v1.json}"
OUT_DIR="${FRANKENLIBC_SWARM_SCALE_INTERPOSE_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_SWARM_SCALE_INTERPOSE_REPORT:-$OUT_DIR/swarm_scale_interpose_workload_evidence_plan.report.json}"
LOG="${FRANKENLIBC_SWARM_SCALE_INTERPOSE_LOG:-$OUT_DIR/swarm_scale_interpose_workload_evidence_plan.log.jsonl}"

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

EXPECTED_SCHEMA = "swarm_scale_interpose_workload_evidence_plan.v1"
EXPECTED_BEAD = "bd-waaa6.5"
REQUIRED_MODES = {"strict", "hardened"}
REQUIRED_FAILURE_SIGNATURES = {
    "swarm_interpose_timeout",
    "swarm_interpose_segv",
    "swarm_interpose_symbol_lookup",
    "swarm_interpose_parity_mismatch",
    "swarm_interpose_performance_regression",
    "swarm_interpose_local_execution",
    "swarm_interpose_missing_field",
}
REQUIRED_LOG_FIELDS = {
    "trace_id",
    "bead_id",
    "workload_class",
    "workload_id",
    "runtime_mode",
    "replacement_level",
    "parallelism",
    "process_count",
    "thread_count",
    "command_kind",
    "timeout_ms",
    "latency_ns",
    "error_count",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
}
REQUIRED_CLASSES = {
    "fork_exec_coreutils_fanout",
    "threaded_allocator_contention",
    "dynamic_runtime_script_mix",
    "c_fixture_matrix_replay",
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


def positive_int(value: Any, context: str) -> int:
    if not isinstance(value, int) or value <= 0:
        fail(f"{context} must be a positive integer")
        return 0
    return value


def validate_sources(plan: dict[str, Any]) -> None:
    sources = plan.get("source_inputs", {})
    if not isinstance(sources, dict) or len(sources) < 4:
        fail("source_inputs must include the existing workload evidence surfaces")
        return
    for source_id, path_text in sources.items():
        if not isinstance(path_text, str) or not path_text:
            fail(f"source_inputs.{source_id} must be a non-empty string")
            continue
        require((ROOT / path_text).exists(), f"source input missing: {source_id}: {path_text}")


def validate_execution_policy(plan: dict[str, Any]) -> None:
    policy = plan.get("execution_policy", {})
    if not isinstance(policy, dict):
        fail("execution_policy must be an object")
        return
    require(policy.get("no_broad_local_stress") is True, "execution_policy.no_broad_local_stress must be true")
    require(policy.get("required_launcher") == "rch", "execution_policy.required_launcher must be rch")
    prefix = string_list(policy.get("required_command_prefix"), "execution_policy.required_command_prefix")
    require("RCH_FORCE_REMOTE=true" in prefix, "execution_policy must require RCH_FORCE_REMOTE=true")
    require("rch" in prefix and "exec" in prefix, "execution_policy must require rch exec")
    forbidden = set(string_list(policy.get("forbidden_evidence_markers"), "execution_policy.forbidden_evidence_markers"))
    require("[RCH] local" in forbidden, "execution_policy must reject [RCH] local fallback evidence")
    host = policy.get("minimum_host_profile", {})
    if not isinstance(host, dict):
        fail("execution_policy.minimum_host_profile must be an object")
    else:
        require(host.get("cpu_cores") == 64, "minimum_host_profile.cpu_cores must be 64")
        require(host.get("memory_gib") == 256, "minimum_host_profile.memory_gib must be 256")
    target_dir = policy.get("target_dir_policy", {})
    if not isinstance(target_dir, dict):
        fail("execution_policy.target_dir_policy must be an object")
    else:
        require(target_dir.get("required") is True, "target_dir_policy.required must be true")
        pattern = target_dir.get("isolation_pattern")
        require(isinstance(pattern, str) and "rch_target_frankenlibc" in pattern, "target_dir_policy must define isolated rch target pattern")


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


def validate_logs_and_budgets(plan: dict[str, Any]) -> None:
    fields = set(string_list(plan.get("required_log_fields"), "required_log_fields"))
    missing = sorted(REQUIRED_LOG_FIELDS - fields)
    require(not missing, f"required_log_fields missing: {missing}")
    modes = set(string_list(plan.get("runtime_modes"), "runtime_modes"))
    require(modes == REQUIRED_MODES, f"runtime_modes must be strict+hardened, got {sorted(modes)}")
    budgets = plan.get("budgets", {})
    if not isinstance(budgets, dict):
        fail("budgets must be an object")
        return
    positive_int(budgets.get("timeout_ms_max"), "budgets.timeout_ms_max")
    require(budgets.get("strict_error_rate_max") == 0, "strict_error_rate_max must be zero")
    require(budgets.get("hardened_error_rate_max") == 0, "hardened_error_rate_max must be zero")
    positive_int(budgets.get("strict_latency_regression_pct_max"), "budgets.strict_latency_regression_pct_max")
    positive_int(budgets.get("hardened_latency_regression_pct_max"), "budgets.hardened_latency_regression_pct_max")


def validate_workload_classes(plan: dict[str, Any]) -> dict[str, Any]:
    classes = plan.get("workload_classes", [])
    if not isinstance(classes, list) or not classes:
        fail("workload_classes must be a non-empty array")
        classes = []
    ids: set[str] = set()
    domains: set[str] = set()
    max_processes = 0
    max_threads = 0
    for index, row in enumerate(classes):
        if not isinstance(row, dict):
            fail(f"workload_classes[{index}] must be an object")
            continue
        class_id = row.get("id")
        if not isinstance(class_id, str) or not class_id:
            fail(f"workload_classes[{index}].id must be non-empty")
            class_id = f"<invalid-{index}>"
        ids.add(class_id)
        domains.update(string_list(row.get("domains"), f"workload_classes.{class_id}.domains"))
        require(set(string_list(row.get("modes"), f"workload_classes.{class_id}.modes")) == REQUIRED_MODES, f"{class_id}: modes must be strict+hardened")
        require(row.get("structured_logs") is True, f"{class_id}: structured_logs must be true")
        timeout = positive_int(row.get("timeout_ms"), f"workload_classes.{class_id}.timeout_ms")
        max_timeout = int(plan.get("budgets", {}).get("timeout_ms_max", 0) or 0)
        if max_timeout:
            require(timeout <= max_timeout, f"{class_id}: timeout exceeds budget max")
        parallelism = row.get("parallelism", {})
        if not isinstance(parallelism, dict):
            fail(f"{class_id}: parallelism must be an object")
            continue
        process_count = positive_int(parallelism.get("process_count"), f"{class_id}.parallelism.process_count")
        thread_count = positive_int(parallelism.get("thread_count"), f"{class_id}.parallelism.thread_count")
        max_processes = max(max_processes, process_count)
        max_threads = max(max_threads, thread_count)
        require(parallelism.get("requires_min_cpu_cores") == 64, f"{class_id}: requires_min_cpu_cores must be 64")
        class_signatures = set(string_list(row.get("expected_failure_signatures"), f"{class_id}.expected_failure_signatures"))
        require("swarm_interpose_local_execution" in class_signatures, f"{class_id}: must reject local execution")
        require(class_signatures <= REQUIRED_FAILURE_SIGNATURES, f"{class_id}: unknown failure signatures {sorted(class_signatures - REQUIRED_FAILURE_SIGNATURES)}")
        for artifact in string_list(row.get("artifact_refs"), f"{class_id}.artifact_refs"):
            require((ROOT / artifact).exists(), f"{class_id}: artifact ref missing: {artifact}")
    missing_ids = sorted(REQUIRED_CLASSES - ids)
    require(not missing_ids, f"missing workload classes: {missing_ids}")
    require(max_processes >= 192, "plan must include a high process fanout workload")
    require(max_threads >= 128, "plan must include a high thread contention workload")
    return {
        "class_count": len(ids),
        "domain_count": len(domains),
        "max_process_count": max_processes,
        "max_thread_count": max_threads,
        "domains": sorted(domains),
    }


def validate_outputs_and_commands(plan: dict[str, Any]) -> None:
    outputs = plan.get("evidence_outputs", {})
    if not isinstance(outputs, dict):
        fail("evidence_outputs must be an object")
    else:
        for key in ["report", "jsonl_log", "run_manifest"]:
            value = outputs.get(key)
            require(isinstance(value, str) and value.startswith("target/conformance/"), f"evidence_outputs.{key} must be under target/conformance")
    commands = string_list(plan.get("validation_commands"), "validation_commands")
    joined = "\n".join(commands)
    require("jq empty tests/conformance/swarm_scale_interpose_workload_evidence_plan.v1.json" in joined, "validation_commands must include jq empty")
    require("bash -n scripts/check_swarm_scale_interpose_workload_evidence_plan.sh" in joined, "validation_commands must include bash -n")
    require("RCH_FORCE_REMOTE=true" in joined, "validation_commands must require RCH_FORCE_REMOTE=true")
    require("rch exec" in joined, "validation_commands must use rch exec")
    require("[RCH] local" not in joined, "validation_commands must not accept local fallback proof")


start_ns = time.time_ns()
plan = load_json(PLAN, "swarm-scale interpose workload evidence plan")
checks["json_parse"] = "pass" if isinstance(plan, dict) and plan else "fail"

require(plan.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(plan.get("bead") == EXPECTED_BEAD, f"bead must be {EXPECTED_BEAD}")
require(plan.get("claim_status") == "plan_only", "claim_status must stay plan_only")
require(plan.get("replacement_level") == "L0_L1_interpose_evidence_only", "replacement_level must stay interpose evidence only")
checks["top_level"] = "pass" if not errors else "fail"

validate_sources(plan)
checks["source_inputs"] = "pass" if not errors else "fail"
validate_execution_policy(plan)
checks["execution_policy"] = "pass" if not errors else "fail"
validate_failures(plan)
checks["failure_signatures"] = "pass" if not errors else "fail"
validate_logs_and_budgets(plan)
checks["logs_and_budgets"] = "pass" if not errors else "fail"
summary = validate_workload_classes(plan)
checks["workload_classes"] = "pass" if not errors else "fail"
validate_outputs_and_commands(plan)
checks["outputs_and_commands"] = "pass" if not errors else "fail"

status = "fail" if errors else "pass"
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
trace_id = f"{EXPECTED_BEAD}::swarm-scale-interpose-plan::{int(start_ns)}"
report = {
    "schema_version": "swarm_scale_interpose_workload_evidence_plan.report.v1",
    "bead": EXPECTED_BEAD,
    "status": status,
    "plan": rel(PLAN),
    "summary": summary,
    "checks": checks,
    "failure_signature": "none" if not errors else "swarm_interpose_missing_field",
    "errors": errors,
    "elapsed_ms": int((time.time_ns() - start_ns) / 1_000_000),
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

events = [
    {
        "timestamp": timestamp,
        "trace_id": trace_id,
        "level": "info" if status == "pass" else "error",
        "event": "swarm_scale_interpose_plan_checked",
        "bead_id": EXPECTED_BEAD,
        "status": status,
        "workload_class_count": summary.get("class_count", 0),
        "failure_signature": report["failure_signature"],
        "artifact_refs": [rel(PLAN), rel(REPORT)],
    },
    {
        "timestamp": timestamp,
        "trace_id": trace_id,
        "level": "info" if status == "pass" else "error",
        "event": "swarm_scale_interpose_plan_execution_policy",
        "bead_id": EXPECTED_BEAD,
        "status": status,
        "required_launcher": plan.get("execution_policy", {}).get("required_launcher"),
        "required_remote": True,
        "failure_signature": report["failure_signature"],
        "artifact_refs": [rel(PLAN), rel(REPORT)],
    },
]
LOG.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: swarm-scale interpose workload evidence plan has {len(errors)} error(s)")
    for error in errors:
        print(f"  - {error}")
    raise SystemExit(1)

print(
    "check_swarm_scale_interpose_workload_evidence_plan: PASS "
    f"(classes={summary.get('class_count', 0)}, domains={summary.get('domain_count', 0)})"
)
PY
