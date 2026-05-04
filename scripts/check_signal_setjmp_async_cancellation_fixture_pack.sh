#!/usr/bin/env bash
# check_signal_setjmp_async_cancellation_fixture_pack.sh -- bd-bp8fl.5.8 gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_SIGNAL_SETJMP_ASYNC_CANCELLATION_MANIFEST:-${ROOT}/tests/conformance/signal_setjmp_async_cancellation_fixture_pack.v1.json}"
OUT_DIR="${FLC_SIGNAL_SETJMP_ASYNC_CANCELLATION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FLC_SIGNAL_SETJMP_ASYNC_CANCELLATION_REPORT:-${OUT_DIR}/signal_setjmp_async_cancellation_fixture_pack.report.json}"
LOG="${FLC_SIGNAL_SETJMP_ASYNC_CANCELLATION_LOG:-${OUT_DIR}/signal_setjmp_async_cancellation_fixture_pack.log.jsonl}"
TARGET_DIR="${FLC_SIGNAL_SETJMP_ASYNC_CANCELLATION_TARGET_DIR:-${OUT_DIR}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" "${TARGET_DIR}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]
target_dir = sys.argv[6]

BEAD_ID = "bd-bp8fl.5.8"
GATE_ID = "signal-setjmp-async-cancellation-fixture-pack-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "signal",
    "mask_state",
    "jump_state",
    "runtime_mode",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "status",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_SCENARIO_KINDS = {
    "signal_mask_change",
    "handler_longjmp",
    "nested_blocked_signal",
    "async_signal_safe_call",
    "cancellation_blocking_syscall",
    "pthread_cleanup_interaction",
    "sigsetjmp_mask_restore",
    "negative_timeout",
    "unsupported_async_boundary",
}
REQUIRED_RUNTIME_MODES = {"strict", "hardened"}
REQUIRED_TIMEOUT_CLASSIFICATIONS = {
    "not_applicable",
    "bounded_wait_pass",
    "expected_eintr",
    "expected_timeout",
    "unsupported_deferred",
}
REQUIRED_SIGNAL_RESULTS = {
    "mask_updated",
    "handler_installed",
    "handler_delivered",
    "async_safe_ok",
    "cancellation_observed",
    "cleanup_ran",
    "mask_restored",
    "timeout_classified",
    "unsupported_deferred",
}
REQUIRED_MASK_RESULTS = {
    "not_applicable",
    "blocked",
    "blocked_then_restored",
    "nested_blocked_pending",
    "sigsetjmp_saved_and_restored",
}
REQUIRED_JUMP_RESULTS = {
    "no_jump",
    "setjmp_initial",
    "longjmp_returned",
    "nested_longjmp_returned",
    "siglongjmp_restored",
    "unsupported",
}
SIGNATURE_PRIORITY = [
    "missing_field",
    "stale_artifact",
    "missing_source_artifact",
    "missing_fixture_case",
    "signal_result_mismatch",
    "mask_state_mismatch",
    "jump_state_mismatch",
    "timeout_classification",
    "unsupported_async_boundary",
    "oracle_mismatch",
]

errors: list[dict] = []
logs: list[dict] = []


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fail(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def load_json(path: Path, label: str):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("missing_source_artifact", f"{label}: cannot parse {path}: {exc}")
        return {}


def resolve(path_text) -> Path:
    path = Path(str(path_text))
    return path if path.is_absolute() else root / path


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def require_object(value, ctx: str) -> dict:
    if isinstance(value, dict):
        return value
    fail("missing_field", f"{ctx}: must be object")
    return {}


def require_array(row: dict, field: str, ctx: str) -> list:
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty array")
    return []


def require_string(row: dict, field: str, ctx: str) -> str:
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty string")
    return ""


def require_int(row: dict, field: str, ctx: str) -> int:
    value = row.get(field)
    if isinstance(value, int) and value >= 0:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-negative integer")
    return 0


def existing_path(path_text, ctx: str) -> None:
    path = resolve(path_text)
    if not path.exists():
        fail("missing_source_artifact", f"{ctx}: missing path {path_text}")


def source_commit_ok(marker: str) -> bool:
    return marker in ("current", "unknown", source_commit)


def fixture_case_names(path_text) -> set[str]:
    fixture = load_json(resolve(path_text), path_text)
    cases = fixture.get("cases", [])
    if isinstance(cases, list):
        return {
            str(row.get("name"))
            for row in cases
            if isinstance(row, dict) and row.get("name")
        }
    fail("missing_source_artifact", f"{path_text}: cases must be an array")
    return set()


manifest = require_object(load_json(manifest_path, "manifest"), "manifest")

if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields must match signal/setjmp async-cancellation log contract")

freshness = require_object(manifest.get("freshness"), "freshness")
required_commit = str(freshness.get("required_source_commit", ""))
if not source_commit_ok(required_commit):
    fail(
        "stale_artifact",
        f"freshness.required_source_commit {required_commit!r} does not match current {source_commit}",
    )

fixture_schema = require_object(manifest.get("fixture_schema"), "fixture_schema")
schema_required_fields = set(str(field) for field in fixture_schema.get("required_fields", []))
for required in [
    "fixture_id",
    "scenario_kind",
    "signal",
    "handler_behavior",
    "mask_state",
    "jump_state",
    "cancellation_interaction",
    "async_safety_class",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "allowed_divergence",
    "expected",
    "actual",
    "timeout_ms",
    "timeout_classification",
    "source_fixture_refs",
    "direct_runner",
    "isolated_runner",
]:
    if required not in schema_required_fields:
        fail("missing_field", f"fixture_schema.required_fields missing {required}")

sources = require_object(manifest.get("sources"), "sources")
required_source_keys = [
    "signal_ops_fixture",
    "setjmp_ops_fixture",
    "pthread_thread_fixture",
    "pthread_cond_fixture",
    "process_ops_fixture",
    "oracle_precedence_divergence",
    "hard_parts_failure_replay_gate",
    "hard_parts_e2e_catalog",
    "setjmp_semantics_contract",
    "signal_abi_test",
    "setjmp_abi_test",
    "signal_ops_conformance_test",
    "setjmp_ops_conformance_test",
    "pthread_hard_parts_gate",
    "signal_native_gate",
    "setjmp_native_gate",
    "setjmp_edges_fixture",
    "setjmp_nested_fixture",
]
for key in required_source_keys:
    source_path = sources.get(key)
    if not isinstance(source_path, str) or not source_path:
        fail("missing_field", f"sources.{key}: must be non-empty string")
    else:
        existing_path(source_path, f"sources.{key}")

fixture_indexes = {
    key: fixture_case_names(sources.get(key, ""))
    for key in [
        "signal_ops_fixture",
        "setjmp_ops_fixture",
        "pthread_thread_fixture",
        "pthread_cond_fixture",
        "process_ops_fixture",
    ]
}

oracle_doc = load_json(resolve(sources.get("oracle_precedence_divergence", "")), "oracle_precedence")
oracle_kinds = {
    str(row.get("id"))
    for row in oracle_doc.get("oracle_kinds", [])
    if isinstance(row, dict) and row.get("id")
}
divergence_classes = {
    str(row.get("id"))
    for row in oracle_doc.get("divergence_classifications", [])
    if isinstance(row, dict) and row.get("id")
}

declared_diagnostics = {
    str(row.get("id"))
    for row in manifest.get("diagnostic_signatures", [])
    if isinstance(row, dict) and row.get("id")
}
for required in SIGNATURE_PRIORITY:
    if required not in declared_diagnostics:
        fail("missing_field", f"diagnostic_signatures missing {required}")

if set(str(kind) for kind in manifest.get("required_scenario_kinds", [])) != REQUIRED_SCENARIO_KINDS:
    fail("missing_field", "required_scenario_kinds must match signal/setjmp/cancellation scope")
if set(str(kind) for kind in manifest.get("required_runtime_modes", [])) != REQUIRED_RUNTIME_MODES:
    fail("missing_field", "required_runtime_modes must include strict and hardened")
if set(str(kind) for kind in manifest.get("required_timeout_classifications", [])) != REQUIRED_TIMEOUT_CLASSIFICATIONS:
    fail("timeout_classification", "required_timeout_classifications drifted")
if set(str(kind) for kind in manifest.get("required_signal_results", [])) != REQUIRED_SIGNAL_RESULTS:
    fail("signal_result_mismatch", "required_signal_results drifted")
if set(str(kind) for kind in manifest.get("required_mask_results", [])) != REQUIRED_MASK_RESULTS:
    fail("mask_state_mismatch", "required_mask_results drifted")
if set(str(kind) for kind in manifest.get("required_jump_results", [])) != REQUIRED_JUMP_RESULTS:
    fail("jump_state_mismatch", "required_jump_results drifted")

rows = manifest.get("fixture_rows")
if not isinstance(rows, list) or not rows:
    fail("missing_fixture_case", "fixture_rows must be a non-empty array")
    rows = []

seen_scenarios: set[str] = set()
seen_modes: set[str] = set()
seen_timeouts: set[str] = set()
blocked_count = 0
direct_runner_count = 0
isolated_runner_count = 0

for index, value in enumerate(rows):
    row = require_object(value, f"fixture_rows[{index}]")
    ctx = f"fixture_rows[{index}]"
    fixture_id = require_string(row, "fixture_id", ctx)
    scenario_kind = require_string(row, "scenario_kind", ctx)
    signal = require_string(row, "signal", ctx)
    handler_behavior = require_string(row, "handler_behavior", ctx)
    mask_state = require_string(row, "mask_state", ctx)
    jump_state = require_string(row, "jump_state", ctx)
    cancellation_interaction = require_string(row, "cancellation_interaction", ctx)
    async_safety_class = require_string(row, "async_safety_class", ctx)
    runtime_mode = require_string(row, "runtime_mode", ctx)
    oracle_kind = require_string(row, "oracle_kind", ctx)
    allowed_divergence = require_string(row, "allowed_divergence", ctx)
    timeout_ms = require_int(row, "timeout_ms", ctx)
    timeout_classification = require_string(row, "timeout_classification", ctx)
    require_string(row, "replacement_level", ctx)

    seen_scenarios.add(scenario_kind)
    seen_modes.add(runtime_mode)
    seen_timeouts.add(timeout_classification)

    if scenario_kind not in REQUIRED_SCENARIO_KINDS:
        fail("missing_fixture_case", f"{ctx}.scenario_kind unknown: {scenario_kind}")
    if runtime_mode not in REQUIRED_RUNTIME_MODES:
        fail("missing_fixture_case", f"{ctx}.runtime_mode unknown: {runtime_mode}")
    if oracle_kind not in oracle_kinds:
        fail("oracle_mismatch", f"{ctx}.oracle_kind unknown: {oracle_kind}")
    if allowed_divergence not in divergence_classes:
        fail("oracle_mismatch", f"{ctx}.allowed_divergence unknown: {allowed_divergence}")
    if timeout_classification not in REQUIRED_TIMEOUT_CLASSIFICATIONS:
        fail("timeout_classification", f"{ctx}.timeout_classification unknown: {timeout_classification}")
    if timeout_ms == 0 and timeout_classification not in {"not_applicable", "unsupported_deferred"}:
        fail("timeout_classification", f"{ctx}: zero timeout cannot use {timeout_classification}")
    if timeout_ms > 0 and timeout_classification == "not_applicable":
        fail("timeout_classification", f"{ctx}: non-zero timeout needs classification")
    if scenario_kind == "negative_timeout" and timeout_classification != "expected_timeout":
        fail("timeout_classification", f"{ctx}: negative timeout row must use expected_timeout")

    schedule = require_object(row.get("deterministic_schedule"), f"{ctx}.deterministic_schedule")
    for required in ["mode", "seed", "control_token"]:
        require_string(schedule, required, f"{ctx}.deterministic_schedule")
    max_steps = require_int(schedule, "max_steps", f"{ctx}.deterministic_schedule")
    if max_steps == 0:
        fail("missing_field", f"{ctx}.deterministic_schedule.max_steps must be positive")
    if "seeded" not in str(schedule.get("mode", "")) and schedule.get("mode") != "single_thread_replay":
        fail("missing_field", f"{ctx}.deterministic_schedule.mode must be replayable")

    flaky = require_object(row.get("flaky_risk_control"), f"{ctx}.flaky_risk_control")
    require_string(flaky, "scheduler", f"{ctx}.flaky_risk_control")
    require_string(flaky, "retry_policy", f"{ctx}.flaky_risk_control")
    require_int(flaky, "timeout_multiplier", f"{ctx}.flaky_risk_control")

    expected = require_object(row.get("expected"), f"{ctx}.expected")
    actual = require_object(row.get("actual"), f"{ctx}.actual")
    for required in [
        "status",
        "errno",
        "signal_result",
        "mask_result",
        "jump_result",
        "failure_signature",
        "user_diagnostic",
    ]:
        require_string(expected, required, f"{ctx}.expected")
    require_array(expected, "order", f"{ctx}.expected")
    for required in ["status", "signal_result", "mask_result", "jump_result", "failure_signature"]:
        require_string(actual, required, f"{ctx}.actual")

    expected_status = str(expected.get("status", ""))
    actual_status = str(actual.get("status", ""))
    expected_signature = str(expected.get("failure_signature", ""))
    actual_signature = str(actual.get("failure_signature", ""))
    expected_signal_result = str(expected.get("signal_result", ""))
    actual_signal_result = str(actual.get("signal_result", ""))
    expected_mask_result = str(expected.get("mask_result", ""))
    actual_mask_result = str(actual.get("mask_result", ""))
    expected_jump_result = str(expected.get("jump_result", ""))
    actual_jump_result = str(actual.get("jump_result", ""))

    if expected_signal_result not in REQUIRED_SIGNAL_RESULTS or actual_signal_result not in REQUIRED_SIGNAL_RESULTS:
        fail("signal_result_mismatch", f"{ctx}: unknown signal result")
    if actual_signal_result != expected_signal_result:
        fail("signal_result_mismatch", f"{ctx}: actual signal result differs from expected")
    if expected_mask_result not in REQUIRED_MASK_RESULTS or actual_mask_result not in REQUIRED_MASK_RESULTS:
        fail("mask_state_mismatch", f"{ctx}: unknown mask result")
    if actual_mask_result != expected_mask_result:
        fail("mask_state_mismatch", f"{ctx}: actual mask result differs from expected")
    if expected_jump_result not in REQUIRED_JUMP_RESULTS or actual_jump_result not in REQUIRED_JUMP_RESULTS:
        fail("jump_state_mismatch", f"{ctx}: unknown jump result")
    if actual_jump_result != expected_jump_result:
        fail("jump_state_mismatch", f"{ctx}: actual jump result differs from expected")
    if actual_status != expected_status:
        fail("signal_result_mismatch", f"{ctx}: actual status differs from expected")
    if actual_signature != expected_signature:
        fail("signal_result_mismatch", f"{ctx}: actual failure signature differs from expected")
    if expected_signature not in declared_diagnostics and expected_signature != "none":
        fail("signal_result_mismatch", f"{ctx}: expected failure signature is undeclared: {expected_signature}")
    if actual_status == "blocked":
        blocked_count += 1

    if scenario_kind in {"signal_mask_change", "nested_blocked_signal", "sigsetjmp_mask_restore"}:
        if actual_mask_result == "not_applicable" or mask_state == "not_applicable":
            fail("mask_state_mismatch", f"{ctx}: mask-sensitive scenario must carry mask evidence")
    if scenario_kind in {"handler_longjmp", "nested_blocked_signal", "sigsetjmp_mask_restore"}:
        if actual_jump_result in {"no_jump", "unsupported"}:
            fail("jump_state_mismatch", f"{ctx}: non-local transfer scenario needs jump evidence")
    if scenario_kind == "async_signal_safe_call" and async_safety_class != "async_signal_safe":
        fail("signal_result_mismatch", f"{ctx}: async signal safe row must use async_signal_safe class")
    if scenario_kind in {"cancellation_blocking_syscall", "pthread_cleanup_interaction"} and cancellation_interaction == "none":
        fail("signal_result_mismatch", f"{ctx}: cancellation scenario must name the cancellation interaction")
    if scenario_kind == "unsupported_async_boundary":
        if actual_status != "blocked":
            fail("unsupported_async_boundary", f"{ctx}: unsupported async boundary must remain blocked")
        if timeout_classification != "unsupported_deferred":
            fail("unsupported_async_boundary", f"{ctx}: unsupported async boundary must use unsupported_deferred")
        if actual_signature != "unsupported_async_boundary":
            fail("unsupported_async_boundary", f"{ctx}: unsupported async boundary must emit stable signature")

    for ref_index, ref_value in enumerate(require_array(row, "source_fixture_refs", ctx)):
        ref = require_object(ref_value, f"{ctx}.source_fixture_refs[{ref_index}]")
        fixture_key = require_string(ref, "fixture", f"{ctx}.source_fixture_refs[{ref_index}]")
        fixture_case = require_string(ref, "case", f"{ctx}.source_fixture_refs[{ref_index}]")
        if fixture_key not in fixture_indexes:
            fail("missing_source_artifact", f"{ctx}.source_fixture_refs[{ref_index}].fixture unknown: {fixture_key}")
        elif fixture_case not in fixture_indexes[fixture_key]:
            fail(
                "missing_source_artifact",
                f"{ctx}.source_fixture_refs[{ref_index}] case missing: {fixture_key}::{fixture_case}",
            )

    row_artifacts: list[str] = []
    for runner_key in ["direct_runner", "isolated_runner"]:
        runner = require_object(row.get(runner_key), f"{ctx}.{runner_key}")
        runner_kind = require_string(runner, "runner_kind", f"{ctx}.{runner_key}")
        require_string(runner, "command", f"{ctx}.{runner_key}")
        if runner_key == "direct_runner" and runner_kind == "direct":
            direct_runner_count += 1
        if runner_key == "isolated_runner" and runner_kind == "isolated":
            isolated_runner_count += 1
        artifacts = require_array(runner, "artifact_refs", f"{ctx}.{runner_key}")
        for artifact in artifacts:
            if not isinstance(artifact, str) or not artifact:
                fail("missing_field", f"{ctx}.{runner_key}.artifact_refs entries must be strings")
                continue
            existing_path(artifact, f"{ctx}.{runner_key}.artifact_refs")
            row_artifacts.append(artifact)

    logs.append(
        {
            "trace_id": f"signal-setjmp-async-cancellation::{fixture_id}",
            "bead_id": BEAD_ID,
            "fixture_id": fixture_id,
            "signal": signal,
            "mask_state": mask_state,
            "jump_state": jump_state,
            "runtime_mode": runtime_mode,
            "oracle_kind": oracle_kind,
            "expected": expected,
            "actual": actual,
            "errno": expected.get("errno", ""),
            "status": actual_status,
            "artifact_refs": sorted(set(row_artifacts)),
            "source_commit": source_commit,
            "target_dir": target_dir,
            "failure_signature": actual_signature,
            "handler_behavior": handler_behavior,
            "cancellation_interaction": cancellation_interaction,
            "async_safety_class": async_safety_class,
        }
    )

missing_scenarios = sorted(REQUIRED_SCENARIO_KINDS - seen_scenarios)
missing_modes = sorted(REQUIRED_RUNTIME_MODES - seen_modes)
missing_timeouts = sorted(REQUIRED_TIMEOUT_CLASSIFICATIONS - seen_timeouts)
if missing_scenarios:
    fail("missing_fixture_case", f"missing scenario kinds: {missing_scenarios}")
if missing_modes:
    fail("missing_fixture_case", f"missing runtime modes: {missing_modes}")
if missing_timeouts:
    fail("timeout_classification", f"missing timeout classifications: {missing_timeouts}")
if direct_runner_count < len(rows) or isolated_runner_count < len(rows):
    fail("missing_field", "each row must define direct and isolated runners")
if blocked_count < 2:
    fail("missing_fixture_case", "negative timeout and unsupported async blockers must stay visible")

status = "pass" if not errors else "fail"
summary = {
    "status": status,
    "bead_id": BEAD_ID,
    "gate_id": GATE_ID,
    "generated_at_utc": now(),
    "source_commit": source_commit,
    "target_dir": target_dir,
    "manifest": rel(manifest_path),
    "fixture_count": len(rows),
    "scenario_kind_count": len(seen_scenarios),
    "runtime_mode_count": len(seen_modes),
    "timeout_classification_count": len(seen_timeouts),
    "direct_runner_count": direct_runner_count,
    "isolated_runner_count": isolated_runner_count,
    "blocked_count": blocked_count,
    "log_row_count": len(logs),
    "errors": errors,
}

report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in logs),
    encoding="utf-8",
)

if errors:
    print(json.dumps(summary, sort_keys=True), file=sys.stderr)
    sys.exit(1)

print(f"signal/setjmp async-cancellation fixture gate passed: {report_path}")
PY
