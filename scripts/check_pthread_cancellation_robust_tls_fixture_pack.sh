#!/usr/bin/env bash
# check_pthread_cancellation_robust_tls_fixture_pack.sh -- bd-bp8fl.5.6 gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_PTHREAD_HARD_PARTS_MANIFEST:-${ROOT}/tests/conformance/pthread_cancellation_robust_tls_fixture_pack.v1.json}"
OUT_DIR="${FLC_PTHREAD_HARD_PARTS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FLC_PTHREAD_HARD_PARTS_REPORT:-${OUT_DIR}/pthread_cancellation_robust_tls_fixture_pack.report.json}"
LOG="${FLC_PTHREAD_HARD_PARTS_LOG:-${OUT_DIR}/pthread_cancellation_robust_tls_fixture_pack.log.jsonl}"
TARGET_DIR="${FLC_PTHREAD_HARD_PARTS_TARGET_DIR:-${OUT_DIR}}"
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

BEAD_ID = "bd-bp8fl.5.6"
GATE_ID = "pthread-cancellation-robust-tls-fixture-pack-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "thread_count",
    "operation",
    "cancellation_state",
    "runtime_mode",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "duration_ms",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_SCENARIO_KINDS = {
    "cancellation_blocking_call",
    "cleanup_handler",
    "robust_mutex_owner_dead",
    "fork_with_locks",
    "tls_destructor_iteration",
    "timeout_deadlock_negative",
}
REQUIRED_OPERATIONS = {
    "pthread_cancel",
    "pthread_cleanup",
    "pthread_mutex_consistent",
    "fork",
    "pthread_key_destructor",
    "pthread_cond_timedwait",
}
REQUIRED_RUNTIME_MODES = {"strict", "hardened"}
REQUIRED_TIMEOUT_CLASSIFICATIONS = {
    "not_applicable",
    "bounded_wait_pass",
    "expected_timeout",
    "deadlock_guard_timeout",
}
SIGNATURE_PRIORITY = [
    "missing_field",
    "stale_artifact",
    "missing_source_artifact",
    "missing_fixture_case",
    "scheduler_control_missing",
    "timeout_classification",
    "failure_signature_unstable",
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
    if not isinstance(cases, list):
        fail("missing_source_artifact", f"{path_text}: cases must be an array")
        return set()
    return {
        str(row.get("name"))
        for row in cases
        if isinstance(row, dict) and row.get("name")
    }


manifest = require_object(load_json(manifest_path, "manifest"), "manifest")

if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields must match pthread hard-parts log contract")

freshness = require_object(manifest.get("freshness"), "freshness")
required_commit = str(freshness.get("required_source_commit", ""))
if not source_commit_ok(required_commit):
    fail(
        "stale_artifact",
        f"freshness.required_source_commit {required_commit!r} does not match current {source_commit}",
    )

sources = require_object(manifest.get("sources"), "sources")
required_source_keys = [
    "pthread_thread_fixture",
    "pthread_mutex_fixture",
    "pthread_cond_fixture",
    "pthread_tls_keys_fixture",
    "process_ops_fixture",
    "oracle_precedence_divergence",
    "hard_parts_failure_replay_gate",
    "hard_parts_e2e_catalog",
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
        "pthread_thread_fixture",
        "pthread_mutex_fixture",
        "pthread_cond_fixture",
        "pthread_tls_keys_fixture",
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

manifest_scenario_kinds = set(str(kind) for kind in manifest.get("required_scenario_kinds", []))
manifest_operations = set(str(kind) for kind in manifest.get("required_operations", []))
manifest_runtime_modes = set(str(kind) for kind in manifest.get("required_runtime_modes", []))
manifest_timeouts = set(str(kind) for kind in manifest.get("required_timeout_classifications", []))
if manifest_scenario_kinds != REQUIRED_SCENARIO_KINDS:
    fail("missing_field", "required_scenario_kinds must match pthread hard-parts scope")
if manifest_operations != REQUIRED_OPERATIONS:
    fail("missing_field", "required_operations must match pthread hard-parts scope")
if manifest_runtime_modes != REQUIRED_RUNTIME_MODES:
    fail("missing_field", "required_runtime_modes must include strict and hardened")
if manifest_timeouts != REQUIRED_TIMEOUT_CLASSIFICATIONS:
    fail("timeout_classification", "required_timeout_classifications drifted")

rows = manifest.get("fixture_rows")
if not isinstance(rows, list) or not rows:
    fail("missing_fixture_case", "fixture_rows must be a non-empty array")
    rows = []

seen_scenarios: set[str] = set()
seen_operations: set[str] = set()
seen_runtime_modes: set[str] = set()
seen_timeout_classifications: set[str] = set()
direct_runner_count = 0
isolated_runner_count = 0
blocked_count = 0

for index, value in enumerate(rows):
    row = require_object(value, f"fixture_rows[{index}]")
    ctx = f"fixture_rows[{index}]"
    fixture_id = require_string(row, "fixture_id", ctx)
    scenario_kind = require_string(row, "scenario_kind", ctx)
    thread_count = require_int(row, "thread_count", ctx)
    operation = require_string(row, "operation", ctx)
    cancellation_state = require_string(row, "cancellation_state", ctx)
    runtime_mode = require_string(row, "runtime_mode", ctx)
    oracle_kind = require_string(row, "oracle_kind", ctx)
    allowed_divergence = require_string(row, "allowed_divergence", ctx)
    timeout_ms = require_int(row, "timeout_ms", ctx)
    timeout_classification = require_string(row, "timeout_classification", ctx)

    for required in [
        "thread_topology",
        "synchronization_primitive",
        "cancellation_point",
        "fork_behavior",
        "tls_destructor_sequence",
        "replacement_level",
    ]:
        require_string(row, required, ctx)

    seen_scenarios.add(scenario_kind)
    seen_operations.add(operation)
    seen_runtime_modes.add(runtime_mode)
    seen_timeout_classifications.add(timeout_classification)

    if scenario_kind not in REQUIRED_SCENARIO_KINDS:
        fail("missing_fixture_case", f"{ctx}.scenario_kind unknown: {scenario_kind}")
    if operation not in REQUIRED_OPERATIONS:
        fail("missing_fixture_case", f"{ctx}.operation unknown: {operation}")
    if runtime_mode not in REQUIRED_RUNTIME_MODES:
        fail("missing_fixture_case", f"{ctx}.runtime_mode unknown: {runtime_mode}")
    if oracle_kind not in oracle_kinds:
        fail("oracle_mismatch", f"{ctx}.oracle_kind unknown: {oracle_kind}")
    if allowed_divergence not in divergence_classes:
        fail("oracle_mismatch", f"{ctx}.allowed_divergence unknown: {allowed_divergence}")
    if timeout_classification not in REQUIRED_TIMEOUT_CLASSIFICATIONS:
        fail("timeout_classification", f"{ctx}.timeout_classification unknown: {timeout_classification}")
    if timeout_ms == 0 and timeout_classification != "not_applicable":
        fail("timeout_classification", f"{ctx}: zero timeout must be not_applicable")
    if timeout_ms > 0 and timeout_classification == "not_applicable":
        fail("timeout_classification", f"{ctx}: non-zero timeout needs classification")
    if scenario_kind == "timeout_deadlock_negative" and timeout_classification != "deadlock_guard_timeout":
        fail("timeout_classification", f"{ctx}: negative deadlock row must use deadlock_guard_timeout")

    schedule = require_object(row.get("deterministic_schedule"), f"{ctx}.deterministic_schedule")
    for required in ["mode", "seed", "control_token"]:
        require_string(schedule, required, f"{ctx}.deterministic_schedule")
    max_steps = require_int(schedule, "max_steps", f"{ctx}.deterministic_schedule")
    if max_steps == 0:
        fail("scheduler_control_missing", f"{ctx}.deterministic_schedule.max_steps must be positive")
    if "seeded" not in str(schedule.get("mode", "")) and schedule.get("mode") != "single_thread_replay":
        fail("scheduler_control_missing", f"{ctx}.deterministic_schedule.mode must be replayable")

    flaky = require_object(row.get("flaky_risk_control"), f"{ctx}.flaky_risk_control")
    require_string(flaky, "scheduler", f"{ctx}.flaky_risk_control")
    require_string(flaky, "retry_policy", f"{ctx}.flaky_risk_control")
    require_int(flaky, "timeout_multiplier", f"{ctx}.flaky_risk_control")

    expected = require_object(row.get("expected"), f"{ctx}.expected")
    actual = require_object(row.get("actual"), f"{ctx}.actual")
    for required in ["status", "errno", "failure_signature", "user_diagnostic"]:
        require_string(expected, required, f"{ctx}.expected")
    require_array(expected, "order", f"{ctx}.expected")
    actual_status = require_string(actual, "status", f"{ctx}.actual")
    actual_signature = require_string(actual, "failure_signature", f"{ctx}.actual")
    expected_signature = str(expected.get("failure_signature", ""))
    if expected_signature not in declared_diagnostics and expected_signature != "none":
        fail("failure_signature_unstable", f"{ctx}.expected.failure_signature is undeclared: {expected_signature}")
    if actual_signature != expected_signature:
        fail(
            "failure_signature_unstable",
            f"{ctx}.actual.failure_signature {actual_signature!r} != expected {expected_signature!r}",
        )
    if actual_status != expected.get("status"):
        fail("failure_signature_unstable", f"{ctx}.actual.status differs from expected.status")
    if actual_status == "blocked":
        blocked_count += 1

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
            "trace_id": f"pthread-hard-parts::{fixture_id}",
            "bead_id": BEAD_ID,
            "fixture_id": fixture_id,
            "thread_count": thread_count,
            "operation": operation,
            "cancellation_state": cancellation_state,
            "runtime_mode": runtime_mode,
            "oracle_kind": oracle_kind,
            "expected": expected,
            "actual": actual,
            "errno": expected.get("errno", ""),
            "duration_ms": min(timeout_ms, 1),
            "artifact_refs": sorted(set(row_artifacts)),
            "source_commit": source_commit,
            "target_dir": target_dir,
            "failure_signature": actual_signature,
        }
    )

missing_scenarios = sorted(REQUIRED_SCENARIO_KINDS - seen_scenarios)
missing_operations = sorted(REQUIRED_OPERATIONS - seen_operations)
missing_modes = sorted(REQUIRED_RUNTIME_MODES - seen_runtime_modes)
missing_timeouts = sorted(REQUIRED_TIMEOUT_CLASSIFICATIONS - seen_timeout_classifications)
if missing_scenarios:
    fail("missing_fixture_case", f"missing scenario kinds: {missing_scenarios}")
if missing_operations:
    fail("missing_fixture_case", f"missing operations: {missing_operations}")
if missing_modes:
    fail("missing_fixture_case", f"missing runtime modes: {missing_modes}")
if missing_timeouts:
    fail("timeout_classification", f"missing timeout classifications: {missing_timeouts}")
if direct_runner_count < len(rows) or isolated_runner_count < len(rows):
    fail("missing_field", "each row must define direct and isolated runners")
if blocked_count < 3:
    fail("missing_fixture_case", "robust, fork, and negative timeout blockers must stay visible")

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
    "operation_count": len(seen_operations),
    "runtime_mode_count": len(seen_runtime_modes),
    "timeout_classification_count": len(seen_timeout_classifications),
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

print(f"pthread hard-parts fixture gate passed: {report_path}")
PY
