#!/usr/bin/env bash
# check_pthread_cancellation_robust_mutex_tls.sh -- bd-bp8fl.5.6 pthread fixture gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_PTHREAD_HARDPARTS_MANIFEST:-${ROOT}/tests/conformance/pthread_cancellation_robust_mutex_tls.v1.json}"
OUT_DIR="${FLC_PTHREAD_HARDPARTS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FLC_PTHREAD_HARDPARTS_REPORT:-${OUT_DIR}/pthread_cancellation_robust_mutex_tls.report.json}"
LOG="${FLC_PTHREAD_HARDPARTS_LOG:-${OUT_DIR}/pthread_cancellation_robust_mutex_tls.log.jsonl}"
TARGET_DIR="${FLC_PTHREAD_HARDPARTS_TARGET_DIR:-${OUT_DIR}}"
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
GATE_ID = "pthread-cancellation-robust-mutex-tls-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "thread_count",
    "operation",
    "cancellation_state",
    "runtime_mode",
    "oracle_kind",
    "expected_status",
    "actual_status",
    "errno",
    "duration_ms",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_FIXTURE_KINDS = {
    "cancellation_blocking_call",
    "cleanup_handler_stack",
    "robust_mutex_owner_dead",
    "fork_with_lock_boundary",
    "timed_wait_timeout",
    "tls_destructor_iteration",
    "negative_deadlock_timeout",
    "cancellation_disabled_noop",
}
REQUIRED_SYMBOLS = {
    "_pthread_cleanup_pop",
    "_pthread_cleanup_push",
    "__call_tls_dtors",
    "fork",
    "pthread_atfork",
    "pthread_cancel",
    "pthread_cond_timedwait",
    "pthread_join",
    "pthread_key_create",
    "pthread_mutex_consistent",
    "pthread_mutex_lock",
    "pthread_mutexattr_setrobust",
    "pthread_setspecific",
    "pthread_testcancel",
}
REQUIRED_RUNTIME_MODES = {"strict", "hardened"}
REQUIRED_REPLACEMENT_LEVELS = {"L0"}
REQUIRED_ERRNO_CLASSES = {"none", "ECANCELED", "EOWNERDEAD", "ETIMEDOUT", "ENOSYS"}
DIAGNOSTIC_SIGNATURES = [
    "missing_field",
    "stale_artifact",
    "missing_source_artifact",
    "missing_fixture_kind",
    "cancellation_contract_gap",
    "robust_mutex_classification",
    "fork_lock_boundary",
    "tls_destructor_order",
    "timeout_classification",
]
ALLOWED_STATUSES = {"pass", "blocked", "timeout", "expected_failure"}

errors = []
logs = []


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fail(signature, message):
    errors.append({"failure_signature": signature, "message": message})


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("missing_source_artifact", f"cannot parse {path}: {exc}")
        return {}


def resolve(path_text):
    path = Path(str(path_text))
    return path if path.is_absolute() else root / path


def require_object(value, ctx):
    if isinstance(value, dict):
        return value
    fail("missing_field", f"{ctx}: must be object")
    return {}


def require_array(row, field, ctx):
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty array")
    return []


def require_string(row, field, ctx):
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty string")
    return ""


def require_positive_int(row, field, ctx):
    value = row.get(field)
    if isinstance(value, int) and value > 0:
        return value
    fail("missing_field", f"{ctx}.{field}: must be positive integer")
    return 0


def existing_path(path_text, ctx):
    path = resolve(path_text)
    if not path.exists():
        fail("missing_source_artifact", f"{ctx}: missing path {path_text}")


def source_commit_ok(marker):
    return marker in ("current", "unknown", source_commit)


manifest = require_object(load_json(manifest_path), "manifest")

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
for key in [
    "pthread_abi",
    "glibc_internal_abi",
    "process_abi",
    "version_script",
    "pthread_thread_fixtures",
    "pthread_thread_stress",
    "pthread_condvar_scenarios",
    "standalone_link_run_smoke",
    "user_visible_diagnostics",
    "hard_parts_e2e_catalog",
]:
    path_text = sources.get(key)
    if isinstance(path_text, str) and path_text:
        existing_path(path_text, f"sources.{key}")
    else:
        fail("missing_field", f"sources.{key}: must be non-empty string")

declared_signatures = {
    str(row.get("id"))
    for row in manifest.get("diagnostic_signatures", [])
    if isinstance(row, dict) and row.get("id")
}
for signature in DIAGNOSTIC_SIGNATURES:
    if signature not in declared_signatures:
        fail("missing_field", f"diagnostic_signatures missing {signature}")

if set(map(str, manifest.get("required_fixture_kinds", []))) != REQUIRED_FIXTURE_KINDS:
    fail("missing_fixture_kind", "required_fixture_kinds must match pthread hard-parts coverage")
if set(map(str, manifest.get("required_symbols", []))) != REQUIRED_SYMBOLS:
    fail("missing_fixture_kind", "required_symbols must match pthread hard-parts coverage")
if set(map(str, manifest.get("required_runtime_modes", []))) != REQUIRED_RUNTIME_MODES:
    fail("missing_fixture_kind", "required_runtime_modes must include strict and hardened")
if set(map(str, manifest.get("required_replacement_levels", []))) != REQUIRED_REPLACEMENT_LEVELS:
    fail("missing_fixture_kind", "required_replacement_levels must be L0")
if set(map(str, manifest.get("required_errno_classes", []))) != REQUIRED_ERRNO_CLASSES:
    fail("missing_field", "required_errno_classes drifted")

rows = manifest.get("fixture_rows")
if not isinstance(rows, list) or not rows:
    fail("missing_fixture_kind", "fixture_rows must be a non-empty array")
    rows = []

seen_kinds = set()
seen_symbols = set()
seen_modes = set()
seen_levels = set()
direct_runner_count = 0
isolated_runner_count = 0
blocked_or_timeout_count = 0

for index, value in enumerate(rows):
    row = require_object(value, f"fixture_rows[{index}]")
    ctx = f"fixture_rows[{index}]"
    fixture_id = require_string(row, "fixture_id", ctx)
    fixture_kind = require_string(row, "fixture_kind", ctx)
    thread_count = require_positive_int(row, "thread_count", ctx)
    operation = require_string(row, "operation", ctx)
    cancellation_state = require_string(row, "cancellation_state", ctx)
    sync_primitive = require_string(row, "sync_primitive", ctx)
    fork_behavior = require_string(row, "fork_behavior", ctx)
    tls_destructor_sequence = require_string(row, "tls_destructor_sequence", ctx)
    timeout_ms = require_positive_int(row, "timeout_ms", ctx)
    runtime_mode = require_string(row, "runtime_mode", ctx)
    replacement_level = require_string(row, "replacement_level", ctx)
    oracle_kind = require_string(row, "oracle_kind", ctx)
    covered_symbols = set(map(str, require_array(row, "covered_symbols", ctx)))
    expected = require_object(row.get("expected"), f"{ctx}.expected")
    artifact_refs = require_array(row, "artifact_refs", ctx)
    source_commit_state = require_string(row, "source_commit_state", ctx)
    direct_runner = require_object(row.get("direct_runner"), f"{ctx}.direct_runner")
    isolated_runner = require_object(row.get("isolated_runner"), f"{ctx}.isolated_runner")

    seen_kinds.add(fixture_kind)
    seen_symbols.update(covered_symbols)
    seen_modes.add(runtime_mode)
    seen_levels.add(replacement_level)

    if fixture_kind not in REQUIRED_FIXTURE_KINDS:
        fail("missing_fixture_kind", f"{fixture_id}: unknown fixture_kind {fixture_kind}")
    unknown_symbols = covered_symbols - REQUIRED_SYMBOLS
    if unknown_symbols:
        fail("missing_fixture_kind", f"{fixture_id}: unknown covered_symbols {sorted(unknown_symbols)}")
    if runtime_mode not in REQUIRED_RUNTIME_MODES:
        fail("missing_fixture_kind", f"{fixture_id}: runtime_mode must be strict or hardened")
    if replacement_level not in REQUIRED_REPLACEMENT_LEVELS:
        fail("missing_fixture_kind", f"{fixture_id}: replacement_level must be L0")
    if not source_commit_ok(source_commit_state):
        fail("stale_artifact", f"{fixture_id}: source_commit_state {source_commit_state!r} is stale")

    for field in ["status", "errno", "order", "failure_signature", "user_diagnostic"]:
        require_string(expected, field, f"{ctx}.expected")

    status = str(expected.get("status", ""))
    errno = str(expected.get("errno", ""))
    failure_signature = str(expected.get("failure_signature", ""))
    if status not in ALLOWED_STATUSES:
        fail("missing_field", f"{fixture_id}: unknown expected status {status}")
    if errno not in REQUIRED_ERRNO_CLASSES:
        fail("missing_field", f"{fixture_id}: unknown errno class {errno}")
    if status == "pass" and failure_signature != "none":
        fail("missing_field", f"{fixture_id}: pass rows must use failure_signature none")
    if status in {"blocked", "timeout", "expected_failure"} and failure_signature == "none":
        fail("missing_field", f"{fixture_id}: non-pass rows need a failure_signature")
    if status in {"blocked", "timeout", "expected_failure"}:
        blocked_or_timeout_count += 1

    if fixture_kind == "cancellation_blocking_call" and status == "pass":
        fail("cancellation_contract_gap", f"{fixture_id}: L0 cancellation blocking call cannot claim pass")
    if fixture_kind == "cleanup_handler_stack" and not {"_pthread_cleanup_push", "_pthread_cleanup_pop"} <= covered_symbols:
        fail("cancellation_contract_gap", f"{fixture_id}: cleanup stack needs push and pop symbols")
    if fixture_kind == "robust_mutex_owner_dead":
        if not {"pthread_mutexattr_setrobust", "pthread_mutex_consistent"} <= covered_symbols:
            fail("robust_mutex_classification", f"{fixture_id}: robust owner-dead row needs robust+consistent symbols")
        if errno != "EOWNERDEAD":
            fail("robust_mutex_classification", f"{fixture_id}: robust owner-dead row must classify EOWNERDEAD")
    if fixture_kind == "fork_with_lock_boundary":
        if not {"pthread_atfork", "fork"} <= covered_symbols:
            fail("fork_lock_boundary", f"{fixture_id}: fork boundary needs pthread_atfork and fork")
        if fork_behavior == "not_applicable":
            fail("fork_lock_boundary", f"{fixture_id}: fork_behavior cannot be not_applicable")
    if fixture_kind == "tls_destructor_iteration":
        if not {"pthread_key_create", "pthread_setspecific", "__call_tls_dtors"} <= covered_symbols:
            fail("tls_destructor_order", f"{fixture_id}: TLS destructor row needs key, setspecific, and destructor symbols")
        if tls_destructor_sequence == "not_applicable":
            fail("tls_destructor_order", f"{fixture_id}: tls_destructor_sequence cannot be not_applicable")
    if fixture_kind in {"timed_wait_timeout", "negative_deadlock_timeout"}:
        if status != "timeout" or errno != "ETIMEDOUT":
            fail("timeout_classification", f"{fixture_id}: timeout rows need status timeout and ETIMEDOUT")
        if timeout_ms <= 0:
            fail("timeout_classification", f"{fixture_id}: timeout rows need positive timeout_ms")

    for ref in artifact_refs:
        existing_path(ref, f"{fixture_id}.artifact_refs")

    for runner_name, runner in [("direct_runner", direct_runner), ("isolated_runner", isolated_runner)]:
        runner_kind = require_string(runner, "runner_kind", f"{ctx}.{runner_name}")
        require_string(runner, "command", f"{ctx}.{runner_name}")
        refs = require_array(runner, "artifact_refs", f"{ctx}.{runner_name}")
        if runner_kind == "direct":
            direct_runner_count += 1
        if runner_kind == "isolated":
            isolated_runner_count += 1
        for ref in refs:
            existing_path(ref, f"{fixture_id}.{runner_name}.artifact_refs")

    primary_symbol = sorted(covered_symbols)[0] if covered_symbols else "unknown"
    log_row = {
        "trace_id": f"{BEAD_ID}::{fixture_id}",
        "bead_id": BEAD_ID,
        "fixture_id": fixture_id,
        "thread_count": thread_count,
        "operation": operation,
        "cancellation_state": cancellation_state,
        "runtime_mode": runtime_mode,
        "oracle_kind": oracle_kind,
        "expected_status": status,
        "actual_status": status if not errors else "not_run",
        "errno": errno,
        "duration_ms": timeout_ms if status == "timeout" else 0,
        "artifact_refs": artifact_refs,
        "source_commit": source_commit,
        "target_dir": target_dir,
        "failure_signature": failure_signature,
        "symbol": primary_symbol,
        "covered_symbols": sorted(covered_symbols),
        "replacement_level": replacement_level,
        "sync_primitive": sync_primitive,
        "fork_behavior": fork_behavior,
        "tls_destructor_sequence": tls_destructor_sequence,
    }
    logs.append(log_row)

missing_kinds = sorted(REQUIRED_FIXTURE_KINDS - seen_kinds)
missing_symbols = sorted(REQUIRED_SYMBOLS - seen_symbols)
missing_modes = sorted(REQUIRED_RUNTIME_MODES - seen_modes)
missing_levels = sorted(REQUIRED_REPLACEMENT_LEVELS - seen_levels)
if missing_kinds:
    fail("missing_fixture_kind", f"missing fixture kinds: {missing_kinds}")
if missing_symbols:
    fail("missing_fixture_kind", f"missing symbols: {missing_symbols}")
if missing_modes:
    fail("missing_fixture_kind", f"missing runtime modes: {missing_modes}")
if missing_levels:
    fail("missing_fixture_kind", f"missing replacement levels: {missing_levels}")

summary = {
    "fixture_row_count": len(rows),
    "covered_fixture_kind_count": len(seen_kinds),
    "covered_symbol_count": len(seen_symbols),
    "runtime_mode_count": len(seen_modes),
    "replacement_level_count": len(seen_levels),
    "direct_runner_count": direct_runner_count,
    "isolated_runner_count": isolated_runner_count,
    "blocked_or_timeout_count": blocked_or_timeout_count,
    "log_row_count": len(logs),
}

report = {
    "schema_version": "v1",
    "bead_id": BEAD_ID,
    "gate_id": GATE_ID,
    "status": "fail" if errors else "pass",
    "generated_at_utc": now(),
    "source_commit": source_commit,
    "target_dir": target_dir,
    "summary": summary,
    "errors": errors,
    "report_artifacts": {
        "manifest": str(manifest_path),
        "report": str(report_path),
        "log": str(log_path),
    },
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as handle:
    for row in logs:
        handle.write(json.dumps(row, sort_keys=True) + "\n")

print(json.dumps(report, sort_keys=True))
if errors:
    sys.exit(1)
PY
