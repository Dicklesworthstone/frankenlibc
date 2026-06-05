#!/usr/bin/env bash
# Validate bd-ldj.2.1 pthread-family completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${1:-${ROOT}/tests/conformance/pthread_family_completion_contract.v1.json}"
OUT_DIR="${2:-${ROOT}/target/conformance}"
REPORT_PATH="${OUT_DIR}/pthread_family_completion_contract.report.json"
LOG_PATH="${OUT_DIR}/pthread_family_completion_contract.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT_PATH}" "${REPORT_PATH}" "${LOG_PATH}" <<'PY'
import hashlib
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT_PATH = pathlib.Path(sys.argv[2]).resolve()
REPORT_PATH = pathlib.Path(sys.argv[3]).resolve()
LOG_PATH = pathlib.Path(sys.argv[4]).resolve()

EXPECTED_SCHEMA = "pthread_family_completion_contract.v1"
EXPECTED_BEAD = "bd-ldj.2"
EXPECTED_COMPLETION_BEAD = "bd-ldj.2.1"
EXPECTED_MISSING_ITEMS = [
    "tests.unit.primary",
    "tests.integration.primary",
    "tests.e2e.primary",
]
EXPECTED_TARGET_SYMBOLS = [
    "pthread_create",
    "pthread_join",
    "pthread_detach",
    "pthread_self",
    "pthread_equal",
    "pthread_mutex_init",
    "pthread_mutex_destroy",
    "pthread_mutex_lock",
    "pthread_mutex_trylock",
    "pthread_mutex_unlock",
    "pthread_cond_init",
    "pthread_cond_destroy",
    "pthread_cond_wait",
    "pthread_cond_timedwait",
    "pthread_cond_clockwait",
    "pthread_cond_signal",
    "pthread_cond_broadcast",
    "pthread_rwlock_init",
    "pthread_rwlock_destroy",
    "pthread_rwlock_rdlock",
    "pthread_rwlock_wrlock",
    "pthread_rwlock_unlock",
    "pthread_rwlock_tryrdlock",
    "pthread_rwlock_trywrlock",
    "pthread_barrier_init",
    "pthread_barrier_destroy",
    "pthread_barrier_wait",
    "pthread_key_create",
    "pthread_key_delete",
    "pthread_getspecific",
    "pthread_setspecific",
    "pthread_once",
    "pthread_spin_init",
    "pthread_spin_destroy",
    "pthread_spin_lock",
    "pthread_spin_trylock",
    "pthread_spin_unlock",
    "pthread_cancel",
    "pthread_getattr_np",
    "pthread_tryjoin_np",
    "pthread_timedjoin_np",
    "pthread_clockjoin_np",
]
EXPECTED_SUPPORT_STATUSES = {"Implemented", "WrapsHostLibc"}
EXPECTED_SOURCE_KEYS = {
    "core_thread",
    "core_mutex",
    "core_cond",
    "core_rwlock",
    "core_tls",
    "abi_pthread",
    "abi_pthread_test",
    "abi_thread_lifecycle_test",
    "abi_mutex_core_test",
    "abi_cond_core_test",
    "abi_rwlock_core_test",
    "abi_once_test",
    "abi_tsd_test",
    "abi_barrier_spin_diff_test",
    "support_matrix",
    "pthread_thread_fixture",
    "pthread_mutex_fixture",
    "pthread_cond_fixture",
    "pthread_tls_keys_fixture",
    "pthread_gnu_extensions_fixture",
    "conformance_thread_test",
    "conformance_mutex_test",
    "conformance_cond_test",
    "conformance_tls_test",
    "conformance_gnu_test",
    "e2e_c_fixture_runner",
    "e2e_pthread_fixture",
    "e2e_pthread_mutex_adversarial_fixture",
    "thread_stress_spec",
    "thread_stress_runner",
    "completion_checker",
    "completion_test",
}
EXPECTED_EVIDENCE_KEYS = {"unit_primary", "integration_primary", "e2e_primary"}
EXPECTED_UNIT_REFS = {
    ("core_thread", "create_and_join_thread_returns_value"),
    ("core_thread", "multiple_threads_created_and_joined"),
    ("core_thread", "join_after_detach_returns_einval"),
    ("core_mutex", "contract_errorcheck_relock_is_ededlk"),
    ("core_mutex", "contract_recursive_relock_succeeds_nonblocking"),
    ("core_mutex", "posix_mutex_unlock_conformance_table"),
    ("core_cond", "scenario_timedwait_monotonic_past_deadline"),
    ("core_cond", "scenario_signal_before_wait_not_queued"),
    ("core_cond", "posix_cond_destroy_conformance_table"),
    ("core_rwlock", "sanitize_rwlock_kind_check"),
    ("core_tls", "setspecific_and_getspecific_roundtrip"),
    ("core_tls", "destructor_iteration_is_bounded_at_max"),
}
EXPECTED_INTEGRATION_REFS = {
    ("abi_pthread_test", "thread_create_join"),
    ("abi_pthread_test", "mutex_errorcheck_double_lock_returns_edeadlk"),
    ("abi_pthread_test", "mutex_zeroed_static_initializer_promotes_on_first_use"),
    ("abi_pthread_test", "condvar_wait_signal_wakeup"),
    ("abi_pthread_test", "cond_clockwait_rejects_invalid_clockid"),
    ("abi_pthread_test", "rwlock_multiple_readers"),
    ("abi_pthread_test", "key_setspecific_getspecific"),
    ("abi_pthread_test", "once_runs_exactly_once"),
    ("abi_pthread_test", "barrier_single_thread_wait"),
    ("abi_pthread_test", "spinlock_trylock_fails_locked"),
    ("abi_pthread_test", "cancel_running_thread"),
    ("abi_pthread_test", "getattr_np_returns_valid_info"),
    ("abi_pthread_test", "tryjoin_np_on_finished_thread"),
    ("abi_pthread_test", "timedjoin_np_succeeds_before_deadline"),
    ("abi_pthread_test", "clockjoin_np_monotonic_succeeds_before_deadline"),
    ("abi_thread_lifecycle_test", "pthread_detach_makes_subsequent_join_fail_with_esrch"),
    ("abi_mutex_core_test", "futex_mutex_contention_increments_wait_and_wake_counters"),
    ("abi_cond_core_test", "condvar_broadcast_wakes_multiple_timedwait_threads"),
    ("abi_rwlock_core_test", "rwlock_writer_blocks_reader_until_unlock"),
    ("abi_once_test", "once_concurrent_threads_run_exactly_once"),
    ("abi_tsd_test", "tsd_isolated_across_concurrent_threads"),
    ("abi_barrier_spin_diff_test", "diff_pthread_barrier_wait_count_one_releases_immediately"),
}
EXPECTED_E2E_ARTIFACTS = {
    "e2e_c_fixture_runner",
    "e2e_pthread_fixture",
    "e2e_pthread_mutex_adversarial_fixture",
    "thread_stress_runner",
}
EXPECTED_THREAD_FIXTURE_CALLS = {
    "pthread_create",
    "pthread_join",
    "pthread_self",
    "pthread_equal",
    "pthread_mutex_lock",
    "pthread_mutex_unlock",
}
EXPECTED_ADVERSARIAL_FIXTURE_CALLS = {
    "pthread_mutexattr_settype",
    "pthread_mutex_trylock",
    "pthread_mutex_unlock",
    "pthread_mutex_destroy",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        err(f"{label} JSON load failed: {exc}")
        return {}


def read_text(path: pathlib.Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} read failed: {exc}")
        return ""


def sha256_file(path: pathlib.Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": "pthread_family_completion_contract.log.v1",
            "event": event,
            "status": status,
            "outcome": status,
            "bead": EXPECTED_COMPLETION_BEAD,
            "bead_id": EXPECTED_COMPLETION_BEAD,
            "source_bead": EXPECTED_BEAD,
            "trace_id": f"{EXPECTED_COMPLETION_BEAD}::{event}",
            "mode": "strict+hardened",
            "api_family": "pthread",
            "symbol": "pthread-family",
            "decision_path": "completion_contract>source_artifact_validation",
            "healing_action": "none",
            "errno": 0,
            "latency_ns": 0,
            "artifact_refs": [rel(CONTRACT_PATH), rel(REPORT_PATH)],
            "details": details,
        }
    )


def artifact_path(value: Any, context: str) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty string path")
        return None
    path = (ROOT / value).resolve()
    if ROOT not in path.parents and path != ROOT:
        err(f"{context} escapes workspace: {value}")
        return None
    if not path.is_file():
        err(f"{context} missing file: {value}")
        return None
    return path


def string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        err(f"{context} must be a list of strings")
        return []
    return list(value)


def validate_rch_commands(section: dict[str, Any], section_name: str) -> None:
    commands = string_list(section.get("required_commands"), f"{section_name}.required_commands")
    for command in commands:
        if "cargo " in command:
            require(command.startswith("rch exec --"), f"non-rch cargo validation command: {command}")


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, pathlib.Path]:
    source_artifacts = manifest.get("source_artifacts")
    if not isinstance(source_artifacts, dict):
        err("source_artifacts must be an object")
        return {}
    missing = EXPECTED_SOURCE_KEYS - set(source_artifacts)
    extra = set(source_artifacts) - EXPECTED_SOURCE_KEYS
    require(not missing, f"source_artifacts missing keys: {sorted(missing)}")
    require(not extra, f"source_artifacts unexpected keys: {sorted(extra)}")

    paths: dict[str, pathlib.Path] = {}
    for key in sorted(EXPECTED_SOURCE_KEYS):
        path = artifact_path(source_artifacts.get(key), f"source_artifacts.{key}")
        if path is not None:
            paths[key] = path
    append_event(
        "pthread_family_completion.source_artifacts",
        "fail" if errors else "pass",
        {"artifact_count": len(paths), "keys": sorted(paths)},
    )
    return paths


def validate_refs(
    section: dict[str, Any],
    section_name: str,
    expected: set[tuple[str, str]],
    paths: dict[str, pathlib.Path],
) -> list[str]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list):
        err(f"{section_name}.required_test_refs must be a list")
        refs = []
    got = {
        (ref.get("artifact"), ref.get("name"))
        for ref in refs
        if isinstance(ref, dict)
        and isinstance(ref.get("artifact"), str)
        and isinstance(ref.get("name"), str)
    }
    require(got == expected, f"{section_name} test refs mismatch: got {sorted(got)}")
    for artifact, name in expected:
        path = paths.get(artifact)
        if path is None:
            continue
        text = read_text(path, artifact)
        require(f"fn {name}" in text, f"{section_name} missing test function {name} in {artifact}")
    validate_rch_commands(section, section_name)
    return [f"{artifact}::{name}" for artifact, name in sorted(expected)]


def validate_e2e(section: dict[str, Any], paths: dict[str, pathlib.Path]) -> list[str]:
    artifacts = section.get("required_artifacts")
    if not isinstance(artifacts, list):
        err("e2e_primary.required_artifacts must be a list")
        artifacts = []
    got = {
        artifact.get("artifact")
        for artifact in artifacts
        if isinstance(artifact, dict) and isinstance(artifact.get("artifact"), str)
    }
    require(got == EXPECTED_E2E_ARTIFACTS, f"e2e artifacts mismatch: got {sorted(got)}")
    validate_rch_commands(section, "e2e_primary")

    runner = read_text(paths.get("e2e_c_fixture_runner", pathlib.Path()), "e2e_c_fixture_runner")
    require("LD_PRELOAD" in runner, "e2e runner must use LD_PRELOAD")
    require("FRANKENLIBC_MODE" in runner, "e2e runner must set FRANKENLIBC_MODE")

    thread_fixture = read_text(paths.get("e2e_pthread_fixture", pathlib.Path()), "e2e_pthread_fixture")
    for call in EXPECTED_THREAD_FIXTURE_CALLS:
        require(call in thread_fixture, f"pthread e2e fixture missing {call}")

    adversarial_fixture = read_text(
        paths.get("e2e_pthread_mutex_adversarial_fixture", pathlib.Path()),
        "e2e_pthread_mutex_adversarial_fixture",
    )
    for call in EXPECTED_ADVERSARIAL_FIXTURE_CALLS:
        require(call in adversarial_fixture, f"pthread adversarial e2e fixture missing {call}")

    stress_runner = read_text(paths.get("thread_stress_runner", pathlib.Path()), "thread_stress_runner")
    require("c_fixture_pthread_common_adversarial" in stress_runner, "thread stress runner must include pthread C fixture scenario")
    require("strict" in stress_runner and "hardened" in stress_runner, "thread stress runner must cover strict and hardened modes")
    return sorted(EXPECTED_E2E_ARTIFACTS)


def validate_support_matrix(paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    support = load_json(paths["support_matrix"], "support_matrix")
    symbols = support.get("symbols", []) if isinstance(support, dict) else []
    by_symbol = {
        row.get("symbol"): row
        for row in symbols
        if isinstance(row, dict) and isinstance(row.get("symbol"), str)
    }
    status_counts: dict[str, int] = {}
    for symbol in EXPECTED_TARGET_SYMBOLS:
        row = by_symbol.get(symbol)
        if row is None:
            err(f"support_matrix missing {symbol}")
            continue
        status = row.get("status")
        require(status in EXPECTED_SUPPORT_STATUSES, f"support_matrix {symbol} status is {status!r}")
        if isinstance(status, str):
            status_counts[status] = status_counts.get(status, 0) + 1
        require(row.get("module") == "pthread_abi", f"support_matrix {symbol} module is {row.get('module')!r}")
    return {
        "checked_symbols": len(EXPECTED_TARGET_SYMBOLS),
        "support_matrix_total": len(by_symbol),
        "allowed_statuses": sorted(EXPECTED_SUPPORT_STATUSES),
        "status_counts": status_counts,
    }


def validate_abi_exports(paths: dict[str, pathlib.Path]) -> list[str]:
    text = read_text(paths["abi_pthread"], "abi_pthread")
    exported: list[str] = []
    for symbol in EXPECTED_TARGET_SYMBOLS:
        marker = f'pub unsafe extern "C" fn {symbol}'
        require(marker in text, f"abi_pthread missing export marker: {marker}")
        exported.append(symbol)
    return exported


def validate_manifest(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
    require(manifest.get("bead") == EXPECTED_BEAD, "bead mismatch")
    require(manifest.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_debt_bead mismatch")
    require(manifest.get("target_symbols") == EXPECTED_TARGET_SYMBOLS, "target_symbols mismatch")
    source_contract = manifest.get("required_source_contract")
    if not isinstance(source_contract, dict):
        err("required_source_contract must be an object")
        source_contract = {}
    support_contract = source_contract.get("support_matrix")
    if not isinstance(support_contract, dict):
        err("required_source_contract.support_matrix must be an object")
        support_contract = {}
    expected_statuses = support_contract.get("expected_statuses")
    require(
        isinstance(expected_statuses, list)
        and set(expected_statuses) == EXPECTED_SUPPORT_STATUSES,
        "support_matrix expected_statuses mismatch",
    )
    require(
        support_contract.get("expected_module") == "pthread_abi",
        "support_matrix expected_module mismatch",
    )
    require(
        support_contract.get("expected_symbols") == len(EXPECTED_TARGET_SYMBOLS),
        "support_matrix expected_symbols mismatch",
    )
    debt = manifest.get("completion_debt")
    if not isinstance(debt, dict):
        err("completion_debt must be an object")
        debt = {}
    require(debt.get("missing_items_closed") == EXPECTED_MISSING_ITEMS, "missing_items_closed mismatch")

    evidence = manifest.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        evidence = {}
    missing = EXPECTED_EVIDENCE_KEYS - set(evidence)
    extra = set(evidence) - EXPECTED_EVIDENCE_KEYS
    require(not missing, f"completion_debt_evidence missing keys: {sorted(missing)}")
    require(not extra, f"completion_debt_evidence unexpected keys: {sorted(extra)}")

    unit_section = evidence.get("unit_primary", {})
    integration_section = evidence.get("integration_primary", {})
    e2e_section = evidence.get("e2e_primary", {})
    if not isinstance(unit_section, dict):
        err("unit_primary must be an object")
        unit_section = {}
    if not isinstance(integration_section, dict):
        err("integration_primary must be an object")
        integration_section = {}
    if not isinstance(e2e_section, dict):
        err("e2e_primary must be an object")
        e2e_section = {}

    unit_bindings = validate_refs(unit_section, "unit_primary", EXPECTED_UNIT_REFS, paths)
    integration_bindings = validate_refs(integration_section, "integration_primary", EXPECTED_INTEGRATION_REFS, paths)
    e2e_bindings = validate_e2e(e2e_section, paths)
    support_summary = validate_support_matrix(paths)
    abi_exports = validate_abi_exports(paths)

    append_event(
        "pthread_family_completion.bindings",
        "fail" if errors else "pass",
        {
            "unit_bindings": len(unit_bindings),
            "integration_bindings": len(integration_bindings),
            "e2e_bindings": len(e2e_bindings),
            "target_symbols": len(EXPECTED_TARGET_SYMBOLS),
        },
    )

    artifact_hashes = {
        key: sha256_file(path)
        for key, path in sorted(paths.items())
        if key in {
            "abi_pthread",
            "abi_pthread_test",
            "core_thread",
            "core_mutex",
            "core_cond",
            "core_rwlock",
            "core_tls",
            "e2e_pthread_fixture",
            "e2e_pthread_mutex_adversarial_fixture",
            "completion_checker",
            "completion_test",
        }
    }

    return {
        "target_symbols": EXPECTED_TARGET_SYMBOLS,
        "unit_bindings": unit_bindings,
        "integration_bindings": integration_bindings,
        "e2e_bindings": e2e_bindings,
        "abi_exports": abi_exports,
        "source_summary": {
            "support_matrix": support_summary,
            "artifact_hashes": artifact_hashes,
        },
    }


manifest = load_json(CONTRACT_PATH, "contract")
paths = validate_source_artifacts(manifest if isinstance(manifest, dict) else {})
summary: dict[str, Any] = {}
if isinstance(manifest, dict) and paths:
    summary = validate_manifest(manifest, paths)

status = "fail" if errors else "pass"
append_event(
    "pthread_family_completion.final",
    status,
    {
        "error_count": len(errors),
        "target_symbol_count": len(EXPECTED_TARGET_SYMBOLS),
    },
)

report = {
    "schema_version": "pthread_family_completion_contract.report.v1",
    "status": status,
    "bead": EXPECTED_COMPLETION_BEAD,
    "source_bead": EXPECTED_BEAD,
    "contract": rel(CONTRACT_PATH),
    "errors": errors,
    **summary,
}
REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG_PATH.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)

if errors:
    print(f"pthread family completion contract failed: {REPORT_PATH}", file=sys.stderr)
    for message in errors:
        print(f"  - {message}", file=sys.stderr)
    sys.exit(1)

print(f"pthread family completion contract passed: {REPORT_PATH}")
PY
