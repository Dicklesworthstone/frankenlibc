#!/usr/bin/env bash
# Validate bd-xxd9.2 pthread lifecycle unit completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${1:-${ROOT}/tests/conformance/pthread_lifecycle_unit_completion_contract.v1.json}"
OUT_DIR="${2:-${ROOT}/target/conformance}"
REPORT_PATH="${OUT_DIR}/pthread_lifecycle_unit_completion_contract.report.json"
LOG_PATH="${OUT_DIR}/pthread_lifecycle_unit_completion_contract.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT_PATH}" "${REPORT_PATH}" "${LOG_PATH}" <<'PY'
import hashlib
import json
import pathlib
import re
import shlex
import sys
from collections import Counter
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT_PATH = pathlib.Path(sys.argv[2]).resolve()
REPORT_PATH = pathlib.Path(sys.argv[3]).resolve()
LOG_PATH = pathlib.Path(sys.argv[4]).resolve()

EXPECTED_SCHEMA = "pthread_lifecycle_unit_completion_contract.v1"
EXPECTED_BEAD = "bd-xxd9"
EXPECTED_COMPLETION_BEAD = "bd-xxd9.2"
EXPECTED_MISSING_ITEMS = ["tests.unit.primary"]
EXPECTED_SOURCE_KEYS = {
    "mutex_core_test",
    "cond_core_test",
    "rwlock_core_test",
    "rwlock_trylock_test",
    "once_test",
    "tsd_test",
    "thread_lifecycle_test",
    "mutex_contract_matrix_test",
    "thread_stress_scenarios",
    "thread_stress_gate",
    "thread_stress_artifacts_test",
    "pthread_family_completion_contract",
    "pthread_family_completion_checker",
    "pthread_family_completion_test",
    "completion_checker",
    "completion_test",
}
EXPECTED_FAMILIES = {
    "mutex",
    "condvar",
    "rwlock",
    "rwlock_trylock",
    "once",
    "tsd",
    "thread_lifecycle",
    "mutex_contract_matrix",
    "thread_stress_artifacts",
}
EXPECTED_TEST_REFS = {
    ("mutex_core_test", "mutex", "futex_mutex_roundtrip_and_trylock_busy"),
    ("mutex_core_test", "mutex", "futex_mutex_contention_increments_wait_and_wake_counters"),
    ("mutex_core_test", "mutex", "futex_mutex_destroy_while_locked_is_ebusy"),
    ("mutex_core_test", "mutex", "futex_mutex_linearizable_counter_smoke"),
    ("mutex_core_test", "mutex", "futex_mutex_init_destroy_reinit"),
    ("mutex_core_test", "mutex", "futex_mutex_contention_two_threads_alternating"),
    ("cond_core_test", "condvar", "condvar_roundtrip_signal_broadcast_destroy"),
    ("cond_core_test", "condvar", "condvar_wait_rejects_unmanaged_and_null_mutex"),
    ("cond_core_test", "condvar", "condvar_timedwait_timeout_relocks_mutex"),
    ("cond_core_test", "condvar", "condvar_signal_wakes_timedwait_thread"),
    ("cond_core_test", "condvar", "condvar_broadcast_wakes_multiple_timedwait_threads"),
    ("rwlock_core_test", "rwlock", "rwlock_roundtrip_read_and_write"),
    ("rwlock_core_test", "rwlock", "rwlock_destroy_busy_and_validation_contract"),
    ("rwlock_core_test", "rwlock", "rwlock_writer_blocks_reader_until_unlock"),
    ("rwlock_core_test", "rwlock", "rwlock_multiple_concurrent_readers"),
    ("rwlock_core_test", "rwlock", "rwlock_read_then_write_interleaved_cycle"),
    ("rwlock_trylock_test", "rwlock_trylock", "tryrdlock_succeeds_when_unlocked"),
    ("rwlock_trylock_test", "rwlock_trylock", "trywrlock_succeeds_when_unlocked"),
    ("rwlock_trylock_test", "rwlock_trylock", "tryrdlock_trywrlock_interleaved_cycle"),
    ("once_test", "once", "once_runs_exactly_once"),
    ("once_test", "once", "once_concurrent_threads_run_exactly_once"),
    ("once_test", "once", "once_high_thread_count_still_runs_once"),
    ("once_test", "once", "once_completed_with_different_routine_is_noop"),
    ("tsd_test", "tsd", "key_create_and_delete_roundtrip"),
    ("tsd_test", "tsd", "tsd_isolated_across_concurrent_threads"),
    ("tsd_test", "tsd", "tsd_destructor_runs_on_thread_exit"),
    ("tsd_test", "tsd", "key_delete_twice_is_einval"),
    ("thread_lifecycle_test", "thread_lifecycle", "pthread_create_join_roundtrip_uses_default_native_routing"),
    ("thread_lifecycle_test", "thread_lifecycle", "pthread_join_and_detach_unknown_thread_are_esrch"),
    ("thread_lifecycle_test", "thread_lifecycle", "pthread_create_join_parallel_batch_stress"),
    ("thread_lifecycle_test", "thread_lifecycle", "pthread_detach_makes_subsequent_join_fail_with_esrch"),
    ("thread_lifecycle_test", "thread_lifecycle", "pthread_join_then_reuse_handle_is_esrch"),
    ("thread_lifecycle_test", "thread_lifecycle", "pthread_self_join_is_rejected_with_edeadlk"),
    ("thread_lifecycle_test", "thread_lifecycle", "pthread_create_join_multiple_sequential"),
    ("mutex_contract_matrix_test", "mutex_contract_matrix", "contract_matrix_matches_expected_and_emits_structured_logs"),
    ("thread_stress_artifacts_test", "thread_stress_artifacts", "thread_stress_gate_emits_valid_bd1f35_artifacts"),
}
EXPECTED_STRESS_SCENARIOS = {
    "fanout_fanin_single",
    "create_join_churn",
    "mixed_detach_join",
    "c_fixture_pthread_common_adversarial",
}
EXPECTED_STRESS_MODES = {"strict", "hardened"}

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
            "schema_version": "pthread_lifecycle_unit_completion_contract.log.v1",
            "event": event,
            "status": status,
            "outcome": status,
            "bead": EXPECTED_COMPLETION_BEAD,
            "bead_id": EXPECTED_COMPLETION_BEAD,
            "source_bead": EXPECTED_BEAD,
            "trace_id": f"{EXPECTED_COMPLETION_BEAD}::{event}",
            "mode": "strict+hardened",
            "api_family": "pthread",
            "symbol": "pthread-lifecycle-unit-pack",
            "decision_path": "completion_contract>pthread_lifecycle_unit_gate",
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


def command_contract_failures(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        return [f"command is not shell-tokenizable: {command}: {exc}"]
    if "cargo" not in tokens:
        return []

    failures: list[str] = []
    cargo_index = tokens.index("cargo")
    try:
        rch_index = tokens.index("rch")
    except ValueError:
        failures.append(f"cargo command must run through rch exec: {command}")
        return failures

    if rch_index > cargo_index:
        failures.append(f"rch must appear before cargo: {command}")
        return failures
    if "RCH_REQUIRE_REMOTE=1" not in tokens[:rch_index]:
        failures.append(f"cargo command must set RCH_REQUIRE_REMOTE=1 before rch: {command}")
    if tokens[rch_index + 1 : rch_index + 3] != ["exec", "--"]:
        failures.append(f"cargo command must use 'rch exec --': {command}")

    payload = tokens[rch_index + 3 : cargo_index]
    if not payload or payload[0] != "env":
        failures.append(f"cargo command must place env assignments inside rch payload: {command}")
    if not any(token.startswith("CARGO_TARGET_DIR=") for token in payload[1:]):
        failures.append(f"cargo command must set CARGO_TARGET_DIR inside rch env payload: {command}")
    return failures


def validate_rch_commands(section: dict[str, Any], section_name: str) -> list[str]:
    commands = string_list(section.get("required_commands"), f"{section_name}.required_commands")
    for command in commands:
        for failure in command_contract_failures(command):
            err(f"{section_name}.required_commands contract failed: {failure}")
    return commands


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
        "pthread_lifecycle_unit.source_artifacts",
        "fail" if errors else "pass",
        {"artifact_count": len(paths), "keys": sorted(paths)},
    )
    return paths


def validate_manifest_shape(manifest: dict[str, Any]) -> None:
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
    require(manifest.get("bead") == EXPECTED_BEAD, "bead mismatch")
    require(manifest.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_debt_bead mismatch")
    completion_debt = manifest.get("completion_debt", {})
    if not isinstance(completion_debt, dict):
        err("completion_debt must be an object")
        completion_debt = {}
    require(completion_debt.get("original_bead") == EXPECTED_BEAD, "completion_debt.original_bead mismatch")
    require(
        string_list(completion_debt.get("missing_items_closed"), "completion_debt.missing_items_closed")
        == EXPECTED_MISSING_ITEMS,
        "completion_debt.missing_items_closed must close only tests.unit.primary",
    )

    surface = manifest.get("pthread_lifecycle_surface", {})
    if not isinstance(surface, dict):
        err("pthread_lifecycle_surface must be an object")
        surface = {}
    families = set(string_list(surface.get("required_families"), "pthread_lifecycle_surface.required_families"))
    require(families == EXPECTED_FAMILIES, f"required families mismatch: got {sorted(families)}")

    stress = surface.get("stress_support", {})
    if not isinstance(stress, dict):
        err("pthread_lifecycle_surface.stress_support must be an object")
        stress = {}
    require(stress.get("artifact") == "thread_stress_scenarios", "stress_support artifact mismatch")
    require(stress.get("source_bead") == "bd-1f35", "stress_support source_bead mismatch")
    require(
        set(string_list(stress.get("required_scenarios"), "stress_support.required_scenarios"))
        == EXPECTED_STRESS_SCENARIOS,
        "stress_support required_scenarios mismatch",
    )
    require(
        set(string_list(stress.get("required_modes"), "stress_support.required_modes")) == EXPECTED_STRESS_MODES,
        "stress_support required_modes mismatch",
    )


def validate_unit_refs(section: dict[str, Any], paths: dict[str, pathlib.Path]) -> list[str]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list):
        err("unit_primary.required_test_refs must be a list")
        refs = []
    got = {
        (ref.get("artifact"), ref.get("family"), ref.get("name"))
        for ref in refs
        if isinstance(ref, dict)
        and isinstance(ref.get("artifact"), str)
        and isinstance(ref.get("family"), str)
        and isinstance(ref.get("name"), str)
    }
    require(got == EXPECTED_TEST_REFS, f"unit_primary test refs mismatch: got {sorted(got)}")

    by_artifact: dict[str, list[str]] = {}
    for artifact, _, name in EXPECTED_TEST_REFS:
        by_artifact.setdefault(artifact, []).append(name)
    for artifact, names in by_artifact.items():
        path = paths.get(artifact)
        if path is None:
            continue
        text = read_text(path, artifact)
        for name in names:
            pattern = re.compile(rf"\bfn\s+{re.escape(name)}\b")
            require(bool(pattern.search(text)), f"{artifact} missing test function {name}")

    family_counts = Counter(family for _, family, _ in EXPECTED_TEST_REFS)
    declared_families = {ref[1] for ref in EXPECTED_TEST_REFS}
    require(declared_families == EXPECTED_FAMILIES, f"unit refs miss families: {sorted(declared_families)}")
    commands = validate_rch_commands(section, "unit_primary")
    append_event(
        "pthread_lifecycle_unit.unit_refs",
        "fail" if errors else "pass",
        {
            "test_ref_count": len(got),
            "family_counts": dict(sorted(family_counts.items())),
            "command_count": len(commands),
        },
    )
    return [f"{artifact}::{name}" for artifact, _, name in sorted(EXPECTED_TEST_REFS)]


def validate_stress_support(paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    stress_spec_path = paths.get("thread_stress_scenarios")
    stress_gate_path = paths.get("thread_stress_gate")
    stress_test_path = paths.get("thread_stress_artifacts_test")
    if stress_spec_path is None or stress_gate_path is None or stress_test_path is None:
        return {"scenarios": [], "modes": []}

    spec = load_json(stress_spec_path, "thread_stress_scenarios")
    require(spec.get("schema_version") == "v1", "thread stress spec schema_version mismatch")
    require(spec.get("bead") == "bd-1f35", "thread stress spec bead mismatch")
    scenarios = spec.get("scenarios", [])
    if not isinstance(scenarios, list):
        err("thread stress spec scenarios must be a list")
        scenarios = []
    scenario_ids = {
        item.get("id") for item in scenarios if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    require(EXPECTED_STRESS_SCENARIOS <= scenario_ids, f"missing stress scenarios: {sorted(EXPECTED_STRESS_SCENARIOS - scenario_ids)}")
    summary = spec.get("summary", {})
    if not isinstance(summary, dict):
        err("thread stress spec summary must be an object")
        summary = {}
    require(int(summary.get("scenario_count", 0)) >= len(EXPECTED_STRESS_SCENARIOS), "thread stress scenario_count too small")
    require(int(summary.get("mode_count", 0)) == len(EXPECTED_STRESS_MODES), "thread stress mode_count mismatch")

    gate_text = read_text(stress_gate_path, "thread_stress_gate")
    for needle in [
        "required_log_fields",
        "strict",
        "hardened",
        "fail_count",
        "cases_fail",
        "artifact_refs",
    ]:
        require(needle in gate_text, f"thread stress gate missing {needle}")

    test_text = read_text(stress_test_path, "thread_stress_artifacts_test")
    require(
        bool(re.search(r"\bfn\s+thread_stress_gate_emits_valid_bd1f35_artifacts\b", test_text)),
        "thread stress artifacts test function missing",
    )
    append_event(
        "pthread_lifecycle_unit.stress_support",
        "fail" if errors else "pass",
        {"scenario_ids": sorted(scenario_ids), "mode_count": summary.get("mode_count")},
    )
    return {"scenarios": sorted(scenario_ids), "modes": sorted(EXPECTED_STRESS_MODES)}


def write_outputs(report: dict[str, Any]) -> None:
    REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG_PATH.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )


manifest = load_json(CONTRACT_PATH, "completion contract")
if not isinstance(manifest, dict):
    err("completion contract root must be an object")
    manifest = {}

validate_manifest_shape(manifest)
paths = validate_source_artifacts(manifest)
evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
unit_primary = evidence.get("unit_primary", {})
if not isinstance(unit_primary, dict):
    err("completion_debt_evidence.unit_primary must be an object")
    unit_primary = {}
unit_bindings = validate_unit_refs(unit_primary, paths)
stress_support = validate_stress_support(paths)

status = "fail" if errors else "pass"
append_event(
    "pthread_lifecycle_unit.completion_contract",
    status,
    {
        "unit_binding_count": len(unit_bindings),
        "family_count": len(EXPECTED_FAMILIES),
        "stress_scenario_count": len(stress_support.get("scenarios", [])),
        "error_count": len(errors),
    },
)

report = {
    "schema_version": "pthread_lifecycle_unit_completion_contract.report.v1",
    "status": status,
    "bead": EXPECTED_COMPLETION_BEAD,
    "source_bead": EXPECTED_BEAD,
    "contract_path": rel(CONTRACT_PATH),
    "contract_sha256": sha256_file(CONTRACT_PATH),
    "source_artifacts": {key: rel(path) for key, path in sorted(paths.items())},
    "families": sorted(EXPECTED_FAMILIES),
    "unit_bindings": unit_bindings,
    "stress_support": stress_support,
    "errors": errors,
}
write_outputs(report)

if errors:
    for message in errors:
        print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS pthread lifecycle unit completion contract "
    f"refs={len(unit_bindings)} families={len(EXPECTED_FAMILIES)} "
    f"stress_scenarios={len(stress_support.get('scenarios', []))}"
)
PY
