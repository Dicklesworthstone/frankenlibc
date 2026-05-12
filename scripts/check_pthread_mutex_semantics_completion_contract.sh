#!/usr/bin/env bash
# Validate bd-327.1 pthread mutex semantics completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_PTHREAD_MUTEX_SEMANTICS_CONTRACT:-${ROOT}/tests/conformance/pthread_mutex_semantics_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_PTHREAD_MUTEX_SEMANTICS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_PTHREAD_MUTEX_SEMANTICS_REPORT:-${OUT_DIR}/pthread_mutex_semantics_completion_contract.report.json}"
LOG="${FRANKENLIBC_PTHREAD_MUTEX_SEMANTICS_LOG:-${OUT_DIR}/pthread_mutex_semantics_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(sys.argv[1]).resolve()
CONTRACT = Path(sys.argv[2]).resolve()
REPORT = Path(sys.argv[3]).resolve()
LOG = Path(sys.argv[4]).resolve()
SOURCE_COMMIT = sys.argv[5]

SCHEMA = "pthread_mutex_semantics_completion_contract.v1"
BEAD = "bd-327"
COMPLETION_BEAD = "bd-327.1"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_SOURCE_IDS = {
    "core_mutex",
    "abi_pthread_mutex",
    "abi_pthread_mutex_core_test",
    "conformance_fixture",
    "conformance_harness",
    "existing_state_invariants_contract",
    "completion_checker",
    "completion_harness",
}
REQUIRED_UNIT_REFS = {
    ("core_mutex", "valid_mutex_type_check"),
    ("core_mutex", "sanitize_mutex_type_check"),
    ("core_mutex", "sanitize_mutex_type_extremes_default_to_normal"),
    ("core_mutex", "contract_normal_relock_blocks"),
    ("core_mutex", "contract_errorcheck_relock_is_ededlk"),
    ("core_mutex", "contract_recursive_relock_succeeds_nonblocking"),
    ("core_mutex", "contract_unlock_locked_by_other_is_eperm"),
    ("core_mutex", "contract_destroy_while_locked_is_ebusy"),
    ("core_mutex", "posix_mutex_unlock_conformance_table"),
    ("core_mutex", "posix_mutex_destroy_conformance_table"),
    ("abi_pthread_mutex_core_test", "futex_mutex_roundtrip_and_trylock_busy"),
    ("abi_pthread_mutex_core_test", "futex_mutex_contention_increments_wait_and_wake_counters"),
}
REQUIRED_FIXTURE_CASES = {
    "mutex_init_default",
    "mutex_lock_unlock",
    "mutex_trylock_unlocked",
    "mutex_trylock_locked_ebusy",
    "mutex_unlock",
    "alias_mutex_trylock_unlocked",
    "alias_mutex_unlock",
    "mutex_destroy",
    "mutex_init_null_attr_default_type",
    "mutex_contention_two_threads",
}
REQUIRED_HARNESS_TESTS = {
    "pthread_mutex_fixture_valid_schema",
    "pthread_mutex_covers_init",
    "pthread_mutex_covers_lock",
    "pthread_mutex_covers_trylock",
    "pthread_mutex_covers_unlock",
    "pthread_mutex_covers_destroy",
    "pthread_mutex_error_codes_valid",
    "pthread_mutex_function_distribution",
    "pthread_mutex_modes_valid",
    "pthread_mutex_has_posix_references",
    "pthread_mutex_covers_alias_symbols",
    "pthread_mutex_fixture_executes_via_isolated_harness",
    "pthread_mutex_alias_symbols_match_canonical_behavior",
}
REQUIRED_EVENTS = {
    "pthread_mutex_semantics.source_artifact",
    "pthread_mutex_semantics.unit_binding",
    "pthread_mutex_semantics.conformance_case",
    "pthread_mutex_semantics.telemetry_contract",
    "pthread_mutex_semantics.completion_contract_validated",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "timestamp",
    "event",
    "status",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "missing_items_closed",
    "source_count",
    "unit_test_ref_count",
    "fixture_case_count",
    "conformance_test_ref_count",
    "telemetry_event_count",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def error(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        error(message)


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        error(f"{label} unreadable: {rel(path)}: {exc}")
        return {}


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        error(f"{label} must be an object")
        return {}
    return value


def require_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        error(f"{label} must be a non-empty array")
        return []
    strings: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            error(f"{label}[{index}] must be a non-empty string")
        else:
            strings.append(item)
    return strings


def workspace_path(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else ROOT / path


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": "pthread_mutex_semantics_completion_contract.log.v1",
            "timestamp": utc_now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}",
            "event": event,
            "status": status,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": BEAD,
            "source_commit": SOURCE_COMMIT,
            "artifact_refs": [rel(CONTRACT), rel(REPORT)],
            "details": details,
        }
    )


def validate_source_artifacts(manifest: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, list):
        error("source_artifacts must be an array")
        return {}, {}

    texts: dict[str, str] = {}
    paths: dict[str, str] = {}
    seen: set[str] = set()
    for index, artifact in enumerate(artifacts):
        artifact_obj = require_object(artifact, f"source_artifacts[{index}]")
        artifact_id = artifact_obj.get("id")
        path_text = artifact_obj.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            error(f"source_artifacts[{index}].id must be a non-empty string")
            continue
        if artifact_id in seen:
            error(f"duplicate source artifact id: {artifact_id}")
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            error(f"source_artifacts[{index}].path must be a non-empty string")
            continue
        path = workspace_path(path_text).resolve()
        if ROOT not in path.parents and path != ROOT:
            error(f"source artifact escapes workspace: {path_text}")
            continue
        if not path.is_file():
            error(f"source artifact missing: {path_text}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as exc:
            error(f"source artifact unreadable: {path_text}: {exc}")
            continue
        texts[artifact_id] = text
        paths[artifact_id] = path_text
        for needle in require_string_list(
            artifact_obj.get("required_needles"),
            f"source_artifacts[{index}].required_needles",
        ):
            if needle not in text:
                error(f"source artifact {artifact_id} missing needle {needle!r}")
        append_event(
            "pthread_mutex_semantics.source_artifact",
            "pass",
            {"artifact_id": artifact_id, "path": path_text},
        )

    missing = REQUIRED_SOURCE_IDS - seen
    extra = seen - REQUIRED_SOURCE_IDS
    require(not missing, f"source artifacts missing ids: {sorted(missing)}")
    require(not extra, f"source artifacts unexpected ids: {sorted(extra)}")
    return texts, paths


def validate_top_level(manifest: dict[str, Any]) -> dict[str, Any]:
    require(manifest.get("schema_version") == SCHEMA, "schema_version mismatch")
    require(manifest.get("bead") == BEAD, "bead mismatch")
    require(
        manifest.get("completion_debt_bead") == COMPLETION_BEAD,
        "completion_debt_bead mismatch",
    )

    evidence = require_object(
        manifest.get("completion_debt_evidence"),
        "completion_debt_evidence",
    )
    require(evidence.get("original_bead") == BEAD, "original_bead mismatch")
    require(
        evidence.get("next_audit_score_threshold", 0) >= 800,
        "next audit score threshold must be at least 800",
    )
    missing = set(
        require_string_list(
            evidence.get("missing_items_closed"),
            "completion_debt_evidence.missing_items_closed",
        )
    )
    require(
        missing == REQUIRED_MISSING_ITEMS,
        f"missing_items_closed must be {sorted(REQUIRED_MISSING_ITEMS)}, got {sorted(missing)}",
    )
    return evidence


def validate_unit_primary(manifest: dict[str, Any], texts: dict[str, str]) -> int:
    unit = require_object(manifest.get("unit_primary"), "unit_primary")
    commands = require_string_list(unit.get("required_commands"), "unit_primary.required_commands")
    for command in commands:
        if "cargo " in command:
            require(command.startswith("rch exec --"), f"cargo validation must use rch: {command}")

    refs = unit.get("required_test_refs")
    if not isinstance(refs, list):
        error("unit_primary.required_test_refs must be an array")
        return 0
    actual: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        ref_obj = require_object(ref, f"unit_primary.required_test_refs[{index}]")
        artifact_id = ref_obj.get("artifact_id")
        name = ref_obj.get("name")
        if not isinstance(artifact_id, str) or not isinstance(name, str):
            error(f"unit_primary.required_test_refs[{index}] must contain artifact_id and name")
            continue
        actual.add((artifact_id, name))
        text = texts.get(artifact_id, "")
        if name not in text:
            error(f"unit test ref {artifact_id}:{name} is not present in source artifact")
        append_event(
            "pthread_mutex_semantics.unit_binding",
            "pass",
            {"artifact_id": artifact_id, "test": name},
        )
    require(
        actual == REQUIRED_UNIT_REFS,
        f"unit refs must be {sorted(REQUIRED_UNIT_REFS)}, got {sorted(actual)}",
    )
    return len(actual)


def validate_conformance_primary(
    manifest: dict[str, Any],
    texts: dict[str, str],
    paths: dict[str, str],
) -> tuple[int, int]:
    conformance = require_object(manifest.get("conformance_primary"), "conformance_primary")
    commands = require_string_list(
        conformance.get("required_commands"),
        "conformance_primary.required_commands",
    )
    for command in commands:
        if "cargo " in command:
            require(command.startswith("rch exec --"), f"cargo validation must use rch: {command}")

    fixture_cases = set(
        require_string_list(
            conformance.get("required_fixture_cases"),
            "conformance_primary.required_fixture_cases",
        )
    )
    require(
        fixture_cases == REQUIRED_FIXTURE_CASES,
        f"fixture cases must be {sorted(REQUIRED_FIXTURE_CASES)}, got {sorted(fixture_cases)}",
    )

    fixture_path = paths.get(str(conformance.get("fixture_artifact_id")))
    fixture_data = load_json(workspace_path(fixture_path), "pthread mutex fixture") if fixture_path else {}
    fixture_obj = require_object(fixture_data, "pthread mutex fixture")
    actual_fixture_cases = {
        case.get("name")
        for case in fixture_obj.get("cases", [])
        if isinstance(case, dict) and isinstance(case.get("name"), str)
    }
    for case_name in sorted(fixture_cases):
        if case_name not in actual_fixture_cases:
            error(f"fixture missing required case: {case_name}")
        append_event(
            "pthread_mutex_semantics.conformance_case",
            "pass",
            {"fixture_case": case_name},
        )

    harness_tests = set(
        require_string_list(
            conformance.get("required_harness_tests"),
            "conformance_primary.required_harness_tests",
        )
    )
    require(
        harness_tests == REQUIRED_HARNESS_TESTS,
        f"harness tests must be {sorted(REQUIRED_HARNESS_TESTS)}, got {sorted(harness_tests)}",
    )
    harness_text = texts.get(str(conformance.get("harness_artifact_id")), "")
    for test_name in sorted(harness_tests):
        if test_name not in harness_text:
            error(f"harness missing required test ref: {test_name}")
    return len(fixture_cases), len(harness_tests)


def validate_telemetry_primary(manifest: dict[str, Any]) -> int:
    telemetry = require_object(manifest.get("telemetry_primary"), "telemetry_primary")
    required_events = set(
        require_string_list(
            telemetry.get("required_events"),
            "telemetry_primary.required_events",
        )
    )
    require(
        required_events == REQUIRED_EVENTS,
        f"telemetry events must be {sorted(REQUIRED_EVENTS)}, got {sorted(required_events)}",
    )
    required_fields = set(
        require_string_list(
            telemetry.get("required_report_fields"),
            "telemetry_primary.required_report_fields",
        )
    )
    missing_fields = REQUIRED_REPORT_FIELDS - required_fields
    require(not missing_fields, f"telemetry report missing fields: {sorted(missing_fields)}")
    for field in ["report_path", "log_path"]:
        value = telemetry.get(field)
        require(isinstance(value, str) and bool(value), f"telemetry_primary.{field} missing")
    append_event(
        "pthread_mutex_semantics.telemetry_contract",
        "pass",
        {
            "required_events": sorted(required_events),
            "required_report_fields": sorted(required_fields),
        },
    )
    return len(required_events)


manifest = require_object(load_json(CONTRACT, "contract"), "contract")
validate_top_level(manifest)
texts, paths = validate_source_artifacts(manifest)
unit_ref_count = validate_unit_primary(manifest, texts)
fixture_case_count, conformance_test_count = validate_conformance_primary(manifest, texts, paths)
telemetry_event_count = validate_telemetry_primary(manifest)

status = "fail" if errors else "pass"
append_event(
    "pthread_mutex_semantics.completion_contract_validated",
    status,
    {
        "unit_test_ref_count": unit_ref_count,
        "fixture_case_count": fixture_case_count,
        "conformance_test_ref_count": conformance_test_count,
        "telemetry_event_count": telemetry_event_count,
        "errors": errors,
    },
)

report = {
    "schema_version": "pthread_mutex_semantics_completion_contract.report.v1",
    "timestamp": utc_now(),
    "event": "pthread_mutex_semantics.completion_contract_validated",
    "status": status,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": BEAD,
    "source_commit": SOURCE_COMMIT,
    "missing_items_closed": sorted(REQUIRED_MISSING_ITEMS),
    "source_count": len(paths),
    "unit_test_ref_count": unit_ref_count,
    "fixture_case_count": fixture_case_count,
    "conformance_test_ref_count": conformance_test_count,
    "telemetry_event_count": telemetry_event_count,
    "artifact_refs": sorted(paths.values()) + [rel(CONTRACT), rel(REPORT), rel(LOG)],
    "failure_signature": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in events),
    encoding="utf-8",
)

if errors:
    for item in errors:
        print(f"pthread_mutex_semantics_completion_contract: ERROR {item}", file=sys.stderr)
    print(
        f"pthread_mutex_semantics_completion_contract: FAIL errors={len(errors)} report={rel(REPORT)} log={rel(LOG)}",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    "pthread_mutex_semantics_completion_contract: PASS "
    f"sources={len(paths)} unit_refs={unit_ref_count} "
    f"fixture_cases={fixture_case_count} events={len(events)}"
)
PY
