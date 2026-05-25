#!/usr/bin/env bash
# check_hard_parts_unit_packs_completion_contract.sh -- bd-1ff3.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_HARD_PARTS_UNIT_PACKS_CONTRACT:-${ROOT}/tests/conformance/hard_parts_unit_packs_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_HARD_PARTS_UNIT_PACKS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_HARD_PARTS_UNIT_PACKS_REPORT:-${OUT_DIR}/hard_parts_unit_packs_completion_contract.report.json}"
LOG="${FRANKENLIBC_HARD_PARTS_UNIT_PACKS_LOG:-${OUT_DIR}/hard_parts_unit_packs_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
out_dir = Path(sys.argv[5])
source_commit = sys.argv[6]

SCHEMA = "hard_parts_unit_packs_completion_contract.v1"
BEAD_ID = "bd-1ff3.1"
ORIGINAL_BEAD = "bd-1ff3"
TRACE_ID = "bd-1ff3.1::hard-parts-unit-packs::v1"

EXPECTED_TESTS: dict[str, list[str]] = {
    "startup": [
        "startup_phase0_executes_main_and_captures_invariants",
        "startup_phase0_rejects_missing_main",
        "startup_phase0_rejects_argc_argv_mismatch",
        "startup_snapshot_rejects_null_output",
        "startup_phase0_rejects_unterminated_argv_scan_window",
        "startup_phase0_rejects_unterminated_envp_scan_window",
        "startup_phase0_rejects_unterminated_auxv_scan_window",
        "startup_phase0_negative_argc_normalizes_to_zero",
        "startup_phase0_main_can_use_stdio_without_bootstrap_crash",
        "libc_start_main_default_owned_startup_does_not_delegate_to_host",
        "libc_start_main_explicit_delegate_env_delegates_to_host",
        "libc_start_main_phase0_unsafe_path_falls_back_to_host",
        "libc_start_main_phase0_missing_main_does_not_fallback",
        "startup_capability_lattice_detects_use_before_env_resolution",
        "startup_init_order_certificate_is_embedded_and_persisted",
    ],
    "setjmp": [
        "jmpbuf_serialization_roundtrip",
        "jmpbuf_layout_is_stable_for_placeholder_contract",
        "phase1_capture_and_restore_roundtrip_in_strict_mode",
        "phase1_longjmp_zero_normalizes_to_one",
        "phase1_nested_capture_assigns_distinct_context_ids",
        "phase1_hardened_rejects_corrupted_context",
        "phase1_rejects_mode_mismatch_between_capture_and_restore",
        "phase1_rejects_foreign_thread_restore_attempts",
        "setjmp_returns_zero_and_captures_context_metadata",
        "longjmp_panics_with_deferred_backend_transfer_message",
        "longjmp_panics_with_normalized_zero_value",
        "longjmp_panics_with_invalid_context_error_for_uninitialized_env",
    ],
    "iconv": [
        "execute_iconv_case_strict_success",
        "execute_iconv_case_strict_e2big",
        "execute_iconv_case_utf32_conversion_matches_host_shape",
        "execute_iconv_case_hardened_success",
        "execute_iconv_case_hardened_unsupported_encoding_denied",
        "execute_iconv_open_case_hardened_supported_descriptor",
        "execute_iconv_close_case_hardened_valid_descriptor",
        "execute_iconv_case_strict_eilseq_seeded_adversarial",
        "execute_iconv_case_strict_einval_incomplete_sequence_seeded",
    ],
    "nss": [
        "execute_getaddrinfo_hosts_subset_hardened_matches_fixture_shape",
        "execute_lookup_hosts_case_handles_inline_comments_and_aliases",
        "execute_lookup_hosts_case_seeded_adversarial_noise",
        "execute_lookup_hosts_case_unknown_name_returns_empty_set",
        "execute_getaddrinfo_case_uses_hosts_subset_when_provided",
        "execute_gethostbyname_case_numeric_ipv4_returns_pointer_shape",
    ],
}

EXPECTED_FIXTURE_CASES: dict[str, list[tuple[str, str]]] = {
    "iconv": [
        ("tests/conformance/fixtures/iconv_phase1.json", "strict_utf8_to_utf16le_basic"),
        ("tests/conformance/fixtures/iconv_phase1.json", "strict_latin1_to_utf8_multibyte"),
        ("tests/conformance/fixtures/iconv_phase1.json", "strict_e2big_preserves_progress"),
        ("tests/conformance/fixtures/iconv_phase1.json", "strict_eilseq_invalid_utf8"),
        ("tests/conformance/fixtures/iconv_phase1.json", "strict_einval_incomplete_utf8"),
        ("tests/conformance/fixtures/iconv_phase1.json", "strict_utf8_to_utf32_with_bom"),
        ("tests/conformance/fixtures/iconv_phase1.json", "hardened_utf16le_to_utf8"),
        ("tests/conformance/fixtures/iconv_phase1.json", "hardened_unsupported_encoding_denied"),
        ("tests/conformance/fixtures/iconv_phase1.json", "iconv_open_hardened_utf8_to_utf16le"),
        ("tests/conformance/fixtures/iconv_phase1.json", "iconv_close_hardened_valid"),
    ],
    "nss": [
        ("tests/conformance/fixtures/resolver.json", "hosts_lookup_basic"),
        ("tests/conformance/fixtures/resolver.json", "hosts_lookup_case_insensitive"),
        ("tests/conformance/fixtures/resolver.json", "hosts_lookup_inline_comments_and_aliases"),
        ("tests/conformance/fixtures/resolver.json", "getaddrinfo_hosts_file_subset"),
        ("tests/conformance/fixtures/resolver.json", "gethostbyname_numeric_ipv4"),
        ("tests/conformance/fixtures/resolver.json", "getaddrinfo_hosts_file_subset_hardened"),
        ("tests/conformance/fixtures/resolver.json", "gethostbyname_numeric_ipv4_hardened"),
    ],
}

EXPECTED_MARKERS: dict[str, list[str]] = {
    "startup": [
        "STARTUP_TEST_SEED",
        "StartupContractCase",
        "assert_startup_errno_contract",
        "append_startup_trace",
        "startup_init_order_certificate_json",
    ],
    "setjmp": [
        "SETJMP_TEST_SEED",
        "Phase1Mode::Hardened",
        "Phase1JumpError::ForeignContext",
        "assert_contract_panic_contains",
        "POSIX longjmp",
    ],
    "iconv": [
        "HARD_PARTS_TEST_SEED",
        "assert_differential_contract",
        "seeded_invalid_utf8_pair",
    ],
    "nss": [
        "HARD_PARTS_TEST_SEED",
        "assert_differential_contract",
        "seeded_hosts_fixture",
    ],
}

FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_subsystem_coverage",
    "missing_unit_test",
    "missing_fixture_case",
    "missing_source_marker",
    "missing_completion_binding",
    "completion_output_contract_failed",
]

events: list[dict[str, Any]] = []
errors: list[dict[str, str]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "completion_contract_failed"


def load_json(path: Path, context: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("malformed_contract", f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def event(name: str, status: str, artifact_refs: list[str], failure_signature: str = "none") -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "event": name,
        "status": status,
        "artifact_refs": sorted(set(artifact_refs)),
        "source_commit": source_commit,
        "target_dir": rel(out_dir),
        "failure_signature": failure_signature,
    }


def as_array(value: Any, context: str, signature: str = "malformed_contract") -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def as_object(value: Any, context: str, signature: str = "malformed_contract") -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def string_field(value: dict[str, Any], field: str, context: str) -> str:
    item = value.get(field)
    if isinstance(item, str) and item:
        return item
    add_error("malformed_contract", f"{context}.{field} must be a non-empty string")
    return ""


def finish(status: str, summary: dict[str, int], subsystems: list[dict[str, Any]], artifact_refs: list[str]) -> None:
    if status == "fail":
        events.append(event("hard_parts_unit_packs_completion_contract_failed", "fail", artifact_refs, primary_signature()))
    report = {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": status,
        "summary": {
            **summary,
            "log_row_count": len(events),
        },
        "source_artifacts": source_artifact_rows,
        "subsystems": subsystems,
        "missing_item_bindings": missing_item_bindings,
        "artifact_refs": sorted(set(artifact_refs)),
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, events)
    if status == "pass":
        print(
            "PASS: hard-parts unit packs completion contract validated "
            f"subsystems={summary.get('subsystem_count', 0)} "
            f"unit_tests={summary.get('unit_test_count', 0)} "
            f"fixture_cases={summary.get('fixture_case_count', 0)} "
            f"log_rows={len(events)}"
        )
        raise SystemExit(0)
    print(f"FAIL: {primary_signature()} errors={len(errors)} report={report_path}", file=sys.stderr)
    raise SystemExit(1)


contract = load_json(contract_path, "contract")
if not isinstance(contract, dict):
    add_error("malformed_contract", "contract must be a JSON object")
    contract = {}

source_artifact_rows: list[dict[str, str]] = []
missing_item_bindings: list[Any] = []
artifact_refs = [rel(contract_path)]
subsystem_rows: list[dict[str, Any]] = []
summary = {
    "source_artifact_count": 0,
    "subsystem_count": 0,
    "unit_test_count": 0,
    "fixture_case_count": 0,
    "marker_count": 0,
}

if contract.get("schema_version") != SCHEMA:
    add_error("malformed_contract", f"schema_version must be {SCHEMA}")
if contract.get("bead_id") != BEAD_ID:
    add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
if contract.get("original_bead") != ORIGINAL_BEAD:
    add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
if contract.get("trace_id") != TRACE_ID:
    add_error("malformed_contract", f"trace_id must be {TRACE_ID}")

for index, artifact in enumerate(as_array(contract.get("source_artifacts"), "source_artifacts")):
    artifact = as_object(artifact, f"source_artifacts[{index}]")
    artifact_id = string_field(artifact, "id", f"source_artifacts[{index}]")
    path_text = string_field(artifact, "path", f"source_artifacts[{index}]")
    role = string_field(artifact, "role", f"source_artifacts[{index}]")
    status = "pass"
    if not path_text or not resolve(path_text).is_file():
        add_error("missing_source_artifact", f"{artifact_id}: missing {path_text}")
        status = "fail"
    else:
        artifact_refs.append(path_text)
        summary["source_artifact_count"] += 1
    source_artifact_rows.append({"id": artifact_id, "path": path_text, "role": role, "status": status})

if errors:
    finish("fail", summary, subsystem_rows, artifact_refs)
events.append(event("source_artifacts_validated", "pass", artifact_refs))

unit_contract = as_object(contract.get("unit_pack_contract"), "unit_pack_contract")
subsystems = as_array(unit_contract.get("required_subsystems"), "unit_pack_contract.required_subsystems")
by_id: dict[str, dict[str, Any]] = {}
for index, subsystem in enumerate(subsystems):
    subsystem = as_object(subsystem, f"required_subsystems[{index}]")
    subsystem_id = string_field(subsystem, "id", f"required_subsystems[{index}]")
    if subsystem_id:
        by_id[subsystem_id] = subsystem

for subsystem_id in EXPECTED_TESTS:
    if subsystem_id not in by_id:
        add_error("missing_subsystem_coverage", f"missing subsystem {subsystem_id}")

if errors:
    finish("fail", summary, subsystem_rows, artifact_refs)

source_cache: dict[str, str] = {}
fixture_cache: dict[str, set[str]] = {}
for subsystem_id in EXPECTED_TESTS:
    subsystem = by_id[subsystem_id]
    evidence_path = string_field(subsystem, "evidence_path", f"{subsystem_id}.evidence_path")
    evidence_file = resolve(evidence_path)
    if not evidence_file.is_file():
        add_error("missing_source_artifact", f"{subsystem_id}: missing evidence source {evidence_path}")
        source = ""
    else:
        artifact_refs.append(evidence_path)
        source = source_cache.setdefault(evidence_path, evidence_file.read_text(encoding="utf-8"))

    manifest_tests = [
        item
        for item in as_array(subsystem.get("required_tests"), f"{subsystem_id}.required_tests", "missing_unit_test")
        if isinstance(item, str)
    ]
    for expected in EXPECTED_TESTS[subsystem_id]:
        if expected not in manifest_tests:
            add_error("missing_unit_test", f"{subsystem_id}: manifest omits required test {expected}")
        elif f"fn {expected}(" not in source:
            add_error("missing_unit_test", f"{subsystem_id}: source omits required test {expected}")

    manifest_markers = [
        item
        for item in as_array(subsystem.get("required_markers"), f"{subsystem_id}.required_markers", "missing_source_marker")
        if isinstance(item, str)
    ]
    for expected in EXPECTED_MARKERS[subsystem_id]:
        if expected not in manifest_markers:
            add_error("missing_source_marker", f"{subsystem_id}: manifest omits marker {expected}")
        elif expected not in source:
            add_error("missing_source_marker", f"{subsystem_id}: source omits marker {expected}")

    manifest_fixture_cases = set()
    for fixture_ref in as_array(subsystem.get("fixture_cases"), f"{subsystem_id}.fixture_cases", "missing_fixture_case"):
        fixture_ref = as_object(fixture_ref, f"{subsystem_id}.fixture_cases[]", "missing_fixture_case")
        fixture_path = string_field(fixture_ref, "fixture", f"{subsystem_id}.fixture_cases[]")
        case_name = string_field(fixture_ref, "case", f"{subsystem_id}.fixture_cases[]")
        if fixture_path and case_name:
            manifest_fixture_cases.add((fixture_path, case_name))

    for fixture_path, case_name in EXPECTED_FIXTURE_CASES.get(subsystem_id, []):
        if (fixture_path, case_name) not in manifest_fixture_cases:
            add_error("missing_fixture_case", f"{subsystem_id}: manifest omits {fixture_path}#{case_name}")
            continue
        if fixture_path not in fixture_cache:
            fixture_file = resolve(fixture_path)
            if not fixture_file.is_file():
                add_error("missing_source_artifact", f"{subsystem_id}: missing fixture {fixture_path}")
                fixture_cache[fixture_path] = set()
            else:
                fixture = load_json(fixture_file, f"{subsystem_id} fixture {fixture_path}")
                cases = fixture.get("cases") if isinstance(fixture, dict) else []
                fixture_cache[fixture_path] = {
                    str(row.get("name"))
                    for row in cases
                    if isinstance(row, dict) and isinstance(row.get("name"), str)
                }
                artifact_refs.append(fixture_path)
        if case_name not in fixture_cache.get(fixture_path, set()):
            add_error("missing_fixture_case", f"{subsystem_id}: fixture {fixture_path} omits case {case_name}")

    subsystem_rows.append({
        "id": subsystem_id,
        "evidence_path": evidence_path,
        "unit_tests": manifest_tests,
        "markers": manifest_markers,
        "fixture_cases": [
            {"fixture": fixture_path, "case": case_name}
            for fixture_path, case_name in sorted(manifest_fixture_cases)
        ],
    })
    summary["subsystem_count"] += 1
    summary["unit_test_count"] += len(EXPECTED_TESTS[subsystem_id])
    summary["fixture_case_count"] += len(EXPECTED_FIXTURE_CASES.get(subsystem_id, []))
    summary["marker_count"] += len(EXPECTED_MARKERS[subsystem_id])

if errors:
    finish("fail", summary, subsystem_rows, artifact_refs)
events.append(event("subsystem_unit_packs_validated", "pass", artifact_refs))
events.append(event("fixture_cases_validated", "pass", artifact_refs))

if unit_contract.get("required_subsystem_count") != len(EXPECTED_TESTS):
    add_error("missing_subsystem_coverage", "required_subsystem_count drift")
if unit_contract.get("required_unit_test_count") != sum(len(tests) for tests in EXPECTED_TESTS.values()):
    add_error("missing_unit_test", "required_unit_test_count drift")
if unit_contract.get("required_fixture_case_count") != sum(len(cases) for cases in EXPECTED_FIXTURE_CASES.values()):
    add_error("missing_fixture_case", "required_fixture_case_count drift")

missing_item_bindings = as_array(contract.get("missing_item_bindings"), "missing_item_bindings", "missing_completion_binding")
unit_bindings = [
    binding
    for binding in missing_item_bindings
    if isinstance(binding, dict) and binding.get("spec_item") == "tests.unit.primary"
]
if len(unit_bindings) != 1:
    add_error("missing_completion_binding", "exactly one tests.unit.primary binding is required")
else:
    binding = unit_bindings[0]
    for field in ("implementation_refs", "test_refs", "required_positive_tests", "required_negative_tests"):
        values = as_array(binding.get(field), f"tests.unit.primary.{field}", "missing_completion_binding")
        if not values:
            add_error("missing_completion_binding", f"tests.unit.primary.{field} must not be empty")
        if field.endswith("_refs"):
            for value in values:
                if not isinstance(value, str) or not resolve(value).is_file():
                    add_error("missing_completion_binding", f"tests.unit.primary.{field} references missing {value!r}")
                elif isinstance(value, str):
                    artifact_refs.append(value)
        if field in ("required_positive_tests", "required_negative_tests"):
            test_refs = [
                value
                for value in as_array(binding.get("test_refs"), "tests.unit.primary.test_refs", "missing_completion_binding")
                if isinstance(value, str) and resolve(value).is_file()
            ]
            source = "\n".join(resolve(path).read_text(encoding="utf-8") for path in test_refs)
            for value in values:
                if not isinstance(value, str) or f"fn {value}(" not in source:
                    add_error("missing_completion_binding", f"completion harness omits test {value!r}")

if errors:
    finish("fail", summary, subsystem_rows, artifact_refs)
events.append(event("missing_item_bindings_validated", "pass", artifact_refs))

output_contract = as_object(contract.get("completion_output_contract"), "completion_output_contract")
required_events = {
    value
    for value in as_array(output_contract.get("required_events"), "completion_output_contract.required_events")
    if isinstance(value, str)
}
actual_events = {row["event"] for row in events}
actual_events.add("hard_parts_unit_packs_completion_contract_validated")
for required_event in required_events:
    if required_event not in actual_events:
        add_error("completion_output_contract_failed", f"missing required event {required_event}")

if errors:
    finish("fail", summary, subsystem_rows, artifact_refs)

events.append(event("hard_parts_unit_packs_completion_contract_validated", "pass", artifact_refs))
finish("pass", summary, subsystem_rows, artifact_refs)
PY
