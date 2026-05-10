#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_ALLOCATOR_E2E_COMPLETION_CONTRACT:-$ROOT/tests/conformance/allocator_e2e_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_ALLOCATOR_E2E_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_ALLOCATOR_E2E_COMPLETION_REPORT:-$OUT_DIR/allocator_e2e_completion_contract.report.json}"
LOG="${FRANKENLIBC_ALLOCATOR_E2E_COMPLETION_LOG:-$OUT_DIR/allocator_e2e_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "allocator_e2e_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "allocator_e2e_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-2x5.5"
COMPLETION_BEAD = "bd-2x5.5.1"
PASS_EVENT = "allocator_e2e_completion_contract_pass"
FAIL_EVENT = "allocator_e2e_completion_contract_fail"
REQUIRED_SOURCE_ARTIFACTS = {
    "allocator_e2e_gate",
    "c_fixture_spec",
    "malloc_fixture",
    "malloc_stress_fixture",
    "allocator_conformance_fixture",
    "allocator_conformance_harness",
    "completion_checker",
    "completion_harness_test",
}
REQUIRED_TELEMETRY_EVENTS = {
    "allocator_e2e_completion_summary",
    "allocator_e2e_fixture_bindings",
    "allocator_e2e_conformance_bindings",
    "allocator_e2e_test_bindings",
    PASS_EVENT,
    FAIL_EVENT,
}
REQUIRED_FIXTURES = {"fixture_malloc", "fixture_malloc_stress"}
PASS_LOG_EVENTS = [
    "allocator_e2e_completion_summary",
    "allocator_e2e_fixture_bindings",
    "allocator_e2e_conformance_bindings",
    "allocator_e2e_test_bindings",
    PASS_EVENT,
]
REQUIRED_E2E_TEST_REFS = {
    "allocator_e2e_gate_runs_host_strict_hardened",
    "allocator_e2e_gate_compiles_malloc_and_stress_fixtures",
    "allocator_e2e_gate_diffs_strict_hardened_against_host",
    "malloc_fixture_covers_basic_allocator_lifecycle",
    "malloc_stress_fixture_covers_concurrency_fragmentation_and_signature",
    "checker_validates_allocator_e2e_completion_contract",
    "checker_emits_allocator_completion_report_and_jsonl",
    "checker_rejects_missing_stress_fixture_binding",
    "checker_rejects_missing_conformance_test_ref",
    "checker_rejects_unknown_telemetry_event",
}
REQUIRED_CONFORMANCE_TEST_REFS = {
    "allocator_fixture_exists",
    "allocator_fixture_valid_schema",
    "allocator_covers_malloc",
    "allocator_covers_calloc",
    "allocator_covers_free",
    "allocator_covers_realloc",
    "allocator_modes_valid",
    "allocator_case_count_stable",
    "allocator_has_posix_references",
    "allocator_error_codes_valid",
    "allocator_covers_edge_cases",
    "allocator_fixture_executes_via_isolated_harness",
    "checker_validates_allocator_e2e_completion_contract",
}
REQUIRED_COMPLETION_TEST_REFS = {
    "manifest_binds_e2e_and_conformance_completion_evidence",
    "checker_validates_allocator_e2e_completion_contract",
    "checker_emits_allocator_completion_report_and_jsonl",
    "checker_rejects_missing_stress_fixture_binding",
    "checker_rejects_missing_conformance_test_ref",
    "checker_rejects_unknown_telemetry_event",
}

errors: list[str] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def read_text(path_text: str, label: str) -> str:
    try:
        return (ROOT / path_text).read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} is unreadable: {path_text}: {exc}")
        return ""


def as_string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def require_set(value: Any, required: set[str], context: str) -> set[str]:
    actual = set(as_string_list(value, context))
    missing = sorted(required - actual)
    if missing:
        err(f"{context} missing {','.join(missing)}")
    return actual


def require_text(path_text: str, needles: list[str], context: str) -> str:
    source = read_text(path_text, context)
    for needle in needles:
        require(needle in source, f"{context} missing text {needle!r}")
    return source


def find_fixture(spec: dict[str, Any], fixture_id: str) -> dict[str, Any]:
    fixtures = spec.get("fixtures", [])
    if not isinstance(fixtures, list):
        err("c_fixture_spec.fixtures must be an array")
        return {}
    for item in fixtures:
        if isinstance(item, dict) and item.get("id") == fixture_id:
            return item
    err(f"c_fixture_spec missing fixture {fixture_id}")
    return {}


def require_fixture_spec(fixture: dict[str, Any], expected: dict[str, Any], fixture_id: str) -> None:
    if not fixture:
        return
    require(fixture.get("source") == expected.get("source"), f"{fixture_id}.source mismatch")
    require(fixture.get("tests") == expected.get("tests"), f"{fixture_id}.tests mismatch")
    require_set(fixture.get("covered_symbols"), set(as_string_list(expected.get("covered_symbols"), f"required_fixture_spec.{fixture_id}.covered_symbols")), f"{fixture_id}.covered_symbols")
    for link_flag in as_string_list(expected.get("link_flags", []), f"required_fixture_spec.{fixture_id}.link_flags", allow_empty=True):
        flags = set(as_string_list(fixture.get("link_flags", []), f"{fixture_id}.link_flags", allow_empty=True))
        require(link_flag in flags, f"{fixture_id}.link_flags missing {link_flag}")
    mode_expectations = expected.get("mode_expectations", [])
    if mode_expectations:
        actual_modes = fixture.get("mode_expectations", {})
        if not isinstance(actual_modes, dict):
            err(f"{fixture_id}.mode_expectations must be an object")
            actual_modes = {}
        for mode in as_string_list(mode_expectations, f"required_fixture_spec.{fixture_id}.mode_expectations"):
            entry = actual_modes.get(mode)
            if not isinstance(entry, dict):
                err(f"{fixture_id}.mode_expectations missing {mode}")
                continue
            require(entry.get("expected_exit") == 0, f"{fixture_id}.{mode}.expected_exit must be 0")
            marker = entry.get("expected_stdout_contains", "")
            require(isinstance(marker, str) and marker, f"{fixture_id}.{mode}.expected_stdout_contains missing")


manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}
missing_sources = sorted(REQUIRED_SOURCE_ARTIFACTS - set(source_artifacts))
if missing_sources:
    err(f"source_artifacts missing {','.join(missing_sources)}")
for source_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{source_id} must be a non-empty string")
        continue
    require((ROOT / path_text).exists(), f"source artifact {source_id} missing: {path_text}")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}

gate = evidence.get("required_e2e_gate", {})
if not isinstance(gate, dict):
    err("required_e2e_gate must be an object")
    gate = {}
require(gate.get("bead") == ORIGINAL_BEAD, "required_e2e_gate.bead mismatch")
gate_script = gate.get("script")
if isinstance(gate_script, str):
    gate_text = require_text(
        gate_script,
        [
            "fixtures=(",
            "fixture_malloc",
            "fixture_malloc_stress",
            "FRANKENLIBC_MODE",
            "LD_PRELOAD",
            "TIMEOUT_SECONDS",
            "normalize_stdout",
            "strict_match",
            "hardened_match",
            "overall_ok",
            "allocator_e2e: PASS",
        ],
        "allocator_e2e_gate",
    )
    for mode in as_string_list(gate.get("modes"), "required_e2e_gate.modes"):
        require(mode in gate_text, f"allocator_e2e_gate missing mode {mode}")
    for field in as_string_list(gate.get("required_report_fields"), "required_e2e_gate.required_report_fields"):
        require(field in gate_text, f"allocator_e2e_gate missing report field {field}")
    for marker in as_string_list(gate.get("required_stdout_markers"), "required_e2e_gate.required_stdout_markers"):
        require(marker in gate_text, f"allocator_e2e_gate missing stdout marker {marker}")
else:
    err("required_e2e_gate.script must be a string")

fixture_spec_contract = evidence.get("required_fixture_spec", {})
if not isinstance(fixture_spec_contract, dict):
    err("required_fixture_spec must be an object")
    fixture_spec_contract = {}
fixture_spec_path = fixture_spec_contract.get("path")
c_fixture_spec = load_json(ROOT / str(fixture_spec_path), "c_fixture_spec") if isinstance(fixture_spec_path, str) else {}
expected_fixtures = fixture_spec_contract.get("fixtures", {})
if not isinstance(expected_fixtures, dict):
    err("required_fixture_spec.fixtures must be an object")
    expected_fixtures = {}
missing_expected_fixtures = sorted(REQUIRED_FIXTURES - set(expected_fixtures))
if missing_expected_fixtures:
    err(f"required_fixture_spec.fixtures missing {','.join(missing_expected_fixtures)}")
for fixture_id, expected in expected_fixtures.items():
    if isinstance(expected, dict):
        require_fixture_spec(find_fixture(c_fixture_spec, fixture_id), expected, fixture_id)
    else:
        err(f"required_fixture_spec.fixtures.{fixture_id} must be an object")

malloc_fixture_path = source_artifacts.get("malloc_fixture", "")
if isinstance(malloc_fixture_path, str):
    require_text(malloc_fixture_path, as_string_list(evidence.get("required_malloc_fixture_checks"), "required_malloc_fixture_checks"), "malloc_fixture")
else:
    err("source_artifacts.malloc_fixture must be a string")

stress_fixture_path = source_artifacts.get("malloc_stress_fixture", "")
if isinstance(stress_fixture_path, str):
    stress_text = require_text(stress_fixture_path, as_string_list(evidence.get("required_stress_fixture_checks"), "required_stress_fixture_checks"), "malloc_stress_fixture")
    require(bool(re.search(r"#define\s+STRESS_THREADS\s+4", stress_text)), "malloc_stress_fixture must define STRESS_THREADS 4")
    require(bool(re.search(r"#define\s+STRESS_ITERS\s+5000", stress_text)), "malloc_stress_fixture must define STRESS_ITERS 5000")
else:
    err("source_artifacts.malloc_stress_fixture must be a string")

conformance_fixture = evidence.get("required_conformance_fixture", {})
if not isinstance(conformance_fixture, dict):
    err("required_conformance_fixture must be an object")
    conformance_fixture = {}
allocator_fixture_path = conformance_fixture.get("path")
allocator_fixture = load_json(ROOT / str(allocator_fixture_path), "allocator_conformance_fixture") if isinstance(allocator_fixture_path, str) else {}
require(allocator_fixture.get("version") == conformance_fixture.get("version"), "allocator fixture version mismatch")
require(allocator_fixture.get("family") == conformance_fixture.get("family"), "allocator fixture family mismatch")
cases = allocator_fixture.get("cases", [])
if not isinstance(cases, list):
    err("allocator fixture cases must be an array")
    cases = []
require(len(cases) >= int(conformance_fixture.get("min_cases", 0)), "allocator fixture has too few cases")
case_names = {case.get("name") for case in cases if isinstance(case, dict)}
missing_cases = sorted(set(as_string_list(conformance_fixture.get("required_case_names"), "required_conformance_fixture.required_case_names")) - case_names)
if missing_cases:
    err(f"allocator fixture missing cases {','.join(missing_cases)}")
functions = {case.get("function") for case in cases if isinstance(case, dict)}
missing_functions = sorted(set(as_string_list(conformance_fixture.get("required_functions"), "required_conformance_fixture.required_functions")) - functions)
if missing_functions:
    err(f"allocator fixture missing functions {','.join(missing_functions)}")
for case in cases:
    if not isinstance(case, dict):
        err("allocator fixture cases must be objects")
        continue
    require("POSIX" in str(case.get("spec_section", "")), f"allocator case {case.get('name')} missing POSIX spec reference")
    require(case.get("expected_errno") == 0, f"allocator case {case.get('name')} expected_errno must be 0")
    require(isinstance(case.get("expected_output"), str) and case.get("expected_output"), f"allocator case {case.get('name')} expected_output missing")

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict):
    err("completion_debt_evidence.test_sources must be an object")
    test_sources = {}
allocator_harness = test_sources.get("allocator_conformance_harness", {})
completion_harness = test_sources.get("completion_harness_test", {})
if not isinstance(allocator_harness, dict):
    err("test_sources.allocator_conformance_harness must be an object")
    allocator_harness = {}
if not isinstance(completion_harness, dict):
    err("test_sources.completion_harness_test must be an object")
    completion_harness = {}
require_set(allocator_harness.get("required_test_refs"), REQUIRED_CONFORMANCE_TEST_REFS - {"checker_validates_allocator_e2e_completion_contract"}, "allocator_conformance_harness.required_test_refs")
require_set(completion_harness.get("required_test_refs"), REQUIRED_COMPLETION_TEST_REFS, "completion_harness_test.required_test_refs")

if isinstance(allocator_harness.get("path"), str):
    harness_text = read_text(allocator_harness["path"], "allocator_conformance_harness")
    for test_ref in as_string_list(allocator_harness.get("required_test_refs"), "allocator_conformance_harness.required_test_refs"):
        require(f"fn {test_ref}" in harness_text, f"allocator_conformance_harness missing test {test_ref}")
else:
    err("allocator_conformance_harness.path must be a string")
if isinstance(completion_harness.get("path"), str):
    completion_text = read_text(completion_harness["path"], "completion_harness_test")
    for test_ref in as_string_list(completion_harness.get("required_test_refs"), "completion_harness_test.required_test_refs"):
        require(f"fn {test_ref}" in completion_text, f"completion_harness_test missing test {test_ref}")
else:
    err("completion_harness_test.path must be a string")

telemetry_events = set(as_string_list(evidence.get("telemetry_events"), "completion_debt_evidence.telemetry_events"))
missing_events = sorted(REQUIRED_TELEMETRY_EVENTS - telemetry_events)
if missing_events:
    err(f"completion_debt_evidence.telemetry_events missing {','.join(missing_events)}")
unknown_events = sorted(telemetry_events - REQUIRED_TELEMETRY_EVENTS)
if unknown_events:
    err(f"completion_debt_evidence.telemetry_events has unsupported event(s) {','.join(unknown_events)}")

missing_bindings = manifest.get("missing_item_bindings", [])
if not isinstance(missing_bindings, list):
    err("missing_item_bindings must be an array")
    missing_bindings = []
binding_by_id = {item.get("id"): item for item in missing_bindings if isinstance(item, dict)}
e2e_binding = binding_by_id.get("tests.e2e.primary")
conformance_binding = binding_by_id.get("tests.conformance.primary")
if not isinstance(e2e_binding, dict):
    err("missing_item_bindings missing tests.e2e.primary")
    e2e_binding = {}
if not isinstance(conformance_binding, dict):
    err("missing_item_bindings missing tests.conformance.primary")
    conformance_binding = {}
require(e2e_binding.get("kind") == "e2e", "tests.e2e.primary kind must be e2e")
require(conformance_binding.get("kind") == "conformance", "tests.conformance.primary kind must be conformance")
require_set(e2e_binding.get("required_test_refs"), REQUIRED_E2E_TEST_REFS, "tests.e2e.primary.required_test_refs")
require_set(conformance_binding.get("required_test_refs"), REQUIRED_CONFORMANCE_TEST_REFS, "tests.conformance.primary.required_test_refs")

source_commit = git_head()
status = "fail" if errors else "pass"
failure_signature = "validation_errors" if errors else "none"
event_names = PASS_LOG_EVENTS if not errors else [
    "allocator_e2e_completion_summary",
    FAIL_EVENT,
]
artifact_refs = {
    key: value
    for key, value in sorted(source_artifacts.items())
    if isinstance(value, str)
}
test_refs = sorted(REQUIRED_E2E_TEST_REFS | REQUIRED_CONFORMANCE_TEST_REFS | REQUIRED_COMPLETION_TEST_REFS)
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

rows = []
for event in event_names:
    rows.append(
        {
            "timestamp": timestamp,
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "status": status,
            "outcome": "pass" if not errors else "fail",
            "source_commit": source_commit,
            "schema_version": EXPECTED_REPORT_SCHEMA,
            "artifact_refs": artifact_refs,
            "test_refs": test_refs,
            "fixtures": sorted(expected_fixtures),
            "conformance_cases": sorted(case_names),
            "failure_signature": failure_signature,
        }
    )

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "generated_at_utc": timestamp,
    "source_commit": source_commit,
    "status": status,
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "summary": {
        "fixtures_bound": len(expected_fixtures),
        "allocator_conformance_cases": len(cases),
        "allocator_functions": len(functions),
        "source_artifacts": len(artifact_refs),
        "test_refs": len(test_refs),
        "errors": len(errors),
    },
    "events": event_names,
    "artifact_refs": artifact_refs,
    "test_refs": test_refs,
    "fixtures": sorted(expected_fixtures),
    "conformance_cases": sorted(case_names),
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

if errors:
    print("FAIL: allocator E2E completion contract failed")
    for message in errors:
        print(f"  - {message}")
    sys.exit(1)

print(f"PASS: allocator E2E completion contract validated {len(expected_fixtures)} fixtures and {len(cases)} conformance cases")
PY
