#!/usr/bin/env bash
# check_symbol_fixture_coverage_completion_contract.sh - bd-15n.1.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SYMBOL_FIXTURE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/symbol_fixture_coverage_completion_contract.v1.json}"
SOURCE_MATRIX="${FRANKENLIBC_SYMBOL_FIXTURE_COMPLETION_SOURCE_MATRIX:-$ROOT/tests/conformance/symbol_fixture_coverage.v1.json}"
REPORT="${FRANKENLIBC_SYMBOL_FIXTURE_COMPLETION_REPORT:-$ROOT/target/conformance/symbol_fixture_coverage_completion_contract.report.json}"
LOG="${FRANKENLIBC_SYMBOL_FIXTURE_COMPLETION_LOG:-$ROOT/target/conformance/symbol_fixture_coverage_completion_contract.log.jsonl}"
GENERATED_MATRIX="${FRANKENLIBC_SYMBOL_FIXTURE_COMPLETION_GENERATED:-$ROOT/target/conformance/symbol_fixture_coverage_completion_contract.generated.v1.json}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$GENERATED_MATRIX")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
SOURCE_MATRIX="$SOURCE_MATRIX" \
REPORT="$REPORT" \
LOG="$LOG" \
GENERATED_MATRIX="$GENERATED_MATRIX" \
python3 - <<'PY'
from __future__ import annotations

import copy
import datetime as _dt
import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
SOURCE_MATRIX = pathlib.Path(os.environ["SOURCE_MATRIX"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
GENERATED_MATRIX = pathlib.Path(os.environ["GENERATED_MATRIX"])

COMPLETION_BEAD = "bd-15n.1.1"
ORIGINAL_BEAD = "bd-15n.1"
EXPECTED_SCHEMA = "symbol_fixture_coverage_completion_contract.v1"
EXPECTED_MANIFEST = "bd-15n.1.1-symbol-fixture-coverage-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "integration_primary": "tests.integration.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
}
EXPECTED_PASS_EVENTS = {
    "symbol_fixture_coverage_completion_contract_validated",
    "symbol_fixture_coverage_source_gate_replayed",
    "symbol_fixture_coverage_generator_roundtrip",
    "symbol_fixture_coverage_completion_summary",
}
EXPECTED_EVENTS = EXPECTED_PASS_EVENTS | {
    "symbol_fixture_coverage_completion_contract_failed",
}
EXPECTED_COMPLETION_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "stream",
    "gate",
    "scenario_id",
    "mode",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "decision_path",
    "outcome",
    "errno",
    "latency_ns",
    "source_commit",
    "target_dir",
    "failure_signature",
    "artifact_refs",
    "details",
}

errors: list[str] = []


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def err(message: str) -> None:
    errors.append(message)


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


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


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


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


def validate_repo_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative: {path_text}")
        return None
    full = ROOT / path
    if not full.exists():
        err(f"{context} references missing path: {path_text}")
        return None
    return full


def validate_file_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        err(f"{context} must be a file:line string")
        return
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        err(f"{context} references line past EOF: {value}")
    elif not lines[line_number - 1].strip():
        err(f"{context} references a blank line: {value}")


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


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


def source_texts(test_sources: Any) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return texts
    for key, path_text in test_sources.items():
        path = validate_repo_path(path_text, f"test_sources.{key}")
        if path is not None:
            texts[key] = path.read_text(encoding="utf-8")
    return texts


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not source:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].source must be non-empty")
            continue
        if not isinstance(name, str) or not name:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].name must be non-empty")
            continue
        key = (source, name)
        if key in seen:
            err(f"completion_debt_evidence.{section_name} duplicates test ref {source}::{name}")
        seen.add(key)
        source_text = texts.get(source, "")
        if not source_text:
            err(f"completion_debt_evidence.{section_name} references unknown source {source}")
        elif not function_exists(source_text, name):
            err(f"completion_debt_evidence.{section_name} references missing test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


def validate_required_commands(section: dict[str, Any], section_name: str) -> None:
    commands = as_string_list(section.get("required_commands"), f"completion_debt_evidence.{section_name}.required_commands")
    for command in commands:
        if "cargo " in command and "rch exec --" not in command:
            err(f"completion_debt_evidence.{section_name}.required_commands must route cargo through rch: {command}")


def parse_source_gate_logs(stdout: str, required_fields: set[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, line in enumerate(stdout.splitlines(), start=1):
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            row = json.loads(stripped)
        except Exception as exc:
            err(f"source gate stdout JSON line {index} is invalid: {exc}")
            continue
        if not isinstance(row, dict):
            err(f"source gate stdout JSON line {index} must be an object")
            continue
        missing = sorted(required_fields - row.keys())
        if missing:
            err(f"source gate stdout JSON line {index} missing fields: {missing}")
        rows.append(row)
    if not rows:
        err("source gate did not emit a structured JSON row")
    return rows


def run_source_gate(required_fields: set[str]) -> tuple[list[dict[str, Any]], str]:
    gate = ROOT / "scripts/check_symbol_fixture_coverage.sh"
    result = subprocess.run(
        ["bash", str(gate)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        err(
            "source symbol fixture coverage gate failed: "
            f"exit={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        return [], result.stdout
    rows = parse_source_gate_logs(result.stdout, required_fields)
    if not any(row.get("severity") == "pass" for row in rows):
        err("source symbol fixture coverage gate did not emit severity=pass")
    return rows, result.stdout


def run_generator_roundtrip(source_matrix: dict[str, Any]) -> dict[str, Any]:
    result = subprocess.run(
        [
            "python3",
            "scripts/generate_symbol_fixture_coverage.py",
            "--support-matrix",
            "support_matrix.json",
            "--fixtures-dir",
            "tests/conformance/fixtures",
            "--c-fixture-spec",
            "tests/conformance/c_fixture_spec.json",
            "--workload-matrix",
            "tests/conformance/workload_matrix.json",
            "--output",
            str(GENERATED_MATRIX),
            "--quiet",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        err(
            "symbol fixture coverage generator failed: "
            f"exit={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        return {}
    generated = load_json(GENERATED_MATRIX, "generated coverage matrix")
    if generated and source_matrix and generated != source_matrix:
        err("generated coverage matrix does not match canonical source matrix")
    return generated


def validate_matrix_contract(matrix: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    spec = contract.get("completion_debt_evidence", {}).get("required_coverage_matrix_contract", {})
    if not isinstance(spec, dict):
        err("completion_debt_evidence.required_coverage_matrix_contract must be an object")
        return {}

    for key in as_string_list(spec.get("required_top_level_keys"), "required_coverage_matrix_contract.required_top_level_keys"):
        if key not in matrix:
            err(f"coverage matrix missing required top-level key: {key}")

    if matrix.get("schema_version") != spec.get("schema_version"):
        err("coverage matrix schema_version mismatch")
    if matrix.get("bead") != spec.get("bead"):
        err("coverage matrix bead mismatch")

    summary = matrix.get("summary", {})
    inventory = matrix.get("fixture_inventory", {})
    families = matrix.get("families", [])
    symbols = matrix.get("symbols", [])
    if not isinstance(summary, dict):
        err("coverage matrix summary must be an object")
        summary = {}
    if not isinstance(inventory, dict):
        err("coverage matrix fixture_inventory must be an object")
        inventory = {}
    if not isinstance(families, list) or not families:
        err("coverage matrix families must be a non-empty array")
        families = []
    if not isinstance(symbols, list) or not symbols:
        err("coverage matrix symbols must be a non-empty array")
        symbols = []

    minimums = {
        "total_exported_symbols": spec.get("minimum_total_exported_symbols"),
        "fixture_json_files": spec.get("minimum_fixture_json_files"),
        "fixture_json_cases": spec.get("minimum_fixture_json_cases"),
        "c_fixture_spec_fixtures": spec.get("minimum_c_fixture_spec_fixtures"),
    }
    if int(summary.get("total_exported_symbols", 0)) < int(minimums["total_exported_symbols"] or 0):
        err("coverage matrix total_exported_symbols is below completion minimum")
    if int(inventory.get("fixture_json_files", 0)) < int(minimums["fixture_json_files"] or 0):
        err("coverage matrix fixture_json_files is below completion minimum")
    if int(inventory.get("fixture_json_cases", 0)) < int(minimums["fixture_json_cases"] or 0):
        err("coverage matrix fixture_json_cases is below completion minimum")
    if int(inventory.get("c_fixture_spec_fixtures", 0)) < int(minimums["c_fixture_spec_fixtures"] or 0):
        err("coverage matrix c_fixture_spec_fixtures is below completion minimum")

    expected_statuses = sorted(as_string_list(spec.get("target_statuses"), "required_coverage_matrix_contract.target_statuses"))
    actual_statuses = sorted([str(item) for item in summary.get("target_statuses", [])])
    if actual_statuses != expected_statuses:
        err(f"coverage matrix target_statuses mismatch: expected={expected_statuses} actual={actual_statuses}")

    if summary.get("total_exported_symbols") != len(symbols):
        err("summary.total_exported_symbols does not match symbols length")
    covered_symbols = sum(1 for row in symbols if isinstance(row, dict) and row.get("covered"))
    if summary.get("covered_exported_symbols") != covered_symbols:
        err("summary.covered_exported_symbols does not match symbol covered count")

    target_total = sum(int(row.get("target_total", 0)) for row in families if isinstance(row, dict))
    target_covered = sum(int(row.get("target_covered", 0)) for row in families if isinstance(row, dict))
    if summary.get("target_total_symbols") != target_total:
        err("summary.target_total_symbols does not match family target totals")
    if summary.get("target_covered_symbols") != target_covered:
        err("summary.target_covered_symbols does not match family target covered totals")
    if summary.get("target_uncovered_symbols") != target_total - target_covered:
        err("summary.target_uncovered_symbols does not match family target uncovered totals")

    symbol_fields = set(as_string_list(spec.get("required_symbol_fields"), "required_coverage_matrix_contract.required_symbol_fields"))
    for index, row in enumerate(symbols[:25]):
        if not isinstance(row, dict):
            err(f"symbols[{index}] must be an object")
            continue
        missing = sorted(symbol_fields - row.keys())
        if missing:
            err(f"symbols[{index}] missing fields: {missing}")

    family_fields = set(as_string_list(spec.get("required_family_fields"), "required_coverage_matrix_contract.required_family_fields"))
    for index, row in enumerate(families[:25]):
        if not isinstance(row, dict):
            err(f"families[{index}] must be an object")
            continue
        missing = sorted(family_fields - row.keys())
        if missing:
            err(f"families[{index}] missing fields: {missing}")

    expected_uncovered = sorted(
        [
            row["module"]
            for row in families
            if isinstance(row, dict)
            and row.get("target_total", 0) > 0
            and row.get("target_covered", 0) == 0
        ]
    )
    actual_uncovered = sorted(
        [
            row.get("module")
            for row in matrix.get("uncovered_target_families", [])
            if isinstance(row, dict)
        ]
    )
    if expected_uncovered != actual_uncovered:
        err(f"uncovered_target_families mismatch: expected={expected_uncovered} actual={actual_uncovered}")

    weak_threshold = float(summary.get("weak_family_threshold_pct", 0.0))
    expected_weak = sorted(
        [
            row["module"]
            for row in families
            if isinstance(row, dict)
            and row.get("target_total", 0) > 0
            and 0 < float(row.get("target_coverage_pct", 0.0)) < weak_threshold
        ]
    )
    actual_weak = sorted(
        [
            row.get("module")
            for row in matrix.get("weak_target_families", [])
            if isinstance(row, dict)
        ]
    )
    if expected_weak != actual_weak:
        err(f"weak_target_families mismatch: expected={expected_weak} actual={actual_weak}")

    return {
        "total_exported_symbols": summary.get("total_exported_symbols", 0),
        "covered_exported_symbols": summary.get("covered_exported_symbols", 0),
        "target_total_symbols": summary.get("target_total_symbols", 0),
        "target_covered_symbols": summary.get("target_covered_symbols", 0),
        "target_uncovered_symbols": summary.get("target_uncovered_symbols", 0),
        "fixture_json_files": inventory.get("fixture_json_files", 0),
        "fixture_json_cases": inventory.get("fixture_json_cases", 0),
        "c_fixture_spec_fixtures": inventory.get("c_fixture_spec_fixtures", 0),
        "uncovered_target_families": len(matrix.get("uncovered_target_families", [])),
        "weak_target_families": len(matrix.get("weak_target_families", [])),
    }


def completion_log(event: str, outcome: str, scenario_id: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": now(),
        "trace_id": f"{COMPLETION_BEAD}::symbol-fixture-coverage-completion-v1::{scenario_id}",
        "level": "info" if outcome == "pass" else "error",
        "event": event,
        "bead_id": COMPLETION_BEAD,
        "stream": "conformance",
        "gate": "symbol_fixture_coverage_completion_contract",
        "scenario_id": scenario_id,
        "mode": "strict",
        "api_family": "conformance",
        "symbol": "symbol_fixture_coverage",
        "oracle_kind": "artifact_contract",
        "expected": {"missing_items": sorted(EXPECTED_MISSING_ITEMS.values())},
        "actual": details,
        "decision_path": "contract_validate_then_replay_source_gate",
        "outcome": outcome,
        "errno": 0 if outcome == "pass" else 1,
        "latency_ns": 0,
        "source_commit": git_head(),
        "target_dir": rel(ROOT / "target/conformance"),
        "failure_signature": "none" if outcome == "pass" else "completion_contract_validation_failed",
        "artifact_refs": [
            rel(CONTRACT),
            rel(SOURCE_MATRIX),
            rel(REPORT),
            rel(LOG),
            rel(GENERATED_MATRIX),
        ],
        "details": details,
    }


def validate_completion_log_shape(rows: list[dict[str, Any]], spec: dict[str, Any]) -> None:
    required_events = set(as_string_list(spec.get("required_completion_log_events"), "required_coverage_matrix_contract.required_completion_log_events"))
    forbidden_events = set(as_string_list(spec.get("forbidden_completion_log_events"), "required_coverage_matrix_contract.forbidden_completion_log_events"))
    actual_events = {str(row.get("event")) for row in rows}
    missing_events = sorted(required_events - actual_events)
    if missing_events:
        err(f"completion log is missing events: {missing_events}")
    forbidden_seen = sorted(forbidden_events & actual_events)
    if forbidden_seen:
        err(f"completion log contains forbidden events: {forbidden_seen}")
    for index, row in enumerate(rows, start=1):
        if row.get("event") not in EXPECTED_EVENTS:
            err(f"completion log row {index} has unexpected event: {row.get('event')}")
        missing = sorted(EXPECTED_COMPLETION_LOG_FIELDS - row.keys())
        if missing:
            err(f"completion log row {index} missing required fields: {missing}")


started_ns = time.time_ns()
contract = load_json(CONTRACT, "completion contract")
source_matrix = load_json(SOURCE_MATRIX, "source coverage matrix")

if contract:
    if contract.get("schema_version") != EXPECTED_SCHEMA:
        err("completion contract schema_version mismatch")
    if contract.get("manifest_id") != EXPECTED_MANIFEST:
        err("completion contract manifest_id mismatch")
    if contract.get("bead") != COMPLETION_BEAD:
        err("completion contract bead mismatch")
    if contract.get("original_bead") != ORIGINAL_BEAD:
        err("completion contract original_bead mismatch")

    source_artifacts = contract.get("source_artifacts", {})
    if not isinstance(source_artifacts, dict) or not source_artifacts:
        err("source_artifacts must be a non-empty object")
    else:
        for key, value in source_artifacts.items():
            validate_repo_path(value, f"source_artifacts.{key}")

    evidence = contract.get("completion_debt_evidence", {})
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        evidence = {}

    bindings = evidence.get("missing_item_bindings", [])
    if not isinstance(bindings, list):
        err("completion_debt_evidence.missing_item_bindings must be an array")
        bindings = []
    binding_map: dict[str, str] = {}
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            err(f"missing_item_bindings[{index}] must be an object")
            continue
        item = binding.get("missing_item_id")
        section = binding.get("evidence_section")
        if not isinstance(item, str) or not item:
            err(f"missing_item_bindings[{index}].missing_item_id must be non-empty")
            continue
        if not isinstance(section, str) or not section:
            err(f"missing_item_bindings[{index}].evidence_section must be non-empty")
            continue
        binding_map[section] = item
    if binding_map != EXPECTED_MISSING_ITEMS:
        err(f"missing item bindings mismatch: expected={EXPECTED_MISSING_ITEMS} actual={binding_map}")

    refs = evidence.get("implementation_refs")
    if not isinstance(refs, list) or not refs:
        err("completion_debt_evidence.implementation_refs must be a non-empty array")
    else:
        for index, ref in enumerate(refs):
            validate_file_line_ref(ref, f"implementation_refs[{index}]")

    texts = source_texts(evidence.get("test_sources"))
    all_test_refs: list[dict[str, str]] = []
    for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
        section = evidence.get(section_name)
        if not isinstance(section, dict):
            err(f"completion_debt_evidence.{section_name} must be an object")
            continue
        if section.get("missing_item_id") != missing_item:
            err(f"completion_debt_evidence.{section_name}.missing_item_id mismatch")
        all_test_refs.extend(validate_test_refs(section, section_name, texts))
        validate_required_commands(section, section_name)

    matrix_summary = validate_matrix_contract(source_matrix, contract)
    matrix_spec = evidence.get("required_coverage_matrix_contract", {})
    required_source_fields = set(
        as_string_list(
            matrix_spec.get("required_source_gate_log_fields"),
            "required_coverage_matrix_contract.required_source_gate_log_fields",
        )
    )
else:
    all_test_refs = []
    matrix_summary = {}
    matrix_spec = {}
    required_source_fields = set()

source_gate_rows, source_gate_stdout = run_source_gate(required_source_fields)
generated = run_generator_roundtrip(source_matrix)
if generated:
    generated_summary = validate_matrix_contract(generated, contract)
else:
    generated_summary = {}

elapsed_ns = time.time_ns() - started_ns
pass_rows = [
    completion_log(
        "symbol_fixture_coverage_completion_contract_validated",
        "pass",
        "completion-contract",
        {
            "missing_items_bound": sorted(EXPECTED_MISSING_ITEMS.values()),
            "test_ref_count": len(all_test_refs),
            "matrix_summary": matrix_summary,
        },
    ),
    completion_log(
        "symbol_fixture_coverage_source_gate_replayed",
        "pass",
        "source-gate",
        {
            "source_gate_log_rows": len(source_gate_rows),
            "source_gate_stdout_tail": source_gate_stdout.splitlines()[-3:],
        },
    ),
    completion_log(
        "symbol_fixture_coverage_generator_roundtrip",
        "pass",
        "generator-roundtrip",
        {
            "generated_matrix": rel(GENERATED_MATRIX),
            "generated_summary": generated_summary,
        },
    ),
    completion_log(
        "symbol_fixture_coverage_completion_summary",
        "pass",
        "completion-summary",
        {
            "elapsed_ns": elapsed_ns,
            "report": rel(REPORT),
            "log": rel(LOG),
        },
    ),
]

if not errors:
    validate_completion_log_shape(pass_rows, matrix_spec)

status = "pass" if not errors else "fail"
if errors:
    log_rows = [
        completion_log(
            "symbol_fixture_coverage_completion_contract_failed",
            "fail",
            "completion-contract",
            {"errors": errors},
        )
    ]
else:
    log_rows = pass_rows

report = {
    "schema_version": "symbol_fixture_coverage_completion_contract.report.v1",
    "bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "source_commit": git_head(),
    "contract": rel(CONTRACT),
    "source_matrix": rel(SOURCE_MATRIX),
    "generated_matrix": rel(GENERATED_MATRIX),
    "summary": {
        "missing_items_bound": sorted(EXPECTED_MISSING_ITEMS.values()),
        "test_ref_count": len(all_test_refs),
        "source_gate_log_rows": len(source_gate_rows),
        "completion_log_rows": len(log_rows),
        "elapsed_ns": elapsed_ns,
        "matrix": matrix_summary,
    },
    "artifact_refs": [rel(CONTRACT), rel(SOURCE_MATRIX), rel(GENERATED_MATRIX), rel(LOG)],
    "errors": errors,
}

write_json(REPORT, report)
write_jsonl(LOG, log_rows)

if errors:
    print("FAIL: symbol fixture coverage completion contract validation failed", file=sys.stderr)
    for message in errors:
        print(f"  - {message}", file=sys.stderr)
    raise SystemExit(1)

print(f"check_symbol_fixture_coverage_completion_contract: PASS ({elapsed_ns // 1_000_000}ms)")
PY
