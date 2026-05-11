#!/usr/bin/env bash
# check_per_symbol_fixture_completion_contract.sh - bd-ldj.5.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/per_symbol_fixture_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_REPORT:-$OUT_DIR/per_symbol_fixture_completion_contract.report.json}"
LOG="${FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_LOG:-$OUT_DIR/per_symbol_fixture_completion_contract.log.jsonl}"
GATE_DIR="${FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_GATE_DIR:-$OUT_DIR/per_symbol_fixture_completion_contract.source_gates}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$GATE_DIR"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
GATE_DIR="$GATE_DIR" \
python3 - <<'PY'
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
GATE_DIR = pathlib.Path(os.environ["GATE_DIR"])

EXPECTED_SCHEMA = "per_symbol_fixture_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "per_symbol_fixture_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-ldj.5.1-per-symbol-fixture-completion-contract"
ORIGINAL_BEAD = "bd-ldj.5"
COMPLETION_BEAD = "bd-ldj.5.1"
REQUIRED_SOURCE_ARTIFACTS = {
    "symbol_fixture_coverage_matrix",
    "symbol_fixture_coverage_completion_contract",
    "symbol_fixture_coverage_gate",
    "symbol_fixture_coverage_harness",
    "fixture_schema_validation_manifest",
    "fixture_schema_validation_gate",
    "fixture_schema_validation_harness",
    "fixture_expected_output_policy",
    "golden_fixture_protocol",
    "golden_fixture_protocol_completion_contract",
    "golden_fixture_protocol_completion_gate",
    "golden_fixture_protocol_harness",
    "completion_checker",
    "completion_harness",
}
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.golden.primary",
    "tests.conformance.primary",
}
PASS_EVENTS = {
    "per_symbol_fixture_completion_summary",
    "per_symbol_fixture_unit_bindings",
    "per_symbol_fixture_golden_bindings",
    "per_symbol_fixture_conformance_bindings",
    "per_symbol_fixture_completion_contract_pass",
}
FAIL_EVENT = "per_symbol_fixture_completion_contract_fail"
REQUIRED_LOG_FIELDS = {
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
    "failure_signature",
    "artifact_refs",
    "details",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "manifest_id",
    "source_bead",
    "completion_debt_bead",
    "status",
    "source_commit",
    "summary",
    "source_artifacts",
    "source_gate_results",
    "events",
    "errors",
}

errors: list[str] = []
source_gate_results: dict[str, dict[str, Any]] = {}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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


def json_lines(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} is unreadable: {rel(path)}: {exc}")
        return []
    rows: list[dict[str, Any]] = []
    for index, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except Exception as exc:
            err(f"{label}:{index} is not valid JSON: {exc}")
            continue
        if not isinstance(value, dict):
            err(f"{label}:{index} must be a JSON object")
            continue
        rows.append(value)
    return rows


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


def require_path(path_text: Any, context: str) -> pathlib.Path | None:
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


def source_text(path_text: str, context: str) -> str:
    path = require_path(path_text, context)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {path_text}: {exc}")
        return ""


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}" in text or f"def {name}" in text


def positive_int(value: Any, context: str) -> int:
    try:
        parsed = int(value)
    except Exception:
        err(f"{context} must be an integer")
        return -1
    if parsed <= 0:
        err(f"{context} must be positive")
    return parsed


def nonnegative_int(value: Any, context: str) -> int:
    try:
        parsed = int(value)
    except Exception:
        err(f"{context} must be an integer")
        return -1
    if parsed < 0:
        err(f"{context} must be nonnegative")
    return parsed


def run_gate(label: str, command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    started = time.time_ns()
    proc = subprocess.run(
        command,
        cwd=ROOT,
        env=merged,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    elapsed_ns = time.time_ns() - started
    source_gate_results[label] = {
        "command": command,
        "exit_code": proc.returncode,
        "latency_ns": elapsed_ns,
        "stdout_tail": proc.stdout[-1600:],
        "stderr_tail": proc.stderr[-1600:],
    }
    if proc.returncode != 0:
        err(
            f"{label} source gate failed exit={proc.returncode} "
            f"stdout={proc.stdout[-800:]!r} stderr={proc.stderr[-800:]!r}"
        )
    return proc


def parse_stdout_json_rows(stdout: str, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, line in enumerate(stdout.splitlines(), start=1):
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            value = json.loads(stripped)
        except Exception as exc:
            err(f"{label} stdout JSON row {index} is invalid: {exc}")
            continue
        if not isinstance(value, dict):
            err(f"{label} stdout JSON row {index} must be an object")
            continue
        rows.append(value)
    return rows


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
    require(manifest.get("manifest_id") == EXPECTED_MANIFEST, f"manifest_id must be {EXPECTED_MANIFEST}")
    require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
    require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

    source_artifacts = manifest.get("source_artifacts", {})
    if not isinstance(source_artifacts, dict) or not source_artifacts:
        err("source_artifacts must be a non-empty object")
        source_artifacts = {}
    missing_sources = sorted(REQUIRED_SOURCE_ARTIFACTS - set(source_artifacts))
    if missing_sources:
        err(f"source_artifacts missing {missing_sources}")
    for artifact_id, path_text in source_artifacts.items():
        require_path(path_text, f"source_artifacts.{artifact_id}")

    evidence = manifest.get("completion_debt_evidence", {})
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        evidence = {}

    bindings = evidence.get("missing_item_bindings", [])
    if not isinstance(bindings, list) or not bindings:
        err("completion_debt_evidence.missing_item_bindings must be a non-empty array")
        bindings = []
    binding_ids = {str(item.get("id")) for item in bindings if isinstance(item, dict)}
    require(binding_ids == REQUIRED_MISSING_ITEMS, f"missing item bindings must be exactly {sorted(REQUIRED_MISSING_ITEMS)}")

    test_sources = evidence.get("test_sources", {})
    source_texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        test_sources = {}
    for source_id, spec in test_sources.items():
        if not isinstance(spec, dict):
            err(f"test_sources.{source_id} must be an object")
            continue
        path_text = spec.get("path")
        if not isinstance(path_text, str):
            err(f"test_sources.{source_id}.path must be a string")
            continue
        text = source_text(path_text, f"test_sources.{source_id}.path")
        source_texts[source_id] = text
        for test_ref in as_string_list(spec.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
            require(function_exists(text, test_ref), f"test source {source_id} missing required test {test_ref}")

    for index, ref in enumerate(evidence.get("implementation_refs", [])):
        if not isinstance(ref, dict):
            err(f"implementation_refs[{index}] must be an object")
            continue
        path_text = ref.get("path")
        if not isinstance(path_text, str):
            err(f"implementation_refs[{index}].path must be a string")
            continue
        text = source_text(path_text, f"implementation_refs.{ref.get('id', index)}.path")
        for needle in as_string_list(ref.get("required_text"), f"implementation_refs.{ref.get('id', index)}.required_text"):
            require(needle in text, f"implementation ref {ref.get('id', index)} missing {needle!r}")

    for item in bindings:
        if not isinstance(item, dict):
            continue
        for test_ref in as_string_list(item.get("required_test_refs"), f"missing_item_bindings.{item.get('id')}.required_test_refs"):
            require(
                any(function_exists(text, test_ref) for text in source_texts.values()),
                f"missing item {item.get('id')} references absent test {test_ref}",
            )

    contract = evidence.get("required_per_symbol_contract", {})
    if not isinstance(contract, dict):
        err("completion_debt_evidence.required_per_symbol_contract must be an object")
        contract = {}
    require(contract.get("coverage_gaps_are_explicit") is True, "coverage_gaps_are_explicit must be true")
    required_gates = set(as_string_list(contract.get("required_source_gates"), "required_per_symbol_contract.required_source_gates"))
    expected_gates = {
        "scripts/check_symbol_fixture_coverage.sh",
        "scripts/check_fixture_schema_validation.sh --validate-only",
        "scripts/check_golden_fixture_protocol_completion_contract.sh",
    }
    require(expected_gates <= required_gates, "required source gate set is incomplete")

    telemetry = manifest.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        telemetry = {}
    require(telemetry.get("report_schema_version") == EXPECTED_REPORT_SCHEMA, "telemetry report schema mismatch")
    require(set(as_string_list(telemetry.get("required_report_fields"), "telemetry.required_report_fields")) == REQUIRED_REPORT_FIELDS, "required report fields mismatch")
    require(set(as_string_list(telemetry.get("required_log_fields"), "telemetry.required_log_fields")) == REQUIRED_LOG_FIELDS, "required log fields mismatch")
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry.required_events"))
    require(PASS_EVENTS <= required_events, "required pass events are incomplete")
    forbidden_pass = set(as_string_list(telemetry.get("forbidden_pass_events"), "telemetry.forbidden_pass_events"))
    require(FAIL_EVENT in forbidden_pass, "fail event must be forbidden on pass")

    return contract


def validate_matrix(matrix: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    for key in as_string_list(contract.get("required_matrix_top_level_keys"), "required_per_symbol_contract.required_matrix_top_level_keys"):
        require(key in matrix, f"symbol fixture matrix missing top-level key {key}")
    require(matrix.get("schema_version") == 1, "symbol fixture matrix schema_version must be 1")
    summary = matrix.get("summary", {})
    inventory = matrix.get("fixture_inventory", {})
    symbols = matrix.get("symbols", [])
    if not isinstance(summary, dict):
        err("symbol fixture matrix summary must be an object")
        summary = {}
    if not isinstance(inventory, dict):
        err("symbol fixture matrix fixture_inventory must be an object")
        inventory = {}
    if not isinstance(symbols, list) or not symbols:
        err("symbol fixture matrix symbols must be a non-empty array")
        symbols = []

    total = positive_int(summary.get("total_exported_symbols"), "summary.total_exported_symbols")
    covered = positive_int(summary.get("covered_exported_symbols"), "summary.covered_exported_symbols")
    uncovered = nonnegative_int(summary.get("target_uncovered_symbols"), "summary.target_uncovered_symbols")
    require(total >= int(contract.get("minimum_total_exported_symbols", 0)), "total exported symbols is below contract minimum")
    require(covered >= int(contract.get("minimum_covered_exported_symbols", 0)), "covered exported symbols is below contract minimum")
    require(uncovered > 0, "current coverage gaps must remain explicit, not hidden")
    require(len(symbols) == total, "symbol row count must match total_exported_symbols")

    require(
        int(inventory.get("fixture_json_files", -1)) >= int(contract.get("minimum_fixture_json_files", 0)),
        "fixture_json_files is below contract minimum",
    )
    require(
        int(inventory.get("fixture_json_cases", -1)) >= int(contract.get("minimum_fixture_json_cases", 0)),
        "fixture_json_cases is below contract minimum",
    )
    require(
        int(inventory.get("fixture_json_unique_functions", -1)) >= int(contract.get("minimum_fixture_json_unique_functions", 0)),
        "fixture_json_unique_functions is below contract minimum",
    )

    required_symbol_fields = set(as_string_list(contract.get("required_symbol_fields"), "required_per_symbol_contract.required_symbol_fields"))
    covered_rows = 0
    for index, row in enumerate(symbols):
        if not isinstance(row, dict):
            err(f"symbols[{index}] must be an object")
            continue
        missing = sorted(required_symbol_fields - set(row))
        if missing:
            err(f"symbols[{index}] missing fields {missing}")
        if row.get("covered") is True:
            covered_rows += 1
            sources = row.get("fixture_sources")
            sources = sources if isinstance(sources, list) else []
            json_fixture_backed = (
                int(row.get("fixture_case_count", 0)) > 0
                and isinstance(row.get("fixture_files"), list)
                and len(row.get("fixture_files")) > 0
                and isinstance(row.get("fixture_modes"), list)
                and len(row.get("fixture_modes")) > 0
            )
            c_fixture_backed = (
                int(row.get("c_fixture_mentions", 0)) > 0
                and isinstance(row.get("fixture_ids"), list)
                and len(row.get("fixture_ids")) > 0
                and "c_fixture_spec" in sources
            )
            require(
                json_fixture_backed or c_fixture_backed,
                f"covered symbol {row.get('symbol')} needs JSON fixture cases or c_fixture_spec evidence",
            )
            require(
                isinstance(row.get("fixture_families"), list) and len(row.get("fixture_families")) > 0,
                f"covered symbol {row.get('symbol')} needs non-empty fixture_families",
            )
            require(sources, f"covered symbol {row.get('symbol')} needs non-empty fixture_sources")
    require(covered_rows == covered, "covered symbol row count must match summary")

    return {
        "total_exported_symbols": total,
        "covered_exported_symbols": covered,
        "target_uncovered_symbols": uncovered,
        "fixture_json_files": inventory.get("fixture_json_files"),
        "fixture_json_cases": inventory.get("fixture_json_cases"),
        "fixture_json_unique_functions": inventory.get("fixture_json_unique_functions"),
    }


def validate_fixture_schema(schema_manifest: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    require(schema_manifest.get("schema_version") == "fixture_schema_validation.v1", "fixture schema validation schema mismatch")
    expected = schema_manifest.get("expected_inventory", {})
    if not isinstance(expected, dict):
        err("fixture_schema_validation.expected_inventory must be an object")
        expected = {}
    require(int(expected.get("standard_case_count", -1)) >= int(contract.get("minimum_fixture_schema_standard_cases", 0)), "fixture schema standard_case_count below contract minimum")
    require(int(expected.get("expected_errno_required_cases", -1)) >= int(contract.get("minimum_expected_errno_required_cases", 0)), "expected_errno_required_cases below contract minimum")
    primary = expected.get("primary_expectation_tags", {})
    require(isinstance(primary, dict) and int(primary.get("expected_output", 0)) > 0, "fixture schema must count expected_output tags")
    require(isinstance(primary, dict) and int(primary.get("expected_return+expected_values", 0)) > 0, "fixture schema must count expected_return+expected_values tags")
    return {
        "standard_case_count": expected.get("standard_case_count"),
        "expected_errno_required_cases": expected.get("expected_errno_required_cases"),
        "expected_output_tags": primary.get("expected_output") if isinstance(primary, dict) else None,
    }


def validate_golden_protocol(protocol: dict[str, Any]) -> dict[str, Any]:
    require(protocol.get("schema_version") == "v1", "golden fixture protocol schema mismatch")
    require(protocol.get("bead") == "bd-15n.3", "golden fixture protocol source bead mismatch")
    capture = protocol.get("protocol", {}).get("capture", {}) if isinstance(protocol.get("protocol"), dict) else {}
    verification = protocol.get("protocol", {}).get("verification", {}) if isinstance(protocol.get("protocol"), dict) else {}
    coverage = protocol.get("protocol", {}).get("coverage_regression", {}) if isinstance(protocol.get("protocol"), dict) else {}
    outputs = capture.get("outputs", [])
    require(capture.get("command") == "scripts/update_conformance_golden.sh", "golden capture command mismatch")
    require(capture.get("fixed_timestamp") == "1970-01-01T00:00:00Z", "golden fixed timestamp mismatch")
    require(verification.get("command") == "scripts/conformance_golden_gate.sh", "golden verification command mismatch")
    require(coverage.get("command") == "scripts/check_conformance_coverage.sh", "golden coverage command mismatch")
    require(isinstance(outputs, list) and len(outputs) >= 4, "golden protocol needs at least four outputs")
    for output in outputs:
        require_path(output, f"golden protocol output {output}")
    return {"golden_output_count": len(outputs)}


def finish(manifest: dict[str, Any], summary: dict[str, Any], status: str, started_ns: int) -> None:
    source_commit = git_head()
    elapsed_ns = time.time_ns() - started_ns
    outcome = "pass" if status == "pass" else "fail"
    failure_signature = "none" if status == "pass" else ";".join(errors[:8])
    artifact_refs = [rel(CONTRACT), rel(REPORT), rel(LOG)]
    timestamp = now()
    events = [
        (
            "per_symbol_fixture_completion_summary",
            "release",
            "summary",
            {"summary": summary, "source_gate_count": len(source_gate_results)},
        ),
        (
            "per_symbol_fixture_unit_bindings",
            "unit",
            "unit_bindings",
            {"required_items": ["tests.unit.primary"], "source_harness": "symbol_fixture_coverage_test"},
        ),
        (
            "per_symbol_fixture_golden_bindings",
            "release",
            "golden_bindings",
            {"required_items": ["tests.golden.primary"], "source_harness": "golden_fixture_protocol_completion_contract_test"},
        ),
        (
            "per_symbol_fixture_conformance_bindings",
            "conformance",
            "conformance_bindings",
            {"required_items": ["tests.conformance.primary"], "source_harness": "fixture_schema_validation_test"},
        ),
        (
            "per_symbol_fixture_completion_contract_pass" if status == "pass" else FAIL_EVENT,
            "release",
            "contract_result",
            {"errors": errors, "latency_ns": elapsed_ns},
        ),
    ]

    rows = []
    for index, (event, stream, scenario, details) in enumerate(events, start=1):
        rows.append(
            {
                "timestamp": timestamp,
                "trace_id": f"{COMPLETION_BEAD}::per-symbol-fixture::{index:03d}",
                "level": "info" if status == "pass" else "error",
                "event": event,
                "bead_id": COMPLETION_BEAD,
                "stream": stream,
                "gate": "per_symbol_fixture_completion_contract",
                "scenario_id": scenario,
                "mode": "strict",
                "api_family": "symbols",
                "symbol": "per_symbol_fixture_contract",
                "oracle_kind": "fixture",
                "expected": {"status": "pass", "required_items": sorted(REQUIRED_MISSING_ITEMS)},
                "actual": {"status": status, "error_count": len(errors)},
                "decision_path": "manifest+coverage_matrix+fixture_schema+golden_protocol",
                "outcome": outcome,
                "errno": 0 if status == "pass" else 1,
                "latency_ns": elapsed_ns,
                "source_commit": source_commit,
                "failure_signature": failure_signature,
                "artifact_refs": artifact_refs,
                "details": details,
            }
        )

    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "source_commit": source_commit,
        "summary": summary,
        "source_artifacts": manifest.get("source_artifacts", {}),
        "source_gate_results": source_gate_results,
        "events": [row["event"] for row in rows],
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows), encoding="utf-8")


started_ns = time.time_ns()
manifest = load_json(CONTRACT, "contract")
required_contract = validate_manifest(manifest)

source_artifacts = manifest.get("source_artifacts", {}) if isinstance(manifest.get("source_artifacts"), dict) else {}
matrix = load_json(ROOT / str(source_artifacts.get("symbol_fixture_coverage_matrix", "")), "symbol fixture coverage matrix")
schema_manifest = load_json(ROOT / str(source_artifacts.get("fixture_schema_validation_manifest", "")), "fixture schema validation manifest")
golden_protocol = load_json(ROOT / str(source_artifacts.get("golden_fixture_protocol", "")), "golden fixture protocol")
matrix_summary = validate_matrix(matrix, required_contract)
schema_summary = validate_fixture_schema(schema_manifest, required_contract)
golden_summary = validate_golden_protocol(golden_protocol)

summary = {
    **matrix_summary,
    **schema_summary,
    **golden_summary,
}

if not errors:
    symbol_proc = run_gate("symbol_fixture_coverage", ["bash", "scripts/check_symbol_fixture_coverage.sh"])
    symbol_rows = parse_stdout_json_rows(symbol_proc.stdout, "symbol_fixture_coverage")
    require(any(row.get("severity") == "pass" for row in symbol_rows), "symbol fixture coverage gate did not emit a pass row")
    source_gate_results["symbol_fixture_coverage"]["json_rows"] = len(symbol_rows)

    schema_proc = run_gate("fixture_schema_validation", ["bash", "scripts/check_fixture_schema_validation.sh", "--validate-only"])
    schema_report = load_json(ROOT / "target/conformance/fixture_schema_validation.report.json", "fixture schema validation report")
    require(schema_report.get("outcome") == "pass", "fixture schema validation report must pass")
    schema_rows = json_lines(ROOT / "target/conformance/fixture_schema_validation.log.jsonl", "fixture schema validation log")
    require(any(row.get("event") == "fixture_schema_validation_validated" for row in schema_rows), "fixture schema validation log missing pass event")
    source_gate_results["fixture_schema_validation"]["json_rows"] = len(schema_rows)

    golden_report = GATE_DIR / "golden_fixture_protocol_completion_contract.report.json"
    golden_log = GATE_DIR / "golden_fixture_protocol_completion_contract.log.jsonl"
    golden_proc = run_gate(
        "golden_fixture_protocol_completion",
        ["bash", "scripts/check_golden_fixture_protocol_completion_contract.sh"],
        {
            "FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_OUT_DIR": str(GATE_DIR),
            "FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_REPORT": str(golden_report),
            "FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_LOG": str(golden_log),
        },
    )
    golden_report_json = load_json(golden_report, "golden fixture protocol completion report")
    require(golden_report_json.get("status") == "pass", "golden fixture protocol completion report must pass")
    golden_rows = json_lines(golden_log, "golden fixture protocol completion log")
    require(any(row.get("event") == "golden_fixture_protocol_completion_contract_pass" for row in golden_rows), "golden fixture protocol completion log missing pass event")
    source_gate_results["golden_fixture_protocol_completion"]["json_rows"] = len(golden_rows)

status = "pass" if not errors else "fail"
finish(manifest, summary, status, started_ns)

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"REPORT={rel(REPORT)}")
print(f"LOG={rel(LOG)}")
if status == "pass":
    print(
        "PASS: per-symbol fixture completion contract "
        f"covered_symbols={summary.get('covered_exported_symbols')} "
        f"fixture_cases={summary.get('fixture_json_cases')}"
    )
else:
    for message in errors:
        print(f"ERROR: {message}")
    raise SystemExit(1)
PY
