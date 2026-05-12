#!/usr/bin/env bash
# check_conformance_logging_completion_contract.sh -- fail-closed gate for bd-2hh.7.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_CONFORMANCE_LOGGING_CONTRACT:-${ROOT}/tests/conformance/conformance_logging_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_CONFORMANCE_LOGGING_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_CONFORMANCE_LOGGING_REPORT:-${OUT_DIR}/conformance_logging_completion_contract.report.json}"
LOG="${FRANKENLIBC_CONFORMANCE_LOGGING_LOG:-${OUT_DIR}/conformance_logging_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
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

BEAD_ID = "bd-2hh.7"
COMPLETION_BEAD_ID = "bd-2hh.7.1"
MANIFEST_ID = "conformance-logging-completion-contract"
REQUIRED_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "conformance_logging_source",
    "conformance_logging_shadow",
    "conformance_logging_fixture",
    "conformance_logging_benchmark",
    "conformance_logging_summary",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str], context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{context} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{context} must be a JSON object")
        return {}
    return value


def read_text(path_text: str, errors: list[str], context: str) -> str:
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} missing file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{context} unreadable: {path_text}: {exc}")
        return ""


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def strings(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{index}] must be a non-empty string")
        else:
            out.append(item)
    return out


def validate_source_artifacts(
    contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> dict[str, str]:
    artifacts = contract.get("source_artifacts")
    required = {
        "shadow_run_engine",
        "shadow_run_tests",
        "structured_log_schema",
        "fixture_pipeline",
        "benchmark_inventory",
        "perf_results",
    }
    paths: dict[str, str] = {}
    if not isinstance(artifacts, list):
        errors.append("source_artifacts must be an array")
        return paths
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("source_artifacts entries must be objects")
            continue
        artifact_id = artifact.get("artifact_id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            errors.append("source artifact missing artifact_id")
            continue
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{artifact_id}.path missing")
            continue
        paths[artifact_id] = path_text
        text = read_text(path_text, errors, artifact_id)
        for needle in strings(artifact.get("required_needles"), errors, f"{artifact_id}.required_needles"):
            if needle not in text:
                errors.append(f"{artifact_id} missing needle {needle!r}")
        rows.append(
            {
                "event": "conformance_logging_source",
                "status": "pass" if text else "fail",
                "artifact_id": artifact_id,
                "artifact_refs": [path_text],
                "timestamp": utc_now(),
            }
        )
    if seen != required:
        errors.append(f"source_artifacts must be exactly {sorted(required)}, got {sorted(seen)}")
    return paths


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    missing = set(strings(evidence.get("missing_items_closed"), errors, "completion_debt_evidence.missing_items_closed"))
    if missing != REQUIRED_ITEMS:
        errors.append(f"completion_debt_evidence.missing_items_closed must be {sorted(REQUIRED_ITEMS)}")

    unit = evidence.get("unit_primary")
    source_text = ""
    if not isinstance(unit, dict):
        errors.append("completion_debt_evidence.unit_primary must be an object")
    else:
        test_source = unit.get("test_source")
        if isinstance(test_source, str):
            source_text = read_text(test_source, errors, "unit_primary.test_source")
        else:
            errors.append("unit_primary.test_source missing")

    for section in ("unit_primary", "e2e_primary", "conformance_primary", "telemetry_primary"):
        item = evidence.get(section)
        if not isinstance(item, dict):
            errors.append(f"completion_debt_evidence.{section} must be an object")
            continue
        for name in strings(item.get("required_test_names"), errors, f"{section}.required_test_names"):
            if f"fn {name}(" not in source_text:
                errors.append(f"{section} references missing Rust test {name}")

    e2e = evidence.get("e2e_primary", {})
    if isinstance(e2e, dict):
        checker = e2e.get("checker")
        if not isinstance(checker, str) or not (root / checker).is_file():
            errors.append("e2e_primary.checker missing")
    conformance = evidence.get("conformance_primary", {})
    if isinstance(conformance, dict):
        for field in ("fixture_pipeline", "benchmark_inventory", "perf_results"):
            value = conformance.get(field)
            if not isinstance(value, str) or not (root / value).is_file():
                errors.append(f"conformance_primary.{field} missing")
    telemetry = evidence.get("telemetry_primary", {})
    if isinstance(telemetry, dict):
        for field in ("report_path", "log_path"):
            value = telemetry.get(field)
            if not isinstance(value, str) or not value:
                errors.append(f"telemetry_primary.{field} missing")


def validate_logging_expectations(
    contract: dict[str, Any],
    paths: dict[str, str],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    logging = contract.get("logging_expectations")
    if not isinstance(logging, dict):
        errors.append("logging_expectations must be an object")
        return
    engine = read_text(paths.get("shadow_run_engine", ""), errors, "shadow_run_engine")
    tests = read_text(paths.get("shadow_run_tests", ""), errors, "shadow_run_tests")
    structured = read_text(paths.get("structured_log_schema", ""), errors, "structured_log_schema")

    for field in strings(logging.get("required_shadow_report_fields"), errors, "logging_expectations.required_shadow_report_fields"):
        if field not in engine:
            errors.append(f"shadow_run_engine missing report field {field!r}")
    for artifact in strings(logging.get("required_shadow_artifacts"), errors, "logging_expectations.required_shadow_artifacts"):
        if artifact not in tests:
            errors.append(f"shadow_run_tests missing required artifact assertion {artifact!r}")
    for event in strings(logging.get("required_shadow_log_events"), errors, "logging_expectations.required_shadow_log_events"):
        if event not in engine and event not in tests:
            errors.append(f"shadow-run evidence missing log event {event!r}")
    for field in strings(logging.get("required_structured_log_fields"), errors, "logging_expectations.required_structured_log_fields"):
        if field not in structured:
            errors.append(f"structured_log_schema missing field {field!r}")
    for kind in strings(logging.get("required_stream_kinds"), errors, "logging_expectations.required_stream_kinds"):
        if kind not in structured:
            errors.append(f"structured_log_schema missing stream kind {kind!r}")

    rows.append(
        {
            "event": "conformance_logging_shadow",
            "status": "pass",
            "artifact_refs": [
                paths.get("shadow_run_engine", ""),
                paths.get("shadow_run_tests", ""),
                paths.get("structured_log_schema", ""),
            ],
            "required_shadow_artifacts": len(logging.get("required_shadow_artifacts", [])),
            "timestamp": utc_now(),
        }
    )


def validate_conformance_expectations(
    contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> None:
    expectations = contract.get("conformance_expectations")
    if not isinstance(expectations, dict):
        errors.append("conformance_expectations must be an object")
        return

    fixture_spec = expectations.get("fixture_pipeline")
    if not isinstance(fixture_spec, dict):
        errors.append("conformance_expectations.fixture_pipeline must be an object")
    else:
        path_text = fixture_spec.get("path")
        fixture = load_json(root / path_text, errors, "fixture_pipeline") if isinstance(path_text, str) else {}
        summary = fixture.get("summary", {}) if isinstance(fixture, dict) else {}
        checks = {
            "total_fixture_files": ("minimum_fixture_files", ">="),
            "total_fixture_cases": ("minimum_fixture_cases", ">="),
            "unique_symbols_in_fixtures": ("minimum_unique_symbols", ">="),
            "fixture_format_issues": ("maximum_fixture_format_issues", "<="),
        }
        for actual_key, (expected_key, op) in checks.items():
            actual = summary.get(actual_key)
            expected = fixture_spec.get(expected_key)
            if not isinstance(actual, (int, float)) or not isinstance(expected, (int, float)):
                errors.append(f"fixture_pipeline {actual_key}/{expected_key} must be numeric")
                continue
            if op == ">=" and actual < expected:
                errors.append(f"fixture_pipeline {actual_key} expected >= {expected}, actual={actual}")
            if op == "<=" and actual > expected:
                errors.append(f"fixture_pipeline {actual_key} expected <= {expected}, actual={actual}")
        rows.append(
            {
                "event": "conformance_logging_fixture",
                "status": "pass",
                "artifact_refs": [path_text],
                "fixture_cases": summary.get("total_fixture_cases"),
                "unique_symbols": summary.get("unique_symbols_in_fixtures"),
                "timestamp": utc_now(),
            }
        )

    inventory_spec = expectations.get("benchmark_inventory")
    if not isinstance(inventory_spec, dict):
        errors.append("conformance_expectations.benchmark_inventory must be an object")
    else:
        path_text = inventory_spec.get("path")
        inventory = load_json(root / path_text, errors, "benchmark_inventory") if isinstance(path_text, str) else {}
        summary = inventory.get("summary", {}) if isinstance(inventory, dict) else {}
        for actual_key, expected_key in [
            ("family_count", "minimum_family_count"),
            ("actual_bench_target_count", "minimum_bench_target_count"),
            ("inventory_row_count", "minimum_inventory_rows"),
        ]:
            actual = summary.get(actual_key)
            expected = inventory_spec.get(expected_key)
            if not isinstance(actual, (int, float)) or not isinstance(expected, (int, float)):
                errors.append(f"benchmark_inventory {actual_key}/{expected_key} must be numeric")
                continue
            if actual < expected:
                errors.append(f"benchmark_inventory {actual_key} expected >= {expected}, actual={actual}")
        modes = set(summary.get("strict_hardened_modes_required", []))
        required_modes = set(strings(inventory_spec.get("required_modes"), errors, "benchmark_inventory.required_modes"))
        if modes != required_modes:
            errors.append(f"benchmark_inventory modes expected={sorted(required_modes)} actual={sorted(modes)}")

    perf_spec = expectations.get("perf_results")
    if not isinstance(perf_spec, dict):
        errors.append("conformance_expectations.perf_results must be an object")
    else:
        path_text = perf_spec.get("path")
        perf = load_json(root / path_text, errors, "perf_results") if isinstance(path_text, str) else {}
        total = perf.get("total_packages")
        failed = perf.get("failed")
        min_packages = perf_spec.get("minimum_packages")
        max_failed = perf_spec.get("maximum_failed_packages")
        if not isinstance(total, int) or not isinstance(min_packages, int) or total < min_packages:
            errors.append(f"perf_results.total_packages expected >= {min_packages}, actual={total}")
        if not isinstance(failed, int) or not isinstance(max_failed, int) or failed > max_failed:
            errors.append(f"perf_results.failed expected <= {max_failed}, actual={failed}")
        required_latency = strings(perf_spec.get("required_latency_fields"), errors, "perf_results.required_latency_fields")
        packages = perf.get("packages")
        if not isinstance(packages, list) or not packages:
            errors.append("perf_results.packages must be non-empty")
        else:
            for index, package in enumerate(packages):
                if not isinstance(package, dict):
                    errors.append(f"perf_results.packages[{index}] must be an object")
                    continue
                latency = package.get("latency_profile")
                if not isinstance(latency, dict):
                    errors.append(f"perf_results.packages[{index}].latency_profile must be an object")
                    continue
                for field in required_latency:
                    if field not in latency:
                        errors.append(f"perf_results.packages[{index}].latency_profile missing {field}")
        rows.append(
            {
                "event": "conformance_logging_benchmark",
                "status": "pass",
                "artifact_refs": [
                    inventory_spec.get("path") if isinstance(inventory_spec, dict) else "",
                    path_text,
                ],
                "package_count": total,
                "failed_packages": failed,
                "timestamp": utc_now(),
            }
        )


def validate_e2e_gate(contract: dict[str, Any], errors: list[str]) -> None:
    gate = contract.get("e2e_gate")
    if not isinstance(gate, dict):
        errors.append("e2e_gate must be an object")
        return
    source = gate.get("source_test")
    if not isinstance(source, str) or not (root / source).is_file():
        errors.append("e2e_gate.source_test missing")
    for field in ("targeted_test_command", "completion_test_command"):
        command = gate.get(field)
        if not isinstance(command, str) or not command.startswith("rch exec -- cargo test "):
            errors.append(f"e2e_gate.{field} must use rch exec cargo test")
    checker = gate.get("checker_command")
    if checker != "bash scripts/check_conformance_logging_completion_contract.sh":
        errors.append("e2e_gate.checker_command drifted")


def validate_telemetry(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> None:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be an object")
        return
    events = set(strings(telemetry.get("required_events"), errors, "telemetry_contract.required_events"))
    if events != REQUIRED_EVENTS:
        errors.append(f"telemetry_contract.required_events must be {sorted(REQUIRED_EVENTS)}")
    fields = set(strings(telemetry.get("required_log_fields"), errors, "telemetry_contract.required_log_fields"))
    for field in ("event", "status", "timestamp", "artifact_refs"):
        if field not in fields:
            errors.append(f"telemetry_contract.required_log_fields missing {field}")
    observed = {row.get("event") for row in rows}
    missing = events - observed
    if missing:
        errors.append(f"telemetry rows missing required events {sorted(missing)}")


def main() -> int:
    errors: list[str] = []
    rows: list[dict[str, Any]] = []
    contract = load_json(contract_path, errors, "contract")

    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")

    paths = validate_source_artifacts(contract, errors, rows)
    validate_completion_evidence(contract, errors)
    validate_logging_expectations(contract, paths, errors, rows)
    validate_conformance_expectations(contract, errors, rows)
    validate_e2e_gate(contract, errors)
    rows.append(
        {
            "event": "conformance_logging_summary",
            "status": "pass" if not errors else "fail",
            "artifact_refs": [
                rel(contract_path),
                "crates/frankenlibc-harness/src/shadow_run.rs",
                "tests/conformance/fixture_pipeline.v1.json",
                "data/gentoo/perf-results/perf_benchmark_results.v1.json",
            ],
            "timestamp": utc_now(),
        }
    )
    validate_telemetry(contract, errors, rows)

    status = "pass" if not errors else "fail"
    report = {
        "status": status,
        "manifest_id": contract.get("manifest_id"),
        "bead": contract.get("bead"),
        "completion_debt_bead": contract.get("completion_debt_bead"),
        "event_count": len(rows),
        "source_count": len(contract.get("source_artifacts", [])),
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, rows)

    if errors:
        print("conformance_logging_completion_contract: FAILED")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(
        "conformance_logging_completion_contract: PASS "
        f"sources={report['source_count']} events={report['event_count']}"
    )
    return 0


raise SystemExit(main())
PY
