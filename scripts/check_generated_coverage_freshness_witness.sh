#!/usr/bin/env bash
# check_generated_coverage_freshness_witness.sh -- bd-j1u6u.3 freshness gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WITNESS="${FRANKENLIBC_GENERATED_COVERAGE_FRESHNESS_WITNESS:-${ROOT}/tests/conformance/generated_coverage_freshness_witness.v1.json}"
OUT_DIR="${FRANKENLIBC_GENERATED_COVERAGE_FRESHNESS_OUT_DIR:-${ROOT}/target/conformance/generated_coverage_freshness}"
REPORT="${FRANKENLIBC_GENERATED_COVERAGE_FRESHNESS_REPORT:-${OUT_DIR}/generated_coverage_freshness_witness.report.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")"

python3 - "${ROOT}" "${WITNESS}" "${REPORT}" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
WITNESS = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])

SCHEMA = "generated_coverage_freshness_witness.v1"
REPORT_SCHEMA = "generated_coverage_freshness_witness.report.v1"
BEAD_ID = "bd-j1u6u.3"
TRACE_ID = "bd-j1u6u.3::generated-coverage-freshness::v1"
REQUIRED_GENERATOR_COMMANDS = {
    "python3 scripts/generate_symbol_fixture_coverage.py --output tests/conformance/symbol_fixture_coverage.v1.json",
    "python3 scripts/generate_per_symbol_fixture_tests.py --output tests/conformance/per_symbol_fixture_tests.v1.json",
    "python3 scripts/generate_fixture_coverage_prioritizer.py --output tests/conformance/fixture_coverage_prioritizer.v1.json",
}
FAILURE_PRIORITY = [
    "malformed_witness",
    "source_hash_drift",
    "fixture_corpus_drift",
    "symbol_count_drift",
    "prioritizer_count_drift",
    "executor_dispatch_drift",
    "missing_generator_command",
]

errors: list[dict[str, str]] = []


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {row["failure_signature"] for row in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "generated_coverage_freshness_failed"


def rel(path: pathlib.Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def resolve(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else ROOT / path


def load_json(path: pathlib.Path, signature: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"cannot parse {rel(path)}: {exc}")
        return {}


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def as_object(value: Any, context: str, signature: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def as_array(value: Any, context: str, signature: str) -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def number_equals(actual: Any, expected: Any, context: str, signature: str) -> None:
    if actual != expected:
        add_error(signature, f"{context}: expected {expected!r}, got {actual!r}")


def sorted_fixture_paths(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(path for path in root.glob("*.json") if path.is_file())


def fixture_corpus_digest(paths: list[pathlib.Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        line = f"{sha256_file(path)}  {rel(path)}\n".encode("utf-8")
        digest.update(line)
    return digest.hexdigest()


def validate_source_hashes(witness: dict[str, Any]) -> None:
    seen: set[str] = set()
    for row in as_array(witness.get("source_files"), "source_files", "malformed_witness"):
        obj = as_object(row, "source_files[]", "malformed_witness")
        source_id = obj.get("id")
        path_text = obj.get("path")
        expected = obj.get("sha256")
        if not isinstance(source_id, str) or not isinstance(path_text, str) or not isinstance(expected, str):
            add_error("malformed_witness", "source_files entries need id, path, and sha256 strings")
            continue
        seen.add(source_id)
        path = resolve(path_text)
        if not path.exists():
            add_error("source_hash_drift", f"missing source file {path_text}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            add_error("source_hash_drift", f"{path_text} sha256 expected {expected}, got {actual}")
    missing = {"symbol_fixture_coverage", "per_symbol_fixture_tests", "fixture_coverage_prioritizer", "executor_dispatch"} - seen
    if missing:
        add_error("malformed_witness", f"missing source file ids: {sorted(missing)}")


def validate_fixture_corpus(witness: dict[str, Any]) -> dict[str, Any]:
    expected = as_object(witness.get("fixture_corpus"), "fixture_corpus", "malformed_witness")
    root_text = expected.get("root")
    if not isinstance(root_text, str):
        add_error("malformed_witness", "fixture_corpus.root must be a string")
        return {}
    paths = sorted_fixture_paths(resolve(root_text))
    fixtures = [load_json(path, "fixture_corpus_drift") for path in paths]
    total_cases = sum(len(obj.get("cases") or []) for obj in fixtures if isinstance(obj, dict))
    functions = {
        case.get("function")
        for obj in fixtures
        if isinstance(obj, dict)
        for case in (obj.get("cases") or [])
        if isinstance(case, dict) and isinstance(case.get("function"), str)
    }
    actual = {
        "json_file_count": len(paths),
        "total_case_count": total_cases,
        "unique_function_count": len(functions),
        "corpus_sha256": fixture_corpus_digest(paths),
    }
    for key, value in actual.items():
        number_equals(value, expected.get(key), f"fixture_corpus.{key}", "fixture_corpus_drift")
    return actual


def validate_counts(witness: dict[str, Any]) -> dict[str, Any]:
    symbol = as_object(load_json(ROOT / "tests/conformance/symbol_fixture_coverage.v1.json", "symbol_count_drift").get("summary"), "symbol summary", "symbol_count_drift")
    per_symbol = as_object(load_json(ROOT / "tests/conformance/per_symbol_fixture_tests.v1.json", "symbol_count_drift").get("summary"), "per-symbol summary", "symbol_count_drift")
    prioritizer = as_object(load_json(ROOT / "tests/conformance/fixture_coverage_prioritizer.v1.json", "prioritizer_count_drift").get("summary"), "prioritizer summary", "prioritizer_count_drift")
    expected_symbols = as_object(witness.get("symbol_counts"), "symbol_counts", "malformed_witness")
    symbol_actual = {
        "target_total_symbols": symbol.get("target_total_symbols"),
        "target_covered_symbols": symbol.get("target_covered_symbols"),
        "target_uncovered_symbols": symbol.get("target_uncovered_symbols"),
        "target_coverage_pct": symbol.get("target_coverage_pct"),
        "symbols_with_fixtures": per_symbol.get("symbols_with_fixtures"),
        "symbols_without_fixtures": per_symbol.get("symbols_without_fixtures"),
        "total_cases": per_symbol.get("total_cases"),
        "uncovered_action_count": per_symbol.get("uncovered_action_count"),
        "total_format_issues": per_symbol.get("total_format_issues"),
    }
    for key, value in symbol_actual.items():
        number_equals(value, expected_symbols.get(key), f"symbol_counts.{key}", "symbol_count_drift")
    expected_prioritizer = as_object(witness.get("prioritizer_counts"), "prioritizer_counts", "malformed_witness")
    for key in [
        "campaign_count",
        "selected_target_uncovered_symbols",
        "all_uncovered_target_symbols",
        "total_first_wave_fixture_count",
    ]:
        number_equals(prioritizer.get(key), expected_prioritizer.get(key), f"prioritizer_counts.{key}", "prioritizer_count_drift")
    return symbol_actual


def validate_executor_dispatch(witness: dict[str, Any]) -> None:
    expected = as_object(witness.get("executor_dispatch"), "executor_dispatch", "malformed_witness")
    path_text = expected.get("path")
    if not isinstance(path_text, str):
        add_error("malformed_witness", "executor_dispatch.path must be a string")
        return
    text = resolve(path_text).read_text(encoding="utf-8")
    actual = text.count("execute_fixture_case")
    number_equals(actual, expected.get("execute_fixture_case_mentions"), "executor_dispatch.execute_fixture_case_mentions", "executor_dispatch_drift")


def validate_generator_commands(witness: dict[str, Any]) -> None:
    commands = set()
    for row in as_array(witness.get("generator_command_lines"), "generator_command_lines", "malformed_witness"):
        if isinstance(row, str):
            commands.add(row)
        else:
            add_error("malformed_witness", "generator_command_lines must contain only strings")
    missing = sorted(REQUIRED_GENERATOR_COMMANDS - commands)
    if missing:
        add_error("missing_generator_command", f"missing generator commands: {missing}")


witness = as_object(load_json(WITNESS, "malformed_witness"), "witness", "malformed_witness")
if witness.get("schema_version") != SCHEMA:
    add_error("malformed_witness", f"schema_version must be {SCHEMA}")
if witness.get("bead_id") != BEAD_ID:
    add_error("malformed_witness", f"bead_id must be {BEAD_ID}")
if witness.get("trace_id") != TRACE_ID:
    add_error("malformed_witness", f"trace_id must be {TRACE_ID}")

validate_source_hashes(witness)
fixture_actual = validate_fixture_corpus(witness)
symbol_actual = validate_counts(witness)
validate_executor_dispatch(witness)
validate_generator_commands(witness)

status = "pass" if not errors else "fail"
report = {
    "schema_version": REPORT_SCHEMA,
    "trace_id": TRACE_ID,
    "bead_id": BEAD_ID,
    "status": status,
    "failure_signature": "none" if status == "pass" else primary_signature(),
    "errors": errors,
    "summary": {
        "fixture_file_count": fixture_actual.get("json_file_count"),
        "fixture_case_count": fixture_actual.get("total_case_count"),
        "unique_function_count": fixture_actual.get("unique_function_count"),
        "target_covered_symbols": symbol_actual.get("target_covered_symbols"),
        "target_uncovered_symbols": symbol_actual.get("target_uncovered_symbols"),
    },
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if status == "pass":
    print(f"PASS generated coverage freshness witness ({REPORT})")
    sys.exit(0)

print(f"FAIL generated coverage freshness witness: {report['failure_signature']} ({REPORT})", file=sys.stderr)
for error in errors:
    print(f"{error['failure_signature']}: {error['message']}", file=sys.stderr)
sys.exit(1)
PY
