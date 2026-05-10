#!/usr/bin/env bash
# check_cve_hardened_assertions_completion_contract.sh - bd-1m5.6.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_CVE_HARDENED_COMPLETION_CONTRACT:-$ROOT/tests/cve_arena/results/hardened_assertions_completion_contract.v1.json}"
SOURCE_REPORT="${FRANKENLIBC_CVE_HARDENED_COMPLETION_SOURCE_REPORT:-$ROOT/tests/cve_arena/results/hardened_assertions.v1.json}"
CORPUS_REPORT="${FRANKENLIBC_CVE_HARDENED_COMPLETION_CORPUS_REPORT:-$ROOT/tests/cve_arena/results/corpus_normalization.v1.json}"
REPORT="${FRANKENLIBC_CVE_HARDENED_COMPLETION_REPORT:-$ROOT/target/conformance/hardened_assertions_completion_contract.report.json}"
LOG="${FRANKENLIBC_CVE_HARDENED_COMPLETION_LOG:-$ROOT/target/conformance/hardened_assertions_completion_contract.log.jsonl}"
REPLAY_REPORT="${FRANKENLIBC_CVE_HARDENED_COMPLETION_REPLAY:-$ROOT/target/conformance/hardened_assertions_completion_contract.replay.v1.json}"
SOURCE_LOG="${FRANKENLIBC_CVE_HARDENED_COMPLETION_SOURCE_LOG:-$ROOT/target/conformance/hardened_assertions_completion_contract.source.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$REPLAY_REPORT")" "$(dirname "$SOURCE_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
SOURCE_REPORT="$SOURCE_REPORT" \
CORPUS_REPORT="$CORPUS_REPORT" \
REPORT="$REPORT" \
LOG="$LOG" \
REPLAY_REPORT="$REPLAY_REPORT" \
SOURCE_LOG="$SOURCE_LOG" \
python3 - <<'PY'
from __future__ import annotations

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
SOURCE_REPORT = pathlib.Path(os.environ["SOURCE_REPORT"])
CORPUS_REPORT = pathlib.Path(os.environ["CORPUS_REPORT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
REPLAY_REPORT = pathlib.Path(os.environ["REPLAY_REPORT"])
SOURCE_LOG = pathlib.Path(os.environ["SOURCE_LOG"])

COMPLETION_BEAD = "bd-1m5.6.1"
ORIGINAL_BEAD = "bd-1m5.6"
CORPUS_BEAD = "bd-1m5.5"
EXPECTED_SCHEMA = "cve_hardened_assertions_completion_contract.v1"
EXPECTED_MANIFEST = "bd-1m5.6.1-cve-hardened-assertions-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
}
EXPECTED_PASS_EVENTS = {
    "cve_hardened_assertions_completion_contract_validated",
    "cve_hardened_assertions_generator_replayed",
    "cve_hardened_assertions_conformance_mapping_verified",
    "cve_hardened_assertions_completion_summary",
}
EXPECTED_EVENTS = EXPECTED_PASS_EVENTS | {
    "cve_hardened_assertions_completion_contract_failed",
}
REQUIRED_COMPLETION_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "stream",
    "gate",
    "scenario_id",
    "mode",
    "runtime_mode",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "decision_path",
    "healing_action",
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
        if source not in texts:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] unknown source: {source}")
            continue
        if not function_exists(texts[source], name):
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] missing function {name} in {source}")
        key = (source, name)
        if key in seen:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] duplicates {source}.{name}")
        seen.add(key)
        normalized.append({"source": source, "name": name})
    return normalized


def completion_row(
    event: str,
    *,
    outcome: str,
    gate: str,
    expected: Any,
    actual: Any,
    details: dict[str, Any] | None = None,
    failure_signature: str = "none",
) -> dict[str, Any]:
    if event not in EXPECTED_EVENTS:
        err(f"internal error: unexpected completion event {event}")
    return {
        "timestamp": now(),
        "trace_id": f"{COMPLETION_BEAD}::{event}",
        "level": "info" if outcome == "pass" else "error",
        "event": event,
        "bead_id": COMPLETION_BEAD,
        "stream": "conformance",
        "gate": gate,
        "scenario_id": COMPLETION_BEAD,
        "mode": "hardened",
        "runtime_mode": "hardened",
        "api_family": "cve_arena",
        "symbol": "cve_hardened_assertions",
        "oracle_kind": "cve_corpus_normalization",
        "expected": expected,
        "actual": actual,
        "decision_path": f"completion_debt::{gate}",
        "healing_action": "contract-validated",
        "outcome": outcome,
        "errno": 0,
        "latency_ns": 0,
        "source_commit": git_head(),
        "target_dir": rel(REPORT.parent),
        "failure_signature": failure_signature,
        "artifact_refs": [rel(CONTRACT), rel(SOURCE_REPORT), rel(CORPUS_REPORT), rel(REPORT)],
        "details": details or {},
    }


def validate_contract(contract: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema_version") != EXPECTED_SCHEMA:
        err(f"schema_version must be {EXPECTED_SCHEMA}")
    if contract.get("manifest_id") != EXPECTED_MANIFEST:
        err(f"manifest_id must be {EXPECTED_MANIFEST}")
    if contract.get("bead") != COMPLETION_BEAD:
        err(f"bead must be {COMPLETION_BEAD}")
    if contract.get("original_bead") != ORIGINAL_BEAD:
        err(f"original_bead must be {ORIGINAL_BEAD}")

    source_artifacts = contract.get("source_artifacts")
    if not isinstance(source_artifacts, dict) or not source_artifacts:
        err("source_artifacts must be a non-empty object")
    else:
        for key, path_text in source_artifacts.items():
            validate_repo_path(path_text, f"source_artifacts.{key}")

    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        return {}

    bindings = evidence.get("missing_item_bindings")
    seen_bindings: dict[str, str] = {}
    if not isinstance(bindings, list):
        err("missing_item_bindings must be an array")
    else:
        for index, binding in enumerate(bindings):
            if not isinstance(binding, dict):
                err(f"missing_item_bindings[{index}] must be an object")
                continue
            missing = binding.get("missing_item_id")
            section = binding.get("evidence_section")
            if not isinstance(missing, str) or not isinstance(section, str):
                err(f"missing_item_bindings[{index}] must include missing_item_id and evidence_section")
                continue
            seen_bindings[section] = missing
    if seen_bindings != EXPECTED_MISSING_ITEMS:
        err(f"missing_item_bindings mismatch: expected {EXPECTED_MISSING_ITEMS}, got {seen_bindings}")

    refs = evidence.get("implementation_refs")
    if not isinstance(refs, list) or not refs:
        err("implementation_refs must be a non-empty array")
    else:
        for index, ref in enumerate(refs):
            validate_file_line_ref(ref, f"implementation_refs[{index}]")

    texts = source_texts(evidence.get("test_sources"))
    for section, missing_item_id in EXPECTED_MISSING_ITEMS.items():
        section_value = evidence.get(section)
        if not isinstance(section_value, dict):
            err(f"completion_debt_evidence.{section} must be an object")
            continue
        if section_value.get("missing_item_id") != missing_item_id:
            err(f"completion_debt_evidence.{section}.missing_item_id must be {missing_item_id}")
        validate_test_refs(section_value, section, texts)
        commands = as_string_list(section_value.get("required_commands"), f"completion_debt_evidence.{section}.required_commands")
        if not any("rch exec" in command for command in commands):
            err(f"completion_debt_evidence.{section}.required_commands must include an rch cargo command")

    source_contract = evidence.get("required_hardened_assertion_contract")
    if not isinstance(source_contract, dict):
        err("required_hardened_assertion_contract must be an object")
        return evidence
    expected_events = set(as_string_list(source_contract.get("required_completion_log_events"), "required_completion_log_events"))
    if expected_events != EXPECTED_PASS_EVENTS:
        err(f"required_completion_log_events mismatch: expected {sorted(EXPECTED_PASS_EVENTS)}, got {sorted(expected_events)}")
    forbidden_events = set(as_string_list(source_contract.get("forbidden_completion_log_events"), "forbidden_completion_log_events"))
    if "cve_hardened_assertions_completion_contract_failed" not in forbidden_events:
        err("forbidden_completion_log_events must include cve_hardened_assertions_completion_contract_failed")
    return evidence


def validate_hardened_report(report: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    source_contract = contract["completion_debt_evidence"]["required_hardened_assertion_contract"]
    if report.get("schema_version") != source_contract.get("source_report_schema_version"):
        err("hardened report schema_version mismatch")
    if report.get("bead") != ORIGINAL_BEAD:
        err(f"hardened report bead must be {ORIGINAL_BEAD}")

    summary = report.get("summary")
    assertions = report.get("assertion_matrix")
    healing_map = report.get("healing_expectation_map")
    regression = report.get("regression_detection")
    if not isinstance(summary, dict):
        err("hardened report summary must be an object")
        summary = {}
    if not isinstance(assertions, list):
        err("hardened report assertion_matrix must be an array")
        assertions = []
    if not isinstance(healing_map, dict):
        err("hardened report healing_expectation_map must be an object")
        healing_map = {}
    if not isinstance(regression, dict):
        err("hardened report regression_detection must be an object")
        regression = {}

    minimum_total = int(source_contract.get("minimum_total_assertions", 0))
    total = len(assertions)
    if total < minimum_total:
        err(f"hardened report assertion_matrix has {total} rows, expected at least {minimum_total}")
    if summary.get("total_assertions") != total:
        err("summary.total_assertions must equal assertion_matrix length")
    if summary.get("no_crash_in_hardened") != total:
        err("summary.no_crash_in_hardened must equal total assertions")
    if summary.get("with_healing_actions") != total:
        err("summary.with_healing_actions must equal total assertions")
    if summary.get("validation_errors") != 0:
        err("summary.validation_errors must be zero")
    if regression.get("status") != "clean":
        err("regression_detection.status must be clean")
    if regression.get("all_no_crash") is not True:
        err("regression_detection.all_no_crash must be true")
    if regression.get("all_with_healing_actions") is not True:
        err("regression_detection.all_with_healing_actions must be true")

    required_strategies = set(as_string_list(source_contract.get("required_prevention_strategies"), "required_prevention_strategies"))
    strategies = summary.get("prevention_strategies")
    if not isinstance(strategies, dict):
        err("summary.prevention_strategies must be an object")
        strategies = {}
    missing_strategies = sorted(required_strategies - set(strategies))
    if missing_strategies:
        err(f"summary.prevention_strategies missing required strategies: {missing_strategies}")

    required_actions = set(as_string_list(source_contract.get("required_healing_actions"), "required_healing_actions"))
    summary_actions = set(as_string_list(summary.get("unique_healing_actions"), "summary.unique_healing_actions"))
    if len(summary_actions) < int(source_contract.get("minimum_unique_healing_actions", 0)):
        err("summary.unique_healing_actions below minimum")
    if not required_actions.issubset(summary_actions):
        err(f"summary.unique_healing_actions missing {sorted(required_actions - summary_actions)}")
    if not required_actions.issubset(set(healing_map)):
        err(f"healing_expectation_map missing {sorted(required_actions - set(healing_map))}")

    required_assertion_fields = set(as_string_list(source_contract.get("required_assertion_fields"), "required_assertion_fields"))
    required_expectation_fields = set(as_string_list(source_contract.get("required_hardened_expectation_fields"), "required_hardened_expectation_fields"))
    required_regression_fields = set(as_string_list(source_contract.get("required_regression_fields"), "required_regression_fields"))
    seen_ids: set[str] = set()
    for index, assertion in enumerate(assertions):
        if not isinstance(assertion, dict):
            err(f"assertion_matrix[{index}] must be an object")
            continue
        missing_fields = required_assertion_fields - set(assertion)
        if missing_fields:
            err(f"assertion_matrix[{index}] missing fields: {sorted(missing_fields)}")
        cve_id = assertion.get("cve_id")
        if not isinstance(cve_id, str) or not cve_id:
            err(f"assertion_matrix[{index}].cve_id must be non-empty")
        elif cve_id in seen_ids:
            err(f"assertion_matrix contains duplicate cve_id: {cve_id}")
        else:
            seen_ids.add(cve_id)
        expectations = assertion.get("hardened_expectations")
        if not isinstance(expectations, dict):
            err(f"assertion_matrix[{index}].hardened_expectations must be an object")
            expectations = {}
        if required_expectation_fields - set(expectations):
            err(f"assertion_matrix[{index}].hardened_expectations missing fields: {sorted(required_expectation_fields - set(expectations))}")
        if expectations.get("crashes") is not False:
            err(f"assertion_matrix[{index}] must not crash in hardened mode")
        if expectations.get("no_uncontrolled_unsafety") is not True:
            err(f"assertion_matrix[{index}] must set no_uncontrolled_unsafety=true")
        healing = expectations.get("healing_actions_required")
        if not isinstance(healing, list) or not healing:
            err(f"assertion_matrix[{index}] must require at least one healing action")
        regression_checks = assertion.get("regression_checks")
        if not isinstance(regression_checks, dict):
            err(f"assertion_matrix[{index}].regression_checks must be an object")
            regression_checks = {}
        if required_regression_fields - set(regression_checks):
            err(f"assertion_matrix[{index}].regression_checks missing fields: {sorted(required_regression_fields - set(regression_checks))}")
        if regression_checks.get("no_crash") is not True:
            err(f"assertion_matrix[{index}].regression_checks.no_crash must be true")
        if sorted(regression_checks.get("healing_actions_list", [])) != sorted(healing or []):
            err(f"assertion_matrix[{index}] regression healing list must match hardened expectations")
        if not isinstance(assertion.get("cwe_prevention"), list) or not assertion.get("cwe_prevention"):
            err(f"assertion_matrix[{index}].cwe_prevention must be non-empty")

    return {
        "total_assertions": total,
        "strategies": sorted(strategies),
        "healing_actions": sorted(summary_actions),
        "assertion_digest": regression.get("assertion_digest"),
    }


def validate_corpus_mapping(source_report: dict[str, Any], replay_report: dict[str, Any], corpus_report: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    if corpus_report.get("bead") != CORPUS_BEAD:
        err(f"corpus report bead must be {CORPUS_BEAD}")
    source_contract = contract["completion_debt_evidence"]["required_hardened_assertion_contract"]
    required_replay_fields = set(as_string_list(source_contract.get("required_corpus_replay_fields"), "required_corpus_replay_fields"))

    source_digest = source_report.get("regression_detection", {}).get("assertion_digest")
    replay_digest = replay_report.get("regression_detection", {}).get("assertion_digest")
    if not isinstance(source_digest, str) or len(source_digest) != 64:
        err("source assertion_digest must be a sha256 hex string")
    if source_digest != replay_digest:
        err("replayed assertion digest must match source hardened assertion digest")

    corpus_entries = corpus_report.get("corpus_index")
    if not isinstance(corpus_entries, list) or not corpus_entries:
        err("corpus_report.corpus_index must be a non-empty array")
        corpus_entries = []
    by_cve: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(corpus_entries):
        if not isinstance(entry, dict):
            err(f"corpus_index[{index}] must be an object")
            continue
        cve_id = entry.get("cve_id")
        if isinstance(cve_id, str):
            by_cve[cve_id] = entry
        if entry.get("manifest_valid") is not True:
            err(f"corpus_index[{index}] must have manifest_valid=true")

    assertions = source_report.get("assertion_matrix", [])
    mapped = 0
    for index, assertion in enumerate(assertions):
        cve_id = assertion.get("cve_id") if isinstance(assertion, dict) else None
        if not isinstance(cve_id, str):
            continue
        entry = by_cve.get(cve_id)
        if entry is None:
            err(f"assertion_matrix[{index}] cve_id {cve_id} missing from corpus normalization report")
            continue
        mapped += 1
        replay = entry.get("replay")
        if not isinstance(replay, dict):
            err(f"corpus entry {cve_id} replay must be an object")
            replay = {}
        missing_replay = required_replay_fields - set(replay)
        if missing_replay:
            err(f"corpus entry {cve_id} replay missing fields: {sorted(missing_replay)}")
        expected_hardened = replay.get("expected_hardened")
        expected_strict = replay.get("expected_strict")
        if not isinstance(expected_hardened, dict):
            err(f"corpus entry {cve_id} expected_hardened must be an object")
            expected_hardened = {}
        if not isinstance(expected_strict, dict):
            err(f"corpus entry {cve_id} expected_strict must be an object")
        hardened = assertion.get("hardened_expectations", {})
        if expected_hardened.get("crashes") is not False:
            err(f"corpus entry {cve_id} expected_hardened.crashes must be false")
        if hardened.get("crashes") != expected_hardened.get("crashes"):
            err(f"assertion {cve_id} crash expectation must match corpus expected_hardened")
        if hardened.get("exit_code") != expected_hardened.get("exit_code"):
            err(f"assertion {cve_id} exit_code must match corpus expected_hardened")
        if sorted(hardened.get("healing_actions_required", [])) != sorted(expected_hardened.get("healing_actions", [])):
            err(f"assertion {cve_id} healing actions must match corpus expected_hardened")

    if mapped != len(assertions):
        err(f"mapped {mapped}/{len(assertions)} hardened assertions to corpus normalization entries")
    return {
        "mapped_assertions": mapped,
        "corpus_entries": len(corpus_entries),
    }


def replay_generator() -> tuple[dict[str, Any], list[dict[str, Any]], int]:
    command = [
        "python3",
        "scripts/generate_cve_hardened_assertions.py",
        "-o",
        str(REPLAY_REPORT),
        "--timestamp",
        "2026-05-10T14:33:00Z",
        "--log",
        str(SOURCE_LOG),
    ]
    started = time.monotonic_ns()
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    elapsed = time.monotonic_ns() - started
    if result.returncode != 0:
        err(f"hardened assertions generator replay failed with exit {result.returncode}: {result.stderr.strip()}")
        return {}, [], elapsed
    replay_report = load_json(REPLAY_REPORT, "replayed hardened assertions report")
    source_log_rows: list[dict[str, Any]] = []
    try:
        source_log_rows = [
            json.loads(line)
            for line in SOURCE_LOG.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except Exception as exc:
        err(f"source generator JSONL log is invalid: {rel(SOURCE_LOG)}: {exc}")
    return replay_report, source_log_rows, elapsed


def validate_source_log(rows: list[dict[str, Any]], contract: dict[str, Any], expected_total: int) -> dict[str, Any]:
    source_contract = contract["completion_debt_evidence"]["required_hardened_assertion_contract"]
    required_fields = set(as_string_list(source_contract.get("required_source_log_fields"), "required_source_log_fields"))
    assertion_rows = [row for row in rows if row.get("event") == "cve_hardened_assertion"]
    summary_rows = [row for row in rows if row.get("event") == "cve_hardened_assertion_summary"]
    if len(assertion_rows) != expected_total:
        err(f"source log must contain {expected_total} assertion rows, got {len(assertion_rows)}")
    if len(summary_rows) != 1:
        err(f"source log must contain exactly one summary row, got {len(summary_rows)}")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            err(f"source log row {index + 1} must be an object")
            continue
        missing = required_fields - set(row)
        if missing:
            err(f"source log row {index + 1} missing fields: {sorted(missing)}")
        if row.get("bead_id") != ORIGINAL_BEAD:
            err(f"source log row {index + 1} bead_id must be {ORIGINAL_BEAD}")
        if row.get("mode") != "hardened":
            err(f"source log row {index + 1} mode must be hardened")
        refs = row.get("artifact_refs")
        if not isinstance(refs, list) or not refs:
            err(f"source log row {index + 1} artifact_refs must be non-empty")
    return {
        "source_log_rows": len(rows),
        "source_assertion_rows": len(assertion_rows),
        "source_summary_rows": len(summary_rows),
    }


contract = load_json(CONTRACT, "completion contract")
source_report = load_json(SOURCE_REPORT, "source hardened assertions report")
corpus_report = load_json(CORPUS_REPORT, "corpus normalization report")
evidence = validate_contract(contract)
source_summary = validate_hardened_report(source_report, contract) if contract else {}
replay_report, source_log_rows, replay_latency_ns = replay_generator()
replay_summary = validate_hardened_report(replay_report, contract) if replay_report and contract else {}
mapping_summary = validate_corpus_mapping(source_report, replay_report, corpus_report, contract) if contract and replay_report else {}
source_log_summary = validate_source_log(source_log_rows, contract, int(source_summary.get("total_assertions", 0))) if contract else {}

rows = [
    completion_row(
        "cve_hardened_assertions_completion_contract_validated",
        outcome="pass",
        gate="completion_contract",
        expected={"missing_items": sorted(EXPECTED_MISSING_ITEMS.values())},
        actual={
            "bindings": sorted(evidence.get("missing_item_bindings", []), key=lambda value: str(value)),
            "implementation_refs": len(evidence.get("implementation_refs", [])),
        },
        details={"schema_version": contract.get("schema_version")},
    ),
    completion_row(
        "cve_hardened_assertions_generator_replayed",
        outcome="pass",
        gate="generator_replay",
        expected={"assertion_digest": source_summary.get("assertion_digest")},
        actual={"assertion_digest": replay_summary.get("assertion_digest")},
        details={**replay_summary, **source_log_summary},
    ),
    completion_row(
        "cve_hardened_assertions_conformance_mapping_verified",
        outcome="pass",
        gate="corpus_conformance_mapping",
        expected={"source_corpus_bead": CORPUS_BEAD},
        actual=mapping_summary,
        details={"corpus_report": rel(CORPUS_REPORT)},
    ),
    completion_row(
        "cve_hardened_assertions_completion_summary",
        outcome="pass",
        gate="completion_summary",
        expected={"status": "clean"},
        actual={
            "errors": len(errors),
            "total_assertions": source_summary.get("total_assertions"),
            "mapped_assertions": mapping_summary.get("mapped_assertions"),
        },
        details={"source_report": rel(SOURCE_REPORT), "replay_latency_ns": replay_latency_ns},
    ),
]

if errors:
    failure_rows = [
        completion_row(
            "cve_hardened_assertions_completion_contract_failed",
            outcome="fail",
            gate="completion_summary",
            expected={"errors": 0},
            actual={"errors": errors},
            details={"errors": errors},
            failure_signature="cve_hardened_completion_contract_failed",
        )
    ]
    write_json(
        REPORT,
        {
            "status": "fail",
            "bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "errors": errors,
            "source_summary": source_summary,
            "replay_summary": replay_summary,
            "mapping_summary": mapping_summary,
            "source_log_summary": source_log_summary,
        },
    )
    write_jsonl(LOG, failure_rows)
    for message in errors:
        print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)

for row in rows:
    missing = REQUIRED_COMPLETION_LOG_FIELDS - set(row)
    if missing:
        print(f"FAIL: internal completion row missing fields {sorted(missing)}", file=sys.stderr)
        sys.exit(1)

write_json(
    REPORT,
    {
        "status": "pass",
        "bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_report": rel(SOURCE_REPORT),
        "corpus_report": rel(CORPUS_REPORT),
        "replay_report": rel(REPLAY_REPORT),
        "source_log": rel(SOURCE_LOG),
        "source_summary": source_summary,
        "replay_summary": replay_summary,
        "mapping_summary": mapping_summary,
        "source_log_summary": source_log_summary,
        "events": [row["event"] for row in rows],
    },
)
write_jsonl(LOG, rows)

print(
    "check_cve_hardened_assertions_completion_contract: PASS "
    f"assertions={source_summary.get('total_assertions')} "
    f"mapped={mapping_summary.get('mapped_assertions')} "
    f"healing_actions={len(source_summary.get('healing_actions', []))}"
)
PY
