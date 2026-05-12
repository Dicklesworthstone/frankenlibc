#!/usr/bin/env bash
# check_regex_glob_free_completion_contract.sh - bd-qerp.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_REGEX_GLOB_FREE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/regex_glob_free_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_REGEX_GLOB_FREE_COMPLETION_OUT_DIR:-$ROOT/target/conformance/regex_glob_free_completion_contract}"
REPORT="${FRANKENLIBC_REGEX_GLOB_FREE_COMPLETION_REPORT:-$OUT_DIR/report.json}"
LOG="${FRANKENLIBC_REGEX_GLOB_FREE_COMPLETION_LOG:-$OUT_DIR/events.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "regex_glob_free_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "regex_glob_free_completion_contract.report.v1"
EXPECTED_BEAD = "bd-qerp.1"
EXPECTED_ORIGINAL_BEAD = "bd-qerp"
EXPECTED_TRACE_ID = "bd-qerp.1::regex-glob-free::completion::v1"
EXPECTED_MISSING_ITEMS = {"tests.conformance.primary"}
REQUIRED_SOURCE_ARTIFACTS = {
    "conformance_executor",
    "regex_glob_fixture",
    "regex_glob_harness_test",
    "completion_checker",
    "completion_harness",
}
PASS_EVENTS = [
    "regex_glob_free.sources_validated",
    "regex_glob_free.implementation_markers_validated",
    "regex_glob_free.fixture_surface_validated",
    "regex_glob_free.bindings_validated",
    "regex_glob_free.completion_contract_pass",
]
FAIL_EVENT = "regex_glob_free.completion_contract_fail"

errors: list[str] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


SOURCE_COMMIT = git_head()


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def emit(event: str, outcome: str = "pass", **details: Any) -> None:
    timestamp = now()
    events.append(
        {
            "timestamp": timestamp,
            "ts": timestamp,
            "trace_id": EXPECTED_TRACE_ID,
            "level": "info" if outcome == "pass" else "error",
            "event": event,
            "bead_id": EXPECTED_BEAD,
            "stream": "conformance",
            "gate": "regex_glob_free_completion_contract",
            "scenario_id": event,
            "mode": "strict",
            "api_family": "string",
            "symbol": "regex_glob_free",
            "oracle_kind": "completion_contract",
            "expected": "pass",
            "actual": outcome,
            "decision_path": "fixture_executor->regcomp/regexec/glob->frankenlibc_regfree/globfree",
            "outcome": outcome,
            "errno": 0,
            "latency_ns": 0,
            "source_commit": SOURCE_COMMIT,
            "failure_signature": "" if outcome == "pass" else "; ".join(errors[:3]),
            "artifact_refs": [rel(CONTRACT)],
            "details": details,
        }
    )


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


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


def as_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        err(f"{label} must be an object")
        return {}
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        err(f"{label} must be an array")
        return []
    return value


def repo_path(path_text: Any, label: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{label} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{label} must stay repo-relative: {path_text}")
        return None
    full = ROOT / path
    if not full.exists():
        err(f"{label} references missing path: {path_text}")
        return None
    return full


def read_artifact(artifacts: dict[str, Any], key: str) -> str:
    path = repo_path(artifacts.get(key), f"source_artifacts.{key}")
    if path is None or not path.is_file():
        err(f"source_artifacts.{key} must reference a file")
        return ""
    return path.read_text(encoding="utf-8")


def function_body(text: str, name: str, next_name: str | None = None) -> str:
    start = text.find(f"fn {name}")
    if start < 0:
        err(f"missing function body: {name}")
        return ""
    if next_name is None:
        return text[start:]
    end = text.find(f"fn {next_name}", start + 1)
    return text[start:] if end < 0 else text[start:end]


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        err("contract_identity: schema_version mismatch")
    if manifest.get("bead_id") != EXPECTED_BEAD:
        err("contract_identity: bead_id mismatch")
    if manifest.get("original_bead") != EXPECTED_ORIGINAL_BEAD:
        err("contract_identity: original_bead mismatch")
    if manifest.get("trace_id") != EXPECTED_TRACE_ID:
        err("contract_identity: trace_id mismatch")

    artifacts = as_object(manifest.get("source_artifacts"), "source_artifacts")
    keys = set(artifacts)
    if keys != REQUIRED_SOURCE_ARTIFACTS:
        err(f"source_artifacts mismatch: expected={sorted(REQUIRED_SOURCE_ARTIFACTS)} got={sorted(keys)}")
    for key, path_text in artifacts.items():
        repo_path(path_text, f"source_artifacts.{key}")

    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    missing_items = {
        item
        for item in as_list(contract.get("missing_item_ids"), "completion_contract.missing_item_ids")
        if isinstance(item, str)
    }
    if missing_items != EXPECTED_MISSING_ITEMS:
        err(f"missing_item_ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing_items)}")

    emit("regex_glob_free.sources_validated", source_artifact_count=len(keys))
    return artifacts


def validate_implementation_markers(manifest: dict[str, Any], artifacts: dict[str, Any]) -> int:
    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    marker_groups = as_object(contract.get("implementation_markers"), "completion_contract.implementation_markers")
    marker_count = 0
    for key in ["conformance_executor", "regex_glob_fixture", "regex_glob_harness_test"]:
        text = read_artifact(artifacts, key)
        for marker in as_list(marker_groups.get(key), f"implementation_markers.{key}"):
            if not isinstance(marker, str) or not marker:
                err(f"implementation_markers.{key} must contain non-empty strings")
                continue
            marker_count += 1
            if marker not in text:
                err(f"missing implementation marker in {key}: {marker}")

    executor = read_artifact(artifacts, "conformance_executor")
    regcomp_body = function_body(executor, "execute_regcomp_case", "execute_regexec_case")
    regexec_body = function_body(executor, "execute_regexec_case", "execute_fnmatch_case")
    glob_body = function_body(executor, "execute_glob_case", "collect_wordexp_words")
    for name, body in [("execute_regcomp_case", regcomp_body), ("execute_regexec_case", regexec_body)]:
        if "frankenlibc_abi::string_abi::regfree" not in body:
            err(f"{name} must release regex_t with frankenlibc regfree")
        if "libc::regfree" in body:
            err(f"{name} must not call host libc::regfree")
    if "frankenlibc_abi::string_abi::globfree" not in glob_body:
        err("execute_glob_case must release glob_t with frankenlibc globfree")
    if "libc::globfree" in glob_body:
        err("execute_glob_case must not call host libc::globfree")

    emit("regex_glob_free.implementation_markers_validated", marker_count=marker_count)
    return marker_count


def validate_fixture_surface(manifest: dict[str, Any], artifacts: dict[str, Any]) -> tuple[int, int, int]:
    fixture_path = repo_path(artifacts.get("regex_glob_fixture"), "source_artifacts.regex_glob_fixture")
    fixture = load_json(fixture_path, "regex_glob_fixture") if fixture_path is not None else {}
    cases = as_list(fixture.get("cases"), "regex_glob_fixture.cases")
    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    test_contract = as_object(contract.get("test_contract"), "completion_contract.test_contract")

    minimum_case_count = test_contract.get("minimum_fixture_case_count")
    if not isinstance(minimum_case_count, int) or len(cases) < minimum_case_count:
        err(f"regex_glob_ops fixture case count below contract: expected >= {minimum_case_count}, got {len(cases)}")

    functions = {case.get("function") for case in cases if isinstance(case, dict)}
    modes = {case.get("mode") for case in cases if isinstance(case, dict)}
    for function in as_list(test_contract.get("required_functions"), "test_contract.required_functions"):
        if function not in functions:
            err(f"regex_glob_ops fixture missing function coverage: {function}")
    for mode in as_list(test_contract.get("required_modes"), "test_contract.required_modes"):
        if mode not in modes:
            err(f"regex_glob_ops fixture missing mode coverage: {mode}")
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            err(f"regex_glob_ops case {index} must be an object")
            continue
        if "expected_output" not in case:
            err(f"regex_glob_ops case {case.get('name', index)!r} must define expected_output")

    commands = {
        item
        for item in as_list(test_contract.get("required_remote_commands"), "test_contract.required_remote_commands")
        if isinstance(item, str)
    }
    required_commands = [
        "cargo test -p frankenlibc-harness --test regex_glob_free_completion_contract_test -- --nocapture",
        "cargo clippy -p frankenlibc-harness --test regex_glob_free_completion_contract_test -- -D warnings",
        "cargo test -p frankenlibc-harness --test regex_glob_ops_conformance_test -- --nocapture",
        "cargo test -p frankenlibc_conformance regex_glob_ops_fixture_cases_match_execute_fixture_case --lib -- --nocapture",
    ]
    for command in required_commands:
        if command not in commands:
            err(f"test_contract.required_remote_commands missing: {command}")

    emit(
        "regex_glob_free.fixture_surface_validated",
        fixture_case_count=len(cases),
        function_count=len(functions),
        mode_count=len(modes),
    )
    return len(cases), len(functions), len(modes)


def validate_bindings(manifest: dict[str, Any]) -> int:
    bindings = as_list(manifest.get("missing_item_bindings"), "missing_item_bindings")
    seen: set[str] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            err(f"missing_item_bindings[{index}] must be an object")
            continue
        binding_id = binding.get("id")
        if not isinstance(binding_id, str):
            err(f"missing_item_bindings[{index}].id must be a string")
            continue
        seen.add(binding_id)
        for list_key in ["implementation_refs", "test_refs", "runtime_validation"]:
            refs = as_list(binding.get(list_key), f"missing_item_bindings[{binding_id}].{list_key}")
            if not refs:
                err(f"missing_item_bindings[{binding_id}].{list_key} must not be empty")
            for ref in refs:
                if not isinstance(ref, str) or not ref:
                    err(f"missing_item_bindings[{binding_id}].{list_key} contains invalid ref")
    if seen != EXPECTED_MISSING_ITEMS:
        err(f"missing_item_bindings mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(seen)}")

    emit("regex_glob_free.bindings_validated", binding_count=len(bindings))
    return len(bindings)


def validate_telemetry(manifest: dict[str, Any]) -> None:
    telemetry = as_object(manifest.get("telemetry_contract"), "telemetry_contract")
    if telemetry.get("report_schema_version") != EXPECTED_REPORT_SCHEMA:
        err("telemetry_contract.report_schema_version mismatch")
    required_events = {
        item for item in as_list(telemetry.get("required_events"), "telemetry_contract.required_events")
        if isinstance(item, str)
    }
    missing = sorted(set(PASS_EVENTS) - required_events)
    if missing:
        err(f"telemetry_contract.required_events missing: {missing}")
    forbidden = {
        item for item in as_list(telemetry.get("forbidden_pass_events"), "telemetry_contract.forbidden_pass_events")
        if isinstance(item, str)
    }
    if FAIL_EVENT not in forbidden:
        err(f"telemetry_contract.forbidden_pass_events missing: {FAIL_EVENT}")


def report(status: str, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "status": status,
        "bead_id": EXPECTED_BEAD,
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "trace_id": EXPECTED_TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "generated_utc": now(),
        "summary": summary,
        "errors": errors,
        "artifact_refs": {
            "contract": rel(CONTRACT),
            "report": rel(REPORT),
            "log": rel(LOG),
        },
    }


manifest = load_json(CONTRACT, "contract")
artifacts = validate_manifest(manifest)
marker_count = validate_implementation_markers(manifest, artifacts)
fixture_case_count, function_count, mode_count = validate_fixture_surface(manifest, artifacts)
binding_count = validate_bindings(manifest)
validate_telemetry(manifest)

summary = {
    "implementation_marker_count": marker_count,
    "fixture_case_count": fixture_case_count,
    "fixture_function_count": function_count,
    "fixture_mode_count": mode_count,
    "binding_count": binding_count,
}

if errors:
    emit(FAIL_EVENT, outcome="fail", error_count=len(errors))
    write_json(REPORT, report("fail", summary))
    write_jsonl(LOG, events)
    for message in errors:
        print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)

emit("regex_glob_free.completion_contract_pass", **summary)
write_json(REPORT, report("pass", summary))
write_jsonl(LOG, events)
print(
    "PASS: regex/glob free completion contract "
    f"markers={marker_count} fixture_cases={fixture_case_count} bindings={binding_count}"
)
PY
