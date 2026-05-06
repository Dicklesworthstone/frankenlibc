#!/usr/bin/env bash
# Validate every conformance fixture file against the current fixture schema policy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FIXTURE_SCHEMA_VALIDATION_CONTRACT:-${ROOT}/tests/conformance/fixture_schema_validation.v1.json}"
FIXTURES_DIR="${FIXTURE_SCHEMA_VALIDATION_FIXTURES_DIR:-}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/fixture_schema_validation.report.json"
LOG="${OUT_DIR}/fixture_schema_validation.log.jsonl"
TRACE_ID="bd-0agsk.6::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"

MODE="validate-only"
if [[ $# -gt 0 ]]; then
  case "$1" in
    --validate-only)
      MODE="validate-only"
      shift
      ;;
    *)
      MODE="unknown:${1}"
      shift
      ;;
  esac
fi

if [[ $# -gt 0 ]]; then
  MODE="unknown:${1}"
fi

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT}" "${FIXTURES_DIR}" "${REPORT}" "${LOG}" "${TRACE_ID}" "${MODE}" <<'PY'
import json
import pathlib
import subprocess
import sys
import time
from collections import Counter

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
fixtures_override = sys.argv[3]
report_path = pathlib.Path(sys.argv[4])
log_path = pathlib.Path(sys.argv[5])
trace_id = sys.argv[6]
mode = sys.argv[7]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "fixture_schema_validation.v1"
EXPECTED_BEAD = "bd-0agsk.6"
POLICY_SCHEMA = "fixture_expected_output_schema_policy.v1"
POLICY_ID = "adapter_normalized_tagged_values"
VALID_MODES = {"strict", "hardened", "both"}
STANDARD_CASE_REQUIRED = ["name", "function", "spec_section", "inputs", "mode"]
PROGRAM_SCENARIO_REQUIRED = ["scenario_id", "source", "expected"]
UNSUPPORTED_SCENARIO_REQUIRED = ["scenario_id", "expected_outcome", "expected_errno"]


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def git_head() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_event(report, event_name: str) -> None:
    event = {
        "timestamp": now_utc(),
        "trace_id": trace_id,
        "level": "error" if report.get("outcome") == "fail" else "info",
        "event": event_name,
        "bead_id": EXPECTED_BEAD,
        "source_commit": report.get("source_commit"),
        "artifact_refs": [str(contract_path), str(report_path)],
        "outcome": report.get("outcome"),
        "failure_signature": report.get("failure_signature"),
        "duration_ms": report.get("duration_ms"),
        "details": report.get("summary", {}),
    }
    log_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")


def finish(report, event_name: str) -> None:
    report["duration_ms"] = (time.time_ns() - start_ns) // 1_000_000
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_event(report, event_name)


def fail(signature: str, message: str, **extra) -> None:
    report = {
        "schema_version": "fixture_schema_validation.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": trace_id,
        "source_commit": extra.pop("source_commit", None),
        "mode": mode,
        "outcome": "fail",
        "failure_signature": signature,
        "failure_message": message,
        "contract": str(contract_path),
        "summary": extra,
    }
    finish(report, "fixture_schema_validation_failed")
    raise SystemExit(f"FAIL[{signature}]: {message}")


def json_kind(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def count_map(counter: Counter) -> dict:
    return {key: counter[key] for key in sorted(counter)}


def primary_tag_for_case(case: dict, tag_rows: list[dict]) -> tuple[str | None, list[str]]:
    for row in tag_rows:
        fields = row.get("fields", [])
        if fields and all(field in case for field in fields):
            return str(row.get("tag", "")), list(fields)
    return None, []


def non_empty_string(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")

if not contract_path.is_file():
    fail("contract_missing", f"contract file missing: {contract_path}")

source_commit = git_head()
contract = load_json(contract_path)
if contract.get("schema_version") != EXPECTED_SCHEMA:
    fail("contract_schema_version", f"contract schema_version must be {EXPECTED_SCHEMA}", source_commit=source_commit)
if contract.get("generated_by_bead") != EXPECTED_BEAD:
    fail("contract_schema_version", f"contract generated_by_bead must be {EXPECTED_BEAD}", source_commit=source_commit)

policy_ref = contract.get("input_policy_artifact", {})
policy_path = root / str(policy_ref.get("path", ""))
if not policy_path.is_file():
    fail("policy_artifact_invalid", f"policy artifact missing: {policy_path}", source_commit=source_commit)
policy = load_json(policy_path)
if policy.get("schema_version") != POLICY_SCHEMA:
    fail("policy_artifact_invalid", f"policy schema_version must be {POLICY_SCHEMA}", source_commit=source_commit)
if policy.get("canonical_policy", {}).get("id") != POLICY_ID:
    fail("policy_artifact_invalid", f"policy id must be {POLICY_ID}", source_commit=source_commit)
tag_rows = policy.get("expectation_tag_precedence")
if not isinstance(tag_rows, list) or not tag_rows:
    fail("policy_artifact_invalid", "policy expectation_tag_precedence must be non-empty", source_commit=source_commit)

fixtures_dir = pathlib.Path(fixtures_override) if fixtures_override else root / str(contract.get("fixture_root", ""))
if not fixtures_dir.is_absolute():
    fixtures_dir = root / fixtures_dir
if not fixtures_dir.is_dir():
    fail("fixture_root_missing", f"fixture root missing: {fixtures_dir}", source_commit=source_commit)

kind_overrides = contract.get("expectation_value_kind_overrides", {})
supplemental_allowed = contract.get("allowed_supplemental_expectation_fields", {})
optional_errno_families = {
    row.get("family")
    for row in contract.get("expected_errno_policy", {}).get("optional_family_exceptions", [])
    if isinstance(row, dict)
}

fixture_files = sorted(fixtures_dir.glob("*.json"))
if not fixture_files:
    fail("fixture_root_missing", f"no fixture JSON files found under {fixtures_dir}", source_commit=source_commit)

fixture_rows = []
primary_tag_counts = Counter()
expected_output_kind_counts = Counter()
supplemental_field_counts = Counter()
summary = Counter()
required_errno_cases = 0
optional_errno_cases = 0

for path in fixture_files:
    rel_path = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    try:
        fixture = load_json(path)
    except (OSError, json.JSONDecodeError) as err:
        fail("fixture_file_unclassified", f"{rel_path}: fixture JSON could not be loaded: {err}", source_commit=source_commit, fixture_path=rel_path)

    has_cases = "cases" in fixture
    has_structured = "program_scenarios" in fixture or "unsupported_scenarios" in fixture
    if has_cases and has_structured:
        fail("fixture_file_unclassified", f"{rel_path}: fixture must not mix cases and structured scenario schemas", source_commit=source_commit, fixture_path=rel_path)
    if not has_cases and not has_structured:
        fail("fixture_file_unclassified", f"{rel_path}: fixture has no cases or structured scenarios", source_commit=source_commit, fixture_path=rel_path)

    family = fixture.get("family")
    if not non_empty_string(family):
        fail("standard_fixture_schema_invalid" if has_cases else "structured_fixture_schema_invalid", f"{rel_path}: family must be a non-empty string", source_commit=source_commit, fixture_path=rel_path)
    if "version" not in fixture and "schema_version" not in fixture:
        fail("standard_fixture_schema_invalid" if has_cases else "structured_fixture_schema_invalid", f"{rel_path}: version or schema_version is required", source_commit=source_commit, fixture_path=rel_path)
    if not non_empty_string(fixture.get("captured_at")):
        fail("standard_fixture_schema_invalid" if has_cases else "structured_fixture_schema_invalid", f"{rel_path}: captured_at must be a non-empty string", source_commit=source_commit, fixture_path=rel_path)

    if has_cases:
        cases = fixture.get("cases")
        if not isinstance(cases, list):
            fail("standard_fixture_schema_invalid", f"{rel_path}: cases must be an array", source_commit=source_commit, fixture_path=rel_path)
        summary["standard_fixture_files"] += 1
        summary["standard_case_count"] += len(cases)
        case_tag_counts = Counter()
        case_kind_counts = Counter()
        case_supplemental_counts = Counter()
        expected_errno_cases = 0

        for index, case in enumerate(cases):
            context = f"{rel_path}#/cases/{index}"
            if not isinstance(case, dict):
                fail("fixture_case_schema_invalid", f"{context}: case must be an object", source_commit=source_commit, fixture_path=rel_path, case_index=index)
            case_name = str(case.get("name", f"case[{index}]"))
            for field in STANDARD_CASE_REQUIRED:
                if field not in case:
                    fail("fixture_case_schema_invalid", f"{context}: missing required field {field}", source_commit=source_commit, fixture_path=rel_path, case_name=case_name, field=field)
            for field in ["name", "function", "spec_section", "mode"]:
                if not non_empty_string(case.get(field)):
                    fail("fixture_case_schema_invalid", f"{context}: {field} must be a non-empty string", source_commit=source_commit, fixture_path=rel_path, case_name=case_name, field=field)
            if case.get("mode") not in VALID_MODES:
                fail("fixture_case_schema_invalid", f"{context}: invalid mode {case.get('mode')}", source_commit=source_commit, fixture_path=rel_path, case_name=case_name)

            selected_tag, selected_fields = primary_tag_for_case(case, tag_rows)
            if selected_tag is None:
                fail("fixture_case_missing_expectation", f"{context}: missing primary expectation tag", source_commit=source_commit, fixture_path=rel_path, case_name=case_name)
            primary_tag_counts[selected_tag] += 1
            case_tag_counts[selected_tag] += 1

            for field in selected_fields:
                allowed_kinds = set(kind_overrides.get(field, []))
                value_kind = json_kind(case.get(field))
                if allowed_kinds and value_kind not in allowed_kinds:
                    fail(
                        "fixture_case_invalid_expectation_shape",
                        f"{context}: {field} has invalid JSON kind {value_kind}",
                        source_commit=source_commit,
                        fixture_path=rel_path,
                        case_name=case_name,
                        field=field,
                        value_kind=value_kind,
                        allowed_kinds=sorted(allowed_kinds),
                    )
                if field == "expected_output":
                    expected_output_kind_counts[value_kind] += 1
                    case_kind_counts[value_kind] += 1

            ignored_fields = set(selected_fields) | {"expected_errno"}
            for field, value in case.items():
                if not field.startswith("expected_") or field in ignored_fields:
                    continue
                allowed_kinds = set(supplemental_allowed.get(field, []))
                value_kind = json_kind(value)
                if not allowed_kinds or value_kind not in allowed_kinds:
                    fail(
                        "fixture_case_invalid_expectation_shape",
                        f"{context}: supplemental {field} has invalid JSON kind {value_kind}",
                        source_commit=source_commit,
                        fixture_path=rel_path,
                        case_name=case_name,
                        field=field,
                        value_kind=value_kind,
                        allowed_kinds=sorted(allowed_kinds),
                    )
                supplemental_field_counts[field] += 1
                case_supplemental_counts[field] += 1

            if family in optional_errno_families:
                optional_errno_cases += 1
            elif "expected_errno" not in case:
                fail("fixture_case_missing_expected_errno", f"{context}: expected_errno is required for family {family}", source_commit=source_commit, fixture_path=rel_path, case_name=case_name, family=family)
            else:
                if json_kind(case.get("expected_errno")) != "number":
                    fail("fixture_case_schema_invalid", f"{context}: expected_errno must be numeric", source_commit=source_commit, fixture_path=rel_path, case_name=case_name)
                expected_errno_cases += 1
                required_errno_cases += 1

        fixture_rows.append({
            "path": rel_path,
            "schema_class": "standard_case_fixture",
            "family": family,
            "case_count": len(cases),
            "expected_errno_cases": expected_errno_cases,
            "primary_expectation_tags": count_map(case_tag_counts),
            "expected_output_value_kinds": count_map(case_kind_counts),
            "supplemental_expectation_fields": count_map(case_supplemental_counts),
        })
        continue

    program_scenarios = fixture.get("program_scenarios", [])
    unsupported_scenarios = fixture.get("unsupported_scenarios", [])
    if not isinstance(program_scenarios, list):
        fail("structured_fixture_schema_invalid", f"{rel_path}: program_scenarios must be an array", source_commit=source_commit, fixture_path=rel_path)
    if not isinstance(unsupported_scenarios, list):
        fail("structured_fixture_schema_invalid", f"{rel_path}: unsupported_scenarios must be an array", source_commit=source_commit, fixture_path=rel_path)
    summary["structured_fixture_files"] += 1
    summary["structured_program_scenarios"] += len(program_scenarios)
    summary["structured_unsupported_scenarios"] += len(unsupported_scenarios)

    for index, scenario in enumerate(program_scenarios):
        context = f"{rel_path}#/program_scenarios/{index}"
        if not isinstance(scenario, dict):
            fail("structured_fixture_schema_invalid", f"{context}: scenario must be an object", source_commit=source_commit, fixture_path=rel_path)
        for field in PROGRAM_SCENARIO_REQUIRED:
            if field not in scenario:
                fail("structured_fixture_schema_invalid", f"{context}: missing {field}", source_commit=source_commit, fixture_path=rel_path, field=field)
        if not non_empty_string(scenario.get("scenario_id")) or not non_empty_string(scenario.get("source")):
            fail("structured_fixture_schema_invalid", f"{context}: scenario_id/source must be non-empty strings", source_commit=source_commit, fixture_path=rel_path)
        expected = scenario.get("expected")
        if not isinstance(expected, dict) or not {"strict", "hardened"}.issubset(expected):
            fail("structured_fixture_schema_invalid", f"{context}: expected must include strict and hardened objects", source_commit=source_commit, fixture_path=rel_path)

    for index, scenario in enumerate(unsupported_scenarios):
        context = f"{rel_path}#/unsupported_scenarios/{index}"
        if not isinstance(scenario, dict):
            fail("structured_fixture_schema_invalid", f"{context}: scenario must be an object", source_commit=source_commit, fixture_path=rel_path)
        for field in UNSUPPORTED_SCENARIO_REQUIRED:
            if field not in scenario:
                signature = "unsupported_scenario_missing_expected_outcome" if field == "expected_outcome" else "structured_fixture_schema_invalid"
                fail(signature, f"{context}: missing {field}", source_commit=source_commit, fixture_path=rel_path, field=field)
        if not non_empty_string(scenario.get("scenario_id")):
            fail("structured_fixture_schema_invalid", f"{context}: scenario_id must be a non-empty string", source_commit=source_commit, fixture_path=rel_path)
        if not non_empty_string(scenario.get("expected_outcome")):
            fail("unsupported_scenario_missing_expected_outcome", f"{context}: expected_outcome must be a non-empty string", source_commit=source_commit, fixture_path=rel_path)
        if json_kind(scenario.get("expected_errno")) not in {"number", "string"}:
            fail("structured_fixture_schema_invalid", f"{context}: expected_errno must be a string or number", source_commit=source_commit, fixture_path=rel_path)

    fixture_rows.append({
        "path": rel_path,
        "schema_class": "structured_scenario_fixture",
        "family": family,
        "program_scenario_count": len(program_scenarios),
        "unsupported_scenario_count": len(unsupported_scenarios),
    })

observed_inventory = {
    "fixture_file_count": len(fixture_files),
    "standard_fixture_files": int(summary["standard_fixture_files"]),
    "structured_fixture_files": int(summary["structured_fixture_files"]),
    "standard_case_count": int(summary["standard_case_count"]),
    "structured_program_scenarios": int(summary["structured_program_scenarios"]),
    "structured_unsupported_scenarios": int(summary["structured_unsupported_scenarios"]),
    "expected_errno_required_cases": required_errno_cases,
    "expected_errno_optional_cases": optional_errno_cases,
    "primary_expectation_tags": count_map(primary_tag_counts),
    "expected_output_value_kinds": count_map(expected_output_kind_counts),
    "supplemental_expectation_fields": count_map(supplemental_field_counts),
}
expected_inventory = contract.get("expected_inventory", {})
if observed_inventory != expected_inventory:
    fail(
        "fixture_inventory_mismatch",
        "fixture inventory drifted from committed schema contract",
        source_commit=source_commit,
        expected_inventory=expected_inventory,
        observed_inventory=observed_inventory,
    )

report = {
    "schema_version": "fixture_schema_validation.report.v1",
    "bead": EXPECTED_BEAD,
    "trace_id": trace_id,
    "source_commit": source_commit,
    "mode": mode,
    "outcome": "pass",
    "failure_signature": None,
    "contract": str(contract_path),
    "fixture_root": str(fixtures_dir),
    "policy_artifact": str(policy_path),
    "summary": observed_inventory,
    "checks": {
        "policy_artifact_valid": "pass",
        "fixture_files_classified": "pass",
        "standard_cases_valid": "pass",
        "structured_scenarios_valid": "pass",
        "expected_errno_policy_enforced": "pass",
        "inventory_matches_contract": "pass",
    },
    "fixture_files": fixture_rows,
}
finish(report, "fixture_schema_validation_validated")
print(
    "PASS: fixture schema validation "
    f"files={len(fixture_files)} cases={observed_inventory['standard_case_count']} "
    f"structured={observed_inventory['structured_fixture_files']}"
)
PY
