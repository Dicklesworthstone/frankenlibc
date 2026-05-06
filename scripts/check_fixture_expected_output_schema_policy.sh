#!/usr/bin/env bash
# Validate the fixture expected-output schema policy without rewriting fixtures.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FIXTURE_EXPECTED_OUTPUT_POLICY_CONTRACT:-${ROOT}/tests/conformance/fixture_expected_output_schema_policy.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/fixture_expected_output_schema_policy.report.json"
LOG="${OUT_DIR}/fixture_expected_output_schema_policy.log.jsonl"
TRACE_ID="bd-0agsk.5::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"

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

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${TRACE_ID}" "${MODE}" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys
import time
from collections import Counter

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
trace_id = sys.argv[5]
mode = sys.argv[6]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "fixture_expected_output_schema_policy.v1"
EXPECTED_BEAD = "bd-0agsk.5"
EXPECTED_POLICY = "adapter_normalized_tagged_values"
REQUIRED_FOCUS_IDS = ["elf_loader", "resolver", "time_ops", "termios_ops"]
EXPECTED_ADAPTER_TOKENS = [
    "fn expected_output_from_raw_case",
    "fn normalize_expected_output_value",
    "fn format_return_and_values",
]


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
        "schema_version": "fixture_expected_output_schema_policy.report.v1",
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
    finish(report, "fixture_expected_output_schema_policy_failed")
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


def primary_tag_for_case(case: dict, tag_rows: list[dict]) -> str | None:
    for row in tag_rows:
        fields = row.get("fields", [])
        if fields and all(field in case for field in fields):
            return str(row.get("tag", ""))
    return None


def supplemental_expected_fields(case: dict, primary_fields: set[str]) -> list[str]:
    ignored = primary_fields | {"expected_errno"}
    return sorted(
        field for field in case
        if field.startswith("expected_") and field not in ignored
    )


if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")

if not contract_path.is_file():
    fail("contract_missing", f"contract file missing: {contract_path}")

source_commit = git_head()
contract = load_json(contract_path)

if contract.get("schema_version") != EXPECTED_SCHEMA:
    fail("contract_schema_version", f"contract schema_version must be {EXPECTED_SCHEMA}", source_commit=source_commit)
if contract.get("generated_by_bead") != EXPECTED_BEAD:
    fail("contract_bead", f"contract generated_by_bead must be {EXPECTED_BEAD}", source_commit=source_commit)
if contract.get("canonical_command") != "scripts/check_fixture_expected_output_schema_policy.sh --validate-only":
    fail("canonical_command_mismatch", "canonical_command must point at validate-only checker", source_commit=source_commit)

policy = contract.get("canonical_policy", {})
if policy.get("id") != EXPECTED_POLICY:
    fail("canonical_policy_mismatch", f"canonical policy must be {EXPECTED_POLICY}", source_commit=source_commit)
if policy.get("internal_comparison_type") != "string":
    fail("canonical_policy_mismatch", "internal comparison type must remain string", source_commit=source_commit)
if policy.get("preserves_existing_harness_behavior") is not True:
    fail("canonical_policy_mismatch", "policy must explicitly preserve existing harness behavior", source_commit=source_commit)

adapter_source = root / str(policy.get("primary_adapter_source", ""))
if not adapter_source.is_file():
    fail("adapter_source_missing", f"adapter source missing: {adapter_source}", source_commit=source_commit)
adapter_text = adapter_source.read_text(encoding="utf-8")
missing_tokens = [token for token in EXPECTED_ADAPTER_TOKENS if token not in adapter_text]
if missing_tokens:
    fail(
        "adapter_source_missing",
        "adapter source is missing expected normalization functions",
        source_commit=source_commit,
        missing_tokens=missing_tokens,
    )

tag_rows = contract.get("expectation_tag_precedence")
if not isinstance(tag_rows, list) or not tag_rows:
    fail("expectation_tag_contract_invalid", "expectation_tag_precedence must be a non-empty array", source_commit=source_commit)

tag_names = [str(row.get("tag", "")) for row in tag_rows if isinstance(row, dict)]
if tag_names[0] != "expected_output":
    fail("expectation_tag_contract_invalid", "expected_output must be the first precedence tag", source_commit=source_commit)
if len(tag_names) != len(set(tag_names)):
    fail("expectation_tag_contract_invalid", "expectation tags must be unique", source_commit=source_commit)

for row in tag_rows:
    if not isinstance(row, dict):
        fail("expectation_tag_contract_invalid", "tag row must be an object", source_commit=source_commit)
    fields = row.get("fields")
    if not isinstance(fields, list) or not fields or not all(isinstance(field, str) for field in fields):
        fail("expectation_tag_contract_invalid", f"{row.get('tag')}: fields must be non-empty strings", source_commit=source_commit)
    kinds = row.get("allowed_json_types")
    if not isinstance(kinds, list) or not kinds:
        fail("expectation_tag_contract_invalid", f"{row.get('tag')}: allowed_json_types must be non-empty", source_commit=source_commit)
    if not isinstance(row.get("adapter"), str) or not row["adapter"]:
        fail("expectation_tag_contract_invalid", f"{row.get('tag')}: adapter must be named", source_commit=source_commit)

all_primary_fields = {
    field
    for row in tag_rows
    for field in row.get("fields", [])
}

focus_rows = contract.get("focus_fixture_inventory")
if not isinstance(focus_rows, list):
    fail("focus_fixture_missing", "focus_fixture_inventory must be an array", source_commit=source_commit)

focus_by_id = {str(row.get("id")): row for row in focus_rows if isinstance(row, dict)}
missing_focus = [fixture_id for fixture_id in REQUIRED_FOCUS_IDS if fixture_id not in focus_by_id]
if missing_focus:
    fail("focus_fixture_missing", "contract must classify all required focus fixtures", source_commit=source_commit, missing_focus=missing_focus)

classified_rows = []
global_kind_counter = Counter()
global_tag_counter = Counter()
total_cases = 0
total_classified = 0

for fixture_id in REQUIRED_FOCUS_IDS:
    declared = focus_by_id[fixture_id]
    rel_path = str(declared.get("path", ""))
    fixture_path = root / rel_path
    if not fixture_path.is_file():
        fail("focus_fixture_missing", f"focus fixture missing: {rel_path}", source_commit=source_commit, fixture_id=fixture_id)

    current_sha = sha256_file(fixture_path)
    if declared.get("sha256") != current_sha:
        fail(
            "fixture_hash_mismatch",
            f"{fixture_id}: fixture sha256 does not match policy inventory",
            source_commit=source_commit,
            fixture_id=fixture_id,
            declared_sha256=declared.get("sha256"),
            current_sha256=current_sha,
        )

    fixture = load_json(fixture_path)
    cases = fixture.get("cases")
    if not isinstance(cases, list):
        fail("focus_fixture_missing", f"{fixture_id}: fixture cases must be an array", source_commit=source_commit, fixture_id=fixture_id)
    if fixture.get("family") != declared.get("family"):
        fail(
            "focus_fixture_missing",
            f"{fixture_id}: family mismatch",
            source_commit=source_commit,
            fixture_id=fixture_id,
            declared_family=declared.get("family"),
            current_family=fixture.get("family"),
        )

    primary_tags = Counter()
    expected_output_kinds = Counter()
    supplemental_fields = Counter()
    expected_errno_cases = 0
    unclassified_cases = []

    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            unclassified_cases.append(f"case[{index}]")
            continue
        tag = primary_tag_for_case(case, tag_rows)
        if tag is None:
            unclassified_cases.append(str(case.get("name", f"case[{index}]")))
            continue
        primary_tags[tag] += 1
        global_tag_counter[tag] += 1
        if "expected_output" in case:
            kind = json_kind(case["expected_output"])
            expected_output_kinds[kind] += 1
            global_kind_counter[kind] += 1
        if "expected_errno" in case:
            expected_errno_cases += 1
        for field in supplemental_expected_fields(case, all_primary_fields):
            supplemental_fields[field] += 1

    if unclassified_cases:
        fail(
            "fixture_case_unclassified",
            f"{fixture_id}: cases lack a primary expectation tag",
            source_commit=source_commit,
            fixture_id=fixture_id,
            unclassified_cases=unclassified_cases,
        )

    actual_case_count = len(cases)
    actual_primary_tags = count_map(primary_tags)
    actual_kinds = count_map(expected_output_kinds)
    actual_supplemental = count_map(supplemental_fields)

    if declared.get("case_count") != actual_case_count:
        fail(
            "fixture_case_count_mismatch",
            f"{fixture_id}: case_count drift",
            source_commit=source_commit,
            fixture_id=fixture_id,
            declared_case_count=declared.get("case_count"),
            actual_case_count=actual_case_count,
        )
    if declared.get("primary_expectation_tags") != actual_primary_tags:
        fail(
            "primary_expectation_tag_mismatch",
            f"{fixture_id}: primary expectation tag inventory drift",
            source_commit=source_commit,
            fixture_id=fixture_id,
            declared=declared.get("primary_expectation_tags"),
            actual=actual_primary_tags,
        )
    if declared.get("expected_output_value_kinds") != actual_kinds:
        fail(
            "expected_output_kind_mismatch",
            f"{fixture_id}: expected_output value-kind inventory drift",
            source_commit=source_commit,
            fixture_id=fixture_id,
            declared=declared.get("expected_output_value_kinds"),
            actual=actual_kinds,
        )
    if int(declared.get("expected_errno_cases", -1)) != expected_errno_cases:
        fail(
            "expected_errno_count_mismatch",
            f"{fixture_id}: expected_errno count drift",
            source_commit=source_commit,
            fixture_id=fixture_id,
            declared=declared.get("expected_errno_cases"),
            actual=expected_errno_cases,
        )
    if declared.get("supplemental_expected_like_fields", {}) != actual_supplemental:
        fail(
            "supplemental_field_mismatch",
            f"{fixture_id}: supplemental expected-like fields drift",
            source_commit=source_commit,
            fixture_id=fixture_id,
            declared=declared.get("supplemental_expected_like_fields"),
            actual=actual_supplemental,
        )

    total_cases += actual_case_count
    total_classified += sum(primary_tags.values())
    classified_rows.append({
        "id": fixture_id,
        "path": rel_path,
        "family": fixture.get("family"),
        "case_count": actual_case_count,
        "classified_cases": sum(primary_tags.values()),
        "primary_expectation_tags": actual_primary_tags,
        "expected_output_value_kinds": actual_kinds,
        "expected_errno_cases": expected_errno_cases,
        "supplemental_expected_like_fields": actual_supplemental,
        "sha256": current_sha,
    })

report = {
    "schema_version": "fixture_expected_output_schema_policy.report.v1",
    "bead": EXPECTED_BEAD,
    "trace_id": trace_id,
    "source_commit": source_commit,
    "mode": mode,
    "outcome": "pass",
    "failure_signature": None,
    "contract": str(contract_path),
    "summary": {
        "canonical_policy": EXPECTED_POLICY,
        "focus_fixture_count": len(REQUIRED_FOCUS_IDS),
        "total_focus_cases": total_cases,
        "classified_focus_cases": total_classified,
        "expected_output_value_kinds": count_map(global_kind_counter),
        "primary_expectation_tags": count_map(global_tag_counter),
        "adapter_source": str(adapter_source.relative_to(root)),
        "string_only_fixture_ids": [
            row["id"]
            for row in classified_rows
            if row["expected_output_value_kinds"] == {"string": row["case_count"]}
        ],
        "mixed_value_fixture_ids": [
            row["id"]
            for row in classified_rows
            if row["expected_output_value_kinds"] != {"string": row["case_count"]}
        ],
    },
    "checks": {
        "contract_schema_valid": "pass",
        "adapter_source_present": "pass",
        "focus_fixtures_present": "pass",
        "all_focus_cases_classified": "pass",
        "expected_output_kind_inventory_current": "pass",
        "supplemental_expected_fields_current": "pass",
    },
    "focus_fixtures": classified_rows,
}
finish(report, "fixture_expected_output_schema_policy_validated")
print(
    "PASS: fixture expected_output schema policy validated "
    f"fixtures={len(REQUIRED_FOCUS_IDS)} cases={total_cases} classified={total_classified}"
)
PY
