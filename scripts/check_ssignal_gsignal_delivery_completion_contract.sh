#!/usr/bin/env bash
# Validate bd-06re.1 ssignal/gsignal delivery completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_SSIGNAL_GSIGNAL_DELIVERY_COMPLETION_CONTRACT:-${1:-${ROOT}/tests/conformance/ssignal_gsignal_delivery_completion_contract.v1.json}}"
OUT_DIR="${FRANKENLIBC_SSIGNAL_GSIGNAL_DELIVERY_COMPLETION_OUT_DIR:-${2:-${ROOT}/target/conformance}}"
REPORT="${FRANKENLIBC_SSIGNAL_GSIGNAL_DELIVERY_COMPLETION_REPORT:-${OUT_DIR}/ssignal_gsignal_delivery_completion_contract.report.json}"
LOG="${FRANKENLIBC_SSIGNAL_GSIGNAL_DELIVERY_COMPLETION_LOG:-${OUT_DIR}/ssignal_gsignal_delivery_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1]).resolve()
contract_path = Path(sys.argv[2]).resolve()
report_path = Path(sys.argv[3]).resolve()
log_path = Path(sys.argv[4]).resolve()
source_commit = sys.argv[5]

SCHEMA = "ssignal_gsignal_delivery_completion_contract.v1"
BEAD_ID = "bd-06re.1"
ORIGINAL_BEAD = "bd-06re"
TRACE_ID = "bd-06re.1::ssignal-gsignal-delivery::v1"
REQUIRED_SPEC_ITEMS = {"tests.golden.primary"}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_completion_binding",
    "missing_source_term",
    "missing_required_golden_case",
    "fixture_golden_drift",
    "completion_output_contract_failed",
]

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {row["failure_signature"] for row in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "completion_output_contract_failed"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("malformed_contract", f"{label}: cannot parse {rel(path)}: {exc}")
        return {}


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def resolve_ref(ref: str) -> Path:
    return resolve(ref.split(":", 1)[0])


def require(condition: bool, signature: str, message: str) -> None:
    if not condition:
        add_error(signature, message)


def require_array(row: dict[str, Any], field: str, ctx: str, signature: str) -> list[Any]:
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    add_error(signature, f"{ctx}.{field} must be a non-empty array")
    return []


def string_list(row: dict[str, Any], field: str, ctx: str, signature: str) -> list[str]:
    result: list[str] = []
    for index, value in enumerate(require_array(row, field, ctx, signature)):
        if isinstance(value, str) and value:
            result.append(value)
        else:
            add_error("malformed_contract", f"{ctx}.{field}[{index}] must be a non-empty string")
    return result


def event(
    name: str,
    status: str,
    scenario_id: str,
    expected: Any,
    actual: Any,
    refs: list[str],
    failure: str = "none",
) -> dict[str, Any]:
    return {
        "timestamp": now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "scenario_id": scenario_id,
        "event": name,
        "status": status,
        "expected": expected,
        "actual": actual,
        "artifact_refs": sorted(set(refs)),
        "source_commit": source_commit,
        "failure_signature": failure,
    }


def base_report(status: str, contract: dict[str, Any], refs: list[str]) -> dict[str, Any]:
    golden = contract.get("golden_delivery_contract", {})
    required_cases = golden.get("required_fixture_cases", []) if isinstance(golden, dict) else []
    evidence = contract.get("completion_debt_evidence", {})
    bindings = evidence.get("missing_item_bindings", []) if isinstance(evidence, dict) else []
    return {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": status,
        "summary": {
            "binding_count": len(bindings) if isinstance(bindings, list) else 0,
            "golden_case_count": len(required_cases) if isinstance(required_cases, list) else 0,
            "log_row_count": len(events),
            "source_artifact_count": len(contract.get("source_artifacts", []))
            if isinstance(contract.get("source_artifacts"), list)
            else 0,
        },
        "source_artifacts": contract.get("source_artifacts", []),
        "missing_item_bindings": bindings if isinstance(bindings, list) else [],
        "golden_delivery": golden if isinstance(golden, dict) else {},
        "artifact_refs": sorted(set(refs)),
        "errors": errors,
    }


def fail_report(stage: str, contract: dict[str, Any], refs: list[str] | None = None) -> None:
    all_refs = sorted(set([rel(contract_path), rel(report_path), rel(log_path), *(refs or [])]))
    events.append(
        event(
            stage + "_failed",
            "fail",
            stage,
            "completion contract passes",
            primary_signature(),
            all_refs,
            primary_signature(),
        )
    )
    write_json(report_path, base_report("fail", contract, all_refs))
    write_jsonl(log_path, events)
    print(
        f"FAIL ssignal_gsignal_delivery_completion_contract primary_failure={primary_signature()} report={rel(report_path)} log={rel(log_path)}",
        file=sys.stderr,
    )
    raise SystemExit(1)


def validate_source_artifacts(contract: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for index, artifact in enumerate(require_array(contract, "source_artifacts", "contract", "malformed_contract")):
        if not isinstance(artifact, dict):
            add_error("malformed_contract", f"source_artifacts[{index}] must be an object")
            continue
        artifact_id = artifact.get("id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            add_error("malformed_contract", f"source_artifacts[{index}].id must be non-empty")
        if not isinstance(path_text, str) or not path_text:
            add_error("malformed_contract", f"source_artifacts[{index}].path must be non-empty")
            continue
        path = resolve(path_text)
        refs.append(rel(path))
        if not path.exists():
            add_error("missing_source_artifact", f"{artifact_id or index}: missing {rel(path)}")
    if not errors:
        events.append(event("source_artifacts_validated", "pass", "source-artifacts", "all sources exist", len(refs), refs))
    return refs


def validate_bindings(contract: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = contract.get("completion_debt_evidence", {})
    if not isinstance(evidence, dict):
        add_error("malformed_contract", "completion_debt_evidence must be an object")
        return []
    bindings = evidence.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        add_error("missing_completion_binding", "completion_debt_evidence.missing_item_bindings must bind tests.golden.primary")
        return []
    seen: set[str] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            add_error("malformed_contract", f"missing_item_bindings[{index}] must be an object")
            continue
        spec_item = binding.get("spec_item")
        if not isinstance(spec_item, str) or not spec_item:
            add_error("malformed_contract", f"missing_item_bindings[{index}].spec_item must be non-empty")
            continue
        seen.add(spec_item)
        if spec_item not in REQUIRED_SPEC_ITEMS:
            add_error("missing_completion_binding", f"unexpected spec item {spec_item}")
        for field in ("implementation_refs", "test_refs", "required_positive_tests", "required_negative_tests", "required_commands"):
            string_list(binding, field, f"missing_item_bindings[{index}]", "missing_completion_binding")
        for ref in string_list(binding, "implementation_refs", f"missing_item_bindings[{index}]", "missing_completion_binding"):
            if not resolve_ref(ref).exists():
                add_error("missing_source_artifact", f"implementation ref missing: {ref}")
        for ref in string_list(binding, "test_refs", f"missing_item_bindings[{index}]", "missing_completion_binding"):
            if not resolve_ref(ref).exists():
                add_error("missing_source_artifact", f"test ref missing: {ref}")
    missing = REQUIRED_SPEC_ITEMS - seen
    for spec_item in sorted(missing):
        add_error("missing_completion_binding", f"missing binding for {spec_item}")
    if not errors:
        events.append(
            event(
                "completion_binding_validated",
                "pass",
                "tests.golden.primary",
                sorted(REQUIRED_SPEC_ITEMS),
                sorted(seen),
                [rel(contract_path)],
            )
        )
    return [binding for binding in bindings if isinstance(binding, dict)]


def read_source(path_text: str, label: str, refs: list[str]) -> str:
    path = resolve(path_text)
    refs.append(rel(path))
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error("missing_source_artifact", f"{label}: cannot read {rel(path)}: {exc}")
        return ""


def require_terms(text: str, terms: list[str], label: str, refs: list[str]) -> None:
    for term in terms:
        if term not in text:
            add_error("missing_source_term", f"{label}: missing term {term!r}")
    if not errors:
        events.append(event(label + "_validated", "pass", label, terms, "all terms present", refs))


def validate_fixture_cases(golden: dict[str, Any], refs: list[str]) -> None:
    fixture_path = golden.get("fixture_path")
    if not isinstance(fixture_path, str) or not fixture_path:
        add_error("malformed_contract", "golden_delivery_contract.fixture_path must be non-empty")
        return
    fixture = load_json(resolve(fixture_path), "signal_ops fixture")
    refs.append(rel(resolve(fixture_path)))
    cases = fixture.get("cases")
    if not isinstance(cases, list):
        add_error("malformed_contract", "signal_ops fixture cases must be an array")
        return
    by_name = {case.get("name"): case for case in cases if isinstance(case, dict)}
    required_cases = golden.get("required_fixture_cases")
    if not isinstance(required_cases, list) or not required_cases:
        add_error("malformed_contract", "golden_delivery_contract.required_fixture_cases must be non-empty")
        return
    validated: list[str] = []
    for index, expected in enumerate(required_cases):
        if not isinstance(expected, dict):
            add_error("malformed_contract", f"required_fixture_cases[{index}] must be an object")
            continue
        name = expected.get("name")
        if not isinstance(name, str) or not name:
            add_error("malformed_contract", f"required_fixture_cases[{index}].name must be non-empty")
            continue
        actual = by_name.get(name)
        if not isinstance(actual, dict):
            add_error("missing_required_golden_case", f"missing signal_ops fixture case {name}")
            continue
        for field in ("function", "mode", "expected_output", "expected_errno", "inputs"):
            if actual.get(field) != expected.get(field):
                add_error(
                    "fixture_golden_drift",
                    f"{name}.{field} expected {expected.get(field)!r}, found {actual.get(field)!r}",
                )
        validated.append(name)
    if not errors:
        events.append(
            event(
                "fixture_golden_cases_validated",
                "pass",
                "signal_ops.required_fixture_cases",
                len(required_cases),
                validated,
                refs,
            )
        )


def validate_golden_delivery(contract: dict[str, Any]) -> list[str]:
    golden = contract.get("golden_delivery_contract")
    if not isinstance(golden, dict):
        add_error("malformed_contract", "golden_delivery_contract must be an object")
        return []
    refs: list[str] = []

    implementation = read_source(str(golden.get("implementation_path", "")), "implementation", refs)
    require_terms(
        implementation,
        string_list(golden, "required_implementation_terms", "golden_delivery_contract", "missing_source_term"),
        "implementation_delegation",
        refs,
    )

    unit_test = read_source(str(golden.get("unit_test_path", "")), "unit test", refs)
    for test_name in string_list(golden, "required_unit_tests", "golden_delivery_contract", "missing_source_term"):
        if f"fn {test_name}" not in unit_test:
            add_error("missing_source_term", f"unit test missing fn {test_name}")
    require_terms(
        unit_test,
        string_list(golden, "required_unit_test_terms", "golden_delivery_contract", "missing_source_term"),
        "unit_delivery_test",
        refs,
    )

    conformance_test = read_source(str(golden.get("conformance_test_path", "")), "conformance test", refs)
    for test_name in string_list(golden, "required_conformance_tests", "golden_delivery_contract", "missing_source_term"):
        if f"fn {test_name}" not in conformance_test:
            add_error("missing_source_term", f"conformance test missing fn {test_name}")
    require_terms(
        conformance_test,
        string_list(golden, "required_conformance_terms", "golden_delivery_contract", "missing_source_term"),
        "conformance_replay_contract",
        refs,
    )

    validate_fixture_cases(golden, refs)
    return refs


def validate_output_contract(contract: dict[str, Any]) -> None:
    output = contract.get("completion_output_contract")
    if not isinstance(output, dict):
        add_error("malformed_contract", "completion_output_contract must be an object")
        return
    required_events = set(string_list(output, "required_events", "completion_output_contract", "completion_output_contract_failed"))
    actual_events = {row["event"] for row in events}
    missing_events = required_events - actual_events - {"ssignal_gsignal_delivery_completion_contract_pass"}
    for event_name in sorted(missing_events):
        add_error("completion_output_contract_failed", f"missing event {event_name}")


contract = load_json(contract_path, "completion contract")
if errors:
    fail_report("load_contract", contract, [rel(contract_path)])

require(contract.get("schema_version") == SCHEMA, "malformed_contract", "schema_version mismatch")
require(contract.get("bead") == BEAD_ID, "malformed_contract", "bead mismatch")
require(contract.get("original_bead") == ORIGINAL_BEAD, "malformed_contract", "original_bead mismatch")
require(contract.get("trace_id") == TRACE_ID, "malformed_contract", "trace_id mismatch")

artifact_refs = [rel(contract_path)]
artifact_refs.extend(validate_source_artifacts(contract))
validate_bindings(contract)
artifact_refs.extend(validate_golden_delivery(contract))
validate_output_contract(contract)

if errors:
    fail_report("validate_contract", contract, artifact_refs)

events.append(
    event(
        "ssignal_gsignal_delivery_completion_contract_pass",
        "pass",
        "completion-output",
        "all required events emitted",
        [row["event"] for row in events],
        artifact_refs,
    )
)
write_json(report_path, base_report("pass", contract, [*artifact_refs, rel(report_path), rel(log_path)]))
write_jsonl(log_path, events)
print(
    "PASS ssignal_gsignal_delivery_completion_contract "
    f"golden_cases={base_report('pass', contract, [])['summary']['golden_case_count']} "
    f"bindings={base_report('pass', contract, [])['summary']['binding_count']} "
    f"events={len(events)} report={rel(report_path)} log={rel(log_path)}"
)
PY
