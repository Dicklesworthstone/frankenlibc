#!/usr/bin/env bash
# check_printf_float_precision_completion_contract.sh -- bd-h7ede.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_PRINTF_FLOAT_PRECISION_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/printf_float_precision_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_PRINTF_FLOAT_PRECISION_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/printf_float_precision_completion}"
REPORT="${FRANKENLIBC_PRINTF_FLOAT_PRECISION_COMPLETION_REPORT:-${OUT_DIR}/printf_float_precision_completion_contract.report.json}"
LOG="${FRANKENLIBC_PRINTF_FLOAT_PRECISION_COMPLETION_LOG:-${OUT_DIR}/printf_float_precision_completion_contract.events.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
LOG = pathlib.Path(sys.argv[4])
OUT_DIR = pathlib.Path(sys.argv[5])
SOURCE_COMMIT = sys.argv[6]

SCHEMA = "printf_float_precision_completion_contract.v1"
REPORT_SCHEMA = "printf_float_precision_completion_contract.report.v1"
BEAD_ID = "bd-h7ede.1"
ORIGINAL_BEAD = "bd-h7ede"
TRACE_ID = "bd-h7ede.1::printf-float-precision::completion::v1"

REQUIRED_ARTIFACT_IDS = {
    "printf_core",
    "printf_conformance_fixture",
    "printf_conformance_harness_test",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.conformance.primary",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_printf_float_precision_sources",
    "checker_accepts_printf_float_precision_completion_contract",
    "checker_emits_structured_printf_precision_telemetry",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_unit_binding",
    "checker_rejects_precision_cap_drift",
    "checker_rejects_missing_conformance_binding",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_unit_binding",
    "missing_conformance_binding",
    "precision_cap_drift",
    "printf_fixture_drift",
    "missing_test_binding",
]

events: list[dict[str, Any]] = []
errors: list[dict[str, str]] = []
artifact_refs: set[str] = {str(CONTRACT)}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else ROOT / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "printf_float_precision_completion_contract_failed"


def load_json(path: pathlib.Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def read_text(path_text: str, signature: str) -> str:
    path = resolve(path_text)
    try:
        artifact_refs.add(rel(path))
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"cannot read {path_text}: {exc}")
        return ""


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def event(name: str, status: str, failure_signature: str = "none", **fields: Any) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "event": name,
        "status": status,
        "source_commit": SOURCE_COMMIT,
        "target_dir": rel(OUT_DIR),
        "failure_signature": failure_signature,
        **fields,
    }


def as_array(value: Any, context: str, signature: str = "malformed_contract") -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def as_object(value: Any, context: str, signature: str = "malformed_contract") -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def string_set(value: Any, context: str, signature: str) -> set[str]:
    rows = as_array(value, context, signature)
    result = {row for row in rows if isinstance(row, str)}
    if len(result) != len(rows):
        add_error(signature, f"{context} must contain only strings")
    return result


def missing(required: set[str], actual: set[str]) -> list[str]:
    return sorted(required - actual)


def require_contains(path_text: str, needles: set[str], signature: str) -> None:
    text = read_text(path_text, signature)
    for needle in sorted(needles):
        if needle not in text:
            add_error(signature, f"{path_text} missing required text: {needle}")


def artifact_map(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = as_array(contract.get("source_artifacts"), "source_artifacts")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        obj = as_object(row, "source_artifacts[]")
        artifact_id = obj.get("id")
        path = obj.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            add_error("malformed_contract", "source artifact id must be a non-empty string")
            continue
        if not isinstance(path, str) or not path:
            add_error("malformed_contract", f"source artifact {artifact_id} path must be non-empty")
            continue
        result[artifact_id] = obj
        if not resolve(path).exists():
            add_error("missing_source_artifact", f"source artifact {artifact_id} missing path {path}")
    missing_artifacts = missing(REQUIRED_ARTIFACT_IDS, set(result))
    if missing_artifacts:
        add_error("missing_source_artifact", f"missing source artifact ids: {missing_artifacts}")
    events.append(
        event(
            "source_artifacts_validated",
            "pass" if not missing_artifacts else "fail",
            "none" if not missing_artifacts else "missing_source_artifact",
            artifact_count=len(result),
        )
    )
    return result


def binding_signature(item_id: str) -> str:
    if item_id == "tests.unit.primary":
        return "missing_unit_binding"
    if item_id == "tests.conformance.primary":
        return "missing_conformance_binding"
    return "malformed_contract"


def validate_contract_shape(contract: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema_version") != SCHEMA:
        add_error("malformed_contract", f"schema_version must be {SCHEMA}")
    if contract.get("bead_id") != BEAD_ID:
        add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
    if contract.get("original_bead") != ORIGINAL_BEAD:
        add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
    completion = as_object(contract.get("completion_contract"), "completion_contract")
    missing_items = string_set(
        completion.get("missing_item_ids"),
        "completion_contract.missing_item_ids",
        "malformed_contract",
    )
    missing_items_missing = missing(REQUIRED_MISSING_ITEMS, missing_items)
    if missing_items_missing:
        for item_id in missing_items_missing:
            add_error(binding_signature(item_id), f"missing item id {item_id}")
    events.append(
        event(
            "completion_contract_shape_validated",
            "pass" if not missing_items_missing else "fail",
            "none" if not missing_items_missing else "malformed_contract",
            missing_item_count=len(missing_items),
        )
    )
    return completion


def validate_missing_item_bindings(contract: dict[str, Any]) -> None:
    bindings = as_array(contract.get("missing_item_bindings"), "missing_item_bindings")
    by_id = {
        row.get("missing_item_id"): as_object(row, "missing_item_bindings[]")
        for row in bindings
        if isinstance(row, dict)
    }
    for item_id in sorted(REQUIRED_MISSING_ITEMS):
        binding = by_id.get(item_id)
        if not binding:
            add_error(binding_signature(item_id), f"missing binding for {item_id}")
            continue
        for key in ["implementation_refs", "test_refs", "runtime_validation"]:
            values = string_set(binding.get(key), f"{item_id}.{key}", binding_signature(item_id))
            if not values:
                add_error(binding_signature(item_id), f"{item_id}.{key} cannot be empty")
    events.append(event("missing_item_bindings_validated", "pass", binding_count=len(by_id)))


def validate_precision_cap(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    cap = as_object(
        completion.get("required_precision_cap"),
        "completion_contract.required_precision_cap",
        "precision_cap_drift",
    )
    if cap.get("cap") != 65535 or cap.get("first_panicking_precision") != 65536:
        add_error("precision_cap_drift", "precision cap metadata must pin 65535/65536")
    if cap.get("required_output_len_at_cap") != 65537:
        add_error("precision_cap_drift", "required output length at cap must remain 65537")
    if cap.get("pathological_precision_case") != "usize::MAX / 2":
        add_error("precision_cap_drift", "pathological precision case must be usize::MAX / 2")

    core_path = str(artifacts.get("printf_core", {}).get("path", ""))
    anchors = string_set(
        completion.get("required_implementation_anchors"),
        "completion_contract.required_implementation_anchors",
        "precision_cap_drift",
    )
    require_contains(core_path, anchors, "precision_cap_drift")
    events.append(
        event(
            "precision_cap_validated",
            "pass",
            cap=cap.get("cap"),
            anchors=len(anchors),
        )
    )


def validate_conformance_fixture(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    fixture = load_json(
        resolve(str(artifacts.get("printf_conformance_fixture", {}).get("path", ""))),
        "printf_conformance_fixture",
        "printf_fixture_drift",
    )
    required = as_object(
        completion.get("required_conformance_fixture"),
        "completion_contract.required_conformance_fixture",
        "printf_fixture_drift",
    )
    if fixture.get("version") != required.get("version"):
        add_error("printf_fixture_drift", f"fixture version expected {required.get('version')!r}")
    if fixture.get("family") != required.get("family"):
        add_error("printf_fixture_drift", f"fixture family expected {required.get('family')!r}")
    cases = as_array(fixture.get("cases"), "printf_conformance_fixture.cases", "printf_fixture_drift")
    if len(cases) < int(required.get("minimum_case_count", 0)):
        add_error("printf_fixture_drift", "fixture case count below minimum")
    if len(cases) != int(required.get("current_case_count", len(cases))):
        add_error("printf_fixture_drift", f"fixture case count expected {required.get('current_case_count')} got {len(cases)}")
    case_names = {str(row.get("name")) for row in cases if isinstance(row, dict)}
    required_names = string_set(required.get("required_case_names"), "required_conformance_fixture.required_case_names", "printf_fixture_drift")
    missing_cases = missing(required_names, case_names)
    if missing_cases:
        add_error("printf_fixture_drift", f"missing required printf fixture cases: {missing_cases}")
    events.append(
        event(
            "printf_conformance_fixture_validated",
            "pass" if not missing_cases else "fail",
            "none" if not missing_cases else "printf_fixture_drift",
            case_count=len(cases),
        )
    )


def validate_harness_and_completion_tests(contract: dict[str, Any], completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    harness_path = str(artifacts.get("printf_conformance_harness_test", {}).get("path", ""))
    harness_tests = string_set(
        completion.get("required_harness_tests"),
        "completion_contract.required_harness_tests",
        "missing_conformance_binding",
    )
    require_contains(harness_path, harness_tests | {"printf_conformance_covers_float_specifiers", "host parity"}, "missing_conformance_binding")

    test_fns = as_object(contract.get("required_test_functions"), "required_test_functions")
    positive = string_set(test_fns.get("positive"), "required_test_functions.positive", "missing_test_binding")
    negative = string_set(test_fns.get("negative"), "required_test_functions.negative", "missing_test_binding")
    missing_positive = missing(REQUIRED_POSITIVE_TESTS, positive)
    missing_negative = missing(REQUIRED_NEGATIVE_TESTS, negative)
    if missing_positive:
        add_error("missing_test_binding", f"missing positive tests: {missing_positive}")
    if missing_negative:
        add_error("missing_test_binding", f"missing negative tests: {missing_negative}")
    completion_test_path = str(artifacts.get("completion_harness_test", {}).get("path", ""))
    require_contains(completion_test_path, REQUIRED_POSITIVE_TESTS | REQUIRED_NEGATIVE_TESTS, "missing_test_binding")
    events.append(
        event(
            "test_surfaces_validated",
            "pass" if not missing_positive and not missing_negative else "fail",
            "none" if not missing_positive and not missing_negative else "missing_test_binding",
            harness_tests=len(harness_tests),
            positive_tests=len(positive),
            negative_tests=len(negative),
        )
    )


def finish(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        events.append(event("printf_float_precision_completion_contract_validated", "pass"))
    else:
        events.append(event("printf_float_precision_completion_contract_failed", "fail", primary_signature()))
    report = {
        "schema_version": REPORT_SCHEMA,
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "status": status,
        "summary": summary,
        "failure_signature": "none" if status == "pass" else primary_signature(),
        "error_count": len(errors),
        "errors": errors,
        "artifact_refs": sorted(artifact_refs),
        "events": events,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, events)
    if status == "pass":
        print(
            "PASS printf float precision completion contract "
            f"sources={summary.get('source_artifacts', 0)} events={len(events)}"
        )
        sys.exit(0)
    print(
        "FAIL printf float precision completion contract "
        f"signature={primary_signature()} errors={len(errors)} report={rel(REPORT)}",
        file=sys.stderr,
    )
    sys.exit(1)


def main() -> None:
    contract = as_object(load_json(CONTRACT, "contract"), "contract")
    artifacts = artifact_map(contract)
    completion = validate_contract_shape(contract)
    validate_missing_item_bindings(contract)
    validate_precision_cap(completion, artifacts)
    validate_conformance_fixture(completion, artifacts)
    validate_harness_and_completion_tests(contract, completion, artifacts)
    finish(
        {
            "source_artifacts": len(artifacts),
            "missing_items": len(REQUIRED_MISSING_ITEMS),
            "events": len(events),
        }
    )


main()
PY
