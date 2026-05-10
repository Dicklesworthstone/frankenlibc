#!/usr/bin/env bash
# check_runtime_math_divergence_bounds_integration_contract.sh -- bd-2625.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_DIVERGENCE_INTEGRATION_CONTRACT:-${ROOT}/tests/runtime_math/runtime_math_divergence_bounds_integration_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MATH_DIVERGENCE_INTEGRATION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_DIVERGENCE_INTEGRATION_REPORT:-${OUT_DIR}/runtime_math_divergence_bounds_integration_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_DIVERGENCE_INTEGRATION_LOG:-${OUT_DIR}/runtime_math_divergence_bounds_integration_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
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
out_dir = Path(sys.argv[5])
source_commit = sys.argv[6]

SCHEMA = "runtime_math_divergence_bounds_integration_contract.v1"
BEAD_ID = "bd-2625.1"
ORIGINAL_BEAD = "bd-2625"
TRACE_ID = "bd-2625.1::runtime-math-divergence-bounds::integration::v1"
REQUIRED_ARTIFACT_IDS = {
    "divergence_matrix",
    "divergence_gate_script",
    "divergence_harness",
    "existing_integration_test",
    "completion_contract",
    "completion_gate",
    "completion_integration_test",
}
REQUIRED_MODES = {"strict", "hardened"}
REQUIRED_FORBIDDEN_RULES = {
    "hardened_profile_less_conservative",
    "hardened_denies_when_strict_allows",
    "hardened_allows_when_strict_fullvalidates",
}
REQUIRED_IMPL_REFS = {
    "tests/runtime_math/runtime_math_divergence_bounds.v1.json",
    "crates/frankenlibc-harness/src/runtime_math_divergence_bounds.rs",
    "scripts/check_runtime_math_divergence_bounds.sh",
    "tests/runtime_math/runtime_math_divergence_bounds_integration_contract.v1.json",
    "scripts/check_runtime_math_divergence_bounds_integration_contract.sh",
}
REQUIRED_TEST_REFS = {
    "crates/frankenlibc-harness/tests/runtime_math_divergence_bounds_test.rs",
    "crates/frankenlibc-harness/tests/runtime_math_divergence_bounds_integration_contract_test.rs",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_runtime_math_divergence_integration_sources",
    "checker_accepts_runtime_math_divergence_integration_contract",
    "integration_gate_generates_structured_runtime_report",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_integration_binding",
    "checker_rejects_missing_strict_hardened_mode_pair",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_divergence_matrix",
    "missing_integration_contract",
    "missing_integration_binding",
    "missing_harness_surface",
    "missing_test_binding",
]

events: list[dict[str, Any]] = []
errors: list[dict[str, str]] = []
artifact_refs: set[str] = {str(contract_path)}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "runtime_math_divergence_bounds_integration_contract_failed"


def load_json(path: Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
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
        "source_commit": source_commit,
        "target_dir": rel(out_dir),
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


def source_contains(path_text: str, needles: set[str], signature: str) -> None:
    path = resolve(path_text)
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"cannot read {path_text}: {exc}")
        return
    for needle in sorted(needles):
        if needle not in text:
            add_error(signature, f"{path_text} missing required text: {needle}")


def finish(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        events.append(event("runtime_math_divergence_integration_contract_validated", "pass"))
    else:
        events.append(
            event(
                "runtime_math_divergence_integration_contract_failed",
                "fail",
                primary_signature(),
            )
        )
    report = {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": status,
        "summary": {
            **summary,
            "event_count": len(events),
        },
        "artifact_refs": sorted(artifact_refs),
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, events)
    if errors:
        print(f"FAIL: runtime_math divergence integration contract errors={len(errors)}")
        for error in errors[:12]:
            print(f"- {error['failure_signature']}: {error['message']}")
        sys.exit(1)
    print(
        "PASS: runtime_math divergence integration contract "
        f"cases={summary.get('total_cases', 0)} artifacts={summary.get('source_artifact_count', 0)}"
    )


contract = load_json(contract_path, "contract")
if contract.get("schema_version") != SCHEMA:
    add_error("malformed_contract", f"schema_version must be {SCHEMA}")
if contract.get("bead_id") != BEAD_ID:
    add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
if contract.get("original_bead") != ORIGINAL_BEAD:
    add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
if contract.get("trace_id") != TRACE_ID:
    add_error("malformed_contract", f"trace_id must be {TRACE_ID}")

source_artifacts = as_array(contract.get("source_artifacts"), "source_artifacts")
source_by_id: dict[str, dict[str, Any]] = {}
for artifact in source_artifacts:
    row = as_object(artifact, "source_artifacts[]")
    artifact_id = row.get("id")
    path_text = row.get("path")
    if not isinstance(artifact_id, str) or not artifact_id:
        add_error("malformed_contract", "source_artifacts[].id must be a non-empty string")
        continue
    if not isinstance(path_text, str) or not path_text:
        add_error("malformed_contract", f"source_artifacts[{artifact_id}].path must be non-empty")
        continue
    source_by_id[artifact_id] = row
    path = resolve(path_text)
    artifact_refs.add(path_text)
    if not path.is_file():
        add_error("missing_source_artifact", f"{artifact_id} source artifact missing: {path_text}")
    if not isinstance(row.get("evidence"), str) or len(row.get("evidence", "").strip()) < 20:
        add_error("malformed_contract", f"{artifact_id} evidence must be descriptive")

missing_artifacts = missing(REQUIRED_ARTIFACT_IDS, set(source_by_id))
if missing_artifacts:
    add_error("missing_source_artifact", f"missing source artifact ids: {missing_artifacts}")
events.append(
    event(
        "source_artifacts_validated",
        "fail" if missing_artifacts else "pass",
        "missing_source_artifact" if missing_artifacts else "none",
        artifact_count=len(source_by_id),
    )
)

matrix_path = source_by_id.get("divergence_matrix", {}).get("path", "")
matrix = load_json(resolve(matrix_path), "divergence_matrix", "missing_divergence_matrix") if matrix_path else {}
matrix_errors_before = len(errors)
if matrix.get("schema_version") != "v1":
    add_error("missing_divergence_matrix", "divergence matrix schema_version must be v1")
if matrix.get("bead") != ORIGINAL_BEAD:
    add_error("missing_divergence_matrix", f"divergence matrix bead must be {ORIGINAL_BEAD}")
if string_set(matrix.get("mode_pair"), "divergence_matrix.mode_pair", "missing_divergence_matrix") != REQUIRED_MODES:
    add_error("missing_divergence_matrix", "divergence matrix mode_pair must be strict+hardened")
forbidden_rules = {
    row.get("id")
    for row in as_array(matrix.get("forbidden_divergences"), "divergence_matrix.forbidden_divergences", "missing_divergence_matrix")
    if isinstance(row, dict)
}
missing_rules = missing(REQUIRED_FORBIDDEN_RULES, {rule for rule in forbidden_rules if isinstance(rule, str)})
if missing_rules:
    add_error("missing_divergence_matrix", f"missing forbidden divergence rules: {missing_rules}")
evaluation_cases = as_array(matrix.get("evaluation_cases"), "divergence_matrix.evaluation_cases", "missing_divergence_matrix")
required_cases = as_array(matrix.get("required_cases"), "divergence_matrix.required_cases", "missing_divergence_matrix")
for case in evaluation_cases + required_cases:
    row = as_object(case, "divergence_matrix.case", "missing_divergence_matrix")
    for key in ("id", "family", "description", "ctx"):
        if key not in row:
            add_error("missing_divergence_matrix", f"divergence matrix case missing {key}")
if len(evaluation_cases) < 4:
    add_error("missing_divergence_matrix", "divergence matrix must keep at least four evaluation cases")
if len(required_cases) < 3:
    add_error("missing_divergence_matrix", "divergence matrix must keep at least three required cases")
events.append(
    event(
        "divergence_matrix_contract_validated",
        "fail" if len(errors) != matrix_errors_before else "pass",
        "missing_divergence_matrix" if len(errors) != matrix_errors_before else "none",
        evaluation_cases=len(evaluation_cases),
        required_cases=len(required_cases),
    )
)

integration_contract = as_object(contract.get("integration_contract"), "integration_contract", "missing_integration_contract")
integration_errors_before = len(errors)
if integration_contract.get("missing_item_id") != "tests.integration.primary":
    add_error("missing_integration_contract", "integration_contract.missing_item_id must be tests.integration.primary")
if integration_contract.get("test_kind") != "rust_integration_test":
    add_error("missing_integration_contract", "integration_contract.test_kind must be rust_integration_test")
if string_set(integration_contract.get("required_modes"), "integration_contract.required_modes", "missing_integration_contract") != REQUIRED_MODES:
    add_error("missing_integration_contract", "integration_contract.required_modes must be strict+hardened")
required_counts = as_object(integration_contract.get("required_matrix_counts"), "integration_contract.required_matrix_counts", "missing_integration_contract")
if required_counts.get("evaluation_cases_min") != 4 or required_counts.get("required_cases_min") != 3:
    add_error("missing_integration_contract", "integration_contract matrix minima must bind 4 evaluation and 3 required cases")
required_outputs = string_set(integration_contract.get("required_output_artifacts"), "integration_contract.required_output_artifacts", "missing_integration_contract")
if len(required_outputs) < 2:
    add_error("missing_integration_contract", "integration_contract must declare log and report artifacts")
events.append(
    event(
        "integration_contract_validated",
        "fail" if len(errors) != integration_errors_before else "pass",
        "missing_integration_contract" if len(errors) != integration_errors_before else "none",
        required_outputs=sorted(required_outputs),
    )
)

bindings = as_array(contract.get("missing_item_bindings"), "missing_item_bindings", "missing_integration_binding")
binding_errors_before = len(errors)
integration_binding = None
for binding in bindings:
    row = as_object(binding, "missing_item_bindings[]", "missing_integration_binding")
    if row.get("missing_item_id") == "tests.integration.primary":
        integration_binding = row
        break
if integration_binding is None:
    add_error("missing_integration_binding", "missing binding for tests.integration.primary")
else:
    impl_refs = string_set(integration_binding.get("implementation_refs"), "implementation_refs", "missing_integration_binding")
    test_refs = string_set(integration_binding.get("test_refs"), "test_refs", "missing_integration_binding")
    runtime_validation = string_set(integration_binding.get("runtime_validation"), "runtime_validation", "missing_integration_binding")
    missing_impl = missing(REQUIRED_IMPL_REFS, impl_refs)
    missing_tests = missing(REQUIRED_TEST_REFS, test_refs)
    if missing_impl:
        add_error("missing_integration_binding", f"missing implementation refs: {missing_impl}")
    if missing_tests:
        add_error("missing_integration_binding", f"missing test refs: {missing_tests}")
    if "frankenlibc_harness::runtime_math_divergence_bounds::run_and_write" not in runtime_validation:
        add_error("missing_integration_binding", "runtime_validation must cite run_and_write integration path")
events.append(
    event(
        "integration_binding_validated",
        "fail" if len(errors) != binding_errors_before else "pass",
        "missing_integration_binding" if len(errors) != binding_errors_before else "none",
    )
)

harness_path = source_by_id.get("divergence_harness", {}).get("path", "")
gate_path = source_by_id.get("divergence_gate_script", {}).get("path", "")
existing_test_path = source_by_id.get("existing_integration_test", {}).get("path", "")
completion_test_path = source_by_id.get("completion_integration_test", {}).get("path", "")
surface_errors_before = len(errors)
if harness_path:
    source_contains(
        harness_path,
        {
            "RuntimeMathKernel::new_for_mode(SafetyLevel::Strict)",
            "RuntimeMathKernel::new_for_mode(SafetyLevel::Hardened)",
            "check_forbidden_rule",
            "RuntimeMathDivergenceBoundsReport",
            "case_log_entry",
        },
        "missing_harness_surface",
    )
if gate_path:
    source_contains(
        gate_path,
        {"runtime-math-divergence-bounds", "--workspace-root", "--log", "--report"},
        "missing_harness_surface",
    )
if existing_test_path:
    source_contains(
        existing_test_path,
        {"gate_script_emits_logs_and_report", "validate_log_file", "runtime_math_divergence_bounds.report.json"},
        "missing_test_binding",
    )
required_test_functions = as_object(contract.get("required_test_functions"), "required_test_functions", "missing_test_binding")
positive_tests = string_set(required_test_functions.get("positive"), "required_test_functions.positive", "missing_test_binding")
negative_tests = string_set(required_test_functions.get("negative"), "required_test_functions.negative", "missing_test_binding")
missing_positive = missing(REQUIRED_POSITIVE_TESTS, positive_tests)
missing_negative = missing(REQUIRED_NEGATIVE_TESTS, negative_tests)
if missing_positive:
    add_error("missing_test_binding", f"missing positive test declarations: {missing_positive}")
if missing_negative:
    add_error("missing_test_binding", f"missing negative test declarations: {missing_negative}")
if completion_test_path:
    source_contains(completion_test_path, REQUIRED_POSITIVE_TESTS | REQUIRED_NEGATIVE_TESTS, "missing_test_binding")
events.append(
    event(
        "harness_gate_surface_validated",
        "fail" if len(errors) != surface_errors_before else "pass",
        "missing_harness_surface" if len(errors) != surface_errors_before else "none",
    )
)

finish(
    {
        "source_artifact_count": len(source_by_id),
        "evaluation_cases": len(evaluation_cases),
        "required_cases": len(required_cases),
        "forbidden_divergences": len(forbidden_rules),
        "total_cases": len(evaluation_cases) + len(required_cases),
        "required_modes": sorted(REQUIRED_MODES),
    }
)
PY
