#!/usr/bin/env bash
# check_env_invariants_completion_contract.sh -- bd-747.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_ENV_INVARIANTS_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/env_invariants_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_ENV_INVARIANTS_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/env_invariants_completion}"
REPORT="${FRANKENLIBC_ENV_INVARIANTS_COMPLETION_REPORT:-${OUT_DIR}/env_invariants_completion_contract.report.json}"
LOG="${FRANKENLIBC_ENV_INVARIANTS_COMPLETION_LOG:-${OUT_DIR}/env_invariants_completion_contract.events.jsonl}"
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

SCHEMA = "env_invariants_completion_contract.v1"
REPORT_SCHEMA = "env_invariants_completion_contract.report.v1"
BEAD_ID = "bd-747.1"
ORIGINAL_BEAD = "bd-747"
TRACE_ID = "bd-747.1::env-invariants::completion::v1"

REQUIRED_ARTIFACT_IDS = {
    "core_env_validation",
    "abi_env_functions",
    "metamorphic_env_tests",
    "secure_getenv_diff_tests",
    "stdlib_env_regressions",
    "env_fuzz_shadow_model",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_env_invariant_sources",
    "checker_accepts_env_invariants_completion_contract",
    "checker_emits_structured_env_telemetry",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_e2e_binding",
    "checker_rejects_missing_fuzz_anchor",
    "checker_rejects_missing_telemetry_binding",
}
REQUIRED_FUZZ_ANCHORS = {
    "enum EnvOp",
    "SetMalformed",
    "BTreeMap<Vec<u8>, Vec<u8>>",
    "ENV_LOCK",
    "reset_env();",
    "Final sweep",
}
REQUIRED_TELEMETRY_MARKERS = {
    "runtime_policy::observe(ApiFamily::Stdlib",
    "getenv_metamorphic_coverage_report",
    "secure_getenv_diff_coverage_report",
    "libc getenv + setenv + unsetenv + secure_getenv",
    "libc secure_getenv",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_unit_binding",
    "missing_e2e_binding",
    "missing_telemetry_binding",
    "env_core_validation_drift",
    "env_abi_implementation_drift",
    "env_e2e_test_drift",
    "env_regression_test_drift",
    "env_fuzz_shadow_model_drift",
    "env_telemetry_drift",
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
    return "env_invariants_completion_contract_failed"


def load_json(path: pathlib.Path, context: str) -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("malformed_contract", f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


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


def read_source(path_text: str, signature: str) -> str:
    path = resolve(path_text)
    try:
        artifact_refs.add(rel(path))
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"cannot read {path_text}: {exc}")
        return ""


def require_contains(path_text: str, needles: set[str], signature: str) -> None:
    text = read_source(path_text, signature)
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
    missing_missing_items = missing(REQUIRED_MISSING_ITEMS, missing_items)
    if missing_missing_items:
        for item in missing_missing_items:
            add_error(f"missing_{item.split('.')[0]}_binding", f"missing item id {item}")
    events.append(
        event(
            "completion_contract_shape_validated",
            "pass" if not missing_missing_items else "fail",
            "none" if not missing_missing_items else "malformed_contract",
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
    events.append(
        event(
            "missing_item_bindings_validated",
            "pass",
            binding_count=len(by_id),
        )
    )


def binding_signature(item_id: str) -> str:
    if item_id == "tests.unit.primary":
        return "missing_unit_binding"
    if item_id == "tests.e2e.primary":
        return "missing_e2e_binding"
    if item_id == "telemetry.primary":
        return "missing_telemetry_binding"
    return "malformed_contract"


def validate_test_bindings(contract: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    test_fns = as_object(contract.get("required_test_functions"), "required_test_functions")
    positive = string_set(test_fns.get("positive"), "required_test_functions.positive", "missing_test_binding")
    negative = string_set(test_fns.get("negative"), "required_test_functions.negative", "missing_test_binding")
    missing_positive = missing(REQUIRED_POSITIVE_TESTS, positive)
    missing_negative = missing(REQUIRED_NEGATIVE_TESTS, negative)
    if missing_positive:
        add_error("missing_test_binding", f"missing positive tests: {missing_positive}")
    if missing_negative:
        add_error("missing_test_binding", f"missing negative tests: {missing_negative}")
    harness = artifacts.get("completion_harness_test", {}).get("path", "")
    if isinstance(harness, str):
        require_contains(harness, REQUIRED_POSITIVE_TESTS | REQUIRED_NEGATIVE_TESTS, "missing_test_binding")
    events.append(
        event(
            "test_surfaces_validated",
            "pass" if not missing_positive and not missing_negative else "fail",
            "none" if not missing_positive and not missing_negative else "missing_test_binding",
            positive_tests=len(positive),
            negative_tests=len(negative),
        )
    )


def validate_core(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    path = artifacts.get("core_env_validation", {}).get("path", "")
    if not isinstance(path, str):
        add_error("env_core_validation_drift", "core_env_validation artifact missing path")
        return
    required_tests = string_set(
        completion.get("required_unit_tests"),
        "completion_contract.required_unit_tests",
        "missing_unit_binding",
    )
    require_contains(
        path,
        {
            "pub fn valid_env_name",
            "pub fn valid_env_value",
            "pub fn entry_matches",
            "pub fn entry_value",
            "!name.is_empty()",
            "!name.contains(&b'=')",
            "!name.contains(&0)",
        }
        | required_tests,
        "env_core_validation_drift",
    )
    events.append(event("core_env_validation_validated", "pass", unit_tests=len(required_tests)))


def validate_abi(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    path = artifacts.get("abi_env_functions", {}).get("path", "")
    if not isinstance(path, str):
        add_error("env_abi_implementation_drift", "abi_env_functions artifact missing path")
        return
    symbols = string_set(
        completion.get("required_symbols"),
        "completion_contract.required_symbols",
        "env_abi_implementation_drift",
    )
    required = {f"pub unsafe extern \"C\" fn {symbol}" for symbol in symbols}
    required |= {
        "frankenlibc_core::stdlib::valid_env_name",
        "frankenlibc_core::stdlib::valid_env_value",
        "runtime_policy::decide(",
        "runtime_policy::observe(ApiFamily::Stdlib",
        "set_abi_errno(libc::EINVAL)",
        "native_getenv",
        "native_setenv",
        "native_unsetenv",
    }
    require_contains(path, required, "env_abi_implementation_drift")
    text = read_source(path, "env_abi_implementation_drift")
    observe_count = text.count("runtime_policy::observe(ApiFamily::Stdlib")
    if observe_count < 6:
        add_error("env_telemetry_drift", f"stdlib_abi observe count {observe_count} < 6")
    events.append(
        event(
            "abi_env_functions_validated",
            "pass",
            required_symbols=len(symbols),
            observe_count=observe_count,
        )
    )


def validate_tests(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    e2e_tests = string_set(
        completion.get("required_e2e_tests"),
        "completion_contract.required_e2e_tests",
        "missing_e2e_binding",
    )
    regressions = string_set(
        completion.get("required_regression_tests"),
        "completion_contract.required_regression_tests",
        "missing_unit_binding",
    )
    metamorphic = artifacts.get("metamorphic_env_tests", {}).get("path", "")
    secure_diff = artifacts.get("secure_getenv_diff_tests", {}).get("path", "")
    stdlib_tests = artifacts.get("stdlib_env_regressions", {}).get("path", "")
    if isinstance(metamorphic, str):
        require_contains(
            metamorphic,
            {test for test in e2e_tests if test.startswith("metamorphic_")}
            | {
                "static ENV_LOCK: Mutex<()>",
                "getenv_metamorphic_coverage_report",
                "divergences",
            },
            "env_e2e_test_drift",
        )
    if isinstance(secure_diff, str):
        require_contains(
            secure_diff,
            {test for test in e2e_tests if test.startswith("diff_")}
            | {
                "secure_getenv_diff_coverage_report",
                "unsafe extern \"C\"",
                "divergences",
            },
            "env_e2e_test_drift",
        )
    if isinstance(stdlib_tests, str):
        require_contains(stdlib_tests, regressions, "env_regression_test_drift")
    events.append(
        event(
            "env_test_sources_validated",
            "pass",
            e2e_tests=len(e2e_tests),
            regression_tests=len(regressions),
        )
    )


def validate_fuzz(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    anchors = string_set(
        completion.get("required_fuzz_anchors"),
        "completion_contract.required_fuzz_anchors",
        "env_fuzz_shadow_model_drift",
    )
    missing_anchors = missing(REQUIRED_FUZZ_ANCHORS, anchors)
    if missing_anchors:
        add_error("env_fuzz_shadow_model_drift", f"missing required fuzz anchors: {missing_anchors}")
    path = artifacts.get("env_fuzz_shadow_model", {}).get("path", "")
    if not isinstance(path, str):
        add_error("env_fuzz_shadow_model_drift", "env_fuzz_shadow_model artifact missing path")
        return
    require_contains(path, anchors, "env_fuzz_shadow_model_drift")
    events.append(event("env_fuzz_shadow_model_validated", "pass", anchors=len(anchors)))


def validate_telemetry(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    markers = string_set(
        completion.get("required_telemetry_markers"),
        "completion_contract.required_telemetry_markers",
        "missing_telemetry_binding",
    )
    missing_required_markers = missing(REQUIRED_TELEMETRY_MARKERS, markers)
    if missing_required_markers:
        add_error(
            "missing_telemetry_binding",
            f"missing required telemetry markers: {missing_required_markers}",
        )
    if not markers:
        add_error("missing_telemetry_binding", "telemetry marker set cannot be empty")
    haystack = ""
    for artifact_id in [
        "abi_env_functions",
        "metamorphic_env_tests",
        "secure_getenv_diff_tests",
        "completion_gate",
    ]:
        path = artifacts.get(artifact_id, {}).get("path", "")
        if isinstance(path, str):
            haystack += "\n" + read_source(path, "env_telemetry_drift")
    missing_markers = sorted(marker for marker in markers if marker not in haystack)
    if missing_markers:
        add_error("env_telemetry_drift", f"missing telemetry markers: {missing_markers}")
    events.append(
        event(
            "env_telemetry_validated",
            "pass" if not missing_markers else "fail",
            "none" if not missing_markers else "env_telemetry_drift",
            markers=len(markers),
        )
    )


def finish(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        events.append(event("env_invariants_completion_contract_validated", "pass"))
    else:
        events.append(
            event(
                "env_invariants_completion_contract_failed",
                "fail",
                primary_signature(),
            )
        )
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
            "PASS env invariants completion contract "
            f"sources={summary.get('source_artifacts', 0)} events={len(events)}"
        )
        sys.exit(0)
    print(
        "FAIL env invariants completion contract "
        f"signature={primary_signature()} errors={len(errors)} report={rel(REPORT)}",
        file=sys.stderr,
    )
    sys.exit(1)


def main() -> None:
    contract = as_object(load_json(CONTRACT, "contract"), "contract")
    artifacts = artifact_map(contract)
    completion = validate_contract_shape(contract)
    validate_missing_item_bindings(contract)
    validate_core(completion, artifacts)
    validate_abi(completion, artifacts)
    validate_tests(completion, artifacts)
    validate_fuzz(completion, artifacts)
    validate_telemetry(completion, artifacts)
    validate_test_bindings(contract, artifacts)
    finish(
        {
            "source_artifacts": len(artifacts),
            "missing_items": len(REQUIRED_MISSING_ITEMS),
            "events": len(events),
        }
    )


main()
PY
