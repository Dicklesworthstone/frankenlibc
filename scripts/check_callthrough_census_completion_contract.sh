#!/usr/bin/env bash
# check_callthrough_census_completion_contract.sh -- bd-7ef9.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_CALLTHROUGH_CENSUS_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/callthrough_census_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_CALLTHROUGH_CENSUS_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/callthrough_census_completion}"
REPORT="${FRANKENLIBC_CALLTHROUGH_CENSUS_COMPLETION_REPORT:-${OUT_DIR}/callthrough_census_completion_contract.report.json}"
LOG="${FRANKENLIBC_CALLTHROUGH_CENSUS_COMPLETION_LOG:-${OUT_DIR}/callthrough_census_completion_contract.events.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
LOG = pathlib.Path(sys.argv[4])
OUT_DIR = pathlib.Path(sys.argv[5])
SOURCE_COMMIT = sys.argv[6]

SCHEMA = "callthrough_census_completion_contract.v1"
REPORT_SCHEMA = "callthrough_census_completion_contract.report.v1"
BEAD_ID = "bd-7ef9.1"
ORIGINAL_BEAD = "bd-7ef9"
TRACE_ID = "bd-7ef9.1::callthrough-census::completion::v1"

REQUIRED_ARTIFACT_IDS = {
    "support_matrix",
    "callthrough_census",
    "census_generator",
    "census_gate",
    "census_harness_test",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "migrations.primary",
    "telemetry.primary",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_callthrough_census_sources",
    "checker_accepts_callthrough_census_completion_contract",
    "checker_emits_structured_callthrough_telemetry",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_migration_binding",
    "checker_rejects_callthrough_summary_drift",
    "checker_rejects_missing_telemetry_binding",
}
REQUIRED_GATE_CHECKS = {
    "artifact_reproducible",
    "support_matrix_alignment",
    "module_counts_consistent",
    "wave_coverage_complete",
    "wave_dependencies_valid",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_unit_binding",
    "missing_migration_binding",
    "missing_telemetry_binding",
    "support_matrix_drift",
    "callthrough_census_drift",
    "decommission_sequence_drift",
    "base_gate_failed",
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
    return "callthrough_census_completion_contract_failed"


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


def binding_signature(item_id: str) -> str:
    if item_id == "tests.unit.primary":
        return "missing_unit_binding"
    if item_id == "migrations.primary":
        return "missing_migration_binding"
    if item_id == "telemetry.primary":
        return "missing_telemetry_binding"
    return "malformed_contract"


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


def validate_support_and_census(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    support = load_json(resolve(str(artifacts.get("support_matrix", {}).get("path", ""))), "support_matrix")
    census = load_json(resolve(str(artifacts.get("callthrough_census", {}).get("path", ""))), "callthrough_census")
    required_support = as_object(
        completion.get("required_support_matrix"),
        "completion_contract.required_support_matrix",
        "support_matrix_drift",
    )
    required_summary = as_object(
        completion.get("required_census_summary"),
        "completion_contract.required_census_summary",
        "callthrough_census_drift",
    )
    support_summary = as_object(support.get("summary"), "support_matrix.summary", "support_matrix_drift")
    census_source = as_object(census.get("source"), "callthrough_census.source", "callthrough_census_drift")
    census_summary = as_object(census.get("summary"), "callthrough_census.summary", "callthrough_census_drift")

    actual_support = {
        "total_exported": support.get("total_exported"),
        "status_summary_callthrough": support_summary.get("GlibcCallThrough", support_summary.get("glibc_call_through", 0)),
        "derived_callthrough_symbols": census_source.get("derived_callthrough_symbols"),
        "summary_delta": census_source.get("summary_delta"),
    }
    for key, expected in required_support.items():
        if actual_support.get(key) != expected:
            add_error("support_matrix_drift", f"{key} expected {expected!r} got {actual_support.get(key)!r}")
    for key, expected in required_summary.items():
        if census_summary.get(key) != expected:
            add_error("callthrough_census_drift", f"summary.{key} expected {expected!r} got {census_summary.get(key)!r}")

    for key in ["module_census", "symbol_census", "decommission_waves"]:
        rows = as_array(census.get(key), f"callthrough_census.{key}", "callthrough_census_drift")
        if required_summary.get("symbol_count") == 0 and rows:
            add_error("decommission_sequence_drift", f"{key} must be empty when symbol_count is zero")

    events.append(
        event(
            "support_matrix_and_census_validated",
            "pass",
            total_exported=actual_support.get("total_exported"),
            callthrough_count=actual_support.get("derived_callthrough_symbols"),
            wave_count=census_summary.get("wave_count"),
        )
    )


def validate_generator_and_gate(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    generator_path = str(artifacts.get("census_generator", {}).get("path", ""))
    gate_path = str(artifacts.get("census_gate", {}).get("path", ""))
    generator_anchors = string_set(
        completion.get("required_generator_anchors"),
        "completion_contract.required_generator_anchors",
        "missing_migration_binding",
    )
    require_contains(generator_path, generator_anchors, "decommission_sequence_drift")
    gate_checks = string_set(
        completion.get("required_gate_checks"),
        "completion_contract.required_gate_checks",
        "missing_telemetry_binding",
    )
    missing_checks = missing(REQUIRED_GATE_CHECKS, gate_checks)
    if missing_checks:
        add_error("missing_telemetry_binding", f"missing gate checks: {missing_checks}")
    require_contains(gate_path, gate_checks | {"callthrough_census.log.jsonl", "artifact_refs", "PASS: wrote callthrough census log"}, "missing_telemetry_binding")
    events.append(
        event(
            "generator_and_gate_validated",
            "pass" if not missing_checks else "fail",
            "none" if not missing_checks else "missing_telemetry_binding",
            generator_anchors=len(generator_anchors),
            gate_checks=len(gate_checks),
        )
    )


def run_base_gate(artifacts: dict[str, dict[str, Any]]) -> None:
    gate_path = str(artifacts.get("census_gate", {}).get("path", ""))
    if not gate_path:
        add_error("base_gate_failed", "census_gate path missing")
        return
    try:
        output = subprocess.run(
            ["bash", str(resolve(gate_path))],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
    except Exception as exc:
        add_error("base_gate_failed", f"{gate_path} could not run: {exc}")
        return
    combined = output.stdout + "\n" + output.stderr
    if output.returncode != 0:
        add_error("base_gate_failed", f"{gate_path} failed rc={output.returncode}: {combined}")
    for marker in [
        "PASS: callthrough census artifact is current",
        "PASS: callthrough census validated",
        "PASS: wrote callthrough census log",
    ]:
        if marker not in combined:
            add_error("base_gate_failed", f"{gate_path} output missing marker: {marker}")
    events.append(
        event(
            "base_callthrough_census_gate_replayed",
            "pass" if output.returncode == 0 else "fail",
            "none" if output.returncode == 0 else "base_gate_failed",
        )
    )


def validate_harness_and_completion_tests(contract: dict[str, Any], completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    harness_path = str(artifacts.get("census_harness_test", {}).get("path", ""))
    harness_tests = string_set(
        completion.get("required_harness_tests"),
        "completion_contract.required_harness_tests",
        "missing_unit_binding",
    )
    require_contains(harness_path, harness_tests | {"structured log row missing", "generator check should pass"}, "missing_unit_binding")

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


def validate_log_fields(completion: dict[str, Any]) -> None:
    required_log_fields = string_set(
        completion.get("required_log_fields"),
        "completion_contract.required_log_fields",
        "missing_telemetry_binding",
    )
    missing_fields = missing(
        {
            "trace_id",
            "mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "errno",
            "latency_ns",
            "artifact_refs",
            "symbol_count",
            "module_count",
            "wave_count",
        },
        required_log_fields,
    )
    if missing_fields:
        add_error("missing_telemetry_binding", f"missing required log fields: {missing_fields}")
    events.append(
        event(
            "telemetry_contract_validated",
            "pass" if not missing_fields else "fail",
            "none" if not missing_fields else "missing_telemetry_binding",
            log_fields=len(required_log_fields),
        )
    )


def finish(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        events.append(event("callthrough_census_completion_contract_validated", "pass"))
    else:
        events.append(
            event(
                "callthrough_census_completion_contract_failed",
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
            "PASS callthrough census completion contract "
            f"sources={summary.get('source_artifacts', 0)} events={len(events)}"
        )
        sys.exit(0)
    print(
        "FAIL callthrough census completion contract "
        f"signature={primary_signature()} errors={len(errors)} report={rel(REPORT)}",
        file=sys.stderr,
    )
    sys.exit(1)


def main() -> None:
    contract = as_object(load_json(CONTRACT, "contract"), "contract")
    artifacts = artifact_map(contract)
    completion = validate_contract_shape(contract)
    validate_missing_item_bindings(contract)
    validate_support_and_census(completion, artifacts)
    validate_generator_and_gate(completion, artifacts)
    run_base_gate(artifacts)
    validate_harness_and_completion_tests(contract, completion, artifacts)
    validate_log_fields(completion)
    finish(
        {
            "source_artifacts": len(artifacts),
            "missing_items": len(REQUIRED_MISSING_ITEMS),
            "events": len(events),
        }
    )


main()
PY
