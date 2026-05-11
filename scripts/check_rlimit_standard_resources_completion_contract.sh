#!/usr/bin/env bash
# Completion gate for bd-0ul0z.1 standard Linux RLIMIT unit evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${1:-$ROOT/tests/conformance/rlimit_standard_resources_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RLIMIT_STANDARD_RESOURCES_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="$OUT_DIR/rlimit_standard_resources_completion_contract.report.json"
LOG="$OUT_DIR/rlimit_standard_resources_completion_contract.log.jsonl"

mkdir -p "$OUT_DIR"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "rlimit_standard_resources_completion_contract.v1"
COMPLETION_BEAD = "bd-0ul0z.1"
ORIGINAL_BEAD = "bd-0ul0z"
TRACE_ID = "bd-0ul0z.1::rlimit-standard-resources::v1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary"}
STANDARD_RESOURCES = {
    "RLIMIT_CPU",
    "RLIMIT_FSIZE",
    "RLIMIT_DATA",
    "RLIMIT_STACK",
    "RLIMIT_CORE",
    "RLIMIT_RSS",
    "RLIMIT_NPROC",
    "RLIMIT_NOFILE",
    "RLIMIT_MEMLOCK",
    "RLIMIT_AS",
    "RLIMIT_LOCKS",
    "RLIMIT_SIGPENDING",
    "RLIMIT_MSGQUEUE",
    "RLIMIT_NICE",
    "RLIMIT_RTPRIO",
    "RLIMIT_RTTIME",
}
FORMERLY_REJECTED = {
    "RLIMIT_RSS",
    "RLIMIT_NPROC",
    "RLIMIT_MEMLOCK",
    "RLIMIT_LOCKS",
    "RLIMIT_SIGPENDING",
    "RLIMIT_MSGQUEUE",
    "RLIMIT_NICE",
    "RLIMIT_RTPRIO",
    "RLIMIT_RTTIME",
}
EXPECTED_EVENTS = {
    "source_artifacts_validated",
    "completion_bindings_validated",
    "validator_source_validated",
    "unit_test_bindings_validated",
    "rlimit_standard_resources_completion_contract_pass",
}

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


SOURCE_COMMIT = git_head()


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def add_error(signature: str, message: str) -> None:
    errors.append({"signature": signature, "message": message})


def event(name: str, status: str, expected: Any, observed: Any) -> None:
    events.append(
        {
            "timestamp": timestamp(),
            "event": name,
            "status": status,
            "bead_id": COMPLETION_BEAD,
            "trace_id": TRACE_ID,
            "source_commit": SOURCE_COMMIT,
            "expected": expected,
            "observed": observed,
            "artifact_refs": [rel(REPORT), rel(LOG)],
        }
    )


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("invalid_json", f"{rel(path)} is not valid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        add_error("invalid_json", f"{rel(path)} must be a JSON object")
        return {}
    return value


def string_set(value: Any, context: str) -> set[str]:
    if not isinstance(value, list):
        add_error("invalid_contract_shape", f"{context} must be an array")
        return set()
    result: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            add_error("invalid_contract_shape", f"{context}[{index}] must be a non-empty string")
            continue
        result.add(item)
    return result


def source_text(path_text: str, context: str) -> str:
    path = ROOT / path_text
    if not path.is_file():
        add_error("missing_source_artifact", f"{context} references missing file {path_text}")
        return ""
    return path.read_text(encoding="utf-8")


def validate_file_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        add_error("invalid_file_line_ref", f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        add_error("invalid_file_line_ref", f"{context} must be a file:line string")
        return
    path = ROOT / path_text
    if not path.is_file():
        add_error("invalid_file_line_ref", f"{context} references missing file {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines):
        add_error("invalid_file_line_ref", f"{context} references line past EOF: {value}")
    elif not lines[line_no - 1].strip():
        add_error("invalid_file_line_ref", f"{context} references blank line: {value}")


def validate_source_artifacts(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        add_error("missing_source_artifacts", "source_artifacts must be a non-empty array")
        event("source_artifacts_validated", "fail", "non-empty source_artifacts", artifacts)
        return []
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            add_error("missing_source_artifacts", f"source_artifacts[{index}] must be an object")
            continue
        path_text = artifact.get("path")
        if not isinstance(path_text, str) or not path_text:
            add_error("missing_source_artifacts", f"source_artifacts[{index}].path is invalid")
            continue
        if not (ROOT / path_text).is_file():
            add_error("missing_source_artifacts", f"source artifact missing: {path_text}")
    status = "fail" if any(e["signature"] == "missing_source_artifacts" for e in errors) else "pass"
    event("source_artifacts_validated", status, "all artifacts exist", [a.get("path") for a in artifacts if isinstance(a, dict)])
    return [a for a in artifacts if isinstance(a, dict)]


def validate_bindings(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = manifest.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        add_error("missing_completion_binding", "completion_debt_evidence must be an object")
        event("completion_bindings_validated", "fail", sorted(EXPECTED_MISSING_ITEMS), [])
        return []
    bindings = evidence.get("missing_item_bindings")
    if not isinstance(bindings, list):
        add_error("missing_completion_binding", "missing_item_bindings must be an array")
        event("completion_bindings_validated", "fail", sorted(EXPECTED_MISSING_ITEMS), [])
        return []
    specs = {binding.get("spec_item") for binding in bindings if isinstance(binding, dict)}
    if specs != EXPECTED_MISSING_ITEMS:
        add_error("missing_completion_binding", f"expected {sorted(EXPECTED_MISSING_ITEMS)} but saw {sorted(str(s) for s in specs)}")
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            add_error("missing_completion_binding", f"missing_item_bindings[{index}] must be an object")
            continue
        for key in ("implementation_refs", "test_refs", "required_positive_tests", "required_negative_tests", "required_commands"):
            if not string_set(binding.get(key), f"missing_item_bindings[{index}].{key}"):
                add_error("missing_completion_binding", f"missing_item_bindings[{index}].{key} must be non-empty")
    status = "fail" if any(e["signature"] == "missing_completion_binding" for e in errors) else "pass"
    event("completion_bindings_validated", status, sorted(EXPECTED_MISSING_ITEMS), sorted(str(s) for s in specs))
    return [b for b in bindings if isinstance(b, dict)]


def validate_contract_header(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        add_error("contract_header_drift", "schema_version mismatch")
    if manifest.get("bead") != COMPLETION_BEAD:
        add_error("contract_header_drift", "bead mismatch")
    if manifest.get("original_bead") != ORIGINAL_BEAD:
        add_error("contract_header_drift", "original_bead mismatch")
    if manifest.get("trace_id") != TRACE_ID:
        add_error("contract_header_drift", "trace_id mismatch")
    threshold = manifest.get("completion_debt_evidence", {}).get("next_audit_score_threshold", 0)
    if int(threshold or 0) < 800:
        add_error("contract_header_drift", "next audit score threshold must be at least 800")


def validate_validator_source(runtime: dict[str, Any]) -> dict[str, str]:
    core_path = runtime.get("core_validator_path")
    abi_path = runtime.get("abi_path")
    if not isinstance(core_path, str) or not isinstance(abi_path, str):
        add_error("validator_source_drift", "core_validator_path and abi_path must be strings")
        event("validator_source_validated", "fail", "core and ABI validator paths", runtime)
        return {"core": "", "abi": ""}

    core = source_text(core_path, "core_validator_path")
    abi = source_text(abi_path, "abi_path")
    expected_expression = runtime.get("validator_expression")
    if not isinstance(expected_expression, str) or expected_expression not in core:
        add_error("validator_source_drift", "core validator expression is missing")
    if core.count("pub fn valid_resource") != 1:
        add_error("validator_source_drift", "core valid_resource function not found exactly once")
    if abi.count("res_core::valid_resource(resource)") < 2:
        add_error("validator_source_drift", "getrlimit and setrlimit must both use the core validator")
    for term in string_set(runtime.get("required_source_terms"), "required_source_terms"):
        if term not in (core + "\n" + abi):
            add_error("validator_source_drift", f"required source term missing: {term}")

    standard = string_set(runtime.get("required_standard_resources"), "required_standard_resources")
    formerly = string_set(runtime.get("formerly_rejected_resources"), "formerly_rejected_resources")
    if standard != STANDARD_RESOURCES:
        add_error("resource_set_drift", f"standard resources drifted: {sorted(standard)}")
    if formerly != FORMERLY_REJECTED:
        add_error("resource_set_drift", f"formerly rejected resources drifted: {sorted(formerly)}")
    if not formerly.issubset(standard):
        add_error("resource_set_drift", "formerly rejected resources must be a subset of standard resources")
    for resource in STANDARD_RESOURCES:
        if resource not in core:
            add_error("resource_set_drift", f"{resource} missing from core validator source")
    for resource in FORMERLY_REJECTED:
        if resource not in core:
            add_error("resource_set_drift", f"{resource} missing from core test coverage")

    status = "fail" if any(e["signature"] in {"validator_source_drift", "resource_set_drift"} for e in errors) else "pass"
    event(
        "validator_source_validated",
        status,
        {"standard_resources": sorted(STANDARD_RESOURCES), "formerly_rejected": sorted(FORMERLY_REJECTED)},
        {"standard_resources": sorted(standard), "formerly_rejected": sorted(formerly)},
    )
    return {"core": core, "abi": abi}


def validate_unit_groups(runtime: dict[str, Any]) -> list[dict[str, Any]]:
    groups = runtime.get("required_unit_test_groups")
    if not isinstance(groups, list) or not groups:
        add_error("unit_binding_drift", "required_unit_test_groups must be a non-empty array")
        event("unit_test_bindings_validated", "fail", "non-empty groups", groups)
        return []
    normalized: list[dict[str, Any]] = []
    for group_index, group in enumerate(groups):
        if not isinstance(group, dict):
            add_error("unit_binding_drift", f"required_unit_test_groups[{group_index}] must be an object")
            continue
        path_text = group.get("path")
        if not isinstance(path_text, str) or not path_text:
            add_error("unit_binding_drift", f"required_unit_test_groups[{group_index}].path is invalid")
            continue
        text = source_text(path_text, f"required_unit_test_groups[{group_index}].path")
        tests = string_set(group.get("tests"), f"required_unit_test_groups[{group_index}].tests")
        terms = string_set(group.get("required_terms"), f"required_unit_test_groups[{group_index}].required_terms")
        for test_name in tests:
            if f"fn {test_name}" not in text:
                add_error("unit_binding_drift", f"missing test {test_name} in {path_text}")
        for term in terms:
            if term not in text:
                add_error("unit_binding_drift", f"missing term {term} in {path_text}")
        normalized.append({"path": path_text, "tests": sorted(tests), "required_terms": sorted(terms)})
    status = "fail" if any(e["signature"] == "unit_binding_drift" for e in errors) else "pass"
    event("unit_test_bindings_validated", status, "declared tests and terms present", normalized)
    return normalized


def main() -> int:
    manifest = load_json(CONTRACT)
    validate_contract_header(manifest)
    artifacts = validate_source_artifacts(manifest)
    bindings = validate_bindings(manifest)
    runtime = manifest.get("rlimit_standard_resource_contract")
    if not isinstance(runtime, dict):
        add_error("validator_source_drift", "rlimit_standard_resource_contract must be an object")
        runtime = {}
    validate_validator_source(runtime)
    unit_groups = validate_unit_groups(runtime)

    status = "fail" if errors else "pass"
    if status == "pass":
        event(
            "rlimit_standard_resources_completion_contract_pass",
            "pass",
            sorted(EXPECTED_EVENTS),
            sorted(e["event"] for e in events) + ["rlimit_standard_resources_completion_contract_pass"],
        )
    else:
        event(
            "rlimit_standard_resources_completion_contract_failed",
            "fail",
            sorted(EXPECTED_EVENTS),
            [error["signature"] for error in errors],
        )

    report = {
        "schema_version": EXPECTED_SCHEMA,
        "bead_id": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "status": status,
        "summary": {
            "binding_count": len(bindings),
            "standard_resource_count": len(STANDARD_RESOURCES),
            "formerly_rejected_resource_count": len(FORMERLY_REJECTED),
            "unit_group_count": len(unit_groups),
        },
        "source_artifacts": artifacts,
        "missing_item_bindings": bindings,
        "artifact_refs": [rel(REPORT), rel(LOG)],
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")
    if status == "pass":
        print(
            "PASS rlimit_standard_resources_completion_contract "
            f"resources={len(STANDARD_RESOURCES)} formerly_rejected={len(FORMERLY_REJECTED)} "
            f"bindings={len(bindings)} unit_groups={len(unit_groups)} report={rel(REPORT)} log={rel(LOG)}"
        )
        return 0
    print(
        "FAIL rlimit_standard_resources_completion_contract "
        + ", ".join(error["signature"] for error in errors),
        file=sys.stderr,
    )
    return 1


sys.exit(main())
PY
