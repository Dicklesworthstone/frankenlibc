#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_USER_WORKLOAD_ACCEPTANCE_MATRIX_COMPLETION_CONTRACT:-$ROOT/tests/conformance/user_workload_acceptance_matrix_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_USER_WORKLOAD_ACCEPTANCE_MATRIX_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_USER_WORKLOAD_ACCEPTANCE_MATRIX_COMPLETION_REPORT:-$OUT_DIR/user_workload_acceptance_matrix_completion_contract.report.json}"
LOG="${FRANKENLIBC_USER_WORKLOAD_ACCEPTANCE_MATRIX_COMPLETION_LOG:-$OUT_DIR/user_workload_acceptance_matrix_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "user_workload_acceptance_matrix_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "user_workload_acceptance_matrix_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-bp8fl.10.1"
COMPLETION_BEAD = "bd-bp8fl.10.1.1"

errors: list[str] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


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


def as_list(value: Any, context: str, allow_empty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    return value


def string_set(value: Any, context: str) -> set[str]:
    result: set[str] = set()
    for index, item in enumerate(as_list(value, context)):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.add(item)
    return result


def source_text(path_text: str, context: str) -> str:
    path = ROOT / path_text
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {path_text}: {exc}")
        return ""


def validate_source_refs(manifest: dict[str, Any]) -> None:
    source_artifacts = manifest.get("source_artifacts", {})
    if not isinstance(source_artifacts, dict) or not source_artifacts:
        err("source_artifacts must be a non-empty object")
        return

    for artifact_id, path_text in source_artifacts.items():
        if not isinstance(path_text, str) or not path_text:
            err(f"source_artifacts.{artifact_id} must be a non-empty string")
            continue
        require((ROOT / path_text).exists(), f"source artifact missing: {artifact_id}: {path_text}")

    evidence = manifest.get("completion_debt_evidence", {})
    refs = as_list(evidence.get("implementation_refs"), "completion_debt_evidence.implementation_refs")
    for ref in refs:
        if not isinstance(ref, dict):
            err("implementation_refs entries must be objects")
            continue
        ref_id = ref.get("id", "<missing-ref-id>")
        path_text = ref.get("path")
        if not isinstance(path_text, str) or not path_text:
            err(f"implementation ref {ref_id} is missing path")
            continue
        text = source_text(path_text, f"implementation ref {ref_id}")
        for needle in as_list(ref.get("required_text"), f"implementation ref {ref_id}.required_text"):
            if not isinstance(needle, str) or not needle:
                err(f"implementation ref {ref_id} has invalid required text")
            elif needle not in text:
                err(f"implementation ref {ref_id} missing required text {needle!r} in {path_text}")

    test_sources = evidence.get("test_sources", {})
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return
    for source_id, source in test_sources.items():
        if not isinstance(source, dict):
            err(f"test source {source_id} must be an object")
            continue
        path_text = source.get("path")
        if not isinstance(path_text, str) or not path_text:
            err(f"test source {source_id} is missing path")
            continue
        text = source_text(path_text, f"test source {source_id}")
        for test_ref in as_list(source.get("required_test_refs"), f"test source {source_id}.required_test_refs"):
            if not isinstance(test_ref, str) or not test_ref:
                err(f"test source {source_id} has invalid test ref")
            elif test_ref not in text:
                err(f"test source {source_id} missing required test ref {test_ref!r}")


def run_source_checker(source_checker: str) -> None:
    proc = subprocess.run(
        ["bash", source_checker],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        err(
            "source user workload acceptance checker failed: "
            f"exit={proc.returncode} stdout={proc.stdout[:1000]!r} stderr={proc.stderr[:1000]!r}"
        )


def validate_required_contract(manifest: dict[str, Any], matrix: dict[str, Any]) -> dict[str, Any]:
    contract = manifest.get("required_source_contract", {})
    if not isinstance(contract, dict):
        err("required_source_contract must be an object")
        contract = {}

    summary_exact = contract.get("summary_exact", {})
    if not isinstance(summary_exact, dict):
        err("required_source_contract.summary_exact must be an object")
        summary_exact = {}

    required_domains = string_set(contract.get("required_domains"), "required_source_contract.required_domains")
    required_taxonomy = string_set(contract.get("required_taxonomy_ids"), "required_source_contract.required_taxonomy_ids")
    required_log_fields = string_set(contract.get("required_log_fields"), "required_source_contract.required_log_fields")
    required_checks = string_set(
        contract.get("required_source_checker_checks"),
        "required_source_contract.required_source_checker_checks",
    )

    actual_domains = string_set(matrix.get("required_domains"), "source matrix required_domains")
    actual_log_fields = string_set(matrix.get("required_log_fields"), "source matrix required_log_fields")
    taxonomy = matrix.get("failure_taxonomy", [])
    taxonomy_ids = {
        item.get("id")
        for item in taxonomy
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    summary = matrix.get("summary", {})
    if not isinstance(summary, dict):
        err("source matrix summary must be an object")
        summary = {}

    require(
        required_domains <= actual_domains,
        f"source matrix missing required domains: {sorted(required_domains - actual_domains)}",
    )
    require(
        required_taxonomy <= taxonomy_ids,
        f"source matrix missing required taxonomy ids: {sorted(required_taxonomy - taxonomy_ids)}",
    )
    require(
        required_log_fields <= actual_log_fields,
        f"source matrix missing required log fields: {sorted(required_log_fields - actual_log_fields)}",
    )

    for field, expected in summary_exact.items():
        actual = summary.get(field)
        if actual != expected:
            err(f"source matrix summary.{field} expected {expected!r}, got {actual!r}")

    policy_required = contract.get("replacement_level_policy", {})
    policy_actual = matrix.get("replacement_level_policy", {})
    if not isinstance(policy_required, dict) or not isinstance(policy_actual, dict):
        err("replacement level policies must be objects")
    else:
        for field, expected in policy_required.items():
            if policy_actual.get(field) != expected:
                err(f"replacement_level_policy.{field} expected {expected!r}, got {policy_actual.get(field)!r}")

    return {
        "summary_exact": summary_exact,
        "required_domains": sorted(required_domains),
        "required_taxonomy_ids": sorted(required_taxonomy),
        "required_log_fields": sorted(required_log_fields),
        "required_source_checker_checks": sorted(required_checks),
    }


def validate_source_report(manifest: dict[str, Any]) -> dict[str, Any]:
    report = load_json(ROOT / "target/conformance/user_workload_acceptance_matrix.report.json", "source report")
    if not report:
        return {}

    require(report.get("status") == "pass", f"source report status must be pass, got {report.get('status')!r}")
    checks = report.get("checks", {})
    if not isinstance(checks, dict):
        err("source report checks must be an object")
        checks = {}

    required_checks = string_set(
        manifest.get("required_source_contract", {}).get("required_source_checker_checks"),
        "required_source_contract.required_source_checker_checks",
    )
    for check in required_checks:
        if checks.get(check) != "pass":
            err(f"source report check {check} did not pass")

    summary_exact = manifest.get("required_source_contract", {}).get("summary_exact", {})
    if isinstance(summary_exact, dict):
        for field, expected in summary_exact.items():
            if report.get(field) != expected:
                err(f"source report {field} expected {expected!r}, got {report.get(field)!r}")

    return report


def validate_missing_item_bindings(manifest: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "tests.unit.primary",
        "tests.e2e.primary",
        "tests.conformance.primary",
        "telemetry.primary",
    }
    bindings = as_list(manifest.get("missing_item_bindings"), "missing_item_bindings")
    seen: set[str] = set()
    telemetry_events: set[str] = set()

    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing_item_bindings entries must be objects")
            continue
        item_id = binding.get("id")
        if not isinstance(item_id, str) or not item_id:
            err("missing item binding without id")
            continue
        seen.add(item_id)
        if item_id == "telemetry.primary":
            telemetry_events = string_set(binding.get("required_log_events"), "telemetry.primary.required_log_events")
        if not (binding.get("required_test_refs") or binding.get("required_scripts") or binding.get("required_artifacts")):
            err(f"missing item binding {item_id} must cite tests, scripts, or artifacts")

    require(expected <= seen, f"missing item bindings absent: {sorted(expected - seen)}")

    telemetry = manifest.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        telemetry = {}
    contract_events = string_set(telemetry.get("log_events"), "telemetry_contract.log_events")
    require(telemetry_events <= contract_events, "telemetry.primary events must be included in telemetry_contract.log_events")

    return {
        "expected_missing_items": sorted(expected),
        "seen_missing_items": sorted(seen),
        "telemetry_events": sorted(contract_events),
    }


def source_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def log_entry(
    event: str,
    scenario_id: str,
    status: str,
    commit: str,
    artifact_refs: list[str],
    details: dict[str, Any],
    seq: int,
) -> dict[str, Any]:
    return {
        "timestamp": "2026-05-10T00:00:00Z",
        "trace_id": f"{COMPLETION_BEAD}::user-workload-acceptance-completion::{seq:03d}",
        "level": "info" if status == "pass" else "error",
        "event": event,
        "bead_id": COMPLETION_BEAD,
        "stream": "conformance",
        "gate": "user_workload_acceptance_matrix_completion_contract",
        "scenario_id": scenario_id,
        "runtime_mode": "strict",
        "replacement_level": "L0",
        "api_family": "user_workload_acceptance",
        "symbol": "*",
        "oracle_kind": "persona_workload_claim_gate",
        "expected": "unit/e2e/conformance/telemetry completion bindings are present",
        "actual": status,
        "outcome": status,
        "latency_ns": 0,
        "artifact_refs": artifact_refs,
        "source_commit": commit,
        "target_dir": rel(ROOT / "target/conformance"),
        "failure_signature": "none" if status == "pass" else "; ".join(errors),
        "details": details,
    }


def write_outputs(
    manifest: dict[str, Any],
    source_report: dict[str, Any],
    contract_summary: dict[str, Any],
    binding_summary: dict[str, Any],
) -> None:
    status = "pass" if not errors else "fail"
    commit = source_commit()
    artifact_refs = [
        "tests/conformance/user_workload_acceptance_matrix_completion_contract.v1.json",
        "scripts/check_user_workload_acceptance_matrix_completion_contract.sh",
        "crates/frankenlibc-harness/tests/user_workload_acceptance_matrix_completion_contract_test.rs",
        "tests/conformance/user_workload_acceptance_matrix.v1.json",
        "target/conformance/user_workload_acceptance_matrix.report.json",
        "target/conformance/user_workload_acceptance_matrix.log.jsonl",
        "target/conformance/user_workload_acceptance_matrix_completion_contract.report.json",
        "target/conformance/user_workload_acceptance_matrix_completion_contract.log.jsonl",
    ]
    events = [
        "user_workload_acceptance_completion_summary",
        "user_workload_acceptance_source_gate_bound",
        "user_workload_acceptance_completion_contract_pass" if status == "pass" else "user_workload_acceptance_completion_contract_failed",
    ]

    summary_exact = contract_summary.get("summary_exact", {})
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "events": events,
        "summary": summary_exact,
        "source_report_status": source_report.get("status"),
        "source_checks": source_report.get("checks", {}),
        "missing_item_bindings": binding_summary,
        "required_domains": contract_summary.get("required_domains", []),
        "required_taxonomy_ids": contract_summary.get("required_taxonomy_ids", []),
        "required_log_fields": contract_summary.get("required_log_fields", []),
        "errors": errors,
        "artifact_refs": artifact_refs,
        "source_commit": commit,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    records = [
        log_entry(
            events[0],
            "completion-summary",
            status,
            commit,
            artifact_refs,
            {
                "summary": summary_exact,
                "runtime_modes_covered": ["strict", "hardened"],
                "replacement_levels_covered": ["L0", "L1", "L2", "L3"],
            },
            1,
        ),
        log_entry(
            events[1],
            "source-gate-bound",
            status,
            commit,
            artifact_refs,
            {"source_report_status": source_report.get("status"), "source_checks": source_report.get("checks", {})},
            2,
        ),
        log_entry(events[2], "completion-contract-result", status, commit, artifact_refs, {"errors": errors}, 3),
    ]
    LOG.write_text("\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")

    print(json.dumps(report, indent=2, sort_keys=True))


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

validate_source_refs(manifest)

source_artifacts = manifest.get("source_artifacts", {})
source_checker = source_artifacts.get("source_checker") if isinstance(source_artifacts, dict) else None
if isinstance(source_checker, str):
    run_source_checker(source_checker)
else:
    err("source_artifacts.source_checker must be present")

matrix_path = source_artifacts.get("source_matrix") if isinstance(source_artifacts, dict) else None
matrix = load_json(ROOT / matrix_path, "source matrix") if isinstance(matrix_path, str) else {}
if not matrix:
    err("source_artifacts.source_matrix must point to readable JSON")

contract_summary = validate_required_contract(manifest, matrix)
source_report = validate_source_report(manifest)
binding_summary = validate_missing_item_bindings(manifest)
write_outputs(manifest, source_report, contract_summary, binding_summary)
raise SystemExit(0 if not errors else 1)
PY
