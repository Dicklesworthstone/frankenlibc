#!/usr/bin/env bash
# check_optimization_proof_ledger_completion_contract.sh -- fail-closed evidence gate for bd-30o.2.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${OPTIMIZATION_PROOF_LEDGER_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/optimization_proof_ledger_completion_contract.v1.json}"
OUT_DIR="${OPTIMIZATION_PROOF_LEDGER_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${OPTIMIZATION_PROOF_LEDGER_COMPLETION_REPORT:-${OUT_DIR}/optimization_proof_ledger_completion_contract.report.json}"
LOG="${OPTIMIZATION_PROOF_LEDGER_COMPLETION_LOG:-${OUT_DIR}/optimization_proof_ledger_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

BEAD_ID = "bd-30o.2"
COMPLETION_DEBT_BEAD_ID = "bd-30o.2.1"
MANIFEST_ID = "optimization-proof-ledger-completion-contract"
REPORT_SCHEMA = "optimization_proof_ledger_completion_contract.report.v1"


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str], context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{context} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{context} must be a JSON object")
        return {}
    return value


def read_text(path_text: str, errors: list[str], context: str) -> str:
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} missing file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{context} unreadable: {path_text}: {exc}")
        return ""


def require_strings(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    strings = []
    for item in value:
        if not isinstance(item, str) or not item:
            errors.append(f"{context} entries must be non-empty strings")
            continue
        strings.append(item)
    return strings


def validate_source_artifacts(contract: dict[str, Any], errors: list[str]) -> list[dict[str, Any]]:
    artifacts = contract.get("source_artifacts")
    rows: list[dict[str, Any]] = []
    if not isinstance(artifacts, dict):
        errors.append("source_artifacts must be object")
        return rows
    for artifact_id, path_text in artifacts.items():
        status = "pass" if isinstance(path_text, str) and (root / path_text).is_file() else "fail"
        if status == "fail":
            errors.append(f"source_artifacts.{artifact_id} missing file: {path_text}")
        rows.append({"artifact_id": artifact_id, "path": path_text, "status": status})
    return rows


def validate_ledger_contract(
    contract: dict[str, Any], ledger: dict[str, Any], errors: list[str]
) -> tuple[int, int]:
    spec = contract.get("ledger_contract")
    if not isinstance(spec, dict):
        errors.append("ledger_contract must be object")
        return 0, 0
    if ledger.get("schema_version") != spec.get("schema_version"):
        errors.append("ledger_contract.schema_version does not match checked-in ledger")
    if ledger.get("bead") != spec.get("bead"):
        errors.append("ledger_contract.bead does not match checked-in ledger")

    template = ledger.get("proof_template")
    if not isinstance(template, dict):
        errors.append("ledger.proof_template must be object")
        template = {}
    template_fields = set(require_strings(template.get("required_fields"), errors, "ledger.proof_template.required_fields"))
    for field in require_strings(spec.get("required_template_fields"), errors, "ledger_contract.required_template_fields"):
        if field not in template_fields:
            errors.append(f"ledger proof template missing required field {field}")

    logging = ledger.get("logging_contract")
    if not isinstance(logging, dict):
        errors.append("ledger.logging_contract must be object")
        logging = {}
    logging_fields = set(require_strings(logging.get("required_fields"), errors, "ledger.logging_contract.required_fields"))
    for field in require_strings(spec.get("required_logging_fields"), errors, "ledger_contract.required_logging_fields"):
        if field not in logging_fields:
            errors.append(f"ledger logging contract missing required field {field}")

    expected_classes = set(require_strings(spec.get("required_input_classes"), errors, "ledger_contract.required_input_classes"))
    actual_classes = set(
        require_strings(
            template.get("minimum_input_class_coverage"),
            errors,
            "ledger.proof_template.minimum_input_class_coverage",
        )
    )
    missing_classes = sorted(expected_classes - actual_classes)
    if missing_classes:
        errors.append(f"ledger minimum input classes missing {missing_classes}")

    candidates = ledger.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        errors.append("ledger.candidates must be non-empty array")
        candidates = []
    candidate_ids = [candidate.get("candidate_id") for candidate in candidates if isinstance(candidate, dict)]
    expected_ids = require_strings(spec.get("expected_candidate_ids"), errors, "ledger_contract.expected_candidate_ids")
    if sorted(candidate_ids) != sorted(expected_ids):
        errors.append(
            f"ledger_contract expected_candidate_ids mismatch: expected={sorted(expected_ids)} actual={sorted(candidate_ids)}"
        )
    expected_traces = spec.get("expected_trace_ids")
    if not isinstance(expected_traces, dict):
        errors.append("ledger_contract.expected_trace_ids must be object")
        expected_traces = {}
    by_id = {
        candidate.get("candidate_id"): candidate
        for candidate in candidates
        if isinstance(candidate, dict) and isinstance(candidate.get("candidate_id"), str)
    }
    for candidate_id, trace_id in expected_traces.items():
        if not isinstance(trace_id, str):
            errors.append(f"ledger_contract.expected_trace_ids.{candidate_id} must be string")
            continue
        actual = by_id.get(candidate_id, {}).get("trace_id")
        if actual != trace_id:
            errors.append(f"{candidate_id} trace_id mismatch: expected {trace_id}, actual {actual}")

    summary = ledger.get("summary")
    expected_summary = spec.get("summary")
    if not isinstance(summary, dict):
        errors.append("ledger.summary must be object")
        summary = {}
    if not isinstance(expected_summary, dict):
        errors.append("ledger_contract.summary must be object")
        expected_summary = {}
    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            errors.append(f"ledger summary {key} mismatch: expected {expected}, actual {summary.get(key)}")

    status_counts = Counter(
        candidate.get("proof_status") for candidate in candidates if isinstance(candidate, dict)
    )
    if summary.get("total_candidates") != len(candidates):
        errors.append("ledger summary total_candidates does not match candidates length")
    for status in ("verified", "rejected", "pending", "waived"):
        if summary.get(status, 0) != status_counts.get(status, 0):
            errors.append(
                f"ledger summary {status} does not match candidate proof_status count"
            )
    return len(candidates), len(expected_ids)


def validate_checker_contract(contract: dict[str, Any], errors: list[str]) -> int:
    spec = contract.get("checker_contract")
    if not isinstance(spec, dict):
        errors.append("checker_contract must be object")
        return 0
    script = spec.get("script")
    source = read_text(script, errors, "checker_contract.script") if isinstance(script, str) else ""
    script_path = root / script if isinstance(script, str) else None
    if script_path is not None and script_path.is_file():
        mode = script_path.stat().st_mode
        if not mode & stat.S_IXUSR:
            errors.append(f"checker_contract.script is not executable: {script}")
    needles = require_strings(spec.get("required_script_needles"), errors, "checker_contract.required_script_needles")
    for needle in needles:
        if needle not in source:
            errors.append(f"checker_contract.script missing needle {needle}")
    return len(needles)


def validate_unit_primary(contract: dict[str, Any], errors: list[str]) -> int:
    unit = contract.get("unit_primary")
    if not isinstance(unit, dict):
        errors.append("unit_primary must be object")
        return 0
    if unit.get("missing_item_id") != "tests.unit.primary":
        errors.append("unit_primary.missing_item_id must be tests.unit.primary")
    test_file = unit.get("test_file")
    source = read_text(test_file, errors, "unit_primary.test_file") if isinstance(test_file, str) else ""
    names = require_strings(unit.get("required_test_names"), errors, "unit_primary.required_test_names")
    for name in names:
        if f"fn {name}(" not in source:
            errors.append(f"unit_primary references missing ledger unit test {name}")
    return len(names)


def validate_e2e_primary(contract: dict[str, Any], errors: list[str]) -> int:
    e2e = contract.get("e2e_primary")
    if not isinstance(e2e, dict):
        errors.append("e2e_primary must be object")
        return 0
    if e2e.get("missing_item_id") != "tests.e2e.primary":
        errors.append("e2e_primary.missing_item_id must be tests.e2e.primary")
    scenarios = e2e.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) < 3:
        errors.append("e2e_primary.scenarios must contain at least three scenarios")
        return 0
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            errors.append("e2e_primary scenarios must be objects")
            continue
        scenario_id = scenario.get("scenario_id")
        command = scenario.get("command")
        if not isinstance(scenario_id, str) or not scenario_id:
            errors.append("e2e_primary scenario_id must be non-empty string")
        if not isinstance(command, str) or not command:
            errors.append(f"e2e scenario missing command: {scenario_id}")
            continue
        if "cargo " in command and not command.startswith("rch cargo "):
            errors.append(f"cargo e2e scenario must use rch cargo: {scenario_id}")
        if not (command.startswith("bash scripts/") or command.startswith("rch cargo ")):
            errors.append(f"e2e scenario command has unsupported launcher: {scenario_id}")
        if scenario.get("expected_exit") != 0:
            errors.append(f"e2e scenario expected_exit must be 0: {scenario_id}")
    return len(scenarios)


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> int:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be object")
        return 0
    if evidence.get("bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    test_source = evidence.get("test_source")
    source = read_text(test_source, errors, "completion_debt_evidence.test_source") if isinstance(test_source, str) else ""
    names = require_strings(evidence.get("required_test_names"), errors, "completion_debt_evidence.required_test_names")
    for name in names:
        if f"fn {name}(" not in source:
            errors.append(f"completion_debt_evidence references missing Rust test {name}")
    return len(names)


def run_original_gate(errors: list[str]) -> dict[str, Any]:
    script = root / "scripts/check_optimization_proof_ledger.sh"
    if not script.is_file():
        errors.append("original optimization proof ledger gate is missing")
        return {"status": "missing", "exit_code": None, "stdout_tail": [], "stderr_tail": []}
    try:
        result = subprocess.run(
            ["bash", str(script)],
            cwd=root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except Exception as exc:
        errors.append(f"original optimization proof ledger gate could not run: {exc}")
        return {"status": "error", "exit_code": None, "stdout_tail": [], "stderr_tail": [str(exc)]}
    if result.returncode != 0:
        errors.append(f"original optimization proof ledger gate failed with exit {result.returncode}")
    return {
        "status": "pass" if result.returncode == 0 else "fail",
        "exit_code": result.returncode,
        "stdout_tail": result.stdout.splitlines()[-12:],
        "stderr_tail": result.stderr.splitlines()[-12:],
    }


def validate_contract(contract: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD_ID}")

    source_rows = validate_source_artifacts(contract, errors)
    artifacts = contract.get("source_artifacts") if isinstance(contract.get("source_artifacts"), dict) else {}
    ledger_path = root / artifacts.get("ledger", "")
    ledger = load_json(ledger_path, errors, "optimization proof ledger")
    candidate_count = 0
    expected_candidate_count = 0
    if ledger:
        candidate_count, expected_candidate_count = validate_ledger_contract(contract, ledger, errors)
    checker_needle_count = validate_checker_contract(contract, errors)
    unit_count = validate_unit_primary(contract, errors)
    e2e_count = validate_e2e_primary(contract, errors)
    completion_test_count = validate_completion_evidence(contract, errors)
    original_gate = run_original_gate(errors)

    return {
        "source_rows": source_rows,
        "candidate_count": candidate_count,
        "expected_candidate_count": expected_candidate_count,
        "checker_needle_count": checker_needle_count,
        "unit_count": unit_count,
        "e2e_count": e2e_count,
        "completion_test_count": completion_test_count,
        "original_gate": original_gate,
    }


errors: list[str] = []
contract = load_json(contract_path, errors, "contract")
metrics = {
    "source_rows": [],
    "candidate_count": 0,
    "expected_candidate_count": 0,
    "checker_needle_count": 0,
    "unit_count": 0,
    "e2e_count": 0,
    "completion_test_count": 0,
    "original_gate": {"status": "not-run", "exit_code": None, "stdout_tail": [], "stderr_tail": []},
}
if contract:
    metrics = validate_contract(contract, errors)

timestamp = utc_now()
log_rows = []
for row in metrics["source_rows"]:
    log_rows.append(
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:source:{row['artifact_id']}",
            "event": "optimization_proof_ledger_completion_source",
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
            "status": row["status"],
            "artifact_refs": [row["path"], rel(contract_path)],
            "failure_signature": "none" if row["status"] == "pass" else "source_artifact_missing",
        }
    )

log_rows.extend(
    [
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:ledger",
            "event": "optimization_proof_ledger_completion_ledger",
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
            "status": "pass" if metrics["candidate_count"] == metrics["expected_candidate_count"] == 3 and not errors else "fail",
            "artifact_refs": ["tests/conformance/optimization_proof_ledger.v1.json", rel(contract_path)],
            "failure_signature": "none" if metrics["candidate_count"] == metrics["expected_candidate_count"] == 3 and not errors else "ledger_contract_error",
        },
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:checker",
            "event": "optimization_proof_ledger_completion_checker",
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
            "status": metrics["original_gate"]["status"],
            "artifact_refs": ["scripts/check_optimization_proof_ledger.sh", rel(contract_path)],
            "failure_signature": "none" if metrics["original_gate"]["status"] == "pass" else "ledger_gate_failed",
        },
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:unit-primary",
            "event": "optimization_proof_ledger_completion_unit",
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
            "status": "pass" if metrics["unit_count"] >= 10 and not errors else "fail",
            "artifact_refs": ["crates/frankenlibc-harness/tests/optimization_proof_ledger_test.rs", rel(contract_path)],
            "failure_signature": "none" if metrics["unit_count"] >= 10 and not errors else "unit_primary_contract_error",
        },
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:e2e-primary",
            "event": "optimization_proof_ledger_completion_e2e",
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
            "status": "pass" if metrics["e2e_count"] >= 3 and not errors else "fail",
            "artifact_refs": ["scripts/check_optimization_proof_ledger_completion_contract.sh", rel(contract_path)],
            "failure_signature": "none" if metrics["e2e_count"] >= 3 and not errors else "e2e_contract_error",
        },
    ]
)

summary = {
    "schema_version": REPORT_SCHEMA,
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "contract": rel(contract_path),
    "candidate_count": metrics["candidate_count"],
    "expected_candidate_count": metrics["expected_candidate_count"],
    "checker_needle_count": metrics["checker_needle_count"],
    "source_artifact_count": len(metrics["source_rows"]),
    "unit_required_test_count": metrics["unit_count"],
    "e2e_scenario_count": metrics["e2e_count"],
    "completion_required_test_count": metrics["completion_test_count"],
    "original_gate_exit_code": metrics["original_gate"]["exit_code"],
    "original_gate_status": metrics["original_gate"]["status"],
    "original_gate_stdout_tail": metrics["original_gate"]["stdout_tail"],
    "original_gate_stderr_tail": metrics["original_gate"]["stderr_tail"],
    "errors": errors,
    "status": "pass" if not errors else "fail",
    "report_path": rel(report_path),
    "log_path": rel(log_path),
}
log_rows.append(
    {
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:summary",
        "event": "optimization_proof_ledger_completion_summary",
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "status": summary["status"],
        "artifact_refs": [rel(contract_path), rel(report_path), rel(log_path)],
        "failure_signature": "none" if not errors else "contract_validation_error",
    }
)

report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")

print(
    "optimization_proof_ledger_completion_contract: "
    f"status={summary['status']} sources={summary['source_artifact_count']} "
    f"candidates={summary['candidate_count']}/{summary['expected_candidate_count']} "
    f"unit_tests={summary['unit_required_test_count']} e2e={summary['e2e_scenario_count']} "
    f"completion_tests={summary['completion_required_test_count']} original_gate={summary['original_gate_status']} "
    f"errors={len(errors)}"
)
print(f"report={rel(report_path)}")
print(f"log={rel(log_path)} rows={len(log_rows)}")
for error in errors:
    print(f"ERROR: {error}")
if errors:
    sys.exit(1)
PY
