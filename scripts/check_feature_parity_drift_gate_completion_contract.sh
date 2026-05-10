#!/usr/bin/env bash
# check_feature_parity_drift_gate_completion_contract.sh - bd-w2c3.1.2.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FLC_FP_DRIFT_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/feature_parity_drift_gate_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FLC_FP_DRIFT_COMPLETION_REPORT:-${OUT_DIR}/feature_parity_drift_gate_completion_contract.report.json}"
LOG_PATH="${FLC_FP_DRIFT_COMPLETION_LOG:-${OUT_DIR}/feature_parity_drift_gate_completion_contract.log.jsonl}"
LOCK_PATH="${OUT_DIR}/feature_parity_drift_gate_completion_contract.source.lock"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT_PATH}")" "$(dirname "${LOG_PATH}")"

export FLC_ROOT="${ROOT}"
export FLC_CONTRACT_PATH="${CONTRACT_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"
export FLC_LOG_PATH="${LOG_PATH}"
export FLC_LOCK_PATH="${LOCK_PATH}"

python3 - <<'PY'
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

root = Path(os.environ["FLC_ROOT"])
contract_path = Path(os.environ["FLC_CONTRACT_PATH"])
report_path = Path(os.environ["FLC_REPORT_PATH"])
log_path = Path(os.environ["FLC_LOG_PATH"])
lock_path = Path(os.environ["FLC_LOCK_PATH"])
ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

COMPLETION_BEAD = "bd-w2c3.1.2.1"
ORIGINAL_BEAD = "bd-w2c3.1.2"
EXPECTED_SCHEMA = "feature_parity_drift_gate_completion_contract.v1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
EXPECTED_EVENTS = {
    "feature_parity_drift_gate_completion_source_gates_replayed",
    "feature_parity_drift_gate_completion_validated",
    "feature_parity_drift_gate_completion_failed",
}
EXPECTED_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "status",
    "source_gate",
    "source_gate_results",
    "missing_items_bound",
    "artifact_refs",
    "failure_signature",
}
SOURCE_EVENT_FIELDS = {
    "trace_id",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
}

errors: list[str] = []


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            rows.append(json.loads(raw))
    return rows


def display_path(path: Path) -> str:
    resolved = path if path.is_absolute() else root / path
    if resolved.is_absolute() and resolved.is_relative_to(root):
        return str(resolved.relative_to(root))
    return str(path)


def repo_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"non-repo-relative path: {value}")
        return root / "__invalid__"
    return root / path


def command_is_allowed(command: str) -> bool:
    stripped = command.strip()
    if stripped.startswith("scripts/") or stripped.startswith("bash -n ") or stripped.startswith("jq "):
        return True
    return " rch exec -- cargo " in f" {stripped} "


def run_command(gate_name: str, script: Path, env_updates: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if env_updates:
        env.update(env_updates)
    start_ns = time.time_ns()
    result = subprocess.run(
        [str(script)],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    result.elapsed_ns = time.time_ns() - start_ns  # type: ignore[attr-defined]
    result.gate_name = gate_name  # type: ignore[attr-defined]
    return result


def find_source_event(stdout: str) -> dict[str, Any] | None:
    for raw in reversed(stdout.splitlines()):
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and SOURCE_EVENT_FIELDS.issubset(event):
            return event
    return None


def validate_test_ref(test_sources: dict[str, Any], source_key: str, name: str, missing_item_id: str) -> None:
    source_path = test_sources.get(source_key)
    if not isinstance(source_path, str):
        errors.append(f"invalid test source key {source_key} in {missing_item_id}")
        return
    path = repo_path(source_path)
    if not path.is_file():
        errors.append(f"test source missing for {source_key}: {source_path}")
        return
    text = path.read_text(encoding="utf-8")
    if f"fn {name}" not in text and f"def {name}" not in text:
        errors.append(f"missing referenced test {source_key}::{name}")


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})

if contract.get("schema_version") != EXPECTED_SCHEMA:
    errors.append("completion contract schema mismatch")
if contract.get("completion_debt_bead") != COMPLETION_BEAD:
    errors.append("completion_debt_bead mismatch")
if contract.get("original_bead") != ORIGINAL_BEAD:
    errors.append("original_bead mismatch")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be at least 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != EXPECTED_MISSING_ITEMS:
    errors.append(f"missing_items mismatch: {sorted(missing_items)}")

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict):
    errors.append("test_sources must be an object")
    test_sources = {}
for source_key, source_path in test_sources.items():
    if not isinstance(source_path, str) or not repo_path(source_path).is_file():
        errors.append(f"test source missing for {source_key}: {source_path}")

source_gates = evidence.get("source_gates", {})
if not isinstance(source_gates, dict):
    errors.append("source_gates must be an object")
    source_gates = {}
for gate_name in (
    "feature_parity_drift",
    "support_matrix_maintenance",
    "feature_parity_gap_bead_coverage",
    "feature_parity_gap_ledger",
):
    gate = source_gates.get(gate_name, {})
    if not isinstance(gate, dict):
        errors.append(f"source gate missing: {gate_name}")
        continue
    for key in ("script", "artifact", "harness_test", "expected_outcome"):
        if not isinstance(gate.get(key), str):
            errors.append(f"{gate_name} missing {key}")
    for key in ("script", "artifact", "harness_test"):
        value = gate.get(key)
        if isinstance(value, str) and not repo_path(value).is_file():
            errors.append(f"{gate_name} path missing: {value}")
    if gate.get("expected_outcome") not in {"pass", "pass_or_fail_closed"}:
        errors.append(f"{gate_name} expected_outcome unsupported")

for section_name in ("tests_unit_primary", "tests_e2e_primary", "tests_conformance_primary"):
    section = evidence.get(section_name, {})
    if not isinstance(section, dict):
        errors.append(f"{section_name} must be an object")
        continue
    missing_item_id = section.get("missing_item_id")
    if missing_item_id not in EXPECTED_MISSING_ITEMS:
        errors.append(f"unknown missing_item_id section: {missing_item_id}")
    for ref in section.get("required_test_refs", []):
        if not isinstance(ref, dict) or not isinstance(ref.get("source"), str) or not isinstance(ref.get("name"), str):
            errors.append(f"invalid test ref in {section_name}")
            continue
        validate_test_ref(test_sources, ref["source"], ref["name"], str(missing_item_id))

for command in evidence.get("tests_e2e_primary", {}).get("required_commands", []):
    if not isinstance(command, str) or not command_is_allowed(command):
        errors.append(f"required command must use rch or a repo script, not bare cargo: {command}")

for artifact in evidence.get("tests_conformance_primary", {}).get("required_artifacts", []):
    if not isinstance(artifact, str) or not repo_path(artifact).is_file():
        errors.append(f"required artifact missing: {artifact}")

telemetry = evidence.get("telemetry_primary", {})
if not isinstance(telemetry, dict):
    errors.append("telemetry_primary must be an object")
    telemetry = {}
if set(telemetry.get("required_events", [])) != EXPECTED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != EXPECTED_FIELDS:
    errors.append("telemetry required_fields mismatch")
if set(telemetry.get("source_event_fields", [])) != SOURCE_EVENT_FIELDS:
    errors.append("telemetry source_event_fields mismatch")

source_gate_results: dict[str, Any] = {}

if not errors:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        gate_scripts = {
            "feature_parity_gap_ledger": (
                "feature_parity_gap_ledger",
                repo_path(str(source_gates["feature_parity_gap_ledger"]["script"])),
                {
                    "FLC_FP_DONE_EVIDENCE_LOG": str(
                        report_path.with_name("feature_parity_drift_gate_completion.done_evidence.log.jsonl")
                    ),
                    "FLC_FP_DONE_EVIDENCE_REPORT": str(
                        report_path.with_name("feature_parity_drift_gate_completion.done_evidence.report.json")
                    ),
                },
            ),
            "feature_parity_gap_bead_coverage": (
                "feature_parity_gap_bead_coverage",
                repo_path(str(source_gates["feature_parity_gap_bead_coverage"]["script"])),
                {},
            ),
            "feature_parity_drift": (
                "feature_parity_drift",
                repo_path(str(source_gates["feature_parity_drift"]["script"])),
                {
                    "FLC_FP_DRIFT_DIAGNOSTICS": str(
                        report_path.with_name("feature_parity_drift_gate_completion.source_drift.json")
                    )
                },
            ),
            "support_matrix_maintenance": (
                "support_matrix_maintenance",
                repo_path(str(source_gates["support_matrix_maintenance"]["script"])),
                {},
            ),
        }

        for gate_name in (
            "feature_parity_gap_ledger",
            "feature_parity_gap_bead_coverage",
            "feature_parity_drift",
            "support_matrix_maintenance",
        ):
            _, script_path, env_updates = gate_scripts[gate_name]
            result = run_command(gate_name, script_path, env_updates)
            stdout = result.stdout
            stderr = result.stderr
            combined = stdout + stderr
            expected = str(source_gates[gate_name]["expected_outcome"])
            gate_status = "pass" if result.returncode == 0 else "fail"
            accepted = result.returncode == 0
            failure_signature = "none"
            if result.returncode != 0:
                allowed = str(source_gates[gate_name].get("allowed_failure_signature", ""))
                if expected == "pass_or_fail_closed" and allowed and allowed in combined:
                    accepted = True
                    gate_status = "fail_closed"
                    failure_signature = allowed
                else:
                    failure_signature = combined[-500:]
            if not accepted:
                errors.append(f"{gate_name} source gate failed: {failure_signature}")
            source_gate_results[gate_name] = {
                "status": gate_status,
                "returncode": result.returncode,
                "accepted": accepted,
                "elapsed_ns": int(getattr(result, "elapsed_ns", 0)),
                "failure_signature": failure_signature,
            }

        fcntl.flock(lock_file, fcntl.LOCK_UN)

if not errors:
    drift_path = report_path.with_name("feature_parity_drift_gate_completion.source_drift.json")
    drift = load_json(drift_path)
    drift_summary = drift.get("summary", {})
    if int(drift_summary.get("diagnostic_count", 0)) < 1:
        errors.append("feature parity drift diagnostic_count must be non-zero")
    if int(drift_summary.get("fail_count", -1)) != 0:
        errors.append("feature parity drift fail_count must be zero")
    source_gate_results["feature_parity_drift"]["diagnostic_count"] = int(
        drift_summary.get("diagnostic_count", 0)
    )

    gap_coverage = load_json(repo_path("tests/conformance/feature_parity_gap_bead_coverage.v1.json"))
    uncovered = int(gap_coverage.get("summary", {}).get("uncovered_gaps", -1))
    if uncovered != 0:
        errors.append("feature parity gap coverage uncovered_gaps must be zero")
    source_gate_results["feature_parity_gap_bead_coverage"]["uncovered_gaps"] = uncovered

    gap_ledger = load_json(repo_path("tests/conformance/feature_parity_gap_ledger.v1.json"))
    parse_errors = gap_ledger.get("parse_errors", [])
    if not isinstance(parse_errors, list) or parse_errors:
        errors.append("feature parity gap ledger parse_errors must be empty")
    done_audit = gap_ledger.get("done_evidence_audit", [])
    if not isinstance(done_audit, list) or not done_audit:
        errors.append("feature parity gap ledger done_evidence_audit must be non-empty")
    source_gate_results["feature_parity_gap_ledger"]["done_evidence_audit_count"] = (
        len(done_audit) if isinstance(done_audit, list) else 0
    )

    support_log = repo_path("target/conformance/support_matrix_maintenance.log.jsonl")
    support_rows = read_jsonl(support_log)
    support_events = {row.get("event") for row in support_rows}
    required_support_events = set(source_gates["support_matrix_maintenance"].get("required_log_events", []))
    if not required_support_events.issubset(support_events):
        errors.append(
            f"support matrix maintenance log missing events: {sorted(required_support_events - support_events)}"
        )
    if support_rows and not {
        "trace_id",
        "event",
        "mode",
        "api_family",
        "symbol",
        "outcome",
        "errno",
        "artifact_refs",
    }.issubset(support_rows[0]):
        errors.append("support matrix maintenance log row missing required telemetry fields")

status = "fail" if errors else "pass"
summary = {
    "missing_items_bound": sorted(missing_items),
    "source_gate_results": source_gate_results,
}
report = {
    "schema_version": "feature_parity_drift_gate_completion_contract.report.v1",
    "bead_id": COMPLETION_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "errors": errors,
    **summary,
}

events = [
    "feature_parity_drift_gate_completion_source_gates_replayed",
    "feature_parity_drift_gate_completion_validated",
]
if errors:
    events = ["feature_parity_drift_gate_completion_failed"]

artifact_refs = [
    display_path(contract_path),
    "tests/conformance/feature_parity_drift_diagnostics.v1.json",
    "tests/conformance/support_matrix_maintenance_report.v1.json",
    "tests/conformance/feature_parity_gap_bead_coverage.v1.json",
    "tests/conformance/feature_parity_gap_ledger.v1.json",
]
log_rows = []
for event in events:
    log_rows.append(
        {
            "timestamp": ts,
            "trace_id": f"{COMPLETION_BEAD}::feature_parity_drift_completion::{event}",
            "event": event,
            "level": "error" if errors else "info",
            "bead_id": COMPLETION_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "status": status,
            "source_gate": "all",
            "source_gate_results": source_gate_results,
            "missing_items_bound": summary["missing_items_bound"],
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if not errors else "feature_parity_drift_gate_completion_failed",
        }
    )

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in log_rows) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    raise SystemExit(1)
PY
