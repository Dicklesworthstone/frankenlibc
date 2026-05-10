#!/usr/bin/env bash
# check_semantic_contract_symbol_join_completion_contract.sh - bd-bp8fl.1.2.1 gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_SEMANTIC_JOIN_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/semantic_contract_symbol_join_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_SEMANTIC_JOIN_COMPLETION_REPORT:-${OUT_DIR}/semantic_contract_symbol_join_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_SEMANTIC_JOIN_COMPLETION_LOG:-${OUT_DIR}/semantic_contract_symbol_join_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}"

export FLC_ROOT="${ROOT}"
export FLC_CONTRACT_PATH="${CONTRACT_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"
export FLC_LOG_PATH="${LOG_PATH}"

python3 - <<'PY'
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

root = Path(os.environ["FLC_ROOT"])
contract_path = Path(os.environ["FLC_CONTRACT_PATH"])
report_path = Path(os.environ["FLC_REPORT_PATH"])
log_path = Path(os.environ["FLC_LOG_PATH"])
ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

errors: list[str] = []
events: list[dict[str, Any]] = []

REQUIRED_EVENTS = {
    "semantic_contract_symbol_join_units_validated",
    "semantic_contract_symbol_join_e2e_validated",
    "semantic_contract_symbol_join_conformance_validated",
    "semantic_contract_symbol_join_telemetry_validated",
}

REQUIRED_FIELDS = {
    "timestamp",
    "trace_id",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "event",
    "status",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "inventory_entry_count",
    "resolved_symbol_join_row_count",
    "semantic_parity_blocker_count",
    "missing_support_symbol_count",
    "missing_version_symbol_count",
    "missing_source_symbol_count",
    "artifact_refs",
    "failure_signature",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def rel_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay under workspace root: {value}")
    return root / path


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


SOURCE_COMMIT = source_commit()


def check_file_line_ref(ref: str) -> None:
    if ":" not in ref:
        errors.append(f"implementation ref missing line separator: {ref}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        errors.append(f"implementation ref has invalid line: {ref}")
        return
    try:
        path = rel_path(path_text)
    except ValueError as exc:
        errors.append(str(exc))
        return
    if not path.is_file():
        errors.append(f"implementation ref path missing: {ref}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no < 1 or line_no > len(lines) or not lines[line_no - 1].strip():
        errors.append(f"implementation ref does not point to non-empty line: {ref}")


def require_test_fn(path: Path, name: str) -> None:
    text = path.read_text(encoding="utf-8")
    if f"fn {name}" not in text:
        errors.append(f"{path.relative_to(root)} missing test function {name}")


def run_existing_gate(checker: Path) -> tuple[bool, dict[str, Any], str]:
    proc = subprocess.run(
        ["bash", str(checker)],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    message = f"stdout={proc.stdout}\nstderr={proc.stderr}"
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        report = {}
        message += "\nstdout did not parse as JSON"
    return proc.returncode == 0, report, message


def emit_event(event: str, status: str, *, summary: dict[str, Any], details: dict[str, Any] | None = None) -> None:
    events.append(
        {
            "timestamp": ts,
            "trace_id": f"bd-bp8fl.1.2.1:{event}",
            "completion_debt_bead": "bd-bp8fl.1.2.1",
            "original_bead": "bd-bp8fl.1.2",
            "source_commit": SOURCE_COMMIT,
            "event": event,
            "status": status,
            "mode": "completion-contract",
            "api_family": "harness",
            "symbol": "semantic_contract_symbol_join",
            "decision_path": "contract+semantic_join_gate+artifact_report+structured_log",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "inventory_entry_count": int(summary.get("inventory_entry_count", 0)),
            "resolved_symbol_join_row_count": int(summary.get("resolved_symbol_join_row_count", 0)),
            "semantic_parity_blocker_count": int(summary.get("semantic_parity_blocker_count", 0)),
            "missing_support_symbol_count": int(summary.get("support_matrix_missing_exact_symbol_count", 0)),
            "missing_version_symbol_count": int(summary.get("version_script_missing_exact_symbol_count", 0)),
            "missing_source_symbol_count": int(summary.get("source_missing_exact_symbol_count", 0)),
            "artifact_refs": [
                "tests/conformance/semantic_contract_symbol_join_completion_contract.v1.json",
                "scripts/check_semantic_contract_symbol_join_completion_contract.sh",
                "tests/conformance/semantic_contract_symbol_join.v1.json",
                "tests/conformance/semantic_contract_inventory.v1.json",
                "scripts/check_semantic_contract_symbol_join.sh",
                "crates/frankenlibc-harness/tests/semantic_contract_symbol_join_test.rs",
            ],
            "failure_signature": "none" if status == "pass" else "semantic_contract_symbol_join_completion_contract_failed",
            "details": details or {},
        }
    )


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})
policy = evidence.get("join_policy", {})

if contract.get("schema") != "semantic_contract_symbol_join_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != "bd-bp8fl.1.2":
    errors.append("bead must be bd-bp8fl.1.2")
if contract.get("completion_debt_bead") != "bd-bp8fl.1.2.1":
    errors.append("completion_debt_bead must be bd-bp8fl.1.2.1")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}:
    errors.append(f"missing_items mismatch: {sorted(missing_items)}")

artifact_paths: dict[str, Path] = {}
for name, value in artifacts.items():
    try:
        path = rel_path(str(value))
    except ValueError as exc:
        errors.append(str(exc))
        continue
    artifact_paths[name] = path
    if name == "abi_source_dir":
        if not path.is_dir():
            errors.append(f"artifact directory {name} missing: {value}")
    elif not path.is_file():
        errors.append(f"artifact {name} missing: {value}")

for ref in evidence.get("implementation_refs", []):
    check_file_line_ref(str(ref))

join_artifact = load_json(artifact_paths["join_artifact"])
inventory_artifact = load_json(artifact_paths["inventory_artifact"])
checker_text = artifact_paths["existing_checker"].read_text(encoding="utf-8")

if join_artifact.get("schema_version") != policy.get("required_schema_version"):
    errors.append("join artifact schema_version mismatch")
if join_artifact.get("bead") != policy.get("required_bead"):
    errors.append("join artifact bead mismatch")
if len(join_artifact.get("entries", [])) < int(policy.get("minimum_inventory_entries", 0)):
    errors.append("join artifact entry count below minimum")
if len(inventory_artifact.get("entries", [])) != len(join_artifact.get("entries", [])):
    errors.append("inventory and join artifact entry counts must match")

join_schema_fields = set()
for fields in join_artifact.get("join_schema", {}).values():
    if isinstance(fields, list):
        join_schema_fields.update(str(field) for field in fields)
missing_join_fields = set(policy.get("required_join_schema_fields", [])) - join_schema_fields
if missing_join_fields:
    errors.append(f"join_schema missing required fields: {sorted(missing_join_fields)}")

for required_fragment in [
    "parse_version_script",
    "summary_matches_current_join",
    "resolved_symbol_join_rows",
    "semantic_contract_symbol_join.report.json",
    "semantic_contract_symbol_join.log.jsonl",
]:
    if required_fragment not in checker_text:
        errors.append(f"existing checker missing required fragment: {required_fragment}")

existing_gate_ok, existing_report, gate_message = run_existing_gate(artifact_paths["existing_checker"])
if not existing_gate_ok:
    errors.append(f"existing semantic join gate failed: {gate_message}")

for field in policy.get("required_report_fields", []):
    if field not in existing_report:
        errors.append(f"existing report missing field: {field}")
if existing_report.get("schema_version") != "v1":
    errors.append("existing report schema_version mismatch")
if existing_report.get("bead") != "bd-bp8fl.1.2":
    errors.append("existing report bead mismatch")
if existing_report.get("status") != "pass":
    errors.append("existing report status must pass")
if existing_report.get("errors"):
    errors.append("existing report errors must be empty")

required_checks = set(policy.get("required_report_checks", []))
checks = existing_report.get("checks", {})
for check in sorted(required_checks):
    if checks.get(check) != "pass":
        errors.append(f"required report check did not pass: {check}")

summary = existing_report.get("summary", {})
if int(summary.get("inventory_entry_count", 0)) < int(policy.get("minimum_inventory_entries", 0)):
    errors.append("report inventory_entry_count below minimum")
if int(summary.get("resolved_symbol_join_row_count", 0)) < int(policy.get("minimum_resolved_symbol_join_rows", 0)):
    errors.append("report resolved_symbol_join_row_count below minimum")
for field, expected in policy.get("required_exact_missing_counts", {}).items():
    if int(summary.get(field, -1)) != int(expected):
        errors.append(f"summary.{field} expected {expected} got {summary.get(field)}")
if len(existing_report.get("resolved_symbol_join_rows", [])) != int(summary.get("resolved_symbol_join_row_count", -1)):
    errors.append("resolved_symbol_join_rows length mismatch")

existing_log_path = root / "target/conformance/semantic_contract_symbol_join.log.jsonl"
if not existing_log_path.is_file():
    errors.append("existing semantic join log artifact missing")
else:
    rows = [
        json.loads(line)
        for line in existing_log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not rows:
        errors.append("existing semantic join log must contain at least one row")
    else:
        log_row = rows[0]
        for field in policy.get("required_log_fields", []):
            if field not in log_row:
                errors.append(f"existing semantic join log missing field: {field}")

sources = evidence.get("test_sources", {})
source_paths = {name: rel_path(str(path)) for name, path in sources.items()}
for section_name in ("unit_primary", "e2e_primary", "conformance_primary"):
    for test_ref in evidence.get(section_name, {}).get("required_test_refs", []):
        source = str(test_ref.get("source", ""))
        name = str(test_ref.get("name", ""))
        path = source_paths.get(source)
        if path is None:
            errors.append(f"unknown test source: {source}")
            continue
        require_test_fn(path, name)

for script in evidence.get("e2e_primary", {}).get("required_scripts", []):
    if not rel_path(str(script).split()[0]).is_file():
        errors.append(f"required script missing: {script}")

for artifact in evidence.get("conformance_primary", {}).get("required_artifacts", []):
    artifact_path = rel_path(str(artifact))
    if not artifact_path.exists():
        errors.append(f"required conformance artifact missing: {artifact}")

for section in ("unit_primary", "e2e_primary"):
    for command in evidence.get(section, {}).get("required_commands", []):
        if "cargo test" in command and "rch exec" not in command:
            errors.append(f"{section} cargo command must be rch-backed: {command}")

telemetry = evidence.get("telemetry_primary", {})
if set(telemetry.get("required_events", [])) != REQUIRED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != REQUIRED_FIELDS:
    errors.append("telemetry required_fields mismatch")

event_summary = {
    "inventory_entry_count": int(summary.get("inventory_entry_count", 0)),
    "resolved_symbol_join_row_count": int(summary.get("resolved_symbol_join_row_count", 0)),
    "semantic_parity_blocker_count": int(summary.get("semantic_parity_blocker_count", 0)),
    "support_matrix_missing_exact_symbol_count": int(summary.get("support_matrix_missing_exact_symbol_count", 0)),
    "version_script_missing_exact_symbol_count": int(summary.get("version_script_missing_exact_symbol_count", 0)),
    "source_missing_exact_symbol_count": int(summary.get("source_missing_exact_symbol_count", 0)),
}

status = "pass" if not errors else "fail"
emit_event(
    "semantic_contract_symbol_join_units_validated",
    status,
    summary=event_summary,
    details={"tests": evidence.get("unit_primary", {}).get("required_test_refs", [])},
)
emit_event(
    "semantic_contract_symbol_join_e2e_validated",
    status,
    summary=event_summary,
    details={"scripts": evidence.get("e2e_primary", {}).get("required_scripts", [])},
)
emit_event(
    "semantic_contract_symbol_join_conformance_validated",
    status,
    summary=event_summary,
    details={"artifacts": evidence.get("conformance_primary", {}).get("required_artifacts", [])},
)
emit_event(
    "semantic_contract_symbol_join_telemetry_validated",
    status,
    summary=event_summary,
    details={"required_fields": sorted(REQUIRED_FIELDS)},
)

report = {
    "schema": "semantic_contract_symbol_join_completion_contract.report.v1",
    "status": status,
    "bead": "bd-bp8fl.1.2",
    "completion_debt_bead": "bd-bp8fl.1.2.1",
    "source_commit": SOURCE_COMMIT,
    "summary": event_summary,
    "required_events": sorted(REQUIRED_EVENTS),
    "required_fields": sorted(REQUIRED_FIELDS),
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)

if errors:
    print("FAIL: semantic contract symbol join completion contract failed")
    for error in errors:
        print(f"  - {error}")
    raise SystemExit(1)

print(
    "PASS: semantic contract symbol join completion contract "
    f"(inventory_entries={event_summary['inventory_entry_count']}, "
    f"resolved_rows={event_summary['resolved_symbol_join_row_count']}, "
    f"semantic_blockers={event_summary['semantic_parity_blocker_count']})"
)
PY
