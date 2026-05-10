#!/usr/bin/env bash
# check_semantic_contract_drift_scan_completion_contract.sh - bd-bp8fl.1.3.1 gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_SEMANTIC_DRIFT_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/semantic_contract_drift_scan_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_SEMANTIC_DRIFT_COMPLETION_REPORT:-${OUT_DIR}/semantic_contract_drift_scan_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_SEMANTIC_DRIFT_COMPLETION_LOG:-${OUT_DIR}/semantic_contract_drift_scan_completion_contract.log.jsonl}"

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

COMPLETION_BEAD = "bd-bp8fl.1.3.1"
ORIGINAL_BEAD = "bd-bp8fl.1.3"
EXPECTED_SCHEMA = "semantic_contract_drift_scan_completion_contract.v1"

EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "semantic_contract_drift_scan_units_validated",
    "semantic_contract_drift_scan_e2e_validated",
    "semantic_contract_drift_scan_conformance_validated",
    "semantic_contract_drift_scan_telemetry_validated",
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
    "tracked_inventory_entries",
    "semantic_parity_blocker_count",
    "untracked_contract_annotation_count",
    "allowed_false_positive_count",
    "support_matrix_stub_count",
    "docs_with_semantic_overlay_reference",
    "resolved_symbol_join_row_count",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def rel_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay under workspace root: {value}")
    return root / path


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


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
        errors.append(f"{display_path(path)} missing test function {name}")


def command_is_allowed(command: str) -> bool:
    stripped = command.strip()
    if stripped.startswith("scripts/") or stripped.startswith("bash -n ") or stripped.startswith("jq "):
        return True
    if " cargo " in f" {stripped} ":
        return " rch exec " in f" {stripped} "
    return True


def run_gate(checker: Path) -> tuple[bool, dict[str, Any], str]:
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


def emit_event(event: str, status: str, *, summary: dict[str, int], details: dict[str, Any] | None = None) -> None:
    events.append(
        {
            "timestamp": ts,
            "trace_id": f"{COMPLETION_BEAD}:{event}",
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "source_commit": SOURCE_COMMIT,
            "event": event,
            "status": status,
            "mode": "completion-contract",
            "api_family": "harness",
            "symbol": "semantic_contract_drift_scan",
            "decision_path": "contract+semantic_drift_gate+symbol_join_gate+structured_log",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "tracked_inventory_entries": summary.get("tracked_inventory_entries", 0),
            "semantic_parity_blocker_count": summary.get("semantic_parity_blocker_count", 0),
            "untracked_contract_annotation_count": summary.get("untracked_contract_annotation_count", 0),
            "allowed_false_positive_count": summary.get("allowed_false_positive_count", 0),
            "support_matrix_stub_count": summary.get("support_matrix_stub_count", 0),
            "docs_with_semantic_overlay_reference": summary.get("docs_with_semantic_overlay_reference", 0),
            "resolved_symbol_join_row_count": summary.get("resolved_symbol_join_row_count", 0),
            "artifact_refs": [
                "tests/conformance/semantic_contract_drift_scan_completion_contract.v1.json",
                "scripts/check_semantic_contract_drift_scan_completion_contract.sh",
                "tests/conformance/semantic_contract_drift_scan.v1.json",
                "tests/conformance/semantic_contract_symbol_join.v1.json",
                "scripts/check_semantic_contract_drift.sh",
                "scripts/check_semantic_contract_symbol_join.sh",
                "crates/frankenlibc-harness/tests/semantic_contract_drift_scan_test.rs",
            ],
            "failure_signature": "none" if status == "pass" else "semantic_contract_drift_scan_completion_contract_failed",
            "details": details or {},
        }
    )


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})
drift_policy = evidence.get("drift_policy", {})
join_policy = evidence.get("supporting_symbol_join_policy", {})

if contract.get("schema") != EXPECTED_SCHEMA:
    errors.append("schema mismatch")
if contract.get("bead") != ORIGINAL_BEAD:
    errors.append(f"bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_BEAD}")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != EXPECTED_MISSING_ITEMS:
    errors.append(f"missing_items mismatch: {sorted(missing_items)}")

artifact_paths: dict[str, Path] = {}
for name, value in artifacts.items():
    try:
        path = rel_path(str(value))
    except ValueError as exc:
        errors.append(str(exc))
        continue
    artifact_paths[name] = path
    if not path.exists():
        errors.append(f"artifact {name} missing: {value}")

for ref in evidence.get("implementation_refs", []):
    check_file_line_ref(str(ref))

drift_artifact = load_json(artifact_paths["drift_artifact"])
if drift_artifact.get("schema_version") != drift_policy.get("required_schema_version"):
    errors.append("drift artifact schema_version mismatch")
if drift_artifact.get("bead") != drift_policy.get("required_bead"):
    errors.append("drift artifact bead mismatch")
replay_kinds = {str(row.get("kind")) for row in drift_artifact.get("replay_cases", [])}
if set(drift_policy.get("required_replay_kinds", [])) != replay_kinds:
    errors.append(f"drift artifact replay kinds mismatch: {sorted(replay_kinds)}")
if set(drift_policy.get("required_log_fields", [])) != set(drift_artifact.get("required_log_fields", [])):
    errors.append("drift artifact required_log_fields mismatch")

for command_section in ("unit_primary", "e2e_primary"):
    for command in evidence.get(command_section, {}).get("required_commands", []):
        if not isinstance(command, str) or not command_is_allowed(command):
            errors.append(f"{command_section} command must use rch for cargo or be a repo script: {command}")

sources = evidence.get("test_sources", {})
source_paths: dict[str, Path] = {}
for source, value in sources.items():
    try:
        path = rel_path(str(value))
    except ValueError as exc:
        errors.append(str(exc))
        continue
    source_paths[source] = path
    if not path.is_file():
        errors.append(f"test source missing: {value}")
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
    try:
        path = rel_path(str(script))
    except ValueError as exc:
        errors.append(str(exc))
        continue
    if not path.is_file():
        errors.append(f"required script missing: {script}")

telemetry = evidence.get("telemetry_primary", {})
if set(telemetry.get("required_events", [])) != REQUIRED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != REQUIRED_FIELDS:
    errors.append("telemetry required_fields mismatch")

drift_report: dict[str, Any] = {}
join_report: dict[str, Any] = {}
if not errors:
    drift_ok, drift_report, drift_message = run_gate(artifact_paths["existing_drift_checker"])
    if not drift_ok:
        errors.append(f"existing semantic drift gate failed: {drift_message}")
    join_ok, join_report, join_message = run_gate(artifact_paths["existing_symbol_join_checker"])
    if not join_ok:
        errors.append(f"supporting semantic symbol join gate failed: {join_message}")

if drift_report:
    if drift_report.get("schema_version") != "v1":
        errors.append("drift report schema_version mismatch")
    if drift_report.get("bead") != ORIGINAL_BEAD:
        errors.append("drift report bead mismatch")
    if drift_report.get("status") != "pass":
        errors.append("drift report status must pass")
    if drift_report.get("errors"):
        errors.append("drift report errors must be empty")
    checks = drift_report.get("checks", {})
    for check in sorted(drift_policy.get("required_checks", [])):
        if checks.get(check) != "pass":
            errors.append(f"required drift check did not pass: {check}")
    drift_summary = drift_report.get("summary", {})
    if int(drift_summary.get("tracked_inventory_entries", 0)) < int(
        drift_policy.get("minimum_tracked_inventory_entries", 0)
    ):
        errors.append("tracked_inventory_entries below minimum")
    if int(drift_summary.get("semantic_parity_blocker_count", 0)) < int(
        drift_policy.get("minimum_semantic_parity_blockers", 0)
    ):
        errors.append("semantic_parity_blocker_count below minimum")
    for field, expected in drift_policy.get("required_summary_values", {}).items():
        if int(drift_summary.get(field, -1)) != int(expected):
            errors.append(f"drift summary.{field} expected {expected} got {drift_summary.get(field)}")
    blockers = set(drift_report.get("claim_surfaces_blocked_by_findings", []))
    required_blockers = set(drift_policy.get("required_claim_blockers", []))
    if not required_blockers.issubset(blockers):
        errors.append(f"drift report missing claim blockers: {sorted(required_blockers - blockers)}")

if join_report:
    if join_report.get("status") != "pass":
        errors.append("supporting symbol join report status must pass")
    join_checks = join_report.get("checks", {})
    for check in sorted(join_policy.get("required_checks", [])):
        if join_checks.get(check) != "pass":
            errors.append(f"required supporting symbol join check did not pass: {check}")
    join_summary = join_report.get("summary", {})
    if int(join_summary.get("resolved_symbol_join_row_count", 0)) < int(
        join_policy.get("minimum_resolved_symbol_join_rows", 0)
    ):
        errors.append("resolved_symbol_join_row_count below minimum")
    for field, expected in join_policy.get("required_summary_values", {}).items():
        if int(join_summary.get(field, -1)) != int(expected):
            errors.append(f"symbol join summary.{field} expected {expected} got {join_summary.get(field)}")

if drift_report:
    drift_log_path = root / "target/conformance/semantic_contract_drift_scan.log.jsonl"
    if not drift_log_path.is_file():
        errors.append("semantic drift scan log artifact missing")
    else:
        rows = read_jsonl(drift_log_path)
        if not rows:
            errors.append("semantic drift scan log must contain at least one row")
        else:
            for field in drift_policy.get("required_log_fields", []):
                if field not in rows[0]:
                    errors.append(f"semantic drift scan log missing field: {field}")

if join_report:
    join_log_path = root / "target/conformance/semantic_contract_symbol_join.log.jsonl"
    if not join_log_path.is_file():
        errors.append("semantic symbol join log artifact missing")
    else:
        rows = read_jsonl(join_log_path)
        if not rows:
            errors.append("semantic symbol join log must contain at least one row")

for artifact in evidence.get("conformance_primary", {}).get("required_artifacts", []):
    try:
        artifact_path = rel_path(str(artifact))
    except ValueError as exc:
        errors.append(str(exc))
        continue
    if not artifact_path.exists():
        errors.append(f"required conformance artifact missing: {artifact}")

drift_summary = drift_report.get("summary", {}) if drift_report else {}
join_summary = join_report.get("summary", {}) if join_report else {}
event_summary = {
    "tracked_inventory_entries": int(drift_summary.get("tracked_inventory_entries", 0)),
    "semantic_parity_blocker_count": int(drift_summary.get("semantic_parity_blocker_count", 0)),
    "untracked_contract_annotation_count": int(drift_summary.get("untracked_contract_annotation_count", 0)),
    "allowed_false_positive_count": int(drift_summary.get("allowed_false_positive_count", 0)),
    "support_matrix_stub_count": int(drift_summary.get("support_matrix_stub_count", 0)),
    "docs_with_semantic_overlay_reference": int(drift_summary.get("docs_with_semantic_overlay_reference", 0)),
    "resolved_symbol_join_row_count": int(join_summary.get("resolved_symbol_join_row_count", 0)),
}
status = "pass" if not errors else "fail"

emit_event(
    "semantic_contract_drift_scan_units_validated",
    status,
    summary=event_summary,
    details={"tests": evidence.get("unit_primary", {}).get("required_test_refs", [])},
)
emit_event(
    "semantic_contract_drift_scan_e2e_validated",
    status,
    summary=event_summary,
    details={"scripts": evidence.get("e2e_primary", {}).get("required_scripts", [])},
)
emit_event(
    "semantic_contract_drift_scan_conformance_validated",
    status,
    summary=event_summary,
    details={"artifacts": evidence.get("conformance_primary", {}).get("required_artifacts", [])},
)
emit_event(
    "semantic_contract_drift_scan_telemetry_validated",
    status,
    summary=event_summary,
    details={"required_fields": sorted(REQUIRED_FIELDS)},
)

report = {
    "schema": "semantic_contract_drift_scan_completion_contract.report.v1",
    "status": status,
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
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
    print("FAIL: semantic contract drift scan completion contract failed")
    for error in errors:
        print(f"  - {error}")
    raise SystemExit(1)

print(
    "PASS: semantic contract drift scan completion contract "
    f"(tracked_inventory_entries={event_summary['tracked_inventory_entries']}, "
    f"semantic_blockers={event_summary['semantic_parity_blocker_count']}, "
    f"resolved_join_rows={event_summary['resolved_symbol_join_row_count']})"
)
PY
