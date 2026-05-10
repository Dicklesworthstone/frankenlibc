#!/usr/bin/env bash
# check_reverse_loader_process_abi_standalone_completion_contract.sh - bd-bp8fl.3.7.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_REVERSE_LOADER_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/reverse_loader_process_abi_standalone_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_REVERSE_LOADER_COMPLETION_REPORT:-${OUT_DIR}/reverse_loader_process_abi_standalone_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_REVERSE_LOADER_COMPLETION_LOG:-${OUT_DIR}/reverse_loader_process_abi_standalone_completion_contract.log.jsonl}"

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

REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}

REQUIRED_EVENTS = {
    "reverse_loader_standalone_units_validated",
    "reverse_loader_standalone_conformance_validated",
    "reverse_loader_standalone_telemetry_validated",
}

REQUIRED_FIELDS = {
    "timestamp",
    "trace_id",
    "completion_debt_bead",
    "original_bead",
    "event",
    "status",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "gap_count",
    "structured_log_row_count",
    "versioned_symbol_requirement_count",
    "positive_smoke_row_count",
    "negative_smoke_row_count",
    "standalone_claim_status",
    "standalone_artifact_status",
    "artifact_refs",
    "failure_signature",
}

REQUIRED_GATE_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "gap_id",
    "api_family",
    "symbol",
    "replacement_level",
    "runtime_mode",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]

REQUIRED_REPORT_CHECKS = {
    "standalone_smoke_binding",
    "versioned_symbol_binding",
    "positive_negative_evidence",
    "readiness_blocker_binding",
    "structured_log",
    "runtime_mode_evidence",
    "ledger_gap_binding",
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


def require_contains(label: str, text: str, needle: str) -> None:
    if needle not in text:
        errors.append(f"{label} missing required text: {needle}")


def require_test_fn(path: Path, name: str) -> None:
    text = path.read_text(encoding="utf-8")
    if f"fn {name}" not in text:
        errors.append(f"{path.relative_to(root)} missing test function {name}")


def command_uses_rch_or_script(command: str) -> bool:
    if command.startswith("scripts/") or command.startswith("bash scripts/"):
        return True
    if "cargo" in command and "rch exec --" in command:
        return True
    return "cargo" not in command


def run_json_command(command: list[str], label: str) -> dict[str, Any] | None:
    proc = subprocess.run(
        command,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        errors.append(f"{label} failed: stdout={proc.stdout.strip()} stderr={proc.stderr.strip()}")
        return None
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        errors.append(f"{label} stdout is not JSON: {exc}")
        return None
    if not isinstance(parsed, dict):
        errors.append(f"{label} stdout must be a JSON object")
        return None
    return parsed


def run_base_gate(path: Path) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    proc = subprocess.run(
        ["bash", str(path)],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        errors.append(
            "base reverse-loader gate failed: "
            f"stdout={proc.stdout.strip()} stderr={proc.stderr.strip()}"
        )
        return None, []
    report_file = root / "target/conformance/reverse_loader_process_abi_standalone_gate.report.json"
    log_file = root / "target/conformance/reverse_loader_process_abi_standalone_gate.log.jsonl"
    try:
        report = load_json(report_file)
    except Exception as exc:
        errors.append(f"base reverse-loader report unreadable: {exc}")
        report = None
    log_rows: list[dict[str, Any]] = []
    try:
        for line in log_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                if isinstance(row, dict):
                    log_rows.append(row)
    except Exception as exc:
        errors.append(f"base reverse-loader log unreadable: {exc}")
    return report if isinstance(report, dict) else None, log_rows


def emit_event(event: str, status: str, *, summary: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": ts,
            "trace_id": f"bd-bp8fl.3.7.1:{event}",
            "completion_debt_bead": "bd-bp8fl.3.7.1",
            "original_bead": "bd-bp8fl.3.7",
            "source_commit": SOURCE_COMMIT,
            "event": event,
            "status": status,
            "mode": "completion-contract",
            "api_family": "harness",
            "symbol": "reverse_loader_process_abi_standalone",
            "decision_path": "contract+reverse_loader_gate+standalone_validate_only+telemetry",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "gap_count": summary.get("gap_count", 0),
            "structured_log_row_count": summary.get("structured_log_row_count", 0),
            "versioned_symbol_requirement_count": summary.get("versioned_symbol_requirement_count", 0),
            "positive_smoke_row_count": summary.get("positive_smoke_row_count", 0),
            "negative_smoke_row_count": summary.get("negative_smoke_row_count", 0),
            "standalone_claim_status": summary.get("standalone_claim_status", "unknown"),
            "standalone_artifact_status": summary.get("standalone_artifact_status", "unknown"),
            "artifact_refs": [
                "tests/conformance/reverse_loader_process_abi_standalone_completion_contract.v1.json",
                "scripts/check_reverse_loader_process_abi_standalone_completion_contract.sh",
                "tests/conformance/reverse_loader_process_abi_standalone_gate.v1.json",
                "scripts/check_reverse_loader_process_abi_standalone_gate.sh",
                "tests/conformance/standalone_link_run_smoke.v1.json",
                "scripts/check_standalone_link_run_smoke.sh",
            ],
            "failure_signature": "none" if status == "pass" else "reverse_loader_standalone_completion_contract_failed",
        }
    )


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})
policy = evidence.get("gate_policy", {})

if contract.get("schema") != "reverse_loader_process_abi_standalone_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != "bd-bp8fl.3.7":
    errors.append("bead must be bd-bp8fl.3.7")
if contract.get("completion_debt_bead") != "bd-bp8fl.3.7.1":
    errors.append("completion_debt_bead must be bd-bp8fl.3.7.1")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != REQUIRED_MISSING_ITEMS:
    errors.append(f"missing_items mismatch: {sorted(missing_items)}")

required_artifacts = {
    "base_artifact",
    "base_checker",
    "base_harness_test",
    "standalone_smoke_artifact",
    "standalone_smoke_checker",
    "completion_contract",
    "completion_checker",
    "completion_harness_test",
}
artifact_paths: dict[str, Path] = {}
for name in required_artifacts:
    value = artifacts.get(name)
    if not isinstance(value, str):
        errors.append(f"artifact {name} must be a string path")
        continue
    try:
        path = rel_path(value)
    except ValueError as exc:
        errors.append(str(exc))
        continue
    artifact_paths[name] = path
    if not path.is_file():
        errors.append(f"artifact {name} missing: {value}")

for ref in evidence.get("implementation_refs", []):
    check_file_line_ref(str(ref))

base_artifact = load_json(artifact_paths.get("base_artifact", contract_path))
base_checker_text = artifact_paths.get("base_checker", contract_path).read_text(encoding="utf-8")
base_test_text = artifact_paths.get("base_harness_test", contract_path).read_text(encoding="utf-8")

if base_artifact.get("schema_version") != "v1":
    errors.append("base artifact schema_version must be v1")
if base_artifact.get("bead") != "bd-bp8fl.3.7":
    errors.append("base artifact bead must be bd-bp8fl.3.7")
if base_artifact.get("required_log_fields") != REQUIRED_GATE_LOG_FIELDS:
    errors.append("base artifact required_log_fields drifted")
if base_artifact.get("claim_policy", {}).get("missing_negative_claim_row") != "claim_blocked":
    errors.append("base artifact claim policy must block missing negative claim rows")

rows = base_artifact.get("rows", [])
if not isinstance(rows, list) or len(rows) != policy.get("required_gap_count"):
    errors.append("base artifact must keep ten reverse-loader gap rows")
versioned_symbol_requirement_count = 0
for index, row in enumerate(rows if isinstance(rows, list) else []):
    context = f"row[{index}]"
    if row.get("evidence_kind") != policy.get("required_evidence_kind"):
        errors.append(f"{context}: evidence_kind drifted")
    if row.get("negative_smoke_id") != policy.get("required_negative_smoke_id"):
        errors.append(f"{context}: negative_smoke_id drifted")
    if row.get("claim_replacement_levels") != policy.get("required_claim_levels"):
        errors.append(f"{context}: claim_replacement_levels drifted")
    runtime_evidence = row.get("runtime_evidence", {})
    strict = runtime_evidence.get("strict") if isinstance(runtime_evidence, dict) else None
    hardened = runtime_evidence.get("hardened") if isinstance(runtime_evidence, dict) else None
    if not isinstance(strict, dict) or not isinstance(hardened, dict):
        errors.append(f"{context}: strict+hardened evidence required")
    for req in row.get("versioned_symbol_requirements", []):
        if isinstance(req, dict) and req.get("symbol") and req.get("version"):
            versioned_symbol_requirement_count += 1
        else:
            errors.append(f"{context}: malformed versioned_symbol_requirements entry")

claim_policy = base_artifact.get("claim_policy", {})
rejected = set(claim_policy.get("rejected_evidence_kinds", []))
required_rejections = set(policy.get("required_claim_rejections", []))
if not required_rejections <= rejected:
    errors.append(f"claim_policy missing rejected evidence kinds: {sorted(required_rejections - rejected)}")
if claim_policy.get("ld_preload_evidence_accepted") is not False:
    errors.append("claim policy must reject LD_PRELOAD evidence")
if claim_policy.get("summary_only_claims_accepted") is not False:
    errors.append("claim policy must reject summary-only claims")

for required in [
    "EXPECTED_GAP_IDS",
    "NEGATIVE_SMOKE_ID",
    "ALLOWED_EVIDENCE_KIND",
    "versioned_symbol_binding",
    "standalone_smoke_binding",
    "structured_log",
    "source_commit_is_current",
]:
    require_contains("base checker", base_checker_text, required)

for required in [
    "gate_artifact_preserves_loader_process_gap_contract",
    "checker_passes_and_emits_report_and_logs",
    "checker_rejects_missing_source_commit_freshness_policy",
    "checker_rejects_missing_gap_row",
    "checker_rejects_stale_source_commit",
    "checker_rejects_missing_versioned_symbol",
    "checker_rejects_missing_negative_row_binding",
    "checker_rejects_expected_actual_mismatch",
]:
    require_contains("base harness test", base_test_text, required)

for section_name in ["unit_primary", "conformance_primary"]:
    section = evidence.get(section_name, {})
    for test_ref in section.get("required_test_refs", []):
        source = test_ref.get("source")
        name = test_ref.get("name")
        if not isinstance(source, str) or source not in artifact_paths:
            errors.append(f"{section_name} test ref has unknown source: {test_ref}")
            continue
        if not isinstance(name, str) or not name:
            errors.append(f"{section_name} test ref has missing name: {test_ref}")
            continue
        require_test_fn(artifact_paths[source], name)
    for command in section.get("required_commands", []):
        if not command_uses_rch_or_script(str(command)):
            errors.append(f"required command must use rch or a repo script, not bare cargo: {command}")

for script in evidence.get("conformance_primary", {}).get("required_scripts", []):
    script_path_text = str(script).split()[0]
    try:
        script_path = rel_path(script_path_text)
    except ValueError as exc:
        errors.append(str(exc))
        continue
    if not script_path.is_file():
        errors.append(f"required script missing: {script}")

telemetry = evidence.get("telemetry_primary", {})
if set(telemetry.get("required_events", [])) != REQUIRED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != REQUIRED_FIELDS:
    errors.append("telemetry required_fields mismatch")

base_report, base_log_rows = run_base_gate(artifact_paths.get("base_checker", contract_path))
base_summary: dict[str, Any] = {}
if isinstance(base_report, dict):
    if base_report.get("status") != "pass":
        errors.append("base reverse-loader gate report must pass")
    checks = base_report.get("checks", {})
    for check in REQUIRED_REPORT_CHECKS:
        if checks.get(check) != "pass":
            errors.append(f"base reverse-loader report check must pass: {check}")
    base_summary = base_report.get("summary", {}) if isinstance(base_report.get("summary"), dict) else {}
    if base_summary.get("gap_rows") != policy.get("required_gap_count"):
        errors.append("base report gap_rows must match required gap count")
    if base_summary.get("structured_log_rows") != policy.get("required_structured_log_rows"):
        errors.append("base report structured_log_rows must be strict+hardened for every gap")

if len(base_log_rows) != policy.get("required_structured_log_rows"):
    errors.append("base reverse-loader log must include strict+hardened rows for every gap")
for index, row in enumerate(base_log_rows):
    for field in REQUIRED_GATE_LOG_FIELDS:
        if field not in row:
            errors.append(f"base reverse-loader log row {index} missing field {field}")

smoke_report = run_json_command(
    ["bash", str(artifact_paths.get("standalone_smoke_checker", contract_path)), "--validate-only"],
    "standalone smoke validate-only",
)
standalone_claim_status = "unknown"
standalone_artifact_status = "unknown"
positive_smoke_rows = 0
negative_smoke_rows = 0
if smoke_report:
    if smoke_report.get("status") != "pass":
        errors.append("standalone smoke validate-only report must pass")
    if smoke_report.get("ld_preload_evidence_accepted") is not False:
        errors.append("standalone smoke validate-only must keep LD_PRELOAD evidence rejected")
    standalone_claim_status = str(smoke_report.get("claim_status", "unknown"))
    artifact_state = smoke_report.get("artifact_state", {})
    standalone_artifact_status = str(artifact_state.get("status", "unknown")) if isinstance(artifact_state, dict) else "unknown"
    summary = smoke_report.get("summary", {})
    if isinstance(summary, dict):
        positive_smoke_rows = int(summary.get("positive_rows", 0))
        negative_smoke_rows = int(summary.get("negative_rows", 0))
    if standalone_claim_status != "schema_validated":
        errors.append("standalone smoke validate-only claim_status must remain schema_validated")
    if standalone_artifact_status != "missing":
        errors.append("standalone smoke validate-only must expose missing replacement artifact state")

status = "fail" if errors else "pass"
summary = {
    "gap_count": base_summary.get("gap_rows", len(rows) if isinstance(rows, list) else 0),
    "structured_log_row_count": base_summary.get("structured_log_rows", len(base_log_rows)),
    "versioned_symbol_requirement_count": versioned_symbol_requirement_count,
    "positive_smoke_row_count": base_summary.get("positive_smoke_rows", positive_smoke_rows),
    "negative_smoke_row_count": base_summary.get("negative_smoke_rows", negative_smoke_rows),
    "standalone_claim_status": standalone_claim_status,
    "standalone_artifact_status": standalone_artifact_status,
}

for event in sorted(REQUIRED_EVENTS):
    emit_event(event, status, summary=summary)

for event in events:
    for field in REQUIRED_FIELDS:
        if field not in event:
            errors.append(f"completion event {event.get('event')} missing field {field}")

status = "fail" if errors else "pass"
for event in events:
    event["status"] = status
    event["errno"] = 0 if status == "pass" else 1
    event["failure_signature"] = (
        "none" if status == "pass" else "reverse_loader_standalone_completion_contract_failed"
    )

report = {
    "schema": "reverse_loader_process_abi_standalone_completion_contract.report.v1",
    "status": status,
    "completion_debt_bead": "bd-bp8fl.3.7.1",
    "original_bead": "bd-bp8fl.3.7",
    "source_commit": SOURCE_COMMIT,
    "summary": summary,
    "required_events": sorted(REQUIRED_EVENTS),
    "required_fields": sorted(REQUIRED_FIELDS),
    "base_report": "target/conformance/reverse_loader_process_abi_standalone_gate.report.json",
    "base_log": "target/conformance/reverse_loader_process_abi_standalone_gate.log.jsonl",
    "standalone_smoke_report": "target/conformance/standalone_link_run_smoke.report.json",
    "standalone_smoke_log": "target/conformance/standalone_link_run_smoke.log.jsonl",
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    raise SystemExit(1)
PY
