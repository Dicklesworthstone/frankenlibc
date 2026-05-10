#!/usr/bin/env bash
# check_support_matrix_maintenance_completion_contract.sh - bd-3g4p.1 gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_SUPPORT_MATRIX_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/support_matrix_maintenance_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_SUPPORT_MATRIX_COMPLETION_REPORT:-${OUT_DIR}/support_matrix_maintenance_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_SUPPORT_MATRIX_COMPLETION_LOG:-${OUT_DIR}/support_matrix_maintenance_completion_contract.log.jsonl}"

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

COMPLETION_BEAD = "bd-3g4p.1"
ORIGINAL_BEAD = "bd-3g4p"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
}
REQUIRED_COMPLETION_EVENTS = {
    "support_matrix_maintenance_units_validated",
    "support_matrix_maintenance_e2e_validated",
    "support_matrix_maintenance_conformance_validated",
}

errors: list[str] = []
test_refs: set[str] = set()


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {path}: {exc}")
        return {}


def load_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    try:
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
        return rows
    except Exception as exc:
        errors.append(f"{label} unreadable: {path}: {exc}")
        return []


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def rel_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay under workspace root: {value}")
    return root / path


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
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
        errors.append(f"implementation ref does not point to a non-empty line: {ref}")


def require_test_fn(source_name: str, path: Path, name: str) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"{source_name} unreadable: {path}: {exc}")
        return
    if f"fn {name}" not in text:
        errors.append(f"{source_name} missing test function {name}")
    test_refs.add(f"{source_name}::{name}")


def stable_sections(report: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    return {key: report.get(key) for key in keys}


def run_command(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    command_env = os.environ.copy()
    if env:
        command_env.update(env)
    return subprocess.run(
        args,
        cwd=root,
        env=command_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


contract = load_json(contract_path, "contract")
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})
policy = evidence.get("maintenance_policy", {})

if contract.get("schema") != "support_matrix_maintenance_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != ORIGINAL_BEAD:
    errors.append(f"bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_BEAD}")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != REQUIRED_MISSING_ITEMS:
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

test_sources: dict[str, Path] = {}
for source_name, path_text in evidence.get("test_sources", {}).items():
    try:
        test_sources[source_name] = rel_path(str(path_text))
    except ValueError as exc:
        errors.append(str(exc))

for section_name, missing_item in [
    ("unit_primary", "tests.unit.primary"),
    ("e2e_primary", "tests.e2e.primary"),
    ("conformance_primary", "tests.conformance.primary"),
]:
    section = evidence.get(section_name, {})
    if section.get("missing_item_id") != missing_item:
        errors.append(f"{section_name}.missing_item_id must be {missing_item}")
    refs = section.get("required_test_refs", [])
    if not isinstance(refs, list) or not refs:
        errors.append(f"{section_name}.required_test_refs missing")
    for ref in refs:
        source_name = str(ref.get("source", ""))
        name = str(ref.get("name", ""))
        source_path = test_sources.get(source_name)
        if not source_path:
            errors.append(f"{section_name} references undeclared source {source_name!r}")
            continue
        require_test_fn(source_name, source_path, name)

canonical = load_json(artifact_paths.get("canonical_report", root / "missing"), "canonical report")
if canonical.get("schema_version") != policy.get("required_schema"):
    errors.append("canonical report schema_version mismatch")
if canonical.get("bead") != policy.get("required_bead"):
    errors.append("canonical report bead mismatch")

summary = canonical.get("summary", {})
dashboard = canonical.get("coverage_dashboard", {})
status_counts = dashboard.get("status_counts", {}) if isinstance(dashboard, dict) else {}

total_symbols = int(summary.get("total_symbols", 0))
status_invalid = int(summary.get("status_invalid", 0))
fixture_linked = int(summary.get("fixture_linked", 0))
status_valid_pct = float(summary.get("status_valid_pct", 0.0))
native_coverage_pct = float(dashboard.get("native_coverage_pct", 0.0)) if isinstance(dashboard, dict) else 0.0

if total_symbols < int(policy.get("minimum_total_symbols", 0)):
    errors.append("canonical total_symbols below minimum")
if status_valid_pct < float(policy.get("minimum_status_valid_pct", 0.0)):
    errors.append("canonical status_valid_pct below minimum")
if status_invalid > int(policy.get("maximum_status_invalid", 0)):
    errors.append("canonical status_invalid above maximum")
if fixture_linked < int(policy.get("minimum_fixture_linked", 0)):
    errors.append("canonical fixture_linked below minimum")
if native_coverage_pct != float(policy.get("required_native_coverage_pct", -1.0)):
    errors.append("canonical native_coverage_pct mismatch")
for status, expected in policy.get("forbidden_status_counts", {}).items():
    if int(status_counts.get(status, 0)) != int(expected):
        errors.append(f"canonical forbidden status count mismatch for {status}")

self_test = run_command(["python3", "scripts/generate_support_matrix_maintenance.py", "--self-test"])
if self_test.returncode != 0:
    errors.append(f"generator self-test failed: stdout={self_test.stdout} stderr={self_test.stderr}")

gate = run_command(
    ["bash", "scripts/check_support_matrix_maintenance.sh"],
    env={"FRANKENLIBC_SYMBOL_GATE_TRACE": "1"},
)
if gate.returncode != 0:
    errors.append(f"maintenance gate failed: stdout={gate.stdout} stderr={gate.stderr}")

generated_path = root / "target/conformance/support_matrix_maintenance.generated.json"
gate_log_path = root / "target/conformance/support_matrix_maintenance.log.jsonl"
generated = load_json(generated_path, "generated maintenance report")
gate_rows = load_jsonl(gate_log_path, "maintenance gate log")

stable_keys = list(policy.get("required_stable_sections", []))
if stable_sections(generated, stable_keys) != stable_sections(canonical, stable_keys):
    errors.append("generated report stable sections drift from canonical")

gate_events = {str(row.get("event", "")) for row in gate_rows}
for event in policy.get("required_gate_events", []):
    if event not in gate_events:
        errors.append(f"maintenance gate log missing event {event}")

completion_status = "pass" if not errors else "fail"
failure_signature = (
    "none" if completion_status == "pass" else "support_matrix_maintenance_completion_contract_failed"
)
artifact_refs = [
    rel(contract_path),
    rel(report_path),
    rel(log_path),
    "scripts/generate_support_matrix_maintenance.py",
    "scripts/check_support_matrix_maintenance.sh",
    "tests/conformance/support_matrix_maintenance_report.v1.json",
    "target/conformance/support_matrix_maintenance.generated.json",
    "target/conformance/support_matrix_maintenance.log.jsonl",
]
required_fields = set(policy.get("required_log_fields", []))


def make_event(event: str) -> dict[str, Any]:
    return {
        "timestamp": ts,
        "trace_id": f"{COMPLETION_BEAD}:{event}",
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": SOURCE_COMMIT,
        "event": event,
        "status": completion_status,
        "mode": "completion-contract",
        "api_family": "support_matrix",
        "symbol": "all",
        "decision_path": "contract+generator_self_test+maintenance_gate+canonical_stable_sections",
        "healing_action": "None",
        "errno": 0 if completion_status == "pass" else 1,
        "latency_ns": 0,
        "total_symbols": total_symbols,
        "status_invalid": status_invalid,
        "fixture_linked": fixture_linked,
        "native_coverage_pct": native_coverage_pct,
        "artifact_refs": artifact_refs,
        "test_refs": sorted(test_refs),
        "failure_signature": failure_signature,
    }


rows = [make_event(event) for event in sorted(REQUIRED_COMPLETION_EVENTS)]
for row in rows:
    missing = required_fields - set(row.keys())
    if missing:
        errors.append(f"completion event {row['event']} missing fields: {sorted(missing)}")

if errors:
    completion_status = "fail"
    failure_signature = "support_matrix_maintenance_completion_contract_failed"
    rows = [make_event(event) for event in sorted(REQUIRED_COMPLETION_EVENTS)]

report = {
    "schema_version": "support_matrix_maintenance_completion_contract.report.v1",
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": SOURCE_COMMIT,
    "status": completion_status,
    "contract": rel(contract_path),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "summary": {
        "total_symbols": total_symbols,
        "status_valid_pct": status_valid_pct,
        "status_invalid": status_invalid,
        "fixture_linked": fixture_linked,
        "native_coverage_pct": native_coverage_pct,
        "gate_event_count": len(gate_rows),
        "test_ref_count": len(test_refs),
    },
    "required_fields": sorted(required_fields),
    "test_refs": sorted(test_refs),
    "errors": errors,
    "artifact_refs": artifact_refs,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
    encoding="utf-8",
)

print(f"STATUS={completion_status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"REPORT={rel(report_path)}")
print(f"LOG={rel(log_path)}")
for error in errors:
    print(f"ERROR: {error}")

if errors:
    raise SystemExit(1)
PY
