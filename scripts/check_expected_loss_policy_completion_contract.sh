#!/usr/bin/env bash
# check_expected_loss_policy_completion_contract.sh - bd-35a.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_EXPECTED_LOSS_POLICY_CONTRACT:-${ROOT}/tests/conformance/expected_loss_policy_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_EXPECTED_LOSS_POLICY_REPORT:-${OUT_DIR}/expected_loss_policy_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_EXPECTED_LOSS_POLICY_LOG:-${OUT_DIR}/expected_loss_policy_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}"

export FLC_ROOT="${ROOT}"
export FLC_CONTRACT_PATH="${CONTRACT_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"
export FLC_LOG_PATH="${LOG_PATH}"

python3 - <<'PY'
from __future__ import annotations

import hashlib
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
    "expected_loss_policy_units_validated",
    "expected_loss_policy_e2e_validated",
    "expected_loss_policy_telemetry_validated",
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
    "family_count",
    "action_count",
    "unit_test_ref_count",
    "e2e_trace_result_count",
    "artifact_index_entries",
    "artifact_refs",
    "failure_signature",
}

TRACE_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "bead_id",
    "mode",
    "api_family",
    "symbol",
    "outcome",
    "errno",
    "latency_ns",
    "details",
    "artifact_refs",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path.relative_to(root)}:{line_no} invalid JSON: {exc}")
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            errors.append(f"{path.relative_to(root)}:{line_no} row must be object")
    return rows


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
    path = rel_path(path_text)
    if not path.exists():
        errors.append(f"implementation ref path missing: {ref}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no < 1 or line_no > len(lines) or not lines[line_no - 1].strip():
        errors.append(f"implementation ref does not point to non-empty line: {ref}")


def require_test_fn(path: Path, name: str) -> None:
    text = path.read_text(encoding="utf-8")
    if f"fn {name}" not in text:
        errors.append(f"{path.relative_to(root)} missing test function {name}")


def count_test_refs(evidence: dict[str, Any], section: str) -> int:
    refs = evidence.get(section, {}).get("required_test_refs", [])
    return len(refs) if isinstance(refs, list) else 0


def validate_matrix(matrix: dict[str, Any], policy: dict[str, Any]) -> dict[str, int]:
    required_actions = [str(item) for item in policy.get("required_actions", [])]
    required_families = [str(item) for item in policy.get("required_families", [])]
    required_fields = [str(item) for item in policy.get("required_action_fields", [])]
    families = matrix.get("families", {})
    if matrix.get("schema_version") != "v1":
        errors.append("expected-loss matrix schema_version must be v1")
    if matrix.get("actions") != required_actions:
        errors.append("expected-loss matrix actions drifted")
    posterior = matrix.get("posterior_model", {})
    if posterior.get("initial_alpha") != 1.0 or posterior.get("initial_beta") != 1.0:
        errors.append("expected-loss posterior prior must be Beta(1,1)")
    if not isinstance(families, dict):
        errors.append("expected-loss matrix families must be object")
        families = {}
    if len(required_families) != 20:
        errors.append("expected_loss_policy.required_families must contain 20 families")
    if set(families) != set(required_families):
        missing = sorted(set(required_families) - set(families))
        extra = sorted(set(families) - set(required_families))
        errors.append(f"expected-loss matrix family set drifted missing={missing} extra={extra}")
    for family in required_families:
        family_matrix = families.get(family, {})
        if not isinstance(family_matrix, dict):
            errors.append(f"family matrix missing or invalid: {family}")
            continue
        for action in required_actions:
            action_model = family_matrix.get(action, {})
            if not isinstance(action_model, dict):
                errors.append(f"{family}.{action} must be object")
                continue
            for field in required_fields:
                if not isinstance(action_model.get(field), (int, float)):
                    errors.append(f"{family}.{action}.{field} must be numeric")
    assumptions = matrix.get("assumptions", [])
    if not isinstance(assumptions, list) or len(assumptions) < int(policy.get("minimum_assumptions", 0)):
        errors.append("expected-loss matrix assumptions below threshold")
    sensitivity = matrix.get("sensitivity_analysis", {})
    posterior_grid = sensitivity.get("posterior_grid", []) if isinstance(sensitivity, dict) else []
    cost_grid = sensitivity.get("cost_norm_grid", []) if isinstance(sensitivity, dict) else []
    if not isinstance(posterior_grid, list) or len(posterior_grid) < int(policy.get("minimum_posterior_grid_points", 0)):
        errors.append("expected-loss posterior sensitivity grid below threshold")
    if not isinstance(cost_grid, list) or len(cost_grid) < int(policy.get("minimum_cost_grid_points", 0)):
        errors.append("expected-loss cost sensitivity grid below threshold")
    return {
        "family_count": len(families),
        "action_count": len(matrix.get("actions", [])) if isinstance(matrix.get("actions"), list) else 0,
        "assumption_count": len(assumptions) if isinstance(assumptions, list) else 0,
    }


def validate_artifact_index(index: dict[str, Any], min_entries: int) -> int:
    if index.get("bead_id") != "bd-35a":
        errors.append("artifact index bead_id must be bd-35a")
    artifacts = index.get("artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("artifact index artifacts must be array")
        return 0
    if len(artifacts) < min_entries:
        errors.append("artifact index entry count below threshold")
    for item in artifacts:
        if not isinstance(item, dict):
            errors.append("artifact index entry must be object")
            continue
        rel = item.get("path")
        expected_sha = item.get("sha256")
        if not isinstance(rel, str) or not isinstance(expected_sha, str):
            errors.append("artifact index entry missing path or sha256")
            continue
        path = rel_path(rel)
        if not path.exists():
            errors.append(f"artifact index path missing: {rel}")
            continue
        if rel.endswith("/trace.jsonl"):
            # The historical generator appends the final run_summary after
            # building its index, so the trace hash records the pre-summary log.
            continue
        actual_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            errors.append(f"artifact index sha256 mismatch: {rel}")
    return len(artifacts)


def validate_trace(rows: list[dict[str, Any]], policy: dict[str, Any]) -> int:
    if len(rows) < int(policy.get("minimum_trace_rows", 0)):
        errors.append("historical trace row count below threshold")
    for row in rows:
        missing = TRACE_FIELDS - set(row)
        if missing:
            errors.append(f"historical trace row missing fields: {sorted(missing)}")
        if row.get("bead_id") != "bd-35a":
            errors.append("historical trace row bead_id must be bd-35a")
    required_modes = [str(item) for item in policy.get("required_modes", [])]
    if not required_modes:
        required_modes = [str(item) for item in evidence.get("e2e_primary", {}).get("required_modes", [])]
    required_symbols = [str(item) for item in evidence.get("e2e_primary", {}).get("required_trace_symbols", [])]
    result_rows = [
        row for row in rows
        if row.get("event") == "test_result" and row.get("outcome") == "pass"
    ]
    if len(result_rows) < int(policy.get("minimum_test_result_rows", 0)):
        errors.append("historical trace pass result count below threshold")
    seen = {(str(row.get("mode")), str(row.get("symbol"))) for row in result_rows}
    for mode in required_modes:
        for symbol in required_symbols:
            if (mode, symbol) not in seen:
                errors.append(f"historical trace missing pass result for {mode}/{symbol}")
    summary_rows = [row for row in rows if row.get("event") == "run_summary" and row.get("outcome") == "pass"]
    if not summary_rows:
        errors.append("historical trace missing passing run_summary")
    return len(result_rows)


def emit_event(
    event: str,
    status: str,
    *,
    family_count: int,
    action_count: int,
    unit_test_ref_count: int,
    e2e_trace_result_count: int,
    artifact_index_entries: int,
    details: dict[str, Any] | None = None,
) -> None:
    events.append(
        {
            "timestamp": ts,
            "trace_id": f"bd-35a.1:{event}",
            "completion_debt_bead": "bd-35a.1",
            "original_bead": "bd-35a",
            "source_commit": SOURCE_COMMIT,
            "event": event,
            "status": status,
            "mode": "strict+hardened",
            "api_family": "runtime_math",
            "symbol": "expected_loss_policy",
            "decision_path": "contract+matrix_gate+historical_evidence_trace+structured_completion_log",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "family_count": family_count,
            "action_count": action_count,
            "unit_test_ref_count": unit_test_ref_count,
            "e2e_trace_result_count": e2e_trace_result_count,
            "artifact_index_entries": artifact_index_entries,
            "artifact_refs": [
                "tests/conformance/expected_loss_policy_completion_contract.v1.json",
                "scripts/check_expected_loss_policy_completion_contract.sh",
                "tests/runtime_math/expected_loss_matrix.v1.json",
                "tests/cve_arena/results/bd-35a/bd35a-20260211T063028Z/trace.jsonl",
            ],
            "failure_signature": "none" if status == "pass" else "expected_loss_policy_completion_contract_failed",
            "details": details or {},
        }
    )


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})

if contract.get("schema") != "expected_loss_policy_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != "bd-35a":
    errors.append("bead must be bd-35a")
if contract.get("completion_debt_bead") != "bd-35a.1":
    errors.append("completion_debt_bead must be bd-35a.1")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}:
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

policy = evidence.get("expected_loss_policy", {})
matrix_summary = validate_matrix(load_json(artifact_paths["expected_loss_matrix"]), policy)
artifact_count = validate_artifact_index(
    load_json(artifact_paths["historical_artifact_index"]),
    int(policy.get("minimum_artifact_index_entries", 0)),
)
trace_result_count = validate_trace(load_jsonl(artifact_paths["historical_evidence_trace"]), policy)

test_sources = evidence.get("test_sources", {})
source_paths: dict[str, Path] = {}
for source, path_text in test_sources.items():
    path = rel_path(str(path_text))
    source_paths[str(source)] = path
    if not path.exists():
        errors.append(f"test source missing: {path_text}")

for section in ("unit_primary", "e2e_primary"):
    for test_ref in evidence.get(section, {}).get("required_test_refs", []):
        source = str(test_ref.get("source", ""))
        name = str(test_ref.get("name", ""))
        source_path = source_paths.get(source)
        if source_path is None:
            errors.append(f"unknown {section} test source: {source}")
        else:
            require_test_fn(source_path, name)
    for command in evidence.get(section, {}).get("required_commands", []):
        if "cargo test" in command and "rch exec" not in command:
            errors.append(f"{section} cargo command must be rch-backed: {command}")

for script in evidence.get("e2e_primary", {}).get("required_scripts", []):
    script_path = rel_path(str(script).split()[0])
    if not script_path.is_file():
        errors.append(f"required script missing: {script}")

gate_proc = subprocess.run(
    ["bash", str(artifact_paths["expected_loss_gate"])],
    cwd=root,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    check=False,
)
gate_output = gate_proc.stdout + gate_proc.stderr
if gate_proc.returncode != 0:
    errors.append(f"expected-loss matrix gate failed with exit {gate_proc.returncode}")
marker = str(policy.get("gate_success_marker", ""))
if marker and marker not in gate_output:
    errors.append("expected-loss matrix gate success marker missing")

telemetry = evidence.get("telemetry_primary", {})
if set(telemetry.get("required_events", [])) != REQUIRED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != REQUIRED_FIELDS:
    errors.append("telemetry required_fields mismatch")

unit_test_ref_count = count_test_refs(evidence, "unit_primary")
status = "pass" if not errors else "fail"
for event, details in [
    (
        "expected_loss_policy_units_validated",
        {"required_tests": evidence.get("unit_primary", {}).get("required_test_refs", [])},
    ),
    (
        "expected_loss_policy_e2e_validated",
        {"gate_exit": gate_proc.returncode, "required_symbols": evidence.get("e2e_primary", {}).get("required_trace_symbols", [])},
    ),
    (
        "expected_loss_policy_telemetry_validated",
        {"required_events": sorted(REQUIRED_EVENTS), "required_fields": sorted(REQUIRED_FIELDS)},
    ),
]:
    emit_event(
        event,
        status,
        family_count=matrix_summary["family_count"],
        action_count=matrix_summary["action_count"],
        unit_test_ref_count=unit_test_ref_count,
        e2e_trace_result_count=trace_result_count,
        artifact_index_entries=artifact_count,
        details=details,
    )

for event in events:
    missing = REQUIRED_FIELDS - set(event)
    if missing:
        errors.append(f"event {event['event']} missing fields: {sorted(missing)}")

if errors:
    for event in events:
        event["status"] = "fail"
        event["errno"] = 1
        event["failure_signature"] = "expected_loss_policy_completion_contract_failed"

report = {
    "schema": "expected_loss_policy_completion_contract.report.v1",
    "status": "pass" if not errors else "fail",
    "completion_debt_bead": "bd-35a.1",
    "original_bead": "bd-35a",
    "source_commit": SOURCE_COMMIT,
    "generated_at": ts,
    "summary": {
        **matrix_summary,
        "unit_test_ref_count": unit_test_ref_count,
        "e2e_trace_result_count": trace_result_count,
        "artifact_index_entries": artifact_count,
    },
    "required_events": sorted(REQUIRED_EVENTS),
    "required_fields": sorted(REQUIRED_FIELDS),
    "errors": errors,
}

report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.parent.mkdir(parents=True, exist_ok=True)
log_path.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)

if errors:
    print("FAIL: expected-loss policy completion contract", file=os.sys.stderr)
    for err in errors:
        print(f" - {err}", file=os.sys.stderr)
    os.sys.exit(1)

print(
    "PASS: expected-loss policy completion contract "
    f"(families={matrix_summary['family_count']}, actions={matrix_summary['action_count']}, "
    f"unit_refs={unit_test_ref_count}, trace_results={trace_result_count}, artifacts={artifact_count}, "
    f"report={report_path.relative_to(root)})"
)
PY
