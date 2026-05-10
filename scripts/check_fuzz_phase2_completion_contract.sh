#!/usr/bin/env bash
# check_fuzz_phase2_completion_contract.sh - bd-1oz.7.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_FUZZ_PHASE2_CONTRACT:-${ROOT}/tests/conformance/fuzz_phase2_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_FUZZ_PHASE2_REPORT:-${OUT_DIR}/fuzz_phase2_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_FUZZ_PHASE2_LOG:-${OUT_DIR}/fuzz_phase2_completion_contract.log.jsonl}"

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
    "fuzz_phase2_units_validated",
    "fuzz_phase2_e2e_validated",
    "fuzz_phase2_fuzz_inventory_validated",
    "fuzz_phase2_conformance_validated",
    "fuzz_phase2_telemetry_validated",
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
    "target_group",
    "target_count",
    "runs_per_target",
    "max_crashes",
    "transition_family_count",
    "symbol_count",
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
    path = rel_path(path_text)
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


def emit_event(event: str, status: str, *, summary: dict[str, Any], details: dict[str, Any] | None = None) -> None:
    events.append(
        {
            "timestamp": ts,
            "trace_id": f"bd-1oz.7.1:{event}",
            "completion_debt_bead": "bd-1oz.7.1",
            "original_bead": "bd-1oz.7",
            "source_commit": SOURCE_COMMIT,
            "event": event,
            "status": status,
            "mode": "fuzz-phase2",
            "api_family": "fuzz",
            "symbol": "fuzz_phase2_targets",
            "decision_path": "contract+target_inventory+ci_nightly_policy",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "target_group": summary.get("target_group", "phase2"),
            "target_count": summary.get("target_count", 0),
            "runs_per_target": summary.get("runs_per_target", 0),
            "max_crashes": summary.get("max_crashes", -1),
            "transition_family_count": summary.get("transition_family_count", 0),
            "symbol_count": summary.get("symbol_count", 0),
            "artifact_refs": [
                "tests/conformance/fuzz_phase2_completion_contract.v1.json",
                "scripts/check_fuzz_phase2_completion_contract.sh",
                "tests/conformance/fuzz_phase2_targets.v1.json",
                "scripts/check_fuzz_phase2_targets.sh",
                "scripts/fuzz_nightly.sh",
            ],
            "failure_signature": "none" if status == "pass" else "fuzz_phase2_completion_contract_failed",
            "details": details or {},
        }
    )


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})

if contract.get("schema") != "fuzz_phase2_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != "bd-1oz.7":
    errors.append("bead must be bd-1oz.7")
if contract.get("completion_debt_bead") != "bd-1oz.7.1":
    errors.append("completion_debt_bead must be bd-1oz.7.1")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
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
    if not path.is_file():
        errors.append(f"artifact {name} missing: {value}")

for ref in evidence.get("implementation_refs", []):
    check_file_line_ref(str(ref))

phase2_report = load_json(artifact_paths["phase2_report"])
summary_json = phase2_report.get("summary", {})
targets_json = phase2_report.get("target_assessments", [])
nightly_policy = phase2_report.get("nightly_policy", {})
coverage = phase2_report.get("coverage_summary", {})
policy = evidence.get("phase2_policy", {})

required_targets = [str(item) for item in policy.get("required_targets", [])]
required_families = [str(item) for item in policy.get("required_transition_families", [])]
actual_targets = [str(row.get("target", "")) for row in targets_json if isinstance(row, dict)]
actual_families = [str(item) for item in coverage.get("transition_families", [])]
target_set = set(actual_targets)

if phase2_report.get("schema_version") != "v1":
    errors.append("phase2 report schema_version must be v1")
if phase2_report.get("bead") != "bd-1oz.7":
    errors.append("phase2 report bead must be bd-1oz.7")
if set(required_targets) != target_set:
    errors.append("required phase2 targets do not match report targets")
if set(nightly_policy.get("required_targets", [])) != target_set:
    errors.append("nightly policy targets do not match report targets")
if set(required_families) - set(actual_families):
    errors.append("missing required transition families")
if int(summary_json.get("total_targets", 0)) < int(policy.get("minimum_phase2_targets", 0)):
    errors.append("total_targets below threshold")
if int(summary_json.get("functional_targets", 0)) < int(policy.get("minimum_functional_targets", 0)):
    errors.append("functional_targets below threshold")
if int(summary_json.get("smoke_viable_targets", 0)) < int(policy.get("minimum_smoke_viable_targets", 0)):
    errors.append("smoke_viable_targets below threshold")
if float(summary_json.get("average_readiness_score", 0.0)) < float(policy.get("minimum_average_readiness_score", 0.0)):
    errors.append("average_readiness_score below threshold")
if int(summary_json.get("total_symbols_covered", 0)) < int(policy.get("minimum_symbol_coverage", 0)):
    errors.append("total_symbols_covered below threshold")
if int(nightly_policy.get("runs_per_target", 0)) != int(policy.get("runs_per_target", -1)):
    errors.append("nightly runs_per_target mismatch")
if int(nightly_policy.get("max_crashes", -1)) != int(policy.get("max_crashes", -2)):
    errors.append("nightly max_crashes mismatch")

fuzz_cargo = artifact_paths["fuzz_cargo"].read_text(encoding="utf-8")
for target in required_targets:
    target_path = artifact_paths.get(target)
    if target_path is None or not target_path.is_file():
        errors.append(f"required fuzz target source missing: {target}")
        continue
    expected_path = f"fuzz_targets/{target}.rs"
    if f'name = "{target}"' not in fuzz_cargo or f'path = "{expected_path}"' not in fuzz_cargo:
        errors.append(f"Cargo.toml missing bin wiring for {target}")

ci_text = artifact_paths["ci_workflow"].read_text(encoding="utf-8")
for required in [
    "scripts/check_fuzz_phase2_targets.sh",
    "FUZZ_RUNS_PER_TARGET=\"${FUZZ_RUNS_PER_TARGET:-1000000}\"",
    "cargo fuzz run --fuzz-dir crates/frankenlibc-fuzz",
    "fuzz_runtime_math",
    "fuzz-summary.v1.json",
]:
    if required not in ci_text:
        errors.append(f"CI workflow missing required fuzz policy text: {required}")

nightly_text = artifact_paths["nightly_runner"].read_text(encoding="utf-8")
for required in [
    "PHASE2_TARGETS=(",
    "cargo-fuzz not installed",
    "cargo check",
    "\"mode\": \"build-check-only\"",
    "\"total_crashes\": ${TOTAL_CRASHES}",
]:
    if required not in nightly_text:
        errors.append(f"fuzz_nightly.sh missing required policy text: {required}")

existing_harness = artifact_paths["existing_harness_test"]
completion_harness = artifact_paths["completion_harness_test"]
for section_name in ("unit_primary", "e2e_primary"):
    for test_ref in evidence.get(section_name, {}).get("required_test_refs", []):
        source = str(test_ref.get("source", ""))
        name = str(test_ref.get("name", ""))
        if source == "existing_harness_test":
            require_test_fn(existing_harness, name)
        elif source == "completion_harness_test":
            require_test_fn(completion_harness, name)
        else:
            errors.append(f"unknown test source: {source}")

for script in evidence.get("e2e_primary", {}).get("required_scripts", []):
    if not rel_path(str(script).split()[0]).is_file():
        errors.append(f"required script missing: {script}")

for section in ("unit_primary", "e2e_primary"):
    for command in evidence.get(section, {}).get("required_commands", []):
        if "cargo test" in command and "rch exec" not in command:
            errors.append(f"{section} cargo command must be rch-backed: {command}")

fuzz_primary = evidence.get("fuzz_primary", {})
if set(fuzz_primary.get("required_targets", [])) != set(required_targets):
    errors.append("fuzz_primary required_targets mismatch")
if int(fuzz_primary.get("max_crashes", -1)) != int(policy.get("max_crashes", -2)):
    errors.append("fuzz_primary max_crashes mismatch")
if "-runs=1000000" not in str(fuzz_primary.get("required_cargo_fuzz_command", "")):
    errors.append("fuzz_primary required command must pin -runs=1000000")

conformance = evidence.get("conformance_primary", {})
for artifact in conformance.get("required_artifacts", []):
    if str(artifact).startswith("target/conformance/"):
        continue
    if not rel_path(str(artifact)).is_file():
        errors.append(f"conformance artifact missing: {artifact}")

telemetry = evidence.get("telemetry_primary", {})
if set(telemetry.get("required_events", [])) != REQUIRED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != REQUIRED_FIELDS:
    errors.append("telemetry required_fields mismatch")

gate_proc = subprocess.run(
    ["bash", str(artifact_paths["phase2_checker"])],
    cwd=root,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    check=False,
)
gate_output = gate_proc.stdout + gate_proc.stderr
if gate_proc.returncode != 0:
    errors.append(f"existing fuzz phase2 gate failed with exit {gate_proc.returncode}")
for marker in policy.get("gate_success_markers", []):
    if str(marker) not in gate_output:
        errors.append(f"existing gate missing success marker: {marker}")

summary = {
    "target_group": nightly_policy.get("target_group", "phase2"),
    "target_count": len(actual_targets),
    "runs_per_target": int(nightly_policy.get("runs_per_target", 0)),
    "max_crashes": int(nightly_policy.get("max_crashes", -1)),
    "transition_family_count": len(actual_families),
    "symbol_count": int(summary_json.get("total_symbols_covered", 0)),
    "functional_targets": int(summary_json.get("functional_targets", 0)),
    "smoke_viable_targets": int(summary_json.get("smoke_viable_targets", 0)),
    "average_readiness_score": float(summary_json.get("average_readiness_score", 0.0)),
}

status = "pass" if not errors else "fail"
emit_event("fuzz_phase2_units_validated", status, summary=summary, details={"tests": evidence.get("unit_primary", {}).get("required_test_refs", [])})
emit_event("fuzz_phase2_e2e_validated", status, summary=summary, details={"existing_gate_exit": gate_proc.returncode})
emit_event("fuzz_phase2_fuzz_inventory_validated", status, summary=summary, details={"targets": actual_targets})
emit_event("fuzz_phase2_conformance_validated", status, summary=summary, details={"report": "tests/conformance/fuzz_phase2_targets.v1.json"})
emit_event("fuzz_phase2_telemetry_validated", status, summary=summary, details={"required_events": sorted(REQUIRED_EVENTS), "required_fields": sorted(REQUIRED_FIELDS)})

for event in events:
    missing = REQUIRED_FIELDS - set(event)
    if missing:
        errors.append(f"event {event['event']} missing fields: {sorted(missing)}")

if errors:
    for event in events:
        event["status"] = "fail"
        event["errno"] = 1
        event["failure_signature"] = "fuzz_phase2_completion_contract_failed"

report = {
    "schema": "fuzz_phase2_completion_contract.report.v1",
    "status": "pass" if not errors else "fail",
    "completion_debt_bead": "bd-1oz.7.1",
    "original_bead": "bd-1oz.7",
    "source_commit": SOURCE_COMMIT,
    "generated_at": ts,
    "summary": summary,
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
    print("FAIL: fuzz phase2 completion contract", file=os.sys.stderr)
    for err in errors:
        print(f" - {err}", file=os.sys.stderr)
    os.sys.exit(1)

print(
    "PASS: fuzz phase2 completion contract "
    f"(targets={summary['target_count']}, families={summary['transition_family_count']}, "
    f"symbols={summary['symbol_count']}, runs={summary['runs_per_target']}, "
    f"report={report_path.relative_to(root)})"
)
PY
