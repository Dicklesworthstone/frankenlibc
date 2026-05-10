#!/usr/bin/env bash
# check_unit_test_closure_packs_completion_contract.sh - bd-w2c3.9.1.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_UNIT_TEST_CLOSURE_PACKS_CONTRACT:-${ROOT}/tests/conformance/unit_test_closure_packs_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_UNIT_TEST_CLOSURE_PACKS_REPORT:-${OUT_DIR}/unit_test_closure_packs_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_UNIT_TEST_CLOSURE_PACKS_LOG:-${OUT_DIR}/unit_test_closure_packs_completion_contract.log.jsonl}"

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
    "unit_test_closure_pack_units_validated",
    "unit_test_closure_pack_e2e_validated",
    "unit_test_closure_pack_telemetry_validated",
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
    "fixture_files",
    "total_cases",
    "strict_cases",
    "hardened_cases",
    "required_family_count",
    "new_pack_count",
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


def emit_event(event: str, status: str, *, summary: dict[str, Any], details: dict[str, Any] | None = None) -> None:
    events.append(
        {
            "timestamp": ts,
            "trace_id": f"bd-w2c3.9.1.1:{event}",
            "completion_debt_bead": "bd-w2c3.9.1.1",
            "original_bead": "bd-w2c3.9.1",
            "source_commit": SOURCE_COMMIT,
            "event": event,
            "status": status,
            "mode": "strict+hardened",
            "api_family": "unit_test_closure_packs",
            "symbol": "scripts/check_unit_test_packs.sh",
            "decision_path": "contract+fixture_scan+existing_gate_replay",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "fixture_files": summary.get("fixture_files", 0),
            "total_cases": summary.get("total_cases", 0),
            "strict_cases": summary.get("strict_cases", 0),
            "hardened_cases": summary.get("hardened_cases", 0),
            "required_family_count": summary.get("required_family_count", 0),
            "new_pack_count": summary.get("new_pack_count", 0),
            "artifact_refs": [
                "tests/conformance/unit_test_closure_packs_completion_contract.v1.json",
                "scripts/check_unit_test_closure_packs_completion_contract.sh",
                "scripts/check_unit_test_packs.sh",
                "crates/frankenlibc-harness/tests/unit_test_closure_packs_test.rs",
            ],
            "failure_signature": "none" if status == "pass" else "unit_test_closure_packs_completion_contract_failed",
            "details": details or {},
        }
    )


def scan_fixtures(fixture_dir: Path, required_families: list[str], new_pack_files: list[str]) -> tuple[dict[str, Any], list[str]]:
    scan_errors: list[str] = []
    fixture_files = sorted(fixture_dir.glob("*.json"))
    families_found: set[str] = set()
    total_cases = 0
    strict_cases = 0
    hardened_cases = 0
    new_pack_summaries: dict[str, dict[str, int | str]] = {}

    for path in fixture_files:
        try:
            data = load_json(path)
        except Exception as exc:  # noqa: BLE001 - gate should report all parse failures.
            scan_errors.append(f"{path.relative_to(root)} failed to parse: {exc}")
            continue
        family = data.get("family", path.stem)
        families_found.add(str(family))
        cases = data.get("cases", [])
        if not isinstance(cases, list):
            scan_errors.append(f"{path.relative_to(root)} cases must be an array")
            cases = []
        strict = sum(1 for case in cases if isinstance(case, dict) and case.get("mode") == "strict")
        hardened = sum(1 for case in cases if isinstance(case, dict) and case.get("mode") == "hardened")
        total_cases += len(cases)
        strict_cases += strict
        hardened_cases += hardened
        if path.name in new_pack_files:
            new_pack_summaries[path.name] = {
                "family": str(family),
                "total_cases": len(cases),
                "strict_cases": strict,
                "hardened_cases": hardened,
            }
            if len(cases) == 0:
                scan_errors.append(f"{path.name} must contain cases")
            if strict == 0 or hardened == 0:
                scan_errors.append(f"{path.name} must contain both strict and hardened cases")

    missing_families = sorted(set(required_families) - families_found)
    if missing_families:
        scan_errors.append(f"missing required families: {missing_families}")
    missing_new_packs = sorted(set(new_pack_files) - set(new_pack_summaries))
    if missing_new_packs:
        scan_errors.append(f"missing new pack files: {missing_new_packs}")

    summary = {
        "fixture_files": len(fixture_files),
        "total_cases": total_cases,
        "strict_cases": strict_cases,
        "hardened_cases": hardened_cases,
        "required_family_count": len(required_families),
        "families_found": len(families_found),
        "missing_families": missing_families,
        "new_pack_count": len(new_pack_summaries),
        "new_pack_summaries": new_pack_summaries,
    }
    return summary, scan_errors


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})

if contract.get("schema") != "unit_test_closure_packs_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != "bd-w2c3.9.1":
    errors.append("bead must be bd-w2c3.9.1")
if contract.get("completion_debt_bead") != "bd-w2c3.9.1.1":
    errors.append("completion_debt_bead must be bd-w2c3.9.1.1")
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

policy = evidence.get("closure_pack_policy", {})
required_families = [str(item) for item in policy.get("required_families", [])]
new_pack_files = [str(item) for item in policy.get("new_pack_files", [])]
if len(required_families) != 12:
    errors.append("closure_pack_policy.required_families must contain 12 families")
if len(new_pack_files) != 7:
    errors.append("closure_pack_policy.new_pack_files must contain 7 files")

summary, scan_errors = scan_fixtures(artifact_paths["fixture_dir"], required_families, new_pack_files)
errors.extend(scan_errors)
if summary["fixture_files"] < int(policy.get("minimum_fixture_files", 0)):
    errors.append("fixture file count below completion threshold")
if summary["total_cases"] < int(policy.get("minimum_total_cases", 0)):
    errors.append("total case count below completion threshold")

existing_harness = artifact_paths["existing_harness_test"]
completion_harness = artifact_paths["completion_harness_test"]
for test_ref in evidence.get("unit_primary", {}).get("required_test_refs", []):
    source = str(test_ref.get("source", ""))
    name = str(test_ref.get("name", ""))
    if source == "existing_harness_test":
        require_test_fn(existing_harness, name)
    elif source == "completion_harness_test":
        require_test_fn(completion_harness, name)
    else:
        errors.append(f"unknown unit test source: {source}")
for test_ref in evidence.get("e2e_primary", {}).get("required_test_refs", []):
    source = str(test_ref.get("source", ""))
    name = str(test_ref.get("name", ""))
    if source == "completion_harness_test":
        require_test_fn(completion_harness, name)
    else:
        errors.append(f"unknown e2e test source: {source}")

for script in evidence.get("e2e_primary", {}).get("required_scripts", []):
    if not rel_path(str(script).split()[0]).is_file():
        errors.append(f"required script missing: {script}")

for section in ("unit_primary", "e2e_primary"):
    for command in evidence.get(section, {}).get("required_commands", []):
        if "cargo test" in command and "rch exec" not in command:
            errors.append(f"{section} cargo command must be rch-backed: {command}")

telemetry = evidence.get("telemetry_primary", {})
if set(telemetry.get("required_events", [])) != REQUIRED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != REQUIRED_FIELDS:
    errors.append("telemetry required_fields mismatch")

gate_proc = subprocess.run(
    ["bash", str(artifact_paths["existing_gate"])],
    cwd=root,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    check=False,
)
gate_output = gate_proc.stdout + gate_proc.stderr
if gate_proc.returncode != 0:
    errors.append(f"existing unit test pack gate failed with exit {gate_proc.returncode}")
for marker in policy.get("gate_success_markers", []):
    if str(marker) not in gate_output:
        errors.append(f"existing gate missing success marker: {marker}")

status = "pass" if not errors else "fail"
emit_event(
    "unit_test_closure_pack_units_validated",
    status,
    summary=summary,
    details={
        "required_families": required_families,
        "new_pack_files": new_pack_files,
    },
)
emit_event(
    "unit_test_closure_pack_e2e_validated",
    status,
    summary=summary,
    details={
        "existing_gate_exit": gate_proc.returncode,
        "existing_gate_markers": policy.get("gate_success_markers", []),
    },
)
emit_event(
    "unit_test_closure_pack_telemetry_validated",
    status,
    summary=summary,
    details={
        "required_events": sorted(REQUIRED_EVENTS),
        "required_fields": sorted(REQUIRED_FIELDS),
    },
)

for event in events:
    missing = REQUIRED_FIELDS - set(event)
    if missing:
        errors.append(f"event {event['event']} missing fields: {sorted(missing)}")

if errors:
    for event in events:
        event["status"] = "fail"
        event["errno"] = 1
        event["failure_signature"] = "unit_test_closure_packs_completion_contract_failed"

report = {
    "schema": "unit_test_closure_packs_completion_contract.report.v1",
    "status": "pass" if not errors else "fail",
    "completion_debt_bead": "bd-w2c3.9.1.1",
    "original_bead": "bd-w2c3.9.1",
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
    print("FAIL: unit test closure packs completion contract", file=os.sys.stderr)
    for err in errors:
        print(f" - {err}", file=os.sys.stderr)
    os.sys.exit(1)

print(
    "PASS: unit test closure packs completion contract "
    f"(fixtures={summary['fixture_files']}, cases={summary['total_cases']}, "
    f"strict={summary['strict_cases']}, hardened={summary['hardened_cases']}, "
    f"report={report_path.relative_to(root)})"
)
PY
