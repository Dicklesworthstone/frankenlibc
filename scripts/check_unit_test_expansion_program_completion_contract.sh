#!/usr/bin/env bash
# check_unit_test_expansion_program_completion_contract.sh - bd-25n.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_UNIT_TEST_EXPANSION_PROGRAM_CONTRACT:-${ROOT}/tests/conformance/unit_test_expansion_program_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_UNIT_TEST_EXPANSION_PROGRAM_REPORT:-${OUT_DIR}/unit_test_expansion_program_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_UNIT_TEST_EXPANSION_PROGRAM_LOG:-${OUT_DIR}/unit_test_expansion_program_completion_contract.log.jsonl}"

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
    "unit_test_expansion_program_units_validated",
    "unit_test_expansion_program_e2e_validated",
    "unit_test_expansion_program_telemetry_validated",
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
    "required_blocker_count",
    "closed_blocker_count",
    "unit_test_ref_count",
    "e2e_script_count",
    "fixture_files",
    "total_cases",
    "strict_cases",
    "hardened_cases",
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


def load_issues(path: Path) -> dict[str, dict[str, Any]]:
    issues: dict[str, dict[str, Any]] = {}
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            issue = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path.relative_to(root)}:{line_no} invalid JSON: {exc}")
            continue
        issue_id = issue.get("id")
        if isinstance(issue_id, str):
            issues[issue_id] = issue
    return issues


def dependency_ids(issue: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for dep in issue.get("dependencies", []):
        if not isinstance(dep, dict):
            continue
        dep_id = dep.get("depends_on_id") or dep.get("id")
        dep_type = dep.get("type") or dep.get("dependency_type")
        if isinstance(dep_id, str) and (dep_type in (None, "blocks") or dep.get("status") == "closed"):
            ids.add(dep_id)
    return ids


def require_test_fn(path: Path, name: str) -> None:
    text = path.read_text(encoding="utf-8")
    if f"fn {name}" not in text:
        errors.append(f"{path.relative_to(root)} missing test function {name}")


def count_test_refs(evidence: dict[str, Any], section: str) -> int:
    refs = evidence.get(section, {}).get("required_test_refs", [])
    return len(refs) if isinstance(refs, list) else 0


def scan_fixtures(fixture_dir: Path) -> tuple[dict[str, int], list[str]]:
    scan_errors: list[str] = []
    fixture_files = sorted(fixture_dir.glob("*.json"))
    total_cases = 0
    strict_cases = 0
    hardened_cases = 0
    for path in fixture_files:
        try:
            data = load_json(path)
        except Exception as exc:  # noqa: BLE001 - contract gate reports all parse failures.
            scan_errors.append(f"{path.relative_to(root)} failed to parse: {exc}")
            continue
        cases = data.get("cases", [])
        if not isinstance(cases, list):
            scan_errors.append(f"{path.relative_to(root)} cases must be an array")
            continue
        total_cases += len(cases)
        strict_cases += sum(1 for case in cases if isinstance(case, dict) and case.get("mode") == "strict")
        hardened_cases += sum(1 for case in cases if isinstance(case, dict) and case.get("mode") == "hardened")
    return (
        {
            "fixture_files": len(fixture_files),
            "total_cases": total_cases,
            "strict_cases": strict_cases,
            "hardened_cases": hardened_cases,
        },
        scan_errors,
    )


def emit_event(
    event: str,
    status: str,
    *,
    summary: dict[str, int],
    required_blocker_count: int,
    closed_blocker_count: int,
    unit_test_ref_count: int,
    e2e_script_count: int,
    details: dict[str, Any] | None = None,
) -> None:
    events.append(
        {
            "timestamp": ts,
            "trace_id": f"bd-25n.1:{event}",
            "completion_debt_bead": "bd-25n.1",
            "original_bead": "bd-25n",
            "source_commit": SOURCE_COMMIT,
            "event": event,
            "status": status,
            "mode": "strict+hardened",
            "api_family": "unit_test_expansion_program",
            "symbol": "bd-25n",
            "decision_path": "contract+bead_parent_closure+unit_pack_gate+structured_telemetry",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "required_blocker_count": required_blocker_count,
            "closed_blocker_count": closed_blocker_count,
            "unit_test_ref_count": unit_test_ref_count,
            "e2e_script_count": e2e_script_count,
            "fixture_files": summary.get("fixture_files", 0),
            "total_cases": summary.get("total_cases", 0),
            "strict_cases": summary.get("strict_cases", 0),
            "hardened_cases": summary.get("hardened_cases", 0),
            "artifact_refs": [
                "tests/conformance/unit_test_expansion_program_completion_contract.v1.json",
                "scripts/check_unit_test_expansion_program_completion_contract.sh",
                "scripts/check_unit_test_packs.sh",
                "crates/frankenlibc-harness/tests/unit_test_expansion_program_completion_contract_test.rs",
            ],
            "failure_signature": "none" if status == "pass" else "unit_test_expansion_program_completion_contract_failed",
            "details": details or {},
        }
    )


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})

if contract.get("schema") != "unit_test_expansion_program_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != "bd-25n":
    errors.append("bead must be bd-25n")
if contract.get("completion_debt_bead") != "bd-25n.1":
    errors.append("completion_debt_bead must be bd-25n.1")
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

issues = load_issues(artifact_paths["beads_jsonl"])
parent_contract = evidence.get("parent_closure_contract", {})
required_blockers = [str(item) for item in parent_contract.get("required_closed_blockers", [])]
if len(required_blockers) != 7:
    errors.append("parent_closure_contract.required_closed_blockers must contain 7 blockers")
parent_issue = issues.get("bd-25n")
closed_blockers = 0
if parent_issue is None:
    errors.append("parent bead bd-25n missing from beads JSONL")
else:
    if parent_issue.get("status") != parent_contract.get("required_parent_status"):
        errors.append("parent bead bd-25n must be closed")
    parent_deps = dependency_ids(parent_issue)
    for blocker in required_blockers:
        if blocker not in parent_deps:
            errors.append(f"parent bead bd-25n missing blocker dependency {blocker}")
    comments_text = "\n".join(
        str(comment.get("text", ""))
        for comment in parent_issue.get("comments", [])
        if isinstance(comment, dict)
    )
    for marker in parent_contract.get("required_comment_evidence_markers", []):
        if str(marker) not in comments_text:
            errors.append(f"parent comment evidence missing marker: {marker}")

for blocker in required_blockers:
    issue = issues.get(blocker)
    if issue is None:
        errors.append(f"required blocker issue missing: {blocker}")
        continue
    if issue.get("status") != "closed":
        errors.append(f"required blocker {blocker} is not closed")
        continue
    closed_blockers += 1

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

policy = evidence.get("unit_pack_policy", {})
summary, scan_errors = scan_fixtures(artifact_paths["fixture_dir"])
errors.extend(scan_errors)
for key in ("minimum_fixture_files", "minimum_total_cases", "minimum_strict_cases", "minimum_hardened_cases"):
    actual_key = key.removeprefix("minimum_")
    if summary.get(actual_key, 0) < int(policy.get(key, 0)):
        errors.append(f"{actual_key} below completion threshold")

if len(policy.get("threading_pack_tests", [])) != 7:
    errors.append("unit_pack_policy.threading_pack_tests must contain 7 test binaries")

gate_proc = subprocess.run(
    ["bash", str(artifact_paths["existing_unit_pack_gate"])],
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

telemetry = evidence.get("telemetry_primary", {})
if set(telemetry.get("required_events", [])) != REQUIRED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != REQUIRED_FIELDS:
    errors.append("telemetry required_fields mismatch")

unit_test_ref_count = count_test_refs(evidence, "unit_primary")
e2e_script_count = len(evidence.get("e2e_primary", {}).get("required_scripts", []))
status = "pass" if not errors else "fail"
emit_event(
    "unit_test_expansion_program_units_validated",
    status,
    summary=summary,
    required_blocker_count=len(required_blockers),
    closed_blocker_count=closed_blockers,
    unit_test_ref_count=unit_test_ref_count,
    e2e_script_count=e2e_script_count,
    details={
        "required_blockers": required_blockers,
        "threading_pack_tests": policy.get("threading_pack_tests", []),
    },
)
emit_event(
    "unit_test_expansion_program_e2e_validated",
    status,
    summary=summary,
    required_blocker_count=len(required_blockers),
    closed_blocker_count=closed_blockers,
    unit_test_ref_count=unit_test_ref_count,
    e2e_script_count=e2e_script_count,
    details={
        "existing_gate_exit": gate_proc.returncode,
        "existing_gate_markers": policy.get("gate_success_markers", []),
    },
)
emit_event(
    "unit_test_expansion_program_telemetry_validated",
    status,
    summary=summary,
    required_blocker_count=len(required_blockers),
    closed_blocker_count=closed_blockers,
    unit_test_ref_count=unit_test_ref_count,
    e2e_script_count=e2e_script_count,
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
        event["failure_signature"] = "unit_test_expansion_program_completion_contract_failed"

report = {
    "schema": "unit_test_expansion_program_completion_contract.report.v1",
    "status": "pass" if not errors else "fail",
    "completion_debt_bead": "bd-25n.1",
    "original_bead": "bd-25n",
    "source_commit": SOURCE_COMMIT,
    "generated_at": ts,
    "summary": {
        **summary,
        "required_blocker_count": len(required_blockers),
        "closed_blocker_count": closed_blockers,
        "unit_test_ref_count": unit_test_ref_count,
        "e2e_script_count": e2e_script_count,
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
    print("FAIL: unit test expansion program completion contract", file=os.sys.stderr)
    for err in errors:
        print(f" - {err}", file=os.sys.stderr)
    os.sys.exit(1)

print(
    "PASS: unit test expansion program completion contract "
    f"(closed_blockers={closed_blockers}/{len(required_blockers)}, "
    f"unit_refs={unit_test_ref_count}, scripts={e2e_script_count}, "
    f"fixtures={summary['fixture_files']}, cases={summary['total_cases']}, "
    f"report={report_path.relative_to(root)})"
)
PY
