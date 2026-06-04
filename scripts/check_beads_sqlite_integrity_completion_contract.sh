#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_BEADS_SQLITE_INTEGRITY_COMPLETION_CONTRACT:-$ROOT/tests/conformance/beads_sqlite_integrity_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_BEADS_SQLITE_INTEGRITY_COMPLETION_TARGET_DIR:-$ROOT/target/conformance/beads_sqlite_integrity_completion}"
REPORT="${FRANKENLIBC_BEADS_SQLITE_INTEGRITY_COMPLETION_REPORT:-$OUT_DIR/beads_sqlite_integrity_completion_contract.report.json}"
LOG="${FRANKENLIBC_BEADS_SQLITE_INTEGRITY_COMPLETION_LOG:-$OUT_DIR/beads_sqlite_integrity_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$OUT_DIR" "$REPORT" "$LOG" <<'PY'
import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT = pathlib.Path(sys.argv[2]).resolve()
OUT_DIR = pathlib.Path(sys.argv[3]).resolve()
REPORT = pathlib.Path(sys.argv[4]).resolve()
LOG = pathlib.Path(sys.argv[5]).resolve()

EXPECTED_SCHEMA = "beads_sqlite_integrity_completion_contract.v1"
REPORT_SCHEMA = "beads_sqlite_integrity_completion_contract.report.v1"
LOG_SCHEMA = "beads_sqlite_integrity_completion_contract.log.v1"
ORIGINAL_BEAD = "bd-yaiw"
COMPLETION_BEAD = "bd-yaiw.1"
TRACE_ID = "bd-yaiw-1-beads-sqlite-integrity-completion-v1"
REQUIRED_MISSING_ITEMS = {"tests.golden.primary"}
REQUIRED_DOCTOR_CHECKS = {
    "sqlite.integrity_check",
    "counts.db_vs_jsonl",
    "sync.metadata",
    "schema.tables",
    "jsonl.parse",
}
REQUIRED_EVENTS = {
    "beads_sqlite_integrity.source_artifacts_validated",
    "beads_sqlite_integrity.golden_binding_validated",
    "beads_sqlite_integrity.read_only_probe_validated",
    "beads_sqlite_integrity.completion_contract_validated",
}
FAILURE_EVENT = "beads_sqlite_integrity.completion_contract_failed"
DESTRUCTIVE_FRAGMENTS = {
    "br sync --flush-only",
    "br sync --import-only",
    "br sync --rebuild",
    "br create",
    "br close",
    "git clean",
    "git reset --hard",
    "rm -rf",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
probe_results: dict[str, Any] = {}


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


SOURCE_COMMIT = source_commit()


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def load_jsonl_ids(path: pathlib.Path) -> set[str]:
    ids: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        errors.append(f"issues JSONL is not readable: {rel(path)}: {exc}")
        return ids
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            errors.append(f"issues JSONL line {index} is invalid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            errors.append(f"issues JSONL line {index} must be a JSON object")
            continue
        issue_id = row.get("id")
        if isinstance(issue_id, str):
            ids.add(issue_id)
    return ids


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def add_event(
    event_name: str,
    level: str,
    gate: str,
    expected: Any,
    actual: Any,
    failure_signature: str | None,
    artifact_refs: list[str],
) -> None:
    events.append(
        {
            "timestamp": now_utc(),
            "schema_version": LOG_SCHEMA,
            "trace_id": f"{TRACE_ID}::{event_name}",
            "level": level,
            "event": event_name,
            "bead_id": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "gate": gate,
            "expected": expected,
            "actual": actual,
            "source_commit": SOURCE_COMMIT,
            "target_dir": rel(OUT_DIR),
            "failure_signature": failure_signature,
            "artifact_refs": artifact_refs,
        }
    )


def run_json_command(command: list[str], key: str) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    probe_results[key] = {
        "command": " ".join(command),
        "exit_code": completed.returncode,
        "stderr_tail": completed.stderr[-1000:],
    }
    try:
        value = json.loads(completed.stdout)
    except Exception as exc:
        if completed.returncode != 0:
            errors.append(f"{key} exited {completed.returncode}: {completed.stderr[-1000:]}")
        errors.append(f"{key} stdout is not JSON: {exc}")
        return {}
    probe_results[key]["parsed"] = value
    if completed.returncode != 0 and key != "doctor":
        errors.append(f"{key} exited {completed.returncode}: {completed.stderr[-1000:]}")
    return value if isinstance(value, dict) else {"rows": value}


def report(status: str) -> dict[str, Any]:
    summary = {
        "doctor_ok": probe_results.get("doctor", {}).get("parsed", {}).get("ok"),
        "doctor_accepted_degraded": probe_results.get("doctor", {}).get("accepted_degraded", False),
        "workspace_health": probe_results.get("doctor", {}).get("parsed", {}).get("workspace_health"),
        "sync_dirty_count": probe_results.get("sync_status", {}).get("parsed", {}).get("dirty_count"),
        "dep_cycle_count": probe_results.get("dep_cycles", {}).get("parsed", {}).get("count"),
        "event_count": len(events),
        "destructive_commands_blocked": not any(
            fragment in " ".join(contract.get("read_only_probe_contract", {}).get("allowed_commands", []))
            for fragment in DESTRUCTIVE_FRAGMENTS
        ),
    }
    return {
        "schema_version": REPORT_SCHEMA,
        "original_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "status": status,
        "summary": summary,
        "probe_results": probe_results,
        "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
        "errors": errors,
    }


def finish(status: str) -> None:
    write_json(REPORT, report(status))
    write_jsonl(LOG, events)
    if status != "pass":
        print("FAIL beads SQLite integrity completion contract", file=sys.stderr)
        for item in errors[:12]:
            print(f"ERROR: {item}", file=sys.stderr)
        raise SystemExit(1)


contract = load_json(CONTRACT, "completion contract")
if not contract:
    add_event(FAILURE_EVENT, "error", "contract_json", "valid object", "invalid", "contract_json_invalid", [rel(CONTRACT)])
    finish("fail")

if contract.get("schema_version") != EXPECTED_SCHEMA:
    errors.append(f"schema_version must be {EXPECTED_SCHEMA}")
if contract.get("original_bead") != ORIGINAL_BEAD:
    errors.append(f"original_bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_BEAD}")
if contract.get("trace_id") != TRACE_ID:
    errors.append(f"trace_id must be {TRACE_ID}")

source_artifacts = contract.get("source_artifacts")
if not isinstance(source_artifacts, dict):
    errors.append("source_artifacts must be an object")
    source_artifacts = {}
for name, path_text in sorted(source_artifacts.items()):
    path = ROOT / str(path_text)
    if not path.exists():
        errors.append(f"source artifact {name} missing: {path_text}")

add_event(
    "beads_sqlite_integrity.source_artifacts_validated",
    "info" if not errors else "error",
    "source_artifacts",
    sorted(source_artifacts.keys()),
    sorted(name for name, path_text in source_artifacts.items() if (ROOT / str(path_text)).exists()),
    None if not errors else "missing_source_artifact",
    [str(value) for value in source_artifacts.values()],
)

read_only = contract.get("read_only_probe_contract")
if not isinstance(read_only, dict):
    errors.append("read_only_probe_contract must be an object")
    read_only = {}
allowed_commands = read_only.get("allowed_commands", [])
if not isinstance(allowed_commands, list) or not all(isinstance(item, str) for item in allowed_commands):
    errors.append("read_only_probe_contract.allowed_commands must be string array")
    allowed_commands = []
joined_commands = "\n".join(allowed_commands)
for fragment in DESTRUCTIVE_FRAGMENTS:
    if fragment in joined_commands:
        errors.append(f"destructive command fragment is forbidden in allowed_commands: {fragment}")

golden = contract.get("golden_primary")
if not isinstance(golden, dict):
    errors.append("golden_primary must be an object")
    golden = {}
if golden.get("missing_item") not in REQUIRED_MISSING_ITEMS:
    errors.append("golden_primary.missing_item must bind tests.golden.primary")
required_doctor_checks = set(golden.get("required_doctor_checks", []))
if not REQUIRED_DOCTOR_CHECKS <= required_doctor_checks:
    errors.append(f"golden_primary.required_doctor_checks missing {sorted(REQUIRED_DOCTOR_CHECKS - required_doctor_checks)}")

missing_items = set(contract.get("completion_debt_evidence", {}).get("missing_items_closed", []))
if missing_items != REQUIRED_MISSING_ITEMS:
    errors.append("completion_debt_evidence.missing_items_closed must equal tests.golden.primary")

if errors:
    add_event(FAILURE_EVENT, "error", "contract_static", "valid", "invalid", "contract_static_invalid", [rel(CONTRACT)])
    finish("fail")

doctor = run_json_command(["br", "doctor", "--json"], "doctor")
sync = run_json_command(["br", "sync", "--status", "--json"], "sync_status")
parent_rows = run_json_command(["br", "--no-db", "show", ORIGINAL_BEAD, "--json"], "parent_show").get("rows", [])
completion_rows = run_json_command(["br", "--no-db", "show", COMPLETION_BEAD, "--json"], "completion_show").get("rows", [])
dep_cycles = run_json_command(["br", "dep", "cycles", "--no-db", "--json"], "dep_cycles")

check_by_name = {
    row.get("name"): row
    for row in doctor.get("checks", [])
    if isinstance(row, dict)
}
required_checks_ok = True
for check_name in required_doctor_checks:
    status = check_by_name.get(check_name, {}).get("status")
    if status != "ok":
        required_checks_ok = False
        errors.append(f"doctor check {check_name} must be ok, got {status!r}")
accepted_degraded_codes = {"stale_recovery_artifacts"}
reliability = doctor.get("reliability_audit", {})
anomalies = reliability.get("anomalies", []) if isinstance(reliability, dict) else []
degraded_codes = {
    str(row.get("code"))
    for row in anomalies
    if isinstance(row, dict) and row.get("code")
}
doctor_accepted_degraded = (
    doctor.get("ok") is False
    and doctor.get("workspace_health") == "degraded"
    and required_checks_ok
    and degraded_codes <= accepted_degraded_codes
)
probe_results["doctor"]["accepted_degraded"] = doctor_accepted_degraded
if doctor.get("ok") is not True and not doctor_accepted_degraded:
    errors.append("br doctor --json must report ok=true or only accepted degraded recovery artifacts")
if check_by_name.get("sqlite.integrity_check", {}).get("status") != "ok":
    errors.append("sqlite.integrity_check must be ok")
if check_by_name.get("counts.db_vs_jsonl", {}).get("status") != "ok":
    errors.append("counts.db_vs_jsonl must be ok")
if sync.get("dirty_count") != golden.get("required_sync_status", {}).get("dirty_count"):
    errors.append("sync dirty_count drifted")
if sync.get("jsonl_newer") != golden.get("required_sync_status", {}).get("jsonl_newer"):
    errors.append("sync jsonl_newer drifted")
if sync.get("db_newer") != golden.get("required_sync_status", {}).get("db_newer"):
    errors.append("sync db_newer drifted")
if dep_cycles.get("count") != 0:
    errors.append("br dep cycles --no-db must report count=0")

def first_status(rows: Any) -> str | None:
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        return rows[0].get("status")
    return None

required_records = golden.get("required_no_db_records", [])
for record in required_records if isinstance(required_records, list) else []:
    issue_id = record.get("id") if isinstance(record, dict) else None
    expected = record.get("status") if isinstance(record, dict) else None
    actual = first_status(parent_rows if issue_id == ORIGINAL_BEAD else completion_rows if issue_id == COMPLETION_BEAD else [])
    if actual != expected:
        errors.append(f"no-db status for {issue_id} drifted: expected {expected}, got {actual}")

jsonl_path = ROOT / str(source_artifacts.get("jsonl_source_of_truth", ".beads/issues.jsonl"))
ids = load_jsonl_ids(jsonl_path)
for issue_id in golden.get("required_jsonl_ids", []):
    if issue_id not in ids:
        errors.append(f"issues JSONL missing required id {issue_id}")

add_event(
    "beads_sqlite_integrity.golden_binding_validated",
    "info" if not errors else "error",
    "golden_primary",
    {
        "doctor_checks": sorted(required_doctor_checks),
        "missing_items": sorted(REQUIRED_MISSING_ITEMS),
    },
    {
        "doctor_ok": doctor.get("ok"),
        "sync_dirty_count": sync.get("dirty_count"),
        "dep_cycles": dep_cycles.get("count"),
    },
    None if not errors else "golden_binding_failed",
    [rel(jsonl_path), ".beads/beads.db"],
)

add_event(
    "beads_sqlite_integrity.read_only_probe_validated",
    "info" if not errors else "error",
    "read_only_probe_contract",
    allowed_commands,
    {key: value.get("exit_code") for key, value in probe_results.items()},
    None if not errors else "read_only_probe_failed",
    [rel(REPORT), rel(LOG)],
)

if errors:
    add_event(FAILURE_EVENT, "error", "completion_contract", "pass", "fail", "validation_failed", [rel(CONTRACT), rel(REPORT), rel(LOG)])
    finish("fail")

add_event(
    "beads_sqlite_integrity.completion_contract_validated",
    "info",
    "completion_contract",
    "pass",
    "pass",
    None,
    [rel(CONTRACT), rel(REPORT), rel(LOG)],
)
finish("pass")

print(
    "PASS beads SQLite integrity completion contract "
    f"doctor_ok={doctor.get('ok')} "
    f"records={check_by_name.get('jsonl.parse', {}).get('details', {}).get('records')} "
    f"events={len(events)}"
)
PY
