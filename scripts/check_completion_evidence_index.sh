#!/usr/bin/env bash
# Emit a DB-free bead-to-evidence index for completion proof handoff.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_COMPLETION_EVIDENCE_INDEX_CONTRACT:-${ROOT}/tests/conformance/completion_evidence_index.v1.json}"
ISSUES="${FRANKENLIBC_COMPLETION_EVIDENCE_INDEX_ISSUES:-${ROOT}/.beads/issues.jsonl}"
OUT_DIR="${FRANKENLIBC_COMPLETION_EVIDENCE_INDEX_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_COMPLETION_EVIDENCE_INDEX_REPORT:-${OUT_DIR}/completion_evidence_index.report.json}"
LOG="${FRANKENLIBC_COMPLETION_EVIDENCE_INDEX_LOG:-${OUT_DIR}/completion_evidence_index.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${ISSUES}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
ISSUES = pathlib.Path(sys.argv[3])
REPORT = pathlib.Path(sys.argv[4])
LOG = pathlib.Path(sys.argv[5])

EXPECTED_SCHEMA = "completion_evidence_index.v1"
REPORT_SCHEMA = "completion_evidence_index.report.v1"
EVENT_SCHEMA = "completion_evidence_index.event.v1"
VALID_PROOF_STATUSES = {"successful_proof", "blocker_evidence"}
REQUIRED_ENTRY_FIELDS = {
    "bead_id",
    "artifact_path",
    "proof_command",
    "proof_status",
    "last_checked_utc",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


def load_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"invalid JSONL at {rel(path)}:{line_no}: {exc}") from exc
            if isinstance(row, dict):
                rows.append(row)
    return rows


def repo_path_exists(path_text: str) -> bool:
    path = pathlib.Path(path_text)
    return not path.is_absolute() and ".." not in path.parts and (ROOT / path).is_file()


def tracker_index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in rows if isinstance(row.get("id"), str)}


def validate_entry(entry: dict[str, Any], index: int) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    label = f"evidence_entries[{index}]"
    for field in REQUIRED_ENTRY_FIELDS:
        if not isinstance(entry.get(field), str) or not str(entry.get(field)).strip():
            errors.append(
                {
                    "failure_signature": f"missing_{field}",
                    "entry": label,
                    "message": f"{label}.{field} must be a non-empty string",
                }
            )
    artifact_path = entry.get("artifact_path")
    if isinstance(artifact_path, str) and artifact_path:
        if not repo_path_exists(artifact_path):
            errors.append(
                {
                    "failure_signature": "missing_artifact_path",
                    "entry": label,
                    "message": f"{artifact_path} must be a checked-in repo-relative file",
                }
            )
    proof_status = entry.get("proof_status")
    if isinstance(proof_status, str) and proof_status not in VALID_PROOF_STATUSES:
        errors.append(
            {
                "failure_signature": "invalid_proof_status",
                "entry": label,
                "message": f"{label}.proof_status must be one of {sorted(VALID_PROOF_STATUSES)}",
            }
        )
    proof_command = entry.get("proof_command")
    if isinstance(proof_command, str):
        lowered = proof_command.lower()
        if "[rch] local" in lowered or "remote execution failed" in lowered:
            errors.append(
                {
                    "failure_signature": "local_fallback_marker",
                    "entry": label,
                    "message": f"{label}.proof_command contains local fallback text",
                }
            )
    return errors


def indexed_entry(entry: dict[str, Any], issue_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    issue = issue_by_id.get(str(entry.get("bead_id")), {})
    proof_status = str(entry.get("proof_status"))
    return {
        "bead_id": entry.get("bead_id"),
        "title": issue.get("title"),
        "tracker_status": issue.get("status"),
        "artifact_path": entry.get("artifact_path"),
        "artifact_exists": repo_path_exists(str(entry.get("artifact_path", ""))),
        "proof_command": entry.get("proof_command"),
        "proof_status": proof_status,
        "counts_as_validation_proof": proof_status == "successful_proof",
        "counts_as_blocker_evidence": proof_status == "blocker_evidence",
        "last_checked_utc": entry.get("last_checked_utc"),
    }


def run_negative_controls(manifest: dict[str, Any], issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []
    entries = manifest.get("evidence_entries")
    entries = entries if isinstance(entries, list) else []

    def signatures_for(mutated_entries: list[Any]) -> set[str]:
        signatures: set[str] = set()
        for index, entry in enumerate(mutated_entries):
            if not isinstance(entry, dict):
                signatures.add("malformed_entry")
                continue
            for error in validate_entry(entry, index):
                signatures.add(str(error["failure_signature"]))
        return signatures

    missing_artifact = copy.deepcopy(entries)
    if missing_artifact and isinstance(missing_artifact[0], dict):
        missing_artifact[0]["artifact_path"] = "tests/conformance/does_not_exist_completion_evidence.json"
    controls.append(
        {
            "name": "missing_artifact_path_fails",
            "expected_signature": "missing_artifact_path",
            "status": "pass" if "missing_artifact_path" in signatures_for(missing_artifact) else "fail",
        }
    )

    missing_command = copy.deepcopy(entries)
    if missing_command and isinstance(missing_command[0], dict):
        missing_command[0]["proof_command"] = ""
    controls.append(
        {
            "name": "missing_proof_command_fails",
            "expected_signature": "missing_proof_command",
            "status": "pass" if "missing_proof_command" in signatures_for(missing_command) else "fail",
        }
    )

    bad_status = copy.deepcopy(entries)
    if bad_status and isinstance(bad_status[0], dict):
        bad_status[0]["proof_status"] = "unknown"
    controls.append(
        {
            "name": "invalid_proof_status_fails",
            "expected_signature": "invalid_proof_status",
            "status": "pass" if "invalid_proof_status" in signatures_for(bad_status) else "fail",
        }
    )

    issue_by_id = tracker_index(issues)
    indexed = [indexed_entry(entry, issue_by_id) for entry in entries if isinstance(entry, dict)]
    successful = [row for row in indexed if row["counts_as_validation_proof"]]
    blockers = [row for row in indexed if row["counts_as_blocker_evidence"]]
    controls.append(
        {
            "name": "blocker_evidence_is_not_successful_proof",
            "expected_signature": "blocker_evidence_separated",
            "status": "pass" if blockers and all(not row["counts_as_validation_proof"] for row in blockers) and successful else "fail",
        }
    )
    return controls


manifest = load_json(CONTRACT)
issues = load_jsonl(ISSUES)
errors: list[dict[str, Any]] = []

if manifest.get("schema_version") != EXPECTED_SCHEMA:
    errors.append(
        {
            "failure_signature": "schema_version",
            "message": f"schema_version must be {EXPECTED_SCHEMA}",
        }
    )
if manifest.get("issues_source") != ".beads/issues.jsonl":
    errors.append(
        {
            "failure_signature": "issues_source",
            "message": "issues_source must be .beads/issues.jsonl",
        }
    )

entries = manifest.get("evidence_entries")
if not isinstance(entries, list) or len(entries) < 3:
    errors.append(
        {
            "failure_signature": "evidence_entries",
            "message": "evidence_entries must contain at least three entries",
        }
    )
    entries = []

for index, entry in enumerate(entries):
    if not isinstance(entry, dict):
        errors.append(
            {
                "failure_signature": "malformed_entry",
                "entry": f"evidence_entries[{index}]",
                "message": "entry must be an object",
            }
        )
        continue
    errors.extend(validate_entry(entry, index))

negative_controls = run_negative_controls(manifest, issues)
for control in negative_controls:
    if control.get("status") != "pass":
        errors.append(
            {
                "failure_signature": "negative_control_failed",
                "message": f"{control.get('name')} did not emit {control.get('expected_signature')}",
            }
        )

issue_by_id = tracker_index(issues)
evidence_index = [indexed_entry(entry, issue_by_id) for entry in entries if isinstance(entry, dict)]
successful_ids = [str(row["bead_id"]) for row in evidence_index if row["counts_as_validation_proof"]]
blocker_ids = [str(row["bead_id"]) for row in evidence_index if row["counts_as_blocker_evidence"]]
summary = {
    "entry_count": len(evidence_index),
    "successful_proof_count": len(successful_ids),
    "blocker_evidence_count": len(blocker_ids),
    "successful_proof_ids": successful_ids,
    "blocker_evidence_ids": blocker_ids,
    "sqlite_accessed": False,
    "issues_source": rel(ISSUES),
}

report = {
    "schema_version": REPORT_SCHEMA,
    "bead": manifest.get("bead"),
    "status": "fail" if errors else "pass",
    "generated_at_utc": utc_now(),
    "source_commit": source_commit(),
    "report_path": rel(REPORT),
    "log_path": rel(LOG),
    "issues_source": rel(ISSUES),
    "sqlite_accessed": False,
    "summary": summary,
    "evidence_index": evidence_index,
    "negative_controls": negative_controls,
    "failures": errors,
}

required_fields = manifest.get("required_report_fields")
if isinstance(required_fields, list):
    for field in required_fields:
        if isinstance(field, str) and field not in report:
            errors.append(
                {
                    "failure_signature": "missing_report_field",
                    "message": f"report missing {field}",
                }
            )
else:
    errors.append({"failure_signature": "required_report_fields", "message": "required_report_fields must be an array"})

report["status"] = "fail" if errors else "pass"
report["failures"] = errors

events = [
    {
        "schema_version": EVENT_SCHEMA,
        "event": "completion_evidence_index_checked",
        "status": report["status"],
        "source_commit": report["source_commit"],
        "entry_count": summary["entry_count"],
        "successful_proof_count": summary["successful_proof_count"],
        "blocker_evidence_count": summary["blocker_evidence_count"],
    }
]
events.extend({"schema_version": EVENT_SCHEMA, "event": "negative_control", **control} for control in negative_controls)

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n", encoding="utf-8")

if errors:
    print(json.dumps({"status": "fail", "failures": errors[:8], "report": rel(REPORT)}, sort_keys=True))
    raise SystemExit(1)

print(json.dumps({"status": "pass", "report": rel(REPORT), **summary}, sort_keys=True))
PY
