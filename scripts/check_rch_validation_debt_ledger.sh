#!/usr/bin/env bash
# Validate the RCH validation debt replay ledger for static-only changes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER="${FRANKENLIBC_RCH_VALIDATION_DEBT_LEDGER:-${ROOT}/tests/conformance/rch_validation_debt_ledger.v1.json}"
OUT_DIR="${FRANKENLIBC_RCH_VALIDATION_DEBT_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${OUT_DIR}/rch_validation_debt_ledger.report.json"
LOG="${OUT_DIR}/rch_validation_debt_ledger.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${LEDGER}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import time
from copy import deepcopy
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
LEDGER = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
LOG = pathlib.Path(sys.argv[4])

EXPECTED_SCHEMA = "rch_validation_debt_ledger.v1"
EXPECTED_BLOCKER = "bd-716tv"
EXPECTED_REMOTE_ENV = "RCH_REQUIRE_REMOTE=1"
REJECTED_LOCAL_MARKER = "[RCH] local"
REMOTE_REFUSAL_MARKER = "remote required; refusing local fallback"
EXPECTED_REPORT = "target/conformance/rch_validation_debt_ledger.report.json"
EXPECTED_LOG = "target/conformance/rch_validation_debt_ledger.log.jsonl"
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "source",
    "status",
    "entry_count",
    "failure_count",
    "failures",
    "events",
    "report_path",
    "log_path",
    "report_contract_fields",
    "contract_status",
    "contract_errors",
}
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def add_error(source: str, signature: str, message: str) -> None:
    errors.append({"source": source, "failure_signature": signature, "message": message})


def git_commit_exists(commit: str) -> bool:
    if not COMMIT_RE.fullmatch(commit):
        return False
    result = subprocess.run(
        ["git", "-C", str(ROOT), "cat-file", "-e", f"{commit}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def ensure_string_list(source: str, signature: str, value: Any, *, non_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (non_empty and not value):
        add_error(source, signature, "expected non-empty string list")
        return []
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            add_error(source, signature, f"invalid string-list item {item!r}")
        else:
            result.append(item)
    return result


def validate_static_check(source: str, row: Any) -> None:
    if not isinstance(row, dict):
        add_error(source, "malformed_static_check", "static check must be an object")
        return
    command = row.get("command")
    if not isinstance(command, str) or not command:
        add_error(source, "missing_static_check_command", "static check must name a command")
    elif "cargo " in command or "rch exec" in command:
        add_error(source, "static_check_not_static", f"static check must not be cargo/RCH proof: {command}")
    if row.get("status") != "pass":
        add_error(source, "static_check_not_pass", f"static check status must be pass: {row.get('status')!r}")


def validate_remote_command(source: str, command: Any) -> None:
    if not isinstance(command, str) or not command:
        add_error(source, "missing_remote_command", "remote validation command must be a non-empty string")
        return
    if EXPECTED_REMOTE_ENV not in command:
        add_error(source, "missing_remote_env", f"remote command must require {EXPECTED_REMOTE_ENV}: {command}")
    if "rch exec" not in command:
        add_error(source, "missing_rch_exec", f"remote command must use rch exec: {command}")
    if "cargo " not in command:
        add_error(source, "missing_cargo_validation", f"remote command must be cargo validation: {command}")
    if REJECTED_LOCAL_MARKER in command:
        add_error(source, "local_fallback_embedded_as_command", "remote command must not contain fallback output")


def validate_remote_proof(source: str, entry: dict[str, Any]) -> None:
    proof = entry.get("remote_proof")
    status = entry.get("replay_status")
    if status == "pending_rch_admissibility":
        if proof is not None:
            add_error(source, "pending_entry_has_remote_proof", "pending entries must not claim remote proof")
        return
    if status != "complete":
        add_error(source, "invalid_replay_status", f"unexpected replay_status={status!r}")
        return
    if not isinstance(proof, dict):
        add_error(source, "complete_without_remote_proof", "complete entries must include remote_proof")
        return
    if proof.get("local_fallback_seen") is not False:
        add_error(source, "complete_with_local_fallback", "complete entries must prove local_fallback_seen=false")
    if proof.get("required_remote_env") != EXPECTED_REMOTE_ENV:
        add_error(source, "complete_missing_remote_env", "complete proof must preserve required remote env")
    transcripts = ensure_string_list(source, "complete_missing_transcripts", proof.get("transcript_artifacts"))
    for transcript in transcripts:
        if not transcript.startswith("target/") and not transcript.startswith("artifacts/"):
            add_error(source, "complete_transcript_path_scope", f"transcript path must be target/ or artifacts/: {transcript}")


def configured_report_fields(packet: dict[str, Any]) -> list[str]:
    report_contract = packet.get("report_contract")
    if not isinstance(report_contract, dict):
        return []
    fields = report_contract.get("must_materialize")
    if not isinstance(fields, list):
        return []
    return [field for field in fields if isinstance(field, str) and field]


def missing_report_fields(packet: dict[str, Any], report: dict[str, Any]) -> list[str]:
    return [field for field in configured_report_fields(packet) if field not in report]


def validate_report_contract(packet: dict[str, Any], source: str) -> None:
    report_contract = packet.get("report_contract")
    if not isinstance(report_contract, dict):
        add_error(source, "missing_report_contract", "report_contract must be an object")
        return
    if report_contract.get("output_path") != EXPECTED_REPORT:
        add_error(source, "report_output_path_mismatch", f"output_path must be {EXPECTED_REPORT}")
    if report_contract.get("log_path") != EXPECTED_LOG:
        add_error(source, "report_log_path_mismatch", f"log_path must be {EXPECTED_LOG}")
    fields = set(ensure_string_list(source, "missing_report_contract_fields", report_contract.get("must_materialize")))
    missing = sorted(REQUIRED_REPORT_FIELDS - fields)
    if missing:
        add_error(source, "report_contract_missing_required_field", f"must_materialize missing {missing}")


def validate_ledger(packet: dict[str, Any], source: str) -> None:
    if packet.get("schema_version") != EXPECTED_SCHEMA:
        add_error(source, "schema_version", "ledger schema_version mismatch")
    if packet.get("ledger_kind") != "static_replay_plan":
        add_error(source, "ledger_kind", "ledger_kind must be static_replay_plan")
    if packet.get("blocker_bead") != EXPECTED_BLOCKER:
        add_error(source, "wrong_blocker", f"ledger blocker_bead must be {EXPECTED_BLOCKER}")
    claim_policy = packet.get("claim_policy", {})
    if not isinstance(claim_policy, dict) or claim_policy.get("claim_allowed") is not False:
        add_error(source, "claim_allowed", "ledger must not allow validation claims")

    policy = packet.get("local_fallback_policy", {})
    if not isinstance(policy, dict):
        add_error(source, "missing_local_fallback_policy", "local_fallback_policy is required")
        policy = {}
    if policy.get("accept_local_cargo") is not False:
        add_error(source, "local_cargo_accepted", "local cargo must not be accepted as proof")
    if policy.get("required_remote_env") != EXPECTED_REMOTE_ENV:
        add_error(source, "missing_remote_env", "local_fallback_policy must require RCH_REQUIRE_REMOTE=1")
    markers = ensure_string_list(source, "missing_rejected_markers", policy.get("rejected_markers"))
    if REJECTED_LOCAL_MARKER not in markers:
        add_error(source, "missing_local_fallback_rejection", "policy must reject [RCH] local")
    if REMOTE_REFUSAL_MARKER not in markers:
        add_error(source, "missing_remote_refusal_marker", "policy must preserve remote-required refusal marker")
    validate_report_contract(packet, f"{source}::report_contract")

    expected = set(ensure_string_list(source, "missing_expected_pending_beads", packet.get("expected_pending_beads")))
    entries = packet.get("entries")
    if not isinstance(entries, list) or not entries:
        add_error(source, "missing_entries", "entries must be a non-empty list")
        entries = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        entry_source = f"{source}::entries[{index}]"
        if not isinstance(entry, dict):
            add_error(entry_source, "malformed_entry", "entry must be an object")
            continue
        bead_id = entry.get("bead_id")
        if not isinstance(bead_id, str) or not bead_id.startswith("bd-"):
            add_error(entry_source, "missing_bead_id", "entry must include bd-* bead_id")
        else:
            seen.add(bead_id)
            entry_source = f"{source}::{bead_id}"
        if entry.get("blocker_bead") != EXPECTED_BLOCKER:
            add_error(entry_source, "wrong_blocker", f"entry blocker_bead must be {EXPECTED_BLOCKER}")
        commit = entry.get("source_commit")
        if not isinstance(commit, str) or not git_commit_exists(commit):
            add_error(entry_source, "invalid_source_commit", f"source_commit is not a reachable commit: {commit!r}")
        for file_path in ensure_string_list(entry_source, "missing_files", entry.get("files")):
            full_path = ROOT / file_path
            if not full_path.is_file():
                add_error(entry_source, "missing_file", f"tracked replay file is missing: {file_path}")
        static_checks = entry.get("static_checks")
        if not isinstance(static_checks, list) or not static_checks:
            add_error(entry_source, "missing_static_checks", "entry must record static checks")
        else:
            for row in static_checks:
                validate_static_check(entry_source, row)
        commands = ensure_string_list(entry_source, "missing_remote_command", entry.get("remote_validation_commands"))
        for command in commands:
            validate_remote_command(entry_source, command)
        validate_remote_proof(entry_source, entry)
    missing_expected = expected - seen
    extra_entries = seen - expected
    if missing_expected:
        add_error(source, "missing_expected_pending_bead", f"missing expected entries: {sorted(missing_expected)}")
    if extra_entries:
        add_error(source, "unexpected_pending_bead", f"unexpected entries not listed in expected_pending_beads: {sorted(extra_entries)}")


def run_negative_controls(packet: dict[str, Any]) -> None:
    controls: list[tuple[str, dict[str, Any], str]] = []
    missing_command = deepcopy(packet)
    missing_command["entries"][0]["remote_validation_commands"] = []
    controls.append(("negative_missing_remote_command", missing_command, "missing_remote_command"))

    local_allowed = deepcopy(packet)
    local_allowed["local_fallback_policy"]["accept_local_cargo"] = True
    controls.append(("negative_local_fallback_accepted", local_allowed, "local_cargo_accepted"))

    complete_without_proof = deepcopy(packet)
    complete_without_proof["entries"][0]["replay_status"] = "complete"
    complete_without_proof["entries"][0]["remote_proof"] = None
    controls.append(("negative_complete_without_remote_proof", complete_without_proof, "complete_without_remote_proof"))

    wrong_blocker = deepcopy(packet)
    wrong_blocker["entries"][0]["blocker_bead"] = "bd-wrong"
    controls.append(("negative_wrong_blocker", wrong_blocker, "wrong_blocker"))

    wrong_report = deepcopy(packet)
    wrong_report["report_contract"]["output_path"] = "target/conformance/wrong_rch_validation_debt_report.json"
    controls.append(("negative_report_output_path_mismatch", wrong_report, "report_output_path_mismatch"))

    wrong_log = deepcopy(packet)
    wrong_log["report_contract"]["log_path"] = "target/conformance/wrong_rch_validation_debt_log.jsonl"
    controls.append(("negative_report_log_path_mismatch", wrong_log, "report_log_path_mismatch"))

    weak_report_contract = deepcopy(packet)
    weak_report_contract["report_contract"]["must_materialize"] = ["schema_version"]
    controls.append(
        (
            "negative_report_contract_missing_required_field",
            weak_report_contract,
            "report_contract_missing_required_field",
        )
    )

    for name, mutated, expected_signature in controls:
        before = len(errors)
        validate_ledger(mutated, name)
        emitted = [err["failure_signature"] for err in errors[before:]]
        del errors[before:]
        if expected_signature not in emitted:
            add_error(name, "negative_control_failed", f"expected {expected_signature}, saw {emitted}")
        events.append(
            {
                "event": "negative_control",
                "name": name,
                "expected_signature": expected_signature,
                "observed_signatures": emitted,
                "status": "pass" if expected_signature in emitted else "fail",
            }
        )

    missing_report = {"schema_version": "rch_validation_debt_ledger.report.v1"}
    observed = "missing_report_field" if missing_report_fields(packet, missing_report) else "no_missing_report_field"
    expected = "missing_report_field"
    if observed != expected:
        add_error("negative_missing_report_field", "negative_control_failed", f"expected {expected}, saw {observed}")
    events.append(
        {
            "event": "negative_control",
            "name": "negative_missing_report_field",
            "expected_signature": expected,
            "observed_signatures": [observed],
            "status": "pass" if observed == expected else "fail",
        }
    )


packet = load_json(LEDGER)
validate_ledger(packet, rel(LEDGER))
run_negative_controls(packet)

events.insert(
    0,
    {
        "event": "ledger_validated",
        "source": rel(LEDGER),
        "entry_count": len(packet.get("entries", [])) if isinstance(packet, dict) else 0,
        "status": "fail" if errors else "pass",
        "checked_at": utc_now(),
    },
)

report = {
    "schema_version": "rch_validation_debt_ledger.report.v1",
    "source": rel(LEDGER),
    "status": "pending",
    "entry_count": len(packet.get("entries", [])) if isinstance(packet, dict) else 0,
    "failure_count": 0,
    "failures": [],
    "events": events,
    "report_path": rel(REPORT),
    "log_path": rel(LOG),
    "report_contract_fields": configured_report_fields(packet) if isinstance(packet, dict) else [],
    "contract_status": "pending",
    "contract_errors": [],
}
if isinstance(packet, dict):
    for missing_field in missing_report_fields(packet, report):
        add_error("report_contract", "missing_report_field", f"report omitted required field: {missing_field}")
report["status"] = "fail" if errors else "pass"
report["failure_count"] = len(errors)
report["failures"] = errors
report["contract_status"] = "fail" if errors else "pass"
report["contract_errors"] = errors
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n", encoding="utf-8")

if errors:
    print(json.dumps({"status": "fail", "failures": errors[:8], "report": rel(REPORT)}))
    raise SystemExit(1)

print(json.dumps({"status": "pass", "entries": report["entry_count"], "events": len(events), "report": rel(REPORT)}))
PY
