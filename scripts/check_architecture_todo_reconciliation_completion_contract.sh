#!/usr/bin/env bash
# check_architecture_todo_reconciliation_completion_contract.sh - bd-0agsk.1.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_ARCH_TODO_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/architecture_todo_reconciliation_completion_contract.v1.json}"
SOURCE_ARTIFACT="${FRANKENLIBC_ARCH_TODO_COMPLETION_SOURCE_ARTIFACT:-${ROOT}/tests/conformance/architecture_todo_reconciliation.v1.json}"
SOURCE_CHECKER="${FRANKENLIBC_ARCH_TODO_COMPLETION_SOURCE_CHECKER:-${ROOT}/scripts/check_architecture_todo_reconciliation.sh}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_ARCH_TODO_COMPLETION_REPORT:-${OUT_DIR}/architecture_todo_reconciliation_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_ARCH_TODO_COMPLETION_LOG:-${OUT_DIR}/architecture_todo_reconciliation_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}"

export FLC_ROOT="${ROOT}"
export FLC_CONTRACT_PATH="${CONTRACT_PATH}"
export FLC_SOURCE_ARTIFACT="${SOURCE_ARTIFACT}"
export FLC_SOURCE_CHECKER="${SOURCE_CHECKER}"
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
source_artifact_path = Path(os.environ["FLC_SOURCE_ARTIFACT"])
source_checker_path = Path(os.environ["FLC_SOURCE_CHECKER"])
report_path = Path(os.environ["FLC_REPORT_PATH"])
log_path = Path(os.environ["FLC_LOG_PATH"])
ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
report_path.parent.mkdir(parents=True, exist_ok=True)
log_path.parent.mkdir(parents=True, exist_ok=True)

COMPLETION_BEAD = "bd-0agsk.1.1"
ORIGINAL_BEAD = "bd-0agsk.1"
EXPECTED_SCHEMA = "architecture_todo_reconciliation_completion_contract.v1"
EXPECTED_SOURCE_SCHEMA = "architecture_todo_reconciliation.v1"
EXPECTED_MISSING_ITEMS = {
    "tests.conformance.primary",
    "migrations.primary",
    "theater.todo_wording.primary",
}
EXPECTED_EVENTS = {
    "architecture_todo_reconciliation_completion_validated",
    "architecture_todo_reconciliation_source_gate_replayed",
    "architecture_todo_reconciliation_completion_failed",
}
EXPECTED_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "status",
    "row_count",
    "mapped_row_count",
    "missing_items_bound",
    "source_report",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            rows.append(json.loads(raw))
    return rows


def display_path(path: Path) -> str:
    if path.is_absolute() and path.is_relative_to(root):
        return str(path.relative_to(root))
    return str(path)


def repo_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"non-repo-relative path: {value}")
        return root / "__invalid__"
    return root / path


def run_source_checker() -> tuple[dict[str, Any] | None, list[dict[str, Any]], str]:
    if not source_checker_path.is_file():
        errors.append(f"source checker missing: {source_checker_path}")
        return None, [], ""
    source_report = report_path.with_name("architecture_todo_reconciliation.source.report.json")
    source_log = log_path.with_name("architecture_todo_reconciliation.source.log.jsonl")
    env = os.environ.copy()
    env["ARCH_TODO_RECONCILIATION_ARTIFACT"] = str(source_artifact_path)
    env["ARCH_TODO_RECONCILIATION_REPORT"] = str(source_report)
    env["ARCH_TODO_RECONCILIATION_LOG"] = str(source_log)
    result = subprocess.run(
        [str(source_checker_path)],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        errors.append(
            "source architecture TODO checker failed: "
            + result.stdout[-500:]
            + result.stderr[-500:]
        )
        return None, [], display_path(source_report)
    try:
        report = load_json(source_report)
    except Exception as exc:  # noqa: BLE001 - emit deterministic diagnostic
        errors.append(f"source report unreadable: {exc}")
        report = None
    return report if isinstance(report, dict) else None, read_jsonl(source_log), display_path(source_report)


def command_is_allowed(command: str) -> bool:
    stripped = command.strip()
    if stripped.startswith("scripts/") or stripped.startswith("bash -n ") or stripped.startswith("jq "):
        return True
    return " rch exec -- cargo " in f" {stripped} "


contract = load_json(contract_path)
source = load_json(source_artifact_path)
evidence = contract.get("completion_debt_evidence", {})

if contract.get("schema_version") != EXPECTED_SCHEMA:
    errors.append("completion contract schema mismatch")
if contract.get("completion_debt_bead") != COMPLETION_BEAD:
    errors.append("completion_debt_bead mismatch")
if contract.get("original_bead") != ORIGINAL_BEAD:
    errors.append("original_bead mismatch")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be at least 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != EXPECTED_MISSING_ITEMS:
    errors.append(f"missing_items mismatch: {sorted(missing_items)}")

test_sources = evidence.get("test_sources", {})
for source_key, source_path in test_sources.items():
    if not isinstance(source_path, str) or not repo_path(source_path).is_file():
        errors.append(f"test source missing for {source_key}: {source_path}")

source_contract = evidence.get("source_contract", {})
required_paths = [
    source_contract.get("artifact"),
    source_contract.get("ledger"),
    source_contract.get("checker"),
    source_contract.get("harness_test"),
]
for value in required_paths:
    if not isinstance(value, str) or not repo_path(value).is_file():
        errors.append(f"source contract path missing: {value}")

if source.get("schema_version") != EXPECTED_SOURCE_SCHEMA:
    errors.append("source artifact schema mismatch")
if source.get("generated_by_bead") != ORIGINAL_BEAD:
    errors.append("source generated_by_bead mismatch")
if source.get("claim_status") != "report_only":
    errors.append("source claim_status must stay report_only")
if source.get("promotion_policy", {}).get("replacement_level_change") != "forbidden":
    errors.append("source replacement_level_change must stay forbidden")

expected_counts = source_contract.get("expected_counts", {})
ledger_counts = source.get("ledger_counts", {})
classification_counts = source.get("classification_counts", {})
for key in ("row_count", "status_completed", "status_in_progress", "status_pending"):
    if int(ledger_counts.get(key, -1)) != int(expected_counts.get(key, -2)):
        errors.append(f"ledger_counts {key} mismatch")
for key in (
    "already_closed_by_ledger_or_closed_bead_evidence",
    "routed_to_new_open_bead",
    "stale_doc_only",
    "blocked_by_missing_artifact",
):
    if int(classification_counts.get(key, -1)) != int(expected_counts.get(key, -2)):
        errors.append(f"classification_counts {key} mismatch")

row_mappings = source.get("row_mappings", [])
mapped_ids: list[str] = []
for mapping in row_mappings if isinstance(row_mappings, list) else []:
    for row_id in mapping.get("ids", []) if isinstance(mapping, dict) else []:
        mapped_ids.append(str(row_id))
if len(mapped_ids) != int(expected_counts.get("row_count", -1)):
    errors.append("mapped row count must equal expected row count")
if len(set(mapped_ids)) != len(mapped_ids):
    errors.append("row mappings must be unique")

new_beads = {
    str(row.get("id"))
    for row in source.get("new_beads", [])
    if isinstance(row, dict) and row.get("id")
}
required_new_beads = set(source_contract.get("required_new_beads", []))
if not required_new_beads.issubset(new_beads):
    errors.append(f"required new beads missing: {sorted(required_new_beads - new_beads)}")

sections = [
    evidence.get("tests_conformance_primary", {}),
    evidence.get("migrations_primary", {}),
    evidence.get("theater_todo_wording_primary", {}),
]
for section in sections:
    missing_item_id = section.get("missing_item_id")
    if missing_item_id not in EXPECTED_MISSING_ITEMS:
        errors.append(f"unknown missing_item_id section: {missing_item_id}")
    for ref in section.get("required_test_refs", []):
        source_key = ref.get("source")
        name = ref.get("name")
        source_path = test_sources.get(source_key)
        if not isinstance(source_path, str) or not isinstance(name, str):
            errors.append(f"invalid test ref in {missing_item_id}")
            continue
        text = repo_path(source_path).read_text(encoding="utf-8")
        if f"fn {name}" not in text and f"def {name}" not in text:
            errors.append(f"missing referenced test {source_key}::{name}")

for command in evidence.get("tests_conformance_primary", {}).get("required_commands", []):
    if not isinstance(command, str) or not command_is_allowed(command):
        errors.append(f"required command must use rch or a repo script, not bare cargo: {command}")

theater = evidence.get("theater_todo_wording_primary", {})
resolution = str(theater.get("resolution_policy", ""))
if "quoted source-ledger token" not in resolution or "must not use WIP/draft/TODO wording" not in resolution:
    errors.append("theater TODO wording resolution is missing or too weak")
if "report_only_promotes_replacement_level" not in set(theater.get("forbidden_completion_claims", [])):
    errors.append("theater forbidden claims must block report_only promotion")

telemetry = evidence.get("telemetry", {})
if set(telemetry.get("required_events", [])) != EXPECTED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != EXPECTED_FIELDS:
    errors.append("telemetry required_fields mismatch")

source_report, source_log_rows, source_report_ref = run_source_checker()
if source_report:
    source_checks = source_report.get("checks", {})
    if not isinstance(source_checks, dict) or any(value != "pass" for value in source_checks.values()):
        errors.append("source architecture TODO report must pass")
    source_summary = source_report.get("summary", {})
    if int(source_summary.get("row_count", -1)) != int(expected_counts.get("row_count", -2)):
        errors.append("source report row_count mismatch")
    if int(source_summary.get("mapped_rows", -1)) != int(expected_counts.get("row_count", -2)):
        errors.append("source report mapped_row_count mismatch")
source_events = {row.get("event") for row in source_log_rows}
for event in source_contract.get("required_log_events", []):
    if event not in source_events:
        errors.append(f"source log event missing: {event}")

status = "fail" if errors else "pass"
summary = {
    "row_count": int(expected_counts.get("row_count", 0)),
    "mapped_row_count": len(mapped_ids),
    "missing_items_bound": sorted(missing_items),
    "source_report": source_report_ref,
}
report = {
    "schema_version": "architecture_todo_reconciliation_completion_contract.report.v1",
    "bead_id": COMPLETION_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "errors": errors,
    **summary,
}
events = [
    "architecture_todo_reconciliation_source_gate_replayed",
    "architecture_todo_reconciliation_completion_validated",
]
if errors:
    events = ["architecture_todo_reconciliation_completion_failed"]
log_rows = []
for event in events:
    log_rows.append(
        {
            "timestamp": ts,
            "trace_id": f"{COMPLETION_BEAD}::architecture_todo_completion::{event}",
            "event": event,
            "level": "error" if errors else "info",
            "bead_id": COMPLETION_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "status": status,
            "row_count": summary["row_count"],
            "mapped_row_count": summary["mapped_row_count"],
            "missing_items_bound": summary["missing_items_bound"],
            "source_report": summary["source_report"],
            "artifact_refs": [
                display_path(contract_path),
                display_path(source_artifact_path),
                summary["source_report"],
            ],
            "failure_signature": "none" if not errors else "architecture_todo_reconciliation_completion_failed",
        }
    )

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in log_rows) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    raise SystemExit(1)
PY
