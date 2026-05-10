#!/usr/bin/env bash
# check_host_libc_dependency_release_audit_completion_contract.sh - bd-bp8fl.6.1.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_HOST_DEP_RELEASE_AUDIT_CONTRACT:-$ROOT/tests/conformance/host_libc_dependency_release_audit_completion_contract.v1.json}"
INVENTORY_CONTRACT="${FRANKENLIBC_HOST_DEP_INVENTORY_CONTRACT:-$ROOT/tests/conformance/host_libc_dependency_inventory.v1.json}"
REPORT="${FRANKENLIBC_HOST_DEP_RELEASE_AUDIT_REPORT:-$ROOT/target/conformance/host_libc_dependency_release_audit_completion_contract.report.json}"
LOG="${FRANKENLIBC_HOST_DEP_RELEASE_AUDIT_LOG:-$ROOT/target/conformance/host_libc_dependency_release_audit_completion_contract.log.jsonl}"
INVENTORY_REPORT="${FRANKENLIBC_HOST_DEP_RELEASE_AUDIT_INVENTORY_REPORT:-$ROOT/target/conformance/host_libc_dependency_release_audit.inventory.report.json}"
INVENTORY_LOG="${FRANKENLIBC_HOST_DEP_RELEASE_AUDIT_INVENTORY_LOG:-$ROOT/target/conformance/host_libc_dependency_release_audit.inventory.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$INVENTORY_REPORT")" "$(dirname "$INVENTORY_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
INVENTORY_CONTRACT="$INVENTORY_CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
INVENTORY_REPORT="$INVENTORY_REPORT" \
INVENTORY_LOG="$INVENTORY_LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
INVENTORY_CONTRACT = pathlib.Path(os.environ["INVENTORY_CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
INVENTORY_REPORT = pathlib.Path(os.environ["INVENTORY_REPORT"])
INVENTORY_LOG = pathlib.Path(os.environ["INVENTORY_LOG"])

COMPLETION_BEAD = "bd-bp8fl.6.1.1"
ORIGINAL_BEAD = "bd-bp8fl.6.1"
EXPECTED_SCHEMA = "host_libc_dependency_release_audit_completion_contract.v1"
EXPECTED_MANIFEST = "bd-bp8fl.6.1.1-host-libc-dependency-release-audit-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_TELEMETRY_EVENTS = {
    "host_libc_dependency_release_audit_completion_contract_validated",
    "host_libc_dependency_release_audit_completion_contract_failed",
    "host_libc_dependency_release_audit_summary",
    "host_libc_dependency_standalone_claim_blockers_preserved",
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "status",
    "source_commit",
    "missing_items_bound",
    "test_refs",
    "inventory_summary",
    "release_artifact_status",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def load_jsonl(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"{label} is unreadable: {rel(path)}: {exc}")
        return rows
    for line_no, raw in enumerate(raw_lines, start=1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except Exception as exc:
            err(f"{label}:{line_no} is not valid JSON: {exc}")
            continue
        if not isinstance(value, dict):
            err(f"{label}:{line_no} must be an object")
            continue
        rows.append(value)
    return rows


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def as_string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def validate_file_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        err(f"{context} must be a file:line string")
        return
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        err(f"{context} references line past EOF: {value}")
    elif not lines[line_number - 1].strip():
        err(f"{context} references a blank line: {value}")


def source_texts(test_sources: Any) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return texts
    for key, path_text in test_sources.items():
        if not isinstance(key, str) or not key:
            err("test_sources keys must be non-empty strings")
            continue
        if not isinstance(path_text, str) or not path_text:
            err(f"test_sources.{key} must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            err(f"test_sources.{key} references missing file: {path_text}")
            continue
        texts[key] = path.read_text(encoding="utf-8")
    return texts


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not source:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].source must be non-empty")
            continue
        if not isinstance(name, str) or not name:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].name must be non-empty")
            continue
        key = (source, name)
        if key in seen:
            err(f"completion_debt_evidence.{section_name} duplicates test ref {source}::{name}")
        seen.add(key)
        text = texts.get(source, "")
        if not text:
            err(f"completion_debt_evidence.{section_name} references unknown source {source}")
        elif f"fn {name}" not in text:
            err(f"completion_debt_evidence.{section_name} references missing test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


def validate_required_commands(section: dict[str, Any], section_name: str) -> None:
    commands = as_string_list(section.get("required_commands"), f"completion_debt_evidence.{section_name}.required_commands")
    for command in commands:
        if "cargo " in command and "rch exec --" not in command:
            err(f"completion_debt_evidence.{section_name}.required_commands must route cargo through rch: {command}")


def run_inventory_gate() -> None:
    env = os.environ.copy()
    env["FRANKENLIBC_HOST_DEP_REPORT"] = str(INVENTORY_REPORT)
    env["FRANKENLIBC_HOST_DEP_LOG"] = str(INVENTORY_LOG)
    env.setdefault("FRANKENLIBC_REQUIRE_RELEASE_ARTIFACT", "0")
    proc = subprocess.run(
        ["bash", "scripts/check_host_libc_dependency_inventory.sh"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        err(
            "host libc dependency inventory gate failed: "
            f"exit={proc.returncode} stdout={proc.stdout[:800]} stderr={proc.stderr[:800]}"
        )


manifest = load_json(CONTRACT, "contract")
inventory_contract = load_json(INVENTORY_CONTRACT, "inventory_contract")
source_commit = git_head()

if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if manifest.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")
if inventory_contract.get("bead") != ORIGINAL_BEAD:
    err(f"inventory contract bead must be {ORIGINAL_BEAD}")

source_artifacts = manifest.get("source_artifacts")
if not isinstance(source_artifacts, dict):
    err("source_artifacts must be an object")
    source_artifacts = {}
for key in [
    "inventory_contract",
    "inventory_gate",
    "inventory_harness",
    "completion_gate",
    "completion_harness",
]:
    path_text = source_artifacts.get(key)
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{key} must be a non-empty string")
    elif not (ROOT / path_text).is_file():
        err(f"source_artifacts.{key} references missing file: {path_text}")

completion = manifest.get("completion_debt_evidence")
if not isinstance(completion, dict):
    err("completion_debt_evidence must be an object")
    completion = {}
if completion.get("bead") != COMPLETION_BEAD:
    err(f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
if completion.get("original_bead") != ORIGINAL_BEAD:
    err(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
threshold = completion.get("next_audit_score_threshold")
if not isinstance(threshold, int) or threshold < 800 or threshold > 1000:
    err("completion_debt_evidence.next_audit_score_threshold must be 800..1000")

implementation_refs = completion.get("implementation_refs")
if not isinstance(implementation_refs, list) or len(implementation_refs) < 14:
    err("completion_debt_evidence.implementation_refs must contain at least 14 file:line refs")
else:
    for index, ref in enumerate(implementation_refs):
        validate_file_line_ref(ref, f"completion_debt_evidence.implementation_refs[{index}]")

manifest_categories = set(as_string_list(completion.get("required_inventory_categories"), "required_inventory_categories"))
contract_categories = set(as_string_list(inventory_contract.get("required_inventory_categories"), "inventory_contract.required_inventory_categories"))
if manifest_categories != contract_categories:
    err("required_inventory_categories must exactly match inventory contract")

manifest_symbols = set(as_string_list(completion.get("required_anchor_symbols"), "required_anchor_symbols"))
contract_symbols = set(as_string_list(inventory_contract.get("required_anchor_symbols"), "inventory_contract.required_anchor_symbols"))
if manifest_symbols != contract_symbols:
    err("required_anchor_symbols must exactly match inventory contract")

manifest_log_fields = set(as_string_list(completion.get("required_inventory_log_fields"), "required_inventory_log_fields"))
contract_log_fields = set(as_string_list(inventory_contract.get("required_log_fields"), "inventory_contract.required_log_fields"))
if manifest_log_fields != contract_log_fields:
    err("required_inventory_log_fields must exactly match inventory contract")

texts = source_texts(completion.get("test_sources"))
missing_items_bound: list[str] = []
test_refs_by_section: dict[str, list[dict[str, str]]] = {}
for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
    section = completion.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    section_threshold = section.get("next_audit_score_threshold", threshold)
    if not isinstance(section_threshold, int) or section_threshold < 800:
        err(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be >= 800")
    missing_items_bound.append(str(section.get("missing_item_id", "")))
    test_refs_by_section[section_name] = validate_test_refs(section, section_name, texts)
    if section_name != "telemetry_primary":
        validate_required_commands(section, section_name)

telemetry = completion.get("telemetry_primary") if isinstance(completion.get("telemetry_primary"), dict) else {}
required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
missing_events = sorted(EXPECTED_TELEMETRY_EVENTS - required_events)
if missing_events:
    err(f"telemetry_primary.required_events missing {missing_events}")
required_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
missing_fields = sorted(EXPECTED_TELEMETRY_FIELDS - required_fields)
if missing_fields:
    err(f"telemetry_primary.required_fields missing {missing_fields}")

run_inventory_gate()
inventory_report = load_json(INVENTORY_REPORT, "inventory_report")
inventory_rows = load_jsonl(INVENTORY_LOG, "inventory_log")
summary = inventory_report.get("summary") if isinstance(inventory_report.get("summary"), dict) else {}
expected_inventory = completion.get("expected_source_inventory")
if not isinstance(expected_inventory, dict):
    err("expected_source_inventory must be an object")
    expected_inventory = {}

if inventory_report.get("status") != "pass":
    err(f"inventory report status must be pass, got {inventory_report.get('status')!r}")
minimum_event_count = expected_inventory.get("minimum_inventory_event_count", 0)
if not isinstance(minimum_event_count, int) or summary.get("inventory_event_count", 0) < minimum_event_count:
    err("inventory_event_count is below expected source inventory minimum")
minimum_blockers = expected_inventory.get("minimum_l2_l3_blocker_count", 0)
if not isinstance(minimum_blockers, int) or summary.get("l2_l3_blocker_count", 0) < minimum_blockers:
    err("l2_l3_blocker_count is below expected minimum")
if summary.get("unapproved_direct_libc_call_count") != expected_inventory.get("unapproved_direct_libc_call_count"):
    err("unapproved_direct_libc_call_count drifted")
release_status = inventory_report.get("release_artifact", {}).get("status")
if release_status != expected_inventory.get("release_artifact_status"):
    err(f"release artifact status drifted: expected {expected_inventory.get('release_artifact_status')!r} actual {release_status!r}")

seen_categories = set(summary.get("required_categories_seen", []))
if seen_categories != manifest_categories:
    err(f"required_categories_seen mismatch: {sorted(seen_categories)}")
seen_symbols = set(summary.get("required_anchor_symbols_seen", []))
if seen_symbols != manifest_symbols:
    err(f"required_anchor_symbols_seen mismatch: {sorted(seen_symbols)}")
source_counts = summary.get("source_surface_counts") if isinstance(summary.get("source_surface_counts"), dict) else {}
for category in as_string_list(expected_inventory.get("required_source_surface_categories"), "expected_source_inventory.required_source_surface_categories"):
    if not isinstance(source_counts.get(category), int) or source_counts.get(category, 0) <= 0:
        err(f"source surface category {category} must have rows")

negative_results = inventory_report.get("negative_claim_results")
if not isinstance(negative_results, list):
    err("inventory_report.negative_claim_results must be an array")
    negative_results = []
negative_by_id = {
    str(row.get("id")): row
    for row in negative_results
    if isinstance(row, dict) and row.get("id")
}
for claim_id in as_string_list(expected_inventory.get("negative_claim_result_ids"), "expected_source_inventory.negative_claim_result_ids"):
    row = negative_by_id.get(claim_id)
    if row is None:
        err(f"missing negative claim result {claim_id}")
        continue
    if row.get("status") not in {"blocked_by_inventory", "guard_clean"}:
        err(f"negative claim result {claim_id} must be blocked_by_inventory or guard_clean")

if not inventory_rows:
    err("inventory log must be non-empty")
for index, row in enumerate(inventory_rows[:50]):
    missing = sorted(manifest_log_fields - set(row))
    if missing:
        err(f"inventory log row {index} missing required fields {missing}")
        break

inventory_summary = {
    "inventory_event_count": summary.get("inventory_event_count", 0),
    "l2_l3_blocker_count": summary.get("l2_l3_blocker_count", 0),
    "unapproved_direct_libc_call_count": summary.get("unapproved_direct_libc_call_count", 0),
    "required_categories_seen": sorted(seen_categories),
    "required_anchor_symbols_seen": sorted(seen_symbols),
    "source_surface_counts": source_counts,
}
status = "pass" if not errors else "fail"
events: list[dict[str, Any]] = []


def event_payload(event: str, level: str, failure_signature: str = "none") -> dict[str, Any]:
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trace_id": f"{COMPLETION_BEAD}::{event}",
        "event": event,
        "level": level,
        "bead_id": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "status": status,
        "source_commit": source_commit,
        "missing_items_bound": missing_items_bound,
        "test_refs": test_refs_by_section,
        "inventory_summary": inventory_summary,
        "release_artifact_status": release_status,
        "artifact_refs": [
            rel(CONTRACT),
            rel(INVENTORY_CONTRACT),
            rel(INVENTORY_REPORT),
            rel(INVENTORY_LOG),
            rel(REPORT),
            rel(LOG),
        ],
        "failure_signature": failure_signature,
    }


events.append(event_payload("host_libc_dependency_release_audit_summary", "info"))
if summary.get("l2_l3_blocker_count", 0) > 0:
    events.append(event_payload("host_libc_dependency_standalone_claim_blockers_preserved", "warning"))
if errors:
    events.append(event_payload("host_libc_dependency_release_audit_completion_contract_failed", "error", ",".join(errors[:8])))
else:
    events.append(event_payload("host_libc_dependency_release_audit_completion_contract_validated", "info"))

LOG.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)

for index, event in enumerate(events):
    missing = sorted(EXPECTED_TELEMETRY_FIELDS - set(event))
    if missing:
        err(f"generated telemetry event {index} missing fields {missing}")
if not errors:
    emitted = {event["event"] for event in events}
    required_for_pass = EXPECTED_TELEMETRY_EVENTS - {"host_libc_dependency_release_audit_completion_contract_failed"}
    missing = sorted(required_for_pass - emitted)
    if missing:
        err(f"pass telemetry missing events {missing}")
        status = "fail"

report = {
    "schema_version": "host_libc_dependency_release_audit_completion_contract.report.v1",
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": inventory_summary,
    "release_artifact_status": release_status,
    "missing_items_bound": missing_items_bound,
    "test_refs": test_refs_by_section,
    "required_telemetry_events": sorted(required_events),
    "required_telemetry_fields": sorted(required_fields),
    "errors": errors,
    "inventory_report": rel(INVENTORY_REPORT),
    "inventory_log": rel(INVENTORY_LOG),
    "log": rel(LOG),
    "artifact_refs": [
        rel(CONTRACT),
        rel(INVENTORY_CONTRACT),
        rel(INVENTORY_REPORT),
        rel(INVENTORY_LOG),
        rel(REPORT),
        rel(LOG),
    ],
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: host libc dependency release-audit completion contract ({len(errors)} errors)")
    for message in errors[:20]:
        print(f"  - {message}")
    raise SystemExit(1)

print(
    "PASS: host libc dependency release-audit completion contract "
    f"(events={inventory_summary['inventory_event_count']}, "
    f"l2_l3_blockers={inventory_summary['l2_l3_blocker_count']}, "
    f"release_artifact={release_status}, report={rel(REPORT)})"
)
PY
