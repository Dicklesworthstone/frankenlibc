#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${SEMANTIC_CONTRACT_INVENTORY_COMPLETION_CONTRACT:-$ROOT/tests/conformance/semantic_contract_inventory_completion_contract.v1.json}"
OUT_DIR="${SEMANTIC_CONTRACT_INVENTORY_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${SEMANTIC_CONTRACT_INVENTORY_COMPLETION_REPORT:-$OUT_DIR/semantic_contract_inventory_completion_contract.report.json}"
LOG="${SEMANTIC_CONTRACT_INVENTORY_COMPLETION_LOG:-$OUT_DIR/semantic_contract_inventory_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
from collections import Counter
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "semantic_contract_inventory_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "semantic_contract_inventory_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-bp8fl.1.1"
COMPLETION_BEAD = "bd-bp8fl.1.1.1"
TRACE_ID = "bd-bp8fl-1-1-1-semantic-contract-inventory-completion-v1"
PASS_EVENT = "semantic_contract_inventory_completion_contract_validated"
FAIL_EVENT = "semantic_contract_inventory_completion_contract_failed"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "original_bead",
    "completion_debt_bead",
    "trace_id",
    "status",
    "source_commit",
    "source_inventory",
    "source_checker",
    "source_tests",
    "missing_item_bindings",
    "summary",
    "artifact_refs",
    "errors",
}
REQUIRED_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "stream",
    "gate",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "source_commit",
    "target_dir",
    "failure_signature",
    "artifact_refs",
}
REQUIRED_EVENTS = {
    "semantic_contract_inventory_source_gate",
    "semantic_contract_inventory_source_checker_gate",
    "semantic_contract_inventory_source_tests_gate",
    PASS_EVENT,
    FAIL_EVENT,
}

errors: list[str] = []
log_rows: list[dict[str, Any]] = []


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


COMMIT = source_commit()


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


def as_list(value: Any, context: str, allow_empty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    return value


def string_set(value: Any, context: str, allow_empty: bool = False) -> set[str]:
    result: set[str] = set()
    for index, item in enumerate(as_list(value, context, allow_empty=allow_empty)):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.add(item)
    return result


def file_line_ref_exists(ref: Any) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        err(f"invalid file-line ref: {ref!r}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        err(f"invalid file-line ref line: {ref}")
        return
    path = ROOT / path_text
    if line_no <= 0 or not path.is_file():
        err(f"file-line ref missing path or positive line: {ref}")
        return
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if line_no > line_count:
        err(f"file-line ref outside file: {ref}")


def read_source(path_text: str, context: str) -> str:
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} missing: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} unreadable: {path_text}: {exc}")
        return ""


def is_executable(path: pathlib.Path) -> bool:
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def emit_row(event: str, gate: str, scenario_id: str, symbol: str, expected: Any, actual: Any, ok: bool) -> None:
    log_rows.append(
        {
            "timestamp": utc_now(),
            "trace_id": f"{COMPLETION_BEAD}::semantic_contract_inventory::{scenario_id}",
            "level": "info" if ok else "error",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "stream": "conformance",
            "gate": gate,
            "scenario_id": scenario_id,
            "runtime_mode": "hardened",
            "replacement_level": "L1",
            "api_family": "semantic_contract_inventory",
            "symbol": symbol,
            "oracle_kind": "completion_debt_contract",
            "expected": expected,
            "actual": actual,
            "source_commit": COMMIT,
            "target_dir": rel(OUT_DIR),
            "failure_signature": "none" if ok else "contract_drift",
            "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
        }
    )


def run_shell_syntax(path_text: str) -> dict[str, Any]:
    proc = subprocess.run(
        ["bash", "-n", path_text],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "path": path_text,
        "exit_status": proc.returncode,
        "stdout_prefix": proc.stdout[:300],
        "stderr_prefix": proc.stderr[:300],
    }


def validate_source_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    contract = manifest.get("source_contract", {}).get("manifest", {})
    if not isinstance(contract, dict):
        err("source_contract.manifest must be an object")
        return {}
    path_text = contract.get("path")
    if not isinstance(path_text, str):
        err("source_contract.manifest.path must be a string")
        return {}
    source_manifest = load_json(ROOT / path_text, "source semantic inventory")
    entries = source_manifest.get("entries", [])
    summary = source_manifest.get("summary", {})
    class_counts = Counter(row.get("semantic_class") for row in entries if isinstance(row, dict))
    source_counts = Counter(row.get("source_path") for row in entries if isinstance(row, dict))
    seed_covered = summary.get("seed_overlay_covered")
    actual = {
        "path": path_text,
        "schema_version": source_manifest.get("schema_version"),
        "bead": source_manifest.get("bead"),
        "entry_count": len(entries) if isinstance(entries, list) else 0,
        "seed_overlay_covered": seed_covered,
        "semantic_classes": sorted(key for key in class_counts if key),
        "source_paths": sorted(key for key in source_counts if key),
    }
    require(source_manifest.get("schema_version") == contract.get("schema_version"), "source manifest schema_version drifted")
    require(source_manifest.get("bead") == contract.get("bead"), "source manifest bead drifted")
    require(isinstance(entries, list) and len(entries) >= int(contract.get("min_entry_count", 0)), "source manifest entry count below completion threshold")
    require(isinstance(seed_covered, int) and seed_covered >= int(contract.get("min_seed_overlay_covered", 0)), "source manifest seed overlay coverage below completion threshold")
    require(set(contract.get("required_semantic_classes", [])) <= set(class_counts), "source manifest missing required semantic classes")
    blocked_fragment = contract.get("required_blocked_claim_fragment")
    require(isinstance(summary, dict) and isinstance(blocked_fragment, str) and blocked_fragment in str(summary.get("blocked_claim", "")), "source manifest blocked claim text drifted")
    require(summary.get("entry_count") == len(entries), "source manifest summary.entry_count mismatch")
    require(summary.get("by_semantic_class") == dict(class_counts), "source manifest semantic class summary mismatch")
    require(summary.get("by_source_path") == dict(source_counts), "source manifest source path summary mismatch")

    required_fields = set(contract.get("required_entry_fields", []))
    for row in entries if isinstance(entries, list) else []:
        if not isinstance(row, dict):
            err("source manifest entries must be objects")
            continue
        row_id = row.get("id", "<missing id>")
        missing_fields = sorted(field for field in required_fields if field not in row)
        if missing_fields:
            err(f"source manifest row {row_id} missing fields {missing_fields}")
        source_path = row.get("source_path")
        marker = row.get("line_marker")
        if isinstance(source_path, str) and isinstance(marker, str):
            source_text = read_source(source_path, f"source manifest row {row_id}")
            if marker not in source_text:
                err(f"source manifest row {row_id} marker missing from {source_path}: {marker!r}")
    claim_policy = source_manifest.get("claim_policy", {})
    for key in string_set(contract.get("required_claim_policy"), "source_contract.manifest.required_claim_policy"):
        if key == "readme_feature_parity_release_notes_may_advance_without_machine_evidence":
            require(claim_policy.get(key) is False, f"source manifest claim_policy.{key} must remain false")
        else:
            require(claim_policy.get(key) is True, f"source manifest claim_policy.{key} must remain true")

    emit_row(
        "semantic_contract_inventory_source_gate",
        "source_manifest",
        "semantic_contract_inventory",
        path_text,
        {
            "min_entry_count": contract.get("min_entry_count"),
            "min_seed_overlay_covered": contract.get("min_seed_overlay_covered"),
        },
        actual,
        not errors,
    )
    return actual


def validate_source_checker(manifest: dict[str, Any]) -> dict[str, Any]:
    contract = manifest.get("source_contract", {}).get("checker", {})
    if not isinstance(contract, dict):
        err("source_contract.checker must be an object")
        return {}
    path_text = contract.get("path")
    if not isinstance(path_text, str):
        err("source_contract.checker.path must be a string")
        return {}
    path = ROOT / path_text
    text = read_source(path_text, "source checker")
    syntax = run_shell_syntax(path_text)
    require(syntax["exit_status"] == 0, f"source checker bash syntax failed: {syntax['stderr_prefix']}")
    require(is_executable(path), f"source checker must be executable: {path_text}")
    for needle in string_set(contract.get("required_needles"), "source_contract.checker.required_needles"):
        if needle not in text:
            err(f"source checker missing needle {needle!r}")

    proc = subprocess.run(
        [str(path)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(proc.returncode == 0, f"source checker failed: stdout={proc.stdout[:500]} stderr={proc.stderr[:500]}")

    report_path = ROOT / str(contract.get("source_report_path", ""))
    log_path = ROOT / str(contract.get("source_log_path", ""))
    report = load_json(report_path, "source checker report")
    source_log_rows = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if log_path.is_file() else []
    if not log_path.is_file():
        err(f"source checker log missing: {rel(log_path)}")
    require(report.get("status") == "pass", "source checker report status must be pass")
    required_checks = string_set(contract.get("required_checks"), "source_contract.checker.required_checks")
    for check in required_checks:
        if report.get("checks", {}).get(check) != "pass":
            err(f"source checker report checks.{check} must pass")
    for field in string_set(contract.get("required_report_fields"), "source_contract.checker.required_report_fields"):
        if field not in report:
            err(f"source checker report missing field {field}")

    actual = {
        "path": path_text,
        "syntax_exit_status": syntax["exit_status"],
        "report_path": rel(report_path),
        "log_path": rel(log_path),
        "report_status": report.get("status"),
        "report_checks": sorted(report.get("checks", {}).keys()) if isinstance(report.get("checks"), dict) else [],
        "source_log_rows": len(source_log_rows),
    }
    emit_row(
        "semantic_contract_inventory_source_checker_gate",
        "source_checker",
        "semantic_contract_inventory_checker",
        path_text,
        {"required_checks": sorted(required_checks), "source_log_rows_min": 1},
        actual,
        proc.returncode == 0 and report.get("status") == "pass" and bool(source_log_rows),
    )
    return actual


def validate_source_tests(manifest: dict[str, Any]) -> dict[str, Any]:
    contract = manifest.get("source_contract", {}).get("source_tests", {})
    if not isinstance(contract, dict):
        err("source_contract.source_tests must be an object")
        return {}
    path_text = contract.get("path")
    if not isinstance(path_text, str):
        err("source_contract.source_tests.path must be a string")
        return {}
    text = read_source(path_text, "source tests")
    required_tests = string_set(contract.get("required_test_refs"), "source_contract.source_tests.required_test_refs")
    for test_ref in required_tests:
        if f"fn {test_ref}" not in text:
            err(f"source tests missing required function {test_ref}")
    actual = {
        "path": path_text,
        "required_tests": sorted(required_tests),
        "required_test_count": len(required_tests),
    }
    emit_row(
        "semantic_contract_inventory_source_tests_gate",
        "source_tests",
        "semantic_contract_inventory_tests",
        path_text,
        {"required_tests": sorted(required_tests)},
        actual,
        all(f"fn {test_ref}" in text for test_ref in required_tests),
    )
    return actual


manifest = load_json(CONTRACT, "completion contract")
if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("original_bead") != ORIGINAL_BEAD:
    err(f"original_bead must be {ORIGINAL_BEAD}")
if manifest.get("completion_debt_bead") != COMPLETION_BEAD:
    err(f"completion_debt_bead must be {COMPLETION_BEAD}")
if manifest.get("trace_id") != TRACE_ID:
    err(f"trace_id must be {TRACE_ID}")

audit = manifest.get("audit_reference", {})
if not isinstance(audit, dict) or audit.get("score_threshold", 0) < 800:
    err("audit_reference.score_threshold must be >= 800")

for ref in as_list(manifest.get("implementation_refs"), "implementation_refs"):
    file_line_ref_exists(ref)

artifacts = manifest.get("source_artifacts")
if not isinstance(artifacts, dict) or not artifacts:
    err("source_artifacts must be a non-empty object")
    artifacts = {}
for artifact_id, path_text in artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{artifact_id} must be a non-empty string")
        continue
    require((ROOT / path_text).exists(), f"source artifact missing: {artifact_id}: {path_text}")

source_inventory = validate_source_manifest(manifest)
source_checker = validate_source_checker(manifest)
source_tests = validate_source_tests(manifest)

item_ids = set()
for item in as_list(manifest.get("missing_item_bindings"), "missing_item_bindings"):
    if not isinstance(item, dict):
        err("missing_item_bindings entries must be objects")
        continue
    item_id = item.get("id")
    if isinstance(item_id, str):
        item_ids.add(item_id)
    refs = item.get("evidence_refs")
    if not isinstance(refs, list) or not refs:
        err(f"missing_item_bindings.{item_id}.evidence_refs must be a non-empty array")
missing_items = sorted(EXPECTED_MISSING_ITEMS - item_ids)
if missing_items:
    err(f"missing_item_bindings missing {','.join(missing_items)}")

evidence = manifest.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
report_fields = string_set(evidence.get("required_report_fields"), "completion_debt_evidence.required_report_fields")
log_fields = string_set(evidence.get("required_log_fields"), "completion_debt_evidence.required_log_fields")
events = string_set(evidence.get("required_events"), "completion_debt_evidence.required_events")
if not REQUIRED_REPORT_FIELDS <= report_fields:
    err(f"completion_debt_evidence.required_report_fields missing {sorted(REQUIRED_REPORT_FIELDS - report_fields)}")
if not REQUIRED_LOG_FIELDS <= log_fields:
    err(f"completion_debt_evidence.required_log_fields missing {sorted(REQUIRED_LOG_FIELDS - log_fields)}")
if not REQUIRED_EVENTS <= events:
    err(f"completion_debt_evidence.required_events missing {sorted(REQUIRED_EVENTS - events)}")

test_source_path = ROOT / "crates/frankenlibc-harness/tests/semantic_contract_inventory_completion_contract_test.rs"
test_source = test_source_path.read_text(encoding="utf-8") if test_source_path.is_file() else ""
for test_ref in string_set(evidence.get("required_test_refs"), "completion_debt_evidence.required_test_refs"):
    if f"fn {test_ref}" not in test_source:
        err(f"completion_debt_evidence.required_test_refs missing test fn {test_ref}")

status = "pass" if not errors else "fail"
summary_event = PASS_EVENT if not errors else FAIL_EVENT
log_rows.append(
    {
        "timestamp": utc_now(),
        "trace_id": f"{COMPLETION_BEAD}::semantic_contract_inventory::summary",
        "level": "info" if not errors else "error",
        "event": summary_event,
        "bead_id": COMPLETION_BEAD,
        "stream": "conformance",
        "gate": "completion_contract",
        "scenario_id": "summary",
        "runtime_mode": "hardened",
        "replacement_level": "L1",
        "api_family": "semantic_contract_inventory",
        "symbol": rel(CONTRACT),
        "oracle_kind": "completion_debt_contract",
        "expected": {
            "missing_items": sorted(EXPECTED_MISSING_ITEMS),
            "required_events": sorted(REQUIRED_EVENTS),
        },
        "actual": {
            "error_count": len(errors),
            "source_entry_count": source_inventory.get("entry_count"),
            "source_log_rows": source_checker.get("source_log_rows"),
        },
        "source_commit": COMMIT,
        "target_dir": rel(OUT_DIR),
        "failure_signature": "none" if not errors else ";".join(errors[:8]),
        "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
    }
)

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "trace_id": TRACE_ID,
    "status": status,
    "source_commit": COMMIT,
    "source_inventory": source_inventory,
    "source_checker": source_checker,
    "source_tests": source_tests,
    "missing_item_bindings": sorted(item_ids),
    "summary": {
        "source_artifact_count": len(artifacts),
        "source_entry_count": source_inventory.get("entry_count"),
        "source_seed_overlay_covered": source_inventory.get("seed_overlay_covered"),
        "source_log_rows": source_checker.get("source_log_rows"),
        "completion_log_rows": len(log_rows),
        "required_report_field_count": len(report_fields),
        "required_log_field_count": len(log_fields),
    },
    "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("\n".join(json.dumps(row, sort_keys=True) for row in log_rows) + "\n", encoding="utf-8")

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"SOURCE_ENTRY_COUNT={source_inventory.get('entry_count')}")
print(f"SOURCE_LOG_ROWS={source_checker.get('source_log_rows')}")
print(f"COMPLETION_LOG_ROWS={len(log_rows)}")
print(f"REPORT={rel(REPORT)}")
print(f"LOG={rel(LOG)}")
for message in errors:
    print(f"ERROR: {message}")

if errors:
    raise SystemExit(1)
PY
