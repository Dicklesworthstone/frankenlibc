#!/usr/bin/env bash
# check_replacement_surface_completion_contract.sh - bd-w2c3.2.4 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_REPLACEMENT_SURFACE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/replacement_surface_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_REPLACEMENT_SURFACE_COMPLETION_REPORT:-$ROOT/target/conformance/replacement_surface_completion_contract.report.json}"
LOG="${FRANKENLIBC_REPLACEMENT_SURFACE_COMPLETION_LOG:-$ROOT/target/conformance/replacement_surface_completion_contract.log.jsonl}"
LEVELS_REPORT="${FRANKENLIBC_REPLACEMENT_SURFACE_COMPLETION_LEVELS_REPORT:-$ROOT/target/conformance/replacement_surface_completion_contract.replacement_levels.report.json}"
LEVELS_LOG="${FRANKENLIBC_REPLACEMENT_SURFACE_COMPLETION_LEVELS_LOG:-$ROOT/target/conformance/replacement_surface_completion_contract.replacement_levels.log.jsonl}"
CALLTHROUGH_REPORT="$ROOT/target/conformance/callthrough_census.report.json"
CALLTHROUGH_LOG="$ROOT/target/conformance/callthrough_census.log.jsonl"
RESIDUAL_REPORT="$ROOT/target/conformance/residual_replacement_callthrough_blockers.report.json"
RESIDUAL_LOG="$ROOT/target/conformance/residual_replacement_callthrough_blockers.log.jsonl"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$LEVELS_REPORT")" "$(dirname "$LEVELS_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
LEVELS_REPORT="$LEVELS_REPORT" \
LEVELS_LOG="$LEVELS_LOG" \
CALLTHROUGH_REPORT="$CALLTHROUGH_REPORT" \
CALLTHROUGH_LOG="$CALLTHROUGH_LOG" \
RESIDUAL_REPORT="$RESIDUAL_REPORT" \
RESIDUAL_LOG="$RESIDUAL_LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from collections import Counter
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
LEVELS_REPORT = pathlib.Path(os.environ["LEVELS_REPORT"])
LEVELS_LOG = pathlib.Path(os.environ["LEVELS_LOG"])
CALLTHROUGH_REPORT = pathlib.Path(os.environ["CALLTHROUGH_REPORT"])
CALLTHROUGH_LOG = pathlib.Path(os.environ["CALLTHROUGH_LOG"])
RESIDUAL_REPORT = pathlib.Path(os.environ["RESIDUAL_REPORT"])
RESIDUAL_LOG = pathlib.Path(os.environ["RESIDUAL_LOG"])

COMPLETION_BEAD = "bd-w2c3.2.4"
ORIGINAL_BEAD = "bd-w2c3.2"
EXPECTED_SCHEMA = "replacement_surface_completion_contract.v1"
EXPECTED_MANIFEST = "bd-w2c3.2.4-replacement-surface-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "integration_primary": "tests.integration.primary",
    "e2e_primary": "tests.e2e.primary",
    "migrations_primary": "migrations.primary",
}
PASS_EVENTS = [
    "replacement_surface_completion_contract_validated",
    "replacement_surface_summary",
    "replacement_levels_gate_replayed",
    "callthrough_census_gate_replayed",
    "residual_callthrough_gate_replayed",
]
EXPECTED_REQUIRED_EVENTS = set(PASS_EVENTS) | {"replacement_surface_completion_contract_failed"}
EXPECTED_REQUIRED_FIELDS = {
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
    "surface_summary",
    "replacement_levels_report",
    "callthrough_census_report",
    "residual_callthrough_report",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


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
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"{label} is not readable: {rel(path)}: {exc}")
        return rows
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            err(f"{label} line {index} is not valid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            err(f"{label} line {index} must be an object")
            continue
        rows.append(row)
    return rows


def string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        out.append(item)
    return out


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


def validate_source_artifacts(source_artifacts: Any) -> None:
    if not isinstance(source_artifacts, dict) or not source_artifacts:
        err("source_artifacts must be a non-empty object")
        return
    for key, value in source_artifacts.items():
        if not isinstance(key, str) or not key:
            err("source_artifacts keys must be non-empty strings")
            continue
        if not isinstance(value, str) or not value:
            err(f"source_artifacts.{key} must be a non-empty path")
            continue
        if not (ROOT / value).is_file():
            err(f"source_artifacts.{key} references missing file: {value}")


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


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, test_ref in enumerate(refs):
        if not isinstance(test_ref, dict):
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = test_ref.get("source")
        name = test_ref.get("name")
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
        elif not function_exists(text, name):
            err(f"completion_debt_evidence.{section_name} references missing test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


def validate_required_commands(section: dict[str, Any], section_name: str) -> None:
    commands = string_list(section.get("required_commands"), f"completion_debt_evidence.{section_name}.required_commands")
    for command in commands:
        if "cargo " in command and "rch exec --" not in command:
            err(f"completion_debt_evidence.{section_name}.required_commands must route cargo through rch: {command}")


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def fail_report(source_commit: str, failure_signature: str, messages: list[str]) -> None:
    report = {
        "schema_version": "replacement_surface_completion_contract.report.v1",
        "bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": "fail",
        "source_commit": source_commit,
        "failure_signature": failure_signature,
        "errors": messages,
        "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
    }
    event = {
        "timestamp": now_utc(),
        "trace_id": f"{COMPLETION_BEAD}::replacement_surface_completion::failed",
        "event": "replacement_surface_completion_contract_failed",
        "level": "error",
        "bead_id": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "status": "fail",
        "source_commit": source_commit,
        "missing_items_bound": [],
        "test_refs": [],
        "surface_summary": {},
        "replacement_levels_report": rel(LEVELS_REPORT),
        "callthrough_census_report": rel(CALLTHROUGH_REPORT),
        "residual_callthrough_report": rel(RESIDUAL_REPORT),
        "artifact_refs": report["artifact_refs"],
        "failure_signature": failure_signature,
        "errors": messages,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, [event])
    raise SystemExit(f"FAIL[{failure_signature}]: " + "; ".join(messages[:6]))


def run_gate(command: list[str], env: dict[str, str] | None = None) -> None:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, **(env or {})},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        err(
            "gate command failed: "
            + " ".join(command)
            + f"\nstdout:\n{completed.stdout[-4000:]}\nstderr:\n{completed.stderr[-4000:]}"
        )


def validate_support_surface(expected: dict[str, Any]) -> dict[str, Any]:
    support = load_json(ROOT / "support_matrix.json", "support_matrix")
    statuses = Counter(str(row.get("status")) for row in support.get("symbols", []) if isinstance(row, dict))
    for status, expected_count in expected.get("support_status_counts", {}).items():
        if statuses.get(status, 0) != expected_count:
            err(f"support_matrix status count mismatch for {status}: expected {expected_count}, actual {statuses.get(status, 0)}")
    applicability = support.get("taxonomy", {}).get("artifact_applicability", {})
    rule = applicability.get("rule", "")
    if "Interpose-only" not in rule or "Implemented+RawSyscall" not in rule:
        err("support_matrix artifact_applicability.rule must preserve Interpose-only host-backed statuses")
    return {"status_counts": dict(statuses), "artifact_applicability_rule": rule}


def validate_replacement_levels(expected: dict[str, Any]) -> dict[str, Any]:
    levels = load_json(ROOT / "tests/conformance/replacement_levels.json", "replacement_levels")
    current = levels.get("current_level")
    release_current = levels.get("release_tag_policy", {}).get("current_release_level")
    if current != expected.get("current_level"):
        err(f"replacement_levels.current_level must be {expected.get('current_level')}, got {current}")
    if release_current != expected.get("current_release_level"):
        err(
            "replacement_levels.release_tag_policy.current_release_level must be "
            f"{expected.get('current_release_level')}, got {release_current}"
        )
    expected_levels = ["L0", "L1", "L2", "L3"]
    actual_levels = [entry.get("level") for entry in levels.get("levels", [])]
    if actual_levels != expected_levels:
        err(f"replacement_levels must define {expected_levels}, got {actual_levels}")
    report = load_json(LEVELS_REPORT, "replacement levels gate report")
    if report.get("status") != "pass":
        err("replacement levels gate report status must be pass")
    if report.get("current_level") != expected.get("current_level"):
        err(f"replacement levels gate report must preserve current_level {expected.get('current_level')}")
    objective_outcomes = report.get("summary", {}).get("objective_outcomes", {})
    blocked = int(objective_outcomes.get("blocked", 0) or 0)
    claim_control = expected.get("replacement_level_claim_control", {})
    expected_gate_status = claim_control.get("l1_objective_gate_status")
    if expected_gate_status:
        actual_gate_status = "blocked" if blocked > 0 else "pass"
        if actual_gate_status != expected_gate_status:
            err(f"replacement levels L1 objective gate status must be {expected_gate_status}, got {actual_gate_status}")
    min_blocked = int(claim_control.get("l1_blocked_objective_count_min", 0))
    if blocked < min_blocked:
        err(f"replacement levels gate must preserve at least {min_blocked} blocked L1 objectives")
    return {
        "current_level": current,
        "current_release_level": release_current,
        "objective_outcomes": objective_outcomes,
        "l1_crt_proof_row_count": report.get("summary", {}).get("l1_crt_proof_row_count"),
    }


def validate_callthrough(expected: dict[str, Any]) -> dict[str, Any]:
    census = load_json(ROOT / "tests/conformance/callthrough_census.v1.json", "callthrough census")
    report = load_json(CALLTHROUGH_REPORT, "callthrough census report")
    source = census.get("source", {})
    summary = census.get("summary", {})
    report_summary = report.get("summary", {})
    checks = report.get("checks", {})
    if source.get("derived_callthrough_symbols") != expected.get("callthrough_census", {}).get("derived_callthrough_symbols"):
        err("callthrough census derived_callthrough_symbols must remain zero")
    for field in ["module_count", "symbol_count", "wave_count"]:
        expected_count = expected.get("callthrough_census", {}).get(field)
        if summary.get(field) != expected_count:
            err(f"callthrough census summary.{field} must be {expected_count}, got {summary.get(field)}")
        if report_summary.get(field) != expected_count:
            err(f"callthrough report summary.{field} must be {expected_count}, got {report_summary.get(field)}")
    if any(value != "pass" for value in checks.values()):
        err(f"callthrough census report checks must all pass: {checks}")
    return {"source": source, "summary": summary, "report_summary": report_summary}


def validate_residual(expected: dict[str, Any]) -> dict[str, Any]:
    report = load_json(RESIDUAL_REPORT, "residual replacement callthrough report")
    summary = report.get("summary", {})
    residual_expected = expected.get("residual_replacement_callthrough_blockers", {})
    for field in ["residual_forbidden_count", "replacement_total_call_throughs", "interpose_total_call_throughs"]:
        if summary.get(field) != residual_expected.get(field):
            err(f"residual report summary.{field} must be {residual_expected.get(field)}, got {summary.get(field)}")
    if summary.get("claim_status") != residual_expected.get("claim_status"):
        err("residual report claim_status must remain replacement_callthrough_blockers_cleared")
    if report.get("outcome") != "pass":
        err("residual replacement callthrough report outcome must be pass")
    checks = report.get("checks", {})
    if any(value != "pass" for value in checks.values()):
        err(f"residual replacement callthrough checks must all pass: {checks}")
    return {"summary": summary, "checks": checks}


source_commit = git_head()
manifest = load_json(CONTRACT, "completion contract")
if errors:
    fail_report(source_commit, "contract_json_invalid", errors)

if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if manifest.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")
validate_source_artifacts(manifest.get("source_artifacts"))

evidence = manifest.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
if evidence.get("bead") != COMPLETION_BEAD:
    err(f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
if evidence.get("original_bead") != ORIGINAL_BEAD:
    err(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
for index, file_line in enumerate(string_list(evidence.get("implementation_refs"), "completion_debt_evidence.implementation_refs")):
    validate_file_line_ref(file_line, f"completion_debt_evidence.implementation_refs[{index}]")

texts = source_texts(evidence.get("test_sources"))
missing_items_bound: list[str] = []
test_refs: list[dict[str, str]] = []
for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
    section = evidence.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    missing_items_bound.append(missing_item)
    test_refs.extend(validate_test_refs(section, section_name, texts))
    validate_required_commands(section, section_name)

telemetry = evidence.get("telemetry")
if not isinstance(telemetry, dict):
    err("completion_debt_evidence.telemetry must be an object")
    telemetry = {}
required_events = set(string_list(telemetry.get("required_events"), "completion_debt_evidence.telemetry.required_events"))
required_fields = set(string_list(telemetry.get("required_fields"), "completion_debt_evidence.telemetry.required_fields"))
if not EXPECTED_REQUIRED_EVENTS.issubset(required_events):
    err(f"telemetry.required_events must include {sorted(EXPECTED_REQUIRED_EVENTS - required_events)}")
if not EXPECTED_REQUIRED_FIELDS.issubset(required_fields):
    err(f"telemetry.required_fields must include {sorted(EXPECTED_REQUIRED_FIELDS - required_fields)}")

if errors:
    fail_report(source_commit, "contract_validation_failed", errors)

run_gate(["bash", "scripts/check_callthrough_census.sh"])
run_gate(["bash", "scripts/check_residual_replacement_callthrough_blockers.sh", "--validate-only"])
run_gate(
    ["bash", "scripts/check_replacement_levels.sh"],
    {
        "FLC_REPLACEMENT_LEVELS_REPORT_PATH": str(LEVELS_REPORT),
        "FLC_REPLACEMENT_LEVELS_LOG_PATH": str(LEVELS_LOG),
    },
)
if errors:
    fail_report(source_commit, "source_gate_replay_failed", errors)

surface_expected = evidence.get("required_surface_truth", {})
support_summary = validate_support_surface(surface_expected)
replacement_summary = validate_replacement_levels(surface_expected)
callthrough_summary = validate_callthrough(surface_expected)
residual_summary = validate_residual(surface_expected)
if errors:
    fail_report(source_commit, "surface_truth_validation_failed", errors)

levels_rows = load_jsonl(LEVELS_LOG, "replacement levels log")
callthrough_rows = load_jsonl(CALLTHROUGH_LOG, "callthrough census log")
residual_rows = load_jsonl(RESIDUAL_LOG, "residual replacement callthrough log")
if not levels_rows:
    err("replacement levels log must contain rows")
if not callthrough_rows:
    err("callthrough census log must contain rows")
if not residual_rows:
    err("residual replacement callthrough log must contain rows")
if errors:
    fail_report(source_commit, "source_log_validation_failed", errors)

surface_summary = {
    "support": support_summary,
    "replacement_levels": replacement_summary,
    "callthrough_census": callthrough_summary,
    "residual_callthrough": residual_summary,
}
artifact_refs = [
    rel(CONTRACT),
    rel(REPORT),
    rel(LOG),
    rel(LEVELS_REPORT),
    rel(LEVELS_LOG),
    rel(CALLTHROUGH_REPORT),
    rel(CALLTHROUGH_LOG),
    rel(RESIDUAL_REPORT),
    rel(RESIDUAL_LOG),
    "support_matrix.json",
    "tests/conformance/replacement_levels.json",
    "tests/conformance/callthrough_census.v1.json",
    "tests/conformance/residual_replacement_callthrough_blockers.v1.json",
]

report = {
    "schema_version": "replacement_surface_completion_contract.report.v1",
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": "pass",
    "source_commit": source_commit,
    "missing_items_bound": missing_items_bound,
    "test_refs": test_refs,
    "surface_summary": surface_summary,
    "replacement_levels_report": rel(LEVELS_REPORT),
    "callthrough_census_report": rel(CALLTHROUGH_REPORT),
    "residual_callthrough_report": rel(RESIDUAL_REPORT),
    "artifact_refs": artifact_refs,
    "failure_signature": None,
}
write_json(REPORT, report)

events: list[dict[str, Any]] = []
for event_name in PASS_EVENTS:
    events.append(
        {
            "timestamp": now_utc(),
            "trace_id": f"{COMPLETION_BEAD}::replacement_surface_completion::{event_name}",
            "event": event_name,
            "level": "info",
            "bead_id": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "status": "pass",
            "source_commit": source_commit,
            "missing_items_bound": missing_items_bound,
            "test_refs": test_refs,
            "surface_summary": surface_summary,
            "replacement_levels_report": rel(LEVELS_REPORT),
            "callthrough_census_report": rel(CALLTHROUGH_REPORT),
            "residual_callthrough_report": rel(RESIDUAL_REPORT),
            "artifact_refs": artifact_refs,
            "failure_signature": None,
        }
    )
write_jsonl(LOG, events)
print(
    "PASS: replacement surface completion contract validated "
    f"current_level={replacement_summary['current_level']} "
    f"callthrough_symbols={callthrough_summary['summary']['symbol_count']} "
    f"residual={residual_summary['summary']['residual_forbidden_count']}"
)
PY
