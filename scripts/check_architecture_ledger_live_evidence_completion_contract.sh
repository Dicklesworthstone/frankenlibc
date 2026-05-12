#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_ARCH_LEDGER_COMPLETION_CONTRACT:-$ROOT/tests/conformance/architecture_ledger_live_evidence_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_ARCH_LEDGER_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_ARCH_LEDGER_COMPLETION_REPORT:-$OUT_DIR/architecture_ledger_live_evidence_completion_contract.report.json}"
LOG="${FRANKENLIBC_ARCH_LEDGER_COMPLETION_LOG:-$OUT_DIR/architecture_ledger_live_evidence_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "architecture_ledger_live_evidence_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "architecture_ledger_live_evidence_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-0agsk"
COMPLETION_BEAD = "bd-0agsk.19"
EXPECTED_MISSING_ITEMS = {
    "tests.golden.primary",
    "tests.conformance.primary",
    "migrations.primary",
    "theater.todo_wording.primary",
}
PASS_EVENTS = [
    ("architecture_ledger_live_evidence_summary", "summary"),
    ("architecture_ledger_live_evidence_golden_validated", "tests.golden.primary"),
    ("architecture_ledger_live_evidence_conformance_validated", "tests.conformance.primary"),
    ("architecture_ledger_live_evidence_migration_validated", "migrations.primary"),
    ("architecture_ledger_live_evidence_theater_validated", "theater.todo_wording.primary"),
    ("architecture_ledger_live_evidence_contract_pass", "summary"),
]
FAIL_EVENT = "architecture_ledger_live_evidence_contract_fail"

errors: list[str] = []


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def workspace_path(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay under workspace root: {path_text}")
    return ROOT / path


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


def require_set(value: Any, expected: set[str], context: str) -> set[str]:
    actual = set(as_string_list(value, context))
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        err(f"{context} missing {','.join(missing)}")
    if extra:
        err(f"{context} has unexpected {','.join(extra)}")
    return actual


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def read_text(path_text: str, label: str) -> str:
    try:
        return workspace_path(path_text).read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} unreadable: {path_text}: {exc}")
        return ""


def issue_rows(path_text: str) -> dict[str, dict[str, Any]]:
    path = workspace_path(path_text)
    rows: dict[str, dict[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"issues jsonl unreadable: {rel(path)}: {exc}")
        return rows
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            err(f"issues jsonl invalid at line {line_no}: {exc}")
            continue
        if isinstance(row, dict) and isinstance(row.get("id"), str):
            rows[row["id"]] = row
    return rows


def check_test_ref(test_sources: dict[str, str], source_id: str, name: str) -> None:
    path_text = test_sources.get(source_id)
    if not path_text:
        err(f"unknown test source: {source_id}")
        return
    text = read_text(path_text, f"test source {source_id}")
    require(f"fn {name}" in text, f"test source {source_id} missing fn {name}")


def check_required_commands(section: dict[str, Any], context: str) -> None:
    for command in as_string_list(section.get("required_commands", []), f"{context}.required_commands", allow_empty=True):
        if "cargo " in command:
            require(
                command.startswith("rch exec -- env CARGO_TARGET_DIR="),
                f"{context} cargo command must be rch-scoped: {command}",
            )


def check_artifact_list(paths: list[str], context: str) -> None:
    for path_text in paths:
        try:
            path = workspace_path(path_text)
        except ValueError as exc:
            err(str(exc))
            continue
        require(path.exists(), f"{context} artifact missing: {path_text}")


manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}
for source_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{source_id} must be a non-empty string")
        continue
    try:
        require(workspace_path(path_text).exists(), f"source artifact {source_id} missing: {path_text}")
    except ValueError as exc:
        err(str(exc))

required_parent = manifest.get("required_parent_closeout", {})
if not isinstance(required_parent, dict):
    err("required_parent_closeout must be an object")
    required_parent = {}
required_children = as_string_list(required_parent.get("required_child_beads"), "required_parent_closeout.required_child_beads")
require(len(required_children) == 18, "required_parent_closeout must list 18 child beads")
issues_path = source_artifacts.get("issues_jsonl", ".beads/issues.jsonl")
issues = issue_rows(str(issues_path))
parent = issues.get(ORIGINAL_BEAD, {})
close_reason = str(parent.get("close_reason") or required_parent.get("parent_close_reason_quote", ""))
require(bool(close_reason), "required_parent_closeout.parent_close_reason_quote must be present")
for token in as_string_list(required_parent.get("close_reason_required_tokens"), "required_parent_closeout.close_reason_required_tokens"):
    require(token in close_reason, f"bd-0agsk close_reason missing token {token!r}")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
require_set(evidence.get("missing_items"), EXPECTED_MISSING_ITEMS, "completion_debt_evidence.missing_items")

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict) or not test_sources:
    err("completion_debt_evidence.test_sources must be a non-empty object")
    test_sources = {}
test_source_paths: dict[str, str] = {}
for source_id, value in test_sources.items():
    if not isinstance(value, str) or not value:
        err(f"test_sources.{source_id} must be a non-empty string")
        continue
    test_source_paths[source_id] = value
    check_artifact_list([value], f"test_sources.{source_id}")

for ref in evidence.get("implementation_refs", []):
    if not isinstance(ref, dict):
        err("implementation_refs entries must be objects")
        continue
    path_text = ref.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"implementation ref {ref.get('id')} missing path")
        continue
    text = read_text(path_text, str(ref.get("id", "implementation_ref")))
    for needle in as_string_list(ref.get("required_text"), f"implementation_refs.{ref.get('id')}.required_text"):
        require(needle in text, f"implementation ref {ref.get('id')} missing {needle!r} in {path_text}")

child_artifacts = evidence.get("child_evidence_artifacts", [])
if not isinstance(child_artifacts, list) or not child_artifacts:
    err("child_evidence_artifacts must be a non-empty array")
    child_artifacts = []
covered_missing: set[str] = set()
for index, artifact in enumerate(child_artifacts):
    if not isinstance(artifact, dict):
        err(f"child_evidence_artifacts[{index}] must be an object")
        continue
    path_text = artifact.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"child_evidence_artifacts[{index}] missing path")
        continue
    check_artifact_list([path_text], f"child_evidence_artifacts.{artifact.get('id', index)}")
    data = load_json(workspace_path(path_text), f"child artifact {artifact.get('id', index)}")
    expected_schema = artifact.get("schema_version")
    if isinstance(expected_schema, str):
        require(data.get("schema_version") == expected_schema, f"{path_text} schema_version drifted")
    expected_generated_by = artifact.get("generated_by_bead")
    if isinstance(expected_generated_by, str):
        require(data.get("generated_by_bead") == expected_generated_by, f"{path_text} generated_by_bead drifted")
    for item in as_string_list(artifact.get("covers"), f"child_evidence_artifacts.{artifact.get('id', index)}.covers"):
        covered_missing.add(item)
require(EXPECTED_MISSING_ITEMS <= covered_missing, "child artifacts do not cover every missing item")

for section_name in ["golden_primary", "conformance_primary", "migrations_primary"]:
    section = evidence.get(section_name, {})
    if not isinstance(section, dict):
        err(f"{section_name} must be an object")
        section = {}
    required_artifacts = as_string_list(section.get("required_artifacts"), f"{section_name}.required_artifacts")
    check_artifact_list(required_artifacts, section_name)
    for test_ref in section.get("required_test_refs", []):
        if not isinstance(test_ref, dict):
            err(f"{section_name}.required_test_refs entries must be objects")
            continue
        check_test_ref(test_source_paths, str(test_ref.get("source", "")), str(test_ref.get("name", "")))
    check_required_commands(section, section_name)

golden = evidence.get("golden_primary", {}) if isinstance(evidence.get("golden_primary"), dict) else {}
golden_artifacts = set(as_string_list(golden.get("required_artifacts"), "golden_primary.required_artifacts"))
for required in [
    "tests/conformance/golden/sha256sums.txt",
    "tests/conformance/golden/fixture_verify_strict_hardened.v1.md",
    "tests/conformance/golden/fixture_verify_strict_hardened.v1.json",
    "tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json",
]:
    require(required in golden_artifacts, f"golden_primary missing required golden artifact {required}")

conformance = evidence.get("conformance_primary", {}) if isinstance(evidence.get("conformance_primary"), dict) else {}
min_child_artifacts = int(conformance.get("minimum_child_artifacts", 0))
require(len(child_artifacts) >= min_child_artifacts, "child evidence artifact count below conformance minimum")

migration_report_path = source_artifacts.get("architecture_migration_state")
if isinstance(migration_report_path, str):
    migration_report = load_json(workspace_path(migration_report_path), "architecture_migration_state")
    branch_policy = migration_report.get("branch_reference_policy", {})
    claim_summary = migration_report.get("claim_summary", {})
    require(isinstance(branch_policy, dict) and branch_policy.get("default_branch") == "main", "migration report default branch must be main")
    require(isinstance(branch_policy, dict) and branch_policy.get("legacy_branch_aliases_allowed") is False, "migration report must forbid legacy branch aliases")
    require(isinstance(claim_summary, dict) and claim_summary.get("replacement_claim") == "not_promoted", "migration report must keep replacement_claim not_promoted")

theater = evidence.get("theater_resolution", {})
if not isinstance(theater, dict):
    err("theater_resolution must be an object")
    theater = {}
require(theater.get("resolution_policy") == required_parent.get("resolution_policy"), "theater resolution policy drifted")
policy_text = str(theater.get("resolution_policy", "")).lower()
require("not by the theater words themselves" in policy_text, "theater policy must reject wording-as-proof")
for forbidden in as_string_list(theater.get("forbidden_completion_claims"), "theater_resolution.forbidden_completion_claims"):
    require(forbidden in {"wip_is_done", "draft_is_done", "todo_word_is_completion", "report_only_promotes_replacement_level"}, f"unexpected theater forbidden claim {forbidden}")
quote_blob = close_reason + "\n" + json.dumps(manifest, sort_keys=True)
for token in as_string_list(theater.get("required_source_quote_tokens"), "theater_resolution.required_source_quote_tokens"):
    require(token in quote_blob, f"theater source quote token missing: {token}")
for test_ref in theater.get("required_test_refs", []):
    if not isinstance(test_ref, dict):
        err("theater_resolution.required_test_refs entries must be objects")
        continue
    check_test_ref(test_source_paths, str(test_ref.get("source", "")), str(test_ref.get("name", "")))

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}
required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
require({event for event, _ in PASS_EVENTS}.issubset(required_events), "telemetry contract missing pass events")
require(FAIL_EVENT in required_events, "telemetry contract missing fail event")

events: list[str] = []
log_rows: list[dict[str, Any]] = []
commit = source_commit()
artifact_refs = sorted(
    {
        str(path)
        for path in source_artifacts.values()
        if isinstance(path, str)
    }
)

if errors:
    events = [FAIL_EVENT]
    log_rows.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "trace_id": manifest.get("trace_id", ""),
            "event": FAIL_EVENT,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": "fail",
            "source_commit": commit,
            "missing_item_id": "summary",
            "child_bead_count": len(required_children),
            "child_artifact_count": len(child_artifacts),
            "artifact_refs": artifact_refs,
            "failure_signature": "architecture_ledger_live_evidence_validation_failed",
        }
    )
else:
    for event, missing_item_id in PASS_EVENTS:
        events.append(event)
        log_rows.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "trace_id": manifest.get("trace_id", ""),
                "event": event,
                "source_bead": ORIGINAL_BEAD,
                "completion_debt_bead": COMPLETION_BEAD,
                "status": "pass",
                "source_commit": commit,
                "missing_item_id": missing_item_id,
                "child_bead_count": len(required_children),
                "child_artifact_count": len(child_artifacts),
                "artifact_refs": artifact_refs,
                "failure_signature": "none",
            }
        )

summary = {
    "missing_item_count": len(EXPECTED_MISSING_ITEMS),
    "child_bead_count": len(required_children),
    "child_artifact_count": len(child_artifacts),
    "closed_child_count": len(required_children),
    "source_artifact_count": len(source_artifacts),
    "golden_artifact_count": len(golden_artifacts),
    "covered_missing_items": sorted(covered_missing),
}

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": "fail" if errors else "pass",
    "source_commit": commit,
    "summary": summary,
    "events": events,
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")

if errors:
    print(f"architecture_ledger_live_evidence_completion_contract: FAIL errors={len(errors)} report={rel(REPORT)}")
    for message in errors:
        print(f"- {message}")
    raise SystemExit(1)

print(
    "architecture_ledger_live_evidence_completion_contract: PASS "
    f"children={summary['child_bead_count']} artifacts={summary['child_artifact_count']} "
    f"goldens={summary['golden_artifact_count']} events={len(events)}"
)
PY
