#!/usr/bin/env bash
# check_docs_support_taxonomy_completion_contract.sh - bd-vfl.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUT_DIR="$ROOT/target/conformance"
CONTRACT="${FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_COMPLETION_CONTRACT:-$ROOT/tests/conformance/docs_support_taxonomy_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_COMPLETION_REPORT:-$OUT_DIR/docs_support_taxonomy_completion_contract.report.json}"
LOG="${FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_COMPLETION_LOG:-$OUT_DIR/docs_support_taxonomy_completion_contract.log.jsonl}"
DOCS_REPORT="$OUT_DIR/docs_semantic_claims.report.json"
DOCS_LOG="$OUT_DIR/docs_semantic_claims.log.jsonl"
CLAIM_REPORT="${FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_CLAIM_REPORT:-$OUT_DIR/docs_support_taxonomy_completion.claim_reconciliation.report.json}"
LEVELS_REPORT="${FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_LEVELS_REPORT:-$OUT_DIR/docs_support_taxonomy_completion.replacement_levels.report.json}"
LEVELS_LOG="${FRANKENLIBC_DOCS_SUPPORT_TAXONOMY_LEVELS_LOG:-$OUT_DIR/docs_support_taxonomy_completion.replacement_levels.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" \
DOCS_REPORT="$DOCS_REPORT" DOCS_LOG="$DOCS_LOG" CLAIM_REPORT="$CLAIM_REPORT" \
LEVELS_REPORT="$LEVELS_REPORT" LEVELS_LOG="$LEVELS_LOG" \
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
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
DOCS_REPORT = pathlib.Path(os.environ["DOCS_REPORT"])
DOCS_LOG = pathlib.Path(os.environ["DOCS_LOG"])
CLAIM_REPORT = pathlib.Path(os.environ["CLAIM_REPORT"])
LEVELS_REPORT = pathlib.Path(os.environ["LEVELS_REPORT"])
LEVELS_LOG = pathlib.Path(os.environ["LEVELS_LOG"])

COMPLETION_BEAD = "bd-vfl.1"
ORIGINAL_BEAD = "bd-vfl"
EXPECTED_SCHEMA = "docs_support_taxonomy_completion_contract.v1"
EXPECTED_MANIFEST = "bd-vfl.1-docs-support-taxonomy-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}
PASS_EVENTS = [
    "docs_support_taxonomy_completion_contract_validated",
    "docs_support_taxonomy_summary",
    "docs_semantic_claims_gate_replayed",
    "claim_reconciliation_gate_replayed",
    "replacement_levels_gate_replayed",
]
EXPECTED_REQUIRED_EVENTS = set(PASS_EVENTS) | {"docs_support_taxonomy_completion_contract_failed"}
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
    "docs_summary",
    "docs_semantic_report",
    "claim_reconciliation_report",
    "replacement_levels_report",
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


def string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        err(f"{context} must be a non-empty array")
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
        if not isinstance(path_text, str) or not path_text:
            err(f"test_sources.{key} must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            err(f"test_sources.{key} references missing file: {path_text}")
            continue
        texts[str(key)] = path.read_text(encoding="utf-8")
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
        if not isinstance(source, str) or not source or not isinstance(name, str) or not name:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must name source and test")
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
    path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")


def fail_report(source_commit: str, failure_signature: str, messages: list[str]) -> None:
    report = {
        "schema_version": "docs_support_taxonomy_completion_contract.report.v1",
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
        "trace_id": f"{COMPLETION_BEAD}:docs-support-taxonomy:failed",
        "event": "docs_support_taxonomy_completion_contract_failed",
        "level": "error",
        "bead_id": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "status": "fail",
        "source_commit": source_commit,
        "missing_items_bound": [],
        "test_refs": [],
        "docs_summary": {},
        "docs_semantic_report": rel(DOCS_REPORT),
        "claim_reconciliation_report": rel(CLAIM_REPORT),
        "replacement_levels_report": rel(LEVELS_REPORT),
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


def validate_docs_truth(expected: dict[str, Any]) -> dict[str, Any]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    parity = (ROOT / "FEATURE_PARITY.md").read_text(encoding="utf-8")
    for phrase in expected.get("required_readme_phrases", []):
        if phrase not in readme:
            err(f"README.md missing required phrase: {phrase}")
    for phrase in expected.get("required_feature_parity_phrases", []):
        if phrase not in parity:
            err(f"FEATURE_PARITY.md missing required phrase: {phrase}")

    docs_report = load_json(DOCS_REPORT, "docs semantic claims report")
    docs_summary = docs_report.get("summary", {})
    if docs_report.get("status") != "pass":
        err("docs semantic claims report status must be pass")
    for field in [
        "required_claim_field_count",
        "semantic_parity_blocker_count",
        "taxonomy_semantic_conflict_count",
        "forbidden_claim_count",
    ]:
        if docs_summary.get(field) != expected.get(field):
            err(f"docs semantic summary.{field} expected {expected.get(field)}, got {docs_summary.get(field)}")
    if docs_report.get("forbidden_claims") not in ([], None):
        err("docs semantic report must not contain forbidden claims")

    claim_report = load_json(CLAIM_REPORT, "claim reconciliation report")
    claim_summary = claim_report.get("summary", {})
    if claim_report.get("status") != "pass":
        err("claim reconciliation report status must be pass")
    if claim_summary.get("errors") != expected.get("claim_reconciliation_errors"):
        err("claim reconciliation errors must remain zero")
    if claim_summary.get("warnings") != expected.get("claim_reconciliation_warnings"):
        err("claim reconciliation warnings must remain zero")

    levels_report = load_json(LEVELS_REPORT, "replacement levels report")
    levels = load_json(ROOT / "tests/conformance/replacement_levels.json", "replacement levels")
    expected_current = expected.get("current_level")
    expected_release = expected.get("current_release_level")
    actual_current = levels.get("current_level")
    actual_release = levels.get("release_tag_policy", {}).get("current_release_level")
    if actual_current != expected_current:
        err(f"replacement_levels.current_level expected {expected_current}, got {actual_current}")
    if actual_release != expected_release:
        err(
            "replacement_levels.release_tag_policy.current_release_level "
            f"expected {expected_release}, got {actual_release}"
        )
    if levels_report.get("status") != "pass" or levels_report.get("current_level") != expected_current:
        err(f"replacement levels gate report must pass and preserve current_level {expected_current}")

    return {
        "docs_semantic": docs_summary,
        "claim_reconciliation": claim_summary,
        "current_level": levels.get("current_level"),
        "current_release_level": levels.get("release_tag_policy", {}).get("current_release_level"),
    }


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

telemetry = evidence.get("telemetry_primary") if isinstance(evidence.get("telemetry_primary"), dict) else {}
required_events = set(string_list(telemetry.get("required_events"), "completion_debt_evidence.telemetry_primary.required_events"))
required_fields = set(string_list(telemetry.get("required_fields"), "completion_debt_evidence.telemetry_primary.required_fields"))
if not EXPECTED_REQUIRED_EVENTS.issubset(required_events):
    err(f"telemetry.required_events must include {sorted(EXPECTED_REQUIRED_EVENTS - required_events)}")
if not EXPECTED_REQUIRED_FIELDS.issubset(required_fields):
    err(f"telemetry.required_fields must include {sorted(EXPECTED_REQUIRED_FIELDS - required_fields)}")

if errors:
    fail_report(source_commit, "contract_validation_failed", errors)

run_gate(["bash", "scripts/check_docs_semantic_claims.sh"])
run_gate(["bash", "scripts/check_claim_reconciliation.sh", str(CLAIM_REPORT)])
run_gate(
    ["bash", "scripts/check_replacement_levels.sh"],
    {
        "FLC_REPLACEMENT_LEVELS_REPORT_PATH": str(LEVELS_REPORT),
        "FLC_REPLACEMENT_LEVELS_LOG_PATH": str(LEVELS_LOG),
    },
)
if errors:
    fail_report(source_commit, "source_gate_replay_failed", errors)

docs_summary = validate_docs_truth(evidence.get("required_docs_truth", {}))
if not load_jsonl(DOCS_LOG, "docs semantic claims log"):
    err("docs semantic claims log must contain rows")
if not load_jsonl(LEVELS_LOG, "replacement levels log"):
    err("replacement levels log must contain rows")
if errors:
    fail_report(source_commit, "docs_truth_validation_failed", errors)

artifact_refs = [
    rel(CONTRACT),
    rel(REPORT),
    rel(LOG),
    rel(DOCS_REPORT),
    rel(DOCS_LOG),
    rel(CLAIM_REPORT),
    rel(LEVELS_REPORT),
    rel(LEVELS_LOG),
    "README.md",
    "FEATURE_PARITY.md",
    "support_matrix.json",
    "tests/conformance/docs_semantic_claims.v1.json",
    "tests/conformance/replacement_claim_doc_audit.v1.json",
    "tests/conformance/claim_reconciliation_report.v1.json",
    "tests/conformance/replacement_levels.json",
]
report = {
    "schema_version": "docs_support_taxonomy_completion_contract.report.v1",
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": "pass",
    "source_commit": source_commit,
    "missing_items_bound": missing_items_bound,
    "test_refs": test_refs,
    "docs_summary": docs_summary,
    "docs_semantic_report": rel(DOCS_REPORT),
    "claim_reconciliation_report": rel(CLAIM_REPORT),
    "replacement_levels_report": rel(LEVELS_REPORT),
    "artifact_refs": artifact_refs,
    "failure_signature": None,
}
write_json(REPORT, report)

events = []
for event_name in PASS_EVENTS:
    events.append(
        {
            "timestamp": now_utc(),
            "trace_id": f"{COMPLETION_BEAD}:docs-support-taxonomy:{event_name}",
            "event": event_name,
            "level": "info",
            "bead_id": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "status": "pass",
            "source_commit": source_commit,
            "missing_items_bound": missing_items_bound,
            "test_refs": test_refs,
            "docs_summary": docs_summary,
            "docs_semantic_report": rel(DOCS_REPORT),
            "claim_reconciliation_report": rel(CLAIM_REPORT),
            "replacement_levels_report": rel(LEVELS_REPORT),
            "artifact_refs": artifact_refs,
            "failure_signature": None,
        }
    )
write_jsonl(LOG, events)
print(
    "PASS: docs support taxonomy completion contract validated "
    f"forbidden_claims={docs_summary['docs_semantic'].get('forbidden_claim_count')} "
    f"claim_errors={docs_summary['claim_reconciliation'].get('errors')} "
    f"current_level={docs_summary['current_level']}"
)
PY
