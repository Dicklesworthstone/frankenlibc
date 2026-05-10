#!/usr/bin/env bash
# Gate for bd-nrh5v.1 setstate overread conformance completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SETSTATE_CONTRACT:-$ROOT/tests/conformance/setstate_overread_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_SETSTATE_REPORT:-$ROOT/target/conformance/setstate_overread_completion_contract.report.json}"
LOG="${FRANKENLIBC_SETSTATE_LOG:-$ROOT/target/conformance/setstate_overread_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "setstate_overread_completion_contract.v1"
EXPECTED_MANIFEST = "bd-nrh5v.1-setstate-overread-conformance-contract"
COMPLETION_BEAD = "bd-nrh5v.1"
ORIGINAL_BEAD = "bd-nrh5v"
EXPECTED_MISSING_ITEMS = {"tests.conformance.primary"}
EXPECTED_SYMBOLS = {"initstate", "setstate", "random", "srandom"}
EXPECTED_TEST_REFS = {
    ("abi_regression", "initstate_setstate_roundtrip"),
    ("abi_regression", "setstate_rejects_tracked_too_short_state"),
    ("abi_regression", "setstate_accepts_untracked_minimum_state_without_overread"),
    ("conformance_diff", "stdlib_random_diff_coverage_report"),
}
EXPECTED_COMMANDS = {
    "cargo test -p frankenlibc-abi --test stdlib_abi_test setstate -- --nocapture --test-threads=1",
    "cargo test -p frankenlibc-abi --test conformance_diff_stdlib_random -- --nocapture --test-threads=1",
}
EXPECTED_REPORT_FIELDS = {
    "schema",
    "bead",
    "original_bead",
    "status",
    "source_commit",
    "missing_items_bound",
    "required_symbols",
    "required_scenarios",
    "required_test_refs",
    "implementation_refs",
    "artifact_refs",
    "failure_signature",
}
EXPECTED_EVENTS = {
    "setstate_overread_completion_contract_validated",
    "setstate_overread_completion_contract_failed",
}

errors: list[str] = []


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{rel(path)} is not valid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{rel(path)} must be a JSON object")
        return {}
    return value


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


def as_string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        err(f"{context} must be a non-empty array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


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
    line_no = int(line_text)
    if line_no > len(lines):
        err(f"{context} references line past EOF: {value}")
    elif not lines[line_no - 1].strip():
        err(f"{context} references a blank line: {value}")


def validate_test_refs(refs: Any, texts: dict[str, str]) -> list[dict[str, str]]:
    if not isinstance(refs, list) or not refs:
        err("completion_debt_evidence.conformance_primary.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not source:
            err(f"required_test_refs[{index}].source must be non-empty")
            continue
        if not isinstance(name, str) or not name:
            err(f"required_test_refs[{index}].name must be non-empty")
            continue
        key = (source, name)
        if key in seen:
            err(f"duplicate test ref {source}::{name}")
        seen.add(key)
        text = texts.get(source, "")
        if not text:
            err(f"test ref {source}::{name} uses undeclared source")
        elif f"fn {name}" not in text:
            err(f"test ref {source}::{name} is missing from source")
        normalized.append({"source": source, "name": name})
    missing = EXPECTED_TEST_REFS - seen
    if missing:
        err("required_test_refs missing expected refs: " + ", ".join(f"{s}::{n}" for s, n in sorted(missing)))
    return normalized


def validate() -> dict[str, Any]:
    manifest = load_json(CONTRACT)
    evidence = manifest.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        evidence = {}
    primary = evidence.get("conformance_primary")
    if not isinstance(primary, dict):
        err("completion_debt_evidence.conformance_primary must be an object")
        primary = {}

    if manifest.get("schema") != EXPECTED_SCHEMA:
        err("schema mismatch")
    if manifest.get("manifest_id") != EXPECTED_MANIFEST:
        err("manifest_id mismatch")
    if manifest.get("bead") != COMPLETION_BEAD or evidence.get("bead") != COMPLETION_BEAD:
        err("completion bead mismatch")
    if manifest.get("original_bead") != ORIGINAL_BEAD or evidence.get("original_bead") != ORIGINAL_BEAD:
        err("original bead mismatch")
    if primary.get("missing_item_id") != "tests.conformance.primary":
        err("conformance_primary missing_item_id mismatch")
    if int(evidence.get("next_audit_score_threshold", 0) or 0) < 800:
        err("next audit score threshold must be at least 800")
    if int(primary.get("next_audit_score_threshold", 0) or 0) < 800:
        err("conformance primary threshold must be at least 800")

    missing_items = set(as_string_list(evidence.get("missing_items"), "missing_items"))
    if missing_items != EXPECTED_MISSING_ITEMS:
        err(f"missing_items should be {sorted(EXPECTED_MISSING_ITEMS)}")

    texts = source_texts(evidence.get("test_sources"))
    required_symbols = set(as_string_list(primary.get("required_symbols"), "required_symbols"))
    if required_symbols != EXPECTED_SYMBOLS:
        err(f"required_symbols should be {sorted(EXPECTED_SYMBOLS)}")
    for symbol in EXPECTED_SYMBOLS:
        if not any(symbol in text for text in texts.values()):
            err(f"symbol {symbol} is not represented in declared test sources")

    scenarios = as_string_list(primary.get("required_scenarios"), "required_scenarios")
    for phrase in ["too-short", "untracked 8-byte", "differential coverage"]:
        if not any(phrase in scenario for scenario in scenarios):
            err(f"required_scenarios must mention {phrase}")

    test_refs = validate_test_refs(primary.get("required_test_refs"), texts)
    commands = set(as_string_list(primary.get("required_commands"), "required_commands"))
    if not EXPECTED_COMMANDS.issubset(commands):
        err("required_commands missing one or more expected validation commands")

    implementation_refs = as_string_list(evidence.get("implementation_refs"), "implementation_refs")
    if len(implementation_refs) < 10:
        err("implementation_refs should cite setstate helper, ABI path, core path, and tests")
    for index, ref in enumerate(implementation_refs):
        validate_file_line_ref(ref, f"implementation_refs[{index}]")

    report_fields = set(as_string_list(primary.get("required_report_fields"), "required_report_fields"))
    if not EXPECTED_REPORT_FIELDS.issubset(report_fields):
        err("required_report_fields missing expected fields")
    events = set(as_string_list(primary.get("required_events"), "required_events"))
    if events != EXPECTED_EVENTS:
        err(f"required_events should be {sorted(EXPECTED_EVENTS)}")

    artifacts = as_string_list(evidence.get("artifact_refs"), "artifact_refs")
    failure_signature = evidence.get("failure_signature")
    if failure_signature != "setstate_untracked_minimum_overread_or_missing_conformance_evidence":
        err("failure_signature mismatch")

    status = "fail" if errors else "pass"
    report: dict[str, Any] = {
        "schema": EXPECTED_SCHEMA,
        "bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "status": status,
        "source_commit": git_head(),
        "generated_at": timestamp(),
        "missing_items_bound": sorted(missing_items),
        "required_symbols": sorted(required_symbols),
        "required_scenarios": scenarios,
        "required_test_refs": test_refs,
        "required_commands": sorted(commands),
        "implementation_refs": implementation_refs,
        "artifact_refs": artifacts,
        "failure_signature": failure_signature,
        "errors": errors,
    }
    return report


report = validate()
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
event = {
    "timestamp": timestamp(),
    "event": "setstate_overread_completion_contract_validated"
    if report["status"] == "pass"
    else "setstate_overread_completion_contract_failed",
    "level": "info" if report["status"] == "pass" else "error",
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": report["status"],
    "source_commit": report["source_commit"],
    "missing_items_bound": report["missing_items_bound"],
    "required_symbols": report["required_symbols"],
    "required_test_refs": report["required_test_refs"],
    "artifact_refs": report["artifact_refs"],
    "failure_signature": report["failure_signature"],
    "errors": report["errors"],
}
with LOG.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(event, sort_keys=True) + "\n")

if errors:
    print(f"setstate overread completion contract failed: {len(errors)} error(s)", file=sys.stderr)
    for message in errors:
        print(f"- {message}", file=sys.stderr)
    sys.exit(1)

print(
    "setstate overread completion contract validated: "
    f"missing_items={len(report['missing_items_bound'])} "
    f"tests={len(report['required_test_refs'])} refs={len(report['implementation_refs'])}"
)
PY
