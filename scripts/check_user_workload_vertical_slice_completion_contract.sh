#!/usr/bin/env bash
# check_user_workload_vertical_slice_completion_contract.sh - bd-bp8fl.10.6.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_VERTICAL_SLICE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/user_workload_vertical_slice_completion_contract.v1.json}"
SOURCE_MANIFEST="${FRANKENLIBC_VERTICAL_SLICE_COMPLETION_SOURCE_MANIFEST:-$ROOT/tests/conformance/user_workload_vertical_slice.v1.json}"
REPORT="${FRANKENLIBC_VERTICAL_SLICE_COMPLETION_REPORT:-$ROOT/target/conformance/user_workload_vertical_slice_completion_contract.report.json}"
LOG="${FRANKENLIBC_VERTICAL_SLICE_COMPLETION_LOG:-$ROOT/target/conformance/user_workload_vertical_slice_completion_contract.log.jsonl}"
SOURCE_REPORT="${FRANKENLIBC_VERTICAL_SLICE_COMPLETION_SOURCE_REPORT:-$ROOT/target/conformance/user_workload_vertical_slice_completion_contract.source.report.json}"
SOURCE_LOG="${FRANKENLIBC_VERTICAL_SLICE_COMPLETION_SOURCE_LOG:-$ROOT/target/conformance/user_workload_vertical_slice_completion_contract.source.log.jsonl}"
SOURCE_INDEX="${FRANKENLIBC_VERTICAL_SLICE_COMPLETION_SOURCE_INDEX:-$ROOT/target/conformance/user_workload_vertical_slice_completion_contract.source.artifact_index.json}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$SOURCE_REPORT")" "$(dirname "$SOURCE_LOG")" "$(dirname "$SOURCE_INDEX")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
SOURCE_MANIFEST="$SOURCE_MANIFEST" \
REPORT="$REPORT" \
LOG="$LOG" \
SOURCE_REPORT="$SOURCE_REPORT" \
SOURCE_LOG="$SOURCE_LOG" \
SOURCE_INDEX="$SOURCE_INDEX" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
SOURCE_MANIFEST = pathlib.Path(os.environ["SOURCE_MANIFEST"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
SOURCE_REPORT = pathlib.Path(os.environ["SOURCE_REPORT"])
SOURCE_LOG = pathlib.Path(os.environ["SOURCE_LOG"])
SOURCE_INDEX = pathlib.Path(os.environ["SOURCE_INDEX"])

COMPLETION_BEAD = "bd-bp8fl.10.6.1"
ORIGINAL_BEAD = "bd-bp8fl.10.6"
EXPECTED_SCHEMA = "user_workload_vertical_slice_completion_contract.v1"
EXPECTED_MANIFEST = "bd-bp8fl.10.6.1-user-workload-vertical-slice-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_PASS_EVENTS = {
    "user_workload_vertical_slice_completion_contract_validated",
    "user_workload_vertical_slice_replayed",
    "user_workload_vertical_slice_claim_blocker_preserved",
    "user_workload_vertical_slice_completion_summary",
}
EXPECTED_EVENTS = EXPECTED_PASS_EVENTS | {
    "user_workload_vertical_slice_completion_contract_failed",
}
EXPECTED_NEGATIVE_IDS = {
    "missing_selected_workload",
    "stale_source_commit",
    "contradictory_claim",
    "missing_smoke_case",
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
    "vertical_slice_summary",
    "vertical_slice_report",
    "vertical_slice_log",
    "vertical_slice_index",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []


def err(message: str) -> None:
    errors.append(message)


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


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


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
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


def validate_repo_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative: {path_text}")
        return None
    full = ROOT / path
    if not full.exists():
        err(f"{context} references missing path: {path_text}")
        return None
    return full


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


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


def source_texts(test_sources: Any) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return texts
    for key, path_text in test_sources.items():
        path = validate_repo_path(path_text, f"test_sources.{key}")
        if path is not None:
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
        source_text = texts.get(source, "")
        if not source_text:
            err(f"completion_debt_evidence.{section_name} references unknown source {source}")
        elif not function_exists(source_text, name):
            err(f"completion_debt_evidence.{section_name} references missing test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


def validate_required_commands(section: dict[str, Any], section_name: str) -> None:
    commands = as_string_list(section.get("required_commands"), f"completion_debt_evidence.{section_name}.required_commands")
    for command in commands:
        if "cargo " in command and "rch exec --" not in command:
            err(f"completion_debt_evidence.{section_name}.required_commands must route cargo through rch: {command}")


def run_source_gate() -> None:
    env = os.environ.copy()
    env.update(
        {
            "USER_WORKLOAD_VERTICAL_SLICE_MANIFEST": str(SOURCE_MANIFEST),
            "USER_WORKLOAD_VERTICAL_SLICE_REPORT": str(SOURCE_REPORT),
            "USER_WORKLOAD_VERTICAL_SLICE_LOG": str(SOURCE_LOG),
            "USER_WORKLOAD_VERTICAL_SLICE_INDEX": str(SOURCE_INDEX),
        }
    )
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts/check_user_workload_vertical_slice.sh")],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        err(
            "source user workload vertical slice gate failed "
            f"exit={proc.returncode} stdout={proc.stdout[-2000:]} stderr={proc.stderr[-2000:]}"
        )


def event_payload(event: str, level: str, status: str, source_commit: str, test_refs: list[dict[str, str]], vertical_slice_summary: dict[str, Any]) -> dict[str, Any]:
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
        "missing_items_bound": sorted(EXPECTED_MISSING_ITEMS.values()),
        "test_refs": test_refs,
        "vertical_slice_summary": vertical_slice_summary,
        "vertical_slice_report": rel(SOURCE_REPORT),
        "vertical_slice_log": rel(SOURCE_LOG),
        "vertical_slice_index": rel(SOURCE_INDEX),
        "artifact_refs": [
            "tests/conformance/user_workload_vertical_slice_completion_contract.v1.json",
            "tests/conformance/user_workload_vertical_slice.v1.json",
            "scripts/check_user_workload_vertical_slice_completion_contract.sh",
            "scripts/check_user_workload_vertical_slice.sh",
        ],
        "failure_signature": None if status == "pass" else "user_workload_vertical_slice_completion_contract_failed",
    }


contract = load_json(CONTRACT, "completion contract")
source_manifest = load_json(SOURCE_MANIFEST, "source vertical slice manifest")
source_commit = git_head()

if contract.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if contract.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if contract.get("bead") != COMPLETION_BEAD or contract.get("original_bead") != ORIGINAL_BEAD:
    err("contract bead/original_bead binding is incorrect")

for key, path_text in contract.get("source_artifacts", {}).items():
    validate_repo_path(path_text, f"source_artifacts.{key}")

evidence = contract.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}

bindings = evidence.get("missing_item_bindings", [])
bound_items: dict[str, Any] = {}
if not isinstance(bindings, list) or not bindings:
    err("completion_debt_evidence.missing_item_bindings must be a non-empty array")
else:
    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing item binding must be an object")
            continue
        section = binding.get("evidence_section")
        item = binding.get("missing_item_id")
        if section not in EXPECTED_MISSING_ITEMS:
            err(f"unexpected missing item evidence section: {section}")
            continue
        bound_items[section] = item
for section, expected in EXPECTED_MISSING_ITEMS.items():
    if bound_items.get(section) != expected:
        err(f"{section} must bind missing item {expected}")

for index, ref in enumerate(evidence.get("implementation_refs", [])):
    validate_file_line_ref(ref, f"implementation_refs[{index}]")

texts = source_texts(evidence.get("test_sources"))
all_test_refs: list[dict[str, str]] = []
for section_name in EXPECTED_MISSING_ITEMS:
    section = evidence.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != EXPECTED_MISSING_ITEMS[section_name]:
        err(f"completion_debt_evidence.{section_name}.missing_item_id is incorrect")
    all_test_refs.extend(validate_test_refs(section, section_name, texts))
    validate_required_commands(section, section_name)

slice_contract = evidence.get("required_vertical_slice_contract", {})
if not isinstance(slice_contract, dict):
    err("completion_debt_evidence.required_vertical_slice_contract must be an object")
    slice_contract = {}

if source_manifest.get("schema_version") != slice_contract.get("schema_version"):
    err("source manifest schema_version does not match completion contract")
if source_manifest.get("bead") != slice_contract.get("bead"):
    err("source manifest bead does not match completion contract")

selected = source_manifest.get("selected_workload", {})
if not isinstance(selected, dict):
    err("source manifest selected_workload must be an object")
    selected = {}
if selected.get("id") != slice_contract.get("selected_workload_id"):
    err("source selected_workload_id does not match completion contract")
if selected.get("source_artifact") != slice_contract.get("selected_workload_source"):
    err("selected workload source artifact does not match completion contract")

required_log_fields = as_string_list(slice_contract.get("required_log_fields"), "required_vertical_slice_contract.required_log_fields")
if source_manifest.get("required_log_fields") != required_log_fields:
    err("source vertical slice required_log_fields do not match completion contract")

required_path_kinds = set(as_string_list(slice_contract.get("required_path_kinds"), "required_vertical_slice_contract.required_path_kinds"))
replay_bindings = source_manifest.get("replay_bindings", [])
if not isinstance(replay_bindings, list):
    err("source manifest replay_bindings must be an array")
    replay_bindings = []
if len(replay_bindings) < int(slice_contract.get("minimum_replay_binding_count", 0)):
    err("source manifest replay_binding_count below completion threshold")
path_kinds = {binding.get("path_kind") for binding in replay_bindings if isinstance(binding, dict)}
if not required_path_kinds.issubset(path_kinds):
    err("source manifest missing required direct/isolated replay path kinds")

required_runtime_modes = set(as_string_list(slice_contract.get("required_runtime_modes"), "required_vertical_slice_contract.required_runtime_modes"))
if set(selected.get("expected_runtime_modes", [])) != required_runtime_modes:
    err("source selected workload runtime modes do not match completion contract")
required_replacement_levels = set(as_string_list(slice_contract.get("required_replacement_levels"), "required_vertical_slice_contract.required_replacement_levels"))
if set(selected.get("expected_replacement_levels", [])) != required_replacement_levels:
    err("source selected workload replacement levels do not preserve L0-L3 ambition")

fixture_count = len(source_manifest.get("fixture_evidence", [])) if isinstance(source_manifest.get("fixture_evidence"), list) else 0
if fixture_count < int(slice_contract.get("minimum_fixture_gate_count", 0)):
    err("source manifest fixture_gate_count below completion threshold")
claim_gate_count = len(source_manifest.get("claim_gates", [])) if isinstance(source_manifest.get("claim_gates"), list) else 0
if claim_gate_count < int(slice_contract.get("minimum_claim_gate_count", 0)):
    err("source manifest claim_gate_count below completion threshold")

required_negative_ids = set(as_string_list(slice_contract.get("required_negative_test_ids"), "required_vertical_slice_contract.required_negative_test_ids"))
if required_negative_ids != EXPECTED_NEGATIVE_IDS:
    err("required_vertical_slice_contract.required_negative_test_ids must include exactly the expected fail-closed cases")
negative_tests = source_manifest.get("negative_tests", [])
negative_ids = {case.get("id") for case in negative_tests if isinstance(case, dict)}
if len(negative_tests) < int(slice_contract.get("minimum_negative_test_count", 0)):
    err("source manifest negative_test_count below completion threshold")
missing_negative_ids = sorted(required_negative_ids - negative_ids)
if missing_negative_ids:
    err("source manifest missing required negative tests: " + ", ".join(missing_negative_ids))

expected_decision = source_manifest.get("expected_current_decision", {})
claim_policy = slice_contract.get("claim_policy_must_block", {})
if not isinstance(expected_decision, dict):
    err("source manifest expected_current_decision must be an object")
    expected_decision = {}
if not isinstance(claim_policy, dict):
    err("required_vertical_slice_contract.claim_policy_must_block must be an object")
    claim_policy = {}
for key in ["status", "support_claimed", "failure_signature"]:
    if expected_decision.get(key) != claim_policy.get(key):
        err(f"expected_current_decision.{key} must remain {claim_policy.get(key)!r}")
if expected_decision.get("status") == "claim_blocked" and expected_decision.get("support_claimed") is True:
    err("expected_current_decision cannot claim support while claim_blocked")
benchmark = source_manifest.get("benchmark_policy", {})
if claim_policy.get("benchmark_policy_must_not_infer_performance") and benchmark.get("hot_path_required") is not False:
    err("benchmark_policy must not infer performance proof from the smoke-only vertical slice")

artifact_index_spec = source_manifest.get("artifact_index", {})
required_artifact_kinds = set(as_string_list(slice_contract.get("required_artifact_index_kinds"), "required_vertical_slice_contract.required_artifact_index_kinds"))
declared_artifact_kinds = set(artifact_index_spec.get("must_include_kinds", [])) if isinstance(artifact_index_spec, dict) else set()
if required_artifact_kinds != declared_artifact_kinds:
    err("source artifact_index must declare the required artifact kinds")

run_source_gate()
source_report = load_json(SOURCE_REPORT, "source vertical slice report")
source_log_rows = load_jsonl(SOURCE_LOG, "source vertical slice log")
source_index = load_json(SOURCE_INDEX, "source vertical slice artifact index")
if source_report.get("status") != "pass":
    err("source vertical slice report must pass")
if source_report.get("selected_workload_id") != slice_contract.get("selected_workload_id"):
    err("source report selected_workload_id does not match completion contract")
if source_report.get("replay_binding_count", 0) < slice_contract.get("minimum_replay_binding_count", 0):
    err("source report replay_binding_count below threshold")
if source_report.get("fixture_gate_count", 0) < slice_contract.get("minimum_fixture_gate_count", 0):
    err("source report fixture_gate_count below threshold")
if source_report.get("claim_gate_count", 0) < slice_contract.get("minimum_claim_gate_count", 0):
    err("source report claim_gate_count below threshold")
if source_report.get("negative_test_count", 0) < slice_contract.get("minimum_negative_test_count", 0):
    err("source report negative_test_count below threshold")
if source_report.get("expected_current_decision", {}).get("status") != claim_policy.get("status"):
    err("source report must preserve claim_blocked decision")
if set(source_report.get("artifact_index_kinds", [])) != required_artifact_kinds:
    err("source report artifact_index_kinds do not match completion contract")
index_kinds = {row.get("kind") for row in source_index.get("artifacts", []) if isinstance(row, dict)}
if not required_artifact_kinds.issubset(index_kinds):
    err("source artifact index missing required artifact kinds")
if len(source_log_rows) != source_report.get("replay_binding_count"):
    err("source vertical slice log row count must match replay_binding_count")
for index, row in enumerate(source_log_rows, start=1):
    missing_fields = [field for field in required_log_fields if field not in row]
    if missing_fields:
        err(f"source vertical slice log row {index} missing fields: {', '.join(missing_fields)}")

telemetry = evidence.get("telemetry_primary", {})
declared_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
if declared_events != EXPECTED_EVENTS:
    err("telemetry_primary.required_events must include exactly the expected pass and fail events")
declared_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
if declared_fields != EXPECTED_TELEMETRY_FIELDS:
    err("telemetry_primary.required_fields must match the completion log schema")

vertical_slice_summary = {
    "selected_workload_id": source_report.get("selected_workload_id"),
    "selected_smoke_workload_ids": source_report.get("selected_smoke_workload_ids"),
    "replay_binding_count": source_report.get("replay_binding_count"),
    "fixture_gate_count": source_report.get("fixture_gate_count"),
    "claim_gate_count": source_report.get("claim_gate_count"),
    "negative_test_count": source_report.get("negative_test_count"),
    "artifact_index_kinds": source_report.get("artifact_index_kinds"),
    "expected_current_decision": source_report.get("expected_current_decision"),
}

status = "pass" if not errors else "fail"
event_names = (
    sorted(EXPECTED_PASS_EVENTS)
    if status == "pass"
    else ["user_workload_vertical_slice_completion_contract_failed"]
)
events = [
    event_payload(
        event=name,
        level="info" if status == "pass" else "error",
        status=status,
        source_commit=source_commit,
        test_refs=all_test_refs,
        vertical_slice_summary=vertical_slice_summary,
    )
    for name in event_names
]

report = {
    "schema_version": EXPECTED_SCHEMA,
    "bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "source_commit": source_commit,
    "missing_items_bound": sorted(EXPECTED_MISSING_ITEMS.values()),
    "vertical_slice_summary": vertical_slice_summary,
    "source_report": rel(SOURCE_REPORT),
    "source_log": rel(SOURCE_LOG),
    "source_index": rel(SOURCE_INDEX),
    "completion_report": rel(REPORT),
    "completion_log": rel(LOG),
    "telemetry_events": [event["event"] for event in events],
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
