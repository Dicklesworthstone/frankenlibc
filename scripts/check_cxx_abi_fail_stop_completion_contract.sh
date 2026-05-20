#!/usr/bin/env bash
# check_cxx_abi_fail_stop_completion_contract.sh - bd-cxafv.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_CXX_ABI_FAIL_STOP_COMPLETION_CONTRACT:-$ROOT/tests/conformance/cxx_abi_fail_stop_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_CXX_ABI_FAIL_STOP_COMPLETION_REPORT:-$ROOT/target/conformance/cxx_abi_fail_stop_completion_contract.report.json}"
LOG="${FRANKENLIBC_CXX_ABI_FAIL_STOP_COMPLETION_LOG:-$ROOT/target/conformance/cxx_abi_fail_stop_completion_contract.log.jsonl}"

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
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

SCHEMA = "cxx_abi_fail_stop_completion_contract.v1"
MANIFEST_ID = "bd-cxafv.1-cxx-abi-fail-stop-completion-contract"
ORIGINAL_BEAD = "bd-cxafv"
COMPLETION_BEAD = "bd-cxafv.1"
MISSING_ITEM = "tests.conformance.primary"
VALIDATED_EVENT = "cxx_abi_fail_stop_completion_contract_validated"
INVARIANT_EVENT = "cxx_abi_fail_stop_source_invariant"
FAILED_EVENT = "cxx_abi_fail_stop_completion_contract_failed"
COVERED_SYMBOLS = ["__cxa_pure_virtual", "__cxa_deleted_virtual"]
TRACKED_UNBOUND_SYMBOLS = [
    "__cxa_throw_bad_array_new_length",
    "__cxa_call_unexpected",
]

errors: list[str] = []
events: list[dict[str, Any]] = []


def now_ms() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z"


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


SOURCE_COMMIT = git_head()


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def emit(event: str, status: str, **fields: Any) -> None:
    row = {
        "timestamp": now_ms(),
        "trace_id": f"{COMPLETION_BEAD}::{event}",
        "event": event,
        "level": "info" if status == "pass" else "error",
        "bead_id": COMPLETION_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "status": status,
        "source_commit": SOURCE_COMMIT,
        "missing_item": MISSING_ITEM,
        "source_invariant_id": fields.pop("source_invariant_id", ""),
        "artifact_refs": fields.pop("artifact_refs", []),
        "failure_signature": fields.pop("failure_signature", ""),
    }
    row.update(fields)
    events.append(row)


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


def path_from_artifact(source_artifacts: dict[str, Any], key: str) -> pathlib.Path | None:
    value = source_artifacts.get(key)
    if not isinstance(value, str) or not value:
        err(f"source_artifacts.{key} must be a non-empty string")
        return None
    path = ROOT / value
    if not path.is_file():
        err(f"source_artifacts.{key} references missing file: {value}")
        return None
    return path


def text_for_source(
    source_artifacts: dict[str, Any],
    source_cache: dict[str, str],
    source_key: str,
) -> str:
    if source_key in source_cache:
        return source_cache[source_key]
    path = path_from_artifact(source_artifacts, source_key)
    if path is None:
        return ""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"source_artifacts.{source_key} is not readable: {exc}")
        return ""
    source_cache[source_key] = text
    return text


def string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
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


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


manifest = load_json(CONTRACT, "completion contract")
source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}

if manifest.get("schema_version") != SCHEMA:
    err("schema_version mismatch")
if manifest.get("manifest_id") != MANIFEST_ID:
    err("manifest_id mismatch")
if manifest.get("bead") != ORIGINAL_BEAD:
    err("bead mismatch")
if manifest.get("completion_debt_bead") != COMPLETION_BEAD:
    err("completion_debt_bead mismatch")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
if evidence.get("bead") != COMPLETION_BEAD:
    err("completion_debt_evidence.bead mismatch")
if evidence.get("original_bead") != ORIGINAL_BEAD:
    err("completion_debt_evidence.original_bead mismatch")
if evidence.get("covered_symbols") != COVERED_SYMBOLS:
    err("completion_debt_evidence.covered_symbols must bind pure/deleted virtual hooks only")
if evidence.get("tracked_but_not_completion_bound_symbols") != TRACKED_UNBOUND_SYMBOLS:
    err("completion_debt_evidence.tracked_but_not_completion_bound_symbols mismatch")

for index, ref in enumerate(evidence.get("implementation_refs", [])):
    validate_file_line_ref(ref, f"completion_debt_evidence.implementation_refs[{index}]")

source_cache: dict[str, str] = {}
for key in [
    "implementation",
    "unistd_abi_tests",
    "completion_gate",
    "completion_harness",
    "semantic_inventory",
    "semantic_symbol_join",
]:
    text_for_source(source_artifacts, source_cache, key)

invariants = evidence.get("required_source_invariants", [])
if not isinstance(invariants, list) or not invariants:
    err("completion_debt_evidence.required_source_invariants must be non-empty")
else:
    seen_invariants: set[str] = set()
    for index, invariant in enumerate(invariants):
        if not isinstance(invariant, dict):
            err(f"required_source_invariants[{index}] must be an object")
            continue
        invariant_id = invariant.get("id")
        source_key = invariant.get("source")
        if not isinstance(invariant_id, str) or not invariant_id:
            err(f"required_source_invariants[{index}].id must be a non-empty string")
            continue
        if invariant_id in seen_invariants:
            err(f"duplicate invariant id: {invariant_id}")
        seen_invariants.add(invariant_id)
        if not isinstance(source_key, str) or not source_key:
            err(f"required_source_invariants[{index}].source must be a non-empty string")
            continue
        source_text = text_for_source(source_artifacts, source_cache, source_key)
        missing = [
            needle
            for needle in string_list(
                invariant.get("must_contain"),
                f"required_source_invariants[{index}].must_contain",
            )
            if needle not in source_text
        ]
        forbidden = [
            needle
            for needle in string_list(
                invariant.get("must_not_contain"),
                f"required_source_invariants[{index}].must_not_contain",
                allow_empty=True,
            )
            if needle in source_text
        ]
        if missing:
            err(f"invariant {invariant_id} missing required source text: {missing}")
        if forbidden:
            err(f"invariant {invariant_id} contains forbidden source text: {forbidden}")
        emit(
            INVARIANT_EVENT,
            "fail" if missing or forbidden else "pass",
            source_invariant_id=invariant_id,
            source=source_key,
            missing_needles=missing,
            forbidden_needles=forbidden,
            artifact_refs=[rel(path_from_artifact(source_artifacts, source_key) or "")],
            failure_signature=(
                f"{invariant_id}_source_invariant_failed" if missing or forbidden else ""
            ),
        )

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict) or not test_sources:
    err("completion_debt_evidence.test_sources must be a non-empty object")
    test_sources = {}

source_texts: dict[str, str] = {}
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
    source_texts[key] = path.read_text(encoding="utf-8")

conformance = evidence.get("conformance_primary", {})
if not isinstance(conformance, dict):
    err("completion_debt_evidence.conformance_primary must be an object")
    conformance = {}
if conformance.get("missing_item_id") != MISSING_ITEM:
    err("conformance_primary.missing_item_id mismatch")
if conformance.get("next_audit_score_threshold", 0) < 800:
    err("conformance_primary.next_audit_score_threshold must be at least 800")

for index, ref in enumerate(conformance.get("required_test_refs", [])):
    if not isinstance(ref, dict):
        err(f"conformance_primary.required_test_refs[{index}] must be an object")
        continue
    source = ref.get("source")
    name = ref.get("name")
    if not isinstance(source, str) or not source:
        err(f"conformance_primary.required_test_refs[{index}].source must be non-empty")
        continue
    if not isinstance(name, str) or not name:
        err(f"conformance_primary.required_test_refs[{index}].name must be non-empty")
        continue
    text = source_texts.get(source, "")
    if not text:
        err(f"conformance_primary.required_test_refs[{index}] references unknown source {source}")
    elif not function_exists(text, name):
        err(f"conformance_primary.required_test_refs[{index}] references missing test {source}::{name}")

for command in string_list(
    conformance.get("required_commands"),
    "conformance_primary.required_commands",
):
    if "cargo " in command:
        if "rch exec --" not in command:
            err(f"cargo command must be routed through rch: {command}")
        if "RCH_REQUIRE_REMOTE=1" not in command:
            err(f"cargo command must require remote execution: {command}")
        if "CARGO_TARGET_DIR=" not in command:
            err(f"cargo command must set CARGO_TARGET_DIR: {command}")

for marker in string_list(
    conformance.get("forbidden_output_markers"),
    "conformance_primary.forbidden_output_markers",
):
    if not marker:
        err("forbidden output marker must be non-empty")

required_events = set(
    string_list(conformance.get("required_events"), "conformance_primary.required_events")
)
required_fields = set(
    string_list(conformance.get("required_fields"), "conformance_primary.required_fields")
)

emit(
    VALIDATED_EVENT if not errors else FAILED_EVENT,
    "pass" if not errors else "fail",
    artifact_refs=[
        rel(CONTRACT),
        rel(REPORT),
        rel(LOG),
        str(source_artifacts.get("implementation", "")),
        str(source_artifacts.get("unistd_abi_tests", "")),
        str(source_artifacts.get("completion_gate", "")),
        str(source_artifacts.get("completion_harness", "")),
    ],
    failure_signature="" if not errors else "cxx_abi_fail_stop_completion_contract_failed",
)

present_events = {row["event"] for row in events}
missing_events = sorted(event for event in required_events if event not in present_events)
if missing_events:
    errors.append(f"missing required telemetry events: {missing_events}")

for row_index, row in enumerate(events):
    missing_fields = sorted(field for field in required_fields if field not in row)
    if missing_fields:
        errors.append(f"telemetry row {row_index} missing fields: {missing_fields}")

report = {
    "schema_version": "cxx_abi_fail_stop_completion_contract.report.v1",
    "status": "fail" if errors else "pass",
    "bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "covered_symbols": COVERED_SYMBOLS,
    "tracked_but_not_completion_bound_symbols": TRACKED_UNBOUND_SYMBOLS,
    "source_commit": SOURCE_COMMIT,
    "contract": rel(CONTRACT),
    "missing_item": MISSING_ITEM,
    "events": [row["event"] for row in events],
    "source_invariants": [
        {
            "id": row.get("source_invariant_id"),
            "status": row.get("status"),
            "failure_signature": row.get("failure_signature"),
        }
        for row in events
        if row.get("event") == INVARIANT_EVENT
    ],
    "artifact_refs": [
        rel(CONTRACT),
        rel(REPORT),
        rel(LOG),
        str(source_artifacts.get("implementation", "")),
        str(source_artifacts.get("completion_gate", "")),
        str(source_artifacts.get("completion_harness", "")),
    ],
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in events),
    encoding="utf-8",
)

if errors:
    print("check_cxx_abi_fail_stop_completion_contract: FAIL", flush=True)
    for message in errors:
        print(f"FAIL: {message}", flush=True)
    raise SystemExit(1)

print("check_cxx_abi_fail_stop_completion_contract: PASS")
PY
