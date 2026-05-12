#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_CONTRACT:-$ROOT/tests/conformance/api_support_docs_generation_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_REPORT:-$OUT_DIR/api_support_docs_generation_completion_contract.report.json}"
LOG="${FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_LOG:-$OUT_DIR/api_support_docs_generation_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
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

EXPECTED_SCHEMA = "api_support_docs_generation_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "api_support_docs_generation_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-3rw.4"
COMPLETION_BEAD = "bd-3rw.4.1"
REQUIRED_BINDINGS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = [
    "api_support_docs_generation_summary",
    "api_support_docs_generation_source_bindings",
    "api_support_docs_generation_unit_binding",
    "api_support_docs_generation_e2e_binding",
    "api_support_docs_generation_fuzz_binding",
    "api_support_docs_generation_conformance_binding",
    "api_support_docs_generation_telemetry_binding",
    "api_support_docs_generation_completion_contract_pass",
]
FAIL_EVENT = "api_support_docs_generation_completion_contract_fail"
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


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


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


def support_counts(support: dict[str, Any]) -> dict[str, int] | None:
    symbols = support.get("symbols")
    total_exported = support.get("total_exported")
    if not isinstance(symbols, list) or not isinstance(total_exported, int):
        err("support_matrix must contain symbols[] and total_exported")
        return None
    if len(symbols) != total_exported:
        err("support_matrix total_exported differs from symbols[] length")
        return None
    counts = {
        "implemented": 0,
        "raw_syscall": 0,
        "wraps_host_libc": 0,
        "glibc_call_through": 0,
        "stub": 0,
    }
    status_to_key = {
        "Implemented": "implemented",
        "RawSyscall": "raw_syscall",
        "WrapsHostLibc": "wraps_host_libc",
        "GlibcCallThrough": "glibc_call_through",
        "Stub": "stub",
    }
    for index, symbol in enumerate(symbols):
        if not isinstance(symbol, dict):
            err(f"support_matrix.symbols[{index}] must be an object")
            continue
        status = symbol.get("status")
        name = symbol.get("symbol", f"#{index}")
        if status not in status_to_key:
            err(f"unknown support status {status!r} for symbol {name!r}")
            continue
        counts[status_to_key[status]] += 1
    return counts


def function_exists(source: str, name: str) -> bool:
    return f"fn {name}" in source or f"def {name}" in source


def validate_required_commands(binding: dict[str, Any]) -> None:
    for command in string_list(binding.get("required_commands"), f"{binding.get('id')}.required_commands"):
        if "cargo " in command and "rch exec --" not in command:
            err(f"{binding.get('id')} required command must route cargo through rch: {command}")


def validate_test_refs(binding: dict[str, Any], test_sources: dict[str, str]) -> list[str]:
    refs = binding.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"{binding.get('id')}.required_test_refs must be non-empty")
        return []
    names: list[str] = []
    for index, ref_value in enumerate(refs):
        if not isinstance(ref_value, dict):
            err(f"{binding.get('id')}.required_test_refs[{index}] must be an object")
            continue
        source = ref_value.get("source")
        name = ref_value.get("name")
        if not isinstance(source, str) or not isinstance(name, str):
            err(f"{binding.get('id')}.required_test_refs[{index}] must name source and test")
            continue
        source_text = test_sources.get(source)
        if source_text is None:
            err(f"{binding.get('id')} references unknown test source {source}")
        elif not function_exists(source_text, name):
            err(f"{binding.get('id')} references missing test {source}::{name}")
        names.append(f"{source}::{name}")
    return names


def write_outputs(
    manifest: dict[str, Any],
    status: str,
    events: list[str],
    summary: dict[str, Any],
    source_commit: str,
) -> None:
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "source_commit": source_commit,
        "summary": summary,
        "source_artifacts": manifest.get("source_artifacts", {}),
        "missing_item_bindings": manifest.get("missing_item_bindings", []),
        "test_refs": summary.get("test_refs", []),
        "events": events,
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    rows = []
    for event in events if status == "pass" else [FAIL_EVENT]:
        rows.append(
            {
                "timestamp": now_utc(),
                "event": event,
                "bead_id": COMPLETION_BEAD,
                "source_bead": ORIGINAL_BEAD,
                "completion_debt_bead": COMPLETION_BEAD,
                "status": status,
                "outcome": status,
                "source_commit": source_commit,
                "schema_version": EXPECTED_REPORT_SCHEMA,
                "artifact_refs": sorted(str(value) for value in manifest.get("source_artifacts", {}).values())
                if isinstance(manifest.get("source_artifacts"), dict)
                else [],
                "test_refs": summary.get("test_refs", []),
                "failure_signature": "none" if status == "pass" else "api_support_docs_generation_contract_failed",
            }
        )
    LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


manifest = load_json(CONTRACT, "contract")
source_commit = git_head()

require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}

source_text_by_id: dict[str, str] = {}
for source_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{source_id} must be a non-empty string")
        continue
    path = ROOT / path_text
    if not path.is_file():
        err(f"source artifact {source_id} missing: {path_text}")
        continue
    source_text_by_id[source_id] = path.read_text(encoding="utf-8")

support = load_json(ROOT / str(source_artifacts.get("support_matrix", "")), "support_matrix")
reality = load_json(ROOT / str(source_artifacts.get("reality_report", "")), "reality_report")
actual_counts = support_counts(support)
expected_snapshot = manifest.get("expected_reality_snapshot", {})
if not isinstance(expected_snapshot, dict):
    err("expected_reality_snapshot must be an object")
    expected_snapshot = {}
if actual_counts is not None:
    require(actual_counts == expected_snapshot.get("counts"), "support_matrix counts differ from expected_reality_snapshot")
require(reality.get("generated_at_utc") == expected_snapshot.get("generated_at_utc"), "reality_report generated_at_utc drifted")
require(reality.get("total_exported") == expected_snapshot.get("total_exported"), "reality_report total_exported drifted")
require(reality.get("counts") == expected_snapshot.get("counts"), "reality_report counts drifted")

doc_contract = manifest.get("doc_generation_contract", {})
if not isinstance(doc_contract, dict):
    err("doc_generation_contract must be an object")
    doc_contract = {}
for source_id, markers in (doc_contract.get("required_code_markers") or {}).items():
    text = source_text_by_id.get(str(source_id), "")
    for marker in string_list(markers, f"doc_generation_contract.required_code_markers.{source_id}"):
        if marker not in text:
            err(f"source artifact {source_id} missing marker: {marker}")

for doc in doc_contract.get("docs", []) if isinstance(doc_contract.get("docs"), list) else []:
    if not isinstance(doc, dict):
        err("doc_generation_contract.docs entries must be objects")
        continue
    path_text = doc.get("path")
    if not isinstance(path_text, str):
        err("doc_generation_contract.docs[].path must be a string")
        continue
    text = (ROOT / path_text).read_text(encoding="utf-8") if (ROOT / path_text).is_file() else ""
    if not text:
        err(f"doc_generation_contract.docs missing doc path: {path_text}")
        continue
    for needle in string_list(doc.get("required_text"), f"doc_generation_contract.docs.{doc.get('id')}.required_text"):
        if needle not in text:
            err(f"missing required docs text in {path_text}: {needle}")

test_sources: dict[str, str] = {}
declared_test_sources = manifest.get("test_sources", {})
if not isinstance(declared_test_sources, dict) or not declared_test_sources:
    err("test_sources must be a non-empty object")
else:
    for source_id, path_text in declared_test_sources.items():
        if not isinstance(path_text, str):
            err(f"test_sources.{source_id} must be a string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            err(f"test source {source_id} missing: {path_text}")
        else:
            test_sources[str(source_id)] = path.read_text(encoding="utf-8")

bindings = manifest.get("missing_item_bindings")
if not isinstance(bindings, list) or not bindings:
    err("missing_item_bindings must be a non-empty array")
    bindings = []
binding_ids = {binding.get("id") for binding in bindings if isinstance(binding, dict)}
require(binding_ids == REQUIRED_BINDINGS, f"missing_item_bindings must be exactly {sorted(REQUIRED_BINDINGS)}")

test_refs: list[str] = []
for binding in bindings:
    if not isinstance(binding, dict):
        err("missing_item_bindings entries must be objects")
        continue
    validate_required_commands(binding)
    test_refs.extend(validate_test_refs(binding, test_sources))

telemetry_contract = manifest.get("telemetry_contract", {})
if not isinstance(telemetry_contract, dict):
    err("telemetry_contract must be an object")
    telemetry_contract = {}
required_event_set = set(string_list(telemetry_contract.get("required_events"), "telemetry_contract.required_events"))
missing_events = sorted(set(REQUIRED_EVENTS + [FAIL_EVENT]) - required_event_set)
if missing_events:
    err(f"telemetry_contract.required_events missing {missing_events}")

summary = {
    "total_exported": expected_snapshot.get("total_exported"),
    "implemented": expected_snapshot.get("counts", {}).get("implemented") if isinstance(expected_snapshot.get("counts"), dict) else None,
    "raw_syscall": expected_snapshot.get("counts", {}).get("raw_syscall") if isinstance(expected_snapshot.get("counts"), dict) else None,
    "docs_checked": len(doc_contract.get("docs", [])) if isinstance(doc_contract.get("docs"), list) else 0,
    "bindings_checked": len(bindings),
    "test_refs": sorted(set(test_refs)),
}

if errors:
    write_outputs(manifest, "fail", [FAIL_EVENT], summary, source_commit)
    for message in errors:
        print(f"FAIL: {message}", file=os.sys.stderr)
    raise SystemExit(1)

write_outputs(manifest, "pass", REQUIRED_EVENTS, summary, source_commit)
print(
    "PASS: api/support docs generation completion contract "
    f"bindings={summary['bindings_checked']} docs={summary['docs_checked']}"
)
PY
