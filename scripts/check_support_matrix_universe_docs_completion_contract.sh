#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SUPPORT_MATRIX_UNIVERSE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/support_matrix_universe_docs_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_SUPPORT_MATRIX_UNIVERSE_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_SUPPORT_MATRIX_UNIVERSE_COMPLETION_REPORT:-$OUT_DIR/support_matrix_universe_docs_completion_contract.report.json}"
LOG="${FRANKENLIBC_SUPPORT_MATRIX_UNIVERSE_COMPLETION_LOG:-$OUT_DIR/support_matrix_universe_docs_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "support_matrix_universe_docs_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "support_matrix_universe_docs_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-2vv.16"
COMPLETION_BEAD = "bd-2vv.16.1"
PASS_EVENT = "support_matrix_universe_completion_contract_pass"
FAIL_EVENT = "support_matrix_universe_completion_contract_fail"
STATUS_TO_COUNT_KEY = {
    "Implemented": "implemented",
    "RawSyscall": "raw_syscall",
    "WrapsHostLibc": "wraps_host_libc",
    "GlibcCallThrough": "glibc_call_through",
    "Stub": "stub",
}
REQUIRED_EVENTS = {
    "support_matrix_universe_completion_summary",
    "support_matrix_universe_source_bindings",
    "support_matrix_universe_conformance_bindings",
    PASS_EVENT,
    FAIL_EVENT,
}
REQUIRED_TEST_REFS = {
    "manifest_binds_symbol_universe_completion_evidence",
    "checker_validates_symbol_universe_docs_contract",
    "checker_emits_universe_report_and_jsonl_rows",
    "checker_rejects_symbol_universe_total_drift",
    "checker_rejects_legacy_snapshot_text",
    "checker_rejects_missing_completion_test_ref",
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


def read_text(path_text: str, label: str) -> str:
    try:
        return (ROOT / path_text).read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} is unreadable: {path_text}: {exc}")
        return ""


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


def require_set(value: Any, required: set[str], context: str) -> set[str]:
    actual = set(as_string_list(value, context))
    missing = sorted(required - actual)
    if missing:
        err(f"{context} missing {','.join(missing)}")
    return actual


def function_exists(source: str, name: str) -> bool:
    return f"fn {name}" in source


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def derive_symbol_status_counts(support: dict[str, Any]) -> dict[str, int]:
    counts = {status: 0 for status in STATUS_TO_COUNT_KEY}
    symbols = support.get("symbols", [])
    if not isinstance(symbols, list):
        err("support_matrix.symbols must be an array")
        return counts
    for index, symbol in enumerate(symbols):
        if not isinstance(symbol, dict):
            err(f"support_matrix.symbols[{index}] must be an object")
            continue
        status = symbol.get("status")
        if status not in counts:
            err(f"support_matrix.symbols[{index}] has unknown status {status!r}")
            continue
        counts[str(status)] += 1
    return counts


def count_key_snapshot(status_counts: dict[str, int]) -> dict[str, int]:
    return {count_key: int(status_counts.get(status, 0)) for status, count_key in STATUS_TO_COUNT_KEY.items()}


def reality_count_snapshot(reality: dict[str, Any]) -> dict[str, int]:
    counts = reality.get("counts", {})
    if not isinstance(counts, dict):
        err("reality_report.counts must be an object")
        counts = {}
    return {
        "implemented": int(counts.get("implemented", 0)),
        "raw_syscall": int(counts.get("raw_syscall", 0)),
        "wraps_host_libc": int(counts.get("wraps_host_libc", 0)),
        "glibc_call_through": int(counts.get("glibc_call_through", 0)),
        "stub": int(counts.get("stub", 0)),
    }


def support_summary_snapshot(support: dict[str, Any]) -> dict[str, int]:
    summary = support.get("summary", {})
    if not isinstance(summary, dict):
        err("support_matrix.summary must be an object")
        summary = {}
    counts = support.get("counts", {})
    if not isinstance(counts, dict):
        counts = {}
    return {
        "implemented": int(summary.get("implemented", counts.get("implemented", 0))),
        "raw_syscall": int(summary.get("raw_syscall", counts.get("raw_syscall", 0))),
        "wraps_host_libc": int(summary.get("wraps_host_libc", counts.get("wraps_host_libc", 0))),
        "glibc_call_through": int(summary.get("glibc_call_through", counts.get("glibc_call_through", 0))),
        "stub": int(summary.get("stub", counts.get("stub", 0))),
    }


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
        "expected_symbol_universe": manifest.get("expected_symbol_universe", {}),
        "universe_join_requirements": manifest.get("universe_join_requirements", {}),
        "test_refs": sorted(summary.get("test_refs", [])),
        "events": events,
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    rows = []
    event_rows = events if status == "pass" else [FAIL_EVENT]
    for event in event_rows:
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
                "test_refs": sorted(summary.get("test_refs", [])),
                "failure_signature": "none" if status == "pass" else "support_matrix_universe_contract_failed",
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
for source_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{source_id} must be a non-empty string")
        continue
    require((ROOT / path_text).exists(), f"source artifact {source_id} missing: {path_text}")

support_matrix = load_json(ROOT / str(source_artifacts.get("support_matrix", "")), "support_matrix")
reality_report = load_json(ROOT / str(source_artifacts.get("reality_report", "")), "reality_report")
expected_universe = manifest.get("expected_symbol_universe", {})
if not isinstance(expected_universe, dict):
    err("expected_symbol_universe must be an object")
    expected_universe = {}
expected_status_counts = expected_universe.get("status_counts", {})
if not isinstance(expected_status_counts, dict):
    err("expected_symbol_universe.status_counts must be an object")
    expected_status_counts = {}

derived_status_counts = derive_symbol_status_counts(support_matrix)
derived_count_keys = count_key_snapshot(derived_status_counts)
expected_count_keys = count_key_snapshot({key: int(value) for key, value in expected_status_counts.items()})
require(derived_status_counts == {key: int(expected_status_counts.get(key, 0)) for key in STATUS_TO_COUNT_KEY}, "derived support_matrix symbols[] counts differ from expected_symbol_universe")
require(int(expected_universe.get("total_symbols", -1)) == sum(derived_status_counts.values()), "expected total_symbols differs from derived symbols[] length")
require(int(support_matrix.get("total_exported", -2)) == sum(derived_status_counts.values()), "support_matrix total_exported differs from derived symbols[] length")
require(len(support_matrix.get("symbols", [])) == sum(derived_status_counts.values()), "support_matrix symbols length differs from derived status total")
require(support_matrix.get("generated_at_utc") == expected_universe.get("generated_at_utc"), "support_matrix generated_at_utc differs from expected")
require(support_summary_snapshot(support_matrix) == derived_count_keys, "support_matrix summary/counts differ from derived symbols[] counts")

require(int(reality_report.get("total_exported", -3)) == sum(derived_status_counts.values()), "reality_report total_exported differs from derived symbols[] length")
require(reality_report.get("generated_at_utc") == expected_universe.get("generated_at_utc"), "reality_report generated_at_utc differs from expected")
require(reality_count_snapshot(reality_report) == derived_count_keys, "reality_report counts differ from derived symbols[] counts")
require(expected_count_keys == derived_count_keys, "expected count-key snapshot differs from derived symbols[] counts")

join_requirements = manifest.get("universe_join_requirements", {})
if not isinstance(join_requirements, dict):
    err("universe_join_requirements must be an object")
    join_requirements = {}
require(
    join_requirements.get("derived_counts_source") == "support_matrix.json:symbols[].status",
    "derived_counts_source must be support_matrix.json:symbols[].status",
)
require_set(
    join_requirements.get("must_match"),
    {
        "support_matrix.total_exported",
        "support_matrix.summary",
        "support_matrix.counts",
        "tests/conformance/reality_report.v1.json.total_exported",
        "tests/conformance/reality_report.v1.json.counts",
        "README.md reality snapshot",
        "FEATURE_PARITY.md current reality",
    },
    "universe_join_requirements.must_match",
)

legacy_needles = as_string_list(expected_universe.get("legacy_snapshots_forbidden"), "expected_symbol_universe.legacy_snapshots_forbidden")
docs = join_requirements.get("docs", [])
if not isinstance(docs, list) or not docs:
    err("universe_join_requirements.docs must be a non-empty array")
    docs = []
for index, doc in enumerate(docs):
    if not isinstance(doc, dict):
        err(f"universe_join_requirements.docs[{index}] must be an object")
        continue
    path_text = doc.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"universe_join_requirements.docs[{index}].path must be a non-empty string")
        continue
    text = read_text(path_text, str(doc.get("id", path_text)))
    for needle in as_string_list(doc.get("required_text"), f"universe_join_requirements.docs[{index}].required_text"):
        require(needle in text, f"{path_text} missing required universe text {needle!r}")
    for forbidden in legacy_needles:
        require(forbidden not in text, f"{path_text} still contains legacy snapshot {forbidden!r}")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
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

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict) or not test_sources:
    err("completion_debt_evidence.test_sources must be a non-empty object")
    test_sources = {}
test_refs: list[str] = []
for source_id, spec in test_sources.items():
    if not isinstance(spec, dict):
        err(f"test source {source_id} must be an object")
        continue
    path_text = spec.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"test source {source_id} missing path")
        continue
    source = read_text(path_text, source_id)
    refs = as_string_list(spec.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs")
    for name in refs:
        test_refs.append(name)
        require(function_exists(source, name), f"test source {path_text} missing function {name}")
require_set(test_refs, REQUIRED_TEST_REFS, "completion test refs")

bindings = manifest.get("missing_item_bindings", [])
if not isinstance(bindings, list) or not bindings:
    err("missing_item_bindings must be a non-empty array")
    bindings = []
binding = next((row for row in bindings if isinstance(row, dict) and row.get("id") == "tests.conformance.primary"), None)
if binding is None:
    err("missing_item_bindings must include tests.conformance.primary")
else:
    require(binding.get("kind") == "conformance", "tests.conformance.primary binding kind must be conformance")
    for path_text in as_string_list(binding.get("required_artifacts"), "tests.conformance.primary.required_artifacts"):
        require((ROOT / path_text).exists(), f"tests.conformance.primary artifact missing: {path_text}")
    require_set(binding.get("required_test_refs"), REQUIRED_TEST_REFS, "tests.conformance.primary.required_test_refs")

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}
require_set(telemetry.get("required_events"), REQUIRED_EVENTS, "telemetry_contract.required_events")

events = [
    "support_matrix_universe_completion_summary",
    "support_matrix_universe_source_bindings",
    "support_matrix_universe_conformance_bindings",
    PASS_EVENT,
]
summary = {
    "generated_at_utc": expected_universe.get("generated_at_utc"),
    "total_symbols": sum(derived_status_counts.values()),
    "status_counts": derived_status_counts,
    "docs_checked": len(docs),
    "test_refs": sorted(set(test_refs)),
}

if errors:
    write_outputs(manifest, "fail", [FAIL_EVENT], summary, source_commit)
    raise SystemExit("FAIL[support_matrix_universe_contract_failed]: " + "; ".join(errors))

write_outputs(manifest, "pass", events, summary, source_commit)
print(
    "PASS: support_matrix universe docs completion contract "
    f"symbols={summary['total_symbols']} implemented={derived_status_counts['Implemented']} "
    f"raw_syscall={derived_status_counts['RawSyscall']}"
)
PY
