#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_REALITY_SNAPSHOT_DOCS_COMPLETION_CONTRACT:-$ROOT/tests/conformance/reality_snapshot_parity_docs_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_REALITY_SNAPSHOT_DOCS_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_REALITY_SNAPSHOT_DOCS_COMPLETION_REPORT:-$OUT_DIR/reality_snapshot_parity_docs_completion_contract.report.json}"
LOG="${FRANKENLIBC_REALITY_SNAPSHOT_DOCS_COMPLETION_LOG:-$OUT_DIR/reality_snapshot_parity_docs_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "reality_snapshot_parity_docs_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "reality_snapshot_parity_docs_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-2vv.13"
COMPLETION_BEAD = "bd-2vv.13.1"
PASS_EVENT = "docs_reality_snapshot_completion_contract_pass"
FAIL_EVENT = "docs_reality_snapshot_completion_contract_fail"
REQUIRED_EVENTS = {
    "docs_reality_snapshot_completion_summary",
    "docs_reality_snapshot_source_bindings",
    "docs_reality_snapshot_conformance_bindings",
    PASS_EVENT,
    FAIL_EVENT,
}
REQUIRED_TEST_REFS = {
    "manifest_binds_docs_reality_conformance_evidence",
    "checker_validates_docs_reality_snapshot_contract",
    "checker_emits_conformance_report_and_jsonl_rows",
    "checker_rejects_missing_readme_reality_source",
    "checker_rejects_reality_count_drift",
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


def reality_counts(reality: dict[str, Any]) -> dict[str, int]:
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


def support_counts(support: dict[str, Any]) -> dict[str, int]:
    summary = support.get("summary", {})
    if not isinstance(summary, dict):
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


def doc_dynamic_tokens(snapshot: dict[str, Any]) -> list[str]:
    counts = snapshot.get("counts", {})
    if not isinstance(counts, dict):
        counts = {}
    return [
        f"generated ` {snapshot.get('generated_at_utc')}`".replace("` ", "`"),
        f"total_exported={snapshot.get('total_exported')}",
        f"implemented={counts.get('implemented')}",
        f"raw_syscall={counts.get('raw_syscall')}",
        f"glibc_call_through={counts.get('glibc_call_through')}",
        f"stub={counts.get('stub')}",
    ]


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
        "expected_reality_snapshot": manifest.get("expected_reality_snapshot", {}),
        "doc_snapshot_requirements": manifest.get("doc_snapshot_requirements", {}),
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
                "failure_signature": "none" if status == "pass" else "reality_snapshot_docs_contract_failed",
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

expected_snapshot = manifest.get("expected_reality_snapshot", {})
if not isinstance(expected_snapshot, dict):
    err("expected_reality_snapshot must be an object")
    expected_snapshot = {}

reality_report = load_json(ROOT / str(source_artifacts.get("reality_report", "")), "reality_report")
support_matrix = load_json(ROOT / str(source_artifacts.get("support_matrix", "")), "support_matrix")
actual_snapshot = {
    "generated_at_utc": reality_report.get("generated_at_utc"),
    "total_exported": int(reality_report.get("total_exported", -1)),
    "counts": reality_counts(reality_report),
}
require(actual_snapshot == expected_snapshot, "expected_reality_snapshot differs from tests/conformance/reality_report.v1.json")

actual_support_counts = support_counts(support_matrix)
require(actual_support_counts == actual_snapshot["counts"], "support_matrix counts differ from reality_report counts")
require(
    int(support_matrix.get("total_exported", -2)) == actual_snapshot["total_exported"],
    "support_matrix total_exported differs from reality_report total_exported",
)
require(
    len(support_matrix.get("symbols", [])) == actual_snapshot["total_exported"],
    "support_matrix symbols length differs from total_exported",
)
require(
    support_matrix.get("generated_at_utc") == actual_snapshot["generated_at_utc"],
    "support_matrix generated_at_utc differs from reality_report",
)

doc_requirements = manifest.get("doc_snapshot_requirements", {})
if not isinstance(doc_requirements, dict):
    err("doc_snapshot_requirements must be an object")
    doc_requirements = {}
require(
    doc_requirements.get("reality_source") == source_artifacts.get("reality_report"),
    "doc_snapshot_requirements.reality_source must point at the reality report source artifact",
)
require(
    doc_requirements.get("support_source") == source_artifacts.get("support_matrix"),
    "doc_snapshot_requirements.support_source must point at the support matrix source artifact",
)
for command_fragment in as_string_list(
    doc_requirements.get("canonical_generation_command"),
    "doc_snapshot_requirements.canonical_generation_command",
):
    require(command_fragment in " ".join(command_fragment.split()), "canonical_generation_command contains an empty fragment")

dynamic_tokens = doc_dynamic_tokens(actual_snapshot)
docs = doc_requirements.get("docs", [])
if not isinstance(docs, list) or not docs:
    err("doc_snapshot_requirements.docs must be a non-empty array")
    docs = []
for index, doc in enumerate(docs):
    if not isinstance(doc, dict):
        err(f"doc_snapshot_requirements.docs[{index}] must be an object")
        continue
    path_text = doc.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"doc_snapshot_requirements.docs[{index}].path must be a non-empty string")
        continue
    text = read_text(path_text, str(doc.get("id", path_text)))
    for needle in as_string_list(doc.get("required_text"), f"doc_snapshot_requirements.docs[{index}].required_text"):
        require(needle in text, f"{path_text} missing required docs text {needle!r}")
    for token in dynamic_tokens:
        require(token in text, f"{path_text} missing dynamic reality token {token!r}")

for guardrail in as_string_list(doc_requirements.get("semantic_guardrails"), "doc_snapshot_requirements.semantic_guardrails"):
    require(len(guardrail.split()) >= 3, f"semantic guardrail is too vague: {guardrail!r}")

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
    require_set(binding.get("required_test_refs"), REQUIRED_TEST_REFS & set(test_refs), "tests.conformance.primary.required_test_refs")

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}
require_set(telemetry.get("required_events"), REQUIRED_EVENTS, "telemetry_contract.required_events")
for field in [
    "schema_version",
    "manifest_id",
    "source_bead",
    "completion_debt_bead",
    "status",
    "source_commit",
    "summary",
    "source_artifacts",
    "expected_reality_snapshot",
    "doc_snapshot_requirements",
    "test_refs",
    "events",
    "errors",
]:
    require(field in set(as_string_list(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields")), f"telemetry report field missing from contract: {field}")

events = [
    "docs_reality_snapshot_completion_summary",
    "docs_reality_snapshot_source_bindings",
    "docs_reality_snapshot_conformance_bindings",
    PASS_EVENT,
]
summary = {
    "generated_at_utc": actual_snapshot.get("generated_at_utc"),
    "total_exported": actual_snapshot.get("total_exported"),
    "implemented": actual_snapshot.get("counts", {}).get("implemented"),
    "raw_syscall": actual_snapshot.get("counts", {}).get("raw_syscall"),
    "wraps_host_libc": actual_snapshot.get("counts", {}).get("wraps_host_libc"),
    "glibc_call_through": actual_snapshot.get("counts", {}).get("glibc_call_through"),
    "stub": actual_snapshot.get("counts", {}).get("stub"),
    "docs_checked": len(docs),
    "test_refs": sorted(set(test_refs)),
}

if errors:
    write_outputs(manifest, "fail", [FAIL_EVENT], summary, source_commit)
    raise SystemExit("FAIL[reality_snapshot_docs_contract_failed]: " + "; ".join(errors))

write_outputs(manifest, "pass", events, summary, source_commit)
print(
    "PASS: reality snapshot docs completion contract "
    f"docs={len(docs)} total_exported={summary['total_exported']} "
    f"implemented={summary['implemented']} raw_syscall={summary['raw_syscall']}"
)
PY
