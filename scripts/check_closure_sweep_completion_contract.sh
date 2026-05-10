#!/usr/bin/env bash
# check_closure_sweep_completion_contract.sh - bd-w2c3.10.3.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_CLOSURE_SWEEP_COMPLETION_CONTRACT:-$ROOT/tests/conformance/closure_sweep_completion_contract.v1.json}"
CLOSURE_REPORT="${FRANKENLIBC_CLOSURE_SWEEP_REPORT:-$ROOT/tests/conformance/closure_sweep_report.v1.json}"
DOCS_SOURCE_MAP="${FRANKENLIBC_CLOSURE_SWEEP_DOCS_MAP:-$ROOT/tests/conformance/docs_source_of_truth_map.v1.json}"
DOCS_TRACE="${FRANKENLIBC_CLOSURE_SWEEP_DOCS_TRACE:-$ROOT/tests/conformance/docs_source_of_truth_trace.v1.jsonl}"
OUT_DIR="${FRANKENLIBC_CLOSURE_SWEEP_COMPLETION_OUT_DIR:-$ROOT/target/conformance/closure_sweep_completion_contract}"
REPORT="${FRANKENLIBC_CLOSURE_SWEEP_COMPLETION_REPORT:-$OUT_DIR/closure_sweep_completion_contract.report.json}"
LOG="${FRANKENLIBC_CLOSURE_SWEEP_COMPLETION_LOG:-$OUT_DIR/closure_sweep_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
CLOSURE_REPORT="$CLOSURE_REPORT" \
DOCS_SOURCE_MAP="$DOCS_SOURCE_MAP" \
DOCS_TRACE="$DOCS_TRACE" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
CLOSURE_REPORT = pathlib.Path(os.environ["CLOSURE_REPORT"])
DOCS_SOURCE_MAP = pathlib.Path(os.environ["DOCS_SOURCE_MAP"])
DOCS_TRACE = pathlib.Path(os.environ["DOCS_TRACE"])
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "closure_sweep_completion_contract.v1"
SOURCE_BEAD = "bd-w2c3.10.3"
COMPLETION_BEAD = "bd-w2c3.10.3.1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_EVENTS = {
    "closure_sweep_completion_contract_validated",
    "closure_sweep_report_validated",
    "docs_source_of_truth_validated",
    "docs_source_gate_replayed",
    "closure_sweep_completion_summary",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
source_gate_results: dict[str, Any] = {}


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


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
            err(f"{label} line {index} must be a JSON object")
            continue
        rows.append(row)
    return rows


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def repo_path(value: Any, context: str, *, must_be_file: bool = False) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(value)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative: {value}")
        return None
    full = ROOT / path
    if must_be_file and not full.is_file():
        err(f"{context} references missing file: {value}")
        return None
    if not must_be_file and not full.exists():
        err(f"{context} references missing path: {value}")
        return None
    return full


def text_for(path_text: str, context: str) -> str:
    path = repo_path(path_text, context, must_be_file=True)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        err(f"{context} is not UTF-8: {path_text}: {exc}")
        return ""


def string_list(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
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


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


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


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "source_bead": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "event": event,
            "status": status,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "closure_sweep_completion_failed",
            "details": details,
        }
    )


def validate_impl_ref(ref: Any, source_text_cache: dict[str, str]) -> str | None:
    if not isinstance(ref, dict):
        err(f"implementation_refs entry must be an object: {ref!r}")
        return None
    kind = ref.get("kind")
    path_text = ref.get("path")
    line = ref.get("line")
    anchor = ref.get("anchor")
    if not isinstance(kind, str) or not kind:
        err(f"implementation_refs entry missing kind: {ref!r}")
    if not isinstance(path_text, str):
        err(f"implementation_refs entry missing path: {ref!r}")
        return kind if isinstance(kind, str) else None
    text = source_text_cache.setdefault(path_text, text_for(path_text, f"implementation_refs.{kind}"))
    lines = text.splitlines()
    if not isinstance(line, int) or line <= 0:
        err(f"{path_text} ref line must be a positive integer")
    elif line > len(lines) or not lines[line - 1].strip():
        err(f"{path_text}:{line} does not point to a non-empty line")
    if not isinstance(anchor, str) or not anchor:
        err(f"{path_text}:{line} missing anchor")
    elif anchor not in text:
        err(f"{path_text} missing anchor {anchor!r}")
    return kind if isinstance(kind, str) else None


def validate_contract(manifest: dict[str, Any]) -> dict[str, str]:
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        err(f"schema_version must be {EXPECTED_SCHEMA}")
    if manifest.get("bead") != SOURCE_BEAD:
        err(f"bead must be {SOURCE_BEAD}")
    if manifest.get("completion_debt_bead") != COMPLETION_BEAD:
        err(f"completion_debt_bead must be {COMPLETION_BEAD}")

    audit = manifest.get("audit", {})
    if not isinstance(audit, dict):
        err("audit must be an object")
        audit = {}
    missing_items = set(string_list(audit.get("missing_items"), "audit.missing_items"))
    if missing_items != EXPECTED_MISSING_ITEMS:
        err(f"audit.missing_items mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing_items)}")

    raw_source_paths = manifest.get("source_paths")
    if not isinstance(raw_source_paths, dict) or not raw_source_paths:
        err("source_paths must be a non-empty object")
        source_paths: dict[str, str] = {}
    else:
        source_paths = {}
        for source, path_text in raw_source_paths.items():
            if isinstance(path_text, str):
                source_paths[str(source)] = path_text
            repo_path(path_text, f"source_paths.{source}")

    source_text_cache: dict[str, str] = {}
    impl_kinds = {
        kind
        for kind in (validate_impl_ref(ref, source_text_cache) for ref in manifest.get("implementation_refs", []))
        if kind
    }
    if len(impl_kinds) < 30:
        err(f"implementation_refs should cite at least 30 concrete anchors, got {len(impl_kinds)}")

    anchors = manifest.get("source_anchors")
    if not isinstance(anchors, dict) or not anchors:
        err("source_anchors must be a non-empty object")
    else:
        for source, expected_anchors in anchors.items():
            path_text = source_paths.get(str(source))
            if not path_text:
                err(f"source_anchors.{source} has no source_paths entry")
                continue
            text = source_text_cache.setdefault(path_text, text_for(path_text, f"source_anchors.{source}"))
            for anchor in string_list(expected_anchors, f"source_anchors.{source}"):
                if anchor not in text:
                    err(f"{path_text} missing source anchor {anchor!r}")

    coverage = manifest.get("completion_coverage")
    if not isinstance(coverage, list) or not coverage:
        err("completion_coverage must be a non-empty array")
    else:
        covered_items: set[str] = set()
        source_texts: dict[str, str] = {}
        for section in coverage:
            if not isinstance(section, dict):
                err("completion_coverage entries must be objects")
                continue
            item_id = section.get("missing_item_id")
            if isinstance(item_id, str):
                covered_items.add(item_id)
            else:
                err("completion_coverage entry missing missing_item_id")
                continue
            if section.get("status") != "covered":
                err(f"completion_coverage.{item_id}.status must be covered")
            if not string_list(section.get("implementation_refs"), f"completion_coverage.{item_id}.implementation_refs"):
                err(f"completion_coverage.{item_id} must cite implementation refs")
            test_refs = section.get("test_refs")
            if not isinstance(test_refs, list) or not test_refs:
                err(f"completion_coverage.{item_id}.test_refs must be non-empty")
            else:
                for index, test_ref in enumerate(test_refs):
                    if not isinstance(test_ref, dict):
                        err(f"completion_coverage.{item_id}.test_refs[{index}] must be an object")
                        continue
                    source = test_ref.get("source")
                    name = test_ref.get("name")
                    if not isinstance(source, str) or source not in source_paths:
                        err(f"completion_coverage.{item_id}.test_refs[{index}] unknown source {source!r}")
                        continue
                    if not isinstance(name, str) or not name:
                        err(f"completion_coverage.{item_id}.test_refs[{index}] missing name")
                        continue
                    text = source_texts.setdefault(source, text_for(source_paths[source], f"test_refs.{source}"))
                    if not function_exists(text, name):
                        err(f"{source_paths[source]} missing test/function {name}")
            commands = string_list(section.get("validation_commands"), f"completion_coverage.{item_id}.validation_commands")
            for command in commands:
                if "cargo " in command:
                    if "rch " not in command:
                        err(f"cargo validation command must use rch: {command}")
                    if "CARGO_TARGET_DIR=" not in command:
                        err(f"cargo validation command must use isolated target dir: {command}")

        if covered_items != EXPECTED_MISSING_ITEMS:
            err(f"completion_coverage items mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(covered_items)}")

    append_event(
        "closure_sweep_completion_contract_validated",
        "pass" if not errors else "fail",
        [rel(CONTRACT)],
        {"missing_items": sorted(EXPECTED_MISSING_ITEMS), "source_paths": sorted(source_paths)},
    )
    return source_paths


def require_fields(payload: dict[str, Any], fields: list[str], context: str) -> None:
    missing = [field for field in fields if field not in payload]
    if missing:
        err(f"{context} missing fields: {missing}")


def validate_closure_report(manifest: dict[str, Any]) -> None:
    report = load_json(CLOSURE_REPORT, "closure sweep report")
    contract = manifest.get("closure_sweep_contract", {})
    if not isinstance(contract, dict):
        err("closure_sweep_contract must be an object")
        return

    require_fields(report, string_list(contract.get("required_report_fields"), "closure_sweep_contract.required_report_fields"), "closure_report")
    summary = report.get("summary")
    if not isinstance(summary, dict):
        err("closure_report.summary must be an object")
        summary = {}
    require_fields(summary, string_list(contract.get("required_summary_fields"), "closure_sweep_contract.required_summary_fields"), "closure_report.summary")

    checks = {
        "schema_version": (report.get("schema_version"), contract.get("expected_schema_version")),
        "status": (report.get("status"), contract.get("expected_status")),
        "errors": (summary.get("errors"), contract.get("expected_error_count")),
        "warnings": (summary.get("warnings"), contract.get("expected_warning_count")),
        "total_findings": (summary.get("total_findings"), contract.get("expected_total_findings")),
        "callthrough_remaining": (summary.get("callthrough_remaining"), contract.get("expected_callthrough_remaining")),
        "open_gap_beads": (summary.get("open_gap_beads"), contract.get("expected_open_gap_beads")),
        "closure_ready": (summary.get("closure_ready"), contract.get("expected_closure_ready")),
        "drift_gates_status": (report.get("drift_gates_status"), contract.get("expected_drift_gates_status")),
    }
    for name, (actual, expected) in checks.items():
        if actual != expected:
            err(f"closure_report {name} mismatch: expected={expected!r} got={actual!r}")

    if report.get("bead") != SOURCE_BEAD:
        err(f"closure_report.bead must be {SOURCE_BEAD}")

    findings = report.get("findings")
    if not isinstance(findings, list) or findings:
        err("closure_report.findings must be an empty array")

    non_closure_reasons = report.get("non_closure_reasons")
    if not isinstance(non_closure_reasons, list) or not non_closure_reasons:
        err("closure_report.non_closure_reasons must document at least one reason")
        non_closure_reasons = []
    actual_categories = {
        row.get("category")
        for row in non_closure_reasons
        if isinstance(row, dict) and isinstance(row.get("category"), str)
    }
    expected_categories = set(string_list(contract.get("required_non_closure_categories"), "closure_sweep_contract.required_non_closure_categories"))
    if actual_categories != expected_categories:
        err(f"non_closure category mismatch: expected={sorted(expected_categories)} got={sorted(actual_categories)}")

    expected_modules = set(string_list(contract.get("expected_uncovered_zero_modules"), "closure_sweep_contract.expected_uncovered_zero_modules"))
    fixture_reason = next(
        (
            row
            for row in non_closure_reasons
            if isinstance(row, dict) and row.get("category") == "fixture_coverage"
        ),
        {},
    )
    modules = fixture_reason.get("modules", []) if isinstance(fixture_reason, dict) else []
    actual_modules = set(string_list(modules, "fixture_coverage.modules"))
    if actual_modules != expected_modules:
        err(f"fixture_coverage modules mismatch: expected={sorted(expected_modules)} got={sorted(actual_modules)}")

    coverage_gaps = report.get("coverage_gaps")
    if not isinstance(coverage_gaps, dict):
        err("closure_report.coverage_gaps must be an object")
    elif coverage_gaps.get("coverage_pct") != summary.get("coverage_pct"):
        err("closure_report coverage_pct must match coverage_gaps.coverage_pct")

    callthrough_gaps = report.get("callthrough_gaps")
    if not isinstance(callthrough_gaps, dict) or callthrough_gaps.get("total_callthrough") != 0:
        err("closure_report.callthrough_gaps.total_callthrough must be 0")

    open_gap_beads = report.get("open_gap_beads")
    if not isinstance(open_gap_beads, dict) or open_gap_beads.get("count") != 0:
        err("closure_report.open_gap_beads.count must be 0")

    append_event(
        "closure_sweep_report_validated",
        "pass" if not errors else "fail",
        [rel(CLOSURE_REPORT)],
        {
            "status": report.get("status"),
            "coverage_pct": summary.get("coverage_pct"),
            "non_closure_categories": sorted(actual_categories),
            "zero_fixture_modules": sorted(actual_modules),
        },
    )


def validate_docs_source_of_truth(manifest: dict[str, Any]) -> None:
    source_map = load_json(DOCS_SOURCE_MAP, "docs source-of-truth map")
    trace_rows = load_jsonl(DOCS_TRACE, "docs source-of-truth trace")
    contract = manifest.get("docs_truth_contract", {})
    if not isinstance(contract, dict):
        err("docs_truth_contract must be an object")
        return

    if source_map.get("bead") != contract.get("expected_bead"):
        err(f"docs source map bead mismatch: expected={contract.get('expected_bead')!r} got={source_map.get('bead')!r}")

    summary = source_map.get("summary")
    if not isinstance(summary, dict):
        err("docs source map summary must be an object")
        summary = {}
    expected_counts = {
        "surface_count": contract.get("expected_surface_count"),
        "section_count": contract.get("expected_section_count"),
        "owner_count": contract.get("expected_owner_count"),
        "fresh_section_count": contract.get("expected_fresh_section_count"),
        "missing_section_count": contract.get("expected_missing_section_count"),
    }
    for key, expected in expected_counts.items():
        if summary.get(key) != expected:
            err(f"docs source map summary.{key} mismatch: expected={expected!r} got={summary.get(key)!r}")

    surfaces = source_map.get("surfaces")
    if not isinstance(surfaces, list):
        err("docs source map surfaces must be an array")
        surfaces = []
    actual_surfaces = {
        row.get("surface_id")
        for row in surfaces
        if isinstance(row, dict) and isinstance(row.get("surface_id"), str)
    }
    required_surfaces = set(string_list(contract.get("required_surfaces"), "docs_truth_contract.required_surfaces"))
    if actual_surfaces != required_surfaces:
        err(f"docs surface mismatch: expected={sorted(required_surfaces)} got={sorted(actual_surfaces)}")

    section_count = 0
    expected_freshness = contract.get("expected_freshness_status")
    for surface in surfaces:
        if not isinstance(surface, dict):
            err("docs source map surface row must be an object")
            continue
        surface_id = surface.get("surface_id", "<unknown>")
        if surface.get("freshness_status") != expected_freshness:
            err(f"{surface_id}: freshness_status mismatch")
        if surface.get("missing_inputs") not in ([], None):
            err(f"{surface_id}: missing_inputs must be empty")
        sections = surface.get("sections")
        if not isinstance(sections, list) or not sections:
            err(f"{surface_id}: sections must be a non-empty array")
            continue
        section_count += len(sections)
        for section in sections:
            if not isinstance(section, dict):
                err(f"{surface_id}: section row must be an object")
                continue
            section_id = section.get("section_id", "<unknown>")
            for key in ("owner", "review_policy", "backing_paths", "source_artifacts", "update_triggers"):
                value = section.get(key)
                if value in ("", [], None):
                    err(f"{surface_id}/{section_id}: missing {key}")
            if section.get("freshness_status") != expected_freshness:
                err(f"{surface_id}/{section_id}: freshness_status mismatch")
            if section.get("missing_inputs") not in ([], None):
                err(f"{surface_id}/{section_id}: missing_inputs must be empty")

    expected_trace_rows = contract.get("expected_trace_rows")
    if len(trace_rows) != expected_trace_rows or len(trace_rows) != section_count:
        err(f"docs trace row count mismatch: expected={expected_trace_rows}, sections={section_count}, got={len(trace_rows)}")

    required_trace_fields = string_list(contract.get("required_trace_fields"), "docs_truth_contract.required_trace_fields")
    for index, row in enumerate(trace_rows, start=1):
        for key in required_trace_fields:
            value = row.get(key)
            if value in ("", [], None):
                err(f"docs trace row {index} missing {key}")
        if row.get("bead_id") != contract.get("expected_bead"):
            err(f"docs trace row {index} bead_id mismatch")
        if row.get("freshness_status") != expected_freshness:
            err(f"docs trace row {index} freshness_status mismatch")

    append_event(
        "docs_source_of_truth_validated",
        "pass" if not errors else "fail",
        [rel(DOCS_SOURCE_MAP), rel(DOCS_TRACE)],
        {
            "surfaces": sorted(actual_surfaces),
            "section_count": section_count,
            "trace_rows": len(trace_rows),
        },
    )


def run_docs_source_gate() -> None:
    proc = subprocess.run(
        ["bash", "scripts/check_docs_env_mismatch.sh"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=180,
    )
    result = {
        "command": "bash scripts/check_docs_env_mismatch.sh",
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-4000:],
    }
    source_gate_results["docs_source_of_truth_gate"] = result
    if proc.returncode != 0:
        err(f"docs source-of-truth gate failed with exit {proc.returncode}")
    append_event(
        "docs_source_gate_replayed",
        "pass" if proc.returncode == 0 else "fail",
        ["scripts/check_docs_env_mismatch.sh"],
        result,
    )


def validate_telemetry_contract(manifest: dict[str, Any], report: dict[str, Any]) -> None:
    contract = manifest.get("telemetry_contract", {})
    if not isinstance(contract, dict):
        err("telemetry_contract must be an object")
        return
    require_fields(report, string_list(contract.get("required_report_fields"), "telemetry_contract.required_report_fields"), "completion report")
    required_log_fields = string_list(contract.get("required_log_fields"), "telemetry_contract.required_log_fields")
    for index, event in enumerate(events, start=1):
        for key in required_log_fields:
            value = event.get(key)
            if value in ("", [], None):
                err(f"event {index} missing {key}")
    actual_events = {
        event.get("event")
        for event in events
        if isinstance(event.get("event"), str)
    }
    required_events = set(string_list(contract.get("required_events"), "telemetry_contract.required_events"))
    missing = sorted(required_events - actual_events)
    if missing:
        err(f"completion events missing: {missing}")


def main() -> int:
    manifest = load_json(CONTRACT, "completion contract")
    source_paths = validate_contract(manifest)
    validate_closure_report(manifest)
    validate_docs_source_of_truth(manifest)
    run_docs_source_gate()

    status = "pass" if not errors else "fail"
    passed = sum(1 for event in events if event["status"] == "pass")
    failed = sum(1 for event in events if event["status"] != "pass")
    append_event(
        "closure_sweep_completion_summary",
        status,
        [rel(CONTRACT), rel(CLOSURE_REPORT), rel(DOCS_SOURCE_MAP), rel(DOCS_TRACE)],
        {
            "gate_count": len(events) + 1,
            "passed": passed + (1 if status == "pass" else 0),
            "failed": failed + (0 if status == "pass" else 1),
            "source_paths": sorted(source_paths),
        },
    )

    report = {
        "schema_version": EXPECTED_SCHEMA,
        "bead": SOURCE_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "source_commit": git_head(),
        "completion_summary": {
            "gate_count": len(events),
            "passed": sum(1 for event in events if event["status"] == "pass"),
            "failed": sum(1 for event in events if event["status"] != "pass"),
        },
        "source_gate_results": source_gate_results,
        "events": events,
        "errors": errors,
    }
    validate_telemetry_contract(manifest, report)
    if errors:
        report["status"] = "fail"
        report["completion_summary"]["failed"] = max(1, report["completion_summary"]["failed"])

    write_json(REPORT, report)
    write_jsonl(LOG, events)

    if report["status"] == "pass":
        print(
            "check_closure_sweep_completion_contract: PASS "
            f"(events={len(events)} docs_gate_exit={source_gate_results.get('docs_source_of_truth_gate', {}).get('exit_code')})"
        )
        return 0
    print("check_closure_sweep_completion_contract: FAIL")
    for message in errors:
        print(f"  - {message}")
    print(f"report={rel(REPORT)}")
    return 1


raise SystemExit(main())
PY
