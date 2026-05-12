#!/usr/bin/env bash
# Validate bd-3h1u.1.1.1 baseline-capture bench-ingestion completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_BASELINE_CAPTURE_CONTRACT:-${ROOT}/tests/conformance/baseline_capture_bench_ingestion_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_BASELINE_CAPTURE_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_BASELINE_CAPTURE_REPORT:-${OUT_DIR}/baseline_capture_bench_ingestion_completion_contract.report.json}"
LOG="${FRANKENLIBC_BASELINE_CAPTURE_LOG:-${OUT_DIR}/baseline_capture_bench_ingestion_completion_contract.log.jsonl}"
SYMBOL_REPORT="${FRANKENLIBC_BASELINE_CAPTURE_SYMBOL_REPORT:-${OUT_DIR}/baseline_capture_symbol_latency_perf_gate.current.v1.json}"
SYMBOL_LOG="${FRANKENLIBC_BASELINE_CAPTURE_SYMBOL_LOG:-${OUT_DIR}/baseline_capture_symbol_latency_perf_gate.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SYMBOL_REPORT}" "${SYMBOL_LOG}" <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT = pathlib.Path(sys.argv[2]).resolve()
REPORT = pathlib.Path(sys.argv[3]).resolve()
LOG = pathlib.Path(sys.argv[4]).resolve()
SYMBOL_REPORT = pathlib.Path(sys.argv[5]).resolve()
SYMBOL_LOG = pathlib.Path(sys.argv[6]).resolve()

SCHEMA = "baseline_capture_bench_ingestion_completion_contract.v1"
REPORT_SCHEMA = "baseline_capture_bench_ingestion_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-3h1u.1.1"
COMPLETION_BEAD = "bd-3h1u.1.1.1"
EXPECTED_MISSING = {"tests.conformance.primary", "telemetry.primary"}
REQUIRED_SOURCE_IDS = {
    "canonical_baseline",
    "capture_map",
    "sample_log",
    "baseline_generator",
    "sample_ingester",
    "baseline_checker",
    "baseline_harness",
    "perf_budget_policy",
    "completion_checker",
    "completion_harness",
}
REQUIRED_COMPLETION_EVENTS = {
    "baseline_capture.source_artifacts_validated",
    "baseline_capture.conformance_binding_validated",
    "baseline_capture.telemetry_validated",
    "baseline_capture.symbol_latency_gate_replayed",
    "baseline_capture.completion_contract_validated",
    "baseline_capture.completion_contract_failed",
}
REQUIRED_SYMBOL_EVENTS = {
    "ci.symbol_latency_budget.pass",
    "ci.symbol_latency_budget.waived_target_violation",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "timestamp",
    "event",
    "status",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "missing_items_bound",
    "source_count",
    "implementation_ref_count",
    "capture_map_source_count",
    "measured_symbol_count",
    "updated_symbols",
    "updated_modes",
    "symbol_latency_report",
    "symbol_latency_log",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


SOURCE_COMMIT = source_commit()


def error(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        error(message)


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        error(f"{label} unreadable: {rel(path)}: {exc}")
        return {}


def string_list(value: Any, label: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        error(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            error(f"{label}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": "baseline_capture_bench_ingestion_completion_contract.log.v1",
            "timestamp": utc_now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}",
            "event": event,
            "level": "info" if status == "pass" else "error",
            "status": status,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "source_commit": SOURCE_COMMIT,
            "artifact_refs": [rel(CONTRACT), rel(REPORT)],
            "details": details,
        }
    )


def validate_file_line_ref(value: Any, label: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        error(f"{label} must be file:line")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        error(f"{label} must be file:line")
        return
    path = ROOT / path_text
    if not path.is_file():
        error(f"{label} references missing file: {value}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines):
        error(f"{label} references line past EOF: {value}")
    elif not lines[line_no - 1].strip():
        error(f"{label} references blank line: {value}")


def function_exists(path_text: str, name: str) -> bool:
    try:
        text = (ROOT / path_text).read_text(encoding="utf-8")
    except OSError:
        return False
    return f"fn {name}" in text


def is_executable(path: pathlib.Path) -> bool:
    try:
        return bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        return False


def validate_sources(manifest: dict[str, Any]) -> dict[str, str]:
    sources = manifest.get("source_artifacts")
    if not isinstance(sources, list):
        error("source_artifacts must be an array")
        return {}
    path_by_id: dict[str, str] = {}
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            error(f"source_artifacts[{index}] must be an object")
            continue
        source_id = source.get("id")
        path_text = source.get("path")
        if not isinstance(source_id, str) or not source_id:
            error(f"source_artifacts[{index}].id must be a string")
            continue
        if not isinstance(path_text, str) or not path_text:
            error(f"source_artifacts[{source_id}].path must be a string")
            continue
        path_by_id[source_id] = path_text
        path = ROOT / path_text
        if not path.is_file():
            error(f"source_artifacts.{source_id} missing: {path_text}")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in string_list(source.get("required_needles"), f"{source_id}.required_needles"):
            if needle not in text:
                error(f"{path_text} missing required needle {needle!r}")
        if path_text.startswith("scripts/") and path.suffix in {".sh", ".py"}:
            require(is_executable(path), f"{path_text} must be executable")
    require(set(path_by_id) == REQUIRED_SOURCE_IDS, f"source ids drifted: {sorted(path_by_id)}")
    append_event(
        "baseline_capture.source_artifacts_validated",
        "pass" if not errors else "fail",
        {"source_count": len(path_by_id), "source_ids": sorted(path_by_id)},
    )
    return path_by_id


def validate_bindings(manifest: dict[str, Any], path_by_id: dict[str, str]) -> None:
    missing = set(
        string_list(
            manifest.get("completion_debt_evidence", {}).get("missing_items_closed"),
            "completion_debt_evidence.missing_items_closed",
        )
    )
    require(missing == EXPECTED_MISSING, f"missing_items_closed must be {sorted(EXPECTED_MISSING)}")
    require(
        manifest.get("completion_debt_evidence", {}).get("next_audit_score_threshold", 0) >= 800,
        "next audit score threshold must be at least 800",
    )
    for index, ref in enumerate(manifest.get("implementation_refs", [])):
        validate_file_line_ref(ref, f"implementation_refs[{index}]")

    for section in ["conformance_primary", "telemetry_primary"]:
        item = manifest.get(section)
        if not isinstance(item, dict):
            error(f"{section} must be an object")
            continue
        require(item.get("missing_item_id") in EXPECTED_MISSING, f"{section}.missing_item_id drifted")
        for index, ref in enumerate(item.get("required_test_refs", [])):
            if not isinstance(ref, dict):
                error(f"{section}.required_test_refs[{index}] must be an object")
                continue
            source = ref.get("source")
            name = ref.get("name")
            if not isinstance(source, str) or not isinstance(name, str):
                error(f"{section}.required_test_refs[{index}] source/name must be strings")
                continue
            path_text = path_by_id.get(source)
            if path_text is None:
                error(f"{section}.required_test_refs[{index}] references unknown source {source}")
                continue
            require(function_exists(path_text, name), f"{path_text} missing test fn {name}")

    append_event(
        "baseline_capture.conformance_binding_validated",
        "pass" if not errors else "fail",
        {
            "missing_items_bound": sorted(missing),
            "implementation_ref_count": len(manifest.get("implementation_refs", [])),
        },
    )


def validate_symbol_artifacts(manifest: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    baseline = load_json(ROOT / "tests/conformance/symbol_latency_baseline.v1.json", "canonical baseline")
    capture_map = load_json(ROOT / "tests/conformance/symbol_latency_capture_map.v1.json", "capture map")
    summary = baseline.get("summary", {}) if isinstance(baseline, dict) else {}
    ingestion = baseline.get("ingestion", {}) if isinstance(baseline, dict) else {}
    requirements = (
        manifest.get("conformance_primary", {})
        .get("required_baseline_summary", {})
        if isinstance(manifest.get("conformance_primary"), dict)
        else {}
    )
    require(baseline.get("schema_version") == 1, "canonical baseline schema_version must be 1")
    require(baseline.get("bead") == "bd-3h1u.1", "canonical baseline bead mismatch")
    require(ingestion.get("trace_id") == "bd-3h1u.1-symbol-latency-ingest-v1", "ingestion trace drifted")
    total_symbols = int(summary.get("total_symbols", 0) or 0)
    updated_symbols = int(ingestion.get("updated_symbols", 0) or 0)
    updated_modes = int(ingestion.get("updated_modes", 0) or 0)
    sources = capture_map.get("sources", []) if isinstance(capture_map, dict) else []
    require(total_symbols >= int(requirements.get("minimum_total_symbols", 0)), "total_symbols below contract minimum")
    require(updated_symbols >= int(requirements.get("minimum_updated_symbols", 0)), "updated_symbols below contract minimum")
    require(updated_modes >= int(requirements.get("minimum_updated_modes", 0)), "updated_modes below contract minimum")
    require(len(sources) >= int(requirements.get("minimum_capture_map_sources", 0)), "capture map source count below minimum")
    measured = summary.get("mode_percentile_measured_counts", {})
    for mode in ["raw", "strict", "hardened"]:
        require(
            measured.get(mode, {}).get("p50", 0) >= int(requirements.get("minimum_measured_symbols_per_mode", 0)),
            f"{mode} p50 measured count below contract minimum",
        )
    return baseline, capture_map


def replay_symbol_latency_gate(manifest: dict[str, Any]) -> dict[str, Any]:
    env = os.environ.copy()
    env["FRANKENLIBC_SYMBOL_LATENCY_REPORT"] = str(SYMBOL_REPORT)
    env["FRANKENLIBC_SYMBOL_LATENCY_EVENT_LOG"] = str(SYMBOL_LOG)
    env["FRANKENLIBC_SYMBOL_LATENCY_GENERATED"] = str(
        SYMBOL_REPORT.parent / "baseline_capture_symbol_latency.generated.v1.json"
    )
    proc = subprocess.run(
        ["bash", "scripts/check_symbol_latency_baseline.sh"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        error(
            "check_symbol_latency_baseline.sh failed: "
            f"stdout={proc.stdout[-1000:]} stderr={proc.stderr[-1000:]}"
        )
        return {}
    symbol_report = load_json(SYMBOL_REPORT, "symbol latency report")
    symbol_events = []
    try:
        for line in SYMBOL_LOG.read_text(encoding="utf-8").splitlines():
            if line.strip():
                symbol_events.append(json.loads(line))
    except Exception as exc:
        error(f"symbol latency log unreadable: {rel(SYMBOL_LOG)}: {exc}")
    actual_events = {row.get("event") for row in symbol_events if isinstance(row, dict)}
    required_events = set(
        string_list(
            manifest.get("telemetry_primary", {}).get("required_symbol_latency_events"),
            "telemetry_primary.required_symbol_latency_events",
        )
    )
    require(REQUIRED_SYMBOL_EVENTS <= required_events, "manifest missing required symbol latency events")
    require(required_events <= actual_events, f"symbol latency events missing {sorted(required_events - actual_events)}")
    require(symbol_report.get("summary", {}).get("gate_passed") is True, "symbol latency report gate_passed must be true")
    require(symbol_report.get("summary", {}).get("measured_symbol_count", 0) >= 16, "measured_symbol_count below 16")
    append_event(
        "baseline_capture.symbol_latency_gate_replayed",
        "pass" if not errors else "fail",
        {
            "symbol_latency_report": rel(SYMBOL_REPORT),
            "symbol_latency_log": rel(SYMBOL_LOG),
            "event_count": len(symbol_events),
            "stdout_tail": proc.stdout[-500:],
        },
    )
    return symbol_report


def validate_telemetry_contract(manifest: dict[str, Any], symbol_report: dict[str, Any]) -> None:
    telemetry = manifest.get("telemetry_primary", {})
    required_completion = set(string_list(telemetry.get("required_completion_events"), "telemetry_primary.required_completion_events"))
    required_fields = set(string_list(telemetry.get("required_report_fields"), "telemetry_primary.required_report_fields"))
    require(REQUIRED_COMPLETION_EVENTS <= required_completion, "completion events missing from manifest")
    require(REQUIRED_REPORT_FIELDS <= required_fields, "report fields missing from manifest")
    require(symbol_report.get("summary", {}).get("strict_waived", 0) > 0 or symbol_report.get("summary", {}).get("hardened_waived", 0) > 0, "expected active waiver telemetry")
    append_event(
        "baseline_capture.telemetry_validated",
        "pass" if not errors else "fail",
        {
            "required_completion_events": sorted(required_completion),
            "required_report_fields": sorted(required_fields),
        },
    )


manifest = load_json(CONTRACT, "contract")
if not isinstance(manifest, dict):
    manifest = {}
if manifest.get("schema_version") != SCHEMA:
    error("schema_version mismatch")
if manifest.get("original_bead") != ORIGINAL_BEAD:
    error(f"original_bead must be {ORIGINAL_BEAD}")
if manifest.get("completion_debt_bead") != COMPLETION_BEAD:
    error(f"completion_debt_bead must be {COMPLETION_BEAD}")
if manifest.get("audit_reference", {}).get("score_threshold", 0) < 800:
    error("audit score threshold must be at least 800")

path_by_id = validate_sources(manifest)
validate_bindings(manifest, path_by_id)
baseline, capture_map = validate_symbol_artifacts(manifest)
symbol_report = replay_symbol_latency_gate(manifest)
validate_telemetry_contract(manifest, symbol_report)

status = "fail" if errors else "pass"
if errors:
    append_event(
        "baseline_capture.completion_contract_failed",
        "fail",
        {"errors": errors},
    )
else:
    append_event(
        "baseline_capture.completion_contract_validated",
        "pass",
        {
            "completion_debt_bead": COMPLETION_BEAD,
            "missing_items_bound": sorted(EXPECTED_MISSING),
        },
    )

report = {
    "schema_version": REPORT_SCHEMA,
    "timestamp": utc_now(),
    "event": "baseline_capture.completion_contract_validated" if not errors else "baseline_capture.completion_contract_failed",
    "status": status,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": SOURCE_COMMIT,
    "missing_items_bound": sorted(EXPECTED_MISSING),
    "source_count": len(path_by_id),
    "implementation_ref_count": len(manifest.get("implementation_refs", [])),
    "capture_map_source_count": len(capture_map.get("sources", [])) if isinstance(capture_map, dict) else 0,
    "measured_symbol_count": symbol_report.get("summary", {}).get("measured_symbol_count", 0),
    "updated_symbols": baseline.get("ingestion", {}).get("updated_symbols", 0) if isinstance(baseline, dict) else 0,
    "updated_modes": baseline.get("ingestion", {}).get("updated_modes", 0) if isinstance(baseline, dict) else 0,
    "symbol_latency_report": rel(SYMBOL_REPORT),
    "symbol_latency_log": rel(SYMBOL_LOG),
    "artifact_refs": [
        rel(CONTRACT),
        "tests/conformance/symbol_latency_baseline.v1.json",
        "tests/conformance/symbol_latency_capture_map.v1.json",
        "tests/conformance/symbol_latency_samples.v1.log",
        "scripts/check_symbol_latency_baseline.sh",
    ],
    "failure_signature": "none" if not errors else "baseline_capture_bench_ingestion_completion_contract_failed",
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG.open("w", encoding="utf-8") as handle:
    for row in events:
        handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

if errors:
    print(f"baseline_capture_bench_ingestion_completion_contract: FAIL errors={len(errors)}", file=sys.stderr)
    for err in errors:
        print(f"ERROR: {err}", file=sys.stderr)
    raise SystemExit(1)

print(
    "baseline_capture_bench_ingestion_completion_contract: PASS "
    f"sources={report['source_count']} "
    f"capture_sources={report['capture_map_source_count']} "
    f"measured_symbols={report['measured_symbol_count']} "
    f"updated_symbols={report['updated_symbols']} "
    f"events={len(events)}"
)
PY
