#!/usr/bin/env bash
# per_symbol_fixture_tests_completion_contract - bd-ldj.5.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/per_symbol_fixture_tests_completion_contract.v1.json}"
SOURCE_REPORT="${FRANKENLIBC_PER_SYMBOL_FIXTURE_REPORT:-$ROOT/tests/conformance/per_symbol_fixture_tests.v1.json}"
BASELINE="${FRANKENLIBC_PER_SYMBOL_FIXTURE_BASELINE:-$ROOT/tests/conformance/conformance_coverage_baseline.v1.json}"
REPORT="${FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_REPORT:-$ROOT/target/conformance/per_symbol_fixture_tests_completion_contract.report.json}"
LOG="${FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_LOG:-$ROOT/target/conformance/per_symbol_fixture_tests_completion_contract.log.jsonl}"
GENERATED_REPORT="${FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_GENERATED:-$ROOT/target/conformance/per_symbol_fixture_tests_completion_contract.generated.v1.json}"
ROUNDTRIP_REPORT="${FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_ROUNDTRIP:-$ROOT/target/conformance/per_symbol_fixture_tests_completion_contract.roundtrip.v1.json}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$GENERATED_REPORT")" "$(dirname "$ROUNDTRIP_REPORT")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
SOURCE_REPORT="$SOURCE_REPORT" \
BASELINE="$BASELINE" \
REPORT="$REPORT" \
LOG="$LOG" \
GENERATED_REPORT="$GENERATED_REPORT" \
ROUNDTRIP_REPORT="$ROUNDTRIP_REPORT" \
python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
SOURCE_REPORT = pathlib.Path(os.environ["SOURCE_REPORT"])
BASELINE = pathlib.Path(os.environ["BASELINE"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
GENERATED_REPORT = pathlib.Path(os.environ["GENERATED_REPORT"])
ROUNDTRIP_REPORT = pathlib.Path(os.environ["ROUNDTRIP_REPORT"])

ORIGINAL_BEAD = "bd-ldj.5"
COMPLETION_BEAD = "bd-ldj.5.1"
EXPECTED_SCHEMA = "per_symbol_fixture_tests_completion_contract.v1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.golden.primary",
    "tests.conformance.primary",
}
EXPECTED_EVENTS = {
    "per_symbol_fixture_completion_contract_validated",
    "per_symbol_fixture_golden_report_validated",
    "per_symbol_fixture_generator_roundtrip_validated",
    "per_symbol_fixture_completion_summary",
}

errors: list[str] = []


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


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


def number(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        err(f"{context} must be numeric")
        return 0.0
    return float(value)


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


def validate_impl_ref(ref: Any, source_text_cache: dict[str, str]) -> str | None:
    if not isinstance(ref, dict):
        err(f"implementation ref must be an object: {ref!r}")
        return None
    kind = ref.get("kind")
    path_text = ref.get("path")
    line = ref.get("line")
    anchor = ref.get("anchor")
    if not isinstance(kind, str) or not kind:
        err(f"implementation ref missing kind: {ref!r}")
    if not isinstance(path_text, str):
        err(f"implementation ref missing path: {ref!r}")
        return kind if isinstance(kind, str) else None
    text = source_text_cache.setdefault(path_text, text_for(path_text, f"implementation_refs.{kind}"))
    lines = text.splitlines()
    if not isinstance(line, int) or line <= 0:
        err(f"{path_text} ref line must be a positive integer")
    elif line > len(lines):
        err(f"{path_text}:{line} is past EOF")
    if not isinstance(anchor, str) or not anchor:
        err(f"{path_text} ref missing anchor")
    elif anchor not in text:
        err(f"{path_text} missing anchor {anchor!r}")
    return kind if isinstance(kind, str) else None


def validate_manifest(manifest: dict[str, Any]) -> dict[str, str]:
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        err(f"schema_version must be {EXPECTED_SCHEMA}")
    if manifest.get("bead") != ORIGINAL_BEAD:
        err(f"bead must be {ORIGINAL_BEAD}")
    if manifest.get("completion_debt_bead") != COMPLETION_BEAD:
        err(f"completion_debt_bead must be {COMPLETION_BEAD}")

    audit = manifest.get("audit", {})
    audit_items = set(string_list(audit.get("missing_items"), "audit.missing_items"))
    if audit_items != EXPECTED_MISSING_ITEMS:
        err(f"audit.missing_items mismatch: expected {sorted(EXPECTED_MISSING_ITEMS)}, got {sorted(audit_items)}")

    source_paths_raw = manifest.get("source_paths")
    if not isinstance(source_paths_raw, dict) or not source_paths_raw:
        err("source_paths must be a non-empty object")
        source_paths: dict[str, str] = {}
    else:
        source_paths = {str(k): str(v) for k, v in source_paths_raw.items() if isinstance(v, str)}
        for key, value in source_paths.items():
            repo_path(value, f"source_paths.{key}")

    source_text_cache: dict[str, str] = {}
    impl_kinds = {
        kind
        for kind in (validate_impl_ref(ref, source_text_cache) for ref in manifest.get("implementation_refs", []))
        if kind
    }
    if len(impl_kinds) < 20:
        err(f"implementation_refs should cite at least 20 concrete anchors, got {len(impl_kinds)}")

    anchors = manifest.get("source_anchors", {})
    if not isinstance(anchors, dict) or not anchors:
        err("source_anchors must be a non-empty object")
    else:
        for source, expected_anchors in anchors.items():
            path_text = source_paths.get(source)
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
        coverage = []
    seen_items: set[str] = set()
    source_text_by_key: dict[str, str] = {}
    for section in coverage:
        if not isinstance(section, dict):
            err(f"completion_coverage item must be an object: {section!r}")
            continue
        item = section.get("missing_item_id")
        if not isinstance(item, str):
            err(f"coverage section missing missing_item_id: {section!r}")
            continue
        seen_items.add(item)
        if section.get("status") != "covered":
            err(f"{item} status must be covered")
        ref_names = set(string_list(section.get("implementation_refs"), f"coverage.{item}.implementation_refs"))
        missing_refs = ref_names - impl_kinds
        if missing_refs:
            err(f"{item} cites unknown implementation refs: {sorted(missing_refs)}")
        test_refs = section.get("test_refs")
        if not isinstance(test_refs, list) or not test_refs:
            err(f"coverage.{item}.test_refs must be non-empty")
        else:
            for index, test_ref in enumerate(test_refs):
                if not isinstance(test_ref, dict):
                    err(f"coverage.{item}.test_refs[{index}] must be an object")
                    continue
                source = test_ref.get("source")
                name = test_ref.get("name")
                if not isinstance(source, str) or not isinstance(name, str):
                    err(f"coverage.{item}.test_refs[{index}] missing source/name")
                    continue
                path_text = source_paths.get(source)
                if not path_text:
                    err(f"coverage.{item}.test_refs[{index}] unknown source {source}")
                    continue
                text = source_text_by_key.setdefault(source, text_for(path_text, f"test_refs.{source}"))
                if not function_exists(text, name):
                    err(f"{path_text} missing test function {name}")
        commands = string_list(section.get("validation_commands"), f"coverage.{item}.validation_commands")
        for command in commands:
            if "cargo " in command and ("rch " not in command or "CARGO_TARGET_DIR=" not in command):
                err(f"{item} cargo validation command must use rch and CARGO_TARGET_DIR: {command}")
    if seen_items != EXPECTED_MISSING_ITEMS:
        err(f"completion_coverage mismatch: expected {sorted(EXPECTED_MISSING_ITEMS)}, got {sorted(seen_items)}")

    structured = manifest.get("structured_evidence", {})
    required_events = set(string_list(structured.get("required_events"), "structured_evidence.required_events"))
    if required_events != EXPECTED_EVENTS:
        err(f"structured events mismatch: {sorted(required_events)}")
    required_fields = set(string_list(structured.get("required_log_fields"), "structured_evidence.required_log_fields"))
    for field in ["timestamp", "trace_id", "level", "event", "bead_id", "outcome", "artifact_refs"]:
        if field not in required_fields:
            err(f"structured_evidence.required_log_fields missing {field}")

    return source_paths


def validate_fixture_report(report: dict[str, Any], baseline: dict[str, Any], contract: dict[str, Any], label: str) -> dict[str, float]:
    fixture_contract = contract.get("fixture_report_contract", {})
    if report.get("schema_version") != fixture_contract.get("schema_version"):
        err(f"{label}: schema_version mismatch")
    if report.get("bead") != ORIGINAL_BEAD:
        err(f"{label}: bead must be {ORIGINAL_BEAD}")
    if not isinstance(report.get("report_hash"), str) or len(report.get("report_hash", "")) < 8:
        err(f"{label}: report_hash must be a stable string")

    summary = report.get("summary", {})
    if not isinstance(summary, dict):
        err(f"{label}: summary must be an object")
        summary = {}
    for field in string_list(fixture_contract.get("required_summary_fields"), "fixture_report_contract.required_summary_fields"):
        if field not in summary:
            err(f"{label}: summary missing {field}")

    stats = {
        "total_symbols": number(summary.get("total_symbols"), f"{label}.summary.total_symbols"),
        "symbols_with_fixtures": number(summary.get("symbols_with_fixtures"), f"{label}.summary.symbols_with_fixtures"),
        "fixture_coverage_pct": number(summary.get("fixture_coverage_pct"), f"{label}.summary.fixture_coverage_pct"),
        "total_fixture_files": number(summary.get("total_fixture_files"), f"{label}.summary.total_fixture_files"),
        "total_cases": number(summary.get("total_cases"), f"{label}.summary.total_cases"),
        "total_format_issues": number(summary.get("total_format_issues"), f"{label}.summary.total_format_issues"),
        "symbols_with_edge_cases": number(summary.get("symbols_with_edge_cases"), f"{label}.summary.symbols_with_edge_cases"),
        "symbols_with_errno_checks": number(summary.get("symbols_with_errno_checks"), f"{label}.summary.symbols_with_errno_checks"),
        "uncovered_action_count": number(summary.get("uncovered_action_count"), f"{label}.summary.uncovered_action_count"),
    }
    thresholds = {
        "total_symbols": fixture_contract.get("min_total_symbols"),
        "symbols_with_fixtures": fixture_contract.get("min_symbols_with_fixtures"),
        "total_fixture_files": fixture_contract.get("min_fixture_files"),
        "total_cases": fixture_contract.get("min_total_cases"),
        "symbols_with_edge_cases": fixture_contract.get("min_symbols_with_edge_cases"),
    }
    for field, minimum in thresholds.items():
        if isinstance(minimum, (int, float)) and stats[field] < float(minimum):
            err(f"{label}: {field} {stats[field]} below minimum {minimum}")
    max_format = fixture_contract.get("max_total_format_issues")
    if isinstance(max_format, (int, float)) and stats["total_format_issues"] > float(max_format):
        err(f"{label}: total_format_issues {stats['total_format_issues']} exceeds {max_format}")

    baseline_summary = baseline.get("summary", {}) if isinstance(baseline.get("summary"), dict) else {}
    baseline_coverage = number(baseline_summary.get("coverage_pct"), "baseline.summary.coverage_pct")
    slack = number(fixture_contract.get("baseline_coverage_slack_pct"), "fixture_report_contract.baseline_coverage_slack_pct")
    if stats["fixture_coverage_pct"] + slack < baseline_coverage:
        err(f"{label}: fixture coverage {stats['fixture_coverage_pct']} regressed below baseline {baseline_coverage}")

    fixture_files = report.get("fixture_file_analyses")
    if not isinstance(fixture_files, list) or not fixture_files:
        err(f"{label}: fixture_file_analyses must be non-empty")
        fixture_files = []
    file_case_sum = 0
    for index, row in enumerate(fixture_files):
        if not isinstance(row, dict):
            err(f"{label}: fixture_file_analyses[{index}] must be an object")
            continue
        for field in ["file", "family", "valid", "total_cases", "unique_symbols", "issues"]:
            if field not in row:
                err(f"{label}: fixture_file_analyses[{index}] missing {field}")
        if row.get("valid") is not True:
            err(f"{label}: fixture file {row.get('file')} is not valid")
        if not isinstance(row.get("issues"), list) or row.get("issues"):
            err(f"{label}: fixture file {row.get('file')} has issues")
        file_case_sum += int(row.get("total_cases", 0) or 0)
    if file_case_sum != int(stats["total_cases"]):
        err(f"{label}: fixture file case sum {file_case_sum} != summary total_cases {stats['total_cases']}")

    per_symbol = report.get("per_symbol_report")
    if not isinstance(per_symbol, list) or not per_symbol:
        err(f"{label}: per_symbol_report must be non-empty")
        per_symbol = []
    if len(per_symbol) != int(stats["total_symbols"]):
        err(f"{label}: per_symbol_report length {len(per_symbol)} != total_symbols {stats['total_symbols']}")

    valid_statuses = set(string_list(fixture_contract.get("valid_symbol_statuses"), "fixture_report_contract.valid_symbol_statuses"))
    with_fixtures_count = 0
    edge_count = 0
    errno_count = 0
    for index, row in enumerate(per_symbol):
        if not isinstance(row, dict):
            err(f"{label}: per_symbol_report[{index}] must be an object")
            continue
        for field in ["symbol", "status", "module", "has_fixtures", "case_count", "fixture_files", "modes_tested", "edge_cases_covered", "has_errno_check", "quality_issues"]:
            if field not in row:
                err(f"{label}: per_symbol_report[{index}] missing {field}")
        if row.get("status") not in valid_statuses:
            err(f"{label}: invalid status for {row.get('symbol')}: {row.get('status')}")
        if row.get("has_fixtures") is True:
            with_fixtures_count += 1
            if int(row.get("case_count", 0) or 0) <= 0:
                err(f"{label}: fixture-covered symbol {row.get('symbol')} has no cases")
            if not row.get("fixture_files"):
                err(f"{label}: fixture-covered symbol {row.get('symbol')} has no fixture files")
        if row.get("edge_cases_covered"):
            edge_count += 1
        if row.get("has_errno_check") is True:
            errno_count += 1
    if with_fixtures_count != int(stats["symbols_with_fixtures"]):
        err(f"{label}: symbols_with_fixtures mismatch")
    if edge_count != int(stats["symbols_with_edge_cases"]):
        err(f"{label}: symbols_with_edge_cases mismatch")
    if errno_count != int(stats["symbols_with_errno_checks"]):
        err(f"{label}: symbols_with_errno_checks mismatch")

    uncovered = report.get("uncovered_action_list")
    if not isinstance(uncovered, list):
        err(f"{label}: uncovered_action_list must be an array")
        uncovered = []
    if len(uncovered) != int(stats["uncovered_action_count"]):
        err(f"{label}: uncovered_action_count mismatch")
    for index, row in enumerate(uncovered[:50]):
        if not isinstance(row, dict):
            err(f"{label}: uncovered_action_list[{index}] must be an object")
            continue
        for field in ["symbol", "status", "module", "action", "priority"]:
            if field not in row:
                err(f"{label}: uncovered_action_list[{index}] missing {field}")

    expected_edges = set(string_list(fixture_contract.get("edge_case_categories"), "fixture_report_contract.edge_case_categories"))
    actual_edges = set(string_list(report.get("edge_case_categories"), f"{label}.edge_case_categories"))
    if actual_edges != expected_edges:
        err(f"{label}: edge_case_categories mismatch")

    return stats


def run_generator(output: pathlib.Path) -> bool:
    generator = ROOT / "scripts/generate_per_symbol_fixture_tests.py"
    result = subprocess.run(
        ["python3", str(generator), "-o", str(output)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        err(
            "per-symbol fixture generator failed: "
            f"exit={result.returncode} stdout={result.stdout.strip()} stderr={result.stderr.strip()}"
        )
        return False
    return True


def validate_generator_roundtrip(generated: dict[str, Any], roundtrip: dict[str, Any], source_stats: dict[str, float]) -> None:
    if generated.get("report_hash") != roundtrip.get("report_hash"):
        err("generator roundtrip report_hash changed across repeated generation")
    if generated.get("summary") != roundtrip.get("summary"):
        err("generator roundtrip summary changed across repeated generation")

    gen_summary = generated.get("summary", {}) if isinstance(generated.get("summary"), dict) else {}
    if number(gen_summary.get("total_cases"), "generated.summary.total_cases") < source_stats.get("total_cases", 0):
        err("generated report has fewer cases than canonical golden report")
    if number(gen_summary.get("symbols_with_fixtures"), "generated.summary.symbols_with_fixtures") < source_stats.get("symbols_with_fixtures", 0):
        err("generated report has fewer fixture-linked symbols than canonical golden report")
    if number(gen_summary.get("total_format_issues"), "generated.summary.total_format_issues") != 0:
        err("generated report contains fixture format issues")


def log_row(event: str, details: dict[str, Any], *, latency_ns: int, source_commit: str) -> dict[str, Any]:
    return {
        "timestamp": now(),
        "trace_id": f"{COMPLETION_BEAD}::per_symbol_fixture_tests",
        "level": "info",
        "event": event,
        "bead_id": COMPLETION_BEAD,
        "stream": "conformance",
        "gate": "per_symbol_fixture_tests_completion_contract",
        "scenario_id": event,
        "mode": "strict",
        "runtime_mode": "strict",
        "api_family": "symbols",
        "symbol": "per_symbol_fixture_tests",
        "oracle_kind": "host_glibc_fixture_golden",
        "expected": {"missing_items": sorted(EXPECTED_MISSING_ITEMS)},
        "actual": details,
        "decision_path": "completion_contract_validate_golden_and_generated_reports",
        "outcome": "pass",
        "source_commit": source_commit,
        "target_dir": rel(REPORT.parent),
        "failure_signature": "none",
        "artifact_refs": [
            rel(CONTRACT),
            rel(SOURCE_REPORT),
            rel(GENERATED_REPORT),
            rel(ROUNDTRIP_REPORT),
            rel(REPORT),
            rel(LOG),
        ],
        "latency_ns": latency_ns,
        "details": details,
    }


start_ns = time.monotonic_ns()
manifest = load_json(CONTRACT, "completion contract")
source_report = load_json(SOURCE_REPORT, "canonical per-symbol fixture report")
baseline = load_json(BASELINE, "conformance coverage baseline")

source_paths = validate_manifest(manifest)
source_stats = validate_fixture_report(source_report, baseline, manifest, "canonical")

if run_generator(GENERATED_REPORT):
    generated_report = load_json(GENERATED_REPORT, "generated per-symbol fixture report")
else:
    generated_report = {}
if run_generator(ROUNDTRIP_REPORT):
    roundtrip_report = load_json(ROUNDTRIP_REPORT, "roundtrip per-symbol fixture report")
else:
    roundtrip_report = {}

if generated_report:
    validate_fixture_report(generated_report, baseline, manifest, "generated")
if generated_report and roundtrip_report:
    validate_generator_roundtrip(generated_report, roundtrip_report, source_stats)

elapsed_ns = time.monotonic_ns() - start_ns
commit = git_head()

if errors:
    failure_report = {
        "schema_version": EXPECTED_SCHEMA,
        "bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": "fail",
        "errors": errors,
        "source_commit": commit,
        "elapsed_ns": elapsed_ns,
        "source_paths": source_paths,
    }
    write_json(REPORT, failure_report)
    write_jsonl(LOG, [
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}::per_symbol_fixture_tests",
            "level": "error",
            "event": "per_symbol_fixture_completion_contract_failed",
            "bead_id": COMPLETION_BEAD,
            "stream": "conformance",
            "gate": "per_symbol_fixture_tests_completion_contract",
            "scenario_id": "completion_contract_failed",
            "mode": "strict",
            "runtime_mode": "strict",
            "api_family": "symbols",
            "symbol": "per_symbol_fixture_tests",
            "oracle_kind": "host_glibc_fixture_golden",
            "expected": {"errors": []},
            "actual": {"errors": errors[:20]},
            "decision_path": "completion_contract_validate_golden_and_generated_reports",
            "outcome": "fail",
            "source_commit": commit,
            "target_dir": rel(REPORT.parent),
            "failure_signature": "completion_contract_validation_failed",
            "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
            "latency_ns": elapsed_ns,
            "details": {"error_count": len(errors)},
        }
    ])
    print("FAIL: per-symbol fixture completion contract validation failed", file=sys.stderr)
    for message in errors:
        print(f" - {message}", file=sys.stderr)
    sys.exit(1)

generated_summary = generated_report.get("summary", {}) if isinstance(generated_report.get("summary"), dict) else {}
rows = [
    log_row(
        "per_symbol_fixture_completion_contract_validated",
        {"missing_items": sorted(EXPECTED_MISSING_ITEMS), "implementation_refs": len(manifest.get("implementation_refs", []))},
        latency_ns=elapsed_ns,
        source_commit=commit,
    ),
    log_row(
        "per_symbol_fixture_golden_report_validated",
        {
            "golden_report_hash": source_report.get("report_hash"),
            "golden_total_cases": source_stats.get("total_cases"),
            "golden_symbols_with_fixtures": source_stats.get("symbols_with_fixtures"),
        },
        latency_ns=elapsed_ns,
        source_commit=commit,
    ),
    log_row(
        "per_symbol_fixture_generator_roundtrip_validated",
        {
            "generated_report_hash": generated_report.get("report_hash"),
            "roundtrip_report_hash": roundtrip_report.get("report_hash"),
            "generated_total_cases": generated_summary.get("total_cases"),
        },
        latency_ns=elapsed_ns,
        source_commit=commit,
    ),
    log_row(
        "per_symbol_fixture_completion_summary",
        {
            "status": "pass",
            "source_report": rel(SOURCE_REPORT),
            "generated_report": rel(GENERATED_REPORT),
            "roundtrip_report": rel(ROUNDTRIP_REPORT),
        },
        latency_ns=elapsed_ns,
        source_commit=commit,
    ),
]
write_jsonl(LOG, rows)
write_json(REPORT, {
    "schema_version": EXPECTED_SCHEMA,
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": "pass",
    "source_commit": commit,
    "elapsed_ns": elapsed_ns,
    "missing_items": sorted(EXPECTED_MISSING_ITEMS),
    "source_report": {
        "path": rel(SOURCE_REPORT),
        "report_hash": source_report.get("report_hash"),
        "summary": source_report.get("summary"),
    },
    "generated_report": {
        "path": rel(GENERATED_REPORT),
        "report_hash": generated_report.get("report_hash"),
        "summary": generated_report.get("summary"),
    },
    "roundtrip_report": {
        "path": rel(ROUNDTRIP_REPORT),
        "report_hash": roundtrip_report.get("report_hash"),
        "summary": roundtrip_report.get("summary"),
    },
    "structured_events": sorted(EXPECTED_EVENTS),
})
print(
    "check_per_symbol_fixture_tests_completion_contract: PASS "
    f"golden_cases={int(source_stats.get('total_cases', 0))} "
    f"generated_cases={generated_summary.get('total_cases')} "
    f"events={len(rows)}"
)
PY
