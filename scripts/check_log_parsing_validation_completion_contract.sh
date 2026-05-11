#!/usr/bin/env bash
# log_parsing_validation_completion_contract - bd-2icq.19.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_LOG_PARSING_COMPLETION_CONTRACT:-$ROOT/tests/conformance/log_parsing_validation_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_LOG_PARSING_COMPLETION_REPORT:-$ROOT/target/conformance/log_parsing_validation_completion_contract.report.json}"
LOG="${FRANKENLIBC_LOG_PARSING_COMPLETION_LOG:-$ROOT/target/conformance/log_parsing_validation_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import importlib.util
import json
import os
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

ORIGINAL_BEAD = "bd-2icq.19"
COMPLETION_BEAD = "bd-2icq.19.1"
EXPECTED_SCHEMA = "log_parsing_validation_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "log_parsing_validation_completion_report.v1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "telemetry.primary"}
EXPECTED_EVENTS = {
    "log_parsing_source_bound",
    "log_parsing_unit_bound",
    "log_parsing_telemetry_bound",
    "log_parsing_completion_summary",
}
FORBIDDEN_COMMAND_SUBSTRINGS = {
    "git reset --hard",
    "git clean -fd",
    "rm -rf",
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
        return None
    if not isinstance(path_text, str):
        err(f"implementation ref {kind} missing path")
        return kind
    if not isinstance(anchor, str) or not anchor:
        err(f"implementation ref {kind} missing anchor")
        return kind
    if not isinstance(line, int) or line <= 0:
        err(f"implementation ref {kind} line must be a positive integer")
        return kind
    source = source_text_cache.setdefault(path_text, text_for(path_text, f"implementation ref {kind}"))
    if not source:
        return kind
    lines = source.splitlines()
    if line > len(lines):
        err(f"implementation ref {kind} line outside file: {path_text}:{line}")
    elif anchor not in lines[line - 1]:
        err(f"implementation ref {kind} line {path_text}:{line} does not contain anchor {anchor!r}")
    if anchor not in source:
        err(f"implementation ref {kind} source missing anchor {anchor!r}")
    return kind


def load_module(name: str, path: pathlib.Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


def validate_manifest(contract: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if contract.get("schema_version") != EXPECTED_SCHEMA:
        err(f"schema_version must be {EXPECTED_SCHEMA}")
    if contract.get("bead") != ORIGINAL_BEAD:
        err(f"bead must be {ORIGINAL_BEAD}")
    if contract.get("completion_debt_bead") != COMPLETION_BEAD:
        err(f"completion_debt_bead must be {COMPLETION_BEAD}")

    audit = contract.get("audit")
    if not isinstance(audit, dict):
        err("audit must be an object")
    else:
        missing = set(string_list(audit.get("missing_items"), "audit.missing_items"))
        if missing != EXPECTED_MISSING_ITEMS:
            err(f"audit.missing_items must match {sorted(EXPECTED_MISSING_ITEMS)}")
        repo_path(audit.get("scorecard"), "audit.scorecard", must_be_file=True)

    source_paths = contract.get("source_paths")
    if not isinstance(source_paths, dict) or not source_paths:
        err("source_paths must be a non-empty object")
    else:
        for key, value in source_paths.items():
            repo_path(value, f"source_paths.{key}")

    source_text_cache: dict[str, str] = {}
    impl_refs = contract.get("implementation_refs")
    if not isinstance(impl_refs, list) or len(impl_refs) < 10:
        err("implementation_refs must include concrete parser, validator, stats, test, and completion refs")
        impl_refs = []
    ref_ids = {ref_id for ref in impl_refs if (ref_id := validate_impl_ref(ref, source_text_cache))}

    anchors = contract.get("source_anchors")
    if not isinstance(anchors, dict) or not anchors:
        err("source_anchors must be a non-empty object")
    elif isinstance(source_paths, dict):
        for source_name, values in anchors.items():
            path_text = source_paths.get(source_name)
            if not isinstance(path_text, str):
                err(f"source_anchors.{source_name} has no matching source_paths entry")
                continue
            source = source_text_cache.setdefault(path_text, text_for(path_text, f"source_anchors.{source_name}"))
            for anchor in string_list(values, f"source_anchors.{source_name}"):
                if anchor not in source:
                    err(f"source_anchors.{source_name} missing anchor {anchor!r}")

    coverage = contract.get("completion_coverage")
    if not isinstance(coverage, list) or not coverage:
        err("completion_coverage must be a non-empty array")
        coverage = []
    covered_items = set()
    for section in coverage:
        if not isinstance(section, dict):
            err(f"completion_coverage item must be an object: {section!r}")
            continue
        missing_item_id = section.get("missing_item_id")
        if not isinstance(missing_item_id, str):
            err("completion_coverage item missing missing_item_id")
            continue
        covered_items.add(missing_item_id)
        if section.get("status") != "covered":
            err(f"completion_coverage.{missing_item_id}.status must be covered")
        impl_ids = string_list(section.get("implementation_refs"), f"completion_coverage.{missing_item_id}.implementation_refs")
        for impl_id in impl_ids:
            if impl_id not in ref_ids:
                err(f"completion_coverage.{missing_item_id} cites unknown implementation ref {impl_id}")
        test_refs = string_list(section.get("test_refs"), f"completion_coverage.{missing_item_id}.test_refs")
        for test_ref in test_refs:
            if test_ref not in ref_ids:
                err(f"completion_coverage.{missing_item_id} cites unknown test ref {test_ref}")
        commands = string_list(section.get("validation_commands"), f"completion_coverage.{missing_item_id}.validation_commands")
        for command in commands:
            if any(forbidden in command for forbidden in FORBIDDEN_COMMAND_SUBSTRINGS):
                err(f"completion_coverage.{missing_item_id} command is forbidden: {command}")
            if "cargo " in command and "rch exec --" not in command:
                err(f"completion_coverage.{missing_item_id} cargo command must use rch: {command}")
        if missing_item_id == "telemetry.primary":
            telemetry_refs = section.get("telemetry_refs")
            if not isinstance(telemetry_refs, list) or not telemetry_refs:
                err("completion_coverage.telemetry.primary must cite telemetry_refs")

    if covered_items != EXPECTED_MISSING_ITEMS:
        err(f"completion_coverage must cover {sorted(EXPECTED_MISSING_ITEMS)}")

    telemetry_contract = contract.get("telemetry_contract")
    if not isinstance(telemetry_contract, dict):
        err("telemetry_contract must be an object")
        telemetry_contract = {}
    else:
        events = set(string_list(telemetry_contract.get("required_events"), "telemetry_contract.required_events"))
        if events != EXPECTED_EVENTS:
            err(f"telemetry_contract.required_events must match {sorted(EXPECTED_EVENTS)}")
        for field in ["report_path", "log_path"]:
            if not isinstance(telemetry_contract.get(field), str):
                err(f"telemetry_contract.{field} must be a string")
        string_list(telemetry_contract.get("required_report_fields"), "telemetry_contract.required_report_fields")
        string_list(telemetry_contract.get("required_summary_fields"), "telemetry_contract.required_summary_fields")

    return coverage, telemetry_contract


def run_fixture_probe() -> dict[str, Any]:
    scripts = ROOT / "scripts/gentoo"
    fixtures = ROOT / "tests/gentoo/fixtures/sample_logs"
    sys.path.insert(0, str(scripts))
    log_parser = load_module("log_parser", scripts / "log_parser.py")
    log_stats = load_module("log_stats", scripts / "log_stats.py")
    log_validator = load_module("log_validator", scripts / "log_validator.py")

    runtime_parser = log_parser.LogParser(strict=True)
    runtime_entries = list(runtime_parser.parse_file(fixtures / "valid_runtime.jsonl"))
    hook_entries = list(log_parser.LogParser(strict=True).parse_file(fixtures / "valid_hook.jsonl"))

    strict_invalid_json_failed = False
    try:
        list(log_parser.LogParser(strict=True).parse_file(fixtures / "invalid_json.jsonl"))
    except log_parser.ParseError:
        strict_invalid_json_failed = True

    non_strict_parser = log_parser.LogParser(strict=False)
    missing_field_entries = list(non_strict_parser.parse_file(fixtures / "invalid_missing_field.jsonl"))

    all_entries = runtime_entries + hook_entries
    stats = log_stats.LogStats()
    stats.extend(all_entries)
    telemetry_summary = stats.to_dict()
    issues = log_validator.LogValidator().validate(all_entries)

    if len(runtime_entries) != 2:
        err(f"valid_runtime.jsonl should produce 2 entries, got {len(runtime_entries)}")
    if len(hook_entries) != 1:
        err(f"valid_hook.jsonl should produce 1 entry, got {len(hook_entries)}")
    if runtime_entries and runtime_entries[0].call != "malloc":
        err("first runtime fixture entry should normalize as malloc")
    if runtime_entries and runtime_entries[0].action != "ClampSize":
        err("first runtime fixture entry should preserve ClampSize action")
    if hook_entries and hook_entries[0].call != "__hook_event__":
        err("hook fixture should normalize event to __hook_event__ call")
    if hook_entries and hook_entries[0].action != "hook_enable":
        err("hook fixture should normalize enable event to hook_enable action")
    if not strict_invalid_json_failed:
        err("strict parser must reject invalid_json.jsonl")
    if missing_field_entries:
        err("non-strict missing-field fixture should yield no valid entries")
    if len(non_strict_parser.errors) != 1:
        err(f"non-strict missing-field fixture should collect one error, got {len(non_strict_parser.errors)}")
    if issues:
        err(f"valid runtime and hook fixtures should have no validation issues, got {len(issues)}")

    telemetry_summary.update(
        {
            "fixture_count": 4,
            "runtime_entries": len(runtime_entries),
            "hook_entries": len(hook_entries),
            "parser_error_count": len(non_strict_parser.errors),
            "validation_issue_count": len(issues),
            "strict_invalid_json_failed": strict_invalid_json_failed,
            "fixture_inputs": [
                "tests/gentoo/fixtures/sample_logs/valid_runtime.jsonl",
                "tests/gentoo/fixtures/sample_logs/valid_hook.jsonl",
                "tests/gentoo/fixtures/sample_logs/invalid_json.jsonl",
                "tests/gentoo/fixtures/sample_logs/invalid_missing_field.jsonl",
            ],
        }
    )

    return {
        "unit_test_inventory": [
            "LogParserTests.test_parse_valid_runtime_log",
            "LogParserTests.test_parse_valid_hook_log",
            "LogParserTests.test_invalid_json_raises_in_strict_mode",
            "LogParserTests.test_invalid_line_collected_in_non_strict_mode",
            "LogParserTests.test_stats_and_validator",
        ],
        "telemetry_summary": telemetry_summary,
    }


def event_row(event: str, outcome: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": now(),
        "trace_id": f"{COMPLETION_BEAD}::log-parsing-validation-completion::001",
        "level": "info" if outcome == "pass" else "error",
        "event": event,
        "bead_id": COMPLETION_BEAD,
        "stream": "conformance",
        "gate": "log_parsing_validation_completion_contract",
        "outcome": outcome,
        "failure_signature": "none" if outcome == "pass" else "contract_validation_failed",
        "artifact_refs": [
            rel(CONTRACT),
            rel(REPORT),
            rel(LOG),
        ],
        "details": details,
    }


contract = load_json(CONTRACT, "contract")
coverage, telemetry_contract = validate_manifest(contract)
probe: dict[str, Any] = {}
try:
    probe = run_fixture_probe()
except Exception as exc:  # noqa: BLE001
    err(f"fixture probe failed: {exc}")
    probe = {"unit_test_inventory": [], "telemetry_summary": {}}

outcome = "fail" if errors else "pass"
rows: list[dict[str, Any]] = [
    event_row(
        "log_parsing_source_bound",
        outcome,
        {
            "implementation_ref_count": len(contract.get("implementation_refs", []))
            if isinstance(contract.get("implementation_refs"), list)
            else 0,
            "source_paths": contract.get("source_paths", {}),
        },
    ),
    event_row(
        "log_parsing_unit_bound",
        outcome,
        {
            "missing_item_id": "tests.unit.primary",
            "unit_tests": probe.get("unit_test_inventory", []),
        },
    ),
    event_row(
        "log_parsing_telemetry_bound",
        outcome,
        {
            "missing_item_id": "telemetry.primary",
            "telemetry_summary": probe.get("telemetry_summary", {}),
            "telemetry_contract": telemetry_contract,
        },
    ),
    event_row(
        "log_parsing_completion_summary",
        outcome,
        {
            "bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "missing_items": sorted(EXPECTED_MISSING_ITEMS),
            "error_count": len(errors),
        },
    ),
]

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "generated_utc": now(),
    "status": outcome,
    "audit_bindings": coverage,
    "unit_test_inventory": probe.get("unit_test_inventory", []),
    "telemetry_summary": probe.get("telemetry_summary", {}),
    "telemetry_log_events": [row["event"] for row in rows],
    "errors": errors,
}

write_json(REPORT, report)
write_jsonl(LOG, rows)

if errors:
    for message in errors:
        print(f"ERROR: {message}", file=sys.stderr)
    print(f"FAIL {COMPLETION_BEAD} log parsing validation completion contract errors={len(errors)}", file=sys.stderr)
    sys.exit(1)

summary = probe["telemetry_summary"]
print(
    "PASS "
    f"{COMPLETION_BEAD} "
    f"entries={summary.get('total_entries')} "
    f"runtime={summary.get('runtime_entries')} "
    f"hook={summary.get('hook_entries')} "
    f"parser_errors={summary.get('parser_error_count')} "
    f"validation_issues={summary.get('validation_issue_count')}"
)
PY
