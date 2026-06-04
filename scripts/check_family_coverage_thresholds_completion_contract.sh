#!/usr/bin/env bash
# family_coverage_thresholds_completion_contract - bd-bp8fl.4.3.1 gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_COMPLETION_CONTRACT:-$ROOT/tests/conformance/family_coverage_thresholds_completion_contract.v1.json}"
ARTIFACT="${FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_ARTIFACT:-$ROOT/tests/conformance/family_coverage_thresholds.v1.json}"
SYMBOL_COVERAGE="${FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_SYMBOL_COVERAGE:-$ROOT/tests/conformance/symbol_fixture_coverage.v1.json}"
REPORT="${FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_COMPLETION_REPORT:-$ROOT/target/conformance/family_coverage_thresholds_completion_contract.report.json}"
LOG="${FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_COMPLETION_LOG:-$ROOT/target/conformance/family_coverage_thresholds_completion_contract.log.jsonl}"
SOURCE_REPORT="${FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_SOURCE_REPORT:-$ROOT/target/conformance/family_coverage_thresholds.report.json}"
SOURCE_LOG="${FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_SOURCE_LOG:-$ROOT/target/conformance/family_coverage_thresholds.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$SOURCE_REPORT")" "$(dirname "$SOURCE_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
ARTIFACT="$ARTIFACT" \
SYMBOL_COVERAGE="$SYMBOL_COVERAGE" \
REPORT="$REPORT" \
LOG="$LOG" \
SOURCE_REPORT="$SOURCE_REPORT" \
SOURCE_LOG="$SOURCE_LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
ARTIFACT = pathlib.Path(os.environ["ARTIFACT"])
SYMBOL_COVERAGE = pathlib.Path(os.environ["SYMBOL_COVERAGE"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
SOURCE_REPORT = pathlib.Path(os.environ["SOURCE_REPORT"])
SOURCE_LOG = pathlib.Path(os.environ["SOURCE_LOG"])
DEFAULT_SOURCE_REPORT = ROOT / "target/conformance/family_coverage_thresholds.report.json"
DEFAULT_SOURCE_LOG = ROOT / "target/conformance/family_coverage_thresholds.log.jsonl"

ORIGINAL_BEAD = "bd-bp8fl.4.3"
COMPLETION_BEAD = "bd-bp8fl.4.3.1"
EXPECTED_SCHEMA = "family_coverage_thresholds_completion_contract.v1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
EXPECTED_EVENTS = {
    "family_coverage_thresholds_completion_contract_validated",
    "family_coverage_thresholds_artifact_validated",
    "family_coverage_thresholds_source_gate_validated",
    "family_coverage_thresholds_completion_summary",
}
RUN_ID = "family-coverage-thresholds-completion"

errors: list[str] = []


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
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


def repo_path(value: Any, context: str, *, must_be_file: bool = True) -> pathlib.Path | None:
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


def strings(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
        else:
            out.append(item)
    return out


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


def validate_impl_ref(ref: Any, cache: dict[str, str]) -> str | None:
    if not isinstance(ref, dict):
        err(f"implementation_refs item must be an object: {ref!r}")
        return None
    kind = ref.get("kind")
    path_text = ref.get("path")
    line = ref.get("line")
    anchor = ref.get("anchor")
    if not isinstance(kind, str) or not kind:
        err(f"implementation ref missing kind: {ref!r}")
    if not isinstance(path_text, str) or not path_text:
        err(f"implementation ref missing path: {ref!r}")
        return kind if isinstance(kind, str) else None
    text = cache.setdefault(path_text, text_for(path_text, f"implementation_refs.{kind}"))
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

    audit_items = set(strings(manifest.get("audit", {}).get("missing_items"), "audit.missing_items"))
    if audit_items != EXPECTED_MISSING_ITEMS:
        err(f"audit.missing_items mismatch: expected {sorted(EXPECTED_MISSING_ITEMS)}, got {sorted(audit_items)}")

    raw_paths = manifest.get("source_paths")
    if not isinstance(raw_paths, dict) or not raw_paths:
        err("source_paths must be a non-empty object")
        source_paths: dict[str, str] = {}
    else:
        source_paths = {str(key): str(value) for key, value in raw_paths.items() if isinstance(value, str)}
        for key, value in source_paths.items():
            repo_path(value, f"source_paths.{key}", must_be_file=True)

    cache: dict[str, str] = {}
    impl_kinds = {
        kind
        for kind in (validate_impl_ref(ref, cache) for ref in manifest.get("implementation_refs", []))
        if kind
    }
    if len(impl_kinds) < 25:
        err(f"implementation_refs should cite at least 25 concrete anchors, got {len(impl_kinds)}")

    anchors = manifest.get("source_anchors")
    if not isinstance(anchors, dict) or not anchors:
        err("source_anchors must be a non-empty object")
    else:
        for source_key, expected_anchors in anchors.items():
            path_text = source_paths.get(source_key)
            if not path_text:
                err(f"source_anchors.{source_key} has no source_paths entry")
                continue
            text = cache.setdefault(path_text, text_for(path_text, f"source_anchors.{source_key}"))
            for anchor in strings(expected_anchors, f"source_anchors.{source_key}"):
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
        ref_names = set(strings(section.get("implementation_refs"), f"coverage.{item}.implementation_refs"))
        unknown = ref_names - impl_kinds
        if unknown:
            err(f"{item} cites unknown implementation refs: {sorted(unknown)}")
        test_refs = section.get("test_refs")
        if not isinstance(test_refs, list) or not test_refs:
            err(f"{item} must cite at least one test ref")
            test_refs = []
        for test_ref in test_refs:
            if not isinstance(test_ref, dict):
                err(f"{item} test_ref must be an object: {test_ref!r}")
                continue
            source_key = test_ref.get("source")
            name = test_ref.get("name")
            if not isinstance(source_key, str) or not isinstance(name, str):
                err(f"{item} test_ref missing source/name: {test_ref!r}")
                continue
            path_text = source_paths.get(source_key)
            if not path_text:
                err(f"{item} test_ref source has no source path: {source_key}")
                continue
            source_text = source_text_by_key.setdefault(source_key, text_for(path_text, f"test_ref.{source_key}"))
            if not function_exists(source_text, name):
                err(f"{item} test ref not found: {path_text}::{name}")
        for command in strings(section.get("validation_commands"), f"coverage.{item}.validation_commands"):
            if "cargo " in command:
                if "rch " not in command:
                    err(f"{item} cargo validation must use rch: {command}")
                if "CARGO_TARGET_DIR=" not in command:
                    err(f"{item} cargo validation must set CARGO_TARGET_DIR: {command}")
    if seen_items != EXPECTED_MISSING_ITEMS:
        err(f"completion_coverage items mismatch: expected {sorted(EXPECTED_MISSING_ITEMS)}, got {sorted(seen_items)}")

    telemetry = manifest.get("telemetry_contract", {})
    expected_events = set(strings(telemetry.get("required_completion_events"), "telemetry_contract.required_completion_events"))
    if expected_events != EXPECTED_EVENTS:
        err(f"telemetry required events mismatch: {sorted(expected_events)}")
    for key in ["completion_report", "completion_log", "source_report", "source_log"]:
        if not isinstance(telemetry.get(key), str) or not telemetry[key]:
            err(f"telemetry_contract.{key} must be present")

    return source_paths


def validate_threshold_artifact(manifest: dict[str, Any], artifact: dict[str, Any], symbol_coverage: dict[str, Any]) -> None:
    contract = manifest.get("threshold_artifact_contract")
    if not isinstance(contract, dict):
        err("threshold_artifact_contract must be an object")
        return

    if artifact.get("schema_version") != contract.get("expected_schema_version"):
        err("canonical artifact schema_version mismatch")
    if artifact.get("bead") != contract.get("expected_bead"):
        err("canonical artifact bead mismatch")

    records = artifact.get("threshold_records")
    if not isinstance(records, list) or not records:
        err("threshold_records must be a non-empty array")
        records = []
    summary = artifact.get("summary")
    if not isinstance(summary, dict):
        err("summary must be an object")
        summary = {}

    expected_summary = {
        "family_count": contract.get("expected_family_count"),
        "pass_count": contract.get("expected_pass_count"),
        "fail_count": contract.get("expected_fail_count"),
        "not_applicable_count": contract.get("expected_not_applicable_count"),
        "claim_gate_decision": contract.get("expected_claim_gate_decision"),
        "target_total_symbols": contract.get("expected_target_total_symbols"),
        "target_covered_symbols": contract.get("expected_target_covered_symbols"),
        "target_uncovered_symbols": contract.get("expected_target_uncovered_symbols"),
    }
    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            err(f"summary.{key} mismatch: expected {expected!r}, got {summary.get(key)!r}")

    required_record = set(strings(contract.get("required_record_keys"), "threshold_artifact_contract.required_record_keys"))
    required_coverage = set(strings(contract.get("required_coverage_keys"), "threshold_artifact_contract.required_coverage_keys"))
    required_levels = set(strings(contract.get("required_replacement_levels"), "threshold_artifact_contract.required_replacement_levels"))
    for row in records:
        if not isinstance(row, dict):
            err(f"threshold record must be object: {row!r}")
            continue
        family_id = row.get("family_id", "<unknown>")
        missing = sorted(required_record - set(row))
        if missing:
            err(f"{family_id}: missing threshold record keys {missing}")
        coverage = row.get("coverage", {})
        if not isinstance(coverage, dict):
            err(f"{family_id}: coverage must be object")
            coverage = {}
        missing_coverage = sorted(required_coverage - set(coverage))
        if missing_coverage:
            err(f"{family_id}: missing coverage keys {missing_coverage}")
        levels = row.get("replacement_level_coverage", {})
        if not isinstance(levels, dict):
            err(f"{family_id}: replacement_level_coverage must be object")
            levels = {}
        missing_levels = sorted(required_levels - set(levels))
        if missing_levels:
            err(f"{family_id}: missing replacement levels {missing_levels}")
        if row.get("decision") == "fail" and row.get("failure_signature") in {"", "none", None}:
            err(f"{family_id}: failing row lacks failure_signature")

    family_ids = {row.get("family_id") for row in records if isinstance(row, dict)}
    symbol_family_targets = {
        row.get("module"): int(row.get("target_total", 0))
        for row in symbol_coverage.get("families", [])
        if isinstance(row, dict)
    }
    expected_families = {
        family
        for family, target_total in symbol_family_targets.items()
        if target_total > 0
    }
    allowed_zero_target_extras = {
        row.get("family_id")
        for row in records
        if isinstance(row, dict)
        and row.get("decision") == "not_applicable"
        and symbol_family_targets.get(row.get("family_id"), 0) == 0
    }
    unexpected_extras = family_ids - expected_families - allowed_zero_target_extras
    if expected_families - family_ids or unexpected_extras:
        err(
            "threshold family inventory mismatch: "
            f"missing={sorted(expected_families - family_ids)} extra={sorted(unexpected_extras)}"
        )

    fail_ids = {row["family_id"] for row in records if isinstance(row, dict) and row.get("decision") == "fail"}
    gap_ids = {
        row.get("family_id")
        for row in artifact.get("gaps_requiring_fixture_beads", [])
        if isinstance(row, dict)
    }
    if fail_ids != gap_ids:
        err("gaps_requiring_fixture_beads must match failing threshold records")

    required_log_fields = set(strings(contract.get("required_log_fields"), "threshold_artifact_contract.required_log_fields"))
    artifact_log_fields = set(strings(artifact.get("required_log_fields"), "canonical_artifact.required_log_fields"))
    if not required_log_fields.issubset(artifact_log_fields):
        err(f"canonical artifact missing required log fields: {sorted(required_log_fields - artifact_log_fields)}")


def validate_source_gate(source_paths: dict[str, str], artifact: dict[str, Any]) -> None:
    source_gate = source_paths.get("source_gate", "scripts/check_family_coverage_thresholds.sh")
    source_env = os.environ.copy()
    source_env.update(
        {
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_ARTIFACT": str(ARTIFACT),
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_SYMBOL_COVERAGE": str(SYMBOL_COVERAGE),
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_REPORT": str(SOURCE_REPORT),
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_LOG": str(SOURCE_LOG),
            "FRANKENLIBC_FAMILY_COVERAGE_THRESHOLDS_REGENERATED": str(
                SOURCE_REPORT.with_name("family_coverage_thresholds.regenerated.v1.json")
            ),
        }
    )
    result = subprocess.run(
        ["bash", str(ROOT / source_gate)],
        cwd=ROOT,
        env=source_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        err(
            "source family coverage threshold gate failed: "
            f"stdout={result.stdout[-1000:]} stderr={result.stderr[-1000:]}"
        )
        return

    source_report = load_json(SOURCE_REPORT, "source gate report")
    if source_report.get("status") != "pass":
        err(f"source gate report status must be pass, got {source_report.get('status')!r}")
    if source_report.get("bead") != ORIGINAL_BEAD:
        err(f"source gate report bead must be {ORIGINAL_BEAD}")

    required_logs = set(strings(artifact.get("required_log_fields"), "canonical_artifact.required_log_fields"))
    log_rows: list[dict[str, Any]] = []
    try:
        source_log_text = SOURCE_LOG.read_text(encoding="utf-8")
    except OSError as exc:
        err(f"source gate log missing: {rel(SOURCE_LOG)}: {exc}")
        return
    lines = source_log_text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            err(f"source log line {line_no}: invalid JSON: {exc}")
            continue
        missing = sorted(required_logs - set(row))
        if missing:
            err(f"source log line {line_no}: missing fields {missing}")
        log_rows.append(row)
    records = artifact.get("threshold_records", [])
    if len(log_rows) != len(records):
        err(f"source log row count mismatch: logs={len(log_rows)} records={len(records)}")
    record_families = {row.get("family_id") for row in records if isinstance(row, dict)}
    log_families = {row.get("family_id") for row in log_rows}
    if record_families != log_families:
        err("source log family set does not match threshold_records")


def event(seq: int, event_name: str, outcome: str, **payload: Any) -> dict[str, Any]:
    row = {
        "timestamp": now(),
        "trace_id": f"{COMPLETION_BEAD}::{RUN_ID}::{seq:03d}",
        "level": "info" if outcome == "pass" else "error",
        "event": event_name,
        "bead_id": COMPLETION_BEAD,
        "runtime_mode": "strict",
        "mode": "strict",
        "outcome": outcome,
        "api_family": "conformance",
        "symbol": "family_coverage_thresholds",
        "artifact_refs": [
            rel(CONTRACT),
            rel(ARTIFACT),
            rel(REPORT),
            rel(LOG),
            rel(SOURCE_REPORT),
            rel(SOURCE_LOG),
        ],
        "source_commit": git_head(),
        "failure_signature": "none" if outcome == "pass" else "family_coverage_thresholds_completion_contract_failed",
    }
    row.update(payload)
    return row


def main() -> int:
    start = time.time()
    manifest = load_json(CONTRACT, "completion contract")
    artifact = load_json(ARTIFACT, "family coverage thresholds artifact")
    symbol_coverage = load_json(SYMBOL_COVERAGE, "symbol fixture coverage artifact")

    source_paths = validate_manifest(manifest)
    validate_threshold_artifact(manifest, artifact, symbol_coverage)
    validate_source_gate(source_paths, artifact)

    outcome = "fail" if errors else "pass"
    rows = [
        event(
            1,
            "family_coverage_thresholds_completion_contract_validated",
            outcome,
            missing_items=sorted(EXPECTED_MISSING_ITEMS),
        ),
        event(
            2,
            "family_coverage_thresholds_artifact_validated",
            outcome,
            family_count=artifact.get("summary", {}).get("family_count"),
            fail_count=artifact.get("summary", {}).get("fail_count"),
            claim_gate_decision=artifact.get("summary", {}).get("claim_gate_decision"),
        ),
        event(
            3,
            "family_coverage_thresholds_source_gate_validated",
            outcome,
            source_report=rel(SOURCE_REPORT),
            source_log=rel(SOURCE_LOG),
        ),
        event(
            4,
            "family_coverage_thresholds_completion_summary",
            outcome,
            duration_ms=int(round((time.time() - start) * 1000.0)),
        ),
    ]
    report = {
        "schema_version": "family_coverage_thresholds_completion_contract.report.v1",
        "bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "status": outcome,
        "missing_items": sorted(EXPECTED_MISSING_ITEMS),
        "checks": {
            "manifest": "pass" if not errors else "fail",
            "threshold_artifact": "pass" if not errors else "fail",
            "source_gate": "pass" if not errors else "fail",
            "structured_log": "pass" if not errors else "fail",
        },
        "summary": artifact.get("summary", {}),
        "source_report": rel(SOURCE_REPORT),
        "source_log": rel(SOURCE_LOG),
        "artifact_refs": [rel(CONTRACT), rel(ARTIFACT), rel(REPORT), rel(LOG)],
        "errors": errors,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, rows)
    if errors:
        print(f"FAIL family coverage thresholds completion contract errors={len(errors)}", file=sys.stderr)
        for message in errors:
            print(f"- {message}", file=sys.stderr)
        return 1
    print(
        "PASS family coverage thresholds completion contract "
        f"families={artifact.get('summary', {}).get('family_count')} "
        f"failures={artifact.get('summary', {}).get('fail_count')} "
        f"events={len(rows)}"
    )
    return 0


raise SystemExit(main())
PY
