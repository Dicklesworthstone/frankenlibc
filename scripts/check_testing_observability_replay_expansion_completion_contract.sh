#!/usr/bin/env bash
# check_testing_observability_replay_expansion_completion_contract.sh - bd-w2c3.9.4 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_TRACK8_COMPLETION_CONTRACT:-$ROOT/tests/conformance/testing_observability_replay_expansion_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_TRACK8_COMPLETION_OUT_DIR:-$ROOT/target/conformance/testing_observability_replay_expansion_completion_contract}"
REPORT="${FRANKENLIBC_TRACK8_COMPLETION_REPORT:-$OUT_DIR/testing_observability_replay_expansion_completion_contract.report.json}"
LOG="${FRANKENLIBC_TRACK8_COMPLETION_LOG:-$OUT_DIR/testing_observability_replay_expansion_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import subprocess
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "testing_observability_replay_expansion_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "testing_observability_replay_expansion_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-w2c3.9"
COMPLETION_BEAD = "bd-w2c3.9.4"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
}
EXPECTED_EVENTS = {
    "track8_unit_evidence_bound",
    "track8_e2e_replay_evidence_bound",
    "track8_fuzz_evidence_bound",
    "track8_conformance_evidence_bound",
    "track8_completion_contract_validated",
}
EVENT_BY_MISSING_ITEM = {
    "tests.unit.primary": "track8_unit_evidence_bound",
    "tests.e2e.primary": "track8_e2e_replay_evidence_bound",
    "tests.fuzz.primary": "track8_fuzz_evidence_bound",
    "tests.conformance.primary": "track8_conformance_evidence_bound",
}
FORBIDDEN_COMMAND_SUBSTRINGS = {
    "git reset --hard",
    "git clean -fd",
    "rm -rf",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def strings(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


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


def read_text(path_text: str, context: str) -> str:
    path = repo_path(path_text, context, must_be_file=True)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        err(f"{context} is not UTF-8: {path_text}: {exc}")
        return ""


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
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def collect_strings(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.add(value)
    elif isinstance(value, list):
        for item in value:
            found.update(collect_strings(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            found.add(str(key))
            found.update(collect_strings(item))
    return found


def function_exists(source_text: str, name: str) -> bool:
    return (
        f"fn {name}(" in source_text
        or f"fn {name}<" in source_text
        or f"def {name}(" in source_text
    )


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    raw = manifest.get("source_artifacts", {})
    if not isinstance(raw, dict) or not raw:
        err("source_artifacts must be a non-empty object")
        return {}
    artifacts: dict[str, str] = {}
    for key, value in raw.items():
        if repo_path(value, f"source_artifacts.{key}", must_be_file=True) is not None and isinstance(value, str):
            artifacts[str(key)] = value
    return artifacts


def validate_impl_refs(manifest: dict[str, Any]) -> int:
    refs = manifest.get("implementation_refs")
    if not isinstance(refs, list) or len(refs) < 12:
        err("implementation_refs must include at least 12 concrete source anchors")
        return 0
    checked = 0
    cache: dict[str, list[str]] = {}
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"implementation_refs[{index}] must be an object")
            continue
        path_text = ref.get("path")
        line = ref.get("line")
        anchor = ref.get("anchor")
        path = repo_path(path_text, f"implementation_refs[{index}].path", must_be_file=True)
        if path is None:
            continue
        if not isinstance(line, int) or line <= 0:
            err(f"implementation_refs[{index}].line must be a positive integer")
            continue
        if not isinstance(anchor, str) or not anchor:
            err(f"implementation_refs[{index}].anchor must be non-empty")
            continue
        lines = cache.setdefault(str(path), path.read_text(encoding="utf-8").splitlines())
        if line > len(lines):
            err(f"implementation_refs[{index}] line outside file: {path_text}:{line}")
            continue
        text = lines[line - 1]
        if not text.strip():
            err(f"implementation_refs[{index}] points at blank line: {path_text}:{line}")
            continue
        if anchor not in text:
            err(f"implementation_refs[{index}] missing anchor {anchor!r} at {path_text}:{line}")
            continue
        checked += 1
    return checked


def validate_command(command: Any, context: str) -> None:
    if not isinstance(command, str) or not command:
        err(f"{context} command must be a non-empty string")
        return
    for forbidden in FORBIDDEN_COMMAND_SUBSTRINGS:
        if forbidden in command:
            err(f"{context} command contains forbidden substring {forbidden!r}: {command}")
    if "cargo " in command and "rch exec" not in command:
        err(f"{context} cargo validation must be rch-backed: {command}")


def validate_test_refs(binding_id: str, refs: Any, artifacts: dict[str, str]) -> list[str]:
    if not isinstance(refs, list) or not refs:
        err(f"binding {binding_id} required_test_refs must be non-empty")
        return []
    cache: dict[str, str] = {}
    found: list[str] = []
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"binding {binding_id} required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or source not in artifacts:
            err(f"binding {binding_id} references unknown test source {source!r}")
            continue
        if not isinstance(name, str) or not name:
            err(f"binding {binding_id} test ref name must be non-empty")
            continue
        text = cache.setdefault(source, read_text(artifacts[source], f"test source {source}"))
        if not function_exists(text, name):
            err(f"binding {binding_id} references missing test {source}::{name}")
            continue
        found.append(f"{source}::{name}")
    return found


def artifact_bead_value(artifact: dict[str, Any], key: str) -> str | None:
    value = artifact.get(key)
    if isinstance(value, str):
        return value
    evidence = artifact.get("completion_debt_evidence")
    if isinstance(evidence, dict) and isinstance(evidence.get(key), str):
        return evidence.get(key)
    return None


def validate_evidence_bindings(manifest: dict[str, Any], artifacts: dict[str, str]) -> tuple[dict[str, dict[str, Any]], int]:
    raw = manifest.get("evidence_bindings")
    if not isinstance(raw, list) or not raw:
        err("evidence_bindings must be a non-empty array")
        return {}, 0
    bindings: dict[str, dict[str, Any]] = {}
    test_ref_count = 0
    for index, binding in enumerate(raw):
        if not isinstance(binding, dict):
            err(f"evidence_bindings[{index}] must be an object")
            continue
        binding_id = binding.get("binding_id")
        if not isinstance(binding_id, str) or not binding_id:
            err(f"evidence_bindings[{index}].binding_id must be non-empty")
            continue
        if binding_id in bindings:
            err(f"duplicate evidence binding id: {binding_id}")
        artifact_key = binding.get("artifact_key")
        if not isinstance(artifact_key, str) or artifact_key not in artifacts:
            err(f"binding {binding_id} artifact_key must name a source artifact")
            continue
        artifact = load_json(ROOT / artifacts[artifact_key], f"binding {binding_id} artifact")
        schema_field = binding.get("schema_field")
        expected_schema = binding.get("expected_schema")
        require(
            isinstance(schema_field, str) and artifact.get(schema_field) == expected_schema,
            f"binding {binding_id} schema mismatch",
        )
        require(
            artifact_bead_value(artifact, "bead") == binding.get("original_bead"),
            f"binding {binding_id} original bead mismatch",
        )
        require(
            artifact_bead_value(artifact, "completion_debt_bead") == binding.get("completion_debt_bead"),
            f"binding {binding_id} completion debt bead mismatch",
        )
        covers = set(strings(binding.get("covers"), f"binding {binding_id}.covers"))
        require(bool(covers), f"binding {binding_id} must cover at least one missing item")
        artifact_strings = collect_strings(artifact)
        for missing_item in covers:
            require(
                missing_item in artifact_strings,
                f"binding {binding_id} artifact does not contain covered item {missing_item}",
            )
        for key in strings(binding.get("required_artifact_keys"), f"binding {binding_id}.required_artifact_keys"):
            require(key in artifacts, f"binding {binding_id} required artifact key not declared: {key}")
        test_ref_count += len(validate_test_refs(binding_id, binding.get("required_test_refs"), artifacts))
        for command_index, command in enumerate(strings(binding.get("required_commands"), f"binding {binding_id}.required_commands")):
            validate_command(command, f"binding {binding_id}.required_commands[{command_index}]")
        binding["_covers_set"] = covers
        bindings[binding_id] = binding
    return bindings, test_ref_count


def validate_completion_coverage(manifest: dict[str, Any], bindings: dict[str, dict[str, Any]]) -> dict[str, Any]:
    raw = manifest.get("completion_coverage")
    if not isinstance(raw, list) or not raw:
        err("completion_coverage must be a non-empty array")
        return {"coverage_count": 0, "binding_count": 0}
    seen: set[str] = set()
    all_binding_ids: set[str] = set()
    for index, coverage in enumerate(raw):
        if not isinstance(coverage, dict):
            err(f"completion_coverage[{index}] must be an object")
            continue
        missing_item = coverage.get("missing_item_id")
        if not isinstance(missing_item, str):
            err(f"completion_coverage[{index}].missing_item_id must be a string")
            continue
        seen.add(missing_item)
        require(coverage.get("status") == "covered", f"{missing_item} status must be covered")
        binding_ids = strings(coverage.get("binding_ids"), f"coverage {missing_item}.binding_ids")
        if missing_item == "tests.fuzz.primary":
            require(len(binding_ids) >= 2, "tests.fuzz.primary must be bound by phase1 and phase2 fuzz evidence")
        if missing_item == "tests.conformance.primary":
            require(len(binding_ids) >= 3, "tests.conformance.primary must be bound by structured, fuzz, and fixture evidence")
        for binding_id in binding_ids:
            all_binding_ids.add(binding_id)
            binding = bindings.get(binding_id)
            if not isinstance(binding, dict):
                err(f"coverage {missing_item} references unknown binding {binding_id}")
                continue
            covers = binding.get("_covers_set", set())
            require(missing_item in covers, f"coverage {missing_item} references binding {binding_id} that does not cover it")
        for command_index, command in enumerate(strings(coverage.get("validation_commands"), f"coverage {missing_item}.validation_commands")):
            validate_command(command, f"coverage {missing_item}.validation_commands[{command_index}]")
    require(seen == EXPECTED_MISSING_ITEMS, f"completion_coverage must cover {sorted(EXPECTED_MISSING_ITEMS)}")
    return {"coverage_count": len(raw), "binding_count": len(all_binding_ids)}


def validate_telemetry_contract(manifest: dict[str, Any]) -> dict[str, Any]:
    telemetry = manifest.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return {"required_events": 0, "required_fields": 0}
    require(
        telemetry.get("report_schema") == EXPECTED_REPORT_SCHEMA,
        "telemetry_contract.report_schema mismatch",
    )
    required_events = set(strings(telemetry.get("required_events"), "telemetry_contract.required_events"))
    require(required_events == EXPECTED_EVENTS, f"telemetry events must be {sorted(EXPECTED_EVENTS)}")
    required_fields = set(strings(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    required_core = {
        "timestamp",
        "trace_id",
        "event",
        "status",
        "artifact_refs",
        "failure_signature",
    }
    require(required_core <= required_fields, f"telemetry required fields missing {sorted(required_core - required_fields)}")
    return {"required_events": len(required_events), "required_fields": len(required_fields), "fields": sorted(required_fields)}


def append_event(
    event: str,
    missing_items: list[str],
    binding_ids: list[str],
    artifact_refs: list[str],
    validation_commands: list[str],
    status: str = "pass",
) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}::track8-completion::{len(events) + 1:03d}",
            "level": "info" if status == "pass" else "error",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "evidence_binding_ids": binding_ids,
            "missing_item_ids": missing_items,
            "artifact_refs": artifact_refs,
            "validation_commands": validation_commands,
            "source_commit": git_head(),
            "failure_signature": "none" if status == "pass" else "track8_completion_contract_failed",
        }
    )


def emit_success_events(manifest: dict[str, Any], artifacts: dict[str, str]) -> None:
    for coverage in manifest.get("completion_coverage", []):
        if not isinstance(coverage, dict):
            continue
        missing_item = coverage.get("missing_item_id")
        event = EVENT_BY_MISSING_ITEM.get(str(missing_item))
        if event is None:
            continue
        binding_ids = [str(item) for item in coverage.get("binding_ids", []) if isinstance(item, str)]
        artifact_refs = []
        for binding in manifest.get("evidence_bindings", []):
            if isinstance(binding, dict) and binding.get("binding_id") in binding_ids:
                key = binding.get("artifact_key")
                if isinstance(key, str) and key in artifacts:
                    artifact_refs.append(artifacts[key])
        append_event(
            event,
            [str(missing_item)],
            binding_ids,
            sorted(set(artifact_refs)),
            [str(item) for item in coverage.get("validation_commands", []) if isinstance(item, str)],
        )
    append_event(
        "track8_completion_contract_validated",
        sorted(EXPECTED_MISSING_ITEMS),
        sorted(
            str(binding.get("binding_id"))
            for binding in manifest.get("evidence_bindings", [])
            if isinstance(binding, dict) and isinstance(binding.get("binding_id"), str)
        ),
        sorted(artifacts.values()),
        ["bash scripts/check_testing_observability_replay_expansion_completion_contract.sh"],
    )


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
audit = manifest.get("audit", {})
if not isinstance(audit, dict):
    err("audit must be an object")
    audit = {}
require(set(strings(audit.get("missing_items"), "audit.missing_items")) == EXPECTED_MISSING_ITEMS, "audit.missing_items mismatch")
require(int(audit.get("next_audit_score_threshold", 0)) >= 800, "audit.next_audit_score_threshold must be >= 800")

artifacts = validate_source_artifacts(manifest)
impl_ref_count = validate_impl_refs(manifest)
bindings, test_ref_count = validate_evidence_bindings(manifest, artifacts)
coverage_summary = validate_completion_coverage(manifest, bindings)
telemetry_summary = validate_telemetry_contract(manifest)

if not errors:
    emit_success_events(manifest, artifacts)

required_fields = set(telemetry_summary.get("fields", []))
for row in events:
    missing = required_fields - set(row)
    if missing:
        err(f"generated telemetry row {row.get('event')} missing fields {sorted(missing)}")
emitted_events = {str(row.get("event")) for row in events}
if not errors:
    require(emitted_events == EXPECTED_EVENTS, f"generated telemetry events mismatch: {sorted(emitted_events)}")

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": "fail" if errors else "pass",
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "summary": {
        "artifact_count": len(artifacts),
        "binding_count": len(bindings),
        "implementation_ref_count": impl_ref_count,
        "coverage_count": coverage_summary.get("coverage_count", 0),
        "test_ref_count": test_ref_count,
        "required_event_count": telemetry_summary.get("required_events", 0),
        "error_count": len(errors),
    },
    "coverage_summary": coverage_summary,
    "errors": errors,
}

write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("testing_observability_replay_expansion_completion_contract: FAIL")
    for message in errors:
        print(f"ERROR: {message}")
    raise SystemExit(1)

print(
    "testing_observability_replay_expansion_completion_contract: "
    f"PASS validated {len(bindings)} bindings, {impl_ref_count} refs, "
    f"{coverage_summary.get('coverage_count', 0)} coverage items"
)
PY
