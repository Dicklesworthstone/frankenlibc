#!/usr/bin/env bash
# check_standalone_host_dependency_probe_completion_contract.sh - bd-zyck1.35.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_STANDALONE_HOST_PROBE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/standalone_host_dependency_probe_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STANDALONE_HOST_PROBE_COMPLETION_OUT_DIR:-$ROOT/target/conformance/standalone_host_dependency_probe_completion_contract}"
REPORT="${FRANKENLIBC_STANDALONE_HOST_PROBE_COMPLETION_REPORT:-$OUT_DIR/standalone_host_dependency_probe_completion_contract.report.json}"
LOG="${FRANKENLIBC_STANDALONE_HOST_PROBE_COMPLETION_LOG:-$OUT_DIR/standalone_host_dependency_probe_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
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

EXPECTED_SCHEMA = "standalone_host_dependency_probe_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "standalone_host_dependency_probe_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-zyck1.35"
COMPLETION_BEAD = "bd-zyck1.35.1"
EXPECTED_MISSING_ITEMS = {"tests.conformance.primary"}
EXPECTED_EVENTS = {
    "standalone_host_probe_conformance_bound",
    "standalone_host_probe_stale_source_bound",
    "standalone_host_probe_completion_contract_validated",
}
EXPECTED_FRESHNESS_POLICY = {
    "recorded_source_commit_field": "source_commit",
    "comparison_target": "current git HEAD",
    "stale_result": "block_standalone_host_dependency_probe_evidence",
    "host_dependency_probe_evidence_allowed_when_stale": False,
    "rejected_evidence_kind": "stale_source_commit",
}
FORBIDDEN_COMMAND_SUBSTRINGS = {"git reset --hard", "git clean -fd", "rm -rf"}

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


def function_exists(source_text: str, name: str) -> bool:
    return (
        f"fn {name}(" in source_text
        or f"fn {name}<" in source_text
        or f"def {name}(" in source_text
    )


def validate_command(command: Any, context: str) -> None:
    if not isinstance(command, str) or not command:
        err(f"{context} command must be a non-empty string")
        return
    for forbidden in FORBIDDEN_COMMAND_SUBSTRINGS:
        if forbidden in command:
            err(f"{context} command contains forbidden substring {forbidden!r}: {command}")
    if "cargo " in command and "rch exec" not in command:
        err(f"{context} cargo validation must be rch-backed: {command}")


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
        if anchor not in lines[line - 1]:
            err(f"implementation_refs[{index}] missing anchor {anchor!r} at {path_text}:{line}")
            continue
        checked += 1
    return checked


def validate_test_refs(binding_id: str, refs: Any, artifacts: dict[str, str]) -> int:
    if not isinstance(refs, list) or not refs:
        err(f"binding {binding_id} required_test_refs must be non-empty")
        return 0
    cache: dict[str, str] = {}
    found = 0
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
        text = cache.setdefault(source, (ROOT / artifacts[source]).read_text(encoding="utf-8"))
        if not function_exists(text, name):
            err(f"binding {binding_id} references missing test {source}::{name}")
            continue
        found += 1
    return found


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
        artifact_key = binding.get("artifact_key")
        if not isinstance(artifact_key, str) or artifact_key not in artifacts:
            err(f"binding {binding_id} artifact_key must name a source artifact")
            continue
        artifact = load_json(ROOT / artifacts[artifact_key], f"binding {binding_id} artifact")
        identity_field = binding.get("identity_field")
        identity_value = binding.get("identity_value")
        require(
            isinstance(identity_field, str) and artifact.get(identity_field) == identity_value,
            f"binding {binding_id} identity mismatch",
        )
        covers = set(strings(binding.get("covers"), f"binding {binding_id}.covers"))
        require(covers == EXPECTED_MISSING_ITEMS, f"binding {binding_id} must cover tests.conformance.primary")
        for key in strings(binding.get("required_artifact_keys"), f"binding {binding_id}.required_artifact_keys"):
            require(key in artifacts, f"binding {binding_id} required artifact key not declared: {key}")
        test_ref_count += validate_test_refs(binding_id, binding.get("required_test_refs"), artifacts)
        for command_index, command in enumerate(strings(binding.get("required_commands"), f"binding {binding_id}.required_commands")):
            validate_command(command, f"binding {binding_id}.required_commands[{command_index}]")
        binding["_covers_set"] = covers
        bindings[binding_id] = binding
    return bindings, test_ref_count


def validate_completion_coverage(manifest: dict[str, Any], bindings: dict[str, dict[str, Any]]) -> dict[str, int]:
    raw = manifest.get("completion_coverage")
    if not isinstance(raw, list) or len(raw) != 1:
        err("completion_coverage must contain exactly tests.conformance.primary")
        return {"coverage_count": 0, "binding_count": 0}
    row = raw[0]
    if not isinstance(row, dict):
        err("completion_coverage[0] must be an object")
        return {"coverage_count": 0, "binding_count": 0}
    require(row.get("missing_item_id") == "tests.conformance.primary", "completion coverage must target tests.conformance.primary")
    require(row.get("status") == "covered", "tests.conformance.primary status must be covered")
    binding_ids = strings(row.get("binding_ids"), "coverage tests.conformance.primary.binding_ids")
    require(
        "standalone_host_dependency_probe_stale_source_gate" in binding_ids,
        "tests.conformance.primary must bind standalone host dependency stale-source gate",
    )
    for binding_id in binding_ids:
        binding = bindings.get(binding_id)
        if not binding:
            err(f"coverage references unknown binding {binding_id}")
            continue
        require("tests.conformance.primary" in binding.get("_covers_set", set()), f"binding {binding_id} does not cover tests.conformance.primary")
    for command_index, command in enumerate(strings(row.get("validation_commands"), "coverage tests.conformance.primary.validation_commands")):
        validate_command(command, f"coverage tests.conformance.primary.validation_commands[{command_index}]")
    return {"coverage_count": 1, "binding_count": len(set(binding_ids))}


def validate_conformance_contract(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest.get("conformance_contract")
    if not isinstance(contract, dict):
        err("conformance_contract must be an object")
        return {}
    require(contract.get("required_source_commit_freshness_policy") == EXPECTED_FRESHNESS_POLICY, "required_source_commit_freshness_policy mismatch")
    plan = load_json(ROOT / artifacts.get("probe_plan", ""), "standalone host dependency probe plan")
    require(plan.get("schema_version") == "v1", "probe plan schema_version must be v1")
    require(plan.get("bead") == contract.get("source_plan_bead"), "probe plan source bead mismatch")
    require(plan.get("source_commit_freshness_policy") == EXPECTED_FRESHNESS_POLICY, "probe plan source_commit_freshness_policy mismatch")
    require(plan.get("source_commit") == "current", "probe plan source_commit must use current marker")
    require(len(plan.get("required_log_fields", [])) == contract.get("required_log_field_count"), "required_log_field_count mismatch")
    require(len(plan.get("required_probe_types", [])) == contract.get("required_probe_type_count"), "required_probe_type_count mismatch")
    require(len(plan.get("probe_rows", [])) == contract.get("required_probe_count"), "required_probe_count mismatch")
    summary = plan.get("summary", {})
    if not isinstance(summary, dict):
        err("probe plan summary must be an object")
        summary = {}
    for contract_key, summary_key in [
        ("required_probe_count", "probe_count"),
        ("required_probe_type_count", "required_probe_type_count"),
        ("required_claim_blocked_count", "claim_blocked_count"),
        ("required_l2_l3_blocker_count", "l2_l3_blocker_count"),
        ("required_forge_projection_field_count", "forge_projection_field_count"),
        ("required_forge_projection_blocking_reason_count", "forge_projection_blocking_reason_count"),
        ("required_forge_projection_failure_signature_count", "forge_projection_failure_signature_count"),
    ]:
        require(summary.get(summary_key) == contract.get(contract_key), f"summary.{summary_key} mismatch")
    require(
        int(summary.get("negative_claim_test_count", 0)) >= int(contract.get("required_negative_claim_test_count_min", 0)),
        "negative claim test count below minimum",
    )
    source_text = (ROOT / artifacts.get("probe_test", "")).read_text(encoding="utf-8")
    for test_name in strings(contract.get("required_stale_source_tests"), "conformance_contract.required_stale_source_tests"):
        require(function_exists(source_text, test_name), f"required stale-source test missing: {test_name}")
    return {
        "probe_count": summary.get("probe_count", 0),
        "claim_blocked_count": summary.get("claim_blocked_count", 0),
        "required_probe_type_count": summary.get("required_probe_type_count", 0),
        "negative_claim_test_count": summary.get("negative_claim_test_count", 0),
        "stale_result": EXPECTED_FRESHNESS_POLICY["stale_result"],
        "rejected_evidence_kind": EXPECTED_FRESHNESS_POLICY["rejected_evidence_kind"],
    }


def validate_telemetry_contract(manifest: dict[str, Any]) -> dict[str, Any]:
    telemetry = manifest.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return {"fields": [], "required_events": 0}
    require(telemetry.get("report_schema") == EXPECTED_REPORT_SCHEMA, "telemetry_contract.report_schema mismatch")
    required_events = set(strings(telemetry.get("required_events"), "telemetry_contract.required_events"))
    require(required_events == EXPECTED_EVENTS, f"telemetry events must be {sorted(EXPECTED_EVENTS)}")
    fields = set(strings(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    core = {"timestamp", "trace_id", "event", "status", "artifact_refs", "source_commit", "probe_count", "claim_blocked_count", "stale_result", "failure_signature"}
    require(core <= fields, f"telemetry required fields missing {sorted(core - fields)}")
    return {"fields": sorted(fields), "required_events": len(required_events)}


def append_event(
    event: str,
    missing_items: list[str],
    binding_ids: list[str],
    artifact_refs: list[str],
    validation_commands: list[str],
    summary: dict[str, Any],
) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}::standalone-host-probe::{len(events) + 1:03d}",
            "level": "info",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": "pass",
            "evidence_binding_ids": binding_ids,
            "missing_item_ids": missing_items,
            "artifact_refs": artifact_refs,
            "validation_commands": validation_commands,
            "source_commit": git_head(),
            "probe_count": summary.get("probe_count", 0),
            "claim_blocked_count": summary.get("claim_blocked_count", 0),
            "stale_result": summary.get("stale_result", ""),
            "failure_signature": "none",
        }
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
conformance_summary = validate_conformance_contract(manifest, artifacts)
telemetry_summary = validate_telemetry_contract(manifest)

if not errors:
    coverage = manifest["completion_coverage"][0]
    binding_ids = [str(item) for item in coverage.get("binding_ids", []) if isinstance(item, str)]
    append_event(
        "standalone_host_probe_conformance_bound",
        ["tests.conformance.primary"],
        binding_ids,
        [artifacts["probe_plan"], artifacts["standalone_artifact"]],
        [str(item) for item in coverage.get("validation_commands", []) if isinstance(item, str)],
        conformance_summary,
    )
    append_event(
        "standalone_host_probe_stale_source_bound",
        ["tests.conformance.primary"],
        ["standalone_host_dependency_probe_stale_source_gate"],
        [artifacts["probe_plan"], artifacts["probe_checker"], artifacts["probe_test"]],
        ["bash scripts/check_standalone_host_dependency_probe_plan.sh"],
        conformance_summary,
    )
    append_event(
        "standalone_host_probe_completion_contract_validated",
        sorted(EXPECTED_MISSING_ITEMS),
        sorted(bindings),
        sorted(artifacts.values()),
        ["bash scripts/check_standalone_host_dependency_probe_completion_contract.sh"],
        conformance_summary,
    )

required_fields = set(telemetry_summary.get("fields", []))
for row in events:
    missing = required_fields - set(row)
    if missing:
        err(f"generated telemetry row {row.get('event')} missing fields {sorted(missing)}")
if not errors:
    emitted_events = {str(row.get("event")) for row in events}
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
        "probe_count": conformance_summary.get("probe_count", 0),
        "claim_blocked_count": conformance_summary.get("claim_blocked_count", 0),
        "required_event_count": telemetry_summary.get("required_events", 0),
        "error_count": len(errors),
    },
    "coverage_summary": coverage_summary,
    "conformance_summary": conformance_summary,
    "errors": errors,
}

write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("standalone_host_dependency_probe_completion_contract: FAIL")
    for message in errors:
        print(f"ERROR: {message}")
    raise SystemExit(1)

print(
    "standalone_host_dependency_probe_completion_contract: "
    f"PASS validated {len(bindings)} bindings, {impl_ref_count} refs, "
    f"{coverage_summary.get('coverage_count', 0)} coverage items"
)
PY
