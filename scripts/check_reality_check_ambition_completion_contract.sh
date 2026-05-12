#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_REALITY_CHECK_AMBITION_CONTRACT:-$ROOT/tests/conformance/reality_check_ambition_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_REALITY_CHECK_AMBITION_OUT_DIR:-$ROOT/target/conformance/reality_check_ambition_completion_contract}"
REPORT="${FRANKENLIBC_REALITY_CHECK_AMBITION_REPORT:-$OUT_DIR/reality_check_ambition_completion_contract.report.json}"
LOG="${FRANKENLIBC_REALITY_CHECK_AMBITION_LOG:-$OUT_DIR/reality_check_ambition_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import shlex
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"]).resolve()
CONTRACT = pathlib.Path(os.environ["CONTRACT"]).resolve()
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"]).resolve()
REPORT = pathlib.Path(os.environ["REPORT"]).resolve()
LOG = pathlib.Path(os.environ["LOG"]).resolve()

EXPECTED_SCHEMA = "reality_check_ambition_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "reality_check_ambition_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-bp8fl.17-reality-check-ambition-completion-contract"
SOURCE_BEAD = "bd-bp8fl"
COMPLETION_BEAD = "bd-bp8fl.17"
REQUIRED_SOURCE_IDS = {
    "issues_jsonl",
    "support_matrix",
    "replacement_levels",
    "parent_acceptance_replay_contract",
    "parent_acceptance_replay_checker",
    "parent_acceptance_replay_test",
    "acceptance_fields_contract",
    "acceptance_fields_checker",
    "acceptance_fields_test",
    "reality_bridge_contract",
    "reality_bridge_checker",
    "reality_bridge_test",
    "ambition_graph_lint_contract",
    "ambition_graph_lint_checker",
    "ambition_graph_lint_test",
    "feature_parity_contract",
    "feature_parity_checker",
    "feature_parity_test",
    "fixture_coverage_contract",
    "fixture_coverage_checker",
    "fixture_coverage_test",
    "hard_parts_contract",
    "hard_parts_checker",
    "hard_parts_test",
    "replacement_contract",
    "replacement_checker",
    "replacement_test",
    "workspace_contract",
    "workspace_checker",
    "workspace_test",
    "perf_contract",
    "perf_checker",
    "perf_test",
    "runtime_evidence_contract",
    "runtime_evidence_checker",
    "runtime_evidence_test",
    "workload_handoff_contract",
    "workload_handoff_checker",
    "workload_handoff_test",
    "workstream_done_contract",
    "workstream_done_checker",
    "workstream_done_test",
    "agent_handoff_contract",
    "agent_handoff_checker",
    "rustfmt_quarantine_contract",
    "rustfmt_quarantine_checker",
    "completion_checker",
    "completion_test",
}
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "reality_check_sources_bound",
    "reality_check_child_workstreams_validated",
    "reality_check_claims_validated",
    "reality_check_missing_items_bound",
    "reality_check_command_policy_validated",
    "reality_check_telemetry_validated",
    "reality_check_completion_contract_pass",
}
REQUIRED_LOG_FIELDS = {
    "timestamp",
    "event",
    "source_bead",
    "completion_debt_bead",
    "status",
    "artifact_refs",
    "failure_signature",
    "details",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except Exception:
        return path.as_posix()


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}


def load_jsonl(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if isinstance(row, dict):
                row["_line_number"] = line_number
                rows.append(row)
            else:
                err(f"{label} line {line_number} is not an object")
    except Exception as exc:
        err(f"{label} is not valid JSONL: {rel(path)}: {exc}")
    return rows


def repo_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative without parent traversal: {path_text}")
        return None
    full = (ROOT / path).resolve()
    if ROOT not in full.parents and full != ROOT:
        err(f"{context} escapes repo root: {path_text}")
        return None
    if not full.exists():
        err(f"{context} references missing path: {path_text}")
        return None
    return full


def as_string_list(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        err(f"{context} must be a {'possibly empty ' if allow_empty else ''}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def append_event(
    event: str,
    status: str,
    artifact_refs: list[str],
    details: dict[str, Any] | None = None,
) -> None:
    events.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "source_bead": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "reality_check_ambition_completion_failed",
            "details": details or {},
        }
    )


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


def validate_line_ref(file_line_ref: Any, context: str) -> None:
    if not isinstance(file_line_ref, str) or ":" not in file_line_ref:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = file_line_ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        err(f"{context} has invalid line number: {file_line_ref}")
        return
    path = repo_path(path_text, context)
    if path is None or not path.is_file():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        err(f"{context} references non-UTF8 text: {file_line_ref}")
        return
    if line_no < 1 or line_no > len(lines):
        err(f"{context} points past EOF: {file_line_ref}")
    elif not lines[line_no - 1].strip():
        err(f"{context} points to a blank line: {file_line_ref}")


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}(" in text or f"fn {name}<" in text or f"def {name}(" in text


def has_unrouted_cargo(command: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for index, token in enumerate(tokens):
        if token != "cargo":
            continue
        if "rch" not in tokens[:index]:
            return True
    return False


def validate_sources(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    found: dict[str, str] = {}
    for artifact_id, path_text in artifacts.items():
        path = repo_path(path_text, f"source_artifacts.{artifact_id}")
        if path is not None and isinstance(path_text, str):
            found[str(artifact_id)] = path_text
    missing = REQUIRED_SOURCE_IDS - set(found)
    extra = set(found) - REQUIRED_SOURCE_IDS
    if missing or extra:
        err(f"source_artifacts ids mismatch: missing={sorted(missing)} extra={sorted(extra)}")
    for ref in as_string_list(manifest.get("implementation_refs"), "implementation_refs"):
        validate_line_ref(ref, f"implementation_refs.{ref}")
    append_event(
        "reality_check_sources_bound",
        "pass" if not errors else "fail",
        [found[key] for key in sorted(found) if key in REQUIRED_SOURCE_IDS],
        {"source_count": len(found)},
    )
    return found


def validate_children(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    rows = load_jsonl(ROOT / artifacts.get("issues_jsonl", ""), "issues_jsonl")
    by_id = {str(row.get("id")): row for row in rows if row.get("id")}
    parent = by_id.get(SOURCE_BEAD)
    if not isinstance(parent, dict):
        err(f"missing parent row {SOURCE_BEAD}")
        parent = {}
    child_specs = manifest.get("required_child_workstreams")
    if not isinstance(child_specs, list) or not child_specs:
        err("required_child_workstreams must be a non-empty array")
        child_specs = []

    missing_children: list[str] = []
    open_children: list[str] = []
    artifact_errors: list[str] = []
    closed_count = 0
    child_ids: list[str] = []
    for index, spec in enumerate(child_specs):
        if not isinstance(spec, dict):
            err(f"required_child_workstreams[{index}] must be an object")
            continue
        child_id = spec.get("id")
        if not isinstance(child_id, str) or not child_id:
            err(f"required_child_workstreams[{index}].id must be a non-empty string")
            continue
        child_ids.append(child_id)
        row = by_id.get(child_id)
        if row is None:
            missing_children.append(child_id)
            continue
        if row.get("status") == spec.get("required_status"):
            closed_count += 1
        else:
            open_children.append(f"{child_id}:{row.get('status')}")
        for artifact_id in as_string_list(spec.get("evidence_artifacts"), f"required_child_workstreams.{child_id}.evidence_artifacts"):
            if artifact_id not in artifacts:
                artifact_errors.append(f"{child_id}:{artifact_id}")

    if len(child_specs) != 16:
        err(f"required_child_workstreams must list 16 entries, got {len(child_specs)}")
    if missing_children:
        err(f"missing child workstream rows: {missing_children}")
    if open_children:
        err(f"child workstream status drift: {open_children}")
    if artifact_errors:
        err(f"child workstream references unknown artifacts: {artifact_errors}")
    if len(child_ids) != len(set(child_ids)):
        err("required_child_workstreams contains duplicate child ids")

    append_event(
        "reality_check_child_workstreams_validated",
        "pass" if not (missing_children or open_children or artifact_errors) else "fail",
        [artifacts.get("issues_jsonl", "")],
        {
            "child_workstream_count": len(child_specs),
            "closed_child_workstream_count": closed_count,
            "parent_status": parent.get("status"),
        },
    )
    return {
        "parent_status": parent.get("status"),
        "child_workstream_count": len(child_specs),
        "closed_child_workstream_count": closed_count,
        "missing_children": missing_children,
        "open_children": open_children,
    }


def validate_claims(manifest: dict[str, Any], artifacts: dict[str, str], child_summary: dict[str, Any]) -> dict[str, Any]:
    rows = load_jsonl(ROOT / artifacts.get("issues_jsonl", ""), "issues_jsonl")
    by_id = {str(row.get("id")): row for row in rows if row.get("id")}
    parent = by_id.get(SOURCE_BEAD, {})
    contract = manifest.get("claimed_closure_contract")
    if not isinstance(contract, dict):
        err("claimed_closure_contract must be an object")
        contract = {}

    require(parent.get("status") == contract.get("expected_parent_status"), "parent status drift")
    require(
        child_summary.get("child_workstream_count") == contract.get("expected_child_workstream_count"),
        "child workstream count drift",
    )
    require(
        child_summary.get("closed_child_workstream_count") == contract.get("expected_closed_child_workstream_count"),
        "closed child workstream count drift",
    )

    close_reason = str(parent.get("close_reason", ""))
    missing_close_terms: list[str] = []
    for term in as_string_list(contract.get("required_parent_close_reason_terms"), "claimed_closure_contract.required_parent_close_reason_terms"):
        if term.lower() not in close_reason.lower():
            missing_close_terms.append(term)
    if missing_close_terms:
        err(f"parent close_reason missing terms: {missing_close_terms}")

    acceptance = str(parent.get("acceptance_criteria", ""))
    missing_acceptance_terms: list[str] = []
    for term in as_string_list(contract.get("required_acceptance_terms"), "claimed_closure_contract.required_acceptance_terms"):
        if term.lower() not in acceptance.lower():
            missing_acceptance_terms.append(term)
    if missing_acceptance_terms:
        err(f"parent acceptance_criteria missing terms: {missing_acceptance_terms}")

    support = load_json(ROOT / artifacts.get("support_matrix", ""), "support_matrix")
    support_summary = support.get("summary", {}) if isinstance(support, dict) and isinstance(support.get("summary"), dict) else {}
    replacement = load_json(ROOT / artifacts.get("replacement_levels", ""), "replacement_levels")
    replacement_claim = replacement.get("current_level") or replacement.get("declared_current_level") or replacement.get("replacement_level")

    summary = {
        "parent_status": parent.get("status"),
        "child_workstream_count": child_summary.get("child_workstream_count"),
        "closed_child_workstream_count": child_summary.get("closed_child_workstream_count"),
        "support_total": support_summary.get("total"),
        "support_stub": support_summary.get("stub"),
        "support_glibc_call_through": support_summary.get("glibc_call_through"),
        "replacement_claim": replacement_claim,
        "missing_close_terms": missing_close_terms,
        "missing_acceptance_terms": missing_acceptance_terms,
    }
    append_event(
        "reality_check_claims_validated",
        "pass" if not (missing_close_terms or missing_acceptance_terms) else "fail",
        [
            artifacts.get("issues_jsonl", ""),
            artifacts.get("support_matrix", ""),
            artifacts.get("replacement_levels", ""),
        ],
        summary,
    )
    return summary


def validate_bindings(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    bindings = manifest.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        err("missing_item_bindings must be a non-empty array")
        return {"binding_count": 0, "test_ref_count": 0, "command_count": 0}
    found_ids: set[str] = set()
    test_ref_count = 0
    command_count = 0
    source_cache: dict[str, str] = {}
    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing_item_bindings entries must be objects")
            continue
        item_id = binding.get("id")
        if not isinstance(item_id, str) or not item_id:
            err("missing_item_bindings entry missing id")
            continue
        found_ids.add(item_id)
        for ref in as_string_list(binding.get("implementation_refs"), f"missing_item_bindings.{item_id}.implementation_refs"):
            validate_line_ref(ref, f"missing_item_bindings.{item_id}.implementation_refs.{ref}")
        refs = binding.get("required_test_refs")
        if not isinstance(refs, list) or not refs:
            err(f"missing_item_bindings.{item_id}.required_test_refs must be non-empty")
            refs = []
        for index, ref_obj in enumerate(refs):
            if not isinstance(ref_obj, dict):
                err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] must be an object")
                continue
            source_id = ref_obj.get("source")
            name = ref_obj.get("name")
            if not isinstance(source_id, str) or source_id not in artifacts:
                err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] references unknown source {source_id!r}")
                continue
            if source_id not in source_cache:
                source_path = repo_path(artifacts[source_id], f"test_source.{source_id}")
                source_cache[source_id] = source_path.read_text(encoding="utf-8") if source_path and source_path.is_file() else ""
            if not isinstance(name, str) or not function_exists(source_cache[source_id], name):
                err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] missing test {source_id}::{name}")
            else:
                test_ref_count += 1
        commands = as_string_list(binding.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands")
        for command in commands:
            command_count += 1
            if has_unrouted_cargo(command):
                err(f"missing_item_bindings.{item_id}.required_commands contains bare cargo command: {command}")

    missing = REQUIRED_MISSING_ITEMS - found_ids
    extra = found_ids - REQUIRED_MISSING_ITEMS
    if missing or extra:
        err(f"missing_item_bindings ids mismatch: missing={sorted(missing)} extra={sorted(extra)}")

    append_event(
        "reality_check_missing_items_bound",
        "pass" if not errors else "fail",
        [artifacts.get("completion_checker", ""), artifacts.get("completion_test", "")],
        {"binding_count": len(bindings), "test_ref_count": test_ref_count, "command_count": command_count},
    )
    return {"binding_count": len(bindings), "test_ref_count": test_ref_count, "command_count": command_count}


def validate_command_policy(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    destructive_fragments = ["git reset" + " --hard", "git clean" + " -fd", "rm" + " -rf"]
    checked_files = [
        artifacts.get("completion_checker", ""),
        artifacts.get("completion_test", ""),
        artifacts.get("parent_acceptance_replay_checker", ""),
        artifacts.get("acceptance_fields_checker", ""),
    ]
    violations: list[str] = []
    for path_text in checked_files:
        path = repo_path(path_text, f"command_policy.{path_text}")
        text = path.read_text(encoding="utf-8") if path and path.is_file() else ""
        for fragment in destructive_fragments:
            if fragment in text:
                violations.append(f"{path_text}:{fragment}")
    for binding in manifest.get("missing_item_bindings", []):
        if not isinstance(binding, dict):
            continue
        for command in binding.get("required_commands", []):
            if isinstance(command, str) and has_unrouted_cargo(command):
                violations.append(f"required_command:{command}")
    if violations:
        err(f"command policy violations: {violations}")
    append_event(
        "reality_check_command_policy_validated",
        "pass" if not violations else "fail",
        checked_files,
        {"violation_count": len(violations), "violations": violations},
    )
    return {"violation_count": len(violations), "violations": violations}


def validate_telemetry(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    telemetry = manifest.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return {"required_events": [], "required_fields": []}
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
    if required_events != REQUIRED_EVENTS:
        err(f"telemetry_contract.required_events mismatch: missing={sorted(REQUIRED_EVENTS - required_events)} extra={sorted(required_events - REQUIRED_EVENTS)}")
    required_fields = set(as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    missing_fields = REQUIRED_LOG_FIELDS - required_fields
    if missing_fields:
        err(f"telemetry_contract.required_log_fields missing {sorted(missing_fields)}")
    append_event(
        "reality_check_telemetry_validated",
        "pass" if not errors else "fail",
        [artifacts.get("completion_checker", ""), artifacts.get("completion_test", "")],
        {"required_event_count": len(required_events), "required_field_count": len(required_fields)},
    )
    return {"required_events": sorted(required_events), "required_fields": sorted(required_fields)}


manifest = load_json(CONTRACT, "reality-check ambition completion contract")
if not isinstance(manifest, dict):
    manifest = {}
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version drift")
require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id drift")
require(manifest.get("original_bead") == SOURCE_BEAD, "original_bead drift")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead drift")
require(manifest.get("next_audit_score_threshold", 0) >= 800, "next audit score threshold must be >=800")

artifacts = validate_sources(manifest)
child_summary = validate_children(manifest, artifacts) if artifacts else {}
claim_summary = validate_claims(manifest, artifacts, child_summary) if artifacts else {}
binding_summary = validate_bindings(manifest, artifacts)
command_summary = validate_command_policy(manifest, artifacts)
telemetry_summary = validate_telemetry(manifest, artifacts)

status = "pass" if not errors else "fail"
append_event(
    "reality_check_completion_contract_pass",
    status,
    [rel(CONTRACT), rel(REPORT), rel(LOG)],
    {"error_count": len(errors)},
)

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": status,
    "source_bead": SOURCE_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "manifest": rel(CONTRACT),
    "report": rel(REPORT),
    "log": rel(LOG),
    "source_commit": source_commit(),
    "summaries": {
        "source_count": len(artifacts),
        "children": child_summary,
        "claims": claim_summary,
        "bindings": binding_summary,
        "commands": command_summary,
        "telemetry": telemetry_summary,
    },
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

if errors:
    print("FAIL: reality-check ambition completion contract failed", flush=True)
    for message in errors:
        print(f"- {message}", flush=True)
    raise SystemExit(1)

print(
    f"PASS: reality-check ambition completion contract validated "
    f"sources={len(artifacts)} children={child_summary.get('closed_child_workstream_count')}/"
    f"{child_summary.get('child_workstream_count')} bindings={binding_summary.get('binding_count')}",
    flush=True,
)
PY
