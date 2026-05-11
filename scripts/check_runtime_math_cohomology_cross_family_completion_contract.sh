#!/usr/bin/env bash
# check_runtime_math_cohomology_cross_family_completion_contract.sh - bd-w2c3.5.2.1 gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_COHOMOLOGY_CONTRACT:-$ROOT/tests/conformance/runtime_math_cohomology_cross_family_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MATH_COHOMOLOGY_OUT_DIR:-$ROOT/target/conformance/runtime_math_cohomology_cross_family_completion_contract}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_COHOMOLOGY_REPORT:-$OUT_DIR/runtime_math_cohomology_cross_family_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_COHOMOLOGY_LOG:-$OUT_DIR/runtime_math_cohomology_cross_family_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "runtime_math_cohomology_cross_family_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "runtime_math_cohomology_cross_family_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-w2c3.5.2"
COMPLETION_BEAD = "bd-w2c3.5.2.1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_EVENTS = {
    "runtime_math_cohomology_completion_contract_validated",
    "runtime_math_cohomology_source_gate_bound",
    "runtime_math_cohomology_unit_e2e_bound",
    "runtime_math_cohomology_completion_summary",
}
EXPECTED_CASE_IDS = {
    "strict_consistency",
    "strict_replay_corruption",
    "hardened_consistency",
    "hardened_replay_corruption",
}
EXPECTED_IMPL_KINDS = {
    "source_checker_strict_consistency",
    "source_checker_hardened_replay",
    "source_checker_structured_log",
    "source_checker_report",
    "source_harness_gate",
    "source_harness_sheaf_cover",
    "source_harness_sheaf_triples",
    "runtime_policy_stage_hash_storage",
    "runtime_policy_compact_stage_hash",
    "runtime_policy_cross_family_overlap",
    "runtime_policy_observer_hook",
    "runtime_policy_test_reset",
    "runtime_policy_strict_unit",
    "runtime_policy_replay_unit",
    "runtime_kernel_overlap_publish",
    "cohomology_monitor_overlap",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


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


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


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


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}::runtime-math-cohomology-completion::{len(events) + 1:03d}",
            "level": "info" if status == "pass" else "error",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "mode": "strict",
            "api_family": "runtime_math",
            "symbol": event,
            "decision_path": "cohomology_completion_contract->source_gate->unit_e2e_binding",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "artifact_refs": artifact_refs,
            "status": status,
            "failure_signature": "none" if status == "pass" else "runtime_math_cohomology_completion_failed",
            "details": details,
        }
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


def validate_impl_refs(manifest: dict[str, Any]) -> set[str]:
    refs = manifest.get("implementation_refs")
    if not isinstance(refs, list) or len(refs) < len(EXPECTED_IMPL_KINDS):
        err("implementation_refs must include concrete source anchors for the full completion surface")
        return set()
    seen: set[str] = set()
    cache: dict[str, str] = {}
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"implementation_refs[{index}] must be an object")
            continue
        kind = ref.get("kind")
        path_text = ref.get("path")
        line = ref.get("line")
        anchor = ref.get("anchor")
        if isinstance(kind, str) and kind:
            seen.add(kind)
        else:
            err(f"implementation_refs[{index}].kind must be a non-empty string")
        if not isinstance(path_text, str):
            err(f"implementation_refs[{index}].path must be a string")
            continue
        text = cache.setdefault(path_text, text_for(path_text, f"implementation_refs.{kind}"))
        lines = text.splitlines()
        if not isinstance(line, int) or line <= 0:
            err(f"{path_text} ref line must be a positive integer")
        elif line > len(lines) or not lines[line - 1].strip():
            err(f"{path_text}:{line} does not point to a non-empty line")
        if not isinstance(anchor, str) or not anchor:
            err(f"{path_text}:{line} missing anchor")
        elif anchor not in text:
            err(f"{path_text} missing anchor {anchor!r}")
    missing = EXPECTED_IMPL_KINDS - seen
    if missing:
        err(f"implementation_refs missing required kinds: {sorted(missing)}")
    return seen


def validate_test_sources(manifest: dict[str, Any]) -> int:
    raw = manifest.get("test_sources", {})
    if not isinstance(raw, dict) or not raw:
        err("test_sources must be a non-empty object")
        return 0
    count = 0
    for source_id, source in raw.items():
        if not isinstance(source, dict):
            err(f"test_sources.{source_id} must be an object")
            continue
        path_text = source.get("path")
        if not isinstance(path_text, str):
            err(f"test_sources.{source_id}.path must be a string")
            continue
        text = text_for(path_text, f"test_sources.{source_id}")
        for name in strings(source.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
            count += 1
            require(function_exists(text, name), f"test_sources.{source_id} missing required test ref {name}")
    return count


def validate_coverage(manifest: dict[str, Any]) -> None:
    coverage = manifest.get("completion_coverage")
    if not isinstance(coverage, list) or len(coverage) != 2:
        err("completion_coverage must contain exactly unit and e2e sections")
        return
    covered = {section.get("missing_item_id") for section in coverage if isinstance(section, dict)}
    require(covered == EXPECTED_MISSING_ITEMS, f"completion_coverage item mismatch: {covered!r}")
    for section in coverage:
        if not isinstance(section, dict):
            err("completion_coverage sections must be objects")
            continue
        require(section.get("status") == "covered", f"{section.get('missing_item_id')} status must be covered")
        strings(section.get("test_refs"), f"completion_coverage.{section.get('missing_item_id')}.test_refs")
        for command in strings(section.get("validation_commands"), f"completion_coverage.{section.get('missing_item_id')}.validation_commands"):
            if "cargo " in command and not (
                command.startswith("rch exec -- ") or command.startswith("rch cargo ")
            ):
                err(f"cargo validation must be rch-backed: {command}")


def require_exact_set(actual: list[str], expected: set[str], context: str) -> None:
    actual_set = set(actual)
    missing = expected - actual_set
    extra = actual_set - expected
    if missing:
        err(f"{context} missing expected cases: {sorted(missing)}")
    if extra:
        err(f"{context} contains unknown cases: {sorted(extra)}")


def validate_required_source_truth(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    truth = manifest.get("required_source_truth")
    if not isinstance(truth, dict):
        err("required_source_truth must be an object")
        return {}

    checker_truth = truth.get("source_checker")
    if not isinstance(checker_truth, dict):
        err("required_source_truth.source_checker must be an object")
        checker_truth = {}
    checker_text = text_for(artifacts.get("source_checker", ""), "source_checker")
    case_ids = strings(checker_truth.get("required_case_ids"), "required_source_truth.source_checker.required_case_ids")
    require_exact_set(case_ids, EXPECTED_CASE_IDS, "required_source_truth.source_checker.required_case_ids")
    for case_id in case_ids:
        require(case_id in checker_text, f"source_checker missing case id {case_id}")
    for test_name in strings(checker_truth.get("required_test_names"), "required_source_truth.source_checker.required_test_names"):
        require(test_name in checker_text, f"source_checker missing test command {test_name}")
    for field in strings(checker_truth.get("required_report_fields"), "required_source_truth.source_checker.required_report_fields"):
        require(field in checker_text, f"source_checker missing required report field {field}")
    for field in strings(checker_truth.get("required_summary_fields"), "required_source_truth.source_checker.required_summary_fields"):
        require(field in checker_text, f"source_checker missing required summary field {field}")
    log_event = checker_truth.get("required_log_event")
    require(isinstance(log_event, str) and log_event in checker_text, "source_checker required_log_event missing")
    for field in strings(checker_truth.get("required_log_fields"), "required_source_truth.source_checker.required_log_fields"):
        require(field in checker_text, f"source_checker missing required log field {field}")
    thresholds = checker_truth.get("expected_thresholds", {})
    if isinstance(thresholds, dict):
        require(thresholds.get("strict_failures_max") == 0, "strict_failures_max must be 0")
        require(thresholds.get("hardened_failures_max") == 0, "hardened_failures_max must be 0")
        require("strict_failures_max" in checker_text, "source_checker missing strict threshold")
        require("hardened_failures_max" in checker_text, "source_checker missing hardened threshold")
    else:
        err("required_source_truth.source_checker.expected_thresholds must be an object")

    runtime_policy = truth.get("runtime_policy")
    if not isinstance(runtime_policy, dict):
        err("required_source_truth.runtime_policy must be an object")
        runtime_policy = {}
    runtime_policy_text = text_for(artifacts.get("runtime_policy", ""), "runtime_policy")
    for name in strings(runtime_policy.get("required_functions"), "required_source_truth.runtime_policy.required_functions"):
        require(function_exists(runtime_policy_text, name), f"runtime_policy missing required function {name}")
    for name in strings(runtime_policy.get("required_test_refs"), "required_source_truth.runtime_policy.required_test_refs"):
        require(function_exists(runtime_policy_text, name), f"runtime_policy missing required test ref {name}")
    for family_ref in strings(runtime_policy.get("required_family_refs"), "required_source_truth.runtime_policy.required_family_refs"):
        require(family_ref in runtime_policy_text, f"runtime_policy missing required family ref {family_ref}")
    observer_call = runtime_policy.get("required_observer_call")
    require(isinstance(observer_call, str) and observer_call in runtime_policy_text, "runtime_policy required_observer_call missing")

    runtime_kernel = truth.get("runtime_kernel")
    if not isinstance(runtime_kernel, dict):
        err("required_source_truth.runtime_kernel must be an object")
        runtime_kernel = {}
    runtime_kernel_text = text_for(artifacts.get("runtime_kernel", ""), "runtime_kernel")
    for name in strings(runtime_kernel.get("required_functions"), "required_source_truth.runtime_kernel.required_functions"):
        require(function_exists(runtime_kernel_text, name), f"runtime_kernel missing required function {name}")
    for call in strings(runtime_kernel.get("required_calls"), "required_source_truth.runtime_kernel.required_calls"):
        require(call in runtime_kernel_text, f"runtime_kernel missing required call {call}")

    cohomology = truth.get("cohomology_monitor")
    if not isinstance(cohomology, dict):
        err("required_source_truth.cohomology_monitor must be an object")
        cohomology = {}
    cohomology_text = text_for(artifacts.get("cohomology_source", ""), "cohomology_monitor")
    for name in strings(cohomology.get("required_functions"), "required_source_truth.cohomology_monitor.required_functions"):
        require(function_exists(cohomology_text, name), f"cohomology_monitor missing required function {name}")
    for name in strings(cohomology.get("required_unit_tests"), "required_source_truth.cohomology_monitor.required_unit_tests"):
        require(function_exists(cohomology_text, name), f"cohomology_monitor missing required unit test {name}")

    sheaf_truth = truth.get("sheaf_artifact")
    if not isinstance(sheaf_truth, dict):
        err("required_source_truth.sheaf_artifact must be an object")
        sheaf_truth = {}
    sheaf = load_json(ROOT / artifacts.get("sheaf_artifact", ""), "sheaf_artifact")
    require(sheaf.get("schema_version") == sheaf_truth.get("schema_version") == "v1", "sheaf_artifact schema_version mismatch")
    require(sheaf.get("bead") == sheaf_truth.get("bead") == "bd-249m.7", "sheaf_artifact bead mismatch")
    cohomology_section = sheaf.get("cohomology", {})
    require(isinstance(cohomology_section, dict) and cohomology_section.get("h1_zero") is True, "sheaf_artifact cohomology.h1_zero must be true")
    open_cover = sheaf.get("open_cover", [])
    cover_ids = sorted(
        row.get("id")
        for row in open_cover
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    )
    expected_cover_ids = sorted(strings(sheaf_truth.get("required_cover_ids"), "required_source_truth.sheaf_artifact.required_cover_ids"))
    require(cover_ids == expected_cover_ids, f"sheaf_artifact open cover mismatch: {cover_ids!r}")
    restriction_maps = sheaf.get("restriction_maps", [])
    min_restrictions = sheaf_truth.get("minimum_restriction_maps")
    require(isinstance(restriction_maps, list) and isinstance(min_restrictions, int) and len(restriction_maps) >= min_restrictions, "sheaf_artifact restriction map count too small")

    return {
        "case_count": len(case_ids),
        "runtime_policy_test_count": len(runtime_policy.get("required_test_refs", [])) if isinstance(runtime_policy.get("required_test_refs"), list) else 0,
        "cohomology_unit_count": len(cohomology.get("required_unit_tests", [])) if isinstance(cohomology.get("required_unit_tests"), list) else 0,
        "open_cover_count": len(cover_ids),
        "restriction_map_count": len(restriction_maps) if isinstance(restriction_maps, list) else 0,
    }


def validate_telemetry_contract(manifest: dict[str, Any]) -> list[str]:
    telemetry = manifest.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return []
    required_events = set(strings(telemetry.get("required_events"), "telemetry_contract.required_events"))
    missing = EXPECTED_EVENTS - required_events
    if missing:
        err(f"telemetry_contract.required_events missing {sorted(missing)}")
    fields = set(strings(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    for field in ["trace_id", "level", "event", "bead_id", "original_bead", "completion_debt_bead", "api_family", "artifact_refs", "failure_signature"]:
        require(field in fields, f"telemetry_contract.required_log_fields missing {field}")
    return sorted(required_events)


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
scorecard = audit.get("scorecard")
if isinstance(scorecard, str):
    repo_path(scorecard, "audit.scorecard", must_be_file=True)
else:
    err("audit.scorecard must be a repo-relative path")

artifacts = validate_source_artifacts(manifest)
impl_kinds = validate_impl_refs(manifest)
test_ref_count = validate_test_sources(manifest)
validate_coverage(manifest)
source_summary = validate_required_source_truth(manifest, artifacts)
telemetry_events = validate_telemetry_contract(manifest)

artifact_refs = sorted(set(artifacts.values()))
append_event(
    "runtime_math_cohomology_completion_contract_validated",
    "pass" if not errors else "fail",
    artifact_refs,
    {
        "schema_version": manifest.get("schema_version"),
        "missing_items": sorted(EXPECTED_MISSING_ITEMS),
        "implementation_ref_count": len(impl_kinds),
    },
)
append_event(
    "runtime_math_cohomology_source_gate_bound",
    "pass" if not errors else "fail",
    artifact_refs,
    source_summary,
)
append_event(
    "runtime_math_cohomology_unit_e2e_bound",
    "pass" if not errors else "fail",
    artifact_refs,
    {
        "test_ref_count": test_ref_count,
        "coverage_items": sorted(EXPECTED_MISSING_ITEMS),
    },
)
append_event(
    "runtime_math_cohomology_completion_summary",
    "pass" if not errors else "fail",
    [rel(REPORT), rel(LOG), rel(CONTRACT)],
    {
        "source_commit": git_head(),
        "required_events": telemetry_events,
        "error_count": len(errors),
    },
)

status = "fail" if errors else "pass"
report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": status,
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "source_commit": git_head(),
    "contract": rel(CONTRACT),
    "report_path": rel(REPORT),
    "log_path": rel(LOG),
    "summary": {
        "missing_items": sorted(EXPECTED_MISSING_ITEMS),
        "implementation_ref_count": len(impl_kinds),
        "test_ref_count": test_ref_count,
        "source_artifact_count": len(artifacts),
        "event_count": len(events),
        "error_count": len(errors),
    },
    "source_summary": source_summary,
    "events": [row["event"] for row in events],
    "errors": errors,
}

write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("FAIL: runtime-math cohomology cross-family completion contract failed")
    for message in errors:
        print(f"  - {message}")
    print(f"Report: {REPORT}")
    print(f"Log: {LOG}")
    raise SystemExit(1)

print(
    "PASS: runtime-math cohomology cross-family completion contract "
    f"validated {len(artifacts)} artifacts, {len(impl_kinds)} refs, {test_ref_count} test refs"
)
print(f"Report: {REPORT}")
print(f"Log: {LOG}")
PY
