#!/usr/bin/env bash
# check_runtime_math_risk_pareto_completion_contract.sh - bd-w2c3.5.1.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_RISK_PARETO_CONTRACT:-$ROOT/tests/conformance/runtime_math_risk_pareto_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MATH_RISK_PARETO_OUT_DIR:-$ROOT/target/conformance/runtime_math_risk_pareto_completion_contract}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_RISK_PARETO_REPORT:-$OUT_DIR/runtime_math_risk_pareto_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_RISK_PARETO_LOG:-$OUT_DIR/runtime_math_risk_pareto_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "runtime_math_risk_pareto_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "runtime_math_risk_pareto_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-w2c3.5.1"
COMPLETION_BEAD = "bd-w2c3.5.1.1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_EVENTS = {
    "runtime_math_risk_pareto_contract_validated",
    "runtime_math_risk_pareto_calibration_bound",
    "runtime_math_risk_pareto_unit_e2e_bound",
    "runtime_math_risk_pareto_completion_summary",
}
EXPECTED_SOURCE_CHECK_IDS = {
    "calibration_baseline_match",
    "pareto_regret_saturates_at_cap",
    "pareto_budget_enforcement_counter",
    "risk_family_isolation",
    "risk_adverse_rate_monotonicity",
    "real_workload_divergence_guard",
}
REQUIRED_IMPL_KINDS = {
    "artifact_bead",
    "artifact_strict",
    "artifact_hardened",
    "generator_check_diff",
    "source_checker_check_list",
    "source_checker_log_event",
    "harness_gate_report",
    "harness_tamper_negative",
    "pareto_regret_unit",
    "risk_monotonicity_unit",
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
            "trace_id": f"{COMPLETION_BEAD}::runtime-math-risk-pareto-completion::{len(events) + 1:03d}",
            "level": "info" if status == "pass" else "error",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "mode": "strict",
            "api_family": "runtime_math",
            "symbol": event,
            "decision_path": "risk_pareto_completion_contract->calibration_artifact->regression_gate",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "artifact_refs": artifact_refs,
            "status": status,
            "failure_signature": "none" if status == "pass" else "runtime_math_risk_pareto_completion_failed",
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
    if not isinstance(refs, list) or len(refs) < 12:
        err("implementation_refs must include at least 12 concrete source anchors")
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
    missing = REQUIRED_IMPL_KINDS - seen
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


def validate_required_source_truth(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    truth = manifest.get("required_source_truth")
    if not isinstance(truth, dict):
        err("required_source_truth must be an object")
        return {}

    artifact_truth = truth.get("calibration_artifact")
    if not isinstance(artifact_truth, dict):
        err("required_source_truth.calibration_artifact must be an object")
        artifact_truth = {}
    artifact = load_json(ROOT / artifacts.get("calibration_artifact", ""), "calibration_artifact")
    require(artifact.get("schema_version") == artifact_truth.get("schema_version") == "v1", "calibration_artifact schema_version mismatch")
    require(artifact.get("bead") == artifact_truth.get("bead") == ORIGINAL_BEAD, "calibration_artifact bead mismatch")
    require(artifact.get("generator") == artifact_truth.get("generator"), "calibration_artifact generator mismatch")

    config = artifact.get("config", {})
    expected_config = artifact_truth.get("config", {})
    if not isinstance(config, dict) or not isinstance(expected_config, dict):
        err("calibration_artifact config must be an object")
    else:
        for key, expected in expected_config.items():
            require(config.get(key) == expected, f"calibration_artifact config.{key} mismatch")

    mode_summary: dict[str, Any] = {}
    expected_decisions = artifact_truth.get("expected_decisions_per_mode")
    min_family_rows = artifact_truth.get("minimum_family_diagnostics_per_mode")
    expected_adverse = artifact_truth.get("expected_adverse_events_per_mode")
    for mode in strings(artifact_truth.get("required_modes"), "required_source_truth.calibration_artifact.required_modes"):
        mode_row = artifact.get(mode)
        if not isinstance(mode_row, dict):
            err(f"calibration_artifact mode missing: {mode}")
            continue
        for field in strings(artifact_truth.get("required_mode_fields"), "required_source_truth.calibration_artifact.required_mode_fields"):
            require(field in mode_row, f"calibration_artifact.{mode} missing field {field}")
        action_summary = mode_row.get("action_summary", {})
        require(action_summary.get("decisions") == expected_decisions, f"calibration_artifact.{mode}.action_summary.decisions mismatch")
        family_rows = mode_row.get("family_diagnostics", [])
        require(isinstance(family_rows, list) and len(family_rows) >= min_family_rows, f"calibration_artifact.{mode}.family_diagnostics too small")
        adverse_total = 0
        if isinstance(family_rows, list):
            adverse_total = sum(int(row.get("adverse_events", 0)) for row in family_rows if isinstance(row, dict))
        require(adverse_total == expected_adverse, f"calibration_artifact.{mode} adverse event total mismatch")
        mode_summary[mode] = {
            "decisions": action_summary.get("decisions") if isinstance(action_summary, dict) else None,
            "family_diagnostics": len(family_rows) if isinstance(family_rows, list) else 0,
            "adverse_events": adverse_total,
        }

    checker_truth = truth.get("source_checker")
    if not isinstance(checker_truth, dict):
        err("required_source_truth.source_checker must be an object")
        checker_truth = {}
    checker_text = text_for(artifacts.get("source_checker", ""), "source_checker")
    required_check_ids = strings(checker_truth.get("required_check_ids"), "required_source_truth.source_checker.required_check_ids")
    required_check_set = set(required_check_ids)
    missing_check_ids = EXPECTED_SOURCE_CHECK_IDS - required_check_set
    extra_check_ids = required_check_set - EXPECTED_SOURCE_CHECK_IDS
    if missing_check_ids:
        err(f"required_source_truth.source_checker.required_check_ids missing expected checks: {sorted(missing_check_ids)}")
    if extra_check_ids:
        err(f"required_source_truth.source_checker.required_check_ids contains unknown checks: {sorted(extra_check_ids)}")
    for check_id in required_check_ids:
        require(check_id in checker_text, f"required_source_truth.source_checker.required_check_ids missing {check_id}")
    log_event = checker_truth.get("required_log_event")
    require(isinstance(log_event, str) and log_event in checker_text, "source_checker required_log_event missing")
    for field in strings(checker_truth.get("required_report_fields"), "required_source_truth.source_checker.required_report_fields"):
        require(field in checker_text, f"source_checker missing report field {field}")
    for field in strings(checker_truth.get("required_log_fields"), "required_source_truth.source_checker.required_log_fields"):
        require(field in checker_text, f"source_checker missing log field {field}")

    regression = truth.get("regression_tests")
    if not isinstance(regression, dict):
        err("required_source_truth.regression_tests must be an object")
        regression = {}
    source_map = {
        "pareto": text_for(artifacts.get("pareto_source", ""), "regression_tests.pareto"),
        "risk": text_for(artifacts.get("risk_source", ""), "regression_tests.risk"),
        "harness": text_for(artifacts.get("source_harness", ""), "regression_tests.harness"),
    }
    for source_key, source_text in source_map.items():
        for name in strings(regression.get(source_key), f"required_source_truth.regression_tests.{source_key}"):
            require(function_exists(source_text, name), f"regression test missing {source_key}::{name}")

    return {
        "modes": mode_summary,
        "source_check_count": len(required_check_ids),
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
    "runtime_math_risk_pareto_contract_validated",
    "pass" if not errors else "fail",
    artifact_refs,
    {
        "schema_version": manifest.get("schema_version"),
        "missing_items": sorted(EXPECTED_MISSING_ITEMS),
        "implementation_ref_count": len(impl_kinds),
    },
)
append_event(
    "runtime_math_risk_pareto_calibration_bound",
    "pass" if not errors else "fail",
    artifact_refs,
    source_summary,
)
append_event(
    "runtime_math_risk_pareto_unit_e2e_bound",
    "pass" if not errors else "fail",
    artifact_refs,
    {
        "test_ref_count": test_ref_count,
        "coverage_items": sorted(EXPECTED_MISSING_ITEMS),
    },
)
append_event(
    "runtime_math_risk_pareto_completion_summary",
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
    print("FAIL: runtime-math risk/pareto completion contract failed")
    for message in errors:
        print(f"  - {message}")
    print(f"Report: {REPORT}")
    print(f"Log: {LOG}")
    raise SystemExit(1)

print(
    "PASS: runtime-math risk/pareto completion contract "
    f"validated {len(artifacts)} artifacts, {len(impl_kinds)} refs, {test_ref_count} test refs"
)
print(f"Report: {REPORT}")
print(f"Log: {LOG}")
PY
