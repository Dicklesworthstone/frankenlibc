#!/usr/bin/env bash
# check_runtime_math_in_progress_closure_completion_contract.sh - bd-w2c3.5.4 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_IN_PROGRESS_CONTRACT:-$ROOT/tests/conformance/runtime_math_in_progress_closure_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MATH_IN_PROGRESS_OUT_DIR:-$ROOT/target/conformance/runtime_math_in_progress_closure_completion_contract}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_IN_PROGRESS_REPORT:-$OUT_DIR/runtime_math_in_progress_closure_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_IN_PROGRESS_LOG:-$OUT_DIR/runtime_math_in_progress_closure_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
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
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "runtime_math_in_progress_closure_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "runtime_math_in_progress_closure_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-w2c3.5"
COMPLETION_BEAD = "bd-w2c3.5.4"
EPIC_BEAD = "bd-5vr"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_EVENTS = {
    "runtime_math_in_progress_closure_contract_validated",
    "runtime_math_track4_source_gates_bound",
    "runtime_math_track4_unit_e2e_bound",
    "runtime_math_in_progress_closure_completion_summary",
}
REQUIRED_IMPL_KINDS = {
    "risk_pareto_artifact_bead",
    "risk_pareto_gate_log",
    "cohomology_gate_modes",
    "admission_tooling_contract",
    "retirement_rc1_match",
    "epic_aggregate_gate",
    "epic_aggregate_report",
    "epic_aggregate_harness",
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
            "trace_id": f"{COMPLETION_BEAD}::runtime-math-in-progress-closure::{len(events) + 1:03d}",
            "level": "info" if status == "pass" else "error",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "runtime_math_epic_bead": EPIC_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "mode": "strict",
            "api_family": "runtime_math",
            "symbol": event,
            "decision_path": "track4_completion_contract->source_gate_bindings->unit_e2e_coverage",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "artifact_refs": artifact_refs,
            "status": status,
            "failure_signature": "none" if status == "pass" else "runtime_math_in_progress_closure_completion_failed",
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
        for ref in strings(section.get("test_refs"), f"completion_coverage.{section.get('missing_item_id')}.test_refs"):
            if "::" not in ref and not ref.startswith("scripts/"):
                err(f"test ref should be a function or script ref: {ref}")
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

    child_rows = truth.get("track_children")
    if not isinstance(child_rows, list) or len(child_rows) != 3:
        err("required_source_truth.track_children must list T4.1/T4.2/T4.3")
        child_rows = []
    child_beads = {row.get("bead") for row in child_rows if isinstance(row, dict)}
    require(
        child_beads == {"bd-w2c3.5.1", "bd-w2c3.5.2", "bd-w2c3.5.3"},
        f"track child bead set mismatch: {sorted(str(row) for row in child_beads)}",
    )
    for index, row in enumerate(child_rows):
        if not isinstance(row, dict):
            err(f"required_source_truth.track_children[{index}] must be an object")
            continue
        repo_path(row.get("gate"), f"track_children[{index}].gate", must_be_file=True)
        repo_path(row.get("harness"), f"track_children[{index}].harness", must_be_file=True)
        if "retirement_gate" in row:
            repo_path(row.get("retirement_gate"), f"track_children[{index}].retirement_gate", must_be_file=True)
        if "retirement_harness" in row:
            repo_path(row.get("retirement_harness"), f"track_children[{index}].retirement_harness", must_be_file=True)

    risk = load_json(ROOT / artifacts.get("risk_pareto_artifact", ""), "risk_pareto_artifact")
    require(risk.get("schema_version") == "v1", "risk_pareto_artifact schema_version mismatch")
    require(risk.get("bead") == "bd-w2c3.5.1", "risk_pareto_artifact bead mismatch")
    for mode in ("strict", "hardened"):
        mode_row = risk.get(mode)
        require(isinstance(mode_row, dict), f"risk_pareto_artifact missing mode {mode}")
        if isinstance(mode_row, dict):
            require(mode_row.get("steps") == 256, f"risk_pareto_artifact {mode}.steps must be 256")
            action_summary = mode_row.get("action_summary", {})
            require(action_summary.get("decisions") == 256, f"risk_pareto_artifact {mode} decisions must be 256")
            require(isinstance(mode_row.get("family_diagnostics"), list), f"risk_pareto_artifact {mode}.family_diagnostics missing")

    admission = load_json(ROOT / artifacts.get("admission_report", ""), "admission_report")
    require(admission.get("bead") == "bd-w2c3.5.3", "admission_report bead mismatch")
    summary = admission.get("summary", {})
    if not isinstance(summary, dict):
        err("admission_report.summary must be an object")
    else:
        for field in ("total_modules", "admitted", "retired", "blocked"):
            require(field in summary, f"admission_report.summary missing {field}")
        require(summary.get("blocked") == 0, "admission_report.summary.blocked must be zero")
    tooling = admission.get("tooling_contract", {})
    if not isinstance(tooling, dict):
        err("admission_report.tooling_contract must be an object")
    else:
        required_tooling = next(
            (set(strings(row.get("required_tooling_true"), "track_children.required_tooling_true")) for row in child_rows if isinstance(row, dict) and row.get("bead") == "bd-w2c3.5.3"),
            set(),
        )
        for field in sorted(required_tooling):
            require(tooling.get(field) is True, f"admission_report.tooling_contract.{field} must be true")

    retirement = load_json(ROOT / artifacts.get("retirement_policy", ""), "retirement_policy")
    require(isinstance(retirement.get("retirement_criteria", {}).get("rules"), list), "retirement_policy rules missing")
    require(isinstance(retirement.get("active_waivers"), list), "retirement_policy active_waivers missing")
    require(isinstance(retirement.get("current_assessment"), dict), "retirement_policy current_assessment missing")

    epic = truth.get("epic_closure")
    if not isinstance(epic, dict):
        err("required_source_truth.epic_closure must be an object")
        epic = {}
    require(epic.get("source_bead") == EPIC_BEAD, "required_source_truth.epic_closure.source_bead mismatch")
    min_checks = epic.get("minimum_checks")
    require(isinstance(min_checks, int) and min_checks >= 9, "required_source_truth.epic_closure.minimum_checks must be >= 9")
    required_checks = set(strings(epic.get("required_checks"), "required_source_truth.epic_closure.required_checks"))
    expected_checks = {
        "manifest",
        "linkage",
        "linkage_proofs",
        "admission",
        "ablation",
        "governance",
        "classification_matrix",
        "value_proof",
        "reverse_round_contracts",
    }
    missing_checks = expected_checks - required_checks
    if missing_checks:
        err(f"required_source_truth.epic_closure.required_checks missing {sorted(missing_checks)}")

    epic_text = text_for(str(epic.get("aggregate_gate", "")), "required_source_truth.epic_closure.aggregate_gate")
    for check in sorted(expected_checks):
        require(f'"{check}"' in epic_text, f"epic closure gate missing append_check id {check}")
    for event in strings(epic.get("required_log_events"), "required_source_truth.epic_closure.required_log_events"):
        require(event in epic_text, f"epic closure gate missing log event {event}")
    for field in strings(epic.get("required_summary_fields"), "required_source_truth.epic_closure.required_summary_fields"):
        require(field in epic_text, f"epic closure gate missing summary field {field}")

    return {
        "track_children": sorted(str(item) for item in child_beads),
        "risk_modes": ["strict", "hardened"],
        "admission_blocked": summary.get("blocked") if isinstance(summary, dict) else None,
        "epic_required_checks": sorted(required_checks),
        "epic_minimum_checks": min_checks,
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
    for field in [
        "trace_id",
        "event",
        "original_bead",
        "completion_debt_bead",
        "api_family",
        "artifact_refs",
        "failure_signature",
    ]:
        require(field in fields, f"telemetry_contract.required_log_fields missing {field}")
    return sorted(required_events)


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
require(manifest.get("runtime_math_epic_bead") == EPIC_BEAD, f"runtime_math_epic_bead must be {EPIC_BEAD}")
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
    "runtime_math_in_progress_closure_contract_validated",
    "pass" if not errors else "fail",
    artifact_refs,
    {
        "schema_version": manifest.get("schema_version"),
        "missing_items": sorted(EXPECTED_MISSING_ITEMS),
        "implementation_ref_count": len(impl_kinds),
    },
)
append_event(
    "runtime_math_track4_source_gates_bound",
    "pass" if not errors else "fail",
    artifact_refs,
    source_summary,
)
append_event(
    "runtime_math_track4_unit_e2e_bound",
    "pass" if not errors else "fail",
    artifact_refs,
    {
        "test_ref_count": test_ref_count,
        "coverage_items": sorted(EXPECTED_MISSING_ITEMS),
    },
)
append_event(
    "runtime_math_in_progress_closure_completion_summary",
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
    "runtime_math_epic_bead": EPIC_BEAD,
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
    print("FAIL: runtime-math in-progress closure completion contract failed")
    for message in errors:
        print(f"  - {message}")
    print(f"Report: {REPORT}")
    print(f"Log: {LOG}")
    raise SystemExit(1)

print(
    "PASS: runtime-math in-progress closure completion contract "
    f"validated {len(artifacts)} artifacts, {len(impl_kinds)} refs, {test_ref_count} test refs"
)
print(f"Report: {REPORT}")
print(f"Log: {LOG}")
PY
