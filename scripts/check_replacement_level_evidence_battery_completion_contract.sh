#!/usr/bin/env bash
# check_replacement_level_evidence_battery_completion_contract.sh - bd-w2c3.2.3.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_REPLACEMENT_LEVEL_COMPLETION_CONTRACT:-$ROOT/tests/conformance/replacement_level_evidence_battery_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_REPLACEMENT_LEVEL_COMPLETION_OUT_DIR:-$ROOT/target/conformance/replacement_level_evidence_battery_completion_contract}"
REPORT="${FRANKENLIBC_REPLACEMENT_LEVEL_COMPLETION_REPORT:-$OUT_DIR/replacement_level_evidence_battery_completion_contract.report.json}"
LOG="${FRANKENLIBC_REPLACEMENT_LEVEL_COMPLETION_LOG:-$OUT_DIR/replacement_level_evidence_battery_completion_contract.log.jsonl}"
LEVEL_GATE_REPORT="${FRANKENLIBC_REPLACEMENT_LEVEL_GATE_REPORT:-$OUT_DIR/replacement_levels_l1_gate.report.json}"
LEVEL_GATE_LOG="${FRANKENLIBC_REPLACEMENT_LEVEL_GATE_LOG:-$OUT_DIR/replacement_levels_l1_gate.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$LEVEL_GATE_REPORT")" "$(dirname "$LEVEL_GATE_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
LEVEL_GATE_REPORT="$LEVEL_GATE_REPORT" \
LEVEL_GATE_LOG="$LEVEL_GATE_LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import subprocess
from collections import Counter
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
LEVEL_GATE_REPORT = pathlib.Path(os.environ["LEVEL_GATE_REPORT"])
LEVEL_GATE_LOG = pathlib.Path(os.environ["LEVEL_GATE_LOG"])

EXPECTED_SCHEMA = "replacement_level_evidence_battery_completion_contract.v1"
SOURCE_BEAD = "bd-w2c3.2.3"
COMPLETION_BEAD = "bd-w2c3.2.3.1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_EVENTS = {
    "replacement_level_contract_validated",
    "replacement_level_sources_validated",
    "replacement_level_gate_replayed",
    "replacement_level_completion_summary",
}
EXPECTED_SOURCE_KEYS = {
    "replacement_levels",
    "replacement_levels_gate",
    "replacement_levels_harness",
    "support_matrix",
    "l1_crt_matrix",
    "replacement_level_dashboard",
    "callthrough_census",
    "residual_callthrough_blockers",
    "readme",
    "completion_contract",
    "completion_checker",
    "completion_harness",
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


def load_jsonl(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"{label} is not readable: {rel(path)}: {exc}")
        return rows
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            err(f"{label} line {index} is not valid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            err(f"{label} line {index} must be a JSON object")
            continue
        rows.append(row)
    return rows


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


def object_at(value: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        err(f"{context}.{key} must be an object")
        return {}
    return child


def expect_set(actual: list[str], expected: list[str], context: str) -> None:
    if set(actual) != set(expected):
        err(f"{context} mismatch: expected={sorted(expected)} got={sorted(actual)}")


def validate_impl_ref(ref: Any, source_text_cache: dict[str, str]) -> str | None:
    if not isinstance(ref, dict):
        err(f"implementation_refs entry must be an object: {ref!r}")
        return None
    kind = ref.get("kind")
    path_text = ref.get("path")
    line = ref.get("line")
    anchor = ref.get("anchor")
    if not isinstance(kind, str) or not kind:
        err(f"implementation_refs entry missing kind: {ref!r}")
    if not isinstance(path_text, str):
        err(f"implementation_refs entry missing path: {ref!r}")
        return kind if isinstance(kind, str) else None
    text = source_text_cache.setdefault(path_text, text_for(path_text, f"implementation_refs.{kind}"))
    lines = text.splitlines()
    if not isinstance(line, int) or line <= 0:
        err(f"{path_text} ref line must be a positive integer")
    elif line > len(lines) or not lines[line - 1].strip():
        err(f"{path_text}:{line} does not point to a non-empty line")
    if not isinstance(anchor, str) or not anchor:
        err(f"{path_text}:{line} missing anchor")
    elif anchor not in text:
        err(f"{path_text} missing anchor {anchor!r}")
    return kind if isinstance(kind, str) else None


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "source_bead": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "event": event,
            "status": status,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "replacement_level_completion_failed",
            "details": details,
        }
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


def validate_contract(manifest: dict[str, Any]) -> dict[str, str]:
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        err(f"schema_version must be {EXPECTED_SCHEMA}")
    if manifest.get("bead") != SOURCE_BEAD:
        err(f"bead must be {SOURCE_BEAD}")
    if manifest.get("completion_debt_bead") != COMPLETION_BEAD:
        err(f"completion_debt_bead must be {COMPLETION_BEAD}")
    if int(manifest.get("next_audit_score_threshold", 0) or 0) < 800:
        err("next_audit_score_threshold must be at least 800")

    audit = object_at(manifest, "audit", "manifest")
    missing_items = set(string_list(audit.get("missing_items"), "audit.missing_items"))
    if missing_items != EXPECTED_MISSING_ITEMS:
        err(f"audit.missing_items mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing_items)}")

    raw_source_paths = manifest.get("source_paths")
    if not isinstance(raw_source_paths, dict):
        err("source_paths must be an object")
        source_paths: dict[str, str] = {}
    else:
        source_paths = {}
        missing_keys = EXPECTED_SOURCE_KEYS - set(raw_source_paths)
        if missing_keys:
            err(f"source_paths missing required keys: {sorted(missing_keys)}")
        for source, path_text in raw_source_paths.items():
            if isinstance(path_text, str):
                source_paths[str(source)] = path_text
            repo_path(path_text, f"source_paths.{source}")

    source_text_cache: dict[str, str] = {}
    impl_kinds = {
        kind
        for kind in (validate_impl_ref(ref, source_text_cache) for ref in manifest.get("implementation_refs", []))
        if kind
    }
    if len(impl_kinds) < 30:
        err(f"implementation_refs should cite at least 30 concrete anchors, got {len(impl_kinds)}")

    anchors = manifest.get("source_anchors", {})
    if not isinstance(anchors, dict):
        err("source_anchors must be an object")
    else:
        for source, required_anchors in anchors.items():
            path_text = source_paths.get(str(source))
            if not path_text:
                err(f"source_anchors.{source} has no matching source_paths entry")
                continue
            text = source_text_cache.setdefault(path_text, text_for(path_text, f"source_anchors.{source}"))
            for anchor in string_list(required_anchors, f"source_anchors.{source}"):
                if anchor not in text:
                    err(f"{path_text} missing source anchor {anchor!r}")

    coverage = manifest.get("completion_coverage")
    if not isinstance(coverage, list) or not coverage:
        err("completion_coverage must be a non-empty array")
    else:
        covered_items = set()
        for index, section in enumerate(coverage):
            if not isinstance(section, dict):
                err(f"completion_coverage[{index}] must be an object")
                continue
            item_id = section.get("missing_item_id")
            if isinstance(item_id, str):
                covered_items.add(item_id)
            if section.get("status") != "covered":
                err(f"completion_coverage[{index}].status must be covered")
            for ref_kind in string_list(section.get("implementation_refs"), f"completion_coverage[{index}].implementation_refs"):
                if ref_kind not in impl_kinds:
                    err(f"coverage references unknown implementation ref {ref_kind}")
            test_refs = section.get("test_refs")
            if not isinstance(test_refs, list) or not test_refs:
                err(f"completion_coverage[{index}].test_refs must be non-empty")
            else:
                for test_ref in test_refs:
                    if not isinstance(test_ref, dict):
                        err(f"completion_coverage[{index}].test_refs entries must be objects")
                        continue
                    source = test_ref.get("source")
                    name = test_ref.get("name")
                    if not isinstance(source, str) or source not in source_paths:
                        err(f"test_ref source is unknown: {source!r}")
                        continue
                    if not isinstance(name, str) or not name:
                        err(f"test_ref name is missing for source {source}")
                        continue
                    text = source_text_cache.setdefault(
                        source_paths[source],
                        text_for(source_paths[source], f"test_ref.{source}"),
                    )
                    if f"fn {name}" not in text and f"def {name}" not in text:
                        err(f"test ref {source}::{name} does not exist in {source_paths[source]}")
            for command in string_list(section.get("validation_commands"), f"completion_coverage[{index}].validation_commands"):
                if "cargo " in command:
                    if "rch " not in command:
                        err(f"cargo validation command must use rch: {command}")
                    if "CARGO_TARGET_DIR=" not in command:
                        err(f"cargo validation command must use isolated CARGO_TARGET_DIR: {command}")
        if covered_items != EXPECTED_MISSING_ITEMS:
            err(f"completion_coverage missing items mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(covered_items)}")

    expected_events = set(string_list(manifest.get("expected_events"), "expected_events"))
    if expected_events != EXPECTED_EVENTS:
        err(f"expected_events mismatch: expected={sorted(EXPECTED_EVENTS)} got={sorted(expected_events)}")

    return source_paths


def validate_sources(manifest: dict[str, Any], source_paths: dict[str, str]) -> dict[str, Any]:
    policy = object_at(manifest, "policy_requirements", "manifest")
    level_req = object_at(policy, "replacement_levels", "policy_requirements")
    support_req = object_at(policy, "support_matrix", "policy_requirements")
    census_req = object_at(policy, "callthrough_census", "policy_requirements")
    residual_req = object_at(policy, "residual_callthrough_blockers", "policy_requirements")
    dashboard_req = object_at(policy, "replacement_level_dashboard", "policy_requirements")

    levels = load_json(ROOT / source_paths.get("replacement_levels", ""), "replacement levels")
    support = load_json(ROOT / source_paths.get("support_matrix", ""), "support matrix")
    census = load_json(ROOT / source_paths.get("callthrough_census", ""), "callthrough census")
    residual = load_json(ROOT / source_paths.get("residual_callthrough_blockers", ""), "residual blockers")
    dashboard = load_json(ROOT / source_paths.get("replacement_level_dashboard", ""), "replacement level dashboard")

    level_entries = levels.get("levels", [])
    if not isinstance(level_entries, list):
        err("replacement_levels.levels must be an array")
        level_entries = []
    level_ids = [entry.get("level") for entry in level_entries if isinstance(entry, dict)]
    expect_set(
        [str(level_id) for level_id in level_ids],
        string_list(level_req.get("expected_levels"), "policy_requirements.replacement_levels.expected_levels"),
        "replacement_levels.levels",
    )
    level_map = {entry.get("level"): entry for entry in level_entries if isinstance(entry, dict)}

    if levels.get("current_level") != level_req.get("current_level"):
        err(f"current_level mismatch: expected={level_req.get('current_level')} got={levels.get('current_level')}")
    release_level = levels.get("release_tag_policy", {}).get("current_release_level")
    if release_level != level_req.get("current_release_level"):
        err(f"release_tag_policy.current_release_level mismatch: expected={level_req.get('current_release_level')} got={release_level}")

    expected_status = object_at(level_req, "expected_status_by_level", "policy_requirements.replacement_levels")
    for level_id, expected in expected_status.items():
        actual = level_map.get(level_id, {}).get("status")
        if actual != expected:
            err(f"level {level_id} status mismatch: expected={expected} got={actual}")

    assessment = levels.get("current_assessment", {})
    zero_counts = object_at(level_req, "expected_zero_counts", "policy_requirements.replacement_levels")
    for key, expected in zero_counts.items():
        actual = assessment.get(key)
        if actual != expected:
            err(f"current_assessment.{key} mismatch: expected={expected} got={actual}")

    support_symbols = support.get("symbols", [])
    if not isinstance(support_symbols, list):
        err("support_matrix.symbols must be an array")
        support_symbols = []
    support_counts = Counter(row.get("status") for row in support_symbols if isinstance(row, dict))
    if len(support_symbols) != support_req.get("total_symbols"):
        err(f"support_matrix total_symbols mismatch: expected={support_req.get('total_symbols')} got={len(support_symbols)}")
    expected_glibc_callthrough = support_req.get("glibc_callthrough", support_req.get("callthrough"))
    if support_counts.get("GlibcCallThrough", 0) != expected_glibc_callthrough:
        err("support_matrix GlibcCallThrough count mismatch")
    if support_counts.get("Stub", 0) != support_req.get("stub"):
        err("support_matrix Stub count mismatch")
    if assessment.get("total_symbols") != len(support_symbols):
        err("replacement_levels current_assessment.total_symbols must match support_matrix.symbols")
    if assessment.get("glibc_callthrough") != support_counts.get("GlibcCallThrough", 0):
        err("replacement_levels current_assessment.glibc_callthrough must match support_matrix")
    expected_host_backed = support_counts.get("WrapsHostLibc", 0) + support_counts.get("GlibcCallThrough", 0)
    if assessment.get("callthrough") != expected_host_backed:
        err("replacement_levels current_assessment.callthrough must match WrapsHostLibc + GlibcCallThrough")
    if assessment.get("stub") != support_counts.get("Stub", 0):
        err("replacement_levels current_assessment.stub must match support_matrix")

    l1 = level_map.get("L1", {})
    objective_gate = l1.get("objective_gate", {}) if isinstance(l1, dict) else {}
    if objective_gate.get("status") != level_req.get("l1_objective_gate_status"):
        err("L1 objective_gate.status mismatch")
    objective_outcomes = {
        row.get("outcome")
        for row in objective_gate.get("obligations", [])
        if isinstance(row, dict)
    }
    expected_outcomes = set(
        string_list(
            level_req.get("l1_required_objective_outcomes"),
            "policy_requirements.replacement_levels.l1_required_objective_outcomes",
        )
    )
    if not expected_outcomes.issubset(objective_outcomes):
        err(f"L1 objective outcomes missing: expected subset={sorted(expected_outcomes)} got={sorted(objective_outcomes)}")

    l2_blockers = [
        blocker
        for blocker in level_map.get("L2", {}).get("blockers", [])
        if isinstance(blocker, str)
    ]
    required_l2 = level_req.get("l2_required_blocker_substring")
    if not any(isinstance(required_l2, str) and required_l2 in blocker for blocker in l2_blockers):
        err(f"L2 blockers must include refreshed standalone packaging blocker: {required_l2}")
    serialized_levels = json.dumps(levels, sort_keys=True)
    for stale_text in string_list(
        level_req.get("stale_blocker_forbidden_substrings"),
        "policy_requirements.replacement_levels.stale_blocker_forbidden_substrings",
    ):
        if stale_text in serialized_levels:
            err(f"replacement_levels contains stale blocker text: {stale_text}")

    if level_map.get("L3", {}).get("host_glibc_required") != level_req.get("l3_host_glibc_required"):
        err("L3 host_glibc_required mismatch")

    census_summary = census.get("summary", {})
    for key in ("module_count", "symbol_count", "wave_count"):
        if census_summary.get(key) != census_req.get(key):
            err(f"callthrough_census.summary.{key} mismatch")

    residual_truth = residual.get("current_truth", {})
    for key in ("residual_forbidden_count", "claim_status"):
        if residual_truth.get(key) != residual_req.get(key):
            err(f"residual_callthrough_blockers.current_truth.{key} mismatch")

    dashboard_summary = dashboard.get("summary", {})
    for key in ("replacement_level", "claim_status", "first_failing_blocker"):
        if dashboard_summary.get(key) != dashboard_req.get(key):
            err(f"replacement_level_dashboard.summary.{key} mismatch")

    return {
        "current_level": levels.get("current_level"),
        "release_level": release_level,
        "level_statuses": {level_id: level_map.get(level_id, {}).get("status") for level_id in level_ids},
        "support_total": len(support_symbols),
        "glibc_callthrough": assessment.get("glibc_callthrough"),
        "host_backed_callthrough": assessment.get("callthrough"),
        "stub": assessment.get("stub"),
        "l1_objective_gate_status": objective_gate.get("status"),
        "l1_objective_outcomes": sorted(str(outcome) for outcome in objective_outcomes),
        "l2_blocker_count": len(l2_blockers),
        "dashboard_claim_status": dashboard_summary.get("claim_status"),
    }


def replay_replacement_level_gate(manifest: dict[str, Any], source_paths: dict[str, str]) -> dict[str, Any]:
    report_req = object_at(
        object_at(manifest, "policy_requirements", "manifest"),
        "replacement_level_gate_report",
        "policy_requirements",
    )
    gate_path = ROOT / source_paths.get("replacement_levels_gate", "scripts/check_replacement_levels.sh")
    env = os.environ.copy()
    env["FLC_REPLACEMENT_LEVELS_REPORT_PATH"] = str(LEVEL_GATE_REPORT)
    env["FLC_REPLACEMENT_LEVELS_LOG_PATH"] = str(LEVEL_GATE_LOG)
    proc = subprocess.run(
        ["bash", str(gate_path)],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        err(f"replacement level gate failed with exit {proc.returncode}: stdout={proc.stdout} stderr={proc.stderr}")

    report = load_json(LEVEL_GATE_REPORT, "replacement level gate report")
    rows = load_jsonl(LEVEL_GATE_LOG, "replacement level gate log")
    scalar_expectations = {
        "schema_version": report_req.get("schema_version"),
        "bead_id": report_req.get("bead_id"),
        "gate_id": report_req.get("gate_id"),
        "status": report_req.get("status"),
        "current_level": report_req.get("current_level"),
        "objective_gate_status": report_req.get("objective_gate_status"),
    }
    for key, expected in scalar_expectations.items():
        if report.get(key) != expected:
            err(f"replacement level gate report {key} mismatch: expected={expected} got={report.get(key)}")
    summary = report.get("summary", {})
    for key in ("script_check_count", "script_failure_count"):
        if summary.get(key) != report_req.get(key):
            err(f"replacement level gate report summary.{key} mismatch")
    if int(summary.get("l1_crt_proof_row_count", 0) or 0) < int(report_req.get("min_l1_crt_proof_rows", 0) or 0):
        err("replacement level gate report has too few L1 CRT proof rows")
    script_checks = report.get("script_checks", [])
    if not isinstance(script_checks, list) or not script_checks:
        err("replacement level gate report.script_checks must be non-empty")
    elif any(check.get("outcome") != "pass" for check in script_checks if isinstance(check, dict)):
        err("replacement level gate report.script_checks must all pass")

    if not rows:
        err("replacement level gate log must include structured rows")
    sources = {row.get("source") for row in rows}
    for required_source in ("script_check", "objective_gate", "l1_crt_startup_tls_proof_matrix"):
        if required_source not in sources:
            err(f"replacement level gate log missing source={required_source}")
    for index, row in enumerate(rows, start=1):
        if not row.get("trace_id"):
            err(f"replacement level gate log row {index} missing trace_id")
        if not row.get("artifact_ref"):
            err(f"replacement level gate log row {index} missing artifact_ref")
        if row.get("source") == "l1_crt_startup_tls_proof_matrix":
            for field in (
                "bead_id",
                "proof_row_id",
                "runtime_mode",
                "replacement_level",
                "expected_status",
                "actual_status",
                "artifact_refs",
                "source_commit",
                "target_dir",
                "failure_signature",
            ):
                if field not in row:
                    err(f"L1 CRT log row missing {field}")

    return {
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout.splitlines()[-10:],
        "stderr": proc.stderr,
        "report": rel(LEVEL_GATE_REPORT),
        "log": rel(LEVEL_GATE_LOG),
        "status": report.get("status"),
        "current_level": report.get("current_level"),
        "script_check_count": summary.get("script_check_count"),
        "script_failure_count": summary.get("script_failure_count"),
        "log_rows": len(rows),
        "log_sources": sorted(str(source) for source in sources),
    }


start_errors = len(errors)
manifest = load_json(CONTRACT, "replacement level completion contract")
source_paths = validate_contract(manifest)
append_event(
    "replacement_level_contract_validated",
    "pass" if len(errors) == start_errors else "fail",
    [rel(CONTRACT)],
    {"error_count": len(errors) - start_errors, "source_paths": sorted(source_paths)},
)

source_errors = len(errors)
source_summary = validate_sources(manifest, source_paths) if source_paths else {}
append_event(
    "replacement_level_sources_validated",
    "pass" if len(errors) == source_errors else "fail",
    [
        source_paths.get("replacement_levels", "tests/conformance/replacement_levels.json"),
        source_paths.get("support_matrix", "support_matrix.json"),
        source_paths.get("replacement_level_dashboard", "tests/conformance/replacement_level_dashboard.v1.json"),
    ],
    source_summary,
)

gate_errors = len(errors)
gate_summary = replay_replacement_level_gate(manifest, source_paths) if source_paths else {}
append_event(
    "replacement_level_gate_replayed",
    "pass" if len(errors) == gate_errors else "fail",
    [rel(LEVEL_GATE_REPORT), rel(LEVEL_GATE_LOG)],
    gate_summary,
)

event_names = {row["event"] for row in events}
if event_names != EXPECTED_EVENTS - {"replacement_level_completion_summary"}:
    err(f"internal event emission mismatch: got={sorted(event_names)}")

append_event(
    "replacement_level_completion_summary",
    "pass" if not errors else "fail",
    [rel(CONTRACT), rel(REPORT), rel(LOG)],
    {
        "ok": not errors,
        "error_count": len(errors),
        "source_bead": SOURCE_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "git_head": git_head(),
    },
)

report = {
    "schema_version": "replacement_level_evidence_battery_completion_report.v1",
    "source_bead": SOURCE_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "ok": not errors,
    "generated_at": now(),
    "git_head": git_head(),
    "contract": rel(CONTRACT),
    "replacement_level_gate_report": rel(LEVEL_GATE_REPORT),
    "replacement_level_gate_log": rel(LEVEL_GATE_LOG),
    "summary": {
        "errors": len(errors),
        "events": len(events),
        "expected_events": sorted(EXPECTED_EVENTS),
        "emitted_events": sorted(row["event"] for row in events),
        "source_summary": source_summary,
        "gate_summary": gate_summary,
    },
    "errors": errors,
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("check_replacement_level_evidence_battery_completion_contract: FAILED")
    for message in errors:
        print(f"  {message}")
    print(f"Report: {rel(REPORT)}")
    print(f"Log: {rel(LOG)}")
    raise SystemExit(1)

print("check_replacement_level_evidence_battery_completion_contract: PASS")
print(f"Report: {rel(REPORT)}")
print(f"Log: {rel(LOG)}")
PY
