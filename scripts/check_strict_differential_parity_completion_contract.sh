#!/usr/bin/env bash
# check_strict_differential_parity_completion_contract.sh - bd-w2c3.3.1.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_STRICT_DIFFERENTIAL_PARITY_CONTRACT:-$ROOT/tests/conformance/strict_differential_parity_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STRICT_DIFFERENTIAL_PARITY_OUT_DIR:-$ROOT/target/conformance/strict_differential_parity_completion_contract}"
REPORT="${FRANKENLIBC_STRICT_DIFFERENTIAL_PARITY_REPORT:-$OUT_DIR/strict_differential_parity_completion_contract.report.json}"
LOG="${FRANKENLIBC_STRICT_DIFFERENTIAL_PARITY_LOG:-$OUT_DIR/strict_differential_parity_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "strict_differential_parity_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "strict_differential_parity_completion_contract.report.v1"
SOURCE_BEAD = "bd-w2c3.3.1"
COMPLETION_BEAD = "bd-w2c3.3.1.1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_EVENTS = {
    "strict_differential_contract_validated",
    "strict_differential_claimed_surface_validated",
    "strict_differential_source_bindings_validated",
    "strict_differential_completion_summary",
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
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        out.append(item)
    return out


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "event": event,
            "source_bead": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "strict_differential_completion_failed",
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


def validate_impl_refs(manifest: dict[str, Any]) -> None:
    refs = manifest.get("implementation_refs")
    if not isinstance(refs, list) or len(refs) < 20:
        err("implementation_refs must include at least 20 concrete source anchors")
        return
    cache: dict[str, str] = {}
    seen: set[str] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"implementation_refs[{index}] must be an object")
            continue
        kind = ref.get("kind")
        path_text = ref.get("path")
        line = ref.get("line")
        anchor = ref.get("anchor")
        if not isinstance(kind, str) or not kind:
            err(f"implementation_refs[{index}].kind must be a non-empty string")
        else:
            seen.add(kind)
        if not isinstance(path_text, str) or not path_text:
            err(f"implementation_refs[{index}].path must be a non-empty string")
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
    required = {
        "matrix_iconv_utf32_case",
        "matrix_wcschr_case",
        "matrix_wcsstr_case",
        "matrix_wmemchr_case",
        "conformance_iconv_utf32_unit",
        "conformance_wcschr_unit",
        "conformance_wcsstr_unit",
        "conformance_wmemchr_unit",
        "wide_string_ops_harness_e2e",
        "wide_memory_harness_e2e",
        "iconv_harness_e2e",
    }
    missing = required - seen
    if missing:
        err(f"implementation_refs missing required kinds: {sorted(missing)}")


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    raw = manifest.get("source_artifacts", {})
    if not isinstance(raw, dict) or not raw:
        err("source_artifacts must be a non-empty object")
        return {}
    result: dict[str, str] = {}
    for key, value in raw.items():
        if repo_path(value, f"source_artifacts.{key}", must_be_file=True) is not None and isinstance(value, str):
            result[str(key)] = value
    return result


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


def validate_test_sources(manifest: dict[str, Any]) -> int:
    raw = manifest.get("test_sources", {})
    if not isinstance(raw, dict) or not raw:
        err("test_sources must be a non-empty object")
        return 0
    ref_count = 0
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
            ref_count += 1
            require(function_exists(text, name), f"test_sources.{source_id} missing test ref {name}")
    return ref_count


def validate_coverage(manifest: dict[str, Any]) -> None:
    coverage = manifest.get("completion_coverage")
    if not isinstance(coverage, list) or len(coverage) != 2:
        err("completion_coverage must contain exactly unit and e2e sections")
        return
    covered = {section.get("missing_item_id") for section in coverage if isinstance(section, dict)}
    require(covered == EXPECTED_MISSING_ITEMS, f"completion_coverage item mismatch: {covered!r}")
    for section in coverage:
        if not isinstance(section, dict):
            continue
        require(section.get("status") == "covered", "completion_coverage sections must be covered")
        require(section.get("test_refs") and isinstance(section.get("test_refs"), list), "completion_coverage sections must cite test_refs")
        for command in strings(section.get("validation_commands"), f"completion_coverage.{section.get('missing_item_id')}.validation_commands"):
            if "cargo " in command:
                require(command.startswith("rch exec -- "), f"cargo validation command must use rch: {command}")


def validate_manifest(manifest: dict[str, Any]) -> dict[str, str]:
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
    require(manifest.get("original_bead") == SOURCE_BEAD, f"original_bead must be {SOURCE_BEAD}")
    require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
    audit = manifest.get("audit", {})
    if not isinstance(audit, dict):
        err("audit must be an object")
        audit = {}
    require(set(strings(audit.get("missing_items"), "audit.missing_items")) == EXPECTED_MISSING_ITEMS, "audit.missing_items must bind unit+e2e primary items")
    require(audit.get("next_audit_score_threshold", 0) >= 800, "next audit score threshold must be at least 800")
    artifacts = validate_source_artifacts(manifest)
    validate_impl_refs(manifest)
    test_ref_count = validate_test_sources(manifest)
    validate_coverage(manifest)
    telemetry = manifest.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        telemetry = {}
    require(set(strings(telemetry.get("required_events"), "telemetry_contract.required_events")) == EXPECTED_EVENTS, "telemetry_contract.required_events mismatch")
    append_event(
        "strict_differential_contract_validated",
        "pass" if not errors else "fail",
        [rel(CONTRACT)],
        {"source_artifact_count": len(artifacts), "test_ref_count": test_ref_count},
    )
    return artifacts


def validate_source_bindings(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    truth = manifest.get("required_source_truth", {})
    if not isinstance(truth, dict):
        err("required_source_truth must be an object")
        truth = {}

    matrix = load_json(ROOT / artifacts.get("conformance_matrix", ""), "conformance_matrix")
    matrix_truth = truth.get("conformance_matrix", {}) if isinstance(truth.get("conformance_matrix"), dict) else {}
    summary = matrix.get("summary", {})
    require(matrix.get("schema_version") == matrix_truth.get("schema_version"), "conformance_matrix schema_version drift")
    require(matrix.get("bead") == matrix_truth.get("bead"), "conformance_matrix bead drift")
    if isinstance(summary, dict):
        require(summary.get("total_cases", 0) >= matrix_truth.get("min_total_cases", 0), "conformance_matrix total_cases below floor")
        require(summary.get("failed") == matrix_truth.get("expected_failed"), "conformance_matrix failed count drift")
        require(summary.get("errors") == matrix_truth.get("expected_errors"), "conformance_matrix errors count drift")
        require(float(summary.get("pass_rate_percent", 0.0)) == float(matrix_truth.get("expected_pass_rate_percent", 0.0)), "conformance_matrix pass_rate drift")
    else:
        err("conformance_matrix summary must be an object")

    strings(truth.get("structured_log_fields"), "required_source_truth.structured_log_fields", allow_empty=True)

    iconv_scope = truth.get("iconv_scope", {}) if isinstance(truth.get("iconv_scope"), dict) else {}
    core_iconv_text = text_for(artifacts.get("core_iconv", ""), "source_artifacts.core_iconv")
    iconv_checker_text = text_for(artifacts.get("iconv_scope_checker", ""), "source_artifacts.iconv_scope_checker")
    require(str(iconv_scope.get("required_codec", "")) in core_iconv_text, "core iconv missing required UTF-32 codec")
    require(f"[&str; {iconv_scope.get('included_codec_count')}]" in core_iconv_text, "core iconv included codec count drift")
    for token in strings(iconv_scope.get("required_checker_tokens"), "required_source_truth.iconv_scope.required_checker_tokens"):
        require(token in iconv_checker_text or token in core_iconv_text, f"iconv source binding missing token {token}")

    append_event(
        "strict_differential_source_bindings_validated",
        "pass" if not errors else "fail",
        [
            artifacts.get("conformance_matrix", ""),
            artifacts.get("core_iconv", ""),
            artifacts.get("iconv_scope_checker", ""),
        ],
        {"matrix_total_cases": summary.get("total_cases") if isinstance(summary, dict) else None},
    )

    strict_global_false = 0
    cases = matrix.get("cases", [])
    if isinstance(cases, list):
        strict_global_false = sum(
            1
            for row in cases
            if isinstance(row, dict)
            and row.get("mode") == "strict"
            and (row.get("host_parity") is False or row.get("status") != "pass")
        )
    return {"matrix": matrix, "strict_global_false": strict_global_false}


def find_fixture_case(fixture: dict[str, Any], name: str) -> dict[str, Any] | None:
    cases = fixture.get("cases", [])
    if not isinstance(cases, list):
        return None
    for row in cases:
        if isinstance(row, dict) and row.get("name") == name:
            return row
    return None


def validate_claimed_surface(manifest: dict[str, Any], matrix: dict[str, Any]) -> dict[str, Any]:
    surface = manifest.get("claimed_surface", {})
    if not isinstance(surface, dict):
        err("claimed_surface must be an object")
        surface = {}
    required_cases = surface.get("strict_required_cases")
    if not isinstance(required_cases, list) or len(required_cases) < 4:
        err("claimed_surface.strict_required_cases must include at least four strict cases")
        required_cases = []

    matrix_cases = {
        row.get("trace_id"): row
        for row in matrix.get("cases", [])
        if isinstance(row, dict) and isinstance(row.get("trace_id"), str)
    }
    mismatch_count = 0
    validated: list[dict[str, Any]] = []
    fixture_cache: dict[str, dict[str, Any]] = {}

    for index, case in enumerate(required_cases):
        if not isinstance(case, dict):
            err(f"claimed_surface.strict_required_cases[{index}] must be an object")
            continue
        fixture_path = case.get("fixture_path")
        case_name = case.get("case_name")
        mode = case.get("mode")
        function = case.get("function")
        expected_output = case.get("expected_output")
        trace_id = case.get("matrix_trace_id")
        if not all(isinstance(value, str) and value for value in [fixture_path, case_name, mode, function, expected_output, trace_id]):
            err(f"claimed_surface.strict_required_cases[{index}] has missing string fields")
            continue
        fixture = fixture_cache.setdefault(fixture_path, load_json(ROOT / fixture_path, f"fixture {fixture_path}"))
        fixture_case = find_fixture_case(fixture, case_name)
        if fixture_case is None:
            err(f"missing fixture case {case_name} in {fixture_path}")
            continue
        require(fixture_case.get("function") == function, f"fixture case {case_name} function drift")
        require(fixture_case.get("mode") == mode, f"fixture case {case_name} mode drift")
        require(fixture_case.get("expected_output") == expected_output, f"fixture case {case_name} expected_output drift")

        matrix_row = matrix_cases.get(trace_id)
        if matrix_row is None:
            err(f"missing conformance matrix row for {trace_id}")
            mismatch_count += 1
            continue
        row_ok = (
            matrix_row.get("case_name") == case_name
            and matrix_row.get("symbol") == function
            and matrix_row.get("mode") == mode
            and matrix_row.get("status") == "pass"
            and matrix_row.get("host_parity") is True
            and matrix_row.get("expected_output") == expected_output
            and matrix_row.get("actual_output") == expected_output
            and matrix_row.get("note") in (None, "")
        )
        if not row_ok:
            mismatch_count += 1
            err(f"claimed strict parity row drifted for {trace_id}: {matrix_row}")
        validated.append(
            {
                "trace_id": trace_id,
                "case_name": case_name,
                "function": function,
                "fixture": fixture_path,
                "status": matrix_row.get("status"),
                "host_parity": matrix_row.get("host_parity"),
            }
        )

    require(
        mismatch_count <= int(surface.get("strict_claimed_surface_mismatch_count_max", -1)),
        f"claimed strict surface mismatch count {mismatch_count} exceeds maximum",
    )
    append_event(
        "strict_differential_claimed_surface_validated",
        "pass" if not errors else "fail",
        [row.get("fixture", "") for row in validated] + ["tests/conformance/conformance_matrix.v1.json"],
        {"validated_case_count": len(validated), "mismatch_count": mismatch_count},
    )
    return {"validated_cases": validated, "mismatch_count": mismatch_count}


def finalize(manifest: dict[str, Any], source_summary: dict[str, Any], surface_summary: dict[str, Any]) -> int:
    status = "fail" if errors else "pass"
    append_event(
        "strict_differential_completion_summary",
        status,
        [rel(CONTRACT), rel(REPORT), rel(LOG)],
        {
            "validated_case_count": len(surface_summary.get("validated_cases", [])),
            "claimed_surface_mismatch_count": surface_summary.get("mismatch_count"),
            "global_strict_nonparity_rows": source_summary.get("strict_global_false"),
        },
    )
    observed = {event["event"] for event in events}
    missing = sorted(EXPECTED_EVENTS - observed)
    if missing:
        errors.append(f"missing required telemetry events: {missing}")
        status = "fail"
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id"),
        "source_bead": SOURCE_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "source_commit": git_head(),
        "summary": {
            "validated_case_count": len(surface_summary.get("validated_cases", [])),
            "claimed_surface_mismatch_count": surface_summary.get("mismatch_count"),
            "global_strict_nonparity_rows": source_summary.get("strict_global_false"),
            "events": len(events),
        },
        "validated_cases": surface_summary.get("validated_cases", []),
        "events": [event["event"] for event in events],
        "errors": errors,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, events)
    if status == "pass":
        print(f"PASS: strict differential parity completion contract validated ({rel(REPORT)})")
        return 0
    print("FAIL: strict differential parity completion contract failed", flush=True)
    for message in errors:
        print(f"  - {message}", flush=True)
    return 1


manifest = load_json(CONTRACT, "completion contract")
artifacts = validate_manifest(manifest)
source_summary = validate_source_bindings(manifest, artifacts)
surface_summary = validate_claimed_surface(manifest, source_summary.get("matrix", {}))
raise SystemExit(finalize(manifest, source_summary, surface_summary))
PY
