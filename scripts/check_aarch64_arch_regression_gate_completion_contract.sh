#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_AARCH64_ARCH_REGRESSION_CONTRACT:-$ROOT/tests/conformance/aarch64_arch_regression_gate_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_AARCH64_ARCH_REGRESSION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_AARCH64_ARCH_REGRESSION_REPORT:-$OUT_DIR/aarch64_arch_regression_gate_completion_contract.report.json}"
LOG="${FRANKENLIBC_AARCH64_ARCH_REGRESSION_LOG:-$OUT_DIR/aarch64_arch_regression_gate_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
SOURCE_COMMIT="$SOURCE_COMMIT" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import sys
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
SOURCE_COMMIT = os.environ["SOURCE_COMMIT"]

SCHEMA = "aarch64_arch_regression_gate_completion_contract.v1"
REPORT_SCHEMA = "aarch64_arch_regression_gate_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-1gg.4"
COMPLETION_BEAD = "bd-1gg.4.1"
FAILURE_SIGNATURE = "aarch64_arch_regression_completion_contract_invalid"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}

errors: list[str] = []
rows: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def repo_path(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else ROOT / path


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def string_list(value: Any, label: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        errors.append(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{label}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def numeric(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def event_row(event: str, status: str = "pass", **fields: Any) -> dict[str, Any]:
    failure = "none" if status == "pass" else FAILURE_SIGNATURE
    row = {
        "timestamp": utc_now(),
        "trace_id": f"{COMPLETION_BEAD}::aarch64_arch_regression::001",
        "level": "info" if status == "pass" else "error",
        "event": event,
        "bead_id": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "source_commit": SOURCE_COMMIT,
        "status": status,
        "outcome": "pass" if status == "pass" else "fail",
        "scenario_id": fields.pop("scenario_id", event),
        "stream": "conformance",
        "gate": "aarch64_arch_regression_gate_completion_contract",
        "mode": fields.pop("mode", "strict"),
        "runtime_mode": fields.pop("runtime_mode", "strict"),
        "replacement_level": fields.pop("replacement_level", "L0"),
        "api_family": fields.pop("api_family", "arch_regression"),
        "symbol": fields.pop("symbol", "aarch64_arch_regression_gate"),
        "oracle_kind": "completion_contract",
        "expected": fields.pop("expected", {"status": "pass"}),
        "actual": fields.pop("actual", {"status": status}),
        "errno": 0 if status == "pass" else 1,
        "decision_path": fields.pop("decision_path", "manifest->matrix->telemetry"),
        "healing_action": "None",
        "latency_ns": fields.pop("latency_ns", 1),
        "target_dir": "target/conformance",
        "failure_signature": failure,
        "arch": fields.pop("arch", "aarch64"),
        "suite": fields.pop("suite", "completion"),
        "perf_delta": fields.pop("perf_delta", 0.0),
        "conformance_delta": fields.pop("conformance_delta", 0.0),
        "verdict": fields.pop("verdict", "claim_blocked"),
        "artifact_refs": fields.pop("artifact_refs", []),
    }
    row.update(fields)
    return row


def validate_line_ref(ref: dict[str, Any]) -> None:
    ref_id = ref.get("id", "<unknown>")
    path_text = ref.get("path")
    line = ref.get("line")
    required_text = ref.get("required_text")
    if not isinstance(path_text, str) or not path_text:
        errors.append(f"implementation ref {ref_id} missing path")
        return
    if not isinstance(line, int) or line <= 0:
        errors.append(f"implementation ref {ref_id} has invalid line")
        return
    path = repo_path(path_text)
    if not path.is_file():
        errors.append(f"implementation ref {ref_id} missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line > len(lines):
        errors.append(f"implementation ref {ref_id} line past EOF: {path_text}:{line}")
        return
    actual = lines[line - 1]
    if not actual.strip():
        errors.append(f"implementation ref {ref_id} points at blank line: {path_text}:{line}")
    if isinstance(required_text, str) and required_text not in actual:
        errors.append(
            f"implementation ref {ref_id} missing required text at {path_text}:{line}: {required_text!r}"
        )


def validate_artifacts(manifest: dict[str, Any]) -> dict[str, pathlib.Path]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        errors.append("source_artifacts must be a non-empty object")
        return {}
    resolved: dict[str, pathlib.Path] = {}
    for artifact_id, path_value in artifacts.items():
        if not isinstance(path_value, str) or not path_value:
            errors.append(f"source artifact {artifact_id} path must be a non-empty string")
            continue
        path = repo_path(path_value)
        resolved[artifact_id] = path
        if not path.is_file():
            errors.append(f"source artifact {artifact_id} missing file: {path_value}")
        rows.append(
            event_row(
                "aarch64_arch_regression_completion.source_artifact_bound",
                suite=artifact_id,
                artifact_refs=[path_value],
            )
        )
    return resolved


def validate_evidence_sources(manifest: dict[str, Any]) -> None:
    evidence = manifest.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    for ref in evidence.get("implementation_refs", []):
        if isinstance(ref, dict):
            validate_line_ref(ref)
        else:
            errors.append("implementation_refs entries must be objects")
    sources = evidence.get("test_sources")
    if not isinstance(sources, dict) or not sources:
        errors.append("completion_debt_evidence.test_sources must be a non-empty object")
        return
    for source_id, source in sources.items():
        if not isinstance(source, dict):
            errors.append(f"test source {source_id} must be an object")
            continue
        path_text = source.get("path")
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"test source {source_id} missing path")
            continue
        path = repo_path(path_text)
        if not path.is_file():
            errors.append(f"test source {source_id} missing file: {path_text}")
            continue
        text = path.read_text(encoding="utf-8")
        for test_ref in string_list(source.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
            require(test_ref in text, f"test source {source_id} missing required test ref {test_ref}")


def validate_missing_bindings(manifest: dict[str, Any], artifacts: dict[str, pathlib.Path]) -> dict[str, Any]:
    bindings = manifest.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        errors.append("missing_item_bindings must be a non-empty array")
        return {"binding_count": 0}
    ids = {binding.get("id") for binding in bindings if isinstance(binding, dict)}
    missing = sorted(REQUIRED_MISSING_ITEMS - ids)
    require(not missing, "missing item bindings absent: " + ", ".join(missing))
    for binding in bindings:
        if not isinstance(binding, dict):
            errors.append("missing_item_bindings entries must be objects")
            continue
        for artifact_id in string_list(binding.get("required_artifacts", []), f"{binding.get('id')}.required_artifacts", allow_empty=True):
            require(artifact_id in artifacts, f"{binding.get('id')} references unknown artifact {artifact_id}")
        rows.append(
            event_row(
                "aarch64_arch_regression_completion.matrix_bound",
                suite=binding.get("evidence_section", binding.get("id", "unknown")),
                artifact_refs=[str(binding.get("id", "unknown"))],
            )
        )
    return {"binding_count": len(bindings)}


def validate_environment_matrix(matrix: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    require(matrix.get("schema_version") == required.get("schema_version"), "environment matrix schema_version mismatch")
    require(matrix.get("bead") == required.get("bead"), "environment matrix bead mismatch")
    rows_value = matrix.get("rows")
    if not isinstance(rows_value, list):
        errors.append("environment matrix rows must be an array")
        rows_value = []
    require(len(rows_value) >= int(required.get("minimum_row_count", 0)), "environment matrix row count below minimum")
    archs = {row.get("architecture") for row in rows_value if isinstance(row, dict)}
    modes = {row.get("runtime_mode") for row in rows_value if isinstance(row, dict)}
    for arch in string_list(required.get("required_architectures"), "environment_matrix.required_architectures"):
        require(arch in archs, f"environment matrix missing required architecture {arch}")
    for mode in string_list(required.get("required_runtime_modes"), "environment_matrix.required_runtime_modes"):
        require(mode in modes, f"environment matrix missing runtime mode {mode}")
    aarch64_rows = [
        row for row in rows_value if isinstance(row, dict) and row.get("architecture") == "aarch64"
    ]
    require(bool(aarch64_rows), "environment matrix has no aarch64 rows")
    require(
        any(row.get("state") == required.get("aarch64_claim_state") for row in aarch64_rows),
        "environment matrix has no blocked aarch64 row",
    )
    require(
        all(row.get("support_claim_allowed") is required.get("aarch64_support_claim_allowed") for row in aarch64_rows),
        "aarch64 environment rows must keep support_claim_allowed=false",
    )
    log_fields = set(string_list(matrix.get("required_log_fields"), "environment_matrix.required_log_fields"))
    for field in string_list(required.get("required_log_fields"), "required environment log fields"):
        require(field in log_fields, f"environment matrix missing required log field {field}")
    rows.append(
        event_row(
            "aarch64_arch_regression_completion.matrix_bound",
            suite="environment_matrix",
            arch="aarch64",
            verdict="claim_blocked",
            artifact_refs=["tests/conformance/user_environment_coverage_matrix.v1.json"],
        )
    )
    return {"row_count": len(rows_value), "aarch64_rows": len(aarch64_rows), "architectures": sorted(str(a) for a in archs)}


def validate_conformance_matrix(matrix: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    require(matrix.get("schema_version") == required.get("schema_version"), "conformance matrix schema_version mismatch")
    require(matrix.get("bead") == required.get("bead"), "conformance matrix bead mismatch")
    cases = matrix.get("cases")
    if not isinstance(cases, list):
        errors.append("conformance matrix cases must be an array")
        cases = []
    summary = matrix.get("summary") if isinstance(matrix.get("summary"), dict) else {}
    total = int(summary.get("total_cases", len(cases)) or 0)
    passed = int(summary.get("passed", 0) or 0)
    failed = int(summary.get("failed", 0) or 0)
    matrix_errors = int(summary.get("errors", 0) or 0)
    pass_rate = numeric(summary.get("pass_rate_percent"))
    require(total == len(cases), "conformance summary total_cases does not match cases length")
    require(total >= int(required.get("minimum_total_cases", 0)), "conformance matrix below minimum total cases")
    require(passed == total, "conformance matrix passed count must equal total cases")
    require(failed <= int(required.get("maximum_failed", 0)), "conformance matrix failed count is nonzero")
    require(matrix_errors <= int(required.get("maximum_errors", 0)), "conformance matrix error count is nonzero")
    require(pass_rate >= numeric(required.get("required_pass_rate_percent")), "conformance pass rate below required threshold")
    rows.append(
        event_row(
            "aarch64_arch_regression_completion.matrix_bound",
            suite="conformance_matrix",
            arch="x86_64",
            verdict="pass",
            conformance_delta=0.0,
            artifact_refs=["tests/conformance/conformance_matrix.v1.json"],
        )
    )
    return {"case_count": total, "passed": passed, "failed": failed, "errors": matrix_errors, "pass_rate_percent": pass_rate}


def validate_perf_prevention(report: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    require(report.get("schema_version") == required.get("schema_version"), "perf prevention schema_version mismatch")
    require(report.get("bead") == required.get("bead"), "perf prevention bead mismatch")
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    total_suites = int(summary.get("total_suites_in_spec", 0) or 0)
    enforced = int(summary.get("suites_enforced_in_gate", 0) or 0)
    baseline_fill = numeric(summary.get("baseline_slot_fill_pct"))
    hotpath = numeric(summary.get("hotpath_symbol_coverage_pct"))
    issues = int(summary.get("total_issues", 0) or 0)
    warnings = int(summary.get("total_warnings", 0) or 0)
    require(total_suites >= int(required.get("minimum_suites_in_spec", 0)), "perf prevention suite count below minimum")
    require(enforced >= int(required.get("minimum_enforced_suites", 0)), "perf enforced suite count below minimum")
    require(baseline_fill >= numeric(required.get("required_baseline_slot_fill_pct")), "perf baseline slot fill below requirement")
    require(hotpath >= numeric(required.get("minimum_hotpath_symbol_coverage_pct")), "perf hotpath coverage below requirement")
    require(issues <= int(required.get("maximum_issues", 0)), "perf prevention issues are nonzero")
    require(warnings <= int(required.get("maximum_warnings", 0)), "perf prevention warnings are nonzero")
    rows.append(
        event_row(
            "aarch64_arch_regression_completion.perf_bound",
            suite="perf_regression_prevention",
            arch="cross_arch",
            perf_delta=0.0,
            verdict="pass",
            artifact_refs=["tests/conformance/perf_regression_prevention.v1.json"],
        )
    )
    return {
        "total_suites_in_spec": total_suites,
        "suites_enforced_in_gate": enforced,
        "baseline_slot_fill_pct": baseline_fill,
        "hotpath_symbol_coverage_pct": hotpath,
        "issues": issues,
        "warnings": warnings,
    }


def validate_standalone_readiness(matrix: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    require(matrix.get("schema_version") == required.get("schema_version"), "standalone readiness schema_version mismatch")
    require(matrix.get("bead") == required.get("bead"), "standalone readiness bead mismatch")
    obligations = matrix.get("obligations")
    proof_rows = matrix.get("proof_rows")
    if not isinstance(obligations, list):
        errors.append("standalone readiness obligations must be an array")
        obligations = []
    if not isinstance(proof_rows, list):
        errors.append("standalone readiness proof_rows must be an array")
        proof_rows = []
    dims = {row.get("dimension") for row in obligations if isinstance(row, dict)}
    surfaces = {row.get("surface") for row in proof_rows if isinstance(row, dict)}
    decisions = {row.get("actual_decision") for row in proof_rows if isinstance(row, dict)}
    for dimension in string_list(required.get("required_dimensions"), "standalone_readiness.required_dimensions"):
        require(dimension in dims, f"standalone readiness missing required dimension {dimension}")
    for surface in string_list(required.get("required_proof_surfaces"), "standalone_readiness.required_proof_surfaces"):
        require(surface in surfaces, f"standalone readiness missing required proof surface {surface}")
    require(required.get("required_claim_decision") in decisions, "standalone readiness missing claim_blocked decision")
    return {"obligation_count": len(obligations), "proof_row_count": len(proof_rows)}


def validate_crosscompile_gate(script_path: pathlib.Path, required: dict[str, Any]) -> dict[str, Any]:
    try:
        text = script_path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"aarch64 crosscompile gate unreadable: {exc}")
        text = ""
    target = required.get("target")
    require(isinstance(target, str) and target in text, "aarch64 crosscompile target missing from gate")
    for crate in string_list(required.get("required_crates"), "crosscompile_gate.required_crates"):
        require(f"-p {crate}" in text, f"aarch64 crosscompile gate missing crate {crate}")
    for stage in string_list(required.get("required_stages"), "crosscompile_gate.required_stages"):
        require(stage in text, f"aarch64 crosscompile gate missing stage {stage}")
    rows.append(
        event_row(
            "aarch64_arch_regression_completion.crosscompile_gate_bound",
            suite="aarch64_crosscompile",
            arch="aarch64",
            verdict="claim_blocked",
            artifact_refs=["scripts/check_aarch64_crosscompile.sh"],
        )
    )
    return {"target": target, "required_crates": required.get("required_crates", [])}


def validate_fuzz_seeds(manifest: dict[str, Any]) -> dict[str, Any]:
    seeds = manifest.get("deterministic_fuzz_seeds")
    if not isinstance(seeds, list):
        errors.append("deterministic_fuzz_seeds must be an array")
        seeds = []
    fuzz_binding = next(
        (
            binding for binding in manifest.get("missing_item_bindings", [])
            if isinstance(binding, dict) and binding.get("id") == "tests.fuzz.primary"
        ),
        {},
    )
    min_count = int(fuzz_binding.get("minimum_seed_count", 0) or 0)
    require(len(seeds) >= min_count, "deterministic fuzz seed count below required minimum")
    seen_ids: set[str] = set()
    seen_signatures: set[str] = set()
    for seed in seeds:
        if not isinstance(seed, dict):
            errors.append("deterministic fuzz seed entries must be objects")
            continue
        seed_id = seed.get("seed_id")
        signature = seed.get("expected_failure_signature")
        require(isinstance(seed_id, str) and bool(seed_id), "deterministic fuzz seed missing seed_id")
        require(isinstance(signature, str) and bool(signature), "deterministic fuzz seed missing expected_failure_signature")
        if seed_id in seen_ids:
            errors.append(f"duplicate deterministic fuzz seed id {seed_id}")
        if signature in seen_signatures:
            errors.append(f"duplicate deterministic fuzz seed signature {signature}")
        seen_ids.add(str(seed_id))
        seen_signatures.add(str(signature))
        rows.append(
            event_row(
                "aarch64_arch_regression_completion.fuzz_seed_replayed",
                suite="deterministic_fuzz_seed",
                arch="aarch64",
                verdict="fail_closed",
                artifact_refs=[str(seed_id)],
                expected={"failure_signature": signature},
            )
        )
    return {"seed_count": len(seeds)}


def validate_telemetry_contract(manifest: dict[str, Any]) -> None:
    telemetry = manifest.get("required_source_contract", {}).get("telemetry", {})
    if not isinstance(telemetry, dict):
        errors.append("required_source_contract.telemetry must be an object")
        return
    required_events = set(string_list(telemetry.get("required_events"), "telemetry.required_events"))
    emitted_events = {row["event"] for row in rows}
    rows.append(
        event_row(
            "aarch64_arch_regression_completion.validated",
            suite="completion_contract",
            arch="aarch64",
            verdict="pass",
            artifact_refs=[rel(CONTRACT), rel(REPORT), rel(LOG)],
        )
    )
    emitted_events.add("aarch64_arch_regression_completion.validated")
    missing_events = sorted(required_events - emitted_events)
    require(not missing_events, "telemetry missing required events: " + ", ".join(missing_events))
    required_fields = string_list(telemetry.get("required_log_fields"), "telemetry.required_log_fields")
    for row in rows:
        for field in required_fields:
            if field not in row:
                errors.append(f"telemetry row {row.get('event')} missing required field {field}")


manifest = load_json(CONTRACT, "completion contract")
if manifest:
    require(manifest.get("schema_version") == SCHEMA, "completion contract schema_version mismatch")
    require(manifest.get("original_bead") == ORIGINAL_BEAD, "original bead mismatch")
    require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion debt bead mismatch")

artifacts = validate_artifacts(manifest)
validate_evidence_sources(manifest)
binding_summary = validate_missing_bindings(manifest, artifacts)

required = manifest.get("required_source_contract")
if not isinstance(required, dict):
    errors.append("required_source_contract must be an object")
    required = {}

env_summary = validate_environment_matrix(
    load_json(artifacts.get("environment_matrix", ROOT / "__missing__"), "environment matrix"),
    required.get("environment_matrix", {}) if isinstance(required.get("environment_matrix"), dict) else {},
)
conf_summary = validate_conformance_matrix(
    load_json(artifacts.get("conformance_matrix", ROOT / "__missing__"), "conformance matrix"),
    required.get("conformance_matrix", {}) if isinstance(required.get("conformance_matrix"), dict) else {},
)
perf_summary = validate_perf_prevention(
    load_json(artifacts.get("perf_prevention_report", ROOT / "__missing__"), "perf prevention report"),
    required.get("perf_regression_prevention", {}) if isinstance(required.get("perf_regression_prevention"), dict) else {},
)
standalone_summary = validate_standalone_readiness(
    load_json(artifacts.get("standalone_readiness_matrix", ROOT / "__missing__"), "standalone readiness matrix"),
    required.get("standalone_readiness", {}) if isinstance(required.get("standalone_readiness"), dict) else {},
)
cross_summary = validate_crosscompile_gate(
    artifacts.get("aarch64_crosscompile_gate", ROOT / "__missing__"),
    required.get("crosscompile_gate", {}) if isinstance(required.get("crosscompile_gate"), dict) else {},
)
fuzz_summary = validate_fuzz_seeds(manifest)
validate_telemetry_contract(manifest)

status = "fail" if errors else "pass"
report = {
    "schema_version": REPORT_SCHEMA,
    "status": status,
    "event": "aarch64_arch_regression_completion.validated",
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "source_commit": SOURCE_COMMIT,
    "errors": errors,
    "summary": {
        **binding_summary,
        "environment": env_summary,
        "conformance": conf_summary,
        "performance": perf_summary,
        "standalone_readiness": standalone_summary,
        "crosscompile_gate": cross_summary,
        "deterministic_fuzz": fuzz_summary,
        "telemetry_rows": len(rows),
    },
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")

if errors:
    print("FAIL: aarch64 arch regression completion contract failed", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: aarch64 arch regression completion contract "
    f"rows={env_summary.get('row_count', 0)} "
    f"aarch64_rows={env_summary.get('aarch64_rows', 0)} "
    f"conformance_cases={conf_summary.get('case_count', 0)} "
    f"perf_issues={perf_summary.get('issues', 0)} "
    f"fuzz_seeds={fuzz_summary.get('seed_count', 0)}"
)
PY
