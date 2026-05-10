#!/usr/bin/env bash
# check_math_value_ablations_completion_contract.sh -- bd-1rxj.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_MATH_VALUE_ABLATIONS_CONTRACT:-${ROOT}/tests/conformance/math_value_ablations_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_MATH_VALUE_ABLATIONS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_MATH_VALUE_ABLATIONS_COMPLETION_REPORT:-${OUT_DIR}/math_value_ablations_completion_contract.report.json}"
LOG="${FRANKENLIBC_MATH_VALUE_ABLATIONS_COMPLETION_LOG:-${OUT_DIR}/math_value_ablations_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
out_dir = Path(sys.argv[5])
source_commit = sys.argv[6]

SCHEMA = "math_value_ablations_completion_contract.v1"
BEAD_ID = "bd-1rxj.1"
ORIGINAL_BEAD = "bd-1rxj"
TRACE_ID = "bd-1rxj.1::math-value-ablations::v1"
REQUIRED_ARTIFACT_IDS = {
    "math_value_ablations",
    "math_value_proof",
    "math_value_gate",
    "math_value_harness_test",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_MODES = {"strict", "hardened"}
REQUIRED_POLICY_FIELDS = {
    "strict_budget_ns_max",
    "hardened_budget_ns_max",
    "min_confidence",
    "min_risk_reduction_ppm",
    "min_quality_gain",
    "min_latency_improvement_pct",
    "retain_rule",
}
REQUIRED_LOG_FIELDS = {
    "trace_id",
    "mode",
    "symbol",
    "event",
    "outcome",
    "errno",
    "timing_ns",
    "tier",
    "decision",
    "confidence",
    "risk_reduction_ppm",
    "quality_gain",
    "latency_improvement_pct",
    "reasons",
}
REQUIRED_BINDING_IMPL_REFS = {
    "tests/conformance/math_value_ablations.v1.json",
    "scripts/check_math_value_ablations.sh",
    "tests/conformance/math_value_ablations_completion_contract.v1.json",
    "scripts/check_math_value_ablations_completion_contract.sh",
}
REQUIRED_BINDING_TEST_REFS = {
    "crates/frankenlibc-harness/tests/math_value_ablations_test.rs",
    "crates/frankenlibc-harness/tests/math_value_ablations_completion_contract_test.rs",
}
REQUIRED_POSITIVE_TESTS = {
    "gate_script_emits_logs_and_report",
    "checker_accepts_math_value_ablation_completion_contract",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_e2e_binding",
    "checker_rejects_incomplete_mode_contract",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_e2e_contract",
    "missing_e2e_binding",
    "base_gate_failed",
    "math_value_artifact_failed",
    "base_gate_output_failed",
]

events: list[dict[str, Any]] = []
errors: list[dict[str, str]] = []
artifact_refs: set[str] = {str(contract_path)}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "math_value_ablations_completion_contract_failed"


def load_json(path: Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def event(name: str, status: str, failure_signature: str = "none", **fields: Any) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "event": name,
        "status": status,
        "source_commit": source_commit,
        "target_dir": rel(out_dir),
        "failure_signature": failure_signature,
        **fields,
    }


def as_array(value: Any, context: str, signature: str = "malformed_contract") -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def as_object(value: Any, context: str, signature: str = "malformed_contract") -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def string_set(value: Any, context: str, signature: str) -> set[str]:
    rows = as_array(value, context, signature)
    result = {row for row in rows if isinstance(row, str)}
    if len(result) != len(rows):
        add_error(signature, f"{context} must contain only strings")
    return result


def missing(required: set[str], actual: set[str]) -> list[str]:
    return sorted(required - actual)


def source_has_fn(path_text: str, fn_name: str, signature: str) -> None:
    path = resolve(path_text)
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"cannot read test source {path_text}: {exc}")
        return
    if f"fn {fn_name}" not in text:
        add_error(signature, f"{path_text} missing test {fn_name}")


def finish(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        events.append(event("math_value_ablations_completion_contract_validated", "pass"))
    else:
        events.append(
            event(
                "math_value_ablations_completion_contract_failed",
                "fail",
                primary_signature(),
            )
        )
    report = {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": status,
        "summary": {
            **summary,
            "event_count": len(events),
        },
        "artifact_refs": sorted(artifact_refs),
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, events)
    if errors:
        print(f"FAIL: math value ablations completion contract errors={len(errors)}")
        for error in errors[:12]:
            print(f"- {error['failure_signature']}: {error['message']}")
        sys.exit(1)
    print(
        "PASS: math value ablations completion contract "
        f"experiments={summary.get('experiment_count', 0)} log_rows={summary.get('base_gate_log_rows', 0)}"
    )


contract = load_json(contract_path, "contract")
if contract.get("schema_version") != SCHEMA:
    add_error("malformed_contract", f"schema_version must be {SCHEMA}")
if contract.get("bead_id") != BEAD_ID:
    add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
if contract.get("original_bead") != ORIGINAL_BEAD:
    add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
if contract.get("trace_id") != TRACE_ID:
    add_error("malformed_contract", f"trace_id must be {TRACE_ID}")

source_artifacts = as_array(contract.get("source_artifacts"), "source_artifacts")
source_by_id: dict[str, dict[str, Any]] = {}
for artifact in source_artifacts:
    row = as_object(artifact, "source_artifacts[]")
    artifact_id = row.get("id")
    path_text = row.get("path")
    if not isinstance(artifact_id, str) or not artifact_id:
        add_error("malformed_contract", "source_artifacts[].id must be a non-empty string")
        continue
    if not isinstance(path_text, str) or not path_text:
        add_error("malformed_contract", f"source_artifacts.{artifact_id}.path must be a non-empty string")
        continue
    source_by_id[artifact_id] = row
    path = resolve(path_text)
    if not path.is_file():
        add_error("missing_source_artifact", f"source artifact missing: {path_text}")
    else:
        artifact_refs.add(path_text)
        if artifact_id.endswith("gate"):
            try:
                mode = path.stat().st_mode
                if mode & 0o111 == 0:
                    add_error("missing_source_artifact", f"gate script is not executable: {path_text}")
            except Exception as exc:
                add_error("missing_source_artifact", f"cannot stat gate script {path_text}: {exc}")

for artifact_id in missing(REQUIRED_ARTIFACT_IDS, set(source_by_id)):
    add_error("missing_source_artifact", f"source_artifacts missing {artifact_id}")

e2e_contract = as_object(contract.get("e2e_contract"), "e2e_contract", "missing_e2e_contract")
if e2e_contract.get("missing_item_id") != "tests.e2e.primary":
    add_error("missing_e2e_contract", "e2e_contract.missing_item_id must be tests.e2e.primary")
required_modes = string_set(e2e_contract.get("required_modes"), "e2e_contract.required_modes", "missing_e2e_contract")
if required_modes != REQUIRED_MODES:
    add_error("missing_e2e_contract", "e2e_contract.required_modes must be strict,hardened")
if e2e_contract.get("required_experiment_count") != 25:
    add_error("missing_e2e_contract", "required_experiment_count must be 25")
if e2e_contract.get("required_log_row_count") != 50:
    add_error("missing_e2e_contract", "required_log_row_count must be 50")
if e2e_contract.get("required_report_schema_version") != "v1":
    add_error("missing_e2e_contract", "required_report_schema_version must be v1")
if e2e_contract.get("required_report_ok") is not True:
    add_error("missing_e2e_contract", "required_report_ok must be true")
policy_fields = string_set(
    e2e_contract.get("required_policy_fields"),
    "e2e_contract.required_policy_fields",
    "missing_e2e_contract",
)
for field in missing(REQUIRED_POLICY_FIELDS, policy_fields):
    add_error("missing_e2e_contract", f"required_policy_fields missing {field}")
log_fields = string_set(
    e2e_contract.get("required_log_fields"),
    "e2e_contract.required_log_fields",
    "missing_e2e_contract",
)
for field in missing(REQUIRED_LOG_FIELDS, log_fields):
    add_error("missing_e2e_contract", f"required_log_fields missing {field}")
required_summary = as_object(
    e2e_contract.get("required_summary"),
    "e2e_contract.required_summary",
    "missing_e2e_contract",
)

bindings = as_array(contract.get("missing_item_bindings"), "missing_item_bindings", "missing_e2e_binding")
binding = next(
    (row for row in bindings if isinstance(row, dict) and row.get("spec_item") == "tests.e2e.primary"),
    None,
)
if not isinstance(binding, dict):
    add_error("missing_e2e_binding", "missing_item_bindings must include tests.e2e.primary")
    binding = {}
impl_refs = string_set(binding.get("implementation_refs"), "tests.e2e.primary.implementation_refs", "missing_e2e_binding")
test_refs = string_set(binding.get("test_refs"), "tests.e2e.primary.test_refs", "missing_e2e_binding")
positive_tests = string_set(binding.get("required_positive_tests"), "tests.e2e.primary.required_positive_tests", "missing_e2e_binding")
negative_tests = string_set(binding.get("required_negative_tests"), "tests.e2e.primary.required_negative_tests", "missing_e2e_binding")
for ref in missing(REQUIRED_BINDING_IMPL_REFS, impl_refs):
    add_error("missing_e2e_binding", f"implementation_refs missing {ref}")
for ref in missing(REQUIRED_BINDING_TEST_REFS, test_refs):
    add_error("missing_e2e_binding", f"test_refs missing {ref}")
for name in missing(REQUIRED_POSITIVE_TESTS, positive_tests):
    add_error("missing_e2e_binding", f"required_positive_tests missing {name}")
for name in missing(REQUIRED_NEGATIVE_TESTS, negative_tests):
    add_error("missing_e2e_binding", f"required_negative_tests missing {name}")

source_has_fn(
    "crates/frankenlibc-harness/tests/math_value_ablations_test.rs",
    "gate_script_emits_logs_and_report",
    "missing_e2e_binding",
)
source_has_fn(
    "crates/frankenlibc-harness/tests/math_value_ablations_completion_contract_test.rs",
    "checker_accepts_math_value_ablation_completion_contract",
    "missing_e2e_binding",
)
source_has_fn(
    "crates/frankenlibc-harness/tests/math_value_ablations_completion_contract_test.rs",
    "checker_rejects_missing_e2e_binding",
    "missing_e2e_binding",
)
source_has_fn(
    "crates/frankenlibc-harness/tests/math_value_ablations_completion_contract_test.rs",
    "checker_rejects_incomplete_mode_contract",
    "missing_e2e_binding",
)
events.append(
    event(
        "source_artifacts_and_e2e_binding_validated",
        "fail" if errors else "pass",
        primary_signature() if errors else "none",
        source_artifact_count=len(source_by_id),
    )
)

if errors:
    finish({"experiment_count": 0, "base_gate_log_rows": 0})

ablations_path = resolve(source_by_id["math_value_ablations"]["path"])
value_proof_path = resolve(source_by_id["math_value_proof"]["path"])
gate_path = resolve(source_by_id["math_value_gate"]["path"])
ablations = load_json(ablations_path, "math_value_ablations", "math_value_artifact_failed")
value_proof = load_json(value_proof_path, "math_value_proof", "math_value_artifact_failed")

if ablations.get("schema_version") != 1:
    add_error("math_value_artifact_failed", "math_value_ablations.schema_version must be 1")
if ablations.get("bead") != ORIGINAL_BEAD:
    add_error("math_value_artifact_failed", f"math_value_ablations.bead must be {ORIGINAL_BEAD}")

experiments = as_array(ablations.get("experiments"), "math_value_ablations.experiments", "math_value_artifact_failed")
if len(experiments) != e2e_contract.get("required_experiment_count"):
    add_error("math_value_artifact_failed", f"expected 25 experiments, got {len(experiments)}")

vp_modules: set[str] = set()
for section in ("production_core_assessments", "production_monitor_assessments"):
    for row in as_array(value_proof.get(section), f"math_value_proof.{section}", "math_value_artifact_failed"):
        if not isinstance(row, dict):
            add_error("math_value_artifact_failed", f"math_value_proof.{section} row must be object")
            continue
        module = row.get("module")
        if isinstance(module, str):
            vp_modules.add(module)
        if row.get("verdict") != "retain":
            add_error("math_value_artifact_failed", f"value proof module {module!r} must have retain verdict")

ablation_modules: set[str] = set()
for index, row in enumerate(experiments):
    exp = as_object(row, f"math_value_ablations.experiments[{index}]", "math_value_artifact_failed")
    module = exp.get("module")
    if not isinstance(module, str) or not module:
        add_error("math_value_artifact_failed", f"experiments[{index}].module must be a non-empty string")
        continue
    if module in ablation_modules:
        add_error("math_value_artifact_failed", f"duplicate ablation module {module}")
    ablation_modules.add(module)
    if exp.get("decision") != "retain":
        add_error("math_value_artifact_failed", f"{module}: decision must be retain")
    stats = as_object(exp.get("statistics"), f"{module}.statistics", "math_value_artifact_failed")
    confidence = stats.get("confidence")
    if not isinstance(confidence, (int, float)) or confidence < 0.8:
        add_error("math_value_artifact_failed", f"{module}: confidence must be >= 0.8")
    for mode in sorted(REQUIRED_MODES):
        section = as_object(exp.get(mode), f"{module}.{mode}", "math_value_artifact_failed")
        for side in ("with", "without"):
            metrics = as_object(section.get(side), f"{module}.{mode}.{side}", "math_value_artifact_failed")
            for metric in ("latency_ns", "risk_ppm", "decision_quality"):
                if not isinstance(metrics.get(metric), (int, float)):
                    add_error("math_value_artifact_failed", f"{module}.{mode}.{side}.{metric} must be numeric")

if ablation_modules != vp_modules:
    add_error(
        "math_value_artifact_failed",
        "ablation module set must match math_value_proof production modules",
    )
summary = as_object(ablations.get("summary"), "math_value_ablations.summary", "math_value_artifact_failed")
for key, expected in sorted(required_summary.items()):
    if summary.get(key) != expected:
        add_error("math_value_artifact_failed", f"math_value_ablations.summary.{key} expected {expected!r} got {summary.get(key)!r}")
policy = as_object(ablations.get("evaluation_policy"), "math_value_ablations.evaluation_policy", "math_value_artifact_failed")
for field in REQUIRED_POLICY_FIELDS:
    if field not in policy:
        add_error("math_value_artifact_failed", f"evaluation_policy missing {field}")

events.append(
    event(
        "math_value_ablation_artifacts_validated",
        "fail" if errors else "pass",
        primary_signature() if errors else "none",
        experiment_count=len(experiments),
        value_proof_module_count=len(vp_modules),
    )
)

if errors:
    finish({"experiment_count": len(experiments), "base_gate_log_rows": 0})

gate_result = subprocess.run(
    ["bash", str(gate_path)],
    cwd=root,
    text=True,
    capture_output=True,
)
events.append(
    event(
        "math_value_ablation_base_gate_executed",
        "pass" if gate_result.returncode == 0 else "fail",
        "none" if gate_result.returncode == 0 else "base_gate_failed",
        returncode=gate_result.returncode,
    )
)
if gate_result.returncode != 0:
    add_error(
        "base_gate_failed",
        "check_math_value_ablations.sh failed "
        f"stdout={gate_result.stdout[-1000:]} stderr={gate_result.stderr[-1000:]}",
    )
    finish({"experiment_count": len(experiments), "base_gate_log_rows": 0})

base_report_path = root / "target/conformance/math_value_ablations.report.json"
base_log_path = root / "target/conformance/math_value_ablations.log.jsonl"
artifact_refs.add(rel(base_report_path))
artifact_refs.add(rel(base_log_path))
base_report = load_json(base_report_path, "base_gate_report", "base_gate_output_failed")
try:
    base_log_rows = [
        json.loads(line)
        for line in base_log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
except Exception as exc:
    add_error("base_gate_output_failed", f"cannot parse base gate JSONL log: {exc}")
    base_log_rows = []

if base_report.get("schema_version") != e2e_contract.get("required_report_schema_version"):
    add_error("base_gate_output_failed", "base report schema_version mismatch")
if base_report.get("bead") != ORIGINAL_BEAD:
    add_error("base_gate_output_failed", f"base report bead must be {ORIGINAL_BEAD}")
if base_report.get("ok") is not e2e_contract.get("required_report_ok"):
    add_error("base_gate_output_failed", "base report ok mismatch")
if base_report.get("failure_count") != 0:
    add_error("base_gate_output_failed", "base report failure_count must be 0")
base_summary = as_object(base_report.get("summary"), "base_report.summary", "base_gate_output_failed")
for key, expected in sorted(required_summary.items()):
    if base_summary.get(key) != expected:
        add_error("base_gate_output_failed", f"base report summary.{key} expected {expected!r} got {base_summary.get(key)!r}")
if len(base_log_rows) != e2e_contract.get("required_log_row_count"):
    add_error("base_gate_output_failed", f"expected 50 base log rows, got {len(base_log_rows)}")

log_modes: set[str] = set()
log_symbols: set[str] = set()
for index, row in enumerate(base_log_rows):
    if not isinstance(row, dict):
        add_error("base_gate_output_failed", f"base log row {index} must be object")
        continue
    missing_fields = sorted(REQUIRED_LOG_FIELDS - set(row))
    if missing_fields:
        add_error("base_gate_output_failed", f"base log row {index} missing {','.join(missing_fields)}")
    if row.get("event") != "runtime_math.value_ablation":
        add_error("base_gate_output_failed", f"base log row {index} event mismatch")
    if row.get("outcome") != "pass":
        add_error("base_gate_output_failed", f"base log row {index} outcome must be pass")
    if row.get("errno") != 0:
        add_error("base_gate_output_failed", f"base log row {index} errno must be 0")
    mode = row.get("mode")
    symbol = row.get("symbol")
    if isinstance(mode, str):
        log_modes.add(mode)
    if isinstance(symbol, str):
        log_symbols.add(symbol)

if log_modes != REQUIRED_MODES:
    add_error("base_gate_output_failed", f"base log modes must be {sorted(REQUIRED_MODES)}")
if log_symbols != ablation_modules:
    add_error("base_gate_output_failed", "base log symbols must match ablation modules")

events.append(
    event(
        "math_value_ablation_outputs_validated",
        "fail" if errors else "pass",
        primary_signature() if errors else "none",
        base_gate_log_rows=len(base_log_rows),
        base_gate_symbol_count=len(log_symbols),
    )
)

finish(
    {
        "experiment_count": len(experiments),
        "value_proof_module_count": len(vp_modules),
        "base_gate_log_rows": len(base_log_rows),
        "required_log_row_count": e2e_contract.get("required_log_row_count"),
    }
)
PY
