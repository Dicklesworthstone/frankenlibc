#!/usr/bin/env bash
# check_tsm_full_pipeline_load_completion_contract.sh - bd-32e.6.1 completion evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_TSM_FULL_PIPELINE_LOAD_CONTRACT:-$ROOT/tests/conformance/tsm_full_pipeline_load_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_TSM_FULL_PIPELINE_LOAD_REPORT:-$ROOT/target/conformance/tsm_full_pipeline_load_completion_contract.report.json}"
LOG="${FRANKENLIBC_TSM_FULL_PIPELINE_LOAD_LOG:-$ROOT/target/conformance/tsm_full_pipeline_load_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

COMPLETION_BEAD = "bd-32e.6.1"
ORIGINAL_BEAD = "bd-32e.6"
EXPECTED_SCHEMA = "tsm_full_pipeline_load_completion_contract.v1"
EXPECTED_MANIFEST = "bd-32e.6.1-tsm-full-pipeline-load-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_DIMENSIONS = {
    "null_validation",
    "low_address_rejection",
    "foreign_pointer_validation",
    "allocation_lifecycle",
    "uaf_temporal_violation",
    "double_free_detection",
    "foreign_pointer_free",
    "bounds_remaining",
    "tls_cache_repeated_validation",
    "pipeline_metrics",
    "deterministic_mixed_workload",
    "concurrent_alloc_validate_free",
    "concurrent_read_validation",
    "concurrent_mixed_workload",
    "latency_budget_guard",
    "monotone_lattice_transition",
    "adversarial_fault_matrix",
}
EXPECTED_MODES = {"strict", "hardened"}
EXPECTED_EVENTS = {
    "tsm_full_pipeline_load_completion_contract_validated",
    "tsm_full_pipeline_load_completion_contract_failed",
    "tsm_pipeline_load_scenario",
}
EXPECTED_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "mode",
    "runtime_mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "scenario_id",
    "coverage_dimensions",
    "failure_signature",
}

errors: list[str] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{rel(path)} is not valid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{rel(path)} must be a JSON object")
        return {}
    return value


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


def as_string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        err(f"{context} must be a non-empty array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def validate_file_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        err(f"{context} must be a file:line string")
        return
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        err(f"{context} references line past EOF: {value}")
    elif not lines[line_number - 1].strip():
        err(f"{context} references a blank line: {value}")


def source_texts(test_sources: Any) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return texts
    for key, path_text in test_sources.items():
        if not isinstance(key, str) or not key:
            err("test_sources keys must be non-empty strings")
            continue
        if not isinstance(path_text, str) or not path_text:
            err(f"test_sources.{key} must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            err(f"test_sources.{key} references missing file: {path_text}")
            continue
        texts[key] = path.read_text(encoding="utf-8")
    return texts


def validate_test_ref(ref: Any, context: str, texts: dict[str, str]) -> dict[str, str] | None:
    if not isinstance(ref, dict):
        err(f"{context} must be an object")
        return None
    source = ref.get("source")
    name = ref.get("name")
    if not isinstance(source, str) or not source:
        err(f"{context}.source must be non-empty")
        return None
    if not isinstance(name, str) or not name:
        err(f"{context}.name must be non-empty")
        return None
    text = texts.get(source, "")
    if not text:
        err(f"{context} references unknown source {source}")
    elif f"fn {name}" not in text:
        err(f"{context} references missing test {source}::{name}")
    return {"source": source, "name": name}


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        normalized_ref = validate_test_ref(
            ref,
            f"completion_debt_evidence.{section_name}.required_test_refs[{index}]",
            texts,
        )
        if normalized_ref is None:
            continue
        key = (normalized_ref["source"], normalized_ref["name"])
        if key in seen:
            err(f"completion_debt_evidence.{section_name} duplicates test ref {key[0]}::{key[1]}")
        seen.add(key)
        normalized.append(normalized_ref)
    return normalized


manifest = load_json(CONTRACT)
if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if manifest.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")

for source in as_string_list(manifest.get("source_modules"), "source_modules"):
    if not (ROOT / source).is_file():
        err(f"source module missing: {source}")

completion = manifest.get("completion_debt_evidence")
if not isinstance(completion, dict):
    completion = {}
    err("completion_debt_evidence must be an object")

if completion.get("bead") != COMPLETION_BEAD:
    err(f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
if completion.get("original_bead") != ORIGINAL_BEAD:
    err(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
threshold = completion.get("next_audit_score_threshold")
if not isinstance(threshold, int) or threshold < 800 or threshold > 1000:
    err("completion_debt_evidence.next_audit_score_threshold must be 800..1000")

implementation_refs = completion.get("implementation_refs")
if not isinstance(implementation_refs, list) or len(implementation_refs) < 15:
    err("completion_debt_evidence.implementation_refs must contain at least 15 file:line refs")
else:
    for index, ref in enumerate(implementation_refs):
        validate_file_line_ref(ref, f"completion_debt_evidence.implementation_refs[{index}]")

texts = source_texts(completion.get("test_sources"))
missing_items_bound: list[str] = []
test_refs_by_section: dict[str, list[dict[str, str]]] = {}
for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
    section = completion.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    missing_items_bound.append(str(section.get("missing_item_id", "")))
    section_threshold = section.get("next_audit_score_threshold", threshold)
    if not isinstance(section_threshold, int) or section_threshold < 800 or section_threshold > 1000:
        err(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be 800..1000")
    test_refs_by_section[section_name] = validate_test_refs(section, section_name, texts)
    if section_name != "telemetry_primary":
        as_string_list(section.get("required_commands"), f"completion_debt_evidence.{section_name}.required_commands")

unit_sources = {ref["source"] for ref in test_refs_by_section.get("unit_primary", [])}
if not {"ptr_validator_unit", "arena_unit", "allocator_sequences"}.issubset(unit_sources):
    err("unit_primary must include ptr-validator, arena, and allocator sequence evidence")
e2e_sources = {ref["source"] for ref in test_refs_by_section.get("e2e_primary", [])}
if "tsm_pipeline_e2e" not in e2e_sources:
    err("e2e_primary must include the TSM pipeline e2e source")

telemetry = completion.get("telemetry_primary")
required_events: set[str] = set()
required_fields: set[str] = set()
if isinstance(telemetry, dict):
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
    required_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
    if telemetry.get("default_report_path") != "target/conformance/tsm_full_pipeline_load_completion_contract.report.json":
        err("telemetry_primary.default_report_path drifted")
    if telemetry.get("default_log_path") != "target/conformance/tsm_full_pipeline_load_completion_contract.log.jsonl":
        err("telemetry_primary.default_log_path drifted")
else:
    err("completion_debt_evidence.telemetry_primary must be an object")

missing_events = sorted(EXPECTED_EVENTS - required_events)
if missing_events:
    err(f"telemetry_primary.required_events missing {missing_events}")
missing_fields = sorted(EXPECTED_FIELDS - required_fields)
if missing_fields:
    err(f"telemetry_primary.required_fields missing {missing_fields}")

workload = completion.get("workload_contract")
scenario_rows: list[dict[str, Any]] = []
declared_dimensions: set[str] = set()
covered_dimensions: set[str] = set()
declared_modes: set[str] = set()
if not isinstance(workload, dict):
    err("completion_debt_evidence.workload_contract must be an object")
    workload = {}

declared_dimensions = set(
    as_string_list(workload.get("required_dimensions"), "workload_contract.required_dimensions")
)
missing_dimensions = sorted(EXPECTED_DIMENSIONS - declared_dimensions)
if missing_dimensions:
    err(f"workload_contract.required_dimensions missing {missing_dimensions}")

declared_modes = set(as_string_list(workload.get("required_modes"), "workload_contract.required_modes"))
missing_modes = sorted(EXPECTED_MODES - declared_modes)
if missing_modes:
    err(f"workload_contract.required_modes missing {missing_modes}")

latency_budget = workload.get("latency_budget")
if isinstance(latency_budget, dict):
    if latency_budget.get("strict_target_ns") != 20:
        err("latency_budget.strict_target_ns must be 20")
    if latency_budget.get("hardened_target_ns") != 200:
        err("latency_budget.hardened_target_ns must be 200")
    if latency_budget.get("ci_guard_ns") != 50000:
        err("latency_budget.ci_guard_ns must be 50000")
    measurement = latency_budget.get("measurement_test")
    if measurement != "validation_latency_within_budget":
        err("latency_budget.measurement_test drifted")
    e2e_text = texts.get("tsm_pipeline_e2e", "")
    if "avg_ns < 50000" not in e2e_text:
        err("tsm pipeline e2e latency guard no longer checks avg_ns < 50000")
else:
    err("workload_contract.latency_budget must be an object")

scenario_matrix = workload.get("scenario_matrix")
if not isinstance(scenario_matrix, list) or not scenario_matrix:
    err("workload_contract.scenario_matrix must be a non-empty array")
else:
    seen_scenarios: set[str] = set()
    for index, scenario in enumerate(scenario_matrix):
        if not isinstance(scenario, dict):
            err(f"workload_contract.scenario_matrix[{index}] must be an object")
            continue
        scenario_id = scenario.get("scenario_id")
        mode = scenario.get("mode")
        api_family = scenario.get("api_family")
        symbol = scenario.get("symbol")
        decision_path = scenario.get("decision_path")
        healing_action = scenario.get("healing_action")
        errno = scenario.get("errno")
        latency_ns = scenario.get("latency_ns")
        if not isinstance(scenario_id, str) or not scenario_id:
            err(f"workload_contract.scenario_matrix[{index}].scenario_id must be non-empty")
            scenario_id = f"invalid-{index}"
        if scenario_id in seen_scenarios:
            err(f"workload_contract.scenario_matrix duplicates scenario {scenario_id}")
        seen_scenarios.add(scenario_id)
        if mode not in EXPECTED_MODES:
            err(f"scenario {scenario_id} mode must be strict or hardened")
            mode = "strict"
        if not isinstance(api_family, str) or api_family != "membrane":
            err(f"scenario {scenario_id} api_family must be membrane")
        if not isinstance(symbol, str) or not symbol:
            err(f"scenario {scenario_id} symbol must be non-empty")
            symbol = "ValidationPipeline"
        if not isinstance(decision_path, str) or not decision_path:
            err(f"scenario {scenario_id} decision_path must be non-empty")
            decision_path = "unknown"
        if not isinstance(healing_action, str) or not healing_action:
            err(f"scenario {scenario_id} healing_action must be non-empty")
            healing_action = "none"
        if not isinstance(errno, int):
            err(f"scenario {scenario_id} errno must be an integer")
            errno = 0
        if not isinstance(latency_ns, int) or latency_ns <= 0:
            err(f"scenario {scenario_id} latency_ns must be a positive integer")
            latency_ns = 1
        if mode == "strict" and latency_ns > 20:
            err(f"scenario {scenario_id} strict latency_ns exceeds 20")
        if mode == "hardened" and latency_ns > 200:
            err(f"scenario {scenario_id} hardened latency_ns exceeds 200")

        dimensions = set(as_string_list(scenario.get("coverage_dimensions"), f"scenario {scenario_id}.coverage_dimensions"))
        unknown_dimensions = sorted(dimensions - EXPECTED_DIMENSIONS)
        if unknown_dimensions:
            err(f"scenario {scenario_id} has unknown dimensions {unknown_dimensions}")
        covered_dimensions |= dimensions

        refs = scenario.get("test_refs")
        normalized_refs: list[dict[str, str]] = []
        if not isinstance(refs, list) or not refs:
            err(f"scenario {scenario_id}.test_refs must be non-empty")
        else:
            for ref_index, ref in enumerate(refs):
                normalized_ref = validate_test_ref(ref, f"scenario {scenario_id}.test_refs[{ref_index}]", texts)
                if normalized_ref is not None:
                    normalized_refs.append(normalized_ref)

        artifact_refs = as_string_list(scenario.get("artifact_refs"), f"scenario {scenario_id}.artifact_refs")
        scenario_rows.append(
            {
                "scenario_id": scenario_id,
                "mode": mode,
                "api_family": api_family or "membrane",
                "symbol": symbol,
                "decision_path": decision_path,
                "healing_action": healing_action,
                "errno": errno,
                "latency_ns": latency_ns,
                "coverage_dimensions": sorted(dimensions),
                "test_refs": normalized_refs,
                "artifact_refs": artifact_refs,
            }
        )

missing_coverage = sorted(EXPECTED_DIMENSIONS - covered_dimensions)
if missing_coverage:
    err(f"workload_contract.scenario_matrix does not cover dimensions {missing_coverage}")
scenario_modes = {str(row["mode"]) for row in scenario_rows}
missing_scenario_modes = sorted(EXPECTED_MODES - scenario_modes)
if missing_scenario_modes:
    err(f"workload_contract.scenario_matrix missing modes {missing_scenario_modes}")

source_commit = git_head()
status = "fail" if errors else "pass"
now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
artifact_refs = [
    rel(CONTRACT),
    rel(REPORT),
    rel(LOG),
    "crates/frankenlibc-membrane/tests/tsm_pipeline_e2e_test.rs",
    "crates/frankenlibc-membrane/src/ptr_validator.rs",
    "crates/frankenlibc-membrane/src/arena.rs",
    "crates/frankenlibc-membrane/tests/allocator_membrane_invariants_sequences_test.rs",
]
report = {
    "schema_version": "tsm_full_pipeline_load_completion_contract.report.v1",
    "timestamp": now,
    "status": status,
    "bead_id": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "missing_items": missing_items_bound,
    "required_dimensions": sorted(declared_dimensions),
    "covered_dimensions": sorted(covered_dimensions),
    "required_modes": sorted(declared_modes),
    "scenario_count": len(scenario_rows),
    "scenarios": scenario_rows,
    "required_events": sorted(required_events),
    "required_fields": sorted(required_fields),
    "test_refs": test_refs_by_section,
    "artifact_refs": artifact_refs,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log_rows: list[dict[str, Any]] = []
for row in scenario_rows:
    mode = str(row["mode"])
    log_rows.append(
        {
            "timestamp": now,
            "trace_id": f"tsm::full_pipeline_load::{row['scenario_id']}",
            "level": "error" if errors else "info",
            "event": "tsm_pipeline_load_scenario",
            "mode": mode,
            "runtime_mode": mode,
            "api_family": row["api_family"],
            "symbol": row["symbol"],
            "decision_path": row["decision_path"],
            "healing_action": row["healing_action"],
            "errno": row["errno"],
            "latency_ns": row["latency_ns"],
            "artifact_refs": row["artifact_refs"],
            "bead_id": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "source_commit": source_commit,
            "scenario_id": row["scenario_id"],
            "coverage_dimensions": row["coverage_dimensions"],
            "test_refs": row["test_refs"],
            "failure_signature": "none" if not errors else "; ".join(errors),
            "stream": "e2e",
            "gate": "tsm_full_pipeline_load_completion_contract",
            "replacement_level": "L1",
            "oracle_kind": "contract",
            "expected": "full_pipeline_load_bound",
            "actual": status,
            "target_dir": rel(REPORT.parent),
        }
    )

terminal_mode = "strict"
log_rows.append(
    {
        "timestamp": now,
        "trace_id": f"tsm::full_pipeline_load::{COMPLETION_BEAD}",
        "level": "error" if errors else "info",
        "event": (
            "tsm_full_pipeline_load_completion_contract_failed"
            if errors
            else "tsm_full_pipeline_load_completion_contract_validated"
        ),
        "mode": terminal_mode,
        "runtime_mode": terminal_mode,
        "api_family": "membrane",
        "symbol": "ValidationPipeline::contract",
        "decision_path": "contract_validate -> report -> jsonl",
        "healing_action": "none",
        "errno": 0,
        "latency_ns": 20,
        "artifact_refs": artifact_refs,
        "bead_id": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "scenario_id": "summary",
        "coverage_dimensions": sorted(covered_dimensions),
        "test_refs": test_refs_by_section,
        "failure_signature": "none" if not errors else "; ".join(errors),
        "stream": "e2e",
        "gate": "tsm_full_pipeline_load_completion_contract",
        "replacement_level": "L1",
        "oracle_kind": "contract",
        "expected": "all_dimensions_bound",
        "actual": status,
        "target_dir": rel(REPORT.parent),
    }
)
LOG.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows),
    encoding="utf-8",
)

if errors:
    for message in errors:
        print(f"error: {message}", file=sys.stderr)
    sys.exit(1)

print(
    "tsm full pipeline load contract validated: "
    f"missing_items={len(missing_items_bound)} scenarios={len(scenario_rows)} "
    f"dimensions={len(covered_dimensions)} modes={','.join(sorted(scenario_modes))}"
)
PY
