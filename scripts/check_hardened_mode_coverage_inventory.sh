#!/usr/bin/env bash
# Validate the hardened-mode fixture coverage inventory dashboard.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${HARDENED_MODE_COVERAGE_INVENTORY_CONTRACT:-${ROOT}/tests/conformance/hardened_mode_coverage_inventory.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${HARDENED_MODE_COVERAGE_INVENTORY_REPORT:-${OUT_DIR}/hardened_mode_coverage_inventory.report.json}"
LOG="${HARDENED_MODE_COVERAGE_INVENTORY_LOG:-${OUT_DIR}/hardened_mode_coverage_inventory.log.jsonl}"
TRACE_ID="bd-0agsk.10::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"

MODE="validate-only"
if [[ $# -gt 0 ]]; then
  case "$1" in
    --validate-only)
      MODE="validate-only"
      shift
      ;;
    *)
      MODE="unknown:${1}"
      shift
      ;;
  esac
fi

if [[ $# -gt 0 ]]; then
  MODE="unknown:${1}"
fi

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${TRACE_ID}" "${MODE}" <<'PY'
import json
import pathlib
import subprocess
import sys
import time
from collections import Counter

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
trace_id = sys.argv[5]
mode = sys.argv[6]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "hardened_mode_coverage_inventory.v1"
EXPECTED_BEAD = "bd-0agsk.10"
VALID_CASE_MODES = {"strict", "hardened", "both"}
ALLOWED_CLAIM_STRENGTHS = {
    "inventory_only",
    "gap_identified",
    "fixture_case_declared",
    "repair_deny_policy_mapped",
    "stress_manifest_declared",
}


def git_head() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def rel(path: pathlib.Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def count_map(counter: Counter) -> dict:
    return {key: counter[key] for key in sorted(counter)}


def write_event(report: dict, event_name: str) -> None:
    event = {
        "timestamp": now_utc(),
        "trace_id": trace_id,
        "level": "error" if report.get("outcome") == "fail" else "info",
        "event": event_name,
        "bead_id": EXPECTED_BEAD,
        "source_commit": report.get("source_commit"),
        "artifact_refs": [str(contract_path), str(report_path)],
        "outcome": report.get("outcome"),
        "failure_signature": report.get("failure_signature"),
        "duration_ms": report.get("duration_ms"),
        "details": report.get("summary", {}),
    }
    log_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")


def finish(report: dict, event_name: str) -> None:
    report["duration_ms"] = (time.time_ns() - start_ns) // 1_000_000
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_event(report, event_name)


def fail(signature: str, message: str, **extra) -> None:
    report = {
        "schema_version": "hardened_mode_coverage_inventory.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": trace_id,
        "source_commit": extra.pop("source_commit", None),
        "mode": mode,
        "outcome": "fail",
        "failure_signature": signature,
        "failure_message": message,
        "contract": str(contract_path),
        "summary": extra,
    }
    finish(report, "hardened_mode_coverage_inventory_failed")
    raise SystemExit(f"FAIL[{signature}]: {message}")


def expect_equal(actual, expected, signature: str, label: str, source_commit: str) -> None:
    if actual != expected:
        fail(signature, f"{label} mismatch", source_commit=source_commit, expected=expected, actual=actual)


if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")

if not contract_path.is_file():
    fail("hardened_coverage_contract_missing", f"contract file missing: {contract_path}")

try:
    contract = load_json(contract_path)
except (OSError, json.JSONDecodeError) as err:
    fail("hardened_coverage_contract_invalid_json", f"contract JSON could not be loaded: {err}")

source_commit = git_head()
if contract.get("schema_version") != EXPECTED_SCHEMA:
    fail(
        "hardened_coverage_contract_wrong_schema",
        f"schema_version must be {EXPECTED_SCHEMA}",
        source_commit=source_commit,
    )
if contract.get("generated_by_bead") != EXPECTED_BEAD:
    fail(
        "hardened_coverage_contract_wrong_bead",
        f"generated_by_bead must be {EXPECTED_BEAD}",
        source_commit=source_commit,
    )

inputs = contract.get("input_artifacts", {})
required_inputs = [
    "fixture_root",
    "fixture_schema_gate",
    "hardened_repair_deny_matrix",
    "stress_orchard_manifest",
    "support_matrix",
]
resolved_inputs: dict[str, pathlib.Path] = {}
for key in required_inputs:
    raw = inputs.get(key)
    if not isinstance(raw, str) or not raw:
        fail("hardened_coverage_input_missing", f"input_artifacts.{key} must be a non-empty path", source_commit=source_commit)
    path = pathlib.Path(raw)
    if not path.is_absolute():
        path = root / path
    if key == "fixture_root":
        if not path.is_dir():
            fail("hardened_coverage_input_missing", f"fixture root missing: {path}", source_commit=source_commit)
    elif not path.is_file():
        fail("hardened_coverage_input_missing", f"input artifact missing: {path}", source_commit=source_commit, input_key=key)
    resolved_inputs[key] = path

schema_gate = load_json(resolved_inputs["fixture_schema_gate"])
if schema_gate.get("schema_version") != "fixture_schema_validation.v1":
    fail("hardened_coverage_input_missing", "fixture schema gate artifact has unexpected schema", source_commit=source_commit)

fixture_files = sorted(resolved_inputs["fixture_root"].glob("*.json"))
cases: list[dict] = []
for path in fixture_files:
    doc = load_json(path)
    family = doc.get("family")
    if not isinstance(family, str) or not family:
        fail("hardened_coverage_fixture_inventory_mismatch", f"{rel(path)} has no family", source_commit=source_commit)
    for case in doc.get("cases", []):
        case_mode = case.get("mode")
        if case_mode not in VALID_CASE_MODES:
            fail(
                "hardened_coverage_fixture_inventory_mismatch",
                f"{rel(path)} case {case.get('name')} has invalid mode {case_mode!r}",
                source_commit=source_commit,
            )
        cases.append(
            {
                "fixture": rel(path),
                "family": family,
                "mode": case_mode,
                "name": case.get("name"),
            }
        )

families = sorted({case["family"] for case in cases})
mode_counts = Counter(case["mode"] for case in cases)
family_rows = []
for family in families:
    family_cases = [case for case in cases if case["family"] == family]
    strict_only = sum(1 for case in family_cases if case["mode"] == "strict")
    hardened_only = sum(1 for case in family_cases if case["mode"] == "hardened")
    paired = sum(1 for case in family_cases if case["mode"] == "both")
    family_rows.append(
        {
            "family": family,
            "fixture_case_count": len(family_cases),
            "strict_only": strict_only,
            "hardened_only": hardened_only,
            "strict_hardened_pair": paired,
            "effective_hardened": hardened_only + paired,
        }
    )

missing_hardened_families = [
    row["family"] for row in family_rows if row["effective_hardened"] == 0
]
actual_inventory = {
    "fixture_file_count": len(fixture_files),
    "standard_case_count": len(cases),
    "family_count": len(families),
    "mode_case_counts": {
        "strict_only": mode_counts["strict"],
        "hardened_only": mode_counts["hardened"],
        "strict_hardened_pair": mode_counts["both"],
    },
    "effective_mode_case_counts": {
        "strict": mode_counts["strict"] + mode_counts["both"],
        "hardened": mode_counts["hardened"] + mode_counts["both"],
    },
    "missing_hardened_family_count": len(missing_hardened_families),
    "missing_hardened_families": missing_hardened_families,
}
expected_inventory = contract.get("expected_inventory", {})
for key in (
    "fixture_file_count",
    "standard_case_count",
    "family_count",
    "mode_case_counts",
    "effective_mode_case_counts",
    "missing_hardened_family_count",
    "missing_hardened_families",
):
    expect_equal(
        actual_inventory[key],
        expected_inventory.get(key),
        "hardened_coverage_fixture_inventory_mismatch",
        f"expected_inventory.{key}",
        source_commit,
    )

matrix = load_json(resolved_inputs["hardened_repair_deny_matrix"])
entries = matrix.get("entries", [])
matrix_actual = {
    "entry_count": len(entries),
    "repair_count": sum(1 for entry in entries if entry.get("decision_path") == "Repair"),
    "deny_count": sum(1 for entry in entries if entry.get("decision_path") == "Deny"),
    "invalid_input_class_count": len(matrix.get("invalid_input_classes", [])),
    "claimed_api_family_count": len(matrix.get("claimed_api_families", [])),
}
matrix_classes = {
    entry.get("invalid_input_class")
    for entry in entries
    if isinstance(entry, dict) and isinstance(entry.get("invalid_input_class"), str)
}
expect_equal(
    matrix_actual,
    expected_inventory.get("hardened_repair_deny_matrix"),
    "hardened_coverage_repair_deny_mismatch",
    "expected_inventory.hardened_repair_deny_matrix",
    source_commit,
)

stress = load_json(resolved_inputs["stress_orchard_manifest"])
stress_scenarios = stress.get("scenarios", [])
stress_actual = {
    "scenario_count": len(stress_scenarios),
    "strict_hardened_pair_scenarios": sum(
        1 for scenario in stress_scenarios if sorted(scenario.get("runtime_modes", [])) == ["hardened", "strict"]
    ),
    "hardened_only_scenarios": sum(
        1 for scenario in stress_scenarios if scenario.get("runtime_modes") == ["hardened"]
    ),
    "hardened_repair_scenarios": sum(
        1 for scenario in stress_scenarios if scenario.get("scenario_kind") == "hardened_repair"
    ),
}
stress_ids = {
    scenario.get("scenario_id")
    for scenario in stress_scenarios
    if isinstance(scenario, dict) and isinstance(scenario.get("scenario_id"), str)
}
stress_repair_ids = {
    scenario.get("scenario_id")
    for scenario in stress_scenarios
    if isinstance(scenario, dict)
    and scenario.get("scenario_kind") == "hardened_repair"
    and isinstance(scenario.get("scenario_id"), str)
}
expect_equal(
    stress_actual,
    expected_inventory.get("stress_orchard"),
    "hardened_coverage_stress_mismatch",
    "expected_inventory.stress_orchard",
    source_commit,
)

support = load_json(resolved_inputs["support_matrix"])
support_symbols = support.get("symbols", [])
support_module_counts = Counter(
    symbol.get("module")
    for symbol in support_symbols
    if isinstance(symbol, dict) and isinstance(symbol.get("module"), str)
)

family_summary_by_name = {row["family"]: row for row in family_rows}
group_reports = []
for index, group in enumerate(contract.get("risk_groups", []), 1):
    group_id = group.get("id")
    if not isinstance(group_id, str) or not group_id:
        fail("hardened_coverage_group_mismatch", f"risk group #{index} missing id", source_commit=source_commit)
    claim_strength = group.get("claim_strength")
    coverage_status = group.get("coverage_status")
    if claim_strength not in ALLOWED_CLAIM_STRENGTHS:
        fail(
            "hardened_coverage_group_overclaim",
            f"{group_id} has forbidden claim_strength {claim_strength!r}",
            source_commit=source_commit,
            group_id=group_id,
        )
    if coverage_status in {"replacement_ready", "complete_family_coverage", "covered"}:
        fail(
            "hardened_coverage_group_overclaim",
            f"{group_id} overclaims coverage_status {coverage_status!r}",
            source_commit=source_commit,
            group_id=group_id,
        )

    fixture_families = group.get("fixture_families", [])
    support_modules = group.get("support_modules", [])
    if not isinstance(fixture_families, list) or not fixture_families:
        fail("hardened_coverage_group_mismatch", f"{group_id} fixture_families must be non-empty", source_commit=source_commit)
    if not isinstance(support_modules, list) or not support_modules:
        fail("hardened_coverage_group_mismatch", f"{group_id} support_modules must be non-empty", source_commit=source_commit)

    unknown_families = sorted(family for family in fixture_families if family not in family_summary_by_name)
    if unknown_families:
        fail(
            "hardened_coverage_group_mismatch",
            f"{group_id} references missing fixture families",
            source_commit=source_commit,
            group_id=group_id,
            missing_families=unknown_families,
        )
    unknown_modules = sorted(module for module in support_modules if module not in support_module_counts)
    if unknown_modules:
        fail(
            "hardened_coverage_support_matrix_mismatch",
            f"{group_id} references missing support modules",
            source_commit=source_commit,
            group_id=group_id,
            missing_modules=unknown_modules,
        )

    selected_rows = [family_summary_by_name[family] for family in fixture_families]
    missing_group_hardened = [
        row["family"] for row in selected_rows if row["effective_hardened"] == 0
    ]
    if missing_group_hardened and coverage_status != "gap_identified":
        fail(
            "hardened_coverage_group_overclaim",
            f"{group_id} has missing hardened families but does not mark a gap",
            source_commit=source_commit,
            group_id=group_id,
            missing_hardened_families=missing_group_hardened,
        )

    matrix_refs = group.get("repair_deny_matrix_classes", [])
    missing_matrix_refs = sorted(ref for ref in matrix_refs if ref not in matrix_classes)
    if missing_matrix_refs:
        fail(
            "hardened_coverage_repair_deny_mismatch",
            f"{group_id} references missing repair/deny matrix classes",
            source_commit=source_commit,
            group_id=group_id,
            missing_classes=missing_matrix_refs,
        )

    scenario_refs = group.get("stress_scenarios", [])
    missing_scenario_refs = sorted(ref for ref in scenario_refs if ref not in stress_ids)
    if missing_scenario_refs:
        fail(
            "hardened_coverage_stress_mismatch",
            f"{group_id} references missing stress scenarios",
            source_commit=source_commit,
            group_id=group_id,
            missing_scenarios=missing_scenario_refs,
        )

    actual_counts = {
        "fixture_case_count": sum(row["fixture_case_count"] for row in selected_rows),
        "strict_only": sum(row["strict_only"] for row in selected_rows),
        "hardened_only": sum(row["hardened_only"] for row in selected_rows),
        "strict_hardened_pair": sum(row["strict_hardened_pair"] for row in selected_rows),
        "effective_hardened": sum(row["effective_hardened"] for row in selected_rows),
        "support_symbol_count": sum(support_module_counts[module] for module in support_modules),
        "stress_repair_scenarios": sum(1 for scenario_id in scenario_refs if scenario_id in stress_repair_ids),
    }
    expected_counts = group.get("expected_counts", {})
    if actual_counts != expected_counts:
        fail(
            "hardened_coverage_group_mismatch",
            f"{group_id} expected_counts mismatch",
            source_commit=source_commit,
            group_id=group_id,
            expected=expected_counts,
            actual=actual_counts,
        )
    if missing_group_hardened != group.get("missing_hardened_families", []):
        fail(
            "hardened_coverage_group_mismatch",
            f"{group_id} missing_hardened_families mismatch",
            source_commit=source_commit,
            group_id=group_id,
            expected=group.get("missing_hardened_families", []),
            actual=missing_group_hardened,
        )

    group_reports.append(
        {
            "id": group_id,
            "coverage_status": coverage_status,
            "claim_strength": claim_strength,
            "counts": actual_counts,
            "missing_hardened_families": missing_group_hardened,
        }
    )

report = {
    "schema_version": "hardened_mode_coverage_inventory.report.v1",
    "bead": EXPECTED_BEAD,
    "trace_id": trace_id,
    "source_commit": source_commit,
    "mode": mode,
    "outcome": "pass",
    "failure_signature": None,
    "contract": str(contract_path),
    "summary": {
        "fixture_inventory": actual_inventory,
        "hardened_repair_deny_matrix": matrix_actual,
        "stress_orchard": stress_actual,
        "support_module_counts": count_map(support_module_counts),
        "risk_groups": group_reports,
    },
}
finish(report, "hardened_mode_coverage_inventory_validated")
print(
    "PASS: hardened mode coverage inventory validated "
    f"cases={len(cases)} hardened_effective={actual_inventory['effective_mode_case_counts']['hardened']} "
    f"groups={len(group_reports)}"
)
PY
