#!/usr/bin/env bash
# check_fixture_coverage_prioritizer_completion_contract.sh -- bd-bp8fl.4.1.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/fixture_coverage_prioritizer_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/fixture_coverage_prioritizer_completion}"
REPORT="${FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_COMPLETION_REPORT:-${OUT_DIR}/fixture_coverage_prioritizer_completion_contract.report.json}"
LOG="${FRANKENLIBC_FIXTURE_COVERAGE_PRIORITIZER_COMPLETION_LOG:-${OUT_DIR}/fixture_coverage_prioritizer_completion_contract.events.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
LOG = pathlib.Path(sys.argv[4])
OUT_DIR = pathlib.Path(sys.argv[5])
SOURCE_COMMIT = sys.argv[6]

SCHEMA = "fixture_coverage_prioritizer_completion_contract.v1"
REPORT_SCHEMA = "fixture_coverage_prioritizer_completion_contract.report.v1"
BEAD_ID = "bd-bp8fl.4.1.1"
ORIGINAL_BEAD = "bd-bp8fl.4.1"
TRACE_ID = "bd-bp8fl.4.1.1::fixture-coverage-prioritizer::completion::v1"

REQUIRED_ARTIFACT_IDS = {
    "prioritizer_artifact",
    "prioritizer_generator",
    "prioritizer_gate",
    "symbol_fixture_coverage",
    "per_symbol_fixture_tests",
    "feature_gap_groups",
    "prioritizer_harness_test",
    "e2e_suite",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_fixture_coverage_prioritizer_sources",
    "checker_accepts_fixture_coverage_prioritizer_completion_contract",
    "checker_emits_structured_fixture_coverage_telemetry",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_e2e_binding",
    "checker_rejects_prioritizer_summary_drift",
    "checker_rejects_missing_telemetry_binding",
}
REQUIRED_GATE_CHECKS = {
    "json_parse",
    "top_level_shape",
    "inputs_and_feature_gap_refs",
    "required_log_fields",
    "campaign_schema",
    "deferred_module_inventory",
    "priority_order",
    "workload_domain_coverage",
    "summary_counts",
}
REQUIRED_LOG_FIELDS = {
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "symbol_family",
    "score",
    "rank",
    "coverage_state",
    "risk_factors",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_unit_binding",
    "missing_e2e_binding",
    "missing_conformance_binding",
    "missing_telemetry_binding",
    "prioritizer_summary_drift",
    "prioritizer_campaign_drift",
    "generator_or_gate_drift",
    "base_gate_failed",
    "missing_test_binding",
]

events: list[dict[str, Any]] = []
errors: list[dict[str, str]] = []
artifact_refs: set[str] = {str(CONTRACT)}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else ROOT / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "fixture_coverage_prioritizer_completion_contract_failed"


def load_json(path: pathlib.Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def read_text(path_text: str, signature: str) -> str:
    path = resolve(path_text)
    try:
        artifact_refs.add(rel(path))
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"cannot read {path_text}: {exc}")
        return ""


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
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
        "source_commit": SOURCE_COMMIT,
        "target_dir": rel(OUT_DIR),
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


def require_contains(path_text: str, needles: set[str], signature: str) -> None:
    text = read_text(path_text, signature)
    for needle in sorted(needles):
        if needle not in text:
            add_error(signature, f"{path_text} missing required text: {needle}")


def artifact_map(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = as_array(contract.get("source_artifacts"), "source_artifacts")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        obj = as_object(row, "source_artifacts[]")
        artifact_id = obj.get("id")
        path = obj.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            add_error("malformed_contract", "source artifact id must be a non-empty string")
            continue
        if not isinstance(path, str) or not path:
            add_error("malformed_contract", f"source artifact {artifact_id} path must be non-empty")
            continue
        result[artifact_id] = obj
        if not resolve(path).exists():
            add_error("missing_source_artifact", f"source artifact {artifact_id} missing path {path}")
    missing_artifacts = missing(REQUIRED_ARTIFACT_IDS, set(result))
    if missing_artifacts:
        add_error("missing_source_artifact", f"missing source artifact ids: {missing_artifacts}")
    events.append(
        event(
            "source_artifacts_validated",
            "pass" if not missing_artifacts else "fail",
            "none" if not missing_artifacts else "missing_source_artifact",
            artifact_count=len(result),
        )
    )
    return result


def binding_signature(item_id: str) -> str:
    if item_id == "tests.unit.primary":
        return "missing_unit_binding"
    if item_id == "tests.e2e.primary":
        return "missing_e2e_binding"
    if item_id == "tests.conformance.primary":
        return "missing_conformance_binding"
    if item_id == "telemetry.primary":
        return "missing_telemetry_binding"
    return "malformed_contract"


def validate_contract_shape(contract: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema_version") != SCHEMA:
        add_error("malformed_contract", f"schema_version must be {SCHEMA}")
    if contract.get("bead_id") != BEAD_ID:
        add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
    if contract.get("original_bead") != ORIGINAL_BEAD:
        add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
    completion = as_object(contract.get("completion_contract"), "completion_contract")
    missing_items = string_set(
        completion.get("missing_item_ids"),
        "completion_contract.missing_item_ids",
        "malformed_contract",
    )
    missing_items_missing = missing(REQUIRED_MISSING_ITEMS, missing_items)
    if missing_items_missing:
        for item_id in missing_items_missing:
            add_error(binding_signature(item_id), f"missing item id {item_id}")
    events.append(
        event(
            "completion_contract_shape_validated",
            "pass" if not missing_items_missing else "fail",
            "none" if not missing_items_missing else "malformed_contract",
            missing_item_count=len(missing_items),
        )
    )
    return completion


def validate_missing_item_bindings(contract: dict[str, Any]) -> None:
    bindings = as_array(contract.get("missing_item_bindings"), "missing_item_bindings")
    by_id = {
        row.get("missing_item_id"): as_object(row, "missing_item_bindings[]")
        for row in bindings
        if isinstance(row, dict)
    }
    for item_id in sorted(REQUIRED_MISSING_ITEMS):
        binding = by_id.get(item_id)
        if not binding:
            add_error(binding_signature(item_id), f"missing binding for {item_id}")
            continue
        for key in ["implementation_refs", "test_refs", "runtime_validation"]:
            values = string_set(binding.get(key), f"{item_id}.{key}", binding_signature(item_id))
            if not values:
                add_error(binding_signature(item_id), f"{item_id}.{key} cannot be empty")
    events.append(event("missing_item_bindings_validated", "pass", binding_count=len(by_id)))


def validate_prioritizer_artifact(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    artifact = load_json(
        resolve(str(artifacts.get("prioritizer_artifact", {}).get("path", ""))),
        "fixture_coverage_prioritizer",
        "prioritizer_summary_drift",
    )
    if artifact.get("schema_version") != "v1" or artifact.get("bead") != ORIGINAL_BEAD:
        add_error("prioritizer_summary_drift", f"prioritizer artifact must declare schema_version=v1 and bead={ORIGINAL_BEAD}")
    summary = as_object(artifact.get("summary"), "prioritizer.summary", "prioritizer_summary_drift")
    required_summary = as_object(
        completion.get("required_prioritizer_summary"),
        "completion_contract.required_prioritizer_summary",
        "prioritizer_summary_drift",
    )
    for key, expected in required_summary.items():
        if summary.get(key) != expected:
            add_error("prioritizer_summary_drift", f"summary.{key} expected {expected!r} got {summary.get(key)!r}")

    campaigns = as_array(artifact.get("campaigns"), "prioritizer.campaigns", "prioritizer_campaign_drift")
    deferred = as_array(artifact.get("deferred_modules"), "prioritizer.deferred_modules", "prioritizer_campaign_drift")
    if summary.get("campaign_count") != len(campaigns):
        add_error("prioritizer_summary_drift", "summary.campaign_count must match campaigns length")
    if summary.get("deferred_module_count") != len(deferred):
        add_error("prioritizer_summary_drift", "summary.deferred_module_count must match deferred_modules length")

    first_wave_total = 0
    selected_uncovered = 0
    campaigns_with_e2e_suite = 0
    ranks = []
    for row in campaigns:
        campaign = as_object(row, "prioritizer.campaigns[]", "prioritizer_campaign_drift")
        ranks.append(campaign.get("rank"))
        first_wave = as_array(campaign.get("first_wave_symbols"), "campaign.first_wave_symbols", "prioritizer_campaign_drift")
        if campaign.get("first_wave_fixture_count") != len(first_wave):
            add_error("prioritizer_campaign_drift", f"{campaign.get('campaign_id')}: first_wave_fixture_count mismatch")
        if campaign.get("structured_log_fields") != "required_log_fields":
            add_error("prioritizer_campaign_drift", f"{campaign.get('campaign_id')}: structured_log_fields must reference required_log_fields")
        scripts = string_set(campaign.get("deterministic_e2e_scripts"), "campaign.deterministic_e2e_scripts", "missing_e2e_binding")
        if "scripts/check_fixture_coverage_prioritizer.sh" not in scripts:
            add_error("missing_e2e_binding", f"{campaign.get('campaign_id')}: deterministic_e2e_scripts missing prioritizer gate")
        if "scripts/e2e_suite.sh" in scripts:
            campaigns_with_e2e_suite += 1
        for script_path in scripts:
            if not resolve(script_path).exists():
                add_error("missing_e2e_binding", f"{campaign.get('campaign_id')}: deterministic script missing: {script_path}")
        first_wave_total += len(first_wave)
        selected_uncovered += int(campaign.get("target_uncovered", 0))
    if campaigns_with_e2e_suite == 0:
        add_error("missing_e2e_binding", "no campaign records scripts/e2e_suite.sh as deterministic E2E evidence")
    if ranks != list(range(1, len(campaigns) + 1)):
        add_error("prioritizer_campaign_drift", "campaign ranks must be contiguous and sorted")
    if summary.get("total_first_wave_fixture_count") != first_wave_total:
        add_error("prioritizer_summary_drift", "summary.total_first_wave_fixture_count must match campaigns")
    if summary.get("selected_target_uncovered_symbols") != selected_uncovered:
        add_error("prioritizer_summary_drift", "summary.selected_target_uncovered_symbols must match campaigns")

    deferred_uncovered = sum(int(as_object(row, "deferred_modules[]", "prioritizer_campaign_drift").get("target_uncovered", 0)) for row in deferred)
    if summary.get("deferred_target_uncovered_symbols") != deferred_uncovered:
        add_error("prioritizer_summary_drift", "summary.deferred_target_uncovered_symbols must match deferred modules")
    if summary.get("all_uncovered_target_symbols") != selected_uncovered + deferred_uncovered:
        add_error("prioritizer_summary_drift", "summary.all_uncovered_target_symbols must match selected + deferred")

    expected_top = as_array(
        completion.get("required_top_campaigns"),
        "completion_contract.required_top_campaigns",
        "prioritizer_campaign_drift",
    )
    for index, expected_value in enumerate(expected_top):
        expected = as_object(expected_value, "required_top_campaigns[]", "prioritizer_campaign_drift")
        actual = as_object(campaigns[index] if index < len(campaigns) else {}, "campaigns[top]", "prioritizer_campaign_drift")
        for key, expected_field in expected.items():
            actual_field = actual.get("scores", {}).get("priority_score") if key == "priority_score" else actual.get(key)
            if actual_field != expected_field:
                add_error("prioritizer_campaign_drift", f"top campaign {index + 1} {key} expected {expected_field!r} got {actual_field!r}")

    log_fields = string_set(artifact.get("required_log_fields"), "prioritizer.required_log_fields", "missing_telemetry_binding")
    missing_fields = missing(REQUIRED_LOG_FIELDS, log_fields)
    if missing_fields:
        add_error("missing_telemetry_binding", f"prioritizer required_log_fields missing {missing_fields}")
    events.append(
        event(
            "prioritizer_artifact_validated",
            "pass",
            campaign_count=len(campaigns),
            deferred_module_count=len(deferred),
            first_wave_total=first_wave_total,
            selected_target_uncovered_symbols=selected_uncovered,
        )
    )


def validate_generator_and_gate(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    generator_path = str(artifacts.get("prioritizer_generator", {}).get("path", ""))
    gate_path = str(artifacts.get("prioritizer_gate", {}).get("path", ""))
    generator_anchors = string_set(
        completion.get("required_generator_anchors"),
        "completion_contract.required_generator_anchors",
        "missing_unit_binding",
    )
    require_contains(generator_path, generator_anchors, "generator_or_gate_drift")
    gate_checks = string_set(
        completion.get("required_gate_checks"),
        "completion_contract.required_gate_checks",
        "missing_conformance_binding",
    )
    missing_checks = missing(REQUIRED_GATE_CHECKS, gate_checks)
    if missing_checks:
        add_error("missing_conformance_binding", f"missing gate checks: {missing_checks}")
    require_contains(
        gate_path,
        gate_checks
        | {
            "fixture_coverage_prioritizer.report.json",
            "fixture_coverage_prioritizer.log.jsonl",
            "source_commit",
            "failure_signature",
        },
        "generator_or_gate_drift",
    )
    events.append(
        event(
            "generator_and_gate_validated",
            "pass" if not missing_checks else "fail",
            "none" if not missing_checks else "missing_conformance_binding",
            generator_anchors=len(generator_anchors),
            gate_checks=len(gate_checks),
        )
    )


def run_base_gate(artifacts: dict[str, dict[str, Any]]) -> None:
    gate_path = str(artifacts.get("prioritizer_gate", {}).get("path", ""))
    if not gate_path:
        add_error("base_gate_failed", "prioritizer_gate path missing")
        return
    try:
        output = subprocess.run(
            ["bash", str(resolve(gate_path))],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
    except Exception as exc:
        add_error("base_gate_failed", f"{gate_path} could not run: {exc}")
        return
    combined = output.stdout + "\n" + output.stderr
    if output.returncode != 0:
        add_error("base_gate_failed", f"{gate_path} failed rc={output.returncode}: {combined}")
    report_path = ROOT / "target/conformance/fixture_coverage_prioritizer.report.json"
    log_path = ROOT / "target/conformance/fixture_coverage_prioritizer.log.jsonl"
    report = load_json(report_path, "fixture_coverage_prioritizer_report", "base_gate_failed")
    if report.get("status") != "pass":
        add_error("base_gate_failed", "fixture coverage prioritizer report status must be pass")
    checks = as_object(report.get("checks"), "fixture_coverage_prioritizer_report.checks", "base_gate_failed")
    failed_checks = [key for key, value in checks.items() if value != "pass"]
    if failed_checks:
        add_error("base_gate_failed", f"base gate failed checks: {failed_checks}")
    try:
        first_log = log_path.read_text(encoding="utf-8").splitlines()[0]
        artifact_refs.add(rel(log_path))
        log_row = json.loads(first_log)
        missing_log_fields = missing(REQUIRED_LOG_FIELDS, set(log_row))
        if missing_log_fields:
            add_error("missing_telemetry_binding", f"base gate log row missing fields: {missing_log_fields}")
    except Exception as exc:
        add_error("missing_telemetry_binding", f"cannot validate base gate log row: {exc}")
    events.append(
        event(
            "base_fixture_coverage_prioritizer_gate_replayed",
            "pass" if output.returncode == 0 and not failed_checks else "fail",
            "none" if output.returncode == 0 and not failed_checks else "base_gate_failed",
            campaign_count=report.get("campaign_count"),
            total_first_wave_fixture_count=report.get("total_first_wave_fixture_count"),
        )
    )


def validate_harness_and_completion_tests(contract: dict[str, Any], completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    harness_path = str(artifacts.get("prioritizer_harness_test", {}).get("path", ""))
    harness_tests = string_set(
        completion.get("required_harness_tests"),
        "completion_contract.required_harness_tests",
        "missing_unit_binding",
    )
    require_contains(
        harness_path,
        harness_tests
        | {
            "structured log row missing",
            "generator self-test failed",
            "generator canonical check failed",
            "report checks.{check} should pass",
        },
        "missing_unit_binding",
    )
    test_fns = as_object(contract.get("required_test_functions"), "required_test_functions")
    positive = string_set(test_fns.get("positive"), "required_test_functions.positive", "missing_test_binding")
    negative = string_set(test_fns.get("negative"), "required_test_functions.negative", "missing_test_binding")
    missing_positive = missing(REQUIRED_POSITIVE_TESTS, positive)
    missing_negative = missing(REQUIRED_NEGATIVE_TESTS, negative)
    if missing_positive:
        add_error("missing_test_binding", f"missing positive tests: {missing_positive}")
    if missing_negative:
        add_error("missing_test_binding", f"missing negative tests: {missing_negative}")
    completion_test_path = str(artifacts.get("completion_harness_test", {}).get("path", ""))
    require_contains(completion_test_path, REQUIRED_POSITIVE_TESTS | REQUIRED_NEGATIVE_TESTS, "missing_test_binding")
    events.append(
        event(
            "test_surfaces_validated",
            "pass" if not missing_positive and not missing_negative else "fail",
            "none" if not missing_positive and not missing_negative else "missing_test_binding",
            harness_tests=len(harness_tests),
            positive_tests=len(positive),
            negative_tests=len(negative),
        )
    )


def validate_completion_log_fields(completion: dict[str, Any]) -> None:
    required_log_fields = string_set(
        completion.get("required_log_fields"),
        "completion_contract.required_log_fields",
        "missing_telemetry_binding",
    )
    missing_fields = missing(REQUIRED_LOG_FIELDS, required_log_fields)
    if missing_fields:
        add_error("missing_telemetry_binding", f"completion required_log_fields missing {missing_fields}")
    events.append(
        event(
            "telemetry_contract_validated",
            "pass" if not missing_fields else "fail",
            "none" if not missing_fields else "missing_telemetry_binding",
            log_fields=len(required_log_fields),
        )
    )


def finish(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        events.append(event("fixture_coverage_prioritizer_completion_contract_validated", "pass"))
    else:
        events.append(
            event(
                "fixture_coverage_prioritizer_completion_contract_failed",
                "fail",
                primary_signature(),
            )
        )
    report = {
        "schema_version": REPORT_SCHEMA,
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "status": status,
        "summary": summary,
        "failure_signature": "none" if status == "pass" else primary_signature(),
        "error_count": len(errors),
        "errors": errors,
        "artifact_refs": sorted(artifact_refs),
        "events": events,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, events)
    if status == "pass":
        print(
            "PASS fixture coverage prioritizer completion contract "
            f"sources={summary.get('source_artifacts', 0)} events={len(events)}"
        )
        sys.exit(0)
    print(
        "FAIL fixture coverage prioritizer completion contract "
        f"signature={primary_signature()} errors={len(errors)} report={rel(REPORT)}",
        file=sys.stderr,
    )
    sys.exit(1)


def main() -> None:
    contract = as_object(load_json(CONTRACT, "contract"), "contract")
    artifacts = artifact_map(contract)
    completion = validate_contract_shape(contract)
    validate_missing_item_bindings(contract)
    validate_prioritizer_artifact(completion, artifacts)
    validate_generator_and_gate(completion, artifacts)
    run_base_gate(artifacts)
    validate_harness_and_completion_tests(contract, completion, artifacts)
    validate_completion_log_fields(completion)
    finish(
        {
            "source_artifacts": len(artifacts),
            "missing_items": len(REQUIRED_MISSING_ITEMS),
            "events": len(events),
        }
    )


main()
PY
