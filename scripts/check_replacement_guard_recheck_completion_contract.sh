#!/usr/bin/env bash
# check_replacement_guard_recheck_completion_contract.sh -- bd-bp8fl.6.5.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_REPLACEMENT_GUARD_RECHECK_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/replacement_guard_recheck_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_REPLACEMENT_GUARD_RECHECK_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/replacement_guard_recheck_completion}"
REPORT="${FRANKENLIBC_REPLACEMENT_GUARD_RECHECK_COMPLETION_REPORT:-${OUT_DIR}/replacement_guard_recheck_completion_contract.report.json}"
LOG="${FRANKENLIBC_REPLACEMENT_GUARD_RECHECK_COMPLETION_LOG:-${OUT_DIR}/replacement_guard_recheck_completion_contract.events.jsonl}"
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

SCHEMA = "replacement_guard_recheck_completion_contract.v1"
REPORT_SCHEMA = "replacement_guard_recheck_completion_contract.report.v1"
BEAD_ID = "bd-bp8fl.6.5.1"
ORIGINAL_BEAD = "bd-bp8fl.6.5"
TRACE_ID = "bd-bp8fl.6.5.1::replacement-guard-recheck::completion::v1"

REQUIRED_ARTIFACT_IDS = {
    "replacement_profile",
    "zero_unapproved_fixtures",
    "replacement_levels",
    "host_dependency_inventory",
    "replacement_guard_gate",
    "replacement_levels_gate",
    "host_dependency_gate",
    "replacement_guard_harness_test",
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
    "contract_binds_replacement_guard_recheck_sources",
    "checker_accepts_replacement_guard_recheck_completion_contract",
    "checker_emits_structured_replacement_guard_telemetry",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_e2e_binding",
    "checker_rejects_replacement_profile_drift",
    "checker_rejects_missing_telemetry_binding",
}
REQUIRED_LOG_FIELDS = {
    "trace_id",
    "bead_id",
    "scenario_id",
    "mode",
    "gate_name",
    "decision_path",
    "module",
    "line",
    "symbol",
    "callthrough_detected",
    "policy_rule",
    "verdict",
    "status",
    "reason",
    "artifact_ref",
    "artifact_refs",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_unit_binding",
    "missing_e2e_binding",
    "missing_conformance_binding",
    "missing_telemetry_binding",
    "replacement_profile_drift",
    "replacement_guard_outcome_drift",
    "replacement_levels_gate_failed",
    "host_dependency_gate_failed",
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
    return "replacement_guard_recheck_completion_contract_failed"


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


def validate_replacement_profile(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    profile = load_json(
        resolve(str(artifacts.get("replacement_profile", {}).get("path", ""))),
        "replacement_profile",
        "replacement_profile_drift",
    )
    fixtures = load_json(
        resolve(str(artifacts.get("zero_unapproved_fixtures", {}).get("path", ""))),
        "replacement_zero_unapproved_fixtures",
        "replacement_profile_drift",
    )
    levels = load_json(
        resolve(str(artifacts.get("replacement_levels", {}).get("path", ""))),
        "replacement_levels",
        "replacement_profile_drift",
    )
    required = as_object(
        completion.get("required_replacement_profile"),
        "completion_contract.required_replacement_profile",
        "replacement_profile_drift",
    )
    census = as_object(profile.get("call_through_census"), "replacement_profile.call_through_census", "replacement_profile_drift")
    families = as_object(profile.get("callthrough_families"), "replacement_profile.callthrough_families", "replacement_profile_drift")
    fixture_summary = as_object(fixtures.get("summary"), "replacement_zero_unapproved_fixtures.summary", "replacement_profile_drift")
    actual = {
        "profile_version": profile.get("profile_version"),
        "generated_bead": profile.get("generated_bead"),
        "total_call_throughs": census.get("total_call_throughs"),
        "callthrough_family_count": len(as_array(families.get("modules"), "callthrough_families.modules", "replacement_profile_drift")),
        "fixture_count": fixture_summary.get("fixture_count"),
        "interpose_allowed_count": fixture_summary.get("interpose_allowed_count"),
        "replacement_forbidden_count": fixture_summary.get("replacement_forbidden_count"),
        "replacement_level_count": len(as_array(levels.get("levels"), "replacement_levels.levels", "replacement_profile_drift")),
        "current_level": levels.get("current_level"),
    }
    for key, expected in required.items():
        if actual.get(key) != expected:
            add_error("replacement_profile_drift", f"{key} expected {expected!r} got {actual.get(key)!r}")
    log_fields = string_set(fixtures.get("required_log_fields"), "zero_unapproved_fixtures.required_log_fields", "missing_telemetry_binding")
    missing_fields = missing(REQUIRED_LOG_FIELDS, log_fields)
    if missing_fields:
        add_error("missing_telemetry_binding", f"fixture pack required_log_fields missing {missing_fields}")
    events.append(
        event(
            "replacement_profile_validated",
            "pass",
            total_call_throughs=actual.get("total_call_throughs"),
            fixture_count=actual.get("fixture_count"),
            current_level=actual.get("current_level"),
        )
    )


def run_command(command: list[str], signature: str, timeout: int = 180, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env={**dict(**__import__("os").environ), **(env or {})},
        )
    except Exception as exc:
        add_error(signature, f"{' '.join(command)} could not run: {exc}")
        return None


def validate_guard_report(mode: str, report: dict[str, Any], expected: dict[str, Any]) -> None:
    if report.get("schema_version") != "v1" or report.get("mode") != mode:
        add_error("replacement_guard_outcome_drift", f"{mode} report has wrong schema/mode")
    if bool(report.get("ok")) != bool(expected.get("expected_ok")):
        add_error("replacement_guard_outcome_drift", f"{mode} ok expected {expected.get('expected_ok')!r} got {report.get('ok')!r}")
    if report.get("total_call_throughs") != expected.get("total_call_throughs"):
        add_error("replacement_guard_outcome_drift", f"{mode} total_call_throughs drift")
    violations = report.get("violations")
    if isinstance(violations, list):
        violation_count = len(violations)
    elif isinstance(violations, int):
        violation_count = violations
    else:
        violation_count = None
        add_error("replacement_guard_outcome_drift", f"{mode}.violations must be a count or array")
    if violation_count != expected.get("violations"):
        add_error("replacement_guard_outcome_drift", f"{mode} violation count drift")
    if report.get("mutex_forbidden_count") != expected.get("mutex_forbidden_count"):
        add_error("replacement_guard_outcome_drift", f"{mode} mutex forbidden count drift")
    backlog = as_object(report.get("non_threading_backlog"), f"{mode}.non_threading_backlog", "replacement_guard_outcome_drift")
    if backlog.get("callthrough_count") != 0 or backlog.get("module_count") != 0:
        add_error("replacement_guard_outcome_drift", f"{mode} non-threading backlog must be zero")


def run_guard_modes(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    gate_path = str(artifacts.get("replacement_guard_gate", {}).get("path", ""))
    expected_modes = as_array(completion.get("required_guard_modes"), "completion_contract.required_guard_modes", "replacement_guard_outcome_drift")
    for row in expected_modes:
        expected = as_object(row, "required_guard_modes[]", "replacement_guard_outcome_drift")
        mode = str(expected.get("mode", ""))
        report_path = OUT_DIR / f"replacement_guard_{mode}.report.json"
        log_path = OUT_DIR / f"replacement_guard_{mode}.log.jsonl"
        output = run_command(
            ["bash", str(resolve(gate_path)), mode],
            "replacement_guard_outcome_drift",
            env={
                "FRANKENLIBC_REPLACEMENT_GUARD_REPORT": str(report_path),
                "FRANKENLIBC_REPLACEMENT_GUARD_LOG": str(log_path),
            },
        )
        if output is None:
            continue
        if output.returncode != expected.get("expected_exit"):
            add_error("replacement_guard_outcome_drift", f"{mode} expected exit {expected.get('expected_exit')} got {output.returncode}")
        combined = output.stdout + "\n" + output.stderr
        if "check_replacement_guard: PASS" not in combined:
            add_error("replacement_guard_outcome_drift", f"{mode} guard output missing PASS marker")
        report = load_json(report_path, f"replacement_guard_{mode}_report", "replacement_guard_outcome_drift")
        artifact_refs.add(rel(log_path))
        validate_guard_report(mode, as_object(report, f"{mode}.report", "replacement_guard_outcome_drift"), expected)
        events.append(
            event(
                f"replacement_guard_{mode}_replayed",
                "pass" if output.returncode == expected.get("expected_exit") else "fail",
                "none" if output.returncode == expected.get("expected_exit") else "replacement_guard_outcome_drift",
                total_call_throughs=report.get("total_call_throughs"),
                violations=report.get("violations"),
            )
        )


def run_level_and_inventory_gates(artifacts: dict[str, dict[str, Any]]) -> None:
    levels_path = str(artifacts.get("replacement_levels_gate", {}).get("path", ""))
    levels = run_command(["bash", str(resolve(levels_path))], "replacement_levels_gate_failed")
    if levels is None or levels.returncode != 0:
        add_error("replacement_levels_gate_failed", "replacement levels gate failed")
    elif "check_replacement_levels: PASS" not in levels.stdout:
        add_error("replacement_levels_gate_failed", "replacement levels gate output missing PASS marker")
    events.append(
        event(
            "replacement_levels_gate_replayed",
            "pass" if levels is not None and levels.returncode == 0 else "fail",
            "none" if levels is not None and levels.returncode == 0 else "replacement_levels_gate_failed",
        )
    )

    inventory_path = str(artifacts.get("host_dependency_gate", {}).get("path", ""))
    inventory = run_command(["bash", str(resolve(inventory_path))], "host_dependency_gate_failed", timeout=240)
    if inventory is None or inventory.returncode != 0:
        add_error("host_dependency_gate_failed", "host dependency inventory gate failed")
        return
    report = load_json(ROOT / "target/conformance/host_libc_dependency_inventory.report.json", "host_dependency_inventory_report", "host_dependency_gate_failed")
    if report.get("status") != "pass":
        add_error("host_dependency_gate_failed", "host dependency inventory report status must be pass")
    events.append(
        event(
            "host_dependency_inventory_gate_replayed",
            "pass" if report.get("status") == "pass" else "fail",
            "none" if report.get("status") == "pass" else "host_dependency_gate_failed",
            l2_l3_blockers=len(report.get("l2_l3_blockers", [])) if isinstance(report.get("l2_l3_blockers"), list) else None,
        )
    )


def require_contains(path_text: str, needles: set[str], signature: str) -> None:
    text = read_text(path_text, signature)
    for needle in sorted(needles):
        if needle not in text:
            add_error(signature, f"{path_text} missing required text: {needle}")


def validate_harness_and_completion_tests(contract: dict[str, Any], completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    harness_path = str(artifacts.get("replacement_guard_harness_test", {}).get("path", ""))
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
            "replacement guard script failed",
            "standalone build result must match replacement guard result",
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
        events.append(event("replacement_guard_recheck_completion_contract_validated", "pass"))
    else:
        events.append(
            event(
                "replacement_guard_recheck_completion_contract_failed",
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
            "PASS replacement guard recheck completion contract "
            f"sources={summary.get('source_artifacts', 0)} events={len(events)}"
        )
        sys.exit(0)
    print(
        "FAIL replacement guard recheck completion contract "
        f"signature={primary_signature()} errors={len(errors)} report={rel(REPORT)}",
        file=sys.stderr,
    )
    sys.exit(1)


def main() -> None:
    contract = as_object(load_json(CONTRACT, "contract"), "contract")
    artifacts = artifact_map(contract)
    completion = validate_contract_shape(contract)
    validate_missing_item_bindings(contract)
    validate_replacement_profile(completion, artifacts)
    run_guard_modes(completion, artifacts)
    run_level_and_inventory_gates(artifacts)
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
