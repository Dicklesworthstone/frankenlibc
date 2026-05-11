#!/usr/bin/env bash
# Validate bd-0agsk.11.1 runtime-mode evidence logging completion proof.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RUNTIME_MODE_EVIDENCE_COMPLETION_CONTRACT:-${1:-${ROOT}/tests/conformance/runtime_mode_evidence_logging_coverage_completion_contract.v1.json}}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MODE_EVIDENCE_COMPLETION_OUT_DIR:-${2:-${ROOT}/target/conformance}}"
REPORT="${FRANKENLIBC_RUNTIME_MODE_EVIDENCE_COMPLETION_REPORT:-${OUT_DIR}/runtime_mode_evidence_logging_coverage_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MODE_EVIDENCE_COMPLETION_LOG:-${OUT_DIR}/runtime_mode_evidence_logging_coverage_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${OUT_DIR}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1]).resolve()
contract_path = Path(sys.argv[2]).resolve()
out_dir = Path(sys.argv[3]).resolve()
report_path = Path(sys.argv[4]).resolve()
log_path = Path(sys.argv[5]).resolve()
source_commit = sys.argv[6]

SCHEMA = "runtime_mode_evidence_logging_coverage_completion_contract.v1"
BEAD_ID = "bd-0agsk.11.1"
ORIGINAL_BEAD = "bd-0agsk.11"
TRACE_ID = "bd-0agsk.11.1::runtime-mode-evidence-logging::v1"
REQUIRED_SPEC_ITEMS = {"tests.conformance.primary", "telemetry.primary"}
REQUIRED_SOURCE_TESTS = {
    "runtime_mode_coverage_gate_passes_current_contract",
    "runtime_mode_coverage_gate_fails_when_startup_evidence_is_removed",
    "isolated_conformance_child_overrides_ambient_mode_and_logs_startup",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_completion_binding",
    "source_contract_drift",
    "source_checker_failed",
    "telemetry_output_drift",
    "conformance_binding_drift",
    "completion_output_contract_failed",
]

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {row["failure_signature"] for row in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "completion_output_contract_failed"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("malformed_contract", f"{label}: cannot parse {rel(path)}: {exc}")
        return {}


def load_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    try:
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                if isinstance(row, dict):
                    rows.append(row)
                else:
                    add_error("telemetry_output_drift", f"{label}: JSONL row must be object")
        return rows
    except Exception as exc:
        add_error("telemetry_output_drift", f"{label}: cannot parse {rel(path)}: {exc}")
        return []


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def resolve_ref(ref: str) -> Path:
    return resolve(ref.split(":", 1)[0])


def require(condition: bool, signature: str, message: str) -> None:
    if not condition:
        add_error(signature, message)


def require_array(row: dict[str, Any], field: str, ctx: str, signature: str) -> list[Any]:
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    add_error(signature, f"{ctx}.{field} must be a non-empty array")
    return []


def string_list(row: dict[str, Any], field: str, ctx: str, signature: str) -> list[str]:
    result: list[str] = []
    for index, value in enumerate(require_array(row, field, ctx, signature)):
        if isinstance(value, str) and value:
            result.append(value)
        else:
            add_error("malformed_contract", f"{ctx}.{field}[{index}] must be a non-empty string")
    return result


def event(
    name: str,
    status: str,
    scenario_id: str,
    expected: Any,
    actual: Any,
    refs: list[str],
    failure: str = "none",
) -> dict[str, Any]:
    return {
        "timestamp": now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "scenario_id": scenario_id,
        "event": name,
        "status": status,
        "expected": expected,
        "actual": actual,
        "artifact_refs": sorted(set(refs)),
        "source_commit": source_commit,
        "failure_signature": failure,
    }


def base_report(status: str, contract: dict[str, Any], refs: list[str]) -> dict[str, Any]:
    evidence = contract.get("completion_debt_evidence", {})
    bindings = evidence.get("missing_item_bindings", []) if isinstance(evidence, dict) else []
    runtime = contract.get("runtime_mode_evidence_contract", {})
    expected_summary = runtime.get("expected_summary", {}) if isinstance(runtime, dict) else {}
    return {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": status,
        "summary": {
            "binding_count": len(bindings) if isinstance(bindings, list) else 0,
            "campaign_count": len(runtime.get("required_campaign_ids", [])) if isinstance(runtime, dict) else 0,
            "expected_coverage_rows": expected_summary.get("coverage_row_count"),
            "expected_startup_rows": expected_summary.get("startup_evidence_row_count"),
            "log_row_count": len(events),
            "source_artifact_count": len(contract.get("source_artifacts", []))
            if isinstance(contract.get("source_artifacts"), list)
            else 0,
        },
        "source_artifacts": contract.get("source_artifacts", []),
        "missing_item_bindings": bindings if isinstance(bindings, list) else [],
        "runtime_mode_evidence": runtime if isinstance(runtime, dict) else {},
        "artifact_refs": sorted(set(refs)),
        "errors": errors,
    }


def fail_report(stage: str, contract: dict[str, Any], refs: list[str] | None = None) -> None:
    all_refs = sorted(set([rel(contract_path), rel(report_path), rel(log_path), *(refs or [])]))
    events.append(
        event(
            stage + "_failed",
            "fail",
            stage,
            "completion contract passes",
            primary_signature(),
            all_refs,
            primary_signature(),
        )
    )
    write_json(report_path, base_report("fail", contract, all_refs))
    write_jsonl(log_path, events)
    print(
        f"FAIL runtime_mode_evidence_logging_coverage_completion_contract primary_failure={primary_signature()} report={rel(report_path)} log={rel(log_path)}",
        file=sys.stderr,
    )
    raise SystemExit(1)


def validate_source_artifacts(contract: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for index, artifact in enumerate(require_array(contract, "source_artifacts", "contract", "malformed_contract")):
        if not isinstance(artifact, dict):
            add_error("malformed_contract", f"source_artifacts[{index}] must be an object")
            continue
        artifact_id = artifact.get("id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            add_error("malformed_contract", f"source_artifacts[{index}].id must be non-empty")
        if not isinstance(path_text, str) or not path_text:
            add_error("malformed_contract", f"source_artifacts[{index}].path must be non-empty")
            continue
        path = resolve(path_text)
        refs.append(rel(path))
        if not path.exists():
            add_error("missing_source_artifact", f"{artifact_id or index}: missing {rel(path)}")
    if not errors:
        events.append(event("source_artifacts_validated", "pass", "source-artifacts", "all sources exist", len(refs), refs))
    return refs


def validate_bindings(contract: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = contract.get("completion_debt_evidence", {})
    if not isinstance(evidence, dict):
        add_error("malformed_contract", "completion_debt_evidence must be an object")
        return []
    bindings = evidence.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        add_error("missing_completion_binding", "completion_debt_evidence.missing_item_bindings must bind conformance and telemetry")
        return []
    seen: set[str] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            add_error("malformed_contract", f"missing_item_bindings[{index}] must be an object")
            continue
        spec_item = binding.get("spec_item")
        if not isinstance(spec_item, str) or not spec_item:
            add_error("malformed_contract", f"missing_item_bindings[{index}].spec_item must be non-empty")
            continue
        seen.add(spec_item)
        for field in ("implementation_refs", "test_refs", "required_positive_tests", "required_negative_tests", "required_commands"):
            string_list(binding, field, f"missing_item_bindings[{index}]", "missing_completion_binding")
        for ref in string_list(binding, "implementation_refs", f"missing_item_bindings[{index}]", "missing_completion_binding"):
            if not resolve_ref(ref).exists():
                add_error("missing_source_artifact", f"implementation ref missing: {ref}")
        for ref in string_list(binding, "test_refs", f"missing_item_bindings[{index}]", "missing_completion_binding"):
            if not resolve_ref(ref).exists():
                add_error("missing_source_artifact", f"test ref missing: {ref}")
    for spec_item in sorted(REQUIRED_SPEC_ITEMS - seen):
        add_error("missing_completion_binding", f"missing binding for {spec_item}")
    unexpected = seen - REQUIRED_SPEC_ITEMS
    for spec_item in sorted(unexpected):
        add_error("missing_completion_binding", f"unexpected binding for {spec_item}")
    if not errors:
        events.append(
            event(
                "completion_bindings_validated",
                "pass",
                "completion-debt-bindings",
                sorted(REQUIRED_SPEC_ITEMS),
                sorted(seen),
                [rel(contract_path)],
            )
        )
    return [binding for binding in bindings if isinstance(binding, dict)]


def validate_source_contract(runtime: dict[str, Any], refs: list[str]) -> dict[str, Any]:
    source_path = resolve(str(runtime.get("source_contract_path", "")))
    refs.append(rel(source_path))
    source = load_json(source_path, "source runtime-mode evidence contract")
    require(source.get("schema_version") == runtime.get("expected_schema"), "source_contract_drift", "source schema drift")
    require(source.get("generated_by_bead") == runtime.get("expected_generated_by_bead"), "source_contract_drift", "source generated_by_bead drift")

    expected_summary = runtime.get("expected_summary", {})
    summary = source.get("summary", {})
    if not isinstance(expected_summary, dict) or not isinstance(summary, dict):
        add_error("source_contract_drift", "source and expected summaries must be objects")
    else:
        for key, expected in expected_summary.items():
            if summary.get(key) != expected:
                add_error("source_contract_drift", f"source summary {key} expected {expected!r}, found {summary.get(key)!r}")

    expected_campaigns = set(string_list(runtime, "required_campaign_ids", "runtime_mode_evidence_contract", "source_contract_drift"))
    rows = source.get("coverage_rows")
    if isinstance(rows, list):
        actual_campaigns = {row.get("campaign_id") for row in rows if isinstance(row, dict)}
        if actual_campaigns != expected_campaigns:
            add_error("source_contract_drift", f"campaign set drifted: expected {sorted(expected_campaigns)!r}, found {sorted(actual_campaigns)!r}")
    else:
        add_error("source_contract_drift", "source coverage_rows must be an array")

    required_policy = runtime.get("required_policy", {})
    policy = source.get("coverage_policy", {})
    if not isinstance(required_policy, dict) or not isinstance(policy, dict):
        add_error("source_contract_drift", "source and required policies must be objects")
    else:
        for key, expected in required_policy.items():
            actual = policy.get(key)
            if isinstance(expected, list):
                if set(actual or []) != set(expected):
                    add_error("source_contract_drift", f"policy {key} expected {expected!r}, found {actual!r}")
            elif actual != expected:
                add_error("source_contract_drift", f"policy {key} expected {expected!r}, found {actual!r}")

    expected_failures = set(string_list(runtime, "required_failure_signatures", "runtime_mode_evidence_contract", "source_contract_drift"))
    actual_failures = {
        test.get("expected_failure_signature")
        for test in source.get("negative_tests", [])
        if isinstance(test, dict)
    }
    missing_failures = expected_failures - actual_failures
    for signature in sorted(missing_failures):
        add_error("source_contract_drift", f"source negative tests missing {signature}")

    if not errors:
        events.append(
            event(
                "source_contract_validated",
                "pass",
                "runtime-mode-source-contract",
                {
                    "campaigns": sorted(expected_campaigns),
                    "summary": expected_summary,
                },
                {
                    "campaigns": sorted(actual_campaigns),
                    "summary": summary,
                },
                refs,
            )
        )
    return source if isinstance(source, dict) else {}


def run_source_checker(runtime: dict[str, Any], refs: list[str]) -> tuple[Path, Path]:
    checker = resolve(str(runtime.get("source_checker_path", "")))
    refs.append(rel(checker))
    if not checker.exists():
        add_error("missing_source_artifact", f"source checker missing: {rel(checker)}")
        return (out_dir / "runtime_mode_evidence_logging_coverage.source.report.json", out_dir / "runtime_mode_evidence_logging_coverage.source.log.jsonl")

    source_report = out_dir / "runtime_mode_evidence_logging_coverage.source.report.json"
    source_log = out_dir / "runtime_mode_evidence_logging_coverage.source.log.jsonl"
    env = os.environ.copy()
    env["RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_REPORT"] = str(source_report)
    env["RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_LOG"] = str(source_log)
    env["RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_CONTRACT"] = str(resolve(str(runtime.get("source_contract_path", ""))))
    result = subprocess.run(
        ["bash", str(checker), "--validate-only"],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    refs.extend([rel(source_report), rel(source_log)])
    if result.returncode != 0:
        add_error("source_checker_failed", f"source checker failed: stdout={result.stdout.strip()} stderr={result.stderr.strip()}")
    elif not source_report.exists() or not source_log.exists():
        add_error("source_checker_failed", "source checker did not emit report and log")
    elif not errors:
        events.append(
            event(
                "source_checker_replayed",
                "pass",
                "runtime-mode-source-checker",
                "exit 0 with report/log",
                {"stdout": result.stdout.strip(), "stderr": result.stderr.strip()},
                refs,
            )
        )
    return (source_report, source_log)


def validate_telemetry(runtime: dict[str, Any], source_report: Path, source_log: Path, refs: list[str]) -> None:
    report = load_json(source_report, "source checker report")
    rows = load_jsonl(source_log, "source checker log")
    expected_report = runtime.get("expected_source_report", {})
    if not isinstance(expected_report, dict):
        add_error("telemetry_output_drift", "expected_source_report must be an object")
        return
    for key in ("schema_version", "bead", "outcome", "failure_signature"):
        if report.get(key) != expected_report.get(key):
            add_error("telemetry_output_drift", f"source report {key} expected {expected_report.get(key)!r}, found {report.get(key)!r}")
    summary = report.get("summary", {})
    if not isinstance(summary, dict):
        add_error("telemetry_output_drift", "source report summary must be an object")
    else:
        if summary.get("coverage_rows") != expected_report.get("coverage_rows"):
            add_error("telemetry_output_drift", "source report coverage_rows drifted")
        if summary.get("startup_evidence_rows") != expected_report.get("startup_evidence_rows"):
            add_error("telemetry_output_drift", "source report startup_evidence_rows drifted")

    expected_event = runtime.get("expected_source_log_event")
    if not any(row.get("event") == expected_event and row.get("outcome") == "pass" for row in rows):
        add_error("telemetry_output_drift", f"source log missing pass event {expected_event}")

    if not errors:
        events.append(
            event(
                "telemetry_output_validated",
                "pass",
                "runtime-mode-source-telemetry",
                expected_report,
                {"report": report, "log_rows": len(rows)},
                refs,
            )
        )


def validate_conformance_tests(runtime: dict[str, Any], refs: list[str]) -> None:
    source_test = resolve(str(runtime.get("source_test_path", "")))
    refs.append(rel(source_test))
    try:
        text = source_test.read_text(encoding="utf-8")
    except Exception as exc:
        add_error("missing_source_artifact", f"source test cannot be read: {rel(source_test)}: {exc}")
        return
    declared_tests = set(string_list(runtime, "required_source_tests", "runtime_mode_evidence_contract", "conformance_binding_drift"))
    if declared_tests != REQUIRED_SOURCE_TESTS:
        add_error("conformance_binding_drift", f"required_source_tests drifted: expected {sorted(REQUIRED_SOURCE_TESTS)!r}, found {sorted(declared_tests)!r}")
    for test_name in sorted(REQUIRED_SOURCE_TESTS):
        if f"fn {test_name}" not in text:
            add_error("conformance_binding_drift", f"source test missing fn {test_name}")
    for term in string_list(runtime, "required_source_test_terms", "runtime_mode_evidence_contract", "conformance_binding_drift"):
        if term not in text:
            add_error("conformance_binding_drift", f"source test missing term {term!r}")
    if not errors:
        events.append(
            event(
                "conformance_test_bindings_validated",
                "pass",
                "runtime-mode-source-tests",
                sorted(REQUIRED_SOURCE_TESTS),
                sorted(declared_tests),
                refs,
            )
        )


def validate_output_contract(contract: dict[str, Any]) -> None:
    output = contract.get("completion_output_contract")
    if not isinstance(output, dict):
        add_error("malformed_contract", "completion_output_contract must be an object")
        return
    required_events = set(string_list(output, "required_events", "completion_output_contract", "completion_output_contract_failed"))
    actual_events = {row["event"] for row in events}
    missing_events = required_events - actual_events - {"runtime_mode_evidence_logging_coverage_completion_contract_pass"}
    for event_name in sorted(missing_events):
        add_error("completion_output_contract_failed", f"missing event {event_name}")


contract = load_json(contract_path, "completion contract")
if errors:
    fail_report("load_contract", contract, [rel(contract_path)])

require(contract.get("schema_version") == SCHEMA, "malformed_contract", "schema_version mismatch")
require(contract.get("bead") == BEAD_ID, "malformed_contract", "bead mismatch")
require(contract.get("original_bead") == ORIGINAL_BEAD, "malformed_contract", "original_bead mismatch")
require(contract.get("trace_id") == TRACE_ID, "malformed_contract", "trace_id mismatch")

runtime = contract.get("runtime_mode_evidence_contract")
if not isinstance(runtime, dict):
    add_error("malformed_contract", "runtime_mode_evidence_contract must be an object")
    runtime = {}

artifact_refs = [rel(contract_path)]
artifact_refs.extend(validate_source_artifacts(contract))
validate_bindings(contract)
validate_source_contract(runtime, artifact_refs)
source_report, source_log = run_source_checker(runtime, artifact_refs)
validate_telemetry(runtime, source_report, source_log, artifact_refs)
validate_conformance_tests(runtime, artifact_refs)
validate_output_contract(contract)

if errors:
    fail_report("validate_contract", contract, artifact_refs)

events.append(
    event(
        "runtime_mode_evidence_logging_coverage_completion_contract_pass",
        "pass",
        "completion-output",
        "all required events emitted",
        [row["event"] for row in events],
        artifact_refs,
    )
)
write_json(report_path, base_report("pass", contract, [*artifact_refs, rel(report_path), rel(log_path)]))
write_jsonl(log_path, events)
summary = base_report("pass", contract, [])["summary"]
print(
    "PASS runtime_mode_evidence_logging_coverage_completion_contract "
    f"campaigns={summary['campaign_count']} bindings={summary['binding_count']} "
    f"events={len(events)} report={rel(report_path)} log={rel(log_path)}"
)
PY
