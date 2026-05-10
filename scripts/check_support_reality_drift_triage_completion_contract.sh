#!/usr/bin/env bash
# check_support_reality_drift_triage_completion_contract.sh -- fail-closed conformance evidence gate for bd-0agsk.4.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${SUPPORT_REALITY_DRIFT_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/support_reality_drift_triage_completion_contract.v1.json}"
OUT_DIR="${SUPPORT_REALITY_DRIFT_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${SUPPORT_REALITY_DRIFT_COMPLETION_REPORT:-${OUT_DIR}/support_reality_drift_triage_completion_contract.report.json}"
LOG="${SUPPORT_REALITY_DRIFT_COMPLETION_LOG:-${OUT_DIR}/support_reality_drift_triage_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
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

BEAD_ID = "bd-0agsk.4"
COMPLETION_DEBT_BEAD_ID = "bd-0agsk.4.1"
MANIFEST_ID = "support-reality-drift-triage-completion-contract"
REQUIRED_EVENTS = {
    "support_reality_drift_completion_source",
    "support_reality_drift_completion_conformance",
    "support_reality_drift_completion_summary",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str], context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{context} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{context} must be a JSON object")
        return {}
    return value


def read_text(path_text: str, errors: list[str], context: str) -> str:
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} missing file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{context} unreadable: {path_text}: {exc}")
        return ""


def validate_line_ref(ref: Any, errors: list[str], context: str) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"{context} must be a file:line string")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{context} has invalid line number: {ref}")
        return
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        errors.append(f"{context} references line past EOF: {ref}")
    elif not lines[line_number - 1].strip():
        errors.append(f"{context} references blank line: {ref}")


def validate_command_policy(contract: dict[str, Any], errors: list[str]) -> None:
    runtime = contract.get("runtime_target")
    if not isinstance(runtime, dict):
        errors.append("runtime_target must be an object")
        return
    allowed = runtime.get("allowed_command_prefixes")
    forbidden = runtime.get("forbidden_command_substrings")
    if not isinstance(allowed, list) or not all(isinstance(item, str) and item for item in allowed):
        errors.append("runtime_target.allowed_command_prefixes must be non-empty strings")
        allowed = []
    if not isinstance(forbidden, list) or not all(isinstance(item, str) and item for item in forbidden):
        errors.append("runtime_target.forbidden_command_substrings must be non-empty strings")
        forbidden = []
    for scenario in contract.get("conformance_primary", {}).get("scenarios", []):
        if not isinstance(scenario, dict) or not isinstance(scenario.get("command"), str):
            continue
        command = scenario["command"]
        scenario_id = str(scenario.get("scenario_id", "unknown"))
        if not any(command.startswith(prefix) for prefix in allowed):
            errors.append(f"{scenario_id} command is not allowlisted: {command}")
        if command.startswith("rch cargo"):
            pass
        for needle in forbidden:
            if needle in command and not command.startswith("rch cargo"):
                errors.append(f"{scenario_id} command contains forbidden substring {needle!r}")


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    test_source = evidence.get("test_source")
    if not isinstance(test_source, str) or not test_source:
        errors.append("completion_debt_evidence.test_source missing")
        source = ""
    else:
        source = read_text(test_source, errors, "completion_debt_evidence.test_source")
    conformance = evidence.get("conformance_primary")
    if not isinstance(conformance, dict):
        errors.append("completion_debt_evidence.conformance_primary missing")
        return
    if conformance.get("missing_item_id") != "tests.conformance.primary":
        errors.append("completion_debt_evidence.conformance_primary.missing_item_id must be tests.conformance.primary")
    names = conformance.get("required_test_names")
    if not isinstance(names, list) or not names:
        errors.append("completion_debt_evidence.conformance_primary.required_test_names missing")
        return
    for name in names:
        if not isinstance(name, str) or f"fn {name}(" not in source:
            errors.append(f"completion_debt_evidence references missing Rust test {name}")


def validate_contract(contract: dict[str, Any], errors: list[str]) -> list[dict[str, Any]]:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD_ID}")

    artifacts = contract.get("source_artifacts")
    source_rows: list[dict[str, Any]] = []
    if not isinstance(artifacts, dict):
        errors.append("source_artifacts must be an object")
        artifacts = {}
    for artifact_id, path_text in artifacts.items():
        if not isinstance(path_text, str) or not (root / path_text).is_file():
            errors.append(f"source_artifacts.{artifact_id} missing file: {path_text}")
            status = "fail"
        else:
            status = "pass"
        source_rows.append({
            "artifact_id": artifact_id,
            "path": path_text,
            "status": status,
        })

    triage_path = artifacts.get("triage_report")
    triage = load_json(root / triage_path, errors, "source_artifacts.triage_report") if isinstance(triage_path, str) else {}
    invariants = contract.get("triage_invariants")
    if not isinstance(invariants, dict):
        errors.append("triage_invariants must be an object")
        invariants = {}
    if triage:
        if triage.get("schema_version") != invariants.get("schema_version"):
            errors.append("triage schema_version drift")
        if triage.get("generated_by_bead") != BEAD_ID:
            errors.append(f"triage generated_by_bead must be {BEAD_ID}")
        if triage.get("claim_status") != invariants.get("claim_status"):
            errors.append("triage claim_status drift")

        allowed = set(triage.get("classification_policy", {}).get("allowed_classifications", []))
        expected_allowed = set(invariants.get("allowed_classifications", []))
        if allowed != expected_allowed:
            errors.append("triage allowed_classifications drift")

        summary = triage.get("summary", {})
        expected_summary = invariants.get("summary", {})
        if not isinstance(summary, dict) or not isinstance(expected_summary, dict):
            errors.append("triage summary must be objects")
        else:
            for key, expected in expected_summary.items():
                if summary.get(key) != expected:
                    errors.append(f"triage summary count mismatch: {key} expected {expected} got {summary.get(key)}")

        buckets = triage.get("delta_buckets")
        if not isinstance(buckets, list):
            errors.append("triage delta_buckets must be array")
            buckets = []
        buckets_by_id = {
            str(bucket.get("id")): bucket
            for bucket in buckets
            if isinstance(bucket, dict) and bucket.get("id")
        }
        for required in invariants.get("required_delta_buckets", []):
            if not isinstance(required, dict):
                errors.append("triage required_delta_buckets entries must be objects")
                continue
            bucket_id = required.get("id")
            bucket = buckets_by_id.get(str(bucket_id))
            if not isinstance(bucket, dict):
                errors.append(f"missing required triage delta bucket {bucket_id}")
                continue
            if bucket.get("classification") != required.get("classification"):
                errors.append(f"{bucket_id} classification drift")
            symbols = bucket.get("symbols")
            if not isinstance(symbols, list):
                errors.append(f"{bucket_id}.symbols must be array")
                symbols = []
            min_count = required.get("min_symbol_count")
            if not isinstance(min_count, int) or len(symbols) < min_count:
                errors.append(f"{bucket_id}.symbols below min count")
            for symbol in required.get("required_symbols", []):
                if symbol not in symbols:
                    errors.append(f"{bucket_id} missing symbol {symbol}")

    checker = contract.get("checker_contract", {})
    if not isinstance(checker, dict):
        errors.append("checker_contract must be object")
    else:
        script = checker.get("script")
        source = read_text(script, errors, "checker_contract.script") if isinstance(script, str) else ""
        for needle in checker.get("required_script_needles", []):
            if not isinstance(needle, str) or needle not in source:
                errors.append(f"checker_contract.script missing needle {needle}")

    rust = contract.get("rust_conformance_contract", {})
    if not isinstance(rust, dict):
        errors.append("rust_conformance_contract must be object")
    else:
        test_file = rust.get("test_file")
        source = read_text(test_file, errors, "rust_conformance_contract.test_file") if isinstance(test_file, str) else ""
        tests = rust.get("required_tests")
        if not isinstance(tests, list) or not tests:
            errors.append("rust_conformance_contract.required_tests must be non-empty array")
            tests = []
        for item in tests:
            if not isinstance(item, dict):
                errors.append("rust_conformance_contract.required_tests entries must be objects")
                continue
            test_name = item.get("test")
            if not isinstance(test_name, str) or f"fn {test_name}(" not in source:
                errors.append(f"missing required Rust conformance test {test_name}")
            if "line_ref" in item:
                validate_line_ref(item["line_ref"], errors, f"rust_conformance_contract.{test_name}.line_ref")

    conformance = contract.get("conformance_primary", {})
    if not isinstance(conformance, dict):
        errors.append("conformance_primary must be object")
    else:
        if conformance.get("missing_item_id") != "tests.conformance.primary":
            errors.append("conformance_primary.missing_item_id must be tests.conformance.primary")
        scenarios = conformance.get("scenarios")
        if not isinstance(scenarios, list) or len(scenarios) < 3:
            errors.append("conformance_primary.scenarios must contain at least three scenarios")
        if isinstance(scenarios, list):
            ids = {scenario.get("scenario_id") for scenario in scenarios if isinstance(scenario, dict)}
            required_ids = {
                "triage_checker_passes_live_inputs",
                "rust_conformance_binds_positive_and_negative_cases",
                "fail_closed_contract_mutations_are_rejected",
            }
            missing = sorted(required_ids - ids)
            if missing:
                errors.append(f"conformance_primary.scenarios missing {missing}")

    telemetry = contract.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be object")
    else:
        fields = telemetry.get("required_log_fields")
        events = telemetry.get("required_log_events")
        if not isinstance(fields, list) or len(fields) < 8:
            errors.append("telemetry_contract.required_log_fields missing")
        if not isinstance(events, list) or set(events) != REQUIRED_EVENTS:
            errors.append("telemetry_contract.required_log_events drifted")

    validate_command_policy(contract, errors)
    validate_completion_evidence(contract, errors)
    return source_rows


def run_original_checker(errors: list[str], contract: dict[str, Any]) -> dict[str, Any]:
    checker_path = contract["source_artifacts"]["checker"]
    result = subprocess.run(
        ["bash", checker_path, "--validate-only"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=90,
    )
    row = {
        "scenario_id": "triage_checker_passes_live_inputs",
        "exit_code": result.returncode,
        "status": "pass" if result.returncode == 0 else "fail",
        "stdout_tail": result.stdout[-1000:],
        "stderr_tail": result.stderr[-1000:],
        "failure_signature": "none" if result.returncode == 0 else "original_checker_failed",
        "artifact_refs": [
            checker_path,
            "target/conformance/support_reality_drift_triage.report.json",
            "target/conformance/support_reality_drift_triage.log.jsonl",
        ],
    }
    if result.returncode != 0:
        errors.append(f"triage_checker_passes_live_inputs expected exit 0 got {result.returncode}")
        return row

    original_report = load_json(root / "target/conformance/support_reality_drift_triage.report.json", errors, "original_checker.report")
    if original_report:
        if original_report.get("schema_version") != contract["checker_contract"]["expected_report_schema"]:
            errors.append("original checker report schema drift")
        if original_report.get("outcome") != "pass":
            errors.append("original checker report outcome must be pass")
        if original_report.get("summary", {}).get("delta_symbol_count") != 75:
            errors.append("original checker report delta_symbol_count drift")
    log_path = root / "target/conformance/support_reality_drift_triage.log.jsonl"
    try:
        log_text = log_path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"original checker log unreadable: {exc}")
    else:
        if contract["checker_contract"]["expected_success_event"] not in log_text:
            errors.append("original checker log missing success event")
    return row


errors: list[str] = []
warnings: list[str] = []
contract = load_json(contract_path, errors, "contract")
source_rows = validate_contract(contract, errors) if contract else []
conformance_rows = [run_original_checker(errors, contract)] if contract and not errors else []
timestamp = utc_now()

source_log_rows = []
for row in source_rows:
    source_log_rows.append({
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:{row['artifact_id']}",
        "event": "support_reality_drift_completion_source",
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "artifact_id": row["artifact_id"],
        "scenario_id": None,
        "status": row["status"],
        "artifact_refs": [row["path"], rel(contract_path)],
        "failure_signature": "none" if row["status"] == "pass" else "source_artifact_missing",
    })

conformance_log_rows = []
for row in conformance_rows:
    conformance_log_rows.append({
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:{row['scenario_id']}",
        "event": "support_reality_drift_completion_conformance",
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "artifact_id": None,
        "scenario_id": row["scenario_id"],
        "status": row["status"],
        "artifact_refs": row["artifact_refs"] + [rel(contract_path)],
        "failure_signature": row["failure_signature"],
        "exit_code": row["exit_code"],
        "stdout_tail": row["stdout_tail"],
        "stderr_tail": row["stderr_tail"],
    })

summary = {
    "schema_version": "support_reality_drift_triage_completion_contract.report.v1",
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "contract": rel(contract_path),
    "source_artifact_count": len(source_rows),
    "conformance_scenario_count": len(conformance_rows),
    "errors": errors,
    "warnings": warnings,
    "status": "pass" if not errors else "fail",
    "report_path": rel(report_path),
    "log_path": rel(log_path),
}

summary_row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:summary",
    "event": "support_reality_drift_completion_summary",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "artifact_id": None,
    "scenario_id": None,
    "status": summary["status"],
    "artifact_refs": [rel(contract_path), rel(report_path), rel(log_path)],
    "failure_signature": "none" if not errors else "contract_validation_error",
}

log_rows = source_log_rows + conformance_log_rows + [summary_row]
report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")

print(
    "support_reality_drift_triage_completion_contract: "
    f"status={summary['status']} sources={summary['source_artifact_count']} "
    f"conformance={summary['conformance_scenario_count']} errors={len(errors)}"
)
print(f"report={rel(report_path)}")
print(f"log={rel(log_path)} rows={len(log_rows)}")
for error in errors:
    print(f"ERROR: {error}")
if errors:
    sys.exit(1)
PY
