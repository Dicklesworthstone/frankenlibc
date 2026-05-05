#!/usr/bin/env bash
# check_strict_hardened_evidence_e2e.sh -- bd-b92jd.4.3
#
# Static fail-closed validator for hermetic strict/hardened runtime-evidence
# e2e scenarios. The gate emits deterministic JSON and JSONL artifacts under
# target/conformance and never performs cargo builds, network I/O, or
# destructive system operations.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${FRANKENLIBC_STRICT_HARDENED_E2E_GATE:-${ROOT}/tests/conformance/strict_hardened_evidence_e2e.v1.json}"
OUT_DIR="${FRANKENLIBC_STRICT_HARDENED_E2E_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_STRICT_HARDENED_E2E_REPORT:-${OUT_DIR}/strict_hardened_evidence_e2e.report.json}"
LOG="${FRANKENLIBC_STRICT_HARDENED_E2E_LOG:-${OUT_DIR}/strict_hardened_evidence_e2e.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${GATE}" "${REPORT}" "${LOG}" <<'PY'
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
gate_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

TRACE_ID = "bd-b92jd.4.3:strict-hardened-evidence-e2e"
BEAD_ID = "bd-b92jd.4.3"
REQUIRED_FAMILIES = ["string", "malloc", "stdio", "pthread", "resolver"]
REQUIRED_MODES = ["strict", "hardened"]
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "scenario_id",
    "api_family",
    "symbol",
    "runtime_mode",
    "validation_profile",
    "expected_decision",
    "actual_decision",
    "healing_action",
    "denied",
    "target_dir",
    "source_commit",
    "artifact_refs",
    "safety_signature",
    "failure_signature",
]
INPUT_KEYS = [
    "runtime_evidence_module",
    "runtime_evidence_verifier",
    "mode_semantics_matrix",
    "hardened_repair_deny_matrix",
    "log_schema",
    "string_fixture",
    "malloc_fixture",
    "stdio_fixture",
    "pthread_fixture",
    "resolver_fixture",
]
DECISION_TERMINALS = {
    "Allow": "allow",
    "FullValidate": "full_validate",
    "Repair": "repair",
    "Deny": "deny",
}

errors = []
logs = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "input_artifacts_exist": "fail",
    "network_and_destructive_guards": "fail",
    "scenario_contract": "fail",
    "family_mode_coverage": "fail",
    "negative_case_coverage": "fail",
    "structured_log": "fail",
}


def fail(message):
    errors.append(message)


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"json_parse: cannot parse {path}: {exc}")
        return None


def ref_path(ref):
    return str(ref).split("#", 1)[0].rstrip("/")


def safe_path(ref):
    rel_text = ref_path(ref)
    rel_path = Path(rel_text)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise ValueError(f"unsafe artifact path: {rel_text}")
    return root / rel_path


def valid_source_commit(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def normalized_terminal(record):
    path = record.get("decision_path", [])
    if not isinstance(path, list) or not path:
        return ""
    return str(path[-1]).replace("-", "_").lower()


def target_dir_is_safe(value):
    if not isinstance(value, str) or not value:
        return False
    if "\n" in value or "\0" in value:
        return False
    return "/rch_target_frankenlibc_" in value or value.endswith("/target")


def bool_field(mapping, key):
    return mapping.get(key) is True


def validate_refs(refs, context):
    missing = []
    if not isinstance(refs, list) or not refs:
        fail(f"{context}: artifact_refs must be a non-empty list")
        return
    for ref in refs:
        try:
            if not safe_path(ref).exists():
                missing.append(str(ref))
        except Exception as exc:
            missing.append(f"{ref}:{exc}")
    if missing:
        fail(f"{context}: strict_hardened_e2e_artifact_missing: {', '.join(missing)}")


def validate_safety(record, context):
    safety = record.get("operation_safety", {})
    if not isinstance(safety, dict):
        fail(f"{context}: operation_safety must be an object")
        return
    if safety.get("real_network_required") is not False:
        fail(f"{context}: strict_hardened_e2e_real_network_required")
    if safety.get("destructive_system_operation") is not False:
        fail(f"{context}: strict_hardened_e2e_destructive_operation")


def validate_evidence_row(record, context):
    row = record.get("evidence_row", {})
    if not isinstance(row, dict):
        fail(f"{context}: evidence_row must be an object")
        return
    matches = [
        ("bead_id", BEAD_ID),
        ("scenario_id", record.get("scenario_id")),
        ("mode", record.get("mode")),
        ("runtime_mode", record.get("runtime_mode")),
        ("validation_profile", record.get("validation_profile")),
        ("decision_action", record.get("actual_decision")),
        ("denied", record.get("denied")),
        ("api_family", record.get("api_family")),
        ("symbol", record.get("symbol")),
        ("source_commit", record.get("source_commit")),
        ("target_dir", record.get("target_dir")),
        ("runtime_evidence_enabled", True),
    ]
    for key, expected in matches:
        if row.get(key) != expected:
            fail(f"{context}: evidence_row.{key} does not match scenario")
    if row.get("schema") != "frankenlibc.runtime_evidence.v1":
        fail(f"{context}: evidence_row.schema is invalid")
    if record.get("actual_decision") == "Repair" and row.get("healing_action") in (None, "", "None"):
        fail(f"{context}: strict_hardened_e2e_missing_healing_action")
    if record.get("actual_decision") != "Repair" and row.get("healing_action") not in (None, "", "None"):
        fail(f"{context}: non-repair scenario must not carry healing_action")
    if not isinstance(row.get("latency_ns"), int) or row.get("latency_ns") < 0:
        fail(f"{context}: evidence_row.latency_ns must be a non-negative integer")


def validate_scenario(record, policy):
    context = str(record.get("scenario_id", "<missing>"))
    for field in policy.get("required_scenario_fields", []):
        if field not in record:
            fail(f"{context}: missing scenario field {field}")

    family = record.get("api_family")
    mode = record.get("mode")
    runtime_mode = record.get("runtime_mode")
    expected = record.get("expected_decision")
    actual = record.get("actual_decision")
    repair = record.get("expected_repair")
    denied = record.get("denied")

    if family not in REQUIRED_FAMILIES:
        fail(f"{context}: api_family is not required")
    if mode not in REQUIRED_MODES:
        fail(f"{context}: runtime mode is not required")
    if runtime_mode != mode:
        fail(f"{context}: runtime_mode must equal mode")
    if record.get("runtime_evidence_enabled") is not True:
        fail(f"{context}: runtime evidence must be enabled")
    if expected not in DECISION_TERMINALS:
        fail(f"{context}: expected_decision is invalid")
    if actual != expected:
        fail(f"{context}: strict_hardened_e2e_decision_mismatch")
    if normalized_terminal(record) != DECISION_TERMINALS.get(str(expected)):
        fail(f"{context}: decision_path terminal does not match expected_decision")
    if mode == "strict" and expected == "Repair":
        fail(f"{context}: strict_hardened_e2e_strict_repair_not_allowed")
    if mode == "strict" and repair not in (None, "", "None"):
        fail(f"{context}: strict_hardened_e2e_strict_repair_not_allowed")
    if expected == "Repair" and mode != "hardened":
        fail(f"{context}: strict_hardened_e2e_strict_repair_not_allowed")
    if expected == "Repair" and repair in (None, "", "None"):
        fail(f"{context}: strict_hardened_e2e_missing_healing_action")
    if expected == "Deny" and denied is not True:
        fail(f"{context}: deny scenario must set denied=true")
    if expected != "Deny" and denied is not False:
        fail(f"{context}: non-deny scenario must set denied=false")
    if not valid_source_commit(record.get("source_commit")):
        fail(f"{context}: source_commit must be a 40-char lowercase hex commit")
    if not target_dir_is_safe(record.get("target_dir")):
        fail(f"{context}: strict_hardened_e2e_missing_target_dir")
    if record.get("source_commit_state") != "current":
        fail(f"{context}: source_commit_state must be current")

    try:
        if not safe_path(record.get("fixture_case_ref", "")).exists():
            fail(f"{context}: strict_hardened_e2e_artifact_missing: fixture_case_ref")
    except Exception as exc:
        fail(f"{context}: strict_hardened_e2e_artifact_missing: {exc}")

    validate_refs(record.get("artifact_refs", []), context)
    validate_safety(record, context)
    validate_evidence_row(record, context)

    logs.append(
        {
            "trace_id": TRACE_ID,
            "bead_id": BEAD_ID,
            "scenario_id": context,
            "api_family": family,
            "symbol": record.get("symbol"),
            "runtime_mode": runtime_mode,
            "validation_profile": record.get("validation_profile"),
            "expected_decision": expected,
            "actual_decision": actual,
            "healing_action": repair,
            "denied": denied,
            "target_dir": record.get("target_dir"),
            "source_commit": record.get("source_commit"),
            "artifact_refs": record.get("artifact_refs", []),
            "safety_signature": "hermetic_no_network_no_destructive_ops",
            "failure_signature": record.get("failure_signature"),
        }
    )


def validate_negative_cases(gate, policy):
    cases = gate.get("negative_scenario_cases", [])
    scenarios = {
        scenario.get("scenario_id"): scenario
        for scenario in gate.get("scenarios", [])
        if isinstance(scenario, dict)
    }
    required = set(policy.get("required_negative_cases", []))
    signatures = set(policy.get("fail_closed_signatures", []))
    seen = set()
    for case in cases if isinstance(cases, list) else []:
        mutation = case.get("mutation")
        signature = case.get("expected_failure_signature")
        target = case.get("target_scenario_id")
        seen.add(mutation)
        if mutation not in required:
            fail(f"{case.get('case_id', '<missing>')}: mutation is not required")
        if signature not in signatures:
            fail(f"{case.get('case_id', '<missing>')}: failure signature is not fail-closed")
        if target not in scenarios:
            fail(f"{case.get('case_id', '<missing>')}: target scenario is missing")
        logs.append(
            {
                "trace_id": TRACE_ID,
                "bead_id": BEAD_ID,
                "scenario_id": target,
                "api_family": scenarios.get(target, {}).get("api_family"),
                "symbol": scenarios.get(target, {}).get("symbol"),
                "runtime_mode": scenarios.get(target, {}).get("runtime_mode"),
                "validation_profile": scenarios.get(target, {}).get("validation_profile"),
                "expected_decision": "BlockScenario",
                "actual_decision": "BlockScenario",
                "healing_action": scenarios.get(target, {}).get("expected_repair"),
                "denied": True,
                "target_dir": scenarios.get(target, {}).get("target_dir"),
                "source_commit": scenarios.get(target, {}).get("source_commit"),
                "artifact_refs": scenarios.get(target, {}).get("artifact_refs", []),
                "safety_signature": "fail_closed_negative_fixture",
                "failure_signature": signature,
            }
        )
    missing = sorted(required - seen)
    if missing:
        fail("negative cases missing mutations: " + ", ".join(missing))


gate = load_json(gate_path)
if gate is not None:
    checks["json_parse"] = "pass"

if isinstance(gate, dict):
    before = len(errors)
    if gate.get("schema_version") != "v1":
        fail("gate schema_version must be v1")
    if gate.get("manifest_id") != "strict-hardened-evidence-e2e":
        fail("gate manifest_id must be strict-hardened-evidence-e2e")
    if gate.get("bead") != BEAD_ID:
        fail(f"gate bead must be {BEAD_ID}")
    if gate.get("required_api_families") != REQUIRED_FAMILIES:
        fail("gate required_api_families must match bd-b92jd.4.3")
    if gate.get("required_modes") != REQUIRED_MODES:
        fail("gate required_modes must match bd-b92jd.4.3")
    if gate.get("required_log_fields") != REQUIRED_LOG_FIELDS:
        fail("gate required_log_fields must match bd-b92jd.4.3")
    if gate.get("runtime_evidence_enabled") is not True:
        fail("gate runtime_evidence_enabled must be true")
    if not valid_source_commit(gate.get("source_commit")):
        fail("gate source_commit must be a 40-char lowercase hex commit")
    if not target_dir_is_safe(gate.get("target_dir")):
        fail("gate strict_hardened_e2e_missing_target_dir")
    try:
        datetime.fromisoformat(str(gate.get("generated_utc")).replace("Z", "+00:00"))
    except Exception:
        fail("gate generated_utc must be a valid ISO timestamp")
    if len(errors) == before:
        checks["top_level_shape"] = "pass"

    inputs = gate.get("inputs", {})
    missing_inputs = [key for key in INPUT_KEYS if not inputs.get(key)]
    missing_paths = []
    for key in INPUT_KEYS:
        ref = inputs.get(key)
        if not ref:
            continue
        try:
            if not safe_path(ref).exists():
                missing_paths.append(f"{key}:{ref}")
        except Exception as exc:
            missing_paths.append(f"{key}:{ref}:{exc}")
    if missing_inputs:
        fail("gate inputs missing keys: " + ", ".join(missing_inputs))
    if missing_paths:
        fail("gate input paths missing: " + ", ".join(missing_paths))
    if not missing_inputs and not missing_paths:
        checks["input_artifacts_exist"] = "pass"

    guards_before = len(errors)
    network = gate.get("network_policy", {})
    safety = gate.get("operation_safety", {})
    if not isinstance(network, dict) or network.get("real_network_required") is not False:
        fail("gate strict_hardened_e2e_real_network_required")
    if not isinstance(safety, dict) or safety.get("destructive_system_operation") is not False:
        fail("gate strict_hardened_e2e_destructive_operation")
    if len(errors) == guards_before:
        checks["network_and_destructive_guards"] = "pass"

    policy = gate.get("scenario_policy", {})
    scenario_errors_before = len(errors)
    scenarios = gate.get("scenarios", [])
    for scenario in scenarios if isinstance(scenarios, list) else []:
        if not isinstance(scenario, dict):
            fail("scenarios must contain only objects")
            continue
        validate_scenario(scenario, policy)
    if len(errors) == scenario_errors_before and isinstance(scenarios, list) and scenarios:
        checks["scenario_contract"] = "pass"

    family_modes = {
        (scenario.get("api_family"), scenario.get("runtime_mode"))
        for scenario in scenarios
        if isinstance(scenario, dict)
    }
    missing_family_modes = [
        f"{family}:{mode}"
        for family in REQUIRED_FAMILIES
        for mode in REQUIRED_MODES
        if (family, mode) not in family_modes
    ]
    if missing_family_modes:
        for item in missing_family_modes:
            if item.endswith(":strict") or item.endswith(":hardened"):
                fail(f"strict_hardened_e2e_missing_mode: {item}")
        missing_families = [
            family
            for family in REQUIRED_FAMILIES
            if not any(pair[0] == family for pair in family_modes)
        ]
        for family in missing_families:
            fail(f"strict_hardened_e2e_missing_family: {family}")
    else:
        checks["family_mode_coverage"] = "pass"

    negative_errors_before = len(errors)
    validate_negative_cases(gate, policy)
    if len(errors) == negative_errors_before:
        checks["negative_case_coverage"] = "pass"

    log_errors_before = len(errors)
    for row in logs:
        missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
        if missing:
            fail("structured log row missing fields: " + ", ".join(missing))
    if len(errors) == log_errors_before and logs:
        checks["structured_log"] = "pass"

status = "pass" if not errors and all(value == "pass" for value in checks.values()) else "fail"
report = {
    "schema_version": "v1",
    "trace_id": TRACE_ID,
    "bead_id": BEAD_ID,
    "status": status,
    "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "target_dir": gate.get("target_dir") if isinstance(gate, dict) else None,
    "source_commit": gate.get("source_commit") if isinstance(gate, dict) else None,
    "checks": checks,
    "summary": {
        "scenario_count": len(gate.get("scenarios", [])) if isinstance(gate, dict) else 0,
        "required_family_count": len(REQUIRED_FAMILIES),
        "required_mode_count": len(REQUIRED_MODES),
        "negative_case_count": len(gate.get("negative_scenario_cases", [])) if isinstance(gate, dict) else 0,
        "structured_log_rows": len(logs),
        "required_log_fields": len(REQUIRED_LOG_FIELDS),
    },
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as handle:
    for row in logs:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
if status != "pass":
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(1)
print(f"strict/hardened evidence e2e gate passed: {report_path}")
PY
