#!/usr/bin/env bash
# check_e2e_scenario_manifest_catalog_completion_contract.sh - bd-b5a.1.1 completion-debt gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_E2E_SCENARIO_CATALOG_CONTRACT:-${ROOT}/tests/conformance/e2e_scenario_manifest_catalog_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_E2E_SCENARIO_CATALOG_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_E2E_SCENARIO_CATALOG_REPORT:-${OUT_DIR}/e2e_scenario_manifest_catalog_completion_contract.report.json}"
LOG="${FRANKENLIBC_E2E_SCENARIO_CATALOG_LOG:-${OUT_DIR}/e2e_scenario_manifest_catalog_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

COMPLETION_DEBT_BEAD = "bd-b5a.1.1"
ORIGINAL_BEAD = "bd-b5a.1"
PASS_EVENT = "e2e_scenario_manifest_catalog_completion_contract_validated"
FAIL_EVENT = "e2e_scenario_manifest_catalog_completion_contract_failed"
CLASS_EVENT = "e2e_scenario_manifest_class_bound"
TRACE_ID = f"{COMPLETION_DEBT_BEAD}:e2e-scenario-manifest-catalog-completion"
REQUIRED_CLASSES = {
    "smoke": 13,
    "stress": 2,
    "fault": 3,
    "stability": 1,
}
REQUIRED_TOTAL_SCENARIOS = 19
EXPECTED_MANIFEST_ID = "bd-b5a.1-e2e-scenario-catalog"
REQUIRED_ARTIFACT_KEYS = {
    "scenario_manifest",
    "manifest_validator",
    "e2e_suite",
    "e2e_suite_checker",
}
REQUIRED_GATE_KEYS = {
    "manifest_validator",
    "e2e_suite",
    "completion_contract",
}
REQUIRED_ROOT_KEYS = {
    "schema_version",
    "manifest_id",
    "description",
    "replay_defaults",
    "scenarios",
}
REQUIRED_SCENARIO_KEYS = {
    "id",
    "class",
    "label",
    "priority",
    "description",
    "command",
    "mode_expectations",
    "artifact_policy",
    "replay",
}
REQUIRED_MODES = {"strict", "hardened"}
REQUIRED_EXPECTATION_KEYS = {
    "expected_outcome",
    "pass_condition",
    "allowed_exit_codes",
}
REQUIRED_ARTIFACT_POLICY_KEYS = {
    "capture_stdout",
    "capture_stderr",
    "capture_env_on_failure",
    "capture_bundle_on_failure",
    "required_artifacts",
}
REQUIRED_REPLAY_KEYS = {"seed_key", "env_keys", "deterministic_inputs"}
REQUIRED_REPLAY_DEFAULT_ENV_KEYS = {
    "FRANKENLIBC_E2E_SEED",
    "FRANKENLIBC_MODE",
    "TIMEOUT_SECONDS",
    "LD_PRELOAD",
}
REQUIRED_LOG_FIELDS = [
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "scenario_class",
    "scenario_count",
    "manifest_id",
    "artifact_refs",
    "test_refs",
    "failure_signature",
]
REQUIRED_VALIDATOR_TOKENS = [
    'ALLOWED_CLASSES = {"smoke", "stress", "fault", "stability"}',
    "REQUIRED_ROOT_KEYS",
    'REQUIRED_MODE_KEYS = {"strict", "hardened"}',
    "REQUIRED_ARTIFACT_POLICY_KEYS",
    "REQUIRED_REPLAY_KEYS",
    "def _cmd_validate",
    "def _cmd_list",
    "def _cmd_metadata",
    "ManifestValidationError",
]
REQUIRED_SUITE_TOKENS = [
    "MANIFEST_PATH",
    "--dry-run-manifest",
    "manifest_validate",
    "manifest_case_metadata",
    'emit_log "info" "manifest_case"',
    "scenario_pack_report.json",
]
REQUIRED_SUITE_CHECKER_TOKENS = [
    "validate_e2e_manifest.py",
    "Manifest dry-run",
    "manifest_case",
    "scenario_pack_report.json",
]

errors = []
logs = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "artifact_paths_exist": "fail",
    "manifest_catalog_shape": "fail",
    "manifest_class_coverage": "fail",
    "manifest_scenario_schema": "fail",
    "validator_source_bound": "fail",
    "suite_source_bound": "fail",
    "unit_primary_refs": "fail",
    "e2e_primary_refs": "fail",
    "structured_log": "fail",
}


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fail(message):
    errors.append(message)


def safe_path(rel):
    rel_text = str(rel).rstrip("/")
    rel_path = Path(rel_text)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise ValueError(f"unsafe workspace-relative path: {rel_text}")
    return root / rel_path


def load_json(path, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{label} unreadable: {path}: {exc}")
        return {}


def read_workspace_text(rel, label):
    try:
        return safe_path(rel).read_text(encoding="utf-8")
    except Exception as exc:
        fail(f"{label} unreadable: {rel}: {exc}")
        return ""


def file_exists(rel, label):
    try:
        path = safe_path(rel)
    except Exception as exc:
        fail(f"{label} unsafe path: {rel}: {exc}")
        return False
    if not path.is_file():
        fail(f"{label} missing file: {rel}")
        return False
    return True


def file_line_ref_exists(ref):
    if not isinstance(ref, str) or ":" not in ref:
        fail(f"invalid file-line ref: {ref!r}")
        return
    rel, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        fail(f"invalid file-line ref line: {ref}")
        return
    if line_no <= 0:
        fail(f"file-line ref must use a positive line: {ref}")
        return
    try:
        path = safe_path(rel)
    except Exception as exc:
        fail(f"file-line ref unsafe path: {ref}: {exc}")
        return
    if not path.is_file():
        fail(f"file-line ref missing path: {ref}")
        return
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if line_no > line_count:
        fail(f"file-line ref outside file: {ref}")


def string_set(values, label):
    if not isinstance(values, list):
        fail(f"{label} must be an array")
        return set()
    actual = set()
    for value in values:
        if isinstance(value, str):
            actual.add(value)
        else:
            fail(f"{label} must contain only strings")
    return actual


def function_exists(source_text, name):
    return f"fn {name}" in source_text


def append_log(
    event,
    status,
    scenario_class=None,
    scenario_count=0,
    manifest_id=None,
    artifact_refs=None,
    test_refs=None,
    failure_signature="none",
):
    logs.append(
        {
            "timestamp": now(),
            "trace_id": TRACE_ID,
            "event": event,
            "completion_debt_bead": COMPLETION_DEBT_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "source_commit": source_commit,
            "status": status,
            "scenario_class": scenario_class,
            "scenario_count": scenario_count,
            "manifest_id": manifest_id,
            "artifact_refs": artifact_refs or [],
            "test_refs": test_refs or [],
            "failure_signature": failure_signature,
        }
    )


def require_dict(value, label):
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
        return {}
    return value


def require_list(value, label):
    if not isinstance(value, list):
        fail(f"{label} must be an array")
        return []
    return value


def validate_test_refs(section_name, evidence, source_texts):
    section = require_dict(evidence.get(section_name), section_name)
    refs = require_list(section.get("required_test_refs"), f"{section_name}.required_test_refs")
    ok = True
    for ref in refs:
        if not isinstance(ref, dict):
            fail(f"{section_name}.required_test_refs entries must be objects")
            ok = False
            continue
        source = ref.get("source")
        name = ref.get("name")
        source_text = source_texts.get(source, "")
        if not isinstance(source, str) or not isinstance(name, str) or not source_text:
            fail(f"{section_name}: invalid test ref {source}.{name}")
            ok = False
            continue
        if not function_exists(source_text, name):
            fail(f"{section_name}: test ref missing {source}.{name}")
            ok = False
    return ok


contract = load_json(contract_path, "contract")
if isinstance(contract, dict) and contract:
    checks["json_parse"] = "pass"

evidence = {}
artifacts = {}
manifest_doc = {}
class_counts = {}
total_scenarios = 0

if isinstance(contract, dict):
    before = len(errors)
    if contract.get("schema_version") != "e2e_scenario_manifest_catalog_completion_contract.v1":
        fail("schema_version drifted")
    if contract.get("bead") != ORIGINAL_BEAD:
        fail(f"bead must be {ORIGINAL_BEAD}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
        fail(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")
    evidence = require_dict(contract.get("completion_debt_evidence"), "completion_debt_evidence")
    if evidence.get("bead") != COMPLETION_DEBT_BEAD:
        fail(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD}")
    if evidence.get("original_bead") != ORIGINAL_BEAD:
        fail(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
    if int(evidence.get("next_audit_score_threshold", 0)) < 800:
        fail("next_audit_score_threshold must be >= 800")
    for ref in evidence.get("implementation_refs", []):
        file_line_ref_exists(ref)
    if len(errors) == before:
        checks["top_level_shape"] = "pass"

    artifacts = require_dict(evidence.get("artifacts"), "artifacts")
    missing_artifact_keys = sorted(REQUIRED_ARTIFACT_KEYS - set(artifacts))
    if missing_artifact_keys:
        fail("artifacts missing keys: " + ", ".join(missing_artifact_keys))
    artifact_before = len(errors)
    for key in REQUIRED_ARTIFACT_KEYS:
        rel = artifacts.get(key)
        if isinstance(rel, str):
            file_exists(rel, f"artifacts.{key}")
        else:
            fail(f"artifacts.{key} must be a string")
    gates = require_dict(evidence.get("gates"), "gates")
    missing_gate_keys = sorted(REQUIRED_GATE_KEYS - set(gates))
    if missing_gate_keys:
        fail("gates missing keys: " + ", ".join(missing_gate_keys))
    for key in REQUIRED_GATE_KEYS:
        rel = gates.get(key)
        if isinstance(rel, str):
            file_exists(rel, f"gates.{key}")
        else:
            fail(f"gates.{key} must be a string")
    if len(errors) == artifact_before and not missing_artifact_keys and not missing_gate_keys:
        checks["artifact_paths_exist"] = "pass"

    contract_spec = require_dict(
        evidence.get("scenario_manifest_contract"),
        "scenario_manifest_contract",
    )
    manifest_rel = contract_spec.get("manifest_path", artifacts.get("scenario_manifest", ""))
    manifest_doc = load_json(safe_path(manifest_rel), "scenario_manifest") if isinstance(manifest_rel, str) else {}

    shape_before = len(errors)
    if manifest_doc.get("schema_version") != contract_spec.get("required_schema_version"):
        fail("manifest schema_version drifted")
    if manifest_doc.get("manifest_id") != EXPECTED_MANIFEST_ID:
        fail("manifest_id drifted")
    for key in REQUIRED_ROOT_KEYS:
        if key not in manifest_doc:
            fail(f"manifest missing root key {key}")
    replay_defaults = require_dict(manifest_doc.get("replay_defaults"), "manifest.replay_defaults")
    if replay_defaults.get("seed_key") != "FRANKENLIBC_E2E_SEED":
        fail("manifest replay_defaults seed_key drifted")
    replay_default_env = string_set(
        replay_defaults.get("env_keys", []),
        "manifest.replay_defaults.env_keys",
    )
    if not REQUIRED_REPLAY_DEFAULT_ENV_KEYS <= replay_default_env:
        fail("manifest replay_defaults missing required env keys")
    if replay_defaults.get("deterministic_inputs") != contract_spec.get("replay_defaults", {}).get("deterministic_inputs_token"):
        fail("manifest replay_defaults deterministic_inputs drifted")
    scenarios = manifest_doc.get("scenarios")
    if not isinstance(scenarios, list):
        fail("manifest scenarios must be an array")
        scenarios = []
    total_scenarios = len(scenarios)
    if total_scenarios < max(REQUIRED_TOTAL_SCENARIOS, int(contract_spec.get("total_scenario_min", 0))):
        fail(f"manifest scenario count below contract minimum: {total_scenarios}")
    if len(errors) == shape_before:
        checks["manifest_catalog_shape"] = "pass"

    class_before = len(errors)
    class_counts = {klass: 0 for klass in REQUIRED_CLASSES}
    ids = set()
    for scenario in scenarios:
        if isinstance(scenario, dict):
            ids.add(scenario.get("id"))
            scenario_class = scenario.get("class")
            if scenario_class in class_counts:
                class_counts[scenario_class] += 1
    required_classes = string_set(contract_spec.get("required_classes"), "scenario_manifest_contract.required_classes")
    if set(REQUIRED_CLASSES) - required_classes:
        fail("scenario contract missing required classes: " + ", ".join(sorted(set(REQUIRED_CLASSES) - required_classes)))
    contract_mins = require_dict(contract_spec.get("class_minimums"), "scenario_manifest_contract.class_minimums")
    for scenario_class, required_count in REQUIRED_CLASSES.items():
        contract_min = int(contract_mins.get(scenario_class, 0))
        if contract_min < required_count:
            fail(f"class minimum for {scenario_class} below required {required_count}")
        actual = class_counts.get(scenario_class, 0)
        if actual < max(required_count, contract_min):
            fail(
                f"{scenario_class}: scenario class count below minimum "
                f"{actual} < {max(required_count, contract_min)}: e2e_scenario_manifest_class_count_drift"
            )
            append_log(
                CLASS_EVENT,
                "fail",
                scenario_class=scenario_class,
                scenario_count=actual,
                manifest_id=manifest_doc.get("manifest_id"),
                artifact_refs=[str(manifest_rel)],
                failure_signature="e2e_scenario_manifest_class_count_drift",
            )
        else:
            append_log(
                CLASS_EVENT,
                "pass",
                scenario_class=scenario_class,
                scenario_count=actual,
                manifest_id=manifest_doc.get("manifest_id"),
                artifact_refs=[str(manifest_rel)],
            )
    representative_ids = string_set(
        contract_spec.get("representative_scenario_ids"),
        "scenario_manifest_contract.representative_scenario_ids",
    )
    if not representative_ids <= ids:
        fail("manifest missing representative scenario ids: " + ", ".join(sorted(representative_ids - ids)))
    if len(errors) == class_before:
        checks["manifest_class_coverage"] = "pass"

    scenario_before = len(errors)
    seen_ids = set()
    for idx, scenario in enumerate(scenarios):
        ctx = f"scenario[{idx}]"
        if not isinstance(scenario, dict):
            fail(f"{ctx} must be an object")
            continue
        missing = REQUIRED_SCENARIO_KEYS - set(scenario)
        if missing:
            fail(f"{ctx} missing keys: " + ", ".join(sorted(missing)))
            continue
        scenario_id = scenario.get("id")
        scenario_class = scenario.get("class")
        label = scenario.get("label")
        if not isinstance(scenario_id, str) or not scenario_id:
            fail(f"{ctx}.id must be a non-empty string")
        elif scenario_id in seen_ids:
            fail(f"{ctx}.id duplicate {scenario_id}")
        else:
            seen_ids.add(scenario_id)
        if scenario_class not in REQUIRED_CLASSES:
            fail(f"{ctx}.class unsupported {scenario_class}")
        if isinstance(scenario_id, str) and isinstance(scenario_class, str) and isinstance(label, str):
            expected_id = f"{scenario_class}.{label}"
            if scenario_id != expected_id:
                fail(f"{ctx}.id must equal {expected_id}")
        if not isinstance(scenario.get("priority"), int) or scenario.get("priority") < 0:
            fail(f"{ctx}.priority must be a non-negative integer")
        if not isinstance(scenario.get("description"), str) or not scenario.get("description"):
            fail(f"{ctx}.description must be a non-empty string")
        command = scenario.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command):
            fail(f"{ctx}.command must be a non-empty string array")
        mode_expectations = require_dict(scenario.get("mode_expectations"), f"{ctx}.mode_expectations")
        if REQUIRED_MODES - set(mode_expectations):
            fail(f"{ctx}.mode_expectations missing modes")
        for mode in REQUIRED_MODES:
            expectation = require_dict(mode_expectations.get(mode), f"{ctx}.mode_expectations.{mode}")
            missing_expectation = REQUIRED_EXPECTATION_KEYS - set(expectation)
            if missing_expectation:
                fail(f"{ctx}.mode_expectations.{mode} missing keys: " + ", ".join(sorted(missing_expectation)))
            if not isinstance(expectation.get("allowed_exit_codes"), list) or not expectation.get("allowed_exit_codes"):
                fail(f"{ctx}.mode_expectations.{mode}.allowed_exit_codes must be non-empty")
        artifact_policy = require_dict(scenario.get("artifact_policy"), f"{ctx}.artifact_policy")
        missing_policy = REQUIRED_ARTIFACT_POLICY_KEYS - set(artifact_policy)
        if missing_policy:
            fail(f"{ctx}.artifact_policy missing keys: " + ", ".join(sorted(missing_policy)))
        if not isinstance(artifact_policy.get("required_artifacts"), list) or not artifact_policy.get("required_artifacts"):
            fail(f"{ctx}.artifact_policy.required_artifacts must be non-empty")
        replay = require_dict(scenario.get("replay"), f"{ctx}.replay")
        missing_replay = REQUIRED_REPLAY_KEYS - set(replay)
        if missing_replay:
            fail(f"{ctx}.replay missing keys: " + ", ".join(sorted(missing_replay)))
        if replay.get("seed_key") != "FRANKENLIBC_E2E_SEED":
            fail(f"{ctx}.replay.seed_key drifted")
        replay_env = string_set(replay.get("env_keys", []), f"{ctx}.replay.env_keys")
        if "FRANKENLIBC_E2E_SEED" not in replay_env:
            fail(f"{ctx}.replay.env_keys missing FRANKENLIBC_E2E_SEED")
    if len(errors) == scenario_before:
        checks["manifest_scenario_schema"] = "pass"

    validator_before = len(errors)
    validator_text = read_workspace_text(artifacts.get("manifest_validator", ""), "manifest_validator")
    validator_contract = require_dict(evidence.get("validator_contract"), "validator_contract")
    for token in validator_contract.get("required_tokens", REQUIRED_VALIDATOR_TOKENS):
        if not isinstance(token, str) or token not in validator_text:
            fail(f"validator missing token {token!r}")
    for command in validator_contract.get("required_commands", []):
        if not isinstance(command, str) or f'add_parser("{command}"' not in validator_text and f"add_parser('{command}'" not in validator_text:
            fail(f"validator missing command {command!r}")
    if len(errors) == validator_before:
        checks["validator_source_bound"] = "pass"

    suite_before = len(errors)
    suite_contract = require_dict(evidence.get("suite_contract"), "suite_contract")
    suite_text = read_workspace_text(artifacts.get("e2e_suite", ""), "e2e_suite")
    checker_text = read_workspace_text(artifacts.get("e2e_suite_checker", ""), "e2e_suite_checker")
    for token in suite_contract.get("required_tokens", REQUIRED_SUITE_TOKENS):
        if not isinstance(token, str) or token not in suite_text:
            fail(f"e2e_suite missing token {token!r}")
    for token in suite_contract.get("checker_required_tokens", REQUIRED_SUITE_CHECKER_TOKENS):
        if not isinstance(token, str) or token not in checker_text:
            fail(f"e2e suite checker missing token {token!r}")
    if len(errors) == suite_before:
        checks["suite_source_bound"] = "pass"

    test_sources = require_dict(evidence.get("test_sources"), "test_sources")
    source_texts = {}
    for source_name, rel in test_sources.items():
        if isinstance(rel, str):
            source_texts[source_name] = read_workspace_text(rel, f"test_sources.{source_name}")
        else:
            fail(f"test_sources.{source_name} must be a string")

    unit_before = len(errors)
    unit = require_dict(evidence.get("unit_primary"), "unit_primary")
    if unit.get("missing_item_id") != "tests.unit.primary":
        fail("unit_primary missing_item_id must be tests.unit.primary")
    unit_refs_ok = validate_test_refs("unit_primary", evidence, source_texts)
    if len(errors) == unit_before and unit_refs_ok:
        checks["unit_primary_refs"] = "pass"

    e2e_before = len(errors)
    e2e = require_dict(evidence.get("e2e_primary"), "e2e_primary")
    if e2e.get("missing_item_id") != "tests.e2e.primary":
        fail("e2e_primary missing_item_id must be tests.e2e.primary")
    for rel in e2e.get("required_gates", []):
        if isinstance(rel, str):
            file_exists(rel, "e2e_primary.required_gates")
        else:
            fail("e2e_primary.required_gates must contain strings")
    e2e_refs_ok = validate_test_refs("e2e_primary", evidence, source_texts)
    if len(errors) == e2e_before and e2e_refs_ok:
        checks["e2e_primary_refs"] = "pass"

    log_before = len(errors)
    for row in logs:
        missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
        if missing:
            fail("structured log row missing fields: " + ", ".join(missing))
    if len(errors) == log_before and logs:
        checks["structured_log"] = "pass"

status = "pass" if not errors and all(value == "pass" for value in checks.values()) else "fail"
if status == "pass":
    append_log(
        PASS_EVENT,
        "pass",
        scenario_count=total_scenarios,
        manifest_id=manifest_doc.get("manifest_id") if isinstance(manifest_doc, dict) else None,
        artifact_refs=list(artifacts.values()) if isinstance(artifacts, dict) else [],
        test_refs=[
            "e2e_manifest_validation_test",
            "e2e_suite_test",
            "e2e_scenario_manifest_catalog_completion_contract_test",
        ],
    )
else:
    append_log(
        FAIL_EVENT,
        "fail",
        scenario_count=total_scenarios,
        manifest_id=manifest_doc.get("manifest_id") if isinstance(manifest_doc, dict) else None,
        failure_signature="e2e_scenario_manifest_catalog_completion_contract_failed",
    )

report = {
    "schema_version": "v1",
    "trace_id": TRACE_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "generated_utc": now(),
    "source_commit": source_commit,
    "checks": checks,
    "summary": {
        "manifest_id": manifest_doc.get("manifest_id") if isinstance(manifest_doc, dict) else None,
        "scenario_count": total_scenarios,
        "class_counts": class_counts,
        "required_class_count": len(REQUIRED_CLASSES),
        "bound_class_count": len([row for row in logs if row.get("event") == CLASS_EVENT and row.get("status") == "pass"]),
        "artifact_count": len(artifacts) if isinstance(artifacts, dict) else 0,
        "log_rows": len(logs),
    },
    "required_classes": sorted(REQUIRED_CLASSES),
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in logs),
    encoding="utf-8",
)

if status == "pass":
    print(
        "PASS: E2E scenario manifest catalog completion contract validated "
        f"classes={report['summary']['bound_class_count']} "
        f"scenarios={report['summary']['scenario_count']}"
    )
    sys.exit(0)

for error in errors:
    print(f"FAIL: {error}", file=sys.stderr)
print("check_e2e_scenario_manifest_catalog_completion_contract: FAILED", file=sys.stderr)
sys.exit(1)
PY
