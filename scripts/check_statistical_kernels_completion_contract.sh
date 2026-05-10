#!/usr/bin/env bash
# check_statistical_kernels_completion_contract.sh - bd-5vr.3.1 completion-debt gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_STATISTICAL_KERNELS_CONTRACT:-${ROOT}/tests/conformance/statistical_kernels_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STATISTICAL_KERNELS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_STATISTICAL_KERNELS_REPORT:-${OUT_DIR}/statistical_kernels_completion_contract.report.json}"
LOG="${FRANKENLIBC_STATISTICAL_KERNELS_LOG:-${OUT_DIR}/statistical_kernels_completion_contract.log.jsonl}"
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

COMPLETION_DEBT_BEAD = "bd-5vr.3.1"
ORIGINAL_BEAD = "bd-5vr.3"
PASS_EVENT = "statistical_kernels_completion_contract_validated"
FAIL_EVENT = "statistical_kernels_completion_contract_failed"
MODULE_EVENT = "statistical_kernel_module_bound"
TRACE_ID = f"{COMPLETION_DEBT_BEAD}:statistical-kernels-completion"
REQUIRED_MODULES = {
    "risk": "crates/frankenlibc-membrane/src/runtime_math/risk.rs",
    "conformal": "crates/frankenlibc-membrane/src/runtime_math/conformal.rs",
    "eprocess": "crates/frankenlibc-membrane/src/runtime_math/eprocess.rs",
    "cvar": "crates/frankenlibc-membrane/src/runtime_math/cvar.rs",
    "changepoint": "crates/frankenlibc-membrane/src/runtime_math/changepoint.rs",
    "alpha_investing": "crates/frankenlibc-membrane/src/runtime_math/alpha_investing.rs",
}
REQUIRED_INLINE_TEST_MIN = {
    "risk": 11,
    "conformal": 11,
    "eprocess": 8,
    "cvar": 5,
    "changepoint": 10,
    "alpha_investing": 21,
}
REQUIRED_ARTIFACT_KEYS = {
    "runtime_risk_monitor_calibration",
    "anytime_valid_monitor_spec",
    "changepoint_drift_policy",
    "controller_manifest",
    "production_kernel_manifest",
    "runtime_math_linkage",
    "math_value_proof",
    "kernel_snapshot_smoke",
}
REQUIRED_GATE_KEYS = {
    "runtime_risk_monitor_calibration",
    "anytime_valid_monitor",
    "changepoint_drift",
    "completion_contract",
}
REQUIRED_LOG_FIELDS = [
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "module",
    "module_path",
    "inline_unit_tests",
    "artifact_refs",
    "test_refs",
    "failure_signature",
]

errors = []
logs = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "artifact_paths_exist": "fail",
    "gate_paths_exist": "fail",
    "module_sources_bound": "fail",
    "inline_unit_tests_bound": "fail",
    "existing_artifact_semantics": "fail",
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


def load_workspace_json(rel, label):
    try:
        return load_json(safe_path(rel), label)
    except Exception as exc:
        fail(f"{label} unsafe path: {rel}: {exc}")
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


def append_log(event, status, module=None, module_path=None, inline_unit_tests=0, artifact_refs=None, test_refs=None, failure_signature="none"):
    logs.append(
        {
            "timestamp": now(),
            "trace_id": TRACE_ID,
            "event": event,
            "completion_debt_bead": COMPLETION_DEBT_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "source_commit": source_commit,
            "status": status,
            "module": module,
            "module_path": module_path,
            "inline_unit_tests": inline_unit_tests,
            "artifact_refs": artifact_refs or [],
            "test_refs": test_refs or [],
            "failure_signature": failure_signature,
        }
    )


contract = load_json(contract_path, "contract")
if isinstance(contract, dict) and contract:
    checks["json_parse"] = "pass"

if isinstance(contract, dict):
    before = len(errors)
    if contract.get("schema_version") != "statistical_kernels_completion_contract.v1":
        fail("schema_version drifted")
    if contract.get("bead") != ORIGINAL_BEAD:
        fail(f"bead must be {ORIGINAL_BEAD}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
        fail(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        fail("completion_debt_evidence must be an object")
        evidence = {}
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

    artifacts = evidence.get("artifacts", {})
    if not isinstance(artifacts, dict):
        fail("artifacts must be an object")
        artifacts = {}
    missing_artifact_keys = sorted(REQUIRED_ARTIFACT_KEYS - set(artifacts))
    if missing_artifact_keys:
        fail("artifacts missing keys: " + ", ".join(missing_artifact_keys))
    artifact_path_errors_before = len(errors)
    loaded_artifacts = {}
    for key in REQUIRED_ARTIFACT_KEYS:
        rel = artifacts.get(key)
        if isinstance(rel, str) and file_exists(rel, f"artifacts.{key}"):
            loaded_artifacts[key] = load_workspace_json(rel, f"artifacts.{key}")
    if len(errors) == artifact_path_errors_before and not missing_artifact_keys:
        checks["artifact_paths_exist"] = "pass"

    gates = evidence.get("gates", {})
    if not isinstance(gates, dict):
        fail("gates must be an object")
        gates = {}
    missing_gate_keys = sorted(REQUIRED_GATE_KEYS - set(gates))
    if missing_gate_keys:
        fail("gates missing keys: " + ", ".join(missing_gate_keys))
    gate_path_errors_before = len(errors)
    for key in REQUIRED_GATE_KEYS:
        rel = gates.get(key)
        if isinstance(rel, str):
            file_exists(rel, f"gates.{key}")
    if len(errors) == gate_path_errors_before and not missing_gate_keys:
        checks["gate_paths_exist"] = "pass"

    kernel_contract = evidence.get("statistical_kernel_contract", {})
    if not isinstance(kernel_contract, dict):
        fail("statistical_kernel_contract must be an object")
        kernel_contract = {}
    required_modules = string_set(
        kernel_contract.get("required_modules"),
        "statistical_kernel_contract.required_modules",
    )
    if set(REQUIRED_MODULES) - required_modules:
        fail(
            "required_modules missing: "
            + ", ".join(sorted(set(REQUIRED_MODULES) - required_modules))
        )
    modules = kernel_contract.get("modules", {})
    if not isinstance(modules, dict):
        fail("statistical_kernel_contract.modules must be an object")
        modules = {}

    module_errors_before = len(errors)
    inline_test_counts = {}
    for module, expected_path in REQUIRED_MODULES.items():
        spec = modules.get(module)
        if not isinstance(spec, dict):
            fail(f"missing module {module}: statistical_kernel_missing_module")
            append_log(
                MODULE_EVENT,
                "fail",
                module=module,
                module_path=expected_path,
                failure_signature="statistical_kernel_missing_module",
            )
            continue
        module_path = spec.get("module_path")
        if module_path != expected_path:
            fail(f"{module}: module_path must be {expected_path}")
        source_text = read_workspace_text(expected_path, f"module.{module}")
        if source_text:
            for token in spec.get("entrypoint_tokens", []):
                if not isinstance(token, str) or token not in source_text:
                    fail(f"{module}: missing entrypoint token {token!r}")
            actual_tests = source_text.count("#[test]")
            inline_test_counts[module] = actual_tests
            expected_min = int(spec.get("unit_test_min", 0))
            if expected_min < REQUIRED_INLINE_TEST_MIN[module]:
                fail(f"{module}: unit_test_min below required {REQUIRED_INLINE_TEST_MIN[module]}")
            if actual_tests < expected_min:
                fail(
                    f"{module}: inline unit tests below contract minimum "
                    f"{actual_tests} < {expected_min}: statistical_kernel_unit_test_threshold_drift"
                )
            append_log(
                MODULE_EVENT,
                "pass" if actual_tests >= expected_min else "fail",
                module=module,
                module_path=expected_path,
                inline_unit_tests=actual_tests,
                artifact_refs=[expected_path],
                failure_signature="none"
                if actual_tests >= expected_min
                else "statistical_kernel_unit_test_threshold_drift",
            )
    if len(errors) == module_errors_before:
        checks["module_sources_bound"] = "pass"
        checks["inline_unit_tests_bound"] = "pass"

    artifact_semantics_before = len(errors)
    runtime_risk = loaded_artifacts.get("runtime_risk_monitor_calibration", {})
    policy = runtime_risk.get("claim_policy", {}) if isinstance(runtime_risk, dict) else {}
    required_calibration_monitors = {"eprocess", "changepoint", "cvar", "conformal", "risk"}
    calibration_monitors = string_set(
        policy.get("required_monitors", []),
        "runtime_risk_monitor_calibration.claim_policy.required_monitors",
    )
    if not required_calibration_monitors <= calibration_monitors:
        fail("runtime risk calibration missing monitor coverage")
    records = runtime_risk.get("calibration_records", []) if isinstance(runtime_risk, dict) else []
    record_monitors = {
        record.get("monitor_id")
        for record in records
        if isinstance(record, dict) and record.get("monitor_id")
    }
    if not required_calibration_monitors <= record_monitors:
        fail("runtime risk calibration records missing required monitors")

    anytime = loaded_artifacts.get("anytime_valid_monitor_spec", {})
    if anytime.get("eprocess_policy", {}).get("implementation") != REQUIRED_MODULES["eprocess"]:
        fail("anytime_valid_monitor_spec eprocess implementation drifted")
    if anytime.get("alpha_investing_policy", {}).get("implementation") != REQUIRED_MODULES["alpha_investing"]:
        fail("anytime_valid_monitor_spec alpha_investing implementation drifted")
    anytime_summary = anytime.get("summary", {})
    if int(anytime_summary.get("eprocess_parameters", 0)) <= 0:
        fail("anytime_valid_monitor_spec missing eprocess parameter coverage")
    if int(anytime_summary.get("alpha_investing_parameters", 0)) <= 0:
        fail("anytime_valid_monitor_spec missing alpha_investing parameter coverage")

    changepoint = loaded_artifacts.get("changepoint_drift_policy", {})
    if changepoint.get("bocpd_parameters", {}).get("implementation") != REQUIRED_MODULES["changepoint"]:
        fail("changepoint_drift_policy implementation drifted")
    if int(changepoint.get("summary", {}).get("bocpd_parameters", 0)) <= 0:
        fail("changepoint_drift_policy missing BOCPD parameter coverage")

    controller_manifest = loaded_artifacts.get("controller_manifest", {})
    controller_modules = {
        row.get("module")
        for row in controller_manifest.get("controllers", [])
        if isinstance(row, dict)
    }
    if not set(REQUIRED_MODULES) <= controller_modules:
        fail("controller_manifest missing statistical kernel modules")
    production = loaded_artifacts.get("production_kernel_manifest", {})
    production_modules = string_set(
        production.get("production_modules", []),
        "production_kernel_manifest.production_modules",
    )
    if not set(REQUIRED_MODULES) <= production_modules:
        fail("production manifest missing statistical kernel modules")
    linkage = loaded_artifacts.get("runtime_math_linkage", {})
    linkage_modules = set(linkage.get("modules", {}).keys()) if isinstance(linkage.get("modules"), dict) else set()
    if not set(REQUIRED_MODULES) <= linkage_modules:
        fail("runtime_math_linkage missing statistical kernel modules")

    snapshot_text = read_workspace_text(
        artifacts.get("kernel_snapshot_smoke", ""),
        "kernel_snapshot_smoke",
    )
    for token in [
        "cvar_max_robust_ns",
        "changepoint_count",
        "conformal_empirical_coverage",
        "alpha_investing_wealth_milli",
    ]:
        if token not in snapshot_text:
            fail(f"kernel snapshot missing telemetry token {token}")
    if len(errors) == artifact_semantics_before:
        checks["existing_artifact_semantics"] = "pass"

    test_sources = evidence.get("test_sources", {})
    if not isinstance(test_sources, dict):
        fail("test_sources must be an object")
        test_sources = {}
    source_texts = {}
    for source_name, rel in test_sources.items():
        if isinstance(rel, str):
            source_texts[source_name] = read_workspace_text(rel, f"test_sources.{source_name}")

    def validate_test_refs(section_name):
        section = evidence.get(section_name, {})
        if not isinstance(section, dict):
            fail(f"{section_name} must be an object")
            return False
        refs = section.get("required_test_refs", [])
        if not isinstance(refs, list):
            fail(f"{section_name}.required_test_refs must be an array")
            return False
        ok = True
        for ref in refs:
            if not isinstance(ref, dict):
                fail(f"{section_name}.required_test_refs entries must be objects")
                ok = False
                continue
            source = ref.get("source")
            name = ref.get("name")
            source_text = source_texts.get(source, "")
            if not isinstance(name, str) or not source_text or not function_exists(source_text, name):
                fail(f"{section_name}: test ref missing {source}.{name}")
                ok = False
        return ok

    unit_before = len(errors)
    unit = evidence.get("unit_primary", {})
    if unit.get("missing_item_id") != "tests.unit.primary":
        fail("unit_primary missing_item_id must be tests.unit.primary")
    unit_modules = string_set(unit.get("required_modules", []), "unit_primary.required_modules")
    if not set(REQUIRED_MODULES) <= unit_modules:
        fail("unit_primary.required_modules missing statistical kernels")
    unit_mins = unit.get("required_inline_unit_test_min", {})
    if not isinstance(unit_mins, dict):
        fail("unit_primary.required_inline_unit_test_min must be an object")
        unit_mins = {}
    for module, required_min in REQUIRED_INLINE_TEST_MIN.items():
        if int(unit_mins.get(module, 0)) < required_min:
            fail(f"unit_primary inline test minimum missing for {module}")
        if inline_test_counts.get(module, 0) < required_min:
            fail(f"unit_primary inline source count below minimum for {module}")
    unit_refs_ok = validate_test_refs("unit_primary")
    if len(errors) == unit_before and unit_refs_ok:
        checks["unit_primary_refs"] = "pass"

    e2e_before = len(errors)
    e2e = evidence.get("e2e_primary", {})
    if e2e.get("missing_item_id") != "tests.e2e.primary":
        fail("e2e_primary missing_item_id must be tests.e2e.primary")
    for rel in e2e.get("required_gates", []):
        if isinstance(rel, str):
            file_exists(rel, "e2e_primary.required_gates")
        else:
            fail("e2e_primary.required_gates must contain strings")
    for rel in e2e.get("required_artifacts", []):
        if isinstance(rel, str):
            file_exists(rel, "e2e_primary.required_artifacts")
        else:
            fail("e2e_primary.required_artifacts must contain strings")
    e2e_refs_ok = validate_test_refs("e2e_primary")
    if len(errors) == e2e_before and e2e_refs_ok:
        checks["e2e_primary_refs"] = "pass"

    log_before = len(errors)
    for row in logs:
        missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
        if missing:
            fail("structured log row missing fields: " + ", ".join(missing))
    if len(errors) == log_before and logs:
        checks["structured_log"] = "pass"
else:
    evidence = {}
    inline_test_counts = {}

status = "pass" if not errors and all(value == "pass" for value in checks.values()) else "fail"
if status == "pass":
    append_log(
        PASS_EVENT,
        "pass",
        artifact_refs=list(evidence.get("artifacts", {}).values()) if isinstance(evidence, dict) else [],
        test_refs=[
            "runtime_risk_monitor_calibration_test",
            "anytime_valid_monitor_test",
            "changepoint_drift_test",
            "statistical_kernels_completion_contract_test",
        ],
    )
else:
    append_log(
        FAIL_EVENT,
        "fail",
        failure_signature="statistical_kernels_completion_contract_failed",
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
        "required_module_count": len(REQUIRED_MODULES),
        "bound_module_count": len([row for row in logs if row.get("event") == MODULE_EVENT and row.get("status") == "pass"]),
        "inline_unit_test_total": sum(inline_test_counts.values()) if isinstance(inline_test_counts, dict) else 0,
        "artifact_count": len(evidence.get("artifacts", {})) if isinstance(evidence, dict) else 0,
        "gate_count": len(evidence.get("gates", {})) if isinstance(evidence, dict) else 0,
        "log_rows": len(logs),
    },
    "required_modules": sorted(REQUIRED_MODULES),
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in logs),
    encoding="utf-8",
)

if status == "pass":
    print(
        "PASS: statistical kernels completion contract validated "
        f"modules={report['summary']['bound_module_count']} "
        f"inline_unit_tests={report['summary']['inline_unit_test_total']}"
    )
    sys.exit(0)

for error in errors:
    print(f"FAIL: {error}", file=sys.stderr)
print("check_statistical_kernels_completion_contract: FAILED", file=sys.stderr)
sys.exit(1)
PY
