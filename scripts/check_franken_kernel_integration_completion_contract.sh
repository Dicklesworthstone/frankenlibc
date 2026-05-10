#!/usr/bin/env bash
# franken_kernel_integration_completion_contract - bd-epeg.1 static completion gate.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_PATH="${FRANKEN_KERNEL_INTEGRATION_COMPLETION_CONTRACT:-${ROOT_DIR}/tests/conformance/franken_kernel_integration_completion_contract.v1.json}"
REPORT_PATH="${FRANKEN_KERNEL_INTEGRATION_COMPLETION_REPORT:-${ROOT_DIR}/target/conformance/franken_kernel_integration_completion_contract.report.json}"
LOG_PATH="${FRANKEN_KERNEL_INTEGRATION_COMPLETION_LOG:-${ROOT_DIR}/target/conformance/franken_kernel_integration_completion_contract.log.jsonl}"

mkdir -p "$(dirname -- "${REPORT_PATH}")" "$(dirname -- "${LOG_PATH}")"

python3 - "${ROOT_DIR}" "${CONTRACT_PATH}" "${REPORT_PATH}" "${LOG_PATH}" <<'PY'
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(sys.argv[1])
CONTRACT = Path(sys.argv[2])
REPORT = Path(sys.argv[3])
LOG = Path(sys.argv[4])
START_NS = time.monotonic_ns()

EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_ID_TYPES = {"TraceId", "DecisionId", "PolicyId", "SchemaVersion"}
EXPECTED_UNIT_TESTS = {
    "scoped_trace_ids_use_canonical_separator_and_hex_width",
    "zero_decision_id_does_not_emit_trace_id",
    "policy_id_wrapper_preserves_assignment_status",
    "membrane_schema_version_is_stable",
    "validation_log_export_includes_trace_and_decision_ids",
    "security_context_default_deny_is_fail_closed",
    "correlation_index_groups_by_trace_id",
    "jsonl_includes_all_required_schema_fields",
    "decision_card_export_is_valid_json",
    "runtime_evidence_jsonl_export_covers_required_schema_fields",
    "proof_healing_evidence_monotone_decision_ids",
    "snapshot_export_jsonl_includes_required_fields",
    "metric_ring_export_jsonl_contains_required_fields",
}
EXPECTED_E2E_TESTS = {
    "runtime_kernel_framework_exports_structured_decision_card_json",
    "runtime_kernel_framework_exports_runtime_math_jsonl_logs",
    "runtime_math_log_jsonl_export_contains_required_runtime_decision_fields",
    "runtime_evidence_jsonl_export_covers_required_schema_fields",
    "validation_log_export_includes_trace_and_decision_ids",
    "jsonl_includes_all_required_schema_fields",
    "snapshot_export_jsonl_contains_aggregate_diagnostics",
    "checker_emits_structured_report_and_jsonl",
    "checker_rejects_missing_canonical_id_source_anchor",
}
EXPECTED_TRACE_SCOPES = {
    "tsm::pointer_validation::",
    "runtime_math::decision_card::",
    "runtime_math::runtime_evidence::",
    "runtime_math::decision::",
    "membrane::heal::",
    "membrane::metrics::",
    "alien_cs::metric::",
    "alien_cs::snapshot::",
}
EXPECTED_EVIDENCE_FIELDS = {
    "trace_id",
    "decision_id",
    "policy_id",
    "schema_version",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
}
EXPECTED_REPORT_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "completion_debt_bead",
    "mode",
    "runtime_mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "decision_id",
    "policy_id",
    "schema_version",
    "artifact_refs",
    "source_commit",
    "failure_signature",
}


def source_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "--short=12", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def read_text(rel: str, errors: list[str]) -> str:
    path = ROOT / rel
    if not path.exists():
        errors.append(f"missing path: {rel}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        errors.append(f"{rel} is not UTF-8: {exc}")
        return ""


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def list_values(value) -> list:
    return value if isinstance(value, list) else []


def string_set(value) -> set[str]:
    return {item for item in list_values(value) if isinstance(item, str)}


def test_name_exists(source_text: str, name: str) -> bool:
    return f"fn {name}(" in source_text or f"def {name}(" in source_text


def validate_file_ref(ref, errors: list[str]) -> None:
    if not isinstance(ref, dict):
        errors.append(f"implementation ref is not an object: {ref!r}")
        return
    path = ref.get("path")
    line = ref.get("line")
    anchor = ref.get("anchor")
    if not isinstance(path, str):
        errors.append(f"implementation ref missing path: {ref!r}")
        return
    text = read_text(path, errors)
    if not text:
        return
    lines = text.splitlines()
    require(isinstance(line, int), f"{path} ref line is not an integer", errors)
    if isinstance(line, int):
        require(1 <= line <= len(lines), f"{path}:{line} outside 1..{len(lines)}", errors)
    require(isinstance(anchor, str) and bool(anchor), f"{path} ref missing anchor", errors)
    if isinstance(anchor, str) and anchor:
        require(anchor in text, f"{path} missing anchor {anchor!r}", errors)


def validate_file_line_strings(refs, errors: list[str], label: str) -> int:
    count = 0
    for ref in list_values(refs):
        if not isinstance(ref, str) or ":" not in ref:
            errors.append(f"{label} ref is not file:line: {ref!r}")
            continue
        rel, line_text = ref.rsplit(":", 1)
        text = read_text(rel, errors)
        if not text:
            continue
        try:
            line_no = int(line_text)
        except ValueError:
            errors.append(f"{label} ref line is not numeric: {ref}")
            continue
        require(1 <= line_no <= len(text.splitlines()), f"{label} ref outside file: {ref}", errors)
        count += 1
    return count


def validate_source_anchors(manifest: dict, errors: list[str]) -> dict[str, str]:
    source_paths = manifest.get("source_paths", {})
    anchors_by_source = manifest.get("source_anchors", {})
    require(isinstance(source_paths, dict), "source_paths must be an object", errors)
    require(isinstance(anchors_by_source, dict), "source_anchors must be an object", errors)
    texts: dict[str, str] = {}
    if not isinstance(source_paths, dict) or not isinstance(anchors_by_source, dict):
        return texts
    for source, anchors in anchors_by_source.items():
        rel = source_paths.get(source)
        require(isinstance(rel, str), f"source path missing for {source}", errors)
        if not isinstance(rel, str):
            continue
        text = texts.setdefault(rel, read_text(rel, errors))
        for anchor in list_values(anchors):
            require(isinstance(anchor, str), f"non-string anchor in {source}", errors)
            if isinstance(anchor, str):
                require(anchor in text, f"{rel} missing source anchor {anchor!r}", errors)
    return texts


def validate_test_refs(manifest: dict, coverage: list[dict], errors: list[str]) -> tuple[int, set[str], set[str]]:
    source_paths = manifest.get("source_paths", {})
    texts: dict[str, str] = {}
    count = 0
    unit_tests: set[str] = set()
    e2e_tests: set[str] = set()
    for section in coverage:
        item_id = section.get("missing_item_id")
        for ref in list_values(section.get("test_refs")):
            name = ref.get("name") if isinstance(ref, dict) else None
            source = ref.get("source") if isinstance(ref, dict) else None
            require(isinstance(name, str), f"test ref missing name: {ref!r}", errors)
            require(isinstance(source, str), f"test ref missing source: {ref!r}", errors)
            if not isinstance(name, str) or not isinstance(source, str):
                continue
            rel = source_paths.get(source) if isinstance(source_paths, dict) else None
            require(isinstance(rel, str), f"test ref {name} has unknown source {source}", errors)
            if not isinstance(rel, str):
                continue
            text = texts.setdefault(rel, read_text(rel, errors))
            require(test_name_exists(text, name), f"{rel} missing test function {name}", errors)
            if item_id == "tests.unit.primary":
                unit_tests.add(name)
            if item_id == "tests.e2e.primary":
                e2e_tests.add(name)
            count += 1
    require(
        EXPECTED_UNIT_TESTS <= unit_tests,
        f"unit coverage missing tests {sorted(EXPECTED_UNIT_TESTS - unit_tests)}",
        errors,
    )
    require(
        EXPECTED_E2E_TESTS <= e2e_tests,
        f"e2e coverage missing tests {sorted(EXPECTED_E2E_TESTS - e2e_tests)}",
        errors,
    )
    return count, unit_tests, e2e_tests


def validate_commands(coverage: list[dict], errors: list[str]) -> int:
    count = 0
    for section in coverage:
        for command in list_values(section.get("validation_commands")):
            require(isinstance(command, str), f"validation command is not a string: {command!r}", errors)
            if not isinstance(command, str):
                continue
            stripped = command.strip()
            require(stripped, "validation command is empty", errors)
            if "cargo " in stripped:
                require("rch " in stripped, f"cargo command is not routed through rch: {stripped}", errors)
                require("CARGO_TARGET_DIR=" in stripped, f"rch cargo command missing CARGO_TARGET_DIR: {stripped}", errors)
                require("RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR" in stripped, f"rch cargo command missing env allowlist: {stripped}", errors)
            count += 1
    return count


def validate_kernel_contract(manifest: dict, errors: list[str]) -> None:
    contract = manifest.get("kernel_adoption_contract", {})
    require(isinstance(contract, dict), "kernel_adoption_contract must be an object", errors)
    if not isinstance(contract, dict):
        return
    require(contract.get("external_schema_forking_allowed") is False, "schema forking must be disallowed", errors)
    require(contract.get("standalone_fallback_required") is True, "standalone fallback must be required", errors)
    require(contract.get("cx_fallback_type") == "ValidationSecurityContext", "cx fallback must be ValidationSecurityContext", errors)
    id_types = string_set(contract.get("canonical_id_types"))
    fields = string_set(contract.get("required_evidence_fields"))
    scopes = string_set(contract.get("required_trace_scopes"))
    require(EXPECTED_ID_TYPES <= id_types, f"missing canonical id types {sorted(EXPECTED_ID_TYPES - id_types)}", errors)
    require(EXPECTED_EVIDENCE_FIELDS <= fields, f"missing evidence fields {sorted(EXPECTED_EVIDENCE_FIELDS - fields)}", errors)
    require(EXPECTED_TRACE_SCOPES <= scopes, f"missing trace scopes {sorted(EXPECTED_TRACE_SCOPES - scopes)}", errors)


def validate_reporting(manifest: dict, errors: list[str]) -> None:
    reporting = manifest.get("reporting", {})
    require(isinstance(reporting, dict), "reporting must be an object", errors)
    if not isinstance(reporting, dict):
        return
    fields = string_set(reporting.get("required_fields"))
    require(EXPECTED_REPORT_FIELDS <= fields, f"missing report fields {sorted(EXPECTED_REPORT_FIELDS - fields)}", errors)
    require(reporting.get("pass_event") == "franken_kernel_integration_completion_contract_validated", "unexpected pass event", errors)
    require(reporting.get("fail_event") == "franken_kernel_integration_completion_contract_failed", "unexpected fail event", errors)


def validate_manifest(manifest: dict) -> tuple[list[str], dict]:
    errors: list[str] = []
    require(manifest.get("schema_version") == "franken_kernel_integration_completion_contract.v1", "bad schema_version", errors)
    require(manifest.get("bead") == "bd-epeg", "bad original bead", errors)
    require(manifest.get("completion_debt_bead") == "bd-epeg.1", "bad completion debt bead", errors)
    require(manifest.get("next_audit_score_threshold", 0) >= 800, "audit threshold must be >= 800", errors)
    audit = manifest.get("audit", {})
    require(isinstance(audit, dict), "audit must be an object", errors)
    missing_items = set(list_values(audit.get("missing_items"))) if isinstance(audit, dict) else set()
    require(EXPECTED_MISSING_ITEMS == missing_items, f"unexpected audit missing items {sorted(missing_items)}", errors)

    for ref in list_values(manifest.get("implementation_refs")):
        validate_file_ref(ref, errors)
    validate_source_anchors(manifest, errors)
    validate_kernel_contract(manifest, errors)
    validate_reporting(manifest, errors)

    coverage = list_values(manifest.get("completion_coverage"))
    require(len(coverage) == 2, "completion_coverage must have exactly two sections", errors)
    coverage_ids = {section.get("missing_item_id") for section in coverage if isinstance(section, dict)}
    require(EXPECTED_MISSING_ITEMS == coverage_ids, f"coverage ids mismatch {sorted(coverage_ids)}", errors)
    implementation_ref_count = 0
    for section in coverage:
        if not isinstance(section, dict):
            errors.append(f"coverage section is not an object: {section!r}")
            continue
        require(section.get("status") == "covered", f"{section.get('missing_item_id')} not covered", errors)
        implementation_ref_count += validate_file_line_strings(
            section.get("implementation_refs"),
            errors,
            f"{section.get('missing_item_id')} implementation",
        )
    test_ref_count, unit_tests, e2e_tests = validate_test_refs(manifest, coverage, errors)
    command_count = validate_commands(coverage, errors)
    return errors, {
        "implementation_ref_count": implementation_ref_count,
        "test_ref_count": test_ref_count,
        "unit_test_count": len(unit_tests),
        "e2e_test_count": len(e2e_tests),
        "validation_command_count": command_count,
        "source_count": len(manifest.get("source_paths", {})),
    }


def write_outputs(status: str, errors: list[str], counts: dict) -> None:
    now = "2026-05-10T00:00:00Z"
    event = (
        "franken_kernel_integration_completion_contract_validated"
        if status == "pass"
        else "franken_kernel_integration_completion_contract_failed"
    )
    artifact_refs = [
        "tests/conformance/franken_kernel_integration_completion_contract.v1.json",
        "scripts/check_franken_kernel_integration_completion_contract.sh",
        "crates/frankenlibc-harness/tests/franken_kernel_integration_completion_contract_test.rs",
    ]
    latency_ns = time.monotonic_ns() - START_NS
    report = {
        "status": status,
        "schema_version": "1.0",
        "timestamp": now,
        "trace_id": "franken_kernel::completion::bd-epeg.1",
        "level": "info" if status == "pass" else "error",
        "event": event,
        "bead_id": "bd-epeg",
        "completion_debt_bead": "bd-epeg.1",
        "mode": "strict",
        "runtime_mode": "strict",
        "api_family": "franken_kernel_adoption",
        "symbol": "franken_kernel::canonical_ids",
        "decision_path": "audit->completion_contract->static_gate",
        "healing_action": None,
        "errno": 0 if status == "pass" else 22,
        "latency_ns": latency_ns,
        "decision_id": 1,
        "policy_id": 1,
        "artifact_refs": artifact_refs,
        "source_commit": source_commit(),
        "failure_signature": "none" if status == "pass" else "contract_validation_failed",
        "counts": counts,
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_row = dict(report)
    log_row["stream"] = "conformance"
    log_row["gate"] = "franken_kernel_integration_completion_contract"
    log_row["outcome"] = "pass" if status == "pass" else "fail"
    LOG.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")


try:
    manifest = load_json(CONTRACT)
except Exception as exc:
    errors = [f"cannot load contract: {exc}"]
    write_outputs("fail", errors, {})
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    sys.exit(1)

errors, counts = validate_manifest(manifest)
if errors:
    write_outputs("fail", errors, counts)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    sys.exit(1)

write_outputs("pass", [], counts)
print(
    "franken_kernel_integration_completion_contract: "
    f"sources={counts['source_count']} unit_tests={counts['unit_test_count']} "
    f"e2e_tests={counts['e2e_test_count']} commands={counts['validation_command_count']}"
)
PY
