#!/usr/bin/env bash
# check_release_dossier_validator_completion_contract.sh -- bd-5fw.3.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RELEASE_DOSSIER_COMPLETION_CONTRACT:-${ROOT}/tests/release/release_dossier_validator_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RELEASE_DOSSIER_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_RELEASE_DOSSIER_COMPLETION_REPORT:-${OUT_DIR}/release_dossier_validator_completion_contract.report.json}"
LOG="${FRANKENLIBC_RELEASE_DOSSIER_COMPLETION_LOG:-${OUT_DIR}/release_dossier_validator_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
out_dir = Path(sys.argv[5])
source_commit = sys.argv[6]

SCHEMA = "release_dossier_validator_completion_contract.v1"
BEAD_ID = "bd-5fw.3.1"
ORIGINAL_BEAD = "bd-5fw.3"
TRACE_ID = "bd-5fw.3.1::release-dossier-validator::v1"
LOG_EVENT = "release_dossier_validator_completion_contract_validated"
LOG_GATE = "release_dossier_validator_completion"
REQUIRED_SOURCE_IDS = {
    "release_dossier_validator",
    "release_dossier_gate",
    "release_dossier_report",
    "release_dossier_harness_test",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_ARTIFACT_IDS = {
    "support_matrix",
    "reality_report",
    "conformance_coverage",
    "claim_reconciliation",
    "closure_sweep",
    "replacement_levels",
    "opportunity_matrix",
    "math_governance",
    "controller_ablation",
    "admission_gate",
    "production_kernel_manifest",
    "release_gate_dag",
    "symbol_fixture_coverage",
    "e2e_scenario_manifest",
    "closure_contract",
}
REQUIRED_CRITICAL_IDS = {
    "support_matrix",
    "reality_report",
    "conformance_coverage",
    "claim_reconciliation",
    "closure_sweep",
    "replacement_levels",
    "math_governance",
    "controller_ablation",
    "admission_gate",
    "production_kernel_manifest",
    "release_gate_dag",
    "closure_contract",
}
REQUIRED_PRESENT_NONCRITICAL_IDS = {"opportunity_matrix", "symbol_fixture_coverage"}
ALLOWED_MISSING_IDS = {"e2e_scenario_manifest"}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "bead",
    "status",
    "verdict",
    "summary",
    "artifact_results",
    "integrity_index",
    "findings",
    "compatibility_policy",
    "dossier_manifest_version",
    "release_notes_hook",
}
REQUIRED_RESULT_FIELDS = {
    "id",
    "path",
    "kind",
    "required",
    "critical",
    "status",
    "sha256",
    "size_bytes",
    "schema_valid",
    "findings",
}
REQUIRED_POLICY_FIELDS = {"format", "schema_versions", "integrity"}
REQUIRED_HOOK_FIELDS = {
    "source_path",
    "selection_policy",
    "entries",
    "release_notes_markdown",
    "summary",
}
REQUIRED_BINDINGS = {
    "tests.unit.primary": {
        "signature": "missing_unit_binding",
        "required_positive_tests": {
            "dossier_artifact_results_have_required_fields",
            "dossier_integrity_index_consistent",
            "dossier_compatibility_policy_present",
            "manifest_binds_unit_e2e_conformance_completion_debt",
            "checker_accepts_release_dossier_validator_completion_contract",
        },
        "required_negative_tests": {
            "checker_rejects_missing_unit_binding",
            "checker_rejects_removed_required_artifact_id",
            "checker_rejects_missing_integrity_binding",
        },
    },
    "tests.e2e.primary": {
        "signature": "missing_e2e_binding",
        "required_positive_tests": {
            "dossier_validator_produces_valid_report",
            "dossier_validator_release_notes_hook_tracks_closed_beads",
            "dossier_validator_release_notes_hook_invalid_limit_falls_back_to_default",
            "checker_emits_structured_report_and_log",
        },
        "required_negative_tests": {
            "checker_rejects_missing_e2e_binding",
            "checker_rejects_non_pass_dossier_report",
            "checker_rejects_removed_required_artifact_id",
        },
    },
    "tests.conformance.primary": {
        "signature": "missing_conformance_binding",
        "required_positive_tests": {
            "dossier_validator_produces_valid_report",
            "dossier_integrity_index_consistent",
            "checker_accepts_release_dossier_validator_completion_contract",
        },
        "required_negative_tests": {
            "checker_rejects_missing_conformance_binding",
            "checker_rejects_removed_required_artifact_id",
            "checker_rejects_missing_integrity_binding",
            "checker_rejects_non_pass_dossier_report",
        },
    },
}
RELEASE_DOSSIER_TESTS = {
    "dossier_validator_produces_valid_report",
    "dossier_artifact_results_have_required_fields",
    "dossier_integrity_index_consistent",
    "dossier_compatibility_policy_present",
    "dossier_validator_release_notes_hook_tracks_closed_beads",
    "dossier_validator_release_notes_hook_invalid_limit_falls_back_to_default",
}
COMPLETION_TESTS = {
    "manifest_binds_unit_e2e_conformance_completion_debt",
    "checker_accepts_release_dossier_validator_completion_contract",
    "checker_emits_structured_report_and_log",
    "checker_rejects_missing_unit_binding",
    "checker_rejects_missing_e2e_binding",
    "checker_rejects_missing_conformance_binding",
    "checker_rejects_removed_required_artifact_id",
    "checker_rejects_missing_integrity_binding",
    "checker_rejects_non_pass_dossier_report",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_unit_binding",
    "missing_e2e_binding",
    "missing_conformance_binding",
    "validator_source_failed",
    "dossier_report_failed",
    "dossier_integrity_failed",
    "dossier_policy_failed",
]

errors: list[dict[str, str]] = []
artifact_refs: set[str] = {str(contract_path)}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "release_dossier_validator_completion_contract_failed"


def load_json(path: Path, context: str, signature: str) -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def as_array(value: Any, context: str, signature: str) -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def as_object(value: Any, context: str, signature: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def string_set(value: Any, context: str, signature: str) -> set[str]:
    rows = as_array(value, context, signature)
    values = {row for row in rows if isinstance(row, str)}
    if len(values) != len(rows):
        add_error(signature, f"{context} must contain only strings")
    return values


def missing(required: set[str], actual: set[str]) -> list[str]:
    return sorted(required - actual)


def require_exact_set(context: str, actual: set[str], expected: set[str], signature: str) -> None:
    absent = missing(expected, actual)
    extra = missing(actual, expected)
    if absent:
        add_error(signature, f"{context} missing {absent}")
    if extra:
        add_error(signature, f"{context} contains unexpected entries {extra}")


def read_text(path_text: str, signature: str) -> str:
    path = resolve(path_text)
    try:
        artifact_refs.add(path_text)
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"cannot read {path_text}: {exc}")
        return ""


def source_has_fn(path_text: str, fn_name: str, signature: str) -> None:
    text = read_text(path_text, signature)
    if f"fn {fn_name}" not in text:
        add_error(signature, f"{path_text} missing test {fn_name}")


def emit_report(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    failure_signature = primary_signature() if errors else "none"
    event = {
        "timestamp": utc_now(),
        "trace_id": f"{TRACE_ID}::{LOG_EVENT}",
        "level": "error" if errors else "info",
        "event": LOG_EVENT,
        "bead_id": BEAD_ID,
        "stream": "release",
        "gate": LOG_GATE,
        "outcome": "fail" if errors else "pass",
        "source_commit": source_commit,
        "target_dir": rel(out_dir),
        "failure_signature": failure_signature,
        "artifact_refs": sorted(artifact_refs),
        "details": {
            "original_bead": ORIGINAL_BEAD,
            "completion_debt_bead": BEAD_ID,
            "error_count": len(errors),
            "summary": summary,
        },
    }
    report = {
        "schema_version": f"{SCHEMA}.report",
        "completion_debt_bead": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": status,
        "summary": summary,
        "artifact_refs": sorted(artifact_refs),
        "log_path": rel(log_path),
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, [event])
    if errors:
        print(f"FAIL: release dossier validator completion contract errors={len(errors)}")
        for error in errors[:16]:
            print(f"- {error['failure_signature']}: {error['message']}")
        sys.exit(1)
    print(
        "PASS: release dossier validator completion contract "
        f"artifacts={summary.get('dossier_artifact_count', 0)} "
        f"integrity={summary.get('integrity_entries', 0)}"
    )


contract = load_json(contract_path, "contract", "malformed_contract")
if contract.get("schema_version") != SCHEMA:
    add_error("malformed_contract", f"schema_version must be {SCHEMA}")
if contract.get("completion_debt_bead") != BEAD_ID:
    add_error("malformed_contract", f"completion_debt_bead must be {BEAD_ID}")
if contract.get("original_bead") != ORIGINAL_BEAD:
    add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
if contract.get("trace_id") != TRACE_ID:
    add_error("malformed_contract", f"trace_id must be {TRACE_ID}")

source_artifacts = as_array(contract.get("source_artifacts"), "source_artifacts", "malformed_contract")
source_by_id: dict[str, dict[str, Any]] = {}
for artifact in source_artifacts:
    row = as_object(artifact, "source_artifacts[]", "malformed_contract")
    artifact_id = row.get("id")
    path_text = row.get("path")
    if not isinstance(artifact_id, str) or not artifact_id:
        add_error("malformed_contract", "source_artifacts[].id must be a non-empty string")
        continue
    if not isinstance(path_text, str) or not path_text:
        add_error("malformed_contract", f"source_artifacts.{artifact_id}.path must be a non-empty string")
        continue
    source_by_id[artifact_id] = row
    path = resolve(path_text)
    if not path.is_file():
        add_error("missing_source_artifact", f"source artifact missing: {path_text}")
    else:
        artifact_refs.add(path_text)

for artifact_id in missing(REQUIRED_SOURCE_IDS, set(source_by_id)):
    add_error("missing_source_artifact", f"source_artifacts missing {artifact_id}")

dossier_contract = as_object(contract.get("dossier_contract"), "dossier_contract", "malformed_contract")
required_artifact_ids = string_set(
    dossier_contract.get("required_artifact_ids"),
    "dossier_contract.required_artifact_ids",
    "malformed_contract",
)
required_critical_ids = string_set(
    dossier_contract.get("required_critical_artifacts"),
    "dossier_contract.required_critical_artifacts",
    "malformed_contract",
)
required_present_noncritical_ids = string_set(
    dossier_contract.get("required_present_noncritical_artifacts"),
    "dossier_contract.required_present_noncritical_artifacts",
    "malformed_contract",
)
allowed_missing_ids = string_set(
    dossier_contract.get("allowed_missing_artifacts"),
    "dossier_contract.allowed_missing_artifacts",
    "malformed_contract",
)
required_report_fields = string_set(
    dossier_contract.get("required_report_fields"),
    "dossier_contract.required_report_fields",
    "malformed_contract",
)
required_result_fields = string_set(
    dossier_contract.get("required_artifact_result_fields"),
    "dossier_contract.required_artifact_result_fields",
    "malformed_contract",
)
required_policy_fields = string_set(
    dossier_contract.get("required_policy_fields"),
    "dossier_contract.required_policy_fields",
    "malformed_contract",
)
require_exact_set("required_artifact_ids", required_artifact_ids, REQUIRED_ARTIFACT_IDS, "malformed_contract")
require_exact_set("required_critical_artifacts", required_critical_ids, REQUIRED_CRITICAL_IDS, "malformed_contract")
require_exact_set(
    "required_present_noncritical_artifacts",
    required_present_noncritical_ids,
    REQUIRED_PRESENT_NONCRITICAL_IDS,
    "malformed_contract",
)
require_exact_set("allowed_missing_artifacts", allowed_missing_ids, ALLOWED_MISSING_IDS, "malformed_contract")
for field in missing(REQUIRED_REPORT_FIELDS, required_report_fields):
    add_error("malformed_contract", f"required_report_fields missing {field}")
for field in missing(REQUIRED_RESULT_FIELDS, required_result_fields):
    add_error("malformed_contract", f"required_artifact_result_fields missing {field}")
for field in missing(REQUIRED_POLICY_FIELDS, required_policy_fields):
    add_error("malformed_contract", f"required_policy_fields missing {field}")

bindings = as_array(contract.get("missing_item_bindings"), "missing_item_bindings", "malformed_contract")
bindings_by_item = {
    row.get("spec_item"): row for row in bindings if isinstance(row, dict) and isinstance(row.get("spec_item"), str)
}
for spec_item, requirements in REQUIRED_BINDINGS.items():
    signature = requirements["signature"]
    binding = as_object(bindings_by_item.get(spec_item), f"missing_item_bindings.{spec_item}", signature)
    positive = string_set(binding.get("required_positive_tests"), f"{spec_item}.required_positive_tests", signature)
    negative = string_set(binding.get("required_negative_tests"), f"{spec_item}.required_negative_tests", signature)
    test_refs = string_set(binding.get("test_refs"), f"{spec_item}.test_refs", signature)
    implementation_refs = string_set(
        binding.get("implementation_refs"),
        f"{spec_item}.implementation_refs",
        signature,
    )
    validation_commands = string_set(
        binding.get("validation_commands"),
        f"{spec_item}.validation_commands",
        signature,
    )
    for test_name in missing(requirements["required_positive_tests"], positive):
        add_error(signature, f"{spec_item} required_positive_tests missing {test_name}")
    for test_name in missing(requirements["required_negative_tests"], negative):
        add_error(signature, f"{spec_item} required_negative_tests missing {test_name}")
    for path_text in missing(
        {
            "crates/frankenlibc-harness/tests/release_dossier_validator_test.rs",
            "crates/frankenlibc-harness/tests/release_dossier_validator_completion_contract_test.rs",
        },
        test_refs,
    ):
        add_error(signature, f"{spec_item} test_refs missing {path_text}")
    for path_text in missing(
        {
            "scripts/release_dossier_validator.py",
            "tests/release/dossier_validation_report.v1.json",
            "scripts/check_release_dossier_validator_completion_contract.sh",
        },
        implementation_refs,
    ):
        add_error(signature, f"{spec_item} implementation_refs missing {path_text}")
    if not validation_commands:
        add_error(signature, f"{spec_item} validation_commands must be non-empty")

for name in RELEASE_DOSSIER_TESTS:
    source_has_fn("crates/frankenlibc-harness/tests/release_dossier_validator_test.rs", name, "missing_unit_binding")
for name in COMPLETION_TESTS:
    source_has_fn(
        "crates/frankenlibc-harness/tests/release_dossier_validator_completion_contract_test.rs",
        name,
        "missing_e2e_binding",
    )

if REQUIRED_SOURCE_IDS.issubset(source_by_id):
    validator_text = read_text(source_by_id["release_dossier_validator"]["path"], "validator_source_failed")
    for marker in string_set(
        dossier_contract.get("validator_source_markers"),
        "dossier_contract.validator_source_markers",
        "malformed_contract",
    ):
        if marker not in validator_text:
            add_error("validator_source_failed", f"release_dossier_validator.py missing marker {marker!r}")

    gate_text = read_text(source_by_id["release_dossier_gate"]["path"], "validator_source_failed")
    for marker in string_set(
        dossier_contract.get("gate_source_markers"),
        "dossier_contract.gate_source_markers",
        "malformed_contract",
    ):
        if marker not in gate_text:
            add_error("validator_source_failed", f"check_release_dossier.sh missing marker {marker!r}")

if errors:
    emit_report(
        {
            "source_artifact_count": len(source_by_id),
            "binding_count": len(bindings_by_item),
            "dossier_artifact_count": 0,
            "integrity_entries": 0,
        }
    )

report_override = os.environ.get("FRANKENLIBC_RELEASE_DOSSIER_REPORT")
report_source_path = report_override or source_by_id["release_dossier_report"]["path"]
dossier_report = load_json(resolve(report_source_path), "release_dossier_report", "dossier_report_failed")

for field in missing(required_report_fields, set(dossier_report)):
    add_error("dossier_report_failed", f"release dossier report missing field {field}")
if dossier_report.get("schema_version") != dossier_contract.get("required_report_schema_version"):
    add_error("dossier_report_failed", "release dossier schema_version mismatch")
if dossier_report.get("bead") != ORIGINAL_BEAD:
    add_error("dossier_report_failed", f"release dossier bead must be {ORIGINAL_BEAD}")
if dossier_report.get("status") != dossier_contract.get("required_report_status"):
    add_error("dossier_report_failed", "release dossier status mismatch")
if dossier_report.get("verdict") != dossier_contract.get("required_verdict"):
    add_error("dossier_report_failed", "release dossier verdict mismatch")

summary = as_object(dossier_report.get("summary"), "release_dossier_report.summary", "dossier_report_failed")
required_summary = as_object(
    dossier_contract.get("required_summary"),
    "dossier_contract.required_summary",
    "malformed_contract",
)
for key, expected in sorted(required_summary.items()):
    if summary.get(key) != expected:
        add_error("dossier_report_failed", f"summary.{key} expected {expected!r} got {summary.get(key)!r}")

artifact_results = as_array(dossier_report.get("artifact_results"), "release_dossier_report.artifact_results", "dossier_report_failed")
if len(artifact_results) != dossier_contract.get("required_artifact_count"):
    add_error(
        "dossier_report_failed",
        f"expected {dossier_contract.get('required_artifact_count')} artifact results, got {len(artifact_results)}",
    )

results_by_id: dict[str, dict[str, Any]] = {}
for index, row in enumerate(artifact_results):
    result = as_object(row, f"artifact_results[{index}]", "dossier_report_failed")
    artifact_id = result.get("id")
    if not isinstance(artifact_id, str) or not artifact_id:
        add_error("dossier_report_failed", f"artifact_results[{index}].id must be string")
        continue
    results_by_id[artifact_id] = result
    for field in missing(required_result_fields, set(result)):
        add_error("dossier_report_failed", f"{artifact_id} missing field {field}")
    if result.get("status") not in {"VALID", "PRESENT", "MISSING"}:
        add_error("dossier_report_failed", f"{artifact_id} has invalid status {result.get('status')!r}")
    if not isinstance(result.get("findings"), list):
        add_error("dossier_report_failed", f"{artifact_id}.findings must be an array")

require_exact_set("release dossier artifact_results", set(results_by_id), REQUIRED_ARTIFACT_IDS, "dossier_report_failed")

integrity_index = as_object(
    dossier_report.get("integrity_index"),
    "release_dossier_report.integrity_index",
    "dossier_integrity_failed",
)
if len(integrity_index) != dossier_contract.get("required_integrity_entries"):
    add_error(
        "dossier_integrity_failed",
        f"expected {dossier_contract.get('required_integrity_entries')} integrity entries, got {len(integrity_index)}",
    )
require_exact_set(
    "integrity_index",
    set(integrity_index),
    REQUIRED_ARTIFACT_IDS - ALLOWED_MISSING_IDS,
    "dossier_integrity_failed",
)

for artifact_id in sorted(REQUIRED_CRITICAL_IDS):
    result = results_by_id.get(artifact_id, {})
    if result.get("status") != "VALID":
        add_error("dossier_report_failed", f"critical artifact {artifact_id} must be VALID")
    if result.get("critical") is not True:
        add_error("dossier_report_failed", f"critical artifact {artifact_id} must be marked critical")
    if result.get("required") is not True:
        add_error("dossier_report_failed", f"critical artifact {artifact_id} must be required")

for artifact_id in sorted(REQUIRED_PRESENT_NONCRITICAL_IDS):
    result = results_by_id.get(artifact_id, {})
    if result.get("status") != "VALID":
        add_error("dossier_report_failed", f"present noncritical artifact {artifact_id} must be VALID")
    if result.get("critical") is not False:
        add_error("dossier_report_failed", f"present noncritical artifact {artifact_id} must not be critical")
    if result.get("required") is not True:
        add_error("dossier_report_failed", f"present noncritical artifact {artifact_id} must remain required")

for artifact_id in sorted(ALLOWED_MISSING_IDS):
    result = results_by_id.get(artifact_id, {})
    if result.get("status") != "MISSING":
        add_error("dossier_report_failed", f"allowed missing artifact {artifact_id} must be MISSING")
    if result.get("required") is not False:
        add_error("dossier_report_failed", f"allowed missing artifact {artifact_id} must not be required")
    if result.get("critical") is not False:
        add_error("dossier_report_failed", f"allowed missing artifact {artifact_id} must not be critical")

for artifact_id, result in sorted(results_by_id.items()):
    if result.get("status") == "MISSING":
        if artifact_id in integrity_index:
            add_error("dossier_integrity_failed", f"missing artifact {artifact_id} must not have integrity entry")
        continue
    sha = result.get("sha256")
    if not isinstance(sha, str) or len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
        add_error("dossier_integrity_failed", f"{artifact_id}.sha256 must be 64 lowercase hex chars")
    entry = as_object(integrity_index.get(artifact_id), f"integrity_index.{artifact_id}", "dossier_integrity_failed")
    if entry.get("sha256") != sha:
        add_error("dossier_integrity_failed", f"integrity sha mismatch for {artifact_id}")
    if entry.get("path") != result.get("path"):
        add_error("dossier_integrity_failed", f"integrity path mismatch for {artifact_id}")
    if entry.get("size_bytes") != result.get("size_bytes"):
        add_error("dossier_integrity_failed", f"integrity size mismatch for {artifact_id}")

policy = as_object(dossier_report.get("compatibility_policy"), "release_dossier_report.compatibility_policy", "dossier_policy_failed")
for field in missing(REQUIRED_POLICY_FIELDS, set(policy)):
    add_error("dossier_policy_failed", f"compatibility_policy missing {field}")

hook_contract = as_object(dossier_contract.get("release_notes_hook"), "dossier_contract.release_notes_hook", "malformed_contract")
required_hook_fields = string_set(hook_contract.get("required_fields"), "release_notes_hook.required_fields", "malformed_contract")
for field in missing(REQUIRED_HOOK_FIELDS, required_hook_fields):
    add_error("malformed_contract", f"release_notes_hook.required_fields missing {field}")
hook = as_object(dossier_report.get("release_notes_hook"), "release_dossier_report.release_notes_hook", "dossier_policy_failed")
for field in missing(REQUIRED_HOOK_FIELDS, set(hook)):
    add_error("dossier_policy_failed", f"release_notes_hook missing {field}")
hook_summary = as_object(hook.get("summary"), "release_notes_hook.summary", "dossier_policy_failed")
selection_policy = as_object(hook.get("selection_policy"), "release_notes_hook.selection_policy", "dossier_policy_failed")
if selection_policy.get("limit") != hook_contract.get("required_limit"):
    add_error("dossier_policy_failed", "release notes hook limit mismatch")
if hook_summary.get("selected") != hook_contract.get("required_selected"):
    add_error("dossier_policy_failed", "release notes hook selected mismatch")
if hook_summary.get("invalid_rows") != hook_contract.get("required_invalid_rows"):
    add_error("dossier_policy_failed", "release notes hook invalid_rows mismatch")
entries = as_array(hook.get("entries"), "release_notes_hook.entries", "dossier_policy_failed")
if len(entries) != hook_contract.get("required_selected"):
    add_error("dossier_policy_failed", "release notes hook entry count mismatch")
markdown = hook.get("release_notes_markdown")
if not isinstance(markdown, str) or "Release Notes Candidates" not in markdown:
    add_error("dossier_policy_failed", "release_notes_markdown missing expected heading")

structured_log = as_object(contract.get("structured_log_contract"), "structured_log_contract", "malformed_contract")
if structured_log.get("event") != LOG_EVENT:
    add_error("malformed_contract", f"structured_log_contract.event must be {LOG_EVENT}")
if structured_log.get("stream") != "release":
    add_error("malformed_contract", "structured_log_contract.stream must be release")
if structured_log.get("gate") != LOG_GATE:
    add_error("malformed_contract", f"structured_log_contract.gate must be {LOG_GATE}")
for field in missing(
    {
        "timestamp",
        "trace_id",
        "level",
        "event",
        "bead_id",
        "stream",
        "gate",
        "outcome",
        "source_commit",
        "target_dir",
        "failure_signature",
        "artifact_refs",
        "details",
    },
    string_set(structured_log.get("required_fields"), "structured_log_contract.required_fields", "malformed_contract"),
):
    add_error("malformed_contract", f"structured_log_contract.required_fields missing {field}")

emit_report(
    {
        "source_artifact_count": len(source_by_id),
        "binding_count": len(bindings_by_item),
        "dossier_artifact_count": len(artifact_results),
        "integrity_entries": len(integrity_index),
        "critical_artifact_count": len(REQUIRED_CRITICAL_IDS),
        "present_noncritical_artifact_count": len(REQUIRED_PRESENT_NONCRITICAL_IDS),
        "allowed_missing_count": len(ALLOWED_MISSING_IDS),
        "release_note_candidates": summary.get("release_note_candidates", 0),
    }
)
PY
