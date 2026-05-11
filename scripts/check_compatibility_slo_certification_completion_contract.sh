#!/usr/bin/env bash
# check_compatibility_slo_certification_completion_contract.sh -- bd-26xb.3.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_COMPAT_SLO_CONTRACT:-${ROOT}/tests/release/compatibility_slo_certification_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_COMPAT_SLO_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_COMPAT_SLO_REPORT:-${OUT_DIR}/compatibility_slo_certification_completion_contract.report.json}"
LOG="${FRANKENLIBC_COMPAT_SLO_LOG:-${OUT_DIR}/compatibility_slo_certification_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
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

SCHEMA = "compatibility_slo_certification_completion_contract.v1"
BEAD_ID = "bd-26xb.3.1"
ORIGINAL_BEAD = "bd-26xb.3"
TRACE_ID = "bd-26xb.3.1::compatibility-slo-certification::v1"
REQUIRED_ARTIFACT_IDS = {
    "release_dossier_validator",
    "release_dossier_gate",
    "release_dossier_report",
    "release_dossier_harness_test",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_POLICY_FIELDS = {"format", "schema_versions", "integrity"}
REQUIRED_UNIT_TESTS = {
    "dossier_artifact_results_have_required_fields",
    "dossier_integrity_index_consistent",
    "dossier_compatibility_policy_present",
    "checker_accepts_compatibility_slo_certification_contract",
}
REQUIRED_E2E_TESTS = {
    "dossier_validator_produces_valid_report",
    "dossier_validator_release_notes_hook_tracks_closed_beads",
    "dossier_validator_release_notes_hook_invalid_limit_falls_back_to_default",
    "checker_accepts_compatibility_slo_certification_contract",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_unit_binding",
    "checker_rejects_missing_e2e_binding",
    "checker_rejects_missing_required_artifact_binding",
}
RELEASE_DOSSIER_TESTS = {
    "dossier_artifact_results_have_required_fields",
    "dossier_integrity_index_consistent",
    "dossier_compatibility_policy_present",
    "dossier_validator_produces_valid_report",
    "dossier_validator_release_notes_hook_tracks_closed_beads",
    "dossier_validator_release_notes_hook_invalid_limit_falls_back_to_default",
}
COMPLETION_TESTS = REQUIRED_NEGATIVE_TESTS | {
    "checker_accepts_compatibility_slo_certification_contract",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_unit_binding",
    "missing_e2e_binding",
    "dossier_report_failed",
    "dossier_policy_failed",
]

events: list[dict[str, Any]] = []
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
    return "compatibility_slo_certification_completion_contract_failed"


def load_json(path: Path, context: str, signature: str = "malformed_contract") -> Any:
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


def event(name: str, status: str, failure_signature: str = "none", **fields: Any) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "event": name,
        "status": status,
        "source_commit": source_commit,
        "target_dir": rel(out_dir),
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


def source_has_fn(path_text: str, fn_name: str, signature: str) -> None:
    path = resolve(path_text)
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"cannot read test source {path_text}: {exc}")
        return
    if f"fn {fn_name}" not in text:
        add_error(signature, f"{path_text} missing test {fn_name}")


def finish(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        events.append(event("compatibility_slo_certification_completion_contract_validated", "pass"))
    else:
        events.append(
            event(
                "compatibility_slo_certification_completion_contract_failed",
                "fail",
                primary_signature(),
            )
        )
    report = {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": status,
        "summary": {
            **summary,
            "event_count": len(events),
        },
        "artifact_refs": sorted(artifact_refs),
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, events)
    if errors:
        print(f"FAIL: compatibility SLO certification contract errors={len(errors)}")
        for error in errors[:12]:
            print(f"- {error['failure_signature']}: {error['message']}")
        sys.exit(1)
    print(
        "PASS: compatibility SLO certification contract "
        f"artifacts={summary.get('artifact_count', 0)} integrity={summary.get('integrity_entries', 0)}"
    )


contract = load_json(contract_path, "contract")
if contract.get("schema_version") != SCHEMA:
    add_error("malformed_contract", f"schema_version must be {SCHEMA}")
if contract.get("bead_id") != BEAD_ID:
    add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
if contract.get("original_bead") != ORIGINAL_BEAD:
    add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
if contract.get("trace_id") != TRACE_ID:
    add_error("malformed_contract", f"trace_id must be {TRACE_ID}")

source_artifacts = as_array(contract.get("source_artifacts"), "source_artifacts")
source_by_id: dict[str, dict[str, Any]] = {}
for artifact in source_artifacts:
    row = as_object(artifact, "source_artifacts[]")
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
        if artifact_id.endswith("gate"):
            try:
                if path.stat().st_mode & 0o111 == 0:
                    add_error("missing_source_artifact", f"gate script is not executable: {path_text}")
            except Exception as exc:
                add_error("missing_source_artifact", f"cannot stat gate script {path_text}: {exc}")

for artifact_id in missing(REQUIRED_ARTIFACT_IDS, set(source_by_id)):
    add_error("missing_source_artifact", f"source_artifacts missing {artifact_id}")

dossier_contract = as_object(contract.get("dossier_contract"), "dossier_contract")
required_summary = as_object(dossier_contract.get("required_summary"), "dossier_contract.required_summary")
required_critical = string_set(
    dossier_contract.get("required_critical_artifacts"),
    "dossier_contract.required_critical_artifacts",
    "malformed_contract",
)
allowed_missing = string_set(
    dossier_contract.get("allowed_missing_artifacts"),
    "dossier_contract.allowed_missing_artifacts",
    "malformed_contract",
)
required_policy = string_set(
    dossier_contract.get("required_policy_fields"),
    "dossier_contract.required_policy_fields",
    "malformed_contract",
)
for field in missing(REQUIRED_POLICY_FIELDS, required_policy):
    add_error("malformed_contract", f"required_policy_fields missing {field}")

bindings = as_array(contract.get("missing_item_bindings"), "missing_item_bindings")
bindings_by_item = {
    row.get("spec_item"): row for row in bindings if isinstance(row, dict) and isinstance(row.get("spec_item"), str)
}

unit = as_object(bindings_by_item.get("tests.unit.primary"), "missing_item_bindings.tests.unit.primary", "missing_unit_binding")
e2e = as_object(bindings_by_item.get("tests.e2e.primary"), "missing_item_bindings.tests.e2e.primary", "missing_e2e_binding")

unit_positive = string_set(unit.get("required_positive_tests"), "unit.required_positive_tests", "missing_unit_binding")
unit_negative = string_set(unit.get("required_negative_tests"), "unit.required_negative_tests", "missing_unit_binding")
e2e_positive = string_set(e2e.get("required_positive_tests"), "e2e.required_positive_tests", "missing_e2e_binding")
e2e_negative = string_set(e2e.get("required_negative_tests"), "e2e.required_negative_tests", "missing_e2e_binding")
unit_tests = string_set(unit.get("test_refs"), "unit.test_refs", "missing_unit_binding")
e2e_tests = string_set(e2e.get("test_refs"), "e2e.test_refs", "missing_e2e_binding")

for test_name in missing(REQUIRED_UNIT_TESTS, unit_positive):
    add_error("missing_unit_binding", f"unit required_positive_tests missing {test_name}")
for test_name in missing({"checker_rejects_missing_unit_binding", "checker_rejects_missing_required_artifact_binding"}, unit_negative):
    add_error("missing_unit_binding", f"unit required_negative_tests missing {test_name}")
for test_name in missing(REQUIRED_E2E_TESTS, e2e_positive):
    add_error("missing_e2e_binding", f"e2e required_positive_tests missing {test_name}")
for test_name in missing({"checker_rejects_missing_e2e_binding", "checker_rejects_missing_required_artifact_binding"}, e2e_negative):
    add_error("missing_e2e_binding", f"e2e required_negative_tests missing {test_name}")
for path_text in missing(
    {
        "crates/frankenlibc-harness/tests/release_dossier_validator_test.rs",
        "crates/frankenlibc-harness/tests/compatibility_slo_certification_completion_contract_test.rs",
    },
    unit_tests,
):
    add_error("missing_unit_binding", f"unit test_refs missing {path_text}")
for path_text in missing(
    {
        "crates/frankenlibc-harness/tests/release_dossier_validator_test.rs",
        "crates/frankenlibc-harness/tests/compatibility_slo_certification_completion_contract_test.rs",
    },
    e2e_tests,
):
    add_error("missing_e2e_binding", f"e2e test_refs missing {path_text}")

for name in RELEASE_DOSSIER_TESTS:
    source_has_fn("crates/frankenlibc-harness/tests/release_dossier_validator_test.rs", name, "missing_unit_binding")
for name in COMPLETION_TESTS:
    source_has_fn(
        "crates/frankenlibc-harness/tests/compatibility_slo_certification_completion_contract_test.rs",
        name,
        "missing_e2e_binding",
    )

events.append(
    event(
        "source_artifacts_and_bindings_validated",
        "fail" if errors else "pass",
        primary_signature() if errors else "none",
        source_artifact_count=len(source_by_id),
    )
)

if errors:
    finish({"artifact_count": 0, "integrity_entries": 0})

dossier_report = load_json(resolve(source_by_id["release_dossier_report"]["path"]), "release_dossier_report", "dossier_report_failed")
if dossier_report.get("schema_version") != "v1":
    add_error("dossier_report_failed", "release dossier schema_version must be v1")
if dossier_report.get("status") != dossier_contract.get("required_report_status"):
    add_error("dossier_report_failed", "release dossier status mismatch")
if dossier_report.get("verdict") != dossier_contract.get("required_verdict"):
    add_error("dossier_report_failed", "release dossier verdict mismatch")

summary = as_object(dossier_report.get("summary"), "release_dossier_report.summary", "dossier_report_failed")
for key, expected in sorted(required_summary.items()):
    if summary.get(key) != expected:
        add_error("dossier_report_failed", f"summary.{key} expected {expected!r} got {summary.get(key)!r}")

artifact_results = as_array(dossier_report.get("artifact_results"), "release_dossier_report.artifact_results", "dossier_report_failed")
if len(artifact_results) != dossier_contract.get("required_artifact_count"):
    add_error("dossier_report_failed", f"expected {dossier_contract.get('required_artifact_count')} artifact results, got {len(artifact_results)}")

results_by_id: dict[str, dict[str, Any]] = {}
for index, row in enumerate(artifact_results):
    result = as_object(row, f"artifact_results[{index}]", "dossier_report_failed")
    artifact_id = result.get("id")
    if not isinstance(artifact_id, str) or not artifact_id:
        add_error("dossier_report_failed", f"artifact_results[{index}].id must be string")
        continue
    results_by_id[artifact_id] = result
    for field in ("path", "kind", "required", "critical", "status", "schema_valid", "findings"):
        if field not in result:
            add_error("dossier_report_failed", f"{artifact_id} missing field {field}")

for artifact_id in missing(required_critical, set(results_by_id)):
    add_error("dossier_report_failed", f"missing critical artifact result {artifact_id}")
for artifact_id in sorted(required_critical):
    result = results_by_id.get(artifact_id, {})
    if result.get("status") != "VALID":
        add_error("dossier_report_failed", f"critical artifact {artifact_id} must be VALID")
    if result.get("critical") is not True:
        add_error("dossier_report_failed", f"critical artifact {artifact_id} must be marked critical")
    if result.get("required") is not True:
        add_error("dossier_report_failed", f"critical artifact {artifact_id} must be required")

for artifact_id in sorted(allowed_missing):
    result = results_by_id.get(artifact_id, {})
    if result.get("status") != "MISSING":
        add_error("dossier_report_failed", f"allowed missing artifact {artifact_id} should be MISSING")
    if result.get("critical") is True:
        add_error("dossier_report_failed", f"allowed missing artifact {artifact_id} must not be critical")

integrity_index = as_object(dossier_report.get("integrity_index"), "release_dossier_report.integrity_index", "dossier_report_failed")
if len(integrity_index) != dossier_contract.get("required_integrity_entries"):
    add_error("dossier_report_failed", f"expected {dossier_contract.get('required_integrity_entries')} integrity entries, got {len(integrity_index)}")
for artifact_id, result in sorted(results_by_id.items()):
    if result.get("status") == "MISSING":
        continue
    entry = as_object(integrity_index.get(artifact_id), f"integrity_index.{artifact_id}", "dossier_report_failed")
    if entry.get("sha256") != result.get("sha256"):
        add_error("dossier_report_failed", f"integrity sha mismatch for {artifact_id}")
    sha = entry.get("sha256")
    if not isinstance(sha, str) or len(sha) != 64:
        add_error("dossier_report_failed", f"integrity sha must be 64 hex chars for {artifact_id}")

policy = as_object(dossier_report.get("compatibility_policy"), "release_dossier_report.compatibility_policy", "dossier_policy_failed")
for field in missing(REQUIRED_POLICY_FIELDS, set(policy)):
    add_error("dossier_policy_failed", f"compatibility_policy missing {field}")

hook_contract = as_object(dossier_contract.get("release_notes_hook"), "dossier_contract.release_notes_hook")
hook = as_object(dossier_report.get("release_notes_hook"), "release_dossier_report.release_notes_hook", "dossier_policy_failed")
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

events.append(
    event(
        "release_dossier_report_validated",
        "fail" if errors else "pass",
        primary_signature() if errors else "none",
        artifact_count=len(artifact_results),
        integrity_entries=len(integrity_index),
        release_note_candidates=summary.get("release_note_candidates"),
    )
)

finish(
    {
        "artifact_count": len(artifact_results),
        "integrity_entries": len(integrity_index),
        "critical_artifact_count": len(required_critical),
        "allowed_missing_count": len(allowed_missing),
        "release_note_candidates": summary.get("release_note_candidates", 0),
    }
)
PY
