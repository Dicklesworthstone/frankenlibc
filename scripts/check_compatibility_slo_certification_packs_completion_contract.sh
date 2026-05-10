#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_COMPAT_CERT_COMPLETION_CONTRACT:-$ROOT/tests/conformance/compatibility_slo_certification_packs_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_COMPAT_CERT_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_COMPAT_CERT_COMPLETION_REPORT:-$OUT_DIR/compatibility_slo_certification_packs_completion_contract.report.json}"
LOG="${FRANKENLIBC_COMPAT_CERT_COMPLETION_LOG:-$OUT_DIR/compatibility_slo_certification_packs_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "compatibility_slo_certification_packs_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "compatibility_slo_certification_packs_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-26xb.3"
COMPLETION_BEAD = "bd-26xb.3.1"
PASS_EVENT = "compatibility_slo_certification_completion_contract_pass"
FAIL_EVENT = "compatibility_slo_certification_completion_contract_fail"
REQUIRED_SOURCE_ARTIFACTS = {
    "release_dossier_validator",
    "release_dossier_report",
    "release_dossier_gate",
    "release_dossier_harness",
    "workload_compatibility_contract",
    "workload_compatibility_gate",
    "workload_compatibility_harness",
    "user_compatibility_report",
    "completion_checker",
    "completion_harness_test",
}
REQUIRED_DOSSIER_ARTIFACT_IDS = {
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
REQUIRED_CRITICAL_ARTIFACT_IDS = {
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
REQUIRED_RELEASE_POLICY_FIELDS = {"format", "schema_versions", "integrity"}
REQUIRED_SOURCE_TEST_REFS = {
    "dossier_artifact_results_have_required_fields",
    "dossier_integrity_index_consistent",
    "dossier_compatibility_policy_present",
    "dossier_validator_produces_valid_report",
    "dossier_validator_release_notes_hook_tracks_closed_beads",
    "dossier_validator_release_notes_hook_invalid_limit_falls_back_to_default",
}
REQUIRED_COMPLETION_TEST_REFS = {
    "manifest_binds_unit_and_e2e_completion_evidence",
    "checker_validates_compatibility_slo_certification_contract",
    "checker_emits_completion_report_and_jsonl",
    "checker_rejects_missing_release_artifact_binding",
    "checker_rejects_missing_source_test_ref",
    "checker_rejects_unimplemented_telemetry_event",
}
REQUIRED_TELEMETRY_EVENTS = {
    "compatibility_slo_certification_completion_summary",
    "compatibility_slo_certification_release_dossier_artifacts",
    "compatibility_slo_certification_source_bindings",
    "compatibility_slo_certification_test_bindings",
    PASS_EVENT,
    FAIL_EVENT,
}
PASS_LOG_EVENTS = [
    "compatibility_slo_certification_completion_summary",
    "compatibility_slo_certification_release_dossier_artifacts",
    "compatibility_slo_certification_source_bindings",
    "compatibility_slo_certification_test_bindings",
    PASS_EVENT,
]

errors: list[str] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def read_text(path_text: str, label: str) -> str:
    try:
        return (ROOT / path_text).read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} is unreadable: {path_text}: {exc}")
        return ""


def as_string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def require_set(value: Any, required: set[str], context: str) -> set[str]:
    actual = set(as_string_list(value, context))
    missing = sorted(required - actual)
    if missing:
        err(f"{context} missing {','.join(missing)}")
    return actual


def require_text(path_text: str, needles: list[str], context: str) -> None:
    source = read_text(path_text, context)
    for needle in needles:
        require(needle in source, f"{context} missing text {needle!r}")


def require_sha(value: Any, context: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        err(f"{context} must be a 64-character lowercase hex SHA256")


manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}
missing_sources = sorted(REQUIRED_SOURCE_ARTIFACTS - set(source_artifacts))
if missing_sources:
    err(f"source_artifacts missing {','.join(missing_sources)}")
for source_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{source_id} must be a non-empty string")
        continue
    require((ROOT / path_text).exists(), f"source artifact {source_id} missing: {path_text}")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}

release_contract = evidence.get("required_release_dossier_contract", {})
if not isinstance(release_contract, dict):
    err("completion_debt_evidence.required_release_dossier_contract must be an object")
    release_contract = {}

required_dossier_artifacts = require_set(
    release_contract.get("required_artifact_ids"),
    REQUIRED_DOSSIER_ARTIFACT_IDS,
    "required_release_dossier_contract.required_artifact_ids",
)
required_critical_artifacts = require_set(
    release_contract.get("critical_artifact_ids"),
    REQUIRED_CRITICAL_ARTIFACT_IDS,
    "required_release_dossier_contract.critical_artifact_ids",
)
require_set(
    release_contract.get("compatibility_policy_fields"),
    REQUIRED_RELEASE_POLICY_FIELDS,
    "required_release_dossier_contract.compatibility_policy_fields",
)

telemetry_events = set(as_string_list(evidence.get("telemetry_events"), "completion_debt_evidence.telemetry_events"))
missing_events = sorted(REQUIRED_TELEMETRY_EVENTS - telemetry_events)
if missing_events:
    err(f"completion_debt_evidence.telemetry_events missing {','.join(missing_events)}")
unknown_events = sorted(telemetry_events - REQUIRED_TELEMETRY_EVENTS)
if unknown_events:
    err(f"completion_debt_evidence.telemetry_events has unsupported event(s) {','.join(unknown_events)}")

for impl_ref in evidence.get("implementation_refs", []):
    if not isinstance(impl_ref, dict):
        err("implementation_refs entries must be objects")
        continue
    path_text = impl_ref.get("path")
    needles = impl_ref.get("required_text")
    if not isinstance(path_text, str):
        err("implementation_refs entry missing path")
        continue
    require((ROOT / path_text).exists(), f"implementation ref path missing: {path_text}")
    require_text(path_text, as_string_list(needles, f"implementation_refs.{impl_ref.get('id', path_text)}.required_text"), f"implementation ref {path_text}")

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict):
    err("completion_debt_evidence.test_sources must be an object")
    test_sources = {}
release_source = test_sources.get("release_dossier_harness", {})
completion_source = test_sources.get("completion_harness_test", {})
workload_source = test_sources.get("workload_compatibility_harness", {})
if not isinstance(release_source, dict):
    err("test_sources.release_dossier_harness must be an object")
    release_source = {}
if not isinstance(completion_source, dict):
    err("test_sources.completion_harness_test must be an object")
    completion_source = {}
if not isinstance(workload_source, dict):
    err("test_sources.workload_compatibility_harness must be an object")
    workload_source = {}
require_set(release_source.get("required_test_refs"), REQUIRED_SOURCE_TEST_REFS, "test_sources.release_dossier_harness.required_test_refs")
require_set(completion_source.get("required_test_refs"), REQUIRED_COMPLETION_TEST_REFS, "test_sources.completion_harness_test.required_test_refs")
require_set(workload_source.get("required_test_refs"), {"workload_compatibility_dossier"}, "test_sources.workload_compatibility_harness.required_test_refs")

report_path = source_artifacts.get("release_dossier_report")
release_report = load_json(ROOT / str(report_path), "release_dossier_report") if isinstance(report_path, str) else {}
require(release_report.get("schema_version") == release_contract.get("report_schema_version"), "release dossier schema_version mismatch")
require(release_report.get("status") == release_contract.get("status"), "release dossier status mismatch")
require(release_report.get("verdict") == release_contract.get("verdict"), "release dossier verdict mismatch")
summary = release_report.get("summary", {})
if not isinstance(summary, dict):
    err("release dossier summary must be an object")
    summary = {}
expected_summary = release_contract.get("summary", {})
if not isinstance(expected_summary, dict):
    err("required_release_dossier_contract.summary must be an object")
    expected_summary = {}
for field, expected in expected_summary.items():
    require(summary.get(field) == expected, f"release dossier summary.{field} mismatch")

artifact_results = release_report.get("artifact_results", [])
if not isinstance(artifact_results, list) or not artifact_results:
    err("release dossier artifact_results must be a non-empty array")
    artifact_results = []
artifact_by_id: dict[str, dict[str, Any]] = {}
for item in artifact_results:
    if not isinstance(item, dict):
        err("release dossier artifact_results entries must be objects")
        continue
    artifact_id = item.get("id")
    if not isinstance(artifact_id, str) or not artifact_id:
        err("release dossier artifact result missing id")
        continue
    artifact_by_id[artifact_id] = item

missing_artifact_results = sorted(required_dossier_artifacts - set(artifact_by_id))
if missing_artifact_results:
    err(f"release dossier artifact_results missing {','.join(missing_artifact_results)}")

optional_missing = release_contract.get("optional_missing_artifact")
for artifact_id in sorted(required_dossier_artifacts):
    item = artifact_by_id.get(artifact_id)
    if item is None:
        continue
    require(isinstance(item.get("path"), str) and item.get("path"), f"artifact {artifact_id} missing path")
    require(isinstance(item.get("kind"), str) and item.get("kind"), f"artifact {artifact_id} missing kind")
    require(isinstance(item.get("required"), bool), f"artifact {artifact_id} missing required bool")
    require(isinstance(item.get("critical"), bool), f"artifact {artifact_id} missing critical bool")
    status = item.get("status")
    if artifact_id == optional_missing:
        require(status == "MISSING", f"optional missing artifact {artifact_id} should be MISSING")
        require(item.get("required") is False, f"optional missing artifact {artifact_id} must not be required")
        require(item.get("critical") is False, f"optional missing artifact {artifact_id} must not be critical")
    else:
        require(status == "VALID", f"artifact {artifact_id} should be VALID")
        require(item.get("schema_valid") is True, f"artifact {artifact_id} schema_valid should be true")
        require_sha(item.get("sha256"), f"artifact {artifact_id}.sha256")
    if artifact_id in required_critical_artifacts:
        require(item.get("critical") is True, f"critical artifact {artifact_id} must be marked critical")

integrity_index = release_report.get("integrity_index", {})
if not isinstance(integrity_index, dict) or not integrity_index:
    err("release dossier integrity_index must be a non-empty object")
    integrity_index = {}
for artifact_id, item in artifact_by_id.items():
    if item.get("status") == "MISSING":
        continue
    index_entry = integrity_index.get(artifact_id)
    if not isinstance(index_entry, dict):
        err(f"integrity_index missing present artifact {artifact_id}")
        continue
    require(index_entry.get("path") == item.get("path"), f"integrity_index path mismatch for {artifact_id}")
    require(index_entry.get("sha256") == item.get("sha256"), f"integrity_index sha256 mismatch for {artifact_id}")

policy = release_report.get("compatibility_policy", {})
if not isinstance(policy, dict):
    err("release dossier compatibility_policy must be an object")
    policy = {}
for field in REQUIRED_RELEASE_POLICY_FIELDS:
    require(isinstance(policy.get(field), str) and policy.get(field), f"compatibility_policy missing {field}")

hook = release_report.get("release_notes_hook", {})
if not isinstance(hook, dict):
    err("release dossier release_notes_hook must be an object")
    hook = {}
hook_contract = release_contract.get("release_notes_hook", {})
if not isinstance(hook_contract, dict):
    err("required_release_dossier_contract.release_notes_hook must be an object")
    hook_contract = {}
require(hook.get("source_path") == hook_contract.get("source_path"), "release_notes_hook.source_path mismatch")
selection_policy = hook.get("selection_policy", {})
expected_selection = hook_contract.get("selection_policy", {})
if not isinstance(selection_policy, dict):
    err("release_notes_hook.selection_policy must be an object")
    selection_policy = {}
if not isinstance(expected_selection, dict):
    err("release_notes_hook selection contract must be an object")
    expected_selection = {}
for field, expected in expected_selection.items():
    require(selection_policy.get(field) == expected, f"release_notes_hook.selection_policy.{field} mismatch")
hook_summary = hook.get("summary", {})
expected_hook_summary = hook_contract.get("summary", {})
if not isinstance(hook_summary, dict):
    err("release_notes_hook.summary must be an object")
    hook_summary = {}
if not isinstance(expected_hook_summary, dict):
    err("release_notes_hook summary contract must be an object")
    expected_hook_summary = {}
for field, expected in expected_hook_summary.items():
    require(hook_summary.get(field) == expected, f"release_notes_hook.summary.{field} mismatch")
entries = hook.get("entries", [])
if not isinstance(entries, list):
    err("release_notes_hook.entries must be an array")
    entries = []
require(len(entries) == expected_hook_summary.get("selected"), "release_notes_hook entries length mismatch")
for index, entry in enumerate(entries):
    if not isinstance(entry, dict):
        err(f"release_notes_hook.entries[{index}] must be an object")
        continue
    for field in as_string_list(hook_contract.get("required_entry_fields"), "release_notes_hook.required_entry_fields"):
        require(field in entry and entry[field] not in ("", None), f"release_notes_hook.entries[{index}] missing {field}")
require(isinstance(hook.get("release_notes_markdown"), str) and "## Release Notes Candidates" in hook.get("release_notes_markdown", ""), "release_notes_hook.release_notes_markdown missing heading")

pack = evidence.get("certification_pack_requirements", {})
if not isinstance(pack, dict):
    err("completion_debt_evidence.certification_pack_requirements must be an object")
    pack = {}
required_pack_fields = require_set(
    pack.get("required_pack_fields"),
    {"passed_workload_set", "deviation_windows", "repair_rate_envelopes", "explicit_unsupported_zones"},
    "certification_pack_requirements.required_pack_fields",
)
workload_contract_path = source_artifacts.get("workload_compatibility_contract")
workload_contract = load_json(ROOT / str(workload_contract_path), "workload_compatibility_contract") if isinstance(workload_contract_path, str) else {}
require(workload_contract.get("schema_version") == "v1", "workload compatibility schema_version mismatch")
workload_fields = set(as_string_list(workload_contract.get("required_dossier_fields"), "workload_compatibility_contract.required_dossier_fields"))
contract_workload_fields = require_set(
    pack.get("workload_compatibility_fields"),
    workload_fields,
    "certification_pack_requirements.workload_compatibility_fields",
)
missing_workload_fields = sorted(workload_fields - contract_workload_fields)
if missing_workload_fields:
    err(f"certification pack workload fields missing {','.join(missing_workload_fields)}")

user_report_path = source_artifacts.get("user_compatibility_report")
user_report = load_json(ROOT / str(user_report_path), "user_compatibility_report") if isinstance(user_report_path, str) else {}
require(user_report.get("schema_version") == "v1", "user compatibility report schema_version mismatch")
user_fields = set(as_string_list(user_report.get("required_report_fields"), "user_compatibility_report.required_report_fields"))
contract_user_fields = require_set(
    pack.get("user_compatibility_fields"),
    user_fields,
    "certification_pack_requirements.user_compatibility_fields",
)
missing_user_fields = sorted(user_fields - contract_user_fields)
if missing_user_fields:
    err(f"certification pack user report fields missing {','.join(missing_user_fields)}")

missing_bindings = manifest.get("missing_item_bindings", [])
if not isinstance(missing_bindings, list):
    err("missing_item_bindings must be an array")
    missing_bindings = []
binding_by_id = {item.get("id"): item for item in missing_bindings if isinstance(item, dict)}
unit_binding = binding_by_id.get("tests.unit.primary")
e2e_binding = binding_by_id.get("tests.e2e.primary")
if not isinstance(unit_binding, dict):
    err("missing_item_bindings missing tests.unit.primary")
    unit_binding = {}
if not isinstance(e2e_binding, dict):
    err("missing_item_bindings missing tests.e2e.primary")
    e2e_binding = {}
require(unit_binding.get("kind") == "unit", "tests.unit.primary kind must be unit")
require(e2e_binding.get("kind") == "e2e", "tests.e2e.primary kind must be e2e")
require_set(unit_binding.get("required_test_refs"), REQUIRED_COMPLETION_TEST_REFS | {
    "dossier_artifact_results_have_required_fields",
    "dossier_integrity_index_consistent",
    "dossier_compatibility_policy_present",
}, "tests.unit.primary.required_test_refs")
require_set(e2e_binding.get("required_test_refs"), {
    "dossier_validator_produces_valid_report",
    "dossier_validator_release_notes_hook_tracks_closed_beads",
    "dossier_validator_release_notes_hook_invalid_limit_falls_back_to_default",
    "workload_compatibility_dossier_test",
    "checker_validates_compatibility_slo_certification_contract",
}, "tests.e2e.primary.required_test_refs")

source_commit = git_head()
status = "fail" if errors else "pass"
failure_signature = "validation_errors" if errors else "none"
event_names = PASS_LOG_EVENTS if not errors else [
    "compatibility_slo_certification_completion_summary",
    FAIL_EVENT,
]
artifact_refs = {
    key: value
    for key, value in sorted(source_artifacts.items())
    if isinstance(value, str)
}
test_refs = sorted(REQUIRED_SOURCE_TEST_REFS | REQUIRED_COMPLETION_TEST_REFS)
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

rows = []
for event in event_names:
    rows.append(
        {
            "timestamp": timestamp,
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "outcome": "pass" if not errors else "fail",
            "source_commit": source_commit,
            "schema_version": EXPECTED_REPORT_SCHEMA,
            "artifact_refs": artifact_refs,
            "test_refs": test_refs,
            "release_artifact_ids": sorted(required_dossier_artifacts),
            "certification_pack_fields": sorted(required_pack_fields),
            "failure_signature": failure_signature,
        }
    )

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "generated_at_utc": timestamp,
    "source_commit": source_commit,
    "status": status,
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "summary": {
        "release_artifacts": len(artifact_by_id),
        "valid_release_artifacts": summary.get("valid"),
        "missing_release_artifacts": summary.get("missing"),
        "critical_missing": summary.get("critical_missing"),
        "release_note_candidates": summary.get("release_note_candidates"),
        "release_notes_selected": hook_summary.get("selected"),
        "source_artifacts": len(artifact_refs),
        "workload_dossier_fields": len(workload_fields),
        "user_report_fields": len(user_fields),
        "test_refs": len(test_refs),
        "errors": len(errors),
    },
    "events": event_names,
    "artifact_refs": artifact_refs,
    "test_refs": test_refs,
    "release_artifact_ids": sorted(required_dossier_artifacts),
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

if errors:
    print("FAIL: compatibility SLO certification-pack completion contract failed")
    for message in errors:
        print(f"  - {message}")
    sys.exit(1)

print(
    "PASS: compatibility SLO certification-pack completion contract validated "
    f"{len(artifact_by_id)} release artifacts"
)
PY
