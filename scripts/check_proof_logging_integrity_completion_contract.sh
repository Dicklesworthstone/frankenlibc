#!/usr/bin/env bash
# Validate bd-34s.7.1 proof logging and artifact-integrity completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_PROOF_LOGGING_CONTRACT:-${ROOT}/tests/conformance/proof_logging_integrity_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_PROOF_LOGGING_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_PROOF_LOGGING_REPORT:-${OUT_DIR}/proof_logging_integrity_completion_contract.report.json}"
LOG="${FRANKENLIBC_PROOF_LOGGING_LOG:-${OUT_DIR}/proof_logging_integrity_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(sys.argv[1]).resolve()
CONTRACT = Path(sys.argv[2]).resolve()
REPORT = Path(sys.argv[3]).resolve()
LOG = Path(sys.argv[4]).resolve()
SOURCE_COMMIT = sys.argv[5]

SCHEMA = "proof_logging_integrity_completion_contract.v1"
BEAD = "bd-34s.7"
COMPLETION_BEAD = "bd-34s.7.1"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}
REQUIRED_SOURCE_IDS = {
    "evidence_compliance_module",
    "evidence_compliance_tests",
    "harness_cli",
    "proof_binder_gate",
    "proof_chain_gate",
    "proof_chain_e2e_tests",
    "evidence_compliance_completion_contract",
    "completion_checker",
    "completion_harness",
}
REQUIRED_UNIT_REFS = {
    ("evidence_compliance_tests", "valid_bundle_passes"),
    ("evidence_compliance_tests", "legacy_index_without_run_id_still_passes_and_emits_migration_warning"),
    ("evidence_compliance_tests", "failure_event_without_artifacts_fails_deterministically"),
    ("evidence_compliance_tests", "malformed_log_line_reports_schema_violation"),
    ("evidence_compliance_tests", "hash_mismatch_emits_debug_and_error_proof_logs"),
}
REQUIRED_E2E_REFS = {
    ("evidence_compliance_tests", "cli_emits_triage_format_with_required_fields"),
    ("proof_chain_e2e_tests", "gate_script_exists_and_executable"),
    ("proof_chain_e2e_tests", "gate_script_emits_logs_and_reports"),
}
REQUIRED_GATE_SCRIPTS = {
    "scripts/check_proof_binder.sh",
    "scripts/check_proof_chain_e2e.sh",
}
REQUIRED_CLI_SUBCOMMANDS = {
    "proof-binder-proofs",
    "proof-chain-e2e",
}
REQUIRED_PROOF_EVENTS = {
    "evidence_compliance.proof_start",
    "evidence_compliance.artifact_hash_compute",
    "evidence_compliance.artifact_hash_mismatch",
    "evidence_compliance.log_schema_violation",
    "evidence_compliance.failure_event_missing_artifact_refs",
    "evidence_compliance.proof_summary",
    "evidence_compliance.proof_failure",
    "proof_chain.scope_boundary",
    "proof_chain.proof_binder",
    "proof_chain.chain_integrity",
    "proof_chain.dashboard",
    "proof_chain.cross_report_consistency",
    "proof_chain.summary",
}
REQUIRED_COMPLETION_EVENTS = {
    "proof_logging_integrity.source_artifact",
    "proof_logging_integrity.unit_binding",
    "proof_logging_integrity.e2e_binding",
    "proof_logging_integrity.telemetry_contract",
    "proof_logging_integrity.completion_contract_validated",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "timestamp",
    "event",
    "status",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "missing_items_closed",
    "source_count",
    "unit_test_ref_count",
    "e2e_test_ref_count",
    "proof_event_count",
    "completion_event_count",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def error(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        error(message)


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        error(f"{label} unreadable: {rel(path)}: {exc}")
        return {}


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        error(f"{label} must be an object")
        return {}
    return value


def require_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        error(f"{label} must be a non-empty array")
        return []
    strings: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            error(f"{label}[{index}] must be a non-empty string")
        else:
            strings.append(item)
    return strings


def workspace_path(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else ROOT / path


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": "proof_logging_integrity_completion_contract.log.v1",
            "timestamp": utc_now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}",
            "event": event,
            "status": status,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": BEAD,
            "source_commit": SOURCE_COMMIT,
            "artifact_refs": [rel(CONTRACT), rel(REPORT)],
            "details": details,
        }
    )


def validate_top_level(manifest: dict[str, Any]) -> None:
    require(manifest.get("schema_version") == SCHEMA, "schema_version mismatch")
    require(manifest.get("bead") == BEAD, "bead mismatch")
    require(
        manifest.get("completion_debt_bead") == COMPLETION_BEAD,
        "completion_debt_bead mismatch",
    )
    evidence = require_object(
        manifest.get("completion_debt_evidence"),
        "completion_debt_evidence",
    )
    require(evidence.get("original_bead") == BEAD, "original_bead mismatch")
    require(
        evidence.get("next_audit_score_threshold", 0) >= 800,
        "next audit score threshold must be at least 800",
    )
    missing = set(
        require_string_list(
            evidence.get("missing_items_closed"),
            "completion_debt_evidence.missing_items_closed",
        )
    )
    require(
        missing == REQUIRED_MISSING_ITEMS,
        f"missing_items_closed must be {sorted(REQUIRED_MISSING_ITEMS)}, got {sorted(missing)}",
    )


def validate_source_artifacts(manifest: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, list):
        error("source_artifacts must be an array")
        return {}, {}
    texts: dict[str, str] = {}
    paths: dict[str, str] = {}
    seen: set[str] = set()
    for index, artifact in enumerate(artifacts):
        artifact_obj = require_object(artifact, f"source_artifacts[{index}]")
        artifact_id = artifact_obj.get("id")
        path_text = artifact_obj.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            error(f"source_artifacts[{index}].id must be a non-empty string")
            continue
        if artifact_id in seen:
            error(f"duplicate source artifact id: {artifact_id}")
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            error(f"source_artifacts[{index}].path must be a non-empty string")
            continue
        path = workspace_path(path_text).resolve()
        if ROOT not in path.parents and path != ROOT:
            error(f"source artifact escapes workspace: {path_text}")
            continue
        if not path.is_file():
            error(f"source artifact missing: {path_text}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as exc:
            error(f"source artifact unreadable: {path_text}: {exc}")
            continue
        texts[artifact_id] = text
        paths[artifact_id] = path_text
        for needle in require_string_list(
            artifact_obj.get("required_needles"),
            f"source_artifacts[{index}].required_needles",
        ):
            if needle not in text:
                error(f"source artifact {artifact_id} missing needle {needle!r}")
        append_event(
            "proof_logging_integrity.source_artifact",
            "pass",
            {"artifact_id": artifact_id, "path": path_text},
        )
    missing = REQUIRED_SOURCE_IDS - seen
    extra = seen - REQUIRED_SOURCE_IDS
    require(not missing, f"source artifacts missing ids: {sorted(missing)}")
    require(not extra, f"source artifacts unexpected ids: {sorted(extra)}")
    return texts, paths


def validate_command_prefixes(commands: list[str], label: str) -> None:
    for command in commands:
        if "cargo " in command:
            require(command.startswith("rch exec --"), f"{label} cargo command must use rch: {command}")


def validate_refs(
    refs: Any,
    expected: set[tuple[str, str]],
    texts: dict[str, str],
    label: str,
    event: str,
) -> int:
    if not isinstance(refs, list):
        error(f"{label} must be an array")
        return 0
    actual: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        ref_obj = require_object(ref, f"{label}[{index}]")
        artifact_id = ref_obj.get("artifact_id")
        name = ref_obj.get("name")
        if not isinstance(artifact_id, str) or not isinstance(name, str):
            error(f"{label}[{index}] must contain artifact_id and name")
            continue
        actual.add((artifact_id, name))
        if name not in texts.get(artifact_id, ""):
            error(f"{label} reference {artifact_id}:{name} is not present in source artifact")
        append_event(event, "pass", {"artifact_id": artifact_id, "test": name})
    require(actual == expected, f"{label} must be {sorted(expected)}, got {sorted(actual)}")
    return len(actual)


def validate_unit_primary(manifest: dict[str, Any], texts: dict[str, str]) -> int:
    unit = require_object(manifest.get("unit_primary"), "unit_primary")
    validate_command_prefixes(
        require_string_list(unit.get("required_commands"), "unit_primary.required_commands"),
        "unit_primary",
    )
    return validate_refs(
        unit.get("required_test_refs"),
        REQUIRED_UNIT_REFS,
        texts,
        "unit_primary.required_test_refs",
        "proof_logging_integrity.unit_binding",
    )


def validate_e2e_primary(manifest: dict[str, Any], texts: dict[str, str]) -> int:
    e2e = require_object(manifest.get("e2e_primary"), "e2e_primary")
    validate_command_prefixes(
        require_string_list(e2e.get("required_commands"), "e2e_primary.required_commands"),
        "e2e_primary",
    )
    gate_scripts = set(
        require_string_list(e2e.get("required_gate_scripts"), "e2e_primary.required_gate_scripts")
    )
    require(gate_scripts == REQUIRED_GATE_SCRIPTS, f"gate scripts mismatch: {sorted(gate_scripts)}")
    for script in gate_scripts:
        require(workspace_path(script).is_file(), f"gate script missing: {script}")
    subcommands = set(
        require_string_list(e2e.get("required_cli_subcommands"), "e2e_primary.required_cli_subcommands")
    )
    require(
        subcommands == REQUIRED_CLI_SUBCOMMANDS,
        f"CLI subcommands mismatch: {sorted(subcommands)}",
    )
    return validate_refs(
        e2e.get("required_test_refs"),
        REQUIRED_E2E_REFS,
        texts,
        "e2e_primary.required_test_refs",
        "proof_logging_integrity.e2e_binding",
    )


def validate_telemetry_primary(manifest: dict[str, Any]) -> tuple[int, int]:
    telemetry = require_object(manifest.get("telemetry_primary"), "telemetry_primary")
    proof_events = set(
        require_string_list(
            telemetry.get("required_proof_events"),
            "telemetry_primary.required_proof_events",
        )
    )
    completion_events = set(
        require_string_list(
            telemetry.get("required_completion_events"),
            "telemetry_primary.required_completion_events",
        )
    )
    report_fields = set(
        require_string_list(
            telemetry.get("required_report_fields"),
            "telemetry_primary.required_report_fields",
        )
    )
    require(
        proof_events == REQUIRED_PROOF_EVENTS,
        f"proof events must be {sorted(REQUIRED_PROOF_EVENTS)}, got {sorted(proof_events)}",
    )
    require(
        completion_events == REQUIRED_COMPLETION_EVENTS,
        f"completion events must be {sorted(REQUIRED_COMPLETION_EVENTS)}, got {sorted(completion_events)}",
    )
    missing_fields = REQUIRED_REPORT_FIELDS - report_fields
    require(not missing_fields, f"telemetry report missing fields: {sorted(missing_fields)}")
    for field in ["report_path", "log_path"]:
        value = telemetry.get(field)
        require(isinstance(value, str) and bool(value), f"telemetry_primary.{field} missing")
    append_event(
        "proof_logging_integrity.telemetry_contract",
        "pass",
        {
            "required_proof_events": sorted(proof_events),
            "required_completion_events": sorted(completion_events),
            "required_report_fields": sorted(report_fields),
        },
    )
    return len(proof_events), len(completion_events)


manifest = require_object(load_json(CONTRACT, "contract"), "contract")
validate_top_level(manifest)
texts, paths = validate_source_artifacts(manifest)
unit_ref_count = validate_unit_primary(manifest, texts)
e2e_ref_count = validate_e2e_primary(manifest, texts)
proof_event_count, completion_event_count = validate_telemetry_primary(manifest)

status = "fail" if errors else "pass"
append_event(
    "proof_logging_integrity.completion_contract_validated",
    status,
    {
        "unit_test_ref_count": unit_ref_count,
        "e2e_test_ref_count": e2e_ref_count,
        "proof_event_count": proof_event_count,
        "completion_event_count": completion_event_count,
        "errors": errors,
    },
)

report = {
    "schema_version": "proof_logging_integrity_completion_contract.report.v1",
    "timestamp": utc_now(),
    "event": "proof_logging_integrity.completion_contract_validated",
    "status": status,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": BEAD,
    "source_commit": SOURCE_COMMIT,
    "missing_items_closed": sorted(REQUIRED_MISSING_ITEMS),
    "source_count": len(paths),
    "unit_test_ref_count": unit_ref_count,
    "e2e_test_ref_count": e2e_ref_count,
    "proof_event_count": proof_event_count,
    "completion_event_count": completion_event_count,
    "artifact_refs": sorted(paths.values()) + [rel(CONTRACT), rel(REPORT), rel(LOG)],
    "failure_signature": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in events),
    encoding="utf-8",
)

if errors:
    for item in errors:
        print(f"proof_logging_integrity_completion_contract: ERROR {item}", file=sys.stderr)
    print(
        f"proof_logging_integrity_completion_contract: FAIL errors={len(errors)} report={rel(REPORT)} log={rel(LOG)}",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    "proof_logging_integrity_completion_contract: PASS "
    f"sources={len(paths)} unit_refs={unit_ref_count} "
    f"e2e_refs={e2e_ref_count} proof_events={proof_event_count} "
    f"events={len(events)}"
)
PY
