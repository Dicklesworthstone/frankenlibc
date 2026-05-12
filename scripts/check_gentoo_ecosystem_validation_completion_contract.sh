#!/usr/bin/env bash
# check_gentoo_ecosystem_validation_completion_contract.sh -- fail-closed parent gate for bd-2icq.25
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_GENTOO_ECOSYSTEM_CONTRACT:-${ROOT}/tests/conformance/gentoo_ecosystem_validation_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_GENTOO_ECOSYSTEM_OUT_DIR:-${ROOT}/target/conformance/gentoo_ecosystem_validation_completion_contract}"
REPORT="${FRANKENLIBC_GENTOO_ECOSYSTEM_REPORT:-${OUT_DIR}/report.json}"
LOG="${FRANKENLIBC_GENTOO_ECOSYSTEM_LOG:-${OUT_DIR}/events.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1]).resolve()
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

SCHEMA_VERSION = "gentoo_ecosystem_validation_completion_contract.v1"
MANIFEST_ID = "gentoo-ecosystem-validation-completion-contract"
BEAD_ID = "bd-2icq"
COMPLETION_BEAD_ID = "bd-2icq.25"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_SOURCE_IDS = {
    "gentoo_unit_contract",
    "gentoo_unit_checker",
    "gentoo_unit_harness",
    "gentoo_e2e_runner",
    "gentoo_full_pipeline_e2e",
    "gentoo_fast_validate_tests",
    "gentoo_telemetry_contract",
    "gentoo_telemetry_harness",
    "gentoo_regression_contract",
    "gentoo_log_contract",
    "gentoo_pipeline_logging_contract",
    "fuzz_phase1_contract",
    "fuzz_harness_architecture_contract",
    "resource_constraints_gate",
}
REQUIRED_EVENTS = {
    "gentoo_ecosystem_validation.source_artifact",
    "gentoo_ecosystem_validation.missing_item_binding",
    "gentoo_ecosystem_validation.required_test_ref",
    "gentoo_ecosystem_validation.telemetry_contract",
    "gentoo_ecosystem_validation.validated",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    candidate = Path(path)
    try:
        return candidate.resolve().relative_to(root).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"contract unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append("contract must be a JSON object")
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


def require_string_list(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    strings: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{index}] must be a non-empty string")
            continue
        strings.append(item)
    return strings


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


def append_event(events: list[dict[str, Any]], event: str, payload: dict[str, Any]) -> None:
    row = {
        "schema_version": "gentoo_ecosystem_validation.event.v1",
        "event": event,
        "bead": BEAD_ID,
        "completion_debt_bead": COMPLETION_BEAD_ID,
        "timestamp_utc": utc_now(),
    }
    row.update(payload)
    events.append(row)


def validate_source_artifacts(
    contract: dict[str, Any],
    errors: list[str],
    events: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    artifacts = contract.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("source_artifacts must be a non-empty array")
        return {}

    by_id: dict[str, dict[str, Any]] = {}
    for index, artifact in enumerate(artifacts):
        context = f"source_artifacts[{index}]"
        if not isinstance(artifact, dict):
            errors.append(f"{context} must be an object")
            continue
        artifact_id = artifact.get("id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            errors.append(f"{context}.id missing")
            continue
        if artifact_id in by_id:
            errors.append(f"duplicate source artifact id {artifact_id}")
        by_id[artifact_id] = artifact
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{context}.path missing")
            continue
        text = read_text(path_text, errors, f"{context}.path")
        for line_ref in artifact.get("line_refs", []):
            validate_line_ref(line_ref, errors, f"{artifact_id}.line_refs")
        for needle in require_string_list(
            artifact.get("required_needles"),
            errors,
            f"{artifact_id}.required_needles",
        ):
            if needle not in text:
                errors.append(f"{artifact_id} missing required needle {needle!r}")
        append_event(
            events,
            "gentoo_ecosystem_validation.source_artifact",
            {
                "artifact_id": artifact_id,
                "kind": artifact.get("kind"),
                "path": path_text,
                "line_ref_count": len(artifact.get("line_refs", []))
                if isinstance(artifact.get("line_refs"), list)
                else 0,
            },
        )

    missing = sorted(REQUIRED_SOURCE_IDS - set(by_id))
    if missing:
        errors.append(f"source_artifacts missing required ids: {missing}")
    return by_id


def source_contains_ref(artifact: dict[str, Any], name: str, errors: list[str], context: str) -> bool:
    path_text = artifact.get("path")
    if not isinstance(path_text, str):
        errors.append(f"{context} references artifact without path")
        return False
    source = read_text(path_text, errors, context)
    patterns = [
        f"fn {name}(",
        f"def {name}(",
        f"\"{name}\"",
        name,
    ]
    return any(pattern in source for pattern in patterns)


def validate_bindings(
    contract: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    errors: list[str],
    events: list[dict[str, Any]],
) -> tuple[set[str], int]:
    bindings = contract.get("evidence_bindings")
    if not isinstance(bindings, list) or not bindings:
        errors.append("evidence_bindings must be a non-empty array")
        return set(), 0

    seen: set[str] = set()
    test_ref_count = 0
    for index, binding in enumerate(bindings):
        context = f"evidence_bindings[{index}]"
        if not isinstance(binding, dict):
            errors.append(f"{context} must be an object")
            continue
        binding_id = binding.get("id")
        if not isinstance(binding_id, str) or not binding_id:
            errors.append(f"{context}.id missing")
            continue
        if binding_id in seen:
            errors.append(f"duplicate evidence binding {binding_id}")
        seen.add(binding_id)
        required_artifacts = require_string_list(
            binding.get("required_artifacts"),
            errors,
            f"{binding_id}.required_artifacts",
        )
        for artifact_id in required_artifacts:
            if artifact_id not in artifacts:
                errors.append(f"{binding_id} references missing artifact {artifact_id}")
        required_commands = require_string_list(
            binding.get("required_commands"),
            errors,
            f"{binding_id}.required_commands",
        )
        for command in required_commands:
            if "cargo " in command and "rch exec --" not in command:
                errors.append(f"{binding_id}.required_commands must route cargo through rch: {command}")
        refs = binding.get("required_test_refs")
        if not isinstance(refs, list) or not refs:
            errors.append(f"{binding_id}.required_test_refs must be a non-empty array")
            refs = []
        for ref_index, ref in enumerate(refs):
            if not isinstance(ref, dict):
                errors.append(f"{binding_id}.required_test_refs[{ref_index}] must be an object")
                continue
            artifact_id = ref.get("artifact")
            name = ref.get("name")
            if not isinstance(artifact_id, str) or not isinstance(name, str):
                errors.append(f"{binding_id}.required_test_refs[{ref_index}] needs artifact and name")
                continue
            artifact = artifacts.get(artifact_id)
            if artifact is None:
                errors.append(f"{binding_id}.required_test_refs[{ref_index}] missing artifact {artifact_id}")
                continue
            if not source_contains_ref(artifact, name, errors, f"{binding_id}.{name}"):
                errors.append(f"{binding_id} missing test/ref {name} in {artifact_id}")
            test_ref_count += 1
            append_event(
                events,
                "gentoo_ecosystem_validation.required_test_ref",
                {"binding_id": binding_id, "artifact_id": artifact_id, "name": name},
            )
        for target in binding.get("required_targets", []):
            if not isinstance(target, str) or not target:
                errors.append(f"{binding_id}.required_targets must be non-empty strings")
                continue
            target_seen = False
            for artifact in artifacts.values():
                path_text = artifact.get("path")
                if not isinstance(path_text, str):
                    continue
                if target in read_text(path_text, errors, f"{binding_id}.{target}"):
                    target_seen = True
                    break
            if not target_seen:
                errors.append(f"{binding_id} required target not referenced by artifacts: {target}")
        append_event(
            events,
            "gentoo_ecosystem_validation.missing_item_binding",
            {
                "binding_id": binding_id,
                "artifact_count": len(required_artifacts),
                "required_command_count": len(required_commands),
            },
        )

    missing = sorted(REQUIRED_MISSING_ITEMS - seen)
    extra = sorted(seen - REQUIRED_MISSING_ITEMS)
    if missing:
        errors.append(f"evidence_bindings missing required items: {missing}")
    if extra:
        errors.append(f"evidence_bindings contains unexpected items: {extra}")
    return seen, test_ref_count


def validate_telemetry_contract(
    contract: dict[str, Any],
    errors: list[str],
    events: list[dict[str, Any]],
) -> list[str]:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be an object")
        return []
    required_events = set(require_string_list(
        telemetry.get("required_events"),
        errors,
        "telemetry_contract.required_events",
    ))
    missing = sorted(REQUIRED_EVENTS - required_events)
    if missing:
        errors.append(f"telemetry_contract.required_events missing {missing}")
    required_report_fields = require_string_list(
        telemetry.get("required_report_fields"),
        errors,
        "telemetry_contract.required_report_fields",
    )
    append_event(
        events,
        "gentoo_ecosystem_validation.telemetry_contract",
        {
            "required_event_count": len(required_events),
            "required_report_fields": required_report_fields,
        },
    )
    return sorted(required_events)


def validate_contract(contract: dict[str, Any], errors: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if contract.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")

    missing_items = set(require_string_list(
        contract.get("required_missing_items"),
        errors,
        "required_missing_items",
    ))
    if missing_items != REQUIRED_MISSING_ITEMS:
        errors.append(f"required_missing_items must be exactly {sorted(REQUIRED_MISSING_ITEMS)}")

    policy = contract.get("closeout_policy")
    if not isinstance(policy, dict):
        errors.append("closeout_policy must be an object")
    else:
        threshold = policy.get("next_audit_score_threshold")
        if not isinstance(threshold, int) or threshold < 800:
            errors.append("closeout_policy.next_audit_score_threshold must be >= 800")
        for flag in [
            "fail_when_artifact_missing",
            "fail_when_line_ref_blank",
            "fail_when_missing_item_unbound",
            "fail_when_required_event_missing",
        ]:
            if policy.get(flag) is not True:
                errors.append(f"closeout_policy.{flag} must be true")

    artifacts = validate_source_artifacts(contract, errors, events)
    bound_items, test_ref_count = validate_bindings(contract, artifacts, errors, events)
    telemetry_events = validate_telemetry_contract(contract, errors, events)
    append_event(
        events,
        "gentoo_ecosystem_validation.validated",
        {
            "status": "pass" if not errors else "fail",
            "missing_items_bound": sorted(bound_items),
            "source_artifact_count": len(artifacts),
            "required_test_ref_count": test_ref_count,
        },
    )
    summary = {
        "bound_items": sorted(bound_items),
        "source_artifact_count": len(artifacts),
        "required_test_ref_count": test_ref_count,
        "telemetry_events": telemetry_events,
    }
    return events, summary


errors: list[str] = []
contract = load_json(contract_path, errors)
events, summary = validate_contract(contract, errors)

report = {
    "schema_version": "gentoo_ecosystem_validation_completion_contract.report.v1",
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "contract": rel(contract_path),
    "status": "pass" if not errors else "fail",
    "generated_utc": utc_now(),
    "missing_items_bound": summary.get("bound_items", []),
    "source_artifact_count": summary.get("source_artifact_count", 0),
    "required_test_ref_count": summary.get("required_test_ref_count", 0),
    "telemetry_events": summary.get("telemetry_events", []),
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)

if errors:
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    "PASS gentoo ecosystem validation completion contract "
    f"sources={report['source_artifact_count']} "
    f"bindings={len(report['missing_items_bound'])} "
    f"test_refs={report['required_test_ref_count']} "
    f"events={len(report['telemetry_events'])}"
)
PY
