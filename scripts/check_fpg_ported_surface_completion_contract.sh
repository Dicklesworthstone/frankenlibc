#!/usr/bin/env bash
# Validate bd-bp8fl.3.13.1 fpg ported-surface completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${1:-${ROOT}/tests/conformance/fpg_ported_surface_completion_contract.v1.json}"
OUT_DIR="${2:-${ROOT}/target/conformance}"
REPORT_PATH="${OUT_DIR}/fpg_ported_surface_completion_contract.report.json"
LOG_PATH="${OUT_DIR}/fpg_ported_surface_completion_contract.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT_PATH}" "${REPORT_PATH}" "${LOG_PATH}" <<'PY'
import hashlib
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT_PATH = pathlib.Path(sys.argv[2]).resolve()
REPORT_PATH = pathlib.Path(sys.argv[3]).resolve()
LOG_PATH = pathlib.Path(sys.argv[4]).resolve()

EXPECTED_SCHEMA = "fpg_ported_surface_completion_contract.v1"
EXPECTED_BEAD = "bd-bp8fl.3.13"
EXPECTED_COMPLETION_BEAD = "bd-bp8fl.3.13.1"
EXPECTED_MISSING_ITEMS = [
    "tests.unit.primary",
    "tests.integration.primary",
    "tests.conformance.primary",
]
EXPECTED_SOURCE_KEYS = {
    "source_gate",
    "source_checker",
    "source_test",
    "feature_parity",
    "gap_ledger",
    "gap_groups",
    "owner_family_groups",
    "completion_checker",
    "completion_test",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        err(f"{label} JSON load failed: {exc}")
        return {}


def read_text(path: pathlib.Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} read failed: {exc}")
        return ""


def sha256_file(path: pathlib.Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": "fpg_ported_surface_completion_contract.log.v1",
            "event": event,
            "status": status,
            "bead": EXPECTED_COMPLETION_BEAD,
            "source_bead": EXPECTED_BEAD,
            "artifact_refs": [rel(CONTRACT_PATH), rel(REPORT_PATH)],
            "details": details,
        }
    )


def artifact_path(value: Any, context: str) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty string path")
        return None
    path = (ROOT / value).resolve()
    if ROOT not in path.parents and path != ROOT:
        err(f"{context} escapes workspace: {value}")
        return None
    if not path.is_file():
        err(f"{context} missing file: {value}")
        return None
    return path


def string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        err(f"{context} must be a list of strings")
        return []
    return list(value)


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, pathlib.Path]:
    source_artifacts = manifest.get("source_artifacts")
    if not isinstance(source_artifacts, dict):
        err("source_artifacts must be an object")
        return {}
    missing = EXPECTED_SOURCE_KEYS - set(source_artifacts)
    extra = set(source_artifacts) - EXPECTED_SOURCE_KEYS
    require(not missing, f"source_artifacts missing keys: {sorted(missing)}")
    require(not extra, f"source_artifacts unexpected keys: {sorted(extra)}")

    paths: dict[str, pathlib.Path] = {}
    for key in sorted(EXPECTED_SOURCE_KEYS):
        path = artifact_path(source_artifacts.get(key), f"source_artifacts.{key}")
        if path is not None:
            paths[key] = path
    append_event(
        "fpg_ported_surface_completion.source_artifacts",
        "fail" if errors else "pass",
        {"artifact_count": len(paths), "keys": sorted(paths)},
    )
    return paths


def validate_test_refs(
    section: dict[str, Any],
    section_name: str,
    test_text: str,
    expected_names: set[str],
) -> list[str]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list):
        err(f"{section_name}.required_test_refs must be a list")
        refs = []
    names = {
        ref.get("name")
        for ref in refs
        if isinstance(ref, dict) and isinstance(ref.get("name"), str)
    }
    require(names == expected_names, f"{section_name} test refs mismatch: got {sorted(names)}")
    for name in expected_names:
        require(name in test_text, f"source_test missing {section_name} test ref: {name}")

    commands = string_list(section.get("required_commands"), f"{section_name}.required_commands")
    for command in commands:
        if "cargo " in command:
            require(command.startswith("rch exec --"), f"non-rch cargo validation command: {command}")
    return sorted(names)


def validate_completion_evidence(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> dict[str, list[str]]:
    evidence = manifest.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        return {"unit": [], "integration": [], "conformance": []}

    test_text = read_text(paths["source_test"], "source_test") if "source_test" in paths else ""
    unit_refs = validate_test_refs(
        evidence.get("unit_primary", {}),
        "unit_primary",
        test_text,
        {"gate_artifact_covers_ported_surface_rows"},
    )
    integration_refs = validate_test_refs(
        evidence.get("integration_primary", {}),
        "integration_primary",
        test_text,
        {
            "gate_script_passes_and_emits_structured_artifacts",
            "gate_rejects_missing_ported_surface_anchor",
            "gate_rejects_premature_done_claim",
            "gate_rejects_stale_gate_source_commit",
            "gate_rejects_stale_feature_parity_binding",
        },
    )

    conformance = evidence.get("conformance_primary")
    if not isinstance(conformance, dict):
        err("conformance_primary must be an object")
        conformance_refs: list[str] = []
    else:
        required_artifacts = conformance.get("required_artifacts")
        if not isinstance(required_artifacts, list):
            err("conformance_primary.required_artifacts must be a list")
            required_artifacts = []
        conformance_refs = [
            ref.get("artifact")
            for ref in required_artifacts
            if isinstance(ref, dict) and isinstance(ref.get("artifact"), str)
        ]
        require(
            set(conformance_refs)
            == {"source_gate", "source_checker", "gap_ledger", "gap_groups", "owner_family_groups"},
            f"conformance artifact refs mismatch: {sorted(conformance_refs)}",
        )
        for command in string_list(
            conformance.get("required_commands"),
            "conformance_primary.required_commands",
        ):
            if "cargo " in command:
                require(command.startswith("rch exec --"), f"non-rch cargo validation command: {command}")

    append_event(
        "fpg_ported_surface_completion.evidence_refs",
        "fail" if errors else "pass",
        {
            "unit_refs": unit_refs,
            "integration_refs": integration_refs,
            "conformance_refs": sorted(conformance_refs),
        },
    )
    return {
        "unit": unit_refs,
        "integration": integration_refs,
        "conformance": sorted(conformance_refs),
    }


def validate_source_gate_contract(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    contract = manifest.get("required_source_gate_contract")
    if not isinstance(contract, dict):
        err("required_source_gate_contract must be an object")
        return {}

    source_gate = load_json(paths["source_gate"], "source_gate")
    require(source_gate.get("schema_version") == contract.get("schema_version"), "source gate schema drift")
    require(source_gate.get("bead") == EXPECTED_BEAD, "source gate bead mismatch")
    require(source_gate.get("manifest_id") == contract.get("expected_manifest_id"), "source gate manifest_id drift")
    require(
        source_gate.get("owner_family_group") == contract.get("owner_family_group"),
        "source gate owner family drift",
    )
    require(
        source_gate.get("source_commit_freshness_policy") == contract.get("source_commit_freshness_policy"),
        "source commit freshness policy drift",
    )

    rows = source_gate.get("rows")
    if not isinstance(rows, list):
        err("source gate rows must be a list")
        rows = []
    gap_ids = [row.get("gap_id") for row in rows if isinstance(row, dict)]
    require(gap_ids == contract.get("expected_gap_ids"), "source gate gap ID drift")
    require(len(rows) == contract.get("expected_gap_count"), "source gate row count drift")
    for row in rows:
        if not isinstance(row, dict):
            err("source gate row must be an object")
            continue
        anchors = row.get("evidence_anchors")
        require(isinstance(anchors, list) and len(anchors) > 0, f"{row.get('gap_id')}: missing evidence anchors")

    required_log_fields = source_gate.get("required_log_fields")
    require(
        isinstance(required_log_fields, list)
        and len(required_log_fields) == contract.get("expected_required_log_field_count"),
        "source gate required_log_fields drift",
    )
    inputs = source_gate.get("inputs")
    require(
        isinstance(inputs, dict) and len(inputs) == contract.get("expected_input_artifact_count"),
        "source gate input artifact count drift",
    )
    if isinstance(inputs, dict):
        for key, value in inputs.items():
            if isinstance(value, str):
                path = (ROOT / value.rstrip("/")).resolve()
                if ROOT not in path.parents and path != ROOT:
                    err(f"source gate input {key} escapes workspace")
                require(path.exists(), f"source gate input path missing: {key}:{value}")
            else:
                err(f"source gate input {key} must be a string")

    policy = source_gate.get("claim_policy", {})
    expected_policy = contract.get("claim_policy", {})
    if isinstance(policy, dict) and isinstance(expected_policy, dict):
        require(
            policy.get("default_decision") == expected_policy.get("default_decision"),
            "claim policy default_decision drift",
        )
        require(
            expected_policy.get("blocked_done_status") in policy.get("block_status_without_all_anchors", []),
            "claim policy DONE block drift",
        )
        for level in expected_policy.get("blocked_replacement_levels", []):
            require(
                level in policy.get("block_replacement_levels_without_evidence", []),
                f"claim policy replacement-level block drift: {level}",
            )
        require(
            policy.get("missing_or_stale_result") == expected_policy.get("missing_or_stale_result"),
            "claim policy stale-result drift",
        )
    else:
        err("claim_policy must be an object")

    markers = contract.get("required_source_markers")
    if not isinstance(markers, dict):
        err("required_source_markers must be an object")
    else:
        for key, expected_markers in markers.items():
            if key not in paths:
                err(f"marker artifact key not reserved: {key}")
                continue
            text = read_text(paths[key], key)
            for marker in string_list(expected_markers, f"required_source_markers.{key}"):
                require(marker in text, f"{key} missing source marker: {marker}")

    append_event(
        "fpg_ported_surface_completion.source_gate_contract",
        "fail" if errors else "pass",
        {
            "gap_count": len(rows),
            "input_count": len(inputs) if isinstance(inputs, dict) else 0,
            "required_log_field_count": len(required_log_fields) if isinstance(required_log_fields, list) else 0,
        },
    )
    return {
        "gap_count": len(rows),
        "gap_ids": gap_ids,
        "input_count": len(inputs) if isinstance(inputs, dict) else 0,
        "required_log_field_count": len(required_log_fields) if isinstance(required_log_fields, list) else 0,
    }


manifest = load_json(CONTRACT_PATH, "contract")
if isinstance(manifest, dict):
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "contract schema_version mismatch")
    require(manifest.get("bead") == EXPECTED_BEAD, "contract bead mismatch")
    require(
        manifest.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD,
        "contract completion_debt_bead mismatch",
    )
    completion_debt = manifest.get("completion_debt", {})
    require(
        isinstance(completion_debt, dict)
        and completion_debt.get("missing_items_closed") == EXPECTED_MISSING_ITEMS,
        "missing_items_closed must close unit, integration, and conformance primary items",
    )

paths = validate_source_artifacts(manifest if isinstance(manifest, dict) else {})
if isinstance(manifest, dict) and len(paths) == len(EXPECTED_SOURCE_KEYS):
    refs = validate_completion_evidence(manifest, paths)
    source_summary = validate_source_gate_contract(manifest, paths)
else:
    refs = {"unit": [], "integration": [], "conformance": []}
    source_summary = {}

status = "fail" if errors else "pass"
report = {
    "schema_version": "fpg_ported_surface_completion_contract.report.v1",
    "status": status,
    "bead": EXPECTED_COMPLETION_BEAD,
    "source_bead": EXPECTED_BEAD,
    "contract": rel(CONTRACT_PATH),
    "contract_sha256": sha256_file(CONTRACT_PATH),
    "source_gate_summary": source_summary,
    "unit_bindings": refs["unit"],
    "integration_bindings": refs["integration"],
    "conformance_bindings": refs["conformance"],
    "events": events,
    "errors": errors,
}

REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG_PATH.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

if errors:
    print(
        "FAIL fpg ported-surface completion contract: "
        + "; ".join(errors[:8]),
        file=sys.stderr,
    )
    sys.exit(1)

print(
    "PASS fpg ported-surface completion contract "
    f"gaps={source_summary.get('gap_count', 0)} unit={len(refs['unit'])} "
    f"integration={len(refs['integration'])} conformance={len(refs['conformance'])}"
)
PY
