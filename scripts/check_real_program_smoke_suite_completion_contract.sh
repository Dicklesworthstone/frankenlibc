#!/usr/bin/env bash
# Validate bd-bp8fl.10.2.1 real-program smoke suite completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${1:-${ROOT}/tests/conformance/real_program_smoke_suite_completion_contract.v1.json}"
OUT_DIR="${2:-${ROOT}/target/conformance}"
REPORT_PATH="${OUT_DIR}/real_program_smoke_suite_completion_contract.report.json"
LOG_PATH="${OUT_DIR}/real_program_smoke_suite_completion_contract.log.jsonl"

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

EXPECTED_SCHEMA = "real_program_smoke_suite_completion_contract.v1"
EXPECTED_BEAD = "bd-bp8fl.10.2"
EXPECTED_COMPLETION_BEAD = "bd-bp8fl.10.2.1"
EXPECTED_MISSING_ITEMS = ["tests.unit.primary", "tests.e2e.primary"]
REQUIRED_SOURCE_KEYS = {
    "smoke_manifest",
    "smoke_checker",
    "smoke_test",
    "vertical_slice",
    "freshness_contract",
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


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": "real_program_smoke_suite_completion_contract.log.v1",
            "event": event,
            "status": status,
            "bead": EXPECTED_COMPLETION_BEAD,
            "source_bead": EXPECTED_BEAD,
            "artifact_refs": [rel(CONTRACT_PATH), rel(REPORT_PATH)],
            "details": details,
        }
    )


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, pathlib.Path]:
    source_artifacts = manifest.get("source_artifacts")
    if not isinstance(source_artifacts, dict):
        err("source_artifacts must be an object")
        return {}
    missing = REQUIRED_SOURCE_KEYS - set(source_artifacts)
    extra = set(source_artifacts) - REQUIRED_SOURCE_KEYS
    require(not missing, f"source_artifacts missing keys: {sorted(missing)}")
    require(not extra, f"source_artifacts unexpected keys: {sorted(extra)}")

    paths: dict[str, pathlib.Path] = {}
    for key in sorted(REQUIRED_SOURCE_KEYS):
        path = artifact_path(source_artifacts.get(key), f"source_artifacts.{key}")
        if path is not None:
            paths[key] = path
    append_event(
        "real_program_smoke_completion.source_artifacts",
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
        require(name in test_text, f"smoke_test missing {section_name} test ref: {name}")

    commands = string_list(section.get("required_commands"), f"{section_name}.required_commands")
    for command in commands:
        if "cargo " in command:
            require(command.startswith("rch exec --"), f"non-rch cargo validation command: {command}")
    return sorted(names)


def validate_completion_evidence(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> dict[str, list[str]]:
    evidence = manifest.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        return {"unit": [], "e2e": []}
    test_text = read_text(paths["smoke_test"], "smoke_test") if "smoke_test" in paths else ""
    unit_names = validate_test_refs(
        evidence.get("unit_primary", {}),
        "unit_primary",
        test_text,
        {
            "manifest_defines_case_schema_and_log_contract",
            "stale_source_commit_policy_blocks_real_program_smoke_evidence",
            "manifest_defines_failure_bundle_schema_and_fixture_classes",
            "cases_cover_required_domains_modes_levels_and_artifact_kinds",
        },
    )
    e2e_names = validate_test_refs(
        evidence.get("e2e_primary", {}),
        "e2e_primary",
        test_text,
        {
            "run_mode_writes_artifacts_and_blocks_claims_without_current_artifacts",
            "validate_only_rejects_stale_recorded_source_commit",
            "current_standalone_artifact_rows_block_host_glibc_dependency",
            "bundle_fixture_mode_covers_required_classes_and_redacts_runner_env",
            "gate_script_exists_and_is_executable",
        },
    )
    append_event(
        "real_program_smoke_completion.test_refs",
        "fail" if errors else "pass",
        {"unit_refs": unit_names, "e2e_refs": e2e_names},
    )
    return {"unit": unit_names, "e2e": e2e_names}


def validate_smoke_contract(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    contract = manifest.get("required_real_program_smoke_contract")
    if not isinstance(contract, dict):
        err("required_real_program_smoke_contract must be an object")
        return {}
    require(contract.get("source_bead") == EXPECTED_BEAD, "source_bead mismatch")
    require(
        contract.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD,
        "completion_debt_bead mismatch in smoke contract",
    )

    smoke = load_json(paths["smoke_manifest"], "smoke_manifest")
    require(smoke.get("bead") == EXPECTED_BEAD, "smoke manifest bead mismatch")
    require(smoke.get("schema_version") == contract.get("schema_version"), "smoke schema drift")
    summary = smoke.get("summary", {})
    if not isinstance(summary, dict):
        err("smoke manifest summary must be an object")
        summary = {}
    summary_expectations = {
        "case_count": "expected_case_count",
        "ld_preload_interpose_case_count": "expected_ld_preload_interpose_case_count",
        "standalone_future_case_count": "expected_standalone_future_case_count",
        "standalone_direct_link_real_program_case_count": "expected_standalone_direct_link_real_program_case_count",
        "strict_case_count": "expected_strict_case_count",
        "hardened_case_count": "expected_hardened_case_count",
        "l0_case_count": "expected_l0_case_count",
        "l1_case_count": "expected_l1_case_count",
        "non_support_claim_policy_rows": "expected_non_support_claim_policy_rows",
        "failure_bundle_schema_fields": "expected_failure_bundle_schema_fields",
        "failure_bundle_fixture_case_count": "expected_failure_bundle_fixture_case_count",
    }
    for summary_key, contract_key in summary_expectations.items():
        require(
            summary.get(summary_key) == contract.get(contract_key),
            f"{summary_key} drift",
        )

    cases = smoke.get("cases")
    if not isinstance(cases, list):
        err("smoke manifest cases must be a list")
        cases = []
    require(len(cases) == contract.get("expected_case_count"), "case count drift")

    required_domains = set(string_list(contract.get("required_domains"), "required_domains"))
    required_modes = set(string_list(contract.get("required_runtime_modes"), "required_runtime_modes"))
    required_levels = set(string_list(contract.get("required_replacement_levels"), "required_replacement_levels"))
    required_case_fields = set(string_list(contract.get("required_case_fields"), "required_case_fields"))
    required_log_fields = set(string_list(contract.get("required_log_fields"), "required_log_fields"))

    manifest_domains = set(string_list(smoke.get("required_domains"), "smoke.required_domains"))
    manifest_modes = set(string_list(smoke.get("required_runtime_modes"), "smoke.required_runtime_modes"))
    manifest_levels = set(string_list(smoke.get("required_replacement_levels"), "smoke.required_replacement_levels"))
    manifest_case_fields = set(string_list(smoke.get("required_case_fields"), "smoke.required_case_fields"))
    manifest_log_fields = set(string_list(smoke.get("required_log_fields"), "smoke.required_log_fields"))
    require(required_domains <= manifest_domains, "required domain coverage drift")
    require(required_modes <= manifest_modes, "required runtime mode coverage drift")
    require(required_levels <= manifest_levels, "required replacement level coverage drift")
    require(required_case_fields <= manifest_case_fields, "required case field drift")
    require(required_log_fields <= manifest_log_fields, "required log field drift")

    case_domains = {case.get("domain") for case in cases if isinstance(case, dict)}
    case_modes = {case.get("runtime_mode") for case in cases if isinstance(case, dict)}
    case_levels = {case.get("replacement_level") for case in cases if isinstance(case, dict)}
    require(required_domains <= case_domains, "case domain coverage drift")
    require(required_modes <= case_modes, "case runtime mode coverage drift")
    require(required_levels <= case_levels, "case replacement level coverage drift")
    for idx, case in enumerate(cases):
        if not isinstance(case, dict):
            err(f"case {idx} must be an object")
            continue
        missing = required_case_fields - set(case)
        require(not missing, f"case {case.get('case_id', idx)} missing fields: {sorted(missing)}")

    require(
        smoke.get("source_commit_freshness_policy") == contract.get("source_commit_freshness_policy"),
        "source commit freshness policy drift",
    )

    source_markers = contract.get("required_source_markers")
    if not isinstance(source_markers, dict):
        err("required_source_markers must be an object")
    else:
        for key, markers in source_markers.items():
            if key not in paths:
                err(f"source marker artifact key not reserved: {key}")
                continue
            text = read_text(paths[key], key)
            for marker in string_list(markers, f"required_source_markers.{key}"):
                require(marker in text, f"{key} missing source marker: {marker}")

    append_event(
        "real_program_smoke_completion.smoke_contract",
        "fail" if errors else "pass",
        {
            "case_count": len(cases),
            "domains": sorted(case_domains),
            "runtime_modes": sorted(case_modes),
            "replacement_levels": sorted(case_levels),
        },
    )
    return {
        "case_count": len(cases),
        "domains": sorted(case_domains),
        "runtime_modes": sorted(case_modes),
        "replacement_levels": sorted(case_levels),
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
        completion_debt.get("missing_items_closed") == EXPECTED_MISSING_ITEMS,
        "missing_items_closed must close unit and e2e primary items",
    )

paths = validate_source_artifacts(manifest if isinstance(manifest, dict) else {})
if isinstance(manifest, dict) and len(paths) == len(REQUIRED_SOURCE_KEYS):
    refs = validate_completion_evidence(manifest, paths)
    smoke_summary = validate_smoke_contract(manifest, paths)
else:
    refs = {"unit": [], "e2e": []}
    smoke_summary = {}

status = "fail" if errors else "pass"
report = {
    "schema_version": "real_program_smoke_suite_completion_contract.report.v1",
    "status": status,
    "bead": EXPECTED_COMPLETION_BEAD,
    "source_bead": EXPECTED_BEAD,
    "contract": rel(CONTRACT_PATH),
    "contract_sha256": sha256_file(CONTRACT_PATH),
    "case_count": smoke_summary.get("case_count", 0),
    "domains": smoke_summary.get("domains", []),
    "runtime_modes": smoke_summary.get("runtime_modes", []),
    "replacement_levels": smoke_summary.get("replacement_levels", []),
    "unit_bindings": refs["unit"],
    "e2e_bindings": refs["e2e"],
    "events": events,
    "errors": errors,
}

REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG_PATH.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

if errors:
    print(
        "FAIL real-program smoke suite completion contract: "
        + "; ".join(errors[:8]),
        file=sys.stderr,
    )
    sys.exit(1)

print(
    "PASS real-program smoke suite completion contract "
    f"cases={report['case_count']} unit={len(report['unit_bindings'])} e2e={len(report['e2e_bindings'])}"
)
PY
