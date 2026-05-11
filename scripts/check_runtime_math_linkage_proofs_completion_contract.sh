#!/usr/bin/env bash
# Validate bd-7dw2.1 runtime_math linkage proof completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${1:-${ROOT}/tests/conformance/runtime_math_linkage_proofs_completion_contract.v1.json}"
OUT_DIR="${2:-${ROOT}/target/conformance}"
REPORT_PATH="${OUT_DIR}/runtime_math_linkage_proofs_completion_contract.report.json"
LOG_PATH="${OUT_DIR}/runtime_math_linkage_proofs_completion_contract.log.jsonl"

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

EXPECTED_SCHEMA = "runtime_math_linkage_proofs_completion_contract.v1"
EXPECTED_BEAD = "bd-7dw2"
EXPECTED_COMPLETION_BEAD = "bd-7dw2.1"
EXPECTED_MISSING_ITEMS = ["tests.integration.primary"]
REQUIRED_SOURCE_KEYS = {
    "production_manifest",
    "linkage_ledger",
    "required_module_gate",
    "linkage_proofs_impl",
    "linkage_proofs_script",
    "linkage_proofs_test",
    "harness_cli",
    "ci_script",
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


def sha256_file(path: pathlib.Path) -> str:
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
            "schema_version": "runtime_math_linkage_proofs_completion_contract.log.v1",
            "event": event,
            "status": status,
            "bead": EXPECTED_COMPLETION_BEAD,
            "source_bead": EXPECTED_BEAD,
            "artifact_refs": [
                rel(CONTRACT_PATH),
                rel(REPORT_PATH),
            ],
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
        "runtime_math_linkage_completion.source_artifacts",
        "fail" if errors else "pass",
        {
            "artifact_count": len(paths),
            "keys": sorted(paths),
        },
    )
    return paths


def validate_integration_evidence(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> None:
    evidence = manifest.get("completion_debt_evidence", {}).get("integration_primary", {})
    if not isinstance(evidence, dict):
        err("completion_debt_evidence.integration_primary must be an object")
        return

    refs = evidence.get("required_test_refs")
    if not isinstance(refs, list):
        err("integration_primary.required_test_refs must be a list")
        refs = []
    names = {
        ref.get("name")
        for ref in refs
        if isinstance(ref, dict) and isinstance(ref.get("name"), str)
    }
    required_names = {"gate_script_exists_and_executable", "gate_script_emits_logs_and_report"}
    require(names == required_names, f"integration test refs mismatch: got {sorted(names)}")

    commands = string_list(evidence.get("required_commands"), "integration_primary.required_commands")
    for command in commands:
        if "cargo " in command:
            require(
                command.startswith("rch exec --"),
                f"non-rch cargo validation command: {command}",
            )
    require(
        "rch exec -- scripts/check_runtime_math_linkage_proofs.sh" in commands,
        "integration command must include rch-wrapped linkage proof script",
    )
    require(
        evidence.get("expected_log") == "target/conformance/runtime_math_linkage_proofs.log.jsonl",
        "integration expected_log drift",
    )
    require(
        evidence.get("expected_report")
        == "target/conformance/runtime_math_linkage_proofs.report.json",
        "integration expected_report drift",
    )

    test_text = read_text(paths["linkage_proofs_test"], "linkage_proofs_test") if "linkage_proofs_test" in paths else ""
    for name in required_names:
        require(name in test_text, f"linkage_proofs_test missing test ref: {name}")

    append_event(
        "runtime_math_linkage_completion.integration_evidence",
        "fail" if errors else "pass",
        {
            "test_refs": sorted(names),
            "command_count": len(commands),
        },
    )


def validate_linkage_contract(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    contract = manifest.get("required_runtime_math_linkage_proof_contract")
    if not isinstance(contract, dict):
        err("required_runtime_math_linkage_proof_contract must be an object")
        return {}

    require(contract.get("source_bead") == EXPECTED_BEAD, "source_bead mismatch")
    require(
        contract.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD,
        "completion_debt_bead mismatch in proof contract",
    )
    require(contract.get("schema_version") == "v1", "proof report schema drift")
    require(contract.get("gate_id") == "runtime_math_linkage_proofs", "gate_id drift")
    require(
        contract.get("harness_subcommand") == "runtime-math-linkage-proofs",
        "harness subcommand drift",
    )

    production_manifest = load_json(paths["production_manifest"], "production_manifest")
    linkage_ledger = load_json(paths["linkage_ledger"], "linkage_ledger")
    production_modules = string_list(
        production_manifest.get("production_modules"),
        "production_manifest.production_modules",
    )
    research_modules = string_list(
        production_manifest.get("research_only_modules"),
        "production_manifest.research_only_modules",
    )
    require(
        len(production_modules) == contract.get("expected_production_module_count"),
        "production module count drift",
    )
    require(
        len(research_modules) == contract.get("expected_research_module_count"),
        "research module count drift",
    )
    require(
        contract.get("production_manifest_default_feature")
        in production_manifest.get("default_feature_set", []),
        "runtime-math-production default feature missing",
    )
    require(
        contract.get("optional_research_feature") in production_manifest.get("optional_feature_set", []),
        "runtime-math-research optional feature missing",
    )

    modules = linkage_ledger.get("modules")
    if not isinstance(modules, dict):
        err("linkage_ledger.modules must be an object")
        modules = {}
    require(
        len(modules) == contract.get("expected_linkage_module_count"),
        "linkage module count drift",
    )
    for module in production_modules:
        row = modules.get(module)
        if not isinstance(row, dict):
            err(f"linkage ledger missing production module: {module}")
            continue
        require(
            row.get("linkage_status") == contract.get("production_linkage_status"),
            f"production linkage status drift for {module}",
        )
        require(
            isinstance(row.get("decision_target"), str) and bool(row["decision_target"]),
            f"production decision_target missing for {module}",
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

    required_gate = load_json(paths["required_module_gate"], "required_module_gate")
    inventory = required_gate.get("prior_gate_inventory", [])
    linkage_inventory = [
        row
        for row in inventory
        if isinstance(row, dict) and row.get("gate_id") == "runtime_math_linkage_proofs"
    ]
    require(linkage_inventory, "required module gate missing runtime_math_linkage_proofs inventory row")
    if linkage_inventory:
        covers = linkage_inventory[0].get("covers", [])
        require(
            "production module decision-law proof rows" in covers
            and "structured proof logs" in covers,
            "required module gate does not bind proof rows and structured proof logs",
        )

    append_event(
        "runtime_math_linkage_completion.proof_contract",
        "fail" if errors else "pass",
        {
            "production_modules": len(production_modules),
            "research_modules": len(research_modules),
            "linkage_modules": len(modules),
        },
    )
    return {
        "production_modules": production_modules,
        "research_modules": research_modules,
        "linkage_module_count": len(modules),
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
        "missing_items_closed must close only tests.integration.primary",
    )

paths = validate_source_artifacts(manifest if isinstance(manifest, dict) else {})
if isinstance(manifest, dict) and len(paths) == len(REQUIRED_SOURCE_KEYS):
    validate_integration_evidence(manifest, paths)
    linkage_summary = validate_linkage_contract(manifest, paths)
else:
    linkage_summary = {}

status = "fail" if errors else "pass"
report = {
    "schema_version": "runtime_math_linkage_proofs_completion_contract.report.v1",
    "status": status,
    "bead": EXPECTED_COMPLETION_BEAD,
    "source_bead": EXPECTED_BEAD,
    "contract": rel(CONTRACT_PATH),
    "contract_sha256": sha256_file(CONTRACT_PATH) if CONTRACT_PATH.is_file() else None,
    "production_module_count": len(linkage_summary.get("production_modules", [])),
    "research_module_count": len(linkage_summary.get("research_modules", [])),
    "linkage_module_count": linkage_summary.get("linkage_module_count", 0),
    "integration_bindings": manifest.get("completion_debt_evidence", {})
    .get("integration_primary", {})
    .get("required_test_refs", [])
    if isinstance(manifest, dict)
    else [],
    "events": events,
    "errors": errors,
}

REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG_PATH.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

if errors:
    print(
        "FAIL runtime math linkage proof completion contract: "
        + "; ".join(errors[:8]),
        file=sys.stderr,
    )
    sys.exit(1)

print(
    "PASS runtime math linkage proof completion contract "
    f"production={report['production_module_count']} linkage={report['linkage_module_count']}"
)
PY
