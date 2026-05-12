#!/usr/bin/env bash
# check_hard_parts_completion_contract.sh - bd-1j4.5.1 completion evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_HARD_PARTS_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/hard_parts_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_HARD_PARTS_COMPLETION_REPORT:-${ROOT}/target/conformance/hard_parts_completion_contract.report.json}"
LOG="${FRANKENLIBC_HARD_PARTS_COMPLETION_LOG:-${ROOT}/target/conformance/hard_parts_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
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
source_commit = sys.argv[5]

ORIGINAL_BEAD = "bd-1j4.5"
COMPLETION_DEBT_BEAD = "bd-1j4.5.1"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "hard_parts_completion.source_ref",
    "hard_parts_completion.missing_item_bound",
    "hard_parts_completion.component_contract_bound",
    "hard_parts_completion.fuzz_corpus_bound",
    "hard_parts_completion.conformance_artifact_bound",
    "hard_parts_completion.completion_contract_validated",
}
REQUIRED_REPORT_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "missing_items",
    "artifact_refs",
    "unit_test_ref_count",
    "e2e_artifact_count",
    "fuzz_corpus_seed_count",
    "conformance_test_ref_count",
    "conformance_artifact_count",
    "component_contract_count",
    "failure_signature",
}
COMPONENT_CONTRACTS = {
    "startup_completion_contract": ("l1_crt_startup_tls_completion_contract.v1", "bd-bp8fl.6.3.1"),
    "rtld_completion_contract": ("rtld_phase1_completion_contract.v1", "bd-1j4.2.1"),
    "resolver_completion_contract": ("resolver_nss_hardening_completion_contract.v1", "bd-1j4.3.1"),
    "locale_completion_contract": ("locale_iconv_completion_contract.v1", "bd-1j4.4.1"),
}
REQUIRED_SUBSYSTEMS = {"startup", "threading", "resolver", "nss", "locale", "iconv"}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def workspace_path(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def require_dict(value: Any, label: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return {}
    return value


def require_list(value: Any, label: str, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{label} must be an array")
        return []
    return value


def require_string_list(value: Any, label: str, errors: list[str]) -> list[str]:
    items = require_list(value, label, errors)
    result: list[str] = []
    for index, item in enumerate(items):
        if isinstance(item, str) and item:
            result.append(item)
        else:
            errors.append(f"{label}[{index}] must be a non-empty string")
    return result


def load_json(path: Path, label: str, errors: list[str]) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(data, dict):
        errors.append(f"{label} must be a JSON object")
        return {}
    return data


def row(event: str, status: str = "pass", **fields: Any) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{COMPLETION_DEBT_BEAD}:hard-parts-completion",
        "event": event,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "status": status,
        **fields,
    }


def validate_line_ref(ref: Any, label: str, errors: list[str]) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"{label} must be file:line")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{label} has invalid line number: {ref}")
        return
    path = workspace_path(path_text)
    if not path.is_file():
        errors.append(f"{label} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        errors.append(f"{label} references line past EOF: {ref}")
    elif not lines[line_number - 1].strip():
        errors.append(f"{label} references blank line: {ref}")


def validate_artifacts(
    evidence: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> tuple[dict[str, str], dict[str, Path]]:
    artifacts = require_dict(evidence.get("artifacts"), "completion_debt_evidence.artifacts", errors)
    directory_artifacts = set(
        require_string_list(evidence.get("directory_artifacts"), "directory_artifacts", errors)
    )
    texts: dict[str, str] = {}
    paths: dict[str, Path] = {}
    for artifact_id, path_value in artifacts.items():
        if not isinstance(path_value, str) or not path_value:
            errors.append(f"artifact {artifact_id} path must be a non-empty string")
            continue
        path = workspace_path(path_value)
        paths[artifact_id] = path
        if artifact_id in directory_artifacts:
            if not path.is_dir():
                errors.append(f"artifact {artifact_id} missing directory: {path_value}")
                continue
        else:
            if not path.is_file():
                errors.append(f"artifact {artifact_id} missing file: {path_value}")
                continue
            try:
                texts[artifact_id] = path.read_text(encoding="utf-8")
            except Exception as exc:
                errors.append(f"artifact {artifact_id} unreadable: {path_value}: {exc}")
                continue
        rows.append(row("hard_parts_completion.source_ref", artifact_id=artifact_id, path=path_value))

    for ref in require_list(evidence.get("implementation_refs"), "implementation_refs", errors):
        validate_line_ref(ref, "implementation_refs", errors)
    return texts, paths


def validate_missing_bindings(
    evidence: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> list[str]:
    bindings = require_list(evidence.get("missing_item_bindings"), "missing_item_bindings", errors)
    actual: set[str] = set()
    sections: set[str] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            errors.append(f"missing_item_bindings[{index}] must be an object")
            continue
        item_id = binding.get("missing_item_id")
        section = binding.get("evidence_section")
        if isinstance(item_id, str):
            actual.add(item_id)
        else:
            errors.append(f"missing_item_bindings[{index}].missing_item_id missing")
        if isinstance(section, str):
            sections.add(section)
        else:
            errors.append(f"missing_item_bindings[{index}].evidence_section missing")
        if isinstance(item_id, str) and isinstance(section, str):
            rows.append(row("hard_parts_completion.missing_item_bound", item_id=item_id, section=section))
    if actual != REQUIRED_MISSING_ITEMS:
        errors.append(f"missing items must be {sorted(REQUIRED_MISSING_ITEMS)}, got {sorted(actual)}")
    for required_section in [
        "unit_primary",
        "e2e_primary",
        "fuzz_primary",
        "conformance_primary",
        "telemetry_primary",
    ]:
        if required_section not in sections or not isinstance(evidence.get(required_section), dict):
            errors.append(f"{required_section} must be bound and present")
    return sorted(actual)


def validate_test_refs(section: dict[str, Any], texts: dict[str, str], label: str, errors: list[str]) -> int:
    count = 0
    for index, ref in enumerate(require_list(section.get("required_test_refs"), f"{label}.required_test_refs", errors)):
        if not isinstance(ref, dict):
            errors.append(f"{label}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not isinstance(name, str):
            errors.append(f"{label}.required_test_refs[{index}] source/name missing")
            continue
        if name not in texts.get(source, ""):
            errors.append(f"{label} test ref {name!r} missing from source {source}")
        count += 1
    return count


def validate_required_artifacts(
    section: dict[str, Any],
    paths: dict[str, Path],
    label: str,
    errors: list[str],
    rows: list[dict[str, Any]] | None = None,
) -> int:
    count = 0
    for artifact_id in require_string_list(section.get("required_artifacts"), f"{label}.required_artifacts", errors):
        if artifact_id not in paths:
            errors.append(f"{label} references unknown artifact {artifact_id}")
        elif not paths[artifact_id].exists():
            errors.append(f"{label} artifact {artifact_id} does not exist")
        else:
            count += 1
            if rows is not None:
                rows.append(row("hard_parts_completion.conformance_artifact_bound", artifact_id=artifact_id))
    return count


def validate_commands(section: dict[str, Any], label: str, errors: list[str]) -> list[str]:
    commands = require_string_list(section.get("commands"), f"{label}.commands", errors)
    for command in commands:
        if (
            "cargo " in command
            and not command.startswith("rch exec --")
            and not command.startswith("cargo fuzz run ")
        ):
            errors.append(f"{label} cargo command must use rch: {command}")
    return commands


def validate_component_contracts(paths: dict[str, Path], errors: list[str], rows: list[dict[str, Any]]) -> int:
    count = 0
    for artifact_id, (schema, completion_bead) in COMPONENT_CONTRACTS.items():
        doc = load_json(paths[artifact_id], artifact_id, errors)
        if doc.get("schema_version") != schema:
            errors.append(f"{artifact_id} schema_version must be {schema}")
        actual_completion_bead = doc.get("completion_debt_bead")
        if not actual_completion_bead:
            actual_completion_bead = doc.get("completion_debt_evidence", {}).get("bead")
        if actual_completion_bead != completion_bead:
            errors.append(f"{artifact_id} completion_debt_bead must be {completion_bead}")
        rows.append(row("hard_parts_completion.component_contract_bound", artifact_id=artifact_id, completion_bead=completion_bead))
        count += 1
    return count


def validate_fuzz(
    evidence: dict[str, Any],
    paths: dict[str, Path],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> int:
    fuzz = require_dict(evidence.get("fuzz_primary"), "fuzz_primary", errors)
    commands = validate_commands(fuzz, "fuzz_primary", errors)
    for target in [
        "fuzz_elf_loader",
        "fuzz_resolv",
        "fuzz_resolver",
        "fuzz_locale",
        "fuzz_iconv",
        "fuzz_signal",
        "fuzz_setjmp",
    ]:
        if not any(target in command for command in commands):
            errors.append(f"fuzz_primary.commands must include {target}")
    requirements = require_list(fuzz.get("corpus_requirements"), "fuzz_primary.corpus_requirements", errors)
    expected = {
        "fuzz_elf_loader_corpus",
        "fuzz_resolv_corpus",
        "fuzz_resolver_corpus",
        "fuzz_locale_corpus",
        "fuzz_iconv_corpus",
        "fuzz_signal_corpus",
        "fuzz_setjmp_corpus",
    }
    seen: set[str] = set()
    total = 0
    for index, requirement in enumerate(requirements):
        if not isinstance(requirement, dict):
            errors.append(f"fuzz_primary.corpus_requirements[{index}] must be an object")
            continue
        artifact_id = requirement.get("artifact")
        min_seed_files = requirement.get("min_seed_files")
        if not isinstance(artifact_id, str) or artifact_id not in paths:
            errors.append(f"fuzz corpus requirements reference unknown artifact {artifact_id!r}")
            continue
        if not isinstance(min_seed_files, int) or min_seed_files <= 0:
            errors.append(f"fuzz corpus requirement {artifact_id} has invalid min_seed_files")
            continue
        seed_count = sum(1 for child in paths[artifact_id].iterdir() if child.is_file())
        if seed_count < min_seed_files:
            errors.append(f"fuzz corpus {artifact_id} has {seed_count} seeds, needs at least {min_seed_files}")
        seen.add(artifact_id)
        total += seed_count
        rows.append(row("hard_parts_completion.fuzz_corpus_bound", artifact_id=artifact_id, seed_count=seed_count))
    if seen != expected:
        errors.append(f"fuzz corpus requirements must bind {sorted(expected)}, got {sorted(seen)}")
    return total


def validate_hard_parts_conformance(
    conformance: dict[str, Any], paths: dict[str, Path], errors: list[str]
) -> None:
    required_subsystems = set(
        require_string_list(conformance.get("required_subsystems"), "conformance_primary.required_subsystems", errors)
    )
    if required_subsystems != REQUIRED_SUBSYSTEMS:
        errors.append(f"required subsystems must be {sorted(REQUIRED_SUBSYSTEMS)}, got {sorted(required_subsystems)}")
    required_classes = set(
        require_string_list(conformance.get("required_failure_classes"), "conformance_primary.required_failure_classes", errors)
    )
    required_families = set(
        require_string_list(conformance.get("required_replay_families"), "conformance_primary.required_replay_families", errors)
    )

    catalog = load_json(paths["hard_parts_e2e_catalog"], "hard_parts e2e catalog", errors)
    scenarios = require_list(catalog.get("scenarios"), "hard_parts_e2e_catalog.scenarios", errors)
    if len(scenarios) < 6:
        errors.append(f"hard parts e2e catalog must contain at least 6 scenarios, got {len(scenarios)}")
    summary_subsystems = set(catalog.get("summary", {}).get("required_subsystems", []))
    covered_subsystems = {
        subsystem
        for scenario in scenarios
        if isinstance(scenario, dict)
        for subsystem in scenario.get("subsystems", [])
    }
    if not required_subsystems.issubset(summary_subsystems | covered_subsystems):
        errors.append(f"hard parts catalog missing subsystems {sorted(required_subsystems - (summary_subsystems | covered_subsystems))}")

    matrix = load_json(paths["hard_parts_e2e_failure_matrix"], "hard parts e2e failure matrix", errors)
    class_ids = {
        row.get("id")
        for row in require_list(matrix.get("classes"), "hard_parts_e2e_failure_matrix.classes", errors)
        if isinstance(row, dict)
    }
    if not required_classes.issubset(class_ids):
        errors.append(f"hard parts failure matrix missing classes {sorted(required_classes - class_ids)}")

    truth = load_json(paths["hard_parts_truth_table"], "hard parts truth table", errors)
    truth_subsystems = {
        row.get("id")
        for row in require_list(truth.get("subsystems"), "hard_parts_truth_table.subsystems", errors)
        if isinstance(row, dict)
    }
    if not required_subsystems.issubset(truth_subsystems):
        errors.append(f"hard parts truth table missing subsystems {sorted(required_subsystems - truth_subsystems)}")
    if truth.get("summary", {}).get("contradiction_count") != 0:
        errors.append("hard parts truth table contradiction_count must be 0")

    deps = load_json(paths["hard_parts_dependency_matrix"], "hard parts dependency matrix", errors)
    dep_subsystems = set(require_string_list(deps.get("subsystems"), "hard_parts_dependency_matrix.subsystems", errors))
    if not required_subsystems.issubset(dep_subsystems):
        errors.append(f"hard parts dependency matrix missing subsystems {sorted(required_subsystems - dep_subsystems)}")
    if len(require_list(deps.get("dependency_matrix"), "hard_parts_dependency_matrix.dependency_matrix", errors)) < 8:
        errors.append("hard parts dependency matrix must contain at least 8 edges")

    replay = load_json(paths["hard_parts_failure_replay_manifest"], "hard parts failure replay manifest", errors)
    families = {
        row.get("failure_family")
        for row in require_list(replay.get("scenarios"), "hard_parts_failure_replay_manifest.scenarios", errors)
        if isinstance(row, dict)
    }
    if not required_families.issubset(families):
        errors.append(f"hard parts replay manifest missing families {sorted(required_families - families)}")


def validate_telemetry(evidence: dict[str, Any], errors: list[str]) -> None:
    telemetry = require_dict(evidence.get("telemetry_primary"), "telemetry_primary", errors)
    events = set(require_string_list(telemetry.get("required_events"), "telemetry_primary.required_events", errors))
    if not REQUIRED_EVENTS.issubset(events):
        errors.append(f"telemetry events missing {sorted(REQUIRED_EVENTS - events)}")
    fields = set(require_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields", errors))
    if not REQUIRED_REPORT_FIELDS.issubset(fields):
        errors.append(f"telemetry fields missing {sorted(REQUIRED_REPORT_FIELDS - fields)}")


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, "completion contract", errors)

if contract.get("schema_version") != "hard_parts_completion_contract.v1":
    errors.append("schema_version must be hard_parts_completion_contract.v1")
if contract.get("bead") != ORIGINAL_BEAD:
    errors.append(f"bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")

evidence = require_dict(contract.get("completion_debt_evidence"), "completion_debt_evidence", errors)
texts, paths = validate_artifacts(evidence, errors, rows)
missing_items = validate_missing_bindings(evidence, errors, rows)
component_contract_count = validate_component_contracts(paths, errors, rows)

unit = require_dict(evidence.get("unit_primary"), "unit_primary", errors)
validate_commands(unit, "unit_primary", errors)
unit_ref_count = validate_test_refs(unit, texts, "unit_primary", errors)
if unit_ref_count < 6:
    errors.append(f"unit_primary must bind at least 6 refs, got {unit_ref_count}")

e2e = require_dict(evidence.get("e2e_primary"), "e2e_primary", errors)
e2e_commands = validate_commands(e2e, "e2e_primary", errors)
if not any("check_hard_parts_e2e.sh" in command for command in e2e_commands):
    errors.append("e2e_primary.commands must include check_hard_parts_e2e.sh")
e2e_artifact_count = validate_required_artifacts(e2e, paths, "e2e_primary", errors)
validate_test_refs(e2e, texts, "e2e_primary", errors)

fuzz_seed_count = validate_fuzz(evidence, paths, errors, rows)

conformance = require_dict(evidence.get("conformance_primary"), "conformance_primary", errors)
validate_commands(conformance, "conformance_primary", errors)
conformance_artifact_count = validate_required_artifacts(conformance, paths, "conformance_primary", errors, rows)
conformance_ref_count = validate_test_refs(conformance, texts, "conformance_primary", errors)
if conformance_ref_count < 5:
    errors.append(f"conformance_primary must bind at least 5 refs, got {conformance_ref_count}")
validate_hard_parts_conformance(conformance, paths, errors)

validate_telemetry(evidence, errors)

status = "fail" if errors else "pass"
failure_signature = "hard_parts_completion_contract_failed" if errors else "none"
report = {
    "schema_version": "hard_parts_completion_contract.report.v1",
    "timestamp": utc_now(),
    "trace_id": f"{COMPLETION_DEBT_BEAD}:hard-parts-completion",
    "event": "hard_parts_completion.completion_contract_validated" if not errors else "hard_parts_completion.completion_contract_failed",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "missing_items": missing_items,
    "artifact_refs": sorted(str(path.relative_to(root)) for path in paths.values() if path.exists()),
    "unit_test_ref_count": unit_ref_count,
    "e2e_artifact_count": e2e_artifact_count,
    "fuzz_corpus_seed_count": fuzz_seed_count,
    "conformance_test_ref_count": conformance_ref_count,
    "conformance_artifact_count": conformance_artifact_count,
    "component_contract_count": component_contract_count,
    "failure_signature": failure_signature,
    "errors": errors,
}

rows.append(row(report["event"], status=status, failure_signature=failure_signature))
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("\n".join(json.dumps(item, sort_keys=True) for item in rows) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: hard-parts completion contract errors={len(errors)}", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: hard-parts completion contract "
    f"unit_refs={unit_ref_count} e2e_artifacts={e2e_artifact_count} "
    f"fuzz_seeds={fuzz_seed_count} conformance_refs={conformance_ref_count} "
    f"component_contracts={component_contract_count}"
)
PY
