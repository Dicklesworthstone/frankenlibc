#!/usr/bin/env bash
# check_rtld_phase1_completion_contract.sh - bd-1j4.2.1 completion evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RTLD_PHASE1_CONTRACT:-${ROOT}/tests/conformance/rtld_phase1_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_RTLD_PHASE1_REPORT:-${ROOT}/target/conformance/rtld_phase1_completion_contract.report.json}"
LOG="${FRANKENLIBC_RTLD_PHASE1_LOG:-${ROOT}/target/conformance/rtld_phase1_completion_contract.log.jsonl}"
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

ORIGINAL_BEAD = "bd-1j4.2"
COMPLETION_DEBT_BEAD = "bd-1j4.2.1"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "rtld_phase1.source_ref",
    "rtld_phase1.missing_item_bound",
    "rtld_phase1.fuzz_corpus_bound",
    "rtld_phase1.elf_loader_case_bound",
    "rtld_phase1.loader_audit_bound",
    "rtld_phase1.completion_contract_validated",
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
    "conformance_test_ref_count",
    "elf_loader_case_count",
    "loader_audit_row_count",
    "fuzz_corpus_seed_count",
    "failure_signature",
}


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
        "trace_id": f"{COMPLETION_DEBT_BEAD}:rtld-phase1",
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
        rows.append(row("rtld_phase1.source_ref", artifact_id=artifact_id, path=path_value))

    for ref in require_list(evidence.get("implementation_refs"), "implementation_refs", errors):
        validate_line_ref(ref, "implementation_refs", errors)

    needles = require_dict(evidence.get("source_needles"), "source_needles", errors)
    for artifact_id, required_needles in needles.items():
        text = texts.get(artifact_id, "")
        for needle in require_string_list(required_needles, f"source_needles.{artifact_id}", errors):
            if needle not in text:
                errors.append(f"{artifact_id} missing required needle {needle!r}")
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
            rows.append(row("rtld_phase1.missing_item_bound", item_id=item_id, section=section))
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


def validate_required_artifacts(section: dict[str, Any], paths: dict[str, Path], label: str, errors: list[str]) -> int:
    count = 0
    for artifact_id in require_string_list(section.get("required_artifacts"), f"{label}.required_artifacts", errors):
        if artifact_id not in paths:
            errors.append(f"{label} references unknown artifact {artifact_id}")
        elif not paths[artifact_id].exists():
            errors.append(f"{label} artifact {artifact_id} does not exist")
        else:
            count += 1
    return count


def validate_fuzz(
    evidence: dict[str, Any],
    paths: dict[str, Path],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> int:
    fuzz = require_dict(evidence.get("fuzz_primary"), "fuzz_primary", errors)
    commands = require_string_list(fuzz.get("commands"), "fuzz_primary.commands", errors)
    if not any("fuzz_elf_loader" in command for command in commands):
        errors.append("fuzz_primary.commands must include fuzz_elf_loader")
    requirements = require_list(fuzz.get("corpus_requirements"), "fuzz_primary.corpus_requirements", errors)
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
            errors.append(
                f"fuzz corpus {artifact_id} has {seed_count} seeds, needs at least {min_seed_files}"
            )
        seen.add(artifact_id)
        total += seed_count
        rows.append(
            row(
                "rtld_phase1.fuzz_corpus_bound",
                artifact_id=artifact_id,
                seed_count=seed_count,
                min_seed_files=min_seed_files,
            )
        )
    if seen != {"fuzz_elf_loader_corpus"}:
        errors.append(f"fuzz corpus requirements must bind fuzz_elf_loader_corpus, got {sorted(seen)}")
    return total


def validate_conformance(
    evidence: dict[str, Any],
    paths: dict[str, Path],
    texts: dict[str, str],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> tuple[int, int, int]:
    conformance = require_dict(evidence.get("conformance_primary"), "conformance_primary", errors)
    fixture_id = conformance.get("elf_loader_fixture")
    audit_id = conformance.get("loader_audit_manifest")
    if not isinstance(fixture_id, str) or fixture_id not in paths:
        errors.append("conformance_primary.elf_loader_fixture must reference a known artifact")
        return 0, 0, 0
    if not isinstance(audit_id, str) or audit_id not in paths:
        errors.append("conformance_primary.loader_audit_manifest must reference a known artifact")
        return 0, 0, 0

    fixture = load_json(paths[fixture_id], "elf_loader fixture", errors)
    cases = fixture.get("cases")
    binaries = fixture.get("binary_fixtures")
    if not isinstance(cases, list):
        errors.append("elf_loader fixture cases must be an array")
        cases = []
    if not isinstance(binaries, list):
        errors.append("elf_loader fixture binary_fixtures must be an array")
        binaries = []
    min_cases = conformance.get("min_elf_loader_cases")
    min_binaries = conformance.get("min_binary_fixtures")
    if not isinstance(min_cases, int) or len(cases) < min_cases:
        errors.append(f"elf_loader fixture needs at least {min_cases} cases, got {len(cases)}")
    if not isinstance(min_binaries, int) or len(binaries) < min_binaries:
        errors.append(f"elf_loader fixture needs at least {min_binaries} binary fixtures, got {len(binaries)}")
    case_by_name = {
        case.get("name"): case for case in cases if isinstance(case, dict) and isinstance(case.get("name"), str)
    }
    for case_name in require_string_list(
        conformance.get("required_elf_loader_cases"),
        "conformance_primary.required_elf_loader_cases",
        errors,
    ):
        if case_name not in case_by_name:
            errors.append(f"elf_loader case missing from fixture: {case_name}")
        else:
            rows.append(row("rtld_phase1.elf_loader_case_bound", case_name=case_name))

    audit = load_json(paths[audit_id], "loader audit manifest", errors)
    audit_rows = audit.get("fixture_rows")
    if not isinstance(audit_rows, list):
        errors.append("loader audit fixture_rows must be an array")
        audit_rows = []
    min_audit_rows = conformance.get("min_loader_audit_rows")
    if not isinstance(min_audit_rows, int) or len(audit_rows) < min_audit_rows:
        errors.append(f"loader audit needs at least {min_audit_rows} rows, got {len(audit_rows)}")
    required_kinds = set(
        require_string_list(
            require_dict(evidence.get("e2e_primary"), "e2e_primary", errors).get("required_fixture_kinds"),
            "e2e_primary.required_fixture_kinds",
            errors,
        )
    )
    actual_kinds = {
        str(row.get("fixture_kind")) for row in audit_rows if isinstance(row, dict) and row.get("fixture_kind")
    }
    missing_kinds = sorted(required_kinds - actual_kinds)
    if missing_kinds:
        errors.append(f"loader audit missing fixture kinds: {missing_kinds}")
    for fixture_kind in sorted(actual_kinds & required_kinds):
        rows.append(row("rtld_phase1.loader_audit_bound", fixture_kind=fixture_kind))

    conformance_ref_count = validate_test_refs(conformance, texts, "conformance_primary", errors)
    if conformance_ref_count < 5:
        errors.append(f"conformance_primary must bind at least 5 test refs, got {conformance_ref_count}")
    return len(cases), len(audit_rows), conformance_ref_count


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

if contract.get("schema_version") != "rtld_phase1_completion_contract.v1":
    errors.append("schema_version must be rtld_phase1_completion_contract.v1")
if contract.get("bead") != ORIGINAL_BEAD:
    errors.append(f"bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")

evidence = require_dict(contract.get("completion_debt_evidence"), "completion_debt_evidence", errors)
texts, paths = validate_artifacts(evidence, errors, rows)
missing_items = validate_missing_bindings(evidence, errors, rows)

unit = require_dict(evidence.get("unit_primary"), "unit_primary", errors)
unit_ref_count = validate_test_refs(unit, texts, "unit_primary", errors)
if unit_ref_count < 8:
    errors.append(f"unit_primary must bind at least 8 unit refs, got {unit_ref_count}")

e2e = require_dict(evidence.get("e2e_primary"), "e2e_primary", errors)
e2e_artifact_count = validate_required_artifacts(e2e, paths, "e2e_primary", errors)
e2e_commands = require_string_list(e2e.get("commands"), "e2e_primary.commands", errors)
if not any("check_loader_dlfcn_relocation_tls_audit.sh" in command for command in e2e_commands):
    errors.append("e2e_primary.commands must include loader/dlfcn audit gate")

fuzz_seed_count = validate_fuzz(evidence, paths, errors, rows)
elf_loader_case_count, loader_audit_row_count, conformance_ref_count = validate_conformance(
    evidence, paths, texts, errors, rows
)
validate_telemetry(evidence, errors)

status = "fail" if errors else "pass"
failure_signature = "rtld_phase1_completion_contract_failed" if errors else "none"
report = {
    "schema_version": "rtld_phase1_completion_contract.report.v1",
    "timestamp": utc_now(),
    "trace_id": f"{COMPLETION_DEBT_BEAD}:rtld-phase1",
    "event": "rtld_phase1.completion_contract_validated" if not errors else "rtld_phase1.completion_contract_failed",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "missing_items": missing_items,
    "artifact_refs": sorted(str(path.relative_to(root)) for path in paths.values() if path.exists()),
    "unit_test_ref_count": unit_ref_count,
    "e2e_artifact_count": e2e_artifact_count,
    "conformance_test_ref_count": conformance_ref_count,
    "elf_loader_case_count": elf_loader_case_count,
    "loader_audit_row_count": loader_audit_row_count,
    "fuzz_corpus_seed_count": fuzz_seed_count,
    "failure_signature": failure_signature,
    "errors": errors,
}

rows.append(row(report["event"], status=status, failure_signature=failure_signature))
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("\n".join(json.dumps(item, sort_keys=True) for item in rows) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: RTLD phase-1 completion contract errors={len(errors)}", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: RTLD phase-1 completion contract "
    f"unit_refs={unit_ref_count} elf_loader_cases={elf_loader_case_count} "
    f"loader_audit_rows={loader_audit_row_count} fuzz_seeds={fuzz_seed_count} "
    f"conformance_refs={conformance_ref_count}"
)
PY
