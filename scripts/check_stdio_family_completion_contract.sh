#!/usr/bin/env bash
# Validate bd-ldj.1.1 stdio-family completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${1:-${ROOT}/tests/conformance/stdio_family_completion_contract.v1.json}"
OUT_DIR="${2:-${ROOT}/target/conformance}"
REPORT_PATH="${OUT_DIR}/stdio_family_completion_contract.report.json"
LOG_PATH="${OUT_DIR}/stdio_family_completion_contract.log.jsonl"

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

EXPECTED_SCHEMA = "stdio_family_completion_contract.v1"
EXPECTED_BEAD = "bd-ldj.1"
EXPECTED_COMPLETION_BEAD = "bd-ldj.1.1"
EXPECTED_MISSING_ITEMS = [
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
]
EXPECTED_TARGET_SYMBOLS = [
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "fprintf",
    "fscanf",
    "fseek",
    "fflush",
]
EXPECTED_SOURCE_KEYS = {
    "core_stdio_file",
    "core_printf",
    "core_scanf",
    "abi_stdio",
    "abi_stdio_test",
    "support_matrix",
    "feature_parity",
    "stdio_fixture",
    "scanf_fixture",
    "stdio_invariants",
    "stdio_phase_strategy",
    "stdio_phase_checker",
    "conformance_executor",
    "conformance_fixture_test",
    "stdio_evidence_schema_test",
    "e2e_c_fixture_runner",
    "e2e_stdio_stream_fixture",
    "e2e_stdio_printf_fixture",
    "completion_checker",
    "completion_test",
}
EXPECTED_EVIDENCE_KEYS = {"unit_primary", "e2e_primary", "conformance_primary"}
EXPECTED_UNIT_REFS = {
    ("core_stdio_file", "test_parse_mode_invalid"),
    ("core_stdio_file", "test_stream_offset_tracks_reads_and_writes"),
    ("core_stdio_file", "test_prepare_seek_flushes_pending_writes_and_clears_read_state"),
    ("core_printf", "test_parse_width_precision"),
    ("core_printf", "test_format_float_basic"),
    ("core_scanf", "test_scan_width_limit"),
    ("core_scanf", "test_scan_string_with_width"),
    ("abi_stdio_test", "fopen_fputs_fflush_fclose_round_trip"),
    ("abi_stdio_test", "fwrite_then_fread_round_trip_matches_bytes"),
    ("abi_stdio_test", "fprintf_formats_and_persists_to_stream"),
    ("abi_stdio_test", "isoc99_fscanf_from_file"),
}
EXPECTED_CONFORMANCE_REFS = {
    ("conformance_fixture_test", "stdio_file_ops_fixture_valid_schema"),
    ("conformance_fixture_test", "stdio_file_ops_covers_fopen"),
    ("conformance_fixture_test", "stdio_file_ops_covers_fclose"),
    ("conformance_fixture_test", "stdio_file_ops_covers_fread"),
    ("conformance_fixture_test", "stdio_file_ops_covers_fwrite"),
    ("conformance_fixture_test", "stdio_file_ops_covers_formatted_io"),
    ("conformance_fixture_test", "stdio_file_ops_covers_fseek"),
    ("conformance_fixture_test", "stdio_file_ops_covers_fflush"),
    ("conformance_fixture_test", "stdio_file_ops_fixture_executes_via_isolated_harness"),
    ("conformance_executor", "stdio_file_ops_fixture_cases_match_execute_fixture_case"),
    ("conformance_executor", "scanf_conformance_fixture_cases_match_execute_fixture_case"),
}
EXPECTED_E2E_ARTIFACTS = {
    "e2e_c_fixture_runner",
    "e2e_stdio_stream_fixture",
    "e2e_stdio_printf_fixture",
}
EXPECTED_CONFORMANCE_ARTIFACTS = {
    "stdio_fixture",
    "scanf_fixture",
    "stdio_invariants",
    "stdio_phase_strategy",
    "stdio_phase_checker",
    "support_matrix",
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
            "schema_version": "stdio_family_completion_contract.log.v1",
            "event": event,
            "status": status,
            "outcome": status,
            "bead": EXPECTED_COMPLETION_BEAD,
            "bead_id": EXPECTED_COMPLETION_BEAD,
            "source_bead": EXPECTED_BEAD,
            "trace_id": f"{EXPECTED_COMPLETION_BEAD}::{event}",
            "mode": "strict+hardened",
            "api_family": "stdio",
            "symbol": "stdio-family",
            "decision_path": "completion_contract>source_artifact_validation",
            "healing_action": "none",
            "errno": 0,
            "latency_ns": 0,
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


def validate_rch_commands(section: dict[str, Any], section_name: str) -> None:
    commands = string_list(section.get("required_commands"), f"{section_name}.required_commands")
    for command in commands:
        if "cargo " in command:
            require(command.startswith("rch exec --"), f"non-rch cargo validation command: {command}")


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
        "stdio_family_completion.source_artifacts",
        "fail" if errors else "pass",
        {"artifact_count": len(paths), "keys": sorted(paths)},
    )
    return paths


def validate_refs(section: dict[str, Any], section_name: str, expected: set[tuple[str, str]], paths: dict[str, pathlib.Path]) -> list[str]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list):
        err(f"{section_name}.required_test_refs must be a list")
        refs = []
    got = {
        (ref.get("artifact"), ref.get("name"))
        for ref in refs
        if isinstance(ref, dict) and isinstance(ref.get("artifact"), str) and isinstance(ref.get("name"), str)
    }
    require(got == expected, f"{section_name} test refs mismatch: got {sorted(got)}")
    for artifact, name in expected:
        if artifact not in paths:
            err(f"{section_name} ref artifact not found in source_artifacts: {artifact}")
            continue
        text = read_text(paths[artifact], artifact)
        require(name in text, f"{artifact} missing {section_name} test ref: {name}")
    validate_rch_commands(section, section_name)
    return [name for _, name in sorted(got)]


def validate_artifact_refs(section: dict[str, Any], section_name: str, expected: set[str], paths: dict[str, pathlib.Path]) -> list[str]:
    refs = section.get("required_artifacts")
    if not isinstance(refs, list):
        err(f"{section_name}.required_artifacts must be a list")
        refs = []
    got = [
        ref.get("artifact")
        for ref in refs
        if isinstance(ref, dict) and isinstance(ref.get("artifact"), str)
    ]
    require(set(got) == expected, f"{section_name} artifact refs mismatch: {sorted(got)}")
    for artifact in expected:
        require(artifact in paths, f"{section_name} artifact key not present in source_artifacts: {artifact}")
    validate_rch_commands(section, section_name)
    return sorted(got)


def validate_support_matrix(path: pathlib.Path, contract: dict[str, Any]) -> dict[str, Any]:
    support = load_json(path, "support_matrix")
    symbols = support.get("symbols") if isinstance(support, dict) else []
    if not isinstance(symbols, list):
        err("support_matrix symbols must be a list")
        symbols = []
    expected_symbols = string_list(contract.get("expected_symbols"), "support_matrix.expected_symbols")
    require(expected_symbols == EXPECTED_TARGET_SYMBOLS, "support_matrix expected_symbols drift")
    expected_status = contract.get("expected_status")
    expected_module = contract.get("expected_module")
    rows_by_symbol = {
        row.get("symbol"): row
        for row in symbols
        if isinstance(row, dict) and isinstance(row.get("symbol"), str)
    }
    found: dict[str, dict[str, Any]] = {}
    for symbol in expected_symbols:
        row = rows_by_symbol.get(symbol)
        if not isinstance(row, dict):
            err(f"support_matrix missing target symbol: {symbol}")
            continue
        require(row.get("status") == expected_status, f"support_matrix {symbol} status drift")
        require(row.get("module") == expected_module, f"support_matrix {symbol} module drift")
        found[symbol] = {
            "status": row.get("status"),
            "module": row.get("module"),
        }
    return found


def validate_fixture(path: pathlib.Path, contract: dict[str, Any], label: str) -> dict[str, Any]:
    fixture = load_json(path, label)
    require(fixture.get("family") == contract.get("expected_family"), f"{label} family drift")
    cases = fixture.get("cases")
    if not isinstance(cases, list):
        err(f"{label} cases must be a list")
        cases = []
    min_cases = contract.get("expected_min_cases")
    require(isinstance(min_cases, int) and len(cases) >= min_cases, f"{label} case count below minimum")
    functions = {
        case.get("function")
        for case in cases
        if isinstance(case, dict) and isinstance(case.get("function"), str)
    }
    for function in string_list(contract.get("required_functions"), f"{label}.required_functions"):
        require(function in functions, f"{label} missing required function: {function}")
    modes = {
        case.get("mode")
        for case in cases
        if isinstance(case, dict) and isinstance(case.get("mode"), str)
    }
    for mode in string_list(contract.get("required_modes", []), f"{label}.required_modes"):
        require(mode in modes, f"{label} missing required mode: {mode}")
    return {
        "family": fixture.get("family"),
        "case_count": len(cases),
        "functions": sorted(functions),
        "modes": sorted(modes),
    }


def validate_source_contract(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    contract = manifest.get("required_source_contract")
    if not isinstance(contract, dict):
        err("required_source_contract must be an object")
        return {}

    support_summary = validate_support_matrix(paths["support_matrix"], contract.get("support_matrix", {}))
    stdio_fixture_summary = validate_fixture(paths["stdio_fixture"], contract.get("stdio_fixture", {}), "stdio_fixture")
    scanf_fixture_summary = validate_fixture(paths["scanf_fixture"], contract.get("scanf_fixture", {}), "scanf_fixture")

    e2e_text = read_text(paths["e2e_c_fixture_runner"], "e2e_c_fixture_runner")
    for marker in string_list(contract.get("e2e_checker_markers"), "e2e_checker_markers"):
        require(marker in e2e_text, f"e2e checker missing marker: {marker}")
    for field in string_list(contract.get("required_log_fields"), "required_log_fields"):
        require(field in e2e_text, f"e2e checker missing required log field: {field}")

    markers = contract.get("source_markers")
    if not isinstance(markers, dict):
        err("source_markers must be an object")
    else:
        for artifact, expected_markers in markers.items():
            if artifact not in paths:
                err(f"source_markers references unknown artifact: {artifact}")
                continue
            text = read_text(paths[artifact], artifact)
            for marker in string_list(expected_markers, f"source_markers.{artifact}"):
                require(marker in text, f"{artifact} missing source marker: {marker}")

    append_event(
        "stdio_family_completion.source_contract",
        "fail" if errors else "pass",
        {
            "symbol_count": len(support_summary),
            "stdio_fixture_cases": stdio_fixture_summary.get("case_count"),
            "scanf_fixture_cases": scanf_fixture_summary.get("case_count"),
        },
    )
    return {
        "support_matrix": support_summary,
        "stdio_fixture": stdio_fixture_summary,
        "scanf_fixture": scanf_fixture_summary,
    }


def validate_completion_evidence(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    evidence = manifest.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        return {}
    require(set(evidence) == EXPECTED_EVIDENCE_KEYS, f"completion_debt_evidence keys mismatch: {sorted(evidence)}")

    unit_refs = validate_refs(evidence.get("unit_primary", {}), "unit_primary", EXPECTED_UNIT_REFS, paths)
    e2e_artifacts = validate_artifact_refs(evidence.get("e2e_primary", {}), "e2e_primary", EXPECTED_E2E_ARTIFACTS, paths)
    conformance_refs = validate_refs(
        evidence.get("conformance_primary", {}),
        "conformance_primary",
        EXPECTED_CONFORMANCE_REFS,
        paths,
    )
    conformance_artifacts = validate_artifact_refs(
        evidence.get("conformance_primary", {}),
        "conformance_primary",
        EXPECTED_CONFORMANCE_ARTIFACTS,
        paths,
    )

    append_event(
        "stdio_family_completion.evidence_refs",
        "fail" if errors else "pass",
        {
            "unit_ref_count": len(unit_refs),
            "e2e_artifact_count": len(e2e_artifacts),
            "conformance_ref_count": len(conformance_refs),
            "conformance_artifact_count": len(conformance_artifacts),
        },
    )
    return {
        "unit": unit_refs,
        "e2e": e2e_artifacts,
        "conformance_tests": conformance_refs,
        "conformance_artifacts": conformance_artifacts,
    }


manifest = load_json(CONTRACT_PATH, "contract")
if isinstance(manifest, dict):
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "contract schema_version mismatch")
    require(manifest.get("bead") == EXPECTED_BEAD, "contract bead mismatch")
    require(manifest.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "contract completion_debt_bead mismatch")
    require(manifest.get("target_symbols") == EXPECTED_TARGET_SYMBOLS, "target_symbols drift")
    completion_debt = manifest.get("completion_debt", {})
    require(
        isinstance(completion_debt, dict)
        and completion_debt.get("missing_items_closed") == EXPECTED_MISSING_ITEMS,
        "missing_items_closed must close unit, e2e, and conformance primary items",
    )

paths = validate_source_artifacts(manifest if isinstance(manifest, dict) else {})
if isinstance(manifest, dict) and len(paths) == len(EXPECTED_SOURCE_KEYS):
    evidence_summary = validate_completion_evidence(manifest, paths)
    source_summary = validate_source_contract(manifest, paths)
else:
    evidence_summary = {}
    source_summary = {}

status = "fail" if errors else "pass"
report = {
    "schema_version": "stdio_family_completion_contract.report.v1",
    "status": status,
    "bead": EXPECTED_COMPLETION_BEAD,
    "source_bead": EXPECTED_BEAD,
    "contract": rel(CONTRACT_PATH),
    "contract_sha256": sha256_file(CONTRACT_PATH),
    "target_symbols": EXPECTED_TARGET_SYMBOLS,
    "missing_items_closed": EXPECTED_MISSING_ITEMS,
    "source_summary": source_summary,
    "unit_bindings": evidence_summary.get("unit", []),
    "e2e_bindings": evidence_summary.get("e2e", []),
    "conformance_test_bindings": evidence_summary.get("conformance_tests", []),
    "conformance_bindings": evidence_summary.get("conformance_artifacts", []),
    "events": events,
    "errors": errors,
}

REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG_PATH.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

if errors:
    print("FAIL stdio family completion contract: " + "; ".join(errors[:8]), file=sys.stderr)
    sys.exit(1)

print(
    "PASS stdio family completion contract "
    f"symbols={len(EXPECTED_TARGET_SYMBOLS)} unit={len(evidence_summary.get('unit', []))} "
    f"e2e={len(evidence_summary.get('e2e', []))} "
    f"conformance={len(evidence_summary.get('conformance_tests', []))}"
)
PY
