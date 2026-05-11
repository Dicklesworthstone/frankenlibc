#!/usr/bin/env bash
# Validate bd-ldj.4.1 iconv/locale-family completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${1:-${ROOT}/tests/conformance/iconv_locale_family_completion_contract.v1.json}"
OUT_DIR="${2:-${ROOT}/target/conformance}"
REPORT_PATH="${OUT_DIR}/iconv_locale_family_completion_contract.report.json"
LOG_PATH="${OUT_DIR}/iconv_locale_family_completion_contract.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT_PATH}" "${REPORT_PATH}" "${LOG_PATH}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT_PATH = pathlib.Path(sys.argv[2]).resolve()
REPORT_PATH = pathlib.Path(sys.argv[3]).resolve()
LOG_PATH = pathlib.Path(sys.argv[4]).resolve()

EXPECTED_SCHEMA = "iconv_locale_family_completion_contract.v1"
EXPECTED_BEAD = "bd-ldj.4"
EXPECTED_COMPLETION_BEAD = "bd-ldj.4.1"
EXPECTED_MISSING_ITEMS = ["tests.unit.primary", "tests.e2e.primary"]
EXPECTED_TARGET_SYMBOLS = [
    "iconv_open",
    "iconv",
    "iconv_close",
    "setlocale",
    "localeconv",
    "nl_langinfo",
    "nl_langinfo_l",
    "newlocale",
    "duplocale",
    "freelocale",
    "uselocale",
    "gettext",
    "ngettext",
    "dgettext",
    "textdomain",
    "bindtextdomain",
    "catopen",
    "catgets",
    "catclose",
]
EXPECTED_MODULES = {
    "iconv_open": "iconv_abi",
    "iconv": "iconv_abi",
    "iconv_close": "iconv_abi",
    "setlocale": "locale_abi",
    "localeconv": "locale_abi",
    "nl_langinfo": "locale_abi",
    "nl_langinfo_l": "locale_abi",
    "newlocale": "locale_abi",
    "duplocale": "locale_abi",
    "freelocale": "locale_abi",
    "uselocale": "locale_abi",
    "gettext": "locale_abi",
    "ngettext": "locale_abi",
    "dgettext": "locale_abi",
    "textdomain": "locale_abi",
    "bindtextdomain": "locale_abi",
    "catopen": "locale_abi",
    "catgets": "locale_abi",
    "catclose": "locale_abi",
}
EXPECTED_SOURCE_KEYS = {
    "core_locale",
    "core_locale_catgets",
    "core_iconv",
    "abi_locale",
    "abi_iconv",
    "abi_locale_test",
    "abi_iconv_test",
    "support_matrix",
    "locale_fixture",
    "iconv_fixture",
    "locale_conformance_test",
    "iconv_conformance_test",
    "iconv_scope_ledger",
    "iconv_scope_test",
    "locale_iconv_breadth_ledger",
    "locale_iconv_breadth_test",
    "iconv_stateful_fixture_pack",
    "iconv_stateful_fixture_pack_test",
    "locale_catalog_transliteration_fixture_pack",
    "locale_catalog_transliteration_fixture_pack_test",
    "completion_checker",
    "completion_test",
}
EXPECTED_EVIDENCE_KEYS = {"unit_primary", "e2e_primary"}
EXPECTED_UNIT_REFS = {
    ("core_locale", "valid_category_accepts_all_defined_categories"),
    ("core_locale", "valid_category_rejects_out_of_range"),
    ("core_locale", "c_locale_conv_decimal_point_is_dot"),
    ("core_locale", "is_c_locale_recognises_c"),
    ("core_locale", "is_c_locale_rejects_other_names"),
    ("core_locale_catgets", "parse_minimal_catalog_with_one_message"),
    ("core_locale_catgets", "parse_rejects_invalid_magic"),
    ("core_locale_catgets", "lookup_handles_collision_chain_via_plane_depth"),
    ("core_locale_catgets", "message_bytes_excludes_nul_terminator"),
    ("core_iconv", "iconv_open_recognizes_phase1_encodings"),
    ("core_iconv", "iconv_open_rejects_out_of_scope_codecs"),
    ("core_iconv", "utf8_to_latin1_basic_conversion"),
    ("core_iconv", "utf8_to_utf16le_conversion"),
    ("core_iconv", "utf8_to_utf32_first_conversion_emits_bom"),
    ("core_iconv", "e2big_reports_partial_progress"),
    ("core_iconv", "invalid_utf8_reports_eilseq"),
    ("core_iconv", "incomplete_utf8_reports_einval"),
    ("core_iconv", "latin1_unrepresentable_reports_eilseq"),
}
EXPECTED_E2E_REFS = {
    ("abi_locale_test", "setlocale_set_c_locale"),
    ("abi_locale_test", "localeconv_stable_pointer"),
    ("abi_locale_test", "nl_langinfo_codeset"),
    ("abi_locale_test", "textdomain_query_reflects_previous_set"),
    ("abi_locale_test", "bindtextdomain_query_reflects_previous_set"),
    ("abi_locale_test", "newlocale_c_locale_succeeds"),
    ("abi_locale_test", "nl_langinfo_l_codeset"),
    ("abi_locale_test", "generated_catalog_hit_miss_and_close_match_host"),
    ("abi_iconv_test", "iconv_open_utf8_to_utf16le"),
    ("abi_iconv_test", "iconv_utf8_to_latin1"),
    ("abi_iconv_test", "iconv_e2big_partial_progress"),
    ("abi_iconv_test", "iconv_invalid_utf8_reports_eilseq_and_preserves_progress"),
    ("abi_iconv_test", "iconv_close_double_close_returns_error"),
    ("locale_conformance_test", "locale_ops_fixture_executes_mode_specific_contracts"),
    ("iconv_conformance_test", "iconv_phase1_fixture_executes_via_isolated_harness"),
    ("iconv_scope_test", "iconv_scope_ledger_included_set_matches_phase1_contract"),
    ("locale_iconv_breadth_test", "implemented_bootstrap_cross_references_canonical_phase1_ledger"),
    ("iconv_stateful_fixture_pack_test", "manifest_defines_iconv_stateful_schema_and_required_coverage"),
    ("locale_catalog_transliteration_fixture_pack_test", "manifest_defines_locale_fixture_schema_and_required_classes"),
}
EXPECTED_E2E_ARTIFACTS = {
    "locale_fixture",
    "iconv_fixture",
    "locale_conformance_test",
    "iconv_conformance_test",
    "iconv_scope_ledger",
    "locale_iconv_breadth_ledger",
}
EXPECTED_LOCALE_FUNCTIONS = {
    "setlocale",
    "localeconv",
    "nl_langinfo",
    "nl_langinfo_l",
    "newlocale",
    "uselocale",
    "duplocale",
    "freelocale",
}
EXPECTED_ICONV_FUNCTIONS = {"iconv_open", "iconv", "iconv_close"}
EXPECTED_MODES = {"strict", "hardened"}
EXPECTED_ICONV_ERROR_CODES = {7, 22, 84}
EXPECTED_ICONV_CODECS = {"UTF-8", "ISO-8859-1", "UTF-16LE", "UTF-32"}

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
            "schema_version": "iconv_locale_family_completion_contract.log.v1",
            "event": event,
            "status": status,
            "outcome": status,
            "bead": EXPECTED_COMPLETION_BEAD,
            "bead_id": EXPECTED_COMPLETION_BEAD,
            "source_bead": EXPECTED_BEAD,
            "trace_id": f"{EXPECTED_COMPLETION_BEAD}::{event}",
            "mode": "strict+hardened",
            "api_family": "locale",
            "symbol": "iconv-locale-family",
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
        "iconv_locale_family_completion.source_artifacts",
        "fail" if errors else "pass",
        {"artifact_count": len(paths), "keys": sorted(paths)},
    )
    return paths


def validate_refs(
    section: dict[str, Any],
    section_name: str,
    expected: set[tuple[str, str]],
    paths: dict[str, pathlib.Path],
) -> list[str]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list):
        err(f"{section_name}.required_test_refs must be a list")
        refs = []
    got = {
        (ref.get("artifact"), ref.get("name"))
        for ref in refs
        if isinstance(ref, dict)
        and isinstance(ref.get("artifact"), str)
        and isinstance(ref.get("name"), str)
    }
    require(got == expected, f"{section_name} test refs mismatch: got {sorted(got)}")
    for artifact, name in expected:
        path = paths.get(artifact)
        if path is None:
            continue
        text = read_text(path, artifact)
        pattern = re.compile(rf"\bfn\s+{re.escape(name)}\b")
        require(bool(pattern.search(text)), f"{section_name} missing test function {name} in {artifact}")
    validate_rch_commands(section, section_name)
    return [f"{artifact}::{name}" for artifact, name in sorted(expected)]


def validate_fixture_modes(cases: list[dict[str, Any]], label: str) -> set[str]:
    modes = {case.get("mode") for case in cases if isinstance(case.get("mode"), str)}
    require(EXPECTED_MODES <= modes, f"{label} must include strict and hardened modes, got {sorted(modes)}")
    return modes


def validate_e2e(section: dict[str, Any], paths: dict[str, pathlib.Path]) -> list[str]:
    artifacts = section.get("required_artifacts")
    if not isinstance(artifacts, list):
        err("e2e_primary.required_artifacts must be a list")
        artifacts = []
    got = {
        artifact.get("artifact")
        for artifact in artifacts
        if isinstance(artifact, dict) and isinstance(artifact.get("artifact"), str)
    }
    require(got == EXPECTED_E2E_ARTIFACTS, f"e2e artifacts mismatch: got {sorted(got)}")
    validate_rch_commands(section, "e2e_primary")

    locale_fixture = load_json(paths["locale_fixture"], "locale_fixture")
    locale_cases = locale_fixture.get("cases", []) if isinstance(locale_fixture, dict) else []
    if not isinstance(locale_cases, list):
        err("locale_fixture.cases must be a list")
        locale_cases = []
    locale_functions = {case.get("function") for case in locale_cases if isinstance(case, dict)}
    require(EXPECTED_LOCALE_FUNCTIONS <= locale_functions, f"locale fixture missing functions: {sorted(EXPECTED_LOCALE_FUNCTIONS - locale_functions)}")
    validate_fixture_modes([case for case in locale_cases if isinstance(case, dict)], "locale fixture")

    iconv_fixture = load_json(paths["iconv_fixture"], "iconv_fixture")
    iconv_cases = iconv_fixture.get("cases", []) if isinstance(iconv_fixture, dict) else []
    if not isinstance(iconv_cases, list):
        err("iconv_fixture.cases must be a list")
        iconv_cases = []
    iconv_functions = {case.get("function") for case in iconv_cases if isinstance(case, dict)}
    require(EXPECTED_ICONV_FUNCTIONS <= iconv_functions, f"iconv fixture missing functions: {sorted(EXPECTED_ICONV_FUNCTIONS - iconv_functions)}")
    iconv_error_codes = {
        case.get("expected_errno")
        for case in iconv_cases
        if isinstance(case, dict) and isinstance(case.get("expected_errno"), int)
    }
    require(EXPECTED_ICONV_ERROR_CODES <= iconv_error_codes, f"iconv fixture missing errno cases: {sorted(EXPECTED_ICONV_ERROR_CODES - iconv_error_codes)}")
    validate_fixture_modes([case for case in iconv_cases if isinstance(case, dict)], "iconv fixture")

    locale_conformance = read_text(paths["locale_conformance_test"], "locale_conformance_test")
    iconv_conformance = read_text(paths["iconv_conformance_test"], "iconv_conformance_test")
    require("conformance-matrix-case" in locale_conformance, "locale conformance test must execute isolated conformance-matrix-case")
    require("conformance-matrix-case" in iconv_conformance, "iconv conformance test must execute isolated conformance-matrix-case")

    scope = load_json(paths["iconv_scope_ledger"], "iconv_scope_ledger")
    included = {
        row.get("canonical")
        for row in scope.get("included_codecs", [])
        if isinstance(row, dict) and isinstance(row.get("canonical"), str)
    } if isinstance(scope, dict) else set()
    require(EXPECTED_ICONV_CODECS <= included, f"iconv scope ledger missing included codecs: {sorted(EXPECTED_ICONV_CODECS - included)}")
    mapping = scope.get("support_matrix_mapping", {}) if isinstance(scope, dict) else {}
    require(mapping.get("module") == "iconv_abi", f"iconv scope support module mismatch: {mapping.get('module')!r}")
    require(set(mapping.get("symbols", [])) == EXPECTED_ICONV_FUNCTIONS, "iconv scope support symbols mismatch")

    breadth = load_json(paths["locale_iconv_breadth_ledger"], "locale_iconv_breadth_ledger")
    implemented = {
        row.get("canonical")
        for row in breadth.get("implemented_bootstrap_codecs", [])
        if isinstance(row, dict) and isinstance(row.get("canonical"), str)
    } if isinstance(breadth, dict) else set()
    require(EXPECTED_ICONV_CODECS <= implemented, f"locale/iconv breadth ledger missing implemented bootstrap codecs: {sorted(EXPECTED_ICONV_CODECS - implemented)}")

    return sorted(EXPECTED_E2E_ARTIFACTS)


def validate_support_matrix(paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    support = load_json(paths["support_matrix"], "support_matrix")
    symbols = support.get("symbols", []) if isinstance(support, dict) else []
    by_symbol = {
        row.get("symbol"): row
        for row in symbols
        if isinstance(row, dict) and isinstance(row.get("symbol"), str)
    }
    for symbol, module in EXPECTED_MODULES.items():
        row = by_symbol.get(symbol)
        if row is None:
            err(f"support_matrix missing {symbol}")
            continue
        require(row.get("status") == "Implemented", f"support_matrix {symbol} status is {row.get('status')!r}")
        require(row.get("module") == module, f"support_matrix {symbol} module is {row.get('module')!r}")
    return {
        "checked_symbols": len(EXPECTED_TARGET_SYMBOLS),
        "support_matrix_total": len(by_symbol),
    }


def validate_abi_exports(paths: dict[str, pathlib.Path]) -> list[str]:
    texts = {
        "locale_abi": read_text(paths["abi_locale"], "abi_locale"),
        "iconv_abi": read_text(paths["abi_iconv"], "abi_iconv"),
    }
    exported: list[str] = []
    for symbol, module in EXPECTED_MODULES.items():
        marker = f'pub unsafe extern "C" fn {symbol}'
        require(marker in texts[module], f"{module} missing export marker: {marker}")
        exported.append(symbol)
    return exported


def validate_manifest(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
    require(manifest.get("bead") == EXPECTED_BEAD, "bead mismatch")
    require(manifest.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_debt_bead mismatch")
    require(manifest.get("target_symbols") == EXPECTED_TARGET_SYMBOLS, "target_symbols mismatch")
    debt = manifest.get("completion_debt")
    if not isinstance(debt, dict):
        err("completion_debt must be an object")
        debt = {}
    require(debt.get("missing_items_closed") == EXPECTED_MISSING_ITEMS, "missing_items_closed mismatch")

    evidence = manifest.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        evidence = {}
    missing = EXPECTED_EVIDENCE_KEYS - set(evidence)
    extra = set(evidence) - EXPECTED_EVIDENCE_KEYS
    require(not missing, f"completion_debt_evidence missing keys: {sorted(missing)}")
    require(not extra, f"completion_debt_evidence unexpected keys: {sorted(extra)}")

    unit_section = evidence.get("unit_primary", {})
    e2e_section = evidence.get("e2e_primary", {})
    if not isinstance(unit_section, dict):
        err("unit_primary must be an object")
        unit_section = {}
    if not isinstance(e2e_section, dict):
        err("e2e_primary must be an object")
        e2e_section = {}

    unit_bindings = validate_refs(unit_section, "unit_primary", EXPECTED_UNIT_REFS, paths)
    e2e_test_bindings = validate_refs(e2e_section, "e2e_primary", EXPECTED_E2E_REFS, paths)
    e2e_artifacts = validate_e2e(e2e_section, paths)
    support_summary = validate_support_matrix(paths)
    abi_exports = validate_abi_exports(paths)

    append_event(
        "iconv_locale_family_completion.bindings",
        "fail" if errors else "pass",
        {
            "unit_bindings": len(unit_bindings),
            "e2e_test_bindings": len(e2e_test_bindings),
            "e2e_artifacts": len(e2e_artifacts),
            "target_symbols": len(EXPECTED_TARGET_SYMBOLS),
        },
    )

    artifact_hashes = {
        key: sha256_file(path)
        for key, path in sorted(paths.items())
        if key in {
            "core_locale",
            "core_locale_catgets",
            "core_iconv",
            "abi_locale",
            "abi_iconv",
            "abi_locale_test",
            "abi_iconv_test",
            "locale_fixture",
            "iconv_fixture",
            "completion_checker",
            "completion_test",
        }
    }

    return {
        "target_symbols": EXPECTED_TARGET_SYMBOLS,
        "unit_bindings": unit_bindings,
        "e2e_test_bindings": e2e_test_bindings,
        "e2e_artifacts": e2e_artifacts,
        "abi_exports": abi_exports,
        "source_summary": {
            "support_matrix": support_summary,
            "artifact_hashes": artifact_hashes,
        },
    }


manifest = load_json(CONTRACT_PATH, "contract")
paths = validate_source_artifacts(manifest if isinstance(manifest, dict) else {})
summary: dict[str, Any] = {}
if isinstance(manifest, dict) and paths:
    summary = validate_manifest(manifest, paths)

status = "fail" if errors else "pass"
append_event(
    "iconv_locale_family_completion.final",
    status,
    {
        "error_count": len(errors),
        "target_symbol_count": len(EXPECTED_TARGET_SYMBOLS),
    },
)

report = {
    "schema_version": "iconv_locale_family_completion_contract.report.v1",
    "status": status,
    "bead": EXPECTED_COMPLETION_BEAD,
    "source_bead": EXPECTED_BEAD,
    "contract": rel(CONTRACT_PATH),
    "errors": errors,
    **summary,
}
REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG_PATH.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)

if errors:
    print(f"iconv/locale family completion contract failed: {REPORT_PATH}", file=sys.stderr)
    for message in errors:
        print(f"  - {message}", file=sys.stderr)
    sys.exit(1)

print(f"iconv/locale family completion contract passed: {REPORT_PATH}")
PY
