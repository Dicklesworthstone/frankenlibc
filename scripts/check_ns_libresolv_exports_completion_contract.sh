#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_NS_LIBRESOLV_EXPORTS_COMPLETION_CONTRACT:-${1:-${ROOT}/tests/conformance/ns_libresolv_exports_completion_contract.v1.json}}"
OUT_DIR="${FRANKENLIBC_NS_LIBRESOLV_EXPORTS_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_NS_LIBRESOLV_EXPORTS_COMPLETION_REPORT:-${OUT_DIR}/ns_libresolv_exports_completion_contract.report.json}"
LOG="${FRANKENLIBC_NS_LIBRESOLV_EXPORTS_COMPLETION_LOG:-${OUT_DIR}/ns_libresolv_exports_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

SCHEMA = "ns_libresolv_exports_completion_contract.v1"
REPORT_SCHEMA = "ns_libresolv_exports_completion_contract.report.v1"
BEAD_ID = "bd-0j2ha.1"
ORIGINAL_BEAD = "bd-0j2ha"
TRACE_ID = "bd-0j2ha.1::ns-libresolv-exports-completion::v1"
EXPECTED_BINDINGS = {"tests.unit.primary", "tests.conformance.primary"}
EXPECTED_SYMBOLS = [
    "ns_datetosecs",
    "ns_format_ttl",
    "ns_get16",
    "ns_get32",
    "ns_initparse",
    "ns_makecanon",
    "ns_msg_getflag",
    "ns_name_ntol",
    "ns_name_rollback",
    "ns_parse_ttl",
    "ns_parserr",
    "ns_put16",
    "ns_put32",
    "ns_samedomain",
    "ns_samename",
    "ns_skiprr",
    "ns_sprintrr",
    "ns_sprintrrf",
    "ns_subdomain",
]

errors: list[dict[str, Any]] = []
events: list[dict[str, Any]] = []


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


SOURCE_COMMIT = git_head()


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def resolve(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return root / candidate


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("json_parse_failed", f"{label} failed to parse: {exc}", [rel(path)])
        return {}
    if not isinstance(value, dict):
        add_error("json_parse_failed", f"{label} must be a JSON object", [rel(path)])
        return {}
    return value


def text_file(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error("missing_source_artifact", f"{label} cannot be read: {rel(path)}: {exc}", [rel(path)])
        return ""


def add_error(signature: str, message: str, refs: list[str] | None = None, **details: Any) -> None:
    errors.append(
        {
            "signature": signature,
            "message": message,
            "artifact_refs": refs or [],
            "details": details,
        }
    )


def event(
    name: str,
    status: str,
    expected: Any,
    observed: Any,
    refs: list[str],
) -> dict[str, Any]:
    return {
        "timestamp": now_utc(),
        "event": name,
        "status": status,
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "expected": expected,
        "observed": observed,
        "artifact_refs": refs,
    }


def summary(contract: dict[str, Any]) -> dict[str, Any]:
    bindings = contract.get("completion_debt_evidence", {}).get("missing_item_bindings", [])
    runtime = contract.get("ns_libresolv_export_contract", {})
    return {
        "binding_count": len(bindings) if isinstance(bindings, list) else 0,
        "required_symbol_count": len(runtime.get("required_symbols", []))
        if isinstance(runtime.get("required_symbols", []), list)
        else 0,
        "unit_test_count": len(runtime.get("required_unit_tests", []))
        if isinstance(runtime.get("required_unit_tests", []), list)
        else 0,
        "conformance_group_count": len(runtime.get("required_conformance_tests", []))
        if isinstance(runtime.get("required_conformance_tests", []), list)
        else 0,
    }


def base_report(status: str, contract: dict[str, Any], refs: list[str]) -> dict[str, Any]:
    return {
        "schema_version": REPORT_SCHEMA,
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "status": status,
        "summary": summary(contract),
        "source_artifacts": contract.get("source_artifacts", []),
        "missing_item_bindings": contract.get("completion_debt_evidence", {}).get("missing_item_bindings", []),
        "artifact_refs": refs,
        "errors": errors,
    }


def fail_report(stage: str, contract: dict[str, Any], refs: list[str]) -> None:
    for item in errors:
        events.append(event("ns_libresolv_exports_completion_contract_failed", "fail", stage, item, item.get("artifact_refs", refs)))
    write_json(report_path, base_report("fail", contract, [*refs, rel(report_path), rel(log_path)]))
    write_jsonl(log_path, events)
    primary = errors[0]["signature"] if errors else "unknown"
    print(f"FAIL ns_libresolv_exports_completion_contract primary_failure={primary} report={rel(report_path)} log={rel(log_path)}", file=sys.stderr)
    raise SystemExit(1)


def string_list(obj: dict[str, Any], key: str, context: str, signature: str) -> list[str]:
    value = obj.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        add_error(signature, f"{context}.{key} must be a non-empty string array")
        return []
    return value


def validate_source_artifacts(contract: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    artifacts = contract.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        add_error("missing_source_artifact", "source_artifacts must be a non-empty array")
        return refs
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            add_error("missing_source_artifact", "source_artifacts entries must be objects")
            continue
        path = resolve(str(artifact.get("path", "")))
        refs.append(rel(path))
        if not path.is_file():
            add_error("missing_source_artifact", f"source artifact missing: {rel(path)}", [rel(path)])
    if not errors:
        events.append(event("source_artifacts_validated", "pass", "all listed artifacts exist", refs, refs))
    return refs


def validate_bindings(contract: dict[str, Any]) -> None:
    bindings = contract.get("completion_debt_evidence", {}).get("missing_item_bindings")
    if not isinstance(bindings, list):
        add_error("missing_completion_binding", "missing_item_bindings must be an array")
        return
    actual = {binding.get("spec_item") for binding in bindings if isinstance(binding, dict)}
    if actual != EXPECTED_BINDINGS:
        add_error("missing_completion_binding", f"expected bindings {sorted(EXPECTED_BINDINGS)!r}, found {sorted(actual)!r}")
    for binding in bindings:
        if not isinstance(binding, dict):
            add_error("missing_completion_binding", "binding entries must be objects")
            continue
        for field in ("implementation_refs", "test_refs", "required_positive_tests", "required_negative_tests", "required_commands"):
            value = binding.get(field)
            if not isinstance(value, list) or not value:
                add_error("missing_completion_binding", f"{binding.get('spec_item', '<unknown>')} missing non-empty {field}")
    if not errors:
        events.append(event("completion_bindings_validated", "pass", sorted(EXPECTED_BINDINGS), sorted(actual), [rel(contract_path)]))


def validate_export_map(runtime: dict[str, Any], refs: list[str]) -> None:
    required_symbols = string_list(runtime, "required_symbols", "ns_libresolv_export_contract", "symbol_set_drift")
    if required_symbols != EXPECTED_SYMBOLS:
        add_error("symbol_set_drift", "required symbol list drifted", expected=EXPECTED_SYMBOLS, observed=required_symbols)
    if len(required_symbols) != len(set(required_symbols)):
        add_error("symbol_set_drift", "required symbol list contains duplicates", observed=required_symbols)

    map_path = resolve(str(runtime.get("version_script_path", "")))
    impl_path = resolve(str(runtime.get("implementation_path", "")))
    refs.extend([rel(map_path), rel(impl_path)])
    map_text = text_file(map_path, "version script")
    impl_text = text_file(impl_path, "resolv ABI source")
    anchor = str(runtime.get("version_script_anchor", ""))
    if anchor not in map_text:
        add_error("export_anchor_missing", "version script bd-0j2ha anchor comment missing", [rel(map_path)], anchor=anchor)

    missing_exports = []
    missing_impls = []
    missing_no_mangle = []
    for symbol in EXPECTED_SYMBOLS:
        if f"{symbol};" not in map_text:
            missing_exports.append(symbol)
        decl = f'pub unsafe extern "C" fn {symbol}'
        pos = impl_text.find(decl)
        if pos < 0:
            missing_impls.append(symbol)
            continue
        prefix = impl_text[max(0, pos - 300) : pos]
        if "unsafe(no_mangle)" not in prefix:
            missing_no_mangle.append(symbol)
    if missing_exports:
        add_error("export_missing", "version script missing required ns_* exports", [rel(map_path)], missing=missing_exports)
    if missing_impls:
        add_error("implementation_missing", "resolv_abi.rs missing required ns_* implementations", [rel(impl_path)], missing=missing_impls)
    if missing_no_mangle:
        add_error("no_mangle_missing", "required ns_* implementations missing no_mangle marker", [rel(impl_path)], missing=missing_no_mangle)
    if not errors:
        events.append(event("export_map_validated", "pass", EXPECTED_SYMBOLS, required_symbols, refs))


def validate_unit_tests(runtime: dict[str, Any], refs: list[str]) -> None:
    required = string_list(runtime, "required_unit_tests", "ns_libresolv_export_contract", "unit_binding_drift")
    path = root / "crates/frankenlibc-abi/tests/resolv_abi_test.rs"
    refs.append(rel(path))
    text = text_file(path, "resolv ABI unit tests")
    missing = [name for name in required if f"fn {name}" not in text]
    if missing:
        add_error("unit_binding_drift", "resolv_abi_test.rs missing required test functions", [rel(path)], missing=missing)
    if not errors:
        events.append(event("unit_test_bindings_validated", "pass", required, required, refs))


def validate_conformance_tests(runtime: dict[str, Any], refs: list[str]) -> None:
    groups = runtime.get("required_conformance_tests")
    if not isinstance(groups, list) or not groups:
        add_error("conformance_binding_drift", "required_conformance_tests must be a non-empty array")
        return
    observed: dict[str, list[str]] = {}
    for group in groups:
        if not isinstance(group, dict):
            add_error("conformance_binding_drift", "required_conformance_tests entries must be objects")
            continue
        path = resolve(str(group.get("path", "")))
        refs.append(rel(path))
        text = text_file(path, "conformance test source")
        tests = group.get("tests")
        if not isinstance(tests, list) or not all(isinstance(name, str) and name for name in tests):
            add_error("conformance_binding_drift", f"{rel(path)} tests must be a non-empty string array")
            tests = []
        missing_tests = [name for name in tests if f"fn {name}" not in text]
        if missing_tests:
            add_error("conformance_binding_drift", f"{rel(path)} missing required test functions", [rel(path)], missing=missing_tests)
        terms = group.get("required_terms", [])
        if not isinstance(terms, list) or not all(isinstance(term, str) and term for term in terms):
            add_error("conformance_binding_drift", f"{rel(path)} required_terms must be a string array")
            terms = []
        missing_terms = [term for term in terms if term not in text]
        if missing_terms:
            add_error("conformance_binding_drift", f"{rel(path)} missing required terms", [rel(path)], missing=missing_terms)
        observed[rel(path)] = list(tests)
    if not errors:
        events.append(event("conformance_test_bindings_validated", "pass", "required conformance groups present", observed, refs))


def validate_output_contract(contract: dict[str, Any]) -> None:
    output = contract.get("completion_output_contract")
    if not isinstance(output, dict):
        add_error("completion_output_contract_failed", "completion_output_contract must be an object")
        return
    required_events = set(string_list(output, "required_events", "completion_output_contract", "completion_output_contract_failed"))
    actual_events = {row["event"] for row in events}
    missing = required_events - actual_events - {"ns_libresolv_exports_completion_contract_pass"}
    for item in sorted(missing):
        add_error("completion_output_contract_failed", f"missing event {item}")


contract = load_json(contract_path, "completion contract")
if errors:
    fail_report("load_contract", contract, [rel(contract_path)])

if contract.get("schema_version") != SCHEMA:
    add_error("malformed_contract", "schema_version mismatch", [rel(contract_path)])
if contract.get("bead") != BEAD_ID:
    add_error("malformed_contract", "bead mismatch", [rel(contract_path)])
if contract.get("original_bead") != ORIGINAL_BEAD:
    add_error("malformed_contract", "original_bead mismatch", [rel(contract_path)])
if contract.get("trace_id") != TRACE_ID:
    add_error("malformed_contract", "trace_id mismatch", [rel(contract_path)])

runtime = contract.get("ns_libresolv_export_contract")
if not isinstance(runtime, dict):
    add_error("malformed_contract", "ns_libresolv_export_contract must be an object", [rel(contract_path)])
    runtime = {}

artifact_refs = [rel(contract_path)]
artifact_refs.extend(validate_source_artifacts(contract))
validate_bindings(contract)
validate_export_map(runtime, artifact_refs)
validate_unit_tests(runtime, artifact_refs)
validate_conformance_tests(runtime, artifact_refs)
validate_output_contract(contract)

if errors:
    fail_report("validate_contract", contract, artifact_refs)

events.append(
    event(
        "ns_libresolv_exports_completion_contract_pass",
        "pass",
        "all required events emitted",
        [row["event"] for row in events],
        artifact_refs,
    )
)
write_json(report_path, base_report("pass", contract, [*artifact_refs, rel(report_path), rel(log_path)]))
write_jsonl(log_path, events)
result_summary = base_report("pass", contract, [])["summary"]
print(
    "PASS ns_libresolv_exports_completion_contract "
    f"symbols={result_summary['required_symbol_count']} "
    f"bindings={result_summary['binding_count']} "
    f"unit_tests={result_summary['unit_test_count']} "
    f"conformance_groups={result_summary['conformance_group_count']} "
    f"report={rel(report_path)} log={rel(log_path)}"
)
PY
