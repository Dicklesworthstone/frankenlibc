#!/usr/bin/env bash
# check_resolver_numeric_files_completion_contract.sh - bd-66s.1 completion-debt gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RESOLVER_NUMERIC_FILES_CONTRACT:-${ROOT}/tests/conformance/resolver_numeric_files_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RESOLVER_NUMERIC_FILES_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_RESOLVER_NUMERIC_FILES_REPORT:-${OUT_DIR}/resolver_numeric_files_completion_contract.report.json}"
LOG="${FRANKENLIBC_RESOLVER_NUMERIC_FILES_LOG:-${OUT_DIR}/resolver_numeric_files_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

COMPLETION_DEBT_BEAD = "bd-66s.1"
ORIGINAL_BEAD = "bd-66s"
PASS_EVENT = "resolver_numeric_files_completion_contract_validated"
FAIL_EVENT = "resolver_numeric_files_completion_contract_failed"
SYMBOL_EVENT = "resolver_numeric_files_symbol_bound"
SUMMARY_EVENT = "resolver_numeric_files_completion_summary"
TRACE_ID = f"{COMPLETION_DEBT_BEAD}:resolver-numeric-files-completion"
EXPECTED_SYMBOLS = {"getaddrinfo", "getnameinfo"}
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}
REQUIRED_ARTIFACT_KEYS = {
    "core_resolver",
    "abi_resolver",
    "abi_resolver_tests",
    "resolver_fixture",
    "resolver_conformance",
    "integration_fixture",
    "c_fixture_spec",
    "c_fixture_suite_test",
    "hard_parts_manifest",
    "hard_parts_gate",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
REQUIRED_GATE_KEYS = {"completion_contract", "resolver_hard_parts", "c_fixture_suite"}
REQUIRED_LOG_FIELDS = [
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "api_family",
    "symbol",
    "evidence_kinds",
    "artifact_refs",
    "test_refs",
    "failure_signature",
]
REQUIRED_GETADDRINFO_KINDS = {
    "numeric_ipv4",
    "numeric_ipv6",
    "hosts_files_backend",
    "freeaddrinfo_cleanup",
}
REQUIRED_GETNAMEINFO_KINDS = {
    "numeric_ipv4",
    "numeric_ipv6",
    "invalid_family",
    "overflow_guards",
}

errors = []
logs = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "artifact_paths_exist": "fail",
    "missing_item_bindings": "fail",
    "symbol_contract": "fail",
    "unit_refs": "fail",
    "e2e_fixture": "fail",
    "telemetry_contract": "fail",
    "structured_log": "fail",
}


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fail(message):
    errors.append(message)


def failure_signature():
    if not errors:
        return "none"
    first = errors[0]
    for prefix in [
        "missing_symbol",
        "missing_item",
        "artifact",
        "fixture",
        "telemetry",
        "test_ref",
        "file_line_ref",
        "schema",
    ]:
        if first.startswith(prefix):
            return prefix
    return "resolver_numeric_files_completion_contract_failed"


def safe_path(rel):
    text = str(rel).rstrip("/")
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or not text:
        raise ValueError(f"unsafe workspace-relative path: {text}")
    return root / path


def load_json(path, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"artifact {label} unreadable: {path}: {exc}")
        return {}


def require_dict(value, label):
    if isinstance(value, dict):
        return value
    fail(f"schema {label} must be an object")
    return {}


def require_list(value, label):
    if isinstance(value, list):
        return value
    fail(f"schema {label} must be an array")
    return []


def read_workspace_text(rel, label):
    try:
        return safe_path(rel).read_text(encoding="utf-8")
    except Exception as exc:
        fail(f"artifact {label} unreadable: {rel}: {exc}")
        return ""


def file_exists(rel, label):
    try:
        path = safe_path(rel)
    except Exception as exc:
        fail(f"artifact {label} unsafe path: {rel}: {exc}")
        return False
    if not path.is_file():
        fail(f"artifact {label} missing file: {rel}")
        return False
    return True


def file_line_ref_exists(ref):
    if not isinstance(ref, str) or ":" not in ref:
        fail(f"file_line_ref invalid ref: {ref!r}")
        return False
    rel, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        fail(f"file_line_ref invalid line: {ref}")
        return False
    if line_no <= 0:
        fail(f"file_line_ref line must be positive: {ref}")
        return False
    try:
        path = safe_path(rel)
    except Exception as exc:
        fail(f"file_line_ref unsafe path: {ref}: {exc}")
        return False
    if not path.is_file():
        fail(f"file_line_ref missing path: {ref}")
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no > len(lines):
        fail(f"file_line_ref outside file: {ref}")
        return False
    if not lines[line_no - 1].strip():
        fail(f"file_line_ref blank line: {ref}")
        return False
    return True


def function_exists(source_text, name):
    return f"fn {name}" in source_text or f"def {name}" in source_text


def load_test_sources(evidence):
    source_texts = {}
    for source_name, rel in require_dict(evidence.get("test_sources"), "test_sources").items():
        if not isinstance(rel, str):
            fail(f"artifact test_sources.{source_name} must be a string")
            continue
        source_texts[source_name] = read_workspace_text(rel, f"test_sources.{source_name}")
    return source_texts


def validate_refs(refs, source_texts, label):
    ok = True
    normalized = []
    for ref in require_list(refs, label):
        if not isinstance(ref, dict):
            fail(f"test_ref {label} entries must be objects")
            ok = False
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not isinstance(name, str):
            fail(f"test_ref {label} entries need source and name strings")
            ok = False
            continue
        text = source_texts.get(source, "")
        if not text:
            fail(f"test_ref {label}: missing source {source}")
            ok = False
            continue
        if not function_exists(text, name):
            fail(f"test_ref {label}: missing function {source}.{name}")
            ok = False
            continue
        normalized.append(f"{source}.{name}")
    return ok, normalized


def fixture_case_names(artifacts):
    rel = artifacts.get("resolver_fixture")
    if not isinstance(rel, str):
        fail("fixture resolver_fixture artifact missing")
        return {}, set()
    fixture = load_json(safe_path(rel), "resolver_fixture")
    cases = require_list(fixture.get("cases"), "resolver_fixture.cases")
    names = {}
    modes = set()
    for case in cases:
        if not isinstance(case, dict):
            continue
        name = case.get("name")
        if isinstance(name, str):
            names[name] = case
        mode = case.get("mode")
        if isinstance(mode, str):
            modes.add(mode)
    return names, modes


def append_log(
    event,
    status,
    api_family=None,
    symbol=None,
    evidence_kinds=None,
    artifact_refs=None,
    test_refs=None,
    failure_signature_value="none",
):
    logs.append(
        {
            "timestamp": now(),
            "trace_id": TRACE_ID,
            "event": event,
            "completion_debt_bead": COMPLETION_DEBT_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "source_commit": source_commit,
            "status": status,
            "api_family": api_family,
            "symbol": symbol,
            "evidence_kinds": evidence_kinds or [],
            "artifact_refs": artifact_refs or [],
            "test_refs": test_refs or [],
            "failure_signature": failure_signature_value,
        }
    )


contract = load_json(contract_path, "contract")
if contract:
    checks["json_parse"] = "pass"

evidence = {}
artifacts = {}
symbol_rows = []
symbol_summaries = []
source_texts = {}

if isinstance(contract, dict):
    before = len(errors)
    if contract.get("schema_version") != "resolver_numeric_files_completion_contract.v1":
        fail("schema version drifted")
    if contract.get("bead") != ORIGINAL_BEAD:
        fail(f"schema bead must be {ORIGINAL_BEAD}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
        fail(f"schema completion_debt_bead must be {COMPLETION_DEBT_BEAD}")
    evidence = require_dict(contract.get("completion_debt_evidence"), "completion_debt_evidence")
    if evidence.get("bead") != COMPLETION_DEBT_BEAD:
        fail(f"schema evidence.bead must be {COMPLETION_DEBT_BEAD}")
    if evidence.get("original_bead") != ORIGINAL_BEAD:
        fail(f"schema evidence.original_bead must be {ORIGINAL_BEAD}")
    if int(evidence.get("next_audit_score_threshold", 0)) < 800:
        fail("schema next_audit_score_threshold must be >= 800")
    for ref in require_list(evidence.get("implementation_refs"), "implementation_refs"):
        file_line_ref_exists(ref)
    if len(errors) == before:
        checks["top_level_shape"] = "pass"

    artifacts = require_dict(evidence.get("artifacts"), "artifacts")
    gates = require_dict(evidence.get("gates"), "gates")
    artifact_before = len(errors)
    for key in sorted(REQUIRED_ARTIFACT_KEYS):
        rel = artifacts.get(key)
        if isinstance(rel, str):
            file_exists(rel, f"artifacts.{key}")
        else:
            fail(f"artifact artifacts.{key} must be a string")
    for key in sorted(REQUIRED_GATE_KEYS):
        rel = gates.get(key)
        if isinstance(rel, str):
            file_exists(rel, f"gates.{key}")
        else:
            fail(f"artifact gates.{key} must be a string")
    missing_artifacts = sorted(REQUIRED_ARTIFACT_KEYS - set(artifacts))
    missing_gates = sorted(REQUIRED_GATE_KEYS - set(gates))
    if missing_artifacts:
        fail("artifact missing keys: " + ", ".join(missing_artifacts))
    if missing_gates:
        fail("artifact gate missing keys: " + ", ".join(missing_gates))
    if len(errors) == artifact_before:
        checks["artifact_paths_exist"] = "pass"

    binding_before = len(errors)
    observed_bindings = {}
    for binding in require_list(evidence.get("missing_item_bindings"), "missing_item_bindings"):
        if not isinstance(binding, dict):
            fail("missing_item binding entries must be objects")
            continue
        section = binding.get("evidence_section")
        missing_item = binding.get("missing_item_id")
        if isinstance(section, str) and isinstance(missing_item, str):
            observed_bindings[section] = missing_item
    if observed_bindings != EXPECTED_MISSING_ITEMS:
        fail(f"missing_item bindings drifted: {observed_bindings}")
    for section, missing_item in EXPECTED_MISSING_ITEMS.items():
        section_doc = require_dict(evidence.get(section), section)
        if section_doc.get("missing_item_id") != missing_item:
            fail(f"missing_item {section}.missing_item_id must be {missing_item}")
    if len(errors) == binding_before:
        checks["missing_item_bindings"] = "pass"

    source_texts = load_test_sources(evidence)
    fixture_names, fixture_modes = fixture_case_names(artifacts)

    symbol_before = len(errors)
    symbol_rows = require_list(evidence.get("required_symbols"), "required_symbols")
    seen_symbols = set()
    for index, row in enumerate(symbol_rows):
        if not isinstance(row, dict):
            fail(f"missing_symbol required_symbols[{index}] must be an object")
            continue
        symbol = row.get("symbol")
        if symbol not in EXPECTED_SYMBOLS:
            fail(f"missing_symbol unexpected required symbol {symbol!r}")
            continue
        seen_symbols.add(symbol)
        family = row.get("family")
        if family != "resolver":
            fail(f"missing_symbol {symbol}: family must be resolver")
        file_line_ref_exists(row.get("abi_ref"))
        for ref in require_list(row.get("core_refs"), f"{symbol}.core_refs"):
            file_line_ref_exists(ref)
        for mode in ["strict", "hardened"]:
            if mode not in row.get("required_modes", []):
                fail(f"missing_symbol {symbol}: required_modes missing {mode}")
        evidence_kinds = set(row.get("evidence_kinds", []))
        required_kinds = (
            REQUIRED_GETADDRINFO_KINDS if symbol == "getaddrinfo" else REQUIRED_GETNAMEINFO_KINDS
        )
        missing_kinds = sorted(required_kinds - evidence_kinds)
        if missing_kinds:
            fail(f"missing_symbol {symbol}: evidence_kinds missing {', '.join(missing_kinds)}")
        unit_ok, unit_refs = validate_refs(row.get("unit_test_refs"), source_texts, f"{symbol}.unit_test_refs")
        abi_ok, abi_refs = validate_refs(row.get("abi_test_refs"), source_texts, f"{symbol}.abi_test_refs")
        if not unit_ok or not abi_ok:
            fail(f"test_ref {symbol}: test refs failed validation")
        fixture_case_count = 0
        if symbol == "getaddrinfo":
            for case_name in require_list(row.get("fixture_cases"), "getaddrinfo.fixture_cases"):
                if case_name not in fixture_names:
                    fail(f"fixture getaddrinfo missing case {case_name}")
                else:
                    fixture_case_count += 1
            if not {"strict", "hardened"} <= fixture_modes:
                fail("fixture resolver fixture must contain strict and hardened modes")
        append_log(
            SYMBOL_EVENT,
            "pass",
            api_family=family,
            symbol=symbol,
            evidence_kinds=sorted(evidence_kinds),
            artifact_refs=[row.get("abi_ref", ""), *row.get("core_refs", [])],
            test_refs=[*unit_refs, *abi_refs],
        )
        symbol_summaries.append(
            {
                "symbol": symbol,
                "family": family,
                "evidence_kinds": sorted(evidence_kinds),
                "fixture_case_count": fixture_case_count,
            }
        )
    missing_symbols = sorted(EXPECTED_SYMBOLS - seen_symbols)
    if missing_symbols:
        fail("missing_symbol required_symbols missing: " + ", ".join(missing_symbols))
    if len(errors) == symbol_before:
        checks["symbol_contract"] = "pass"

    refs_before = len(errors)
    for section in ["unit_primary", "e2e_primary"]:
        section_doc = require_dict(evidence.get(section), section)
        validate_refs(section_doc.get("required_test_refs"), source_texts, f"{section}.required_test_refs")
    if len(errors) == refs_before:
        checks["unit_refs"] = "pass"

    e2e_before = len(errors)
    e2e = require_dict(evidence.get("e2e_primary"), "e2e_primary")
    c_spec = load_json(safe_path(artifacts.get("c_fixture_spec", "")), "c_fixture_spec")
    fixtures = require_list(c_spec.get("fixtures"), "c_fixture_spec.fixtures")
    fixture_id = e2e.get("fixture_id")
    c_fixture = None
    for row in fixtures:
        if isinstance(row, dict) and row.get("id") == fixture_id:
            c_fixture = row
            break
    if not c_fixture:
        fail(f"fixture c_fixture_spec missing fixture id {fixture_id}")
    else:
        covered = set(c_fixture.get("covered_symbols", []))
        missing = sorted(set(e2e.get("required_covered_symbols", [])) - covered)
        if missing:
            fail("fixture fixture_nss missing covered symbols: " + ", ".join(missing))
        modes = require_dict(c_fixture.get("mode_expectations"), "fixture_nss.mode_expectations")
        for mode in e2e.get("required_mode_expectations", []):
            mode_obj = require_dict(modes.get(mode), f"fixture_nss.mode_expectations.{mode}")
            if mode_obj.get("expected_exit") != 0:
                fail(f"fixture fixture_nss {mode} expected_exit must be 0")
            marker = mode_obj.get("expected_stdout_contains", "")
            if not isinstance(marker, str) or not marker.strip():
                fail(f"fixture fixture_nss {mode} expected_stdout_contains must be non-empty")
    integration_text = read_workspace_text(artifacts.get("integration_fixture", ""), "integration_fixture")
    for token in ["getaddrinfo", "freeaddrinfo", "fixture_nss: PASS"]:
        if token not in integration_text:
            fail(f"fixture integration fixture missing token {token}")
    if len(errors) == e2e_before:
        checks["e2e_fixture"] = "pass"

    telemetry_before = len(errors)
    telemetry = require_dict(evidence.get("telemetry_primary"), "telemetry_primary")
    for ref in require_list(telemetry.get("telemetry_refs"), "telemetry_primary.telemetry_refs"):
        file_line_ref_exists(ref)
    log_contract = require_dict(telemetry.get("structured_log_contract"), "structured_log_contract")
    required_events = set(log_contract.get("required_events", []))
    if not {PASS_EVENT, SYMBOL_EVENT, SUMMARY_EVENT} <= required_events:
        fail("telemetry structured log missing required pass events")
    if FAIL_EVENT not in set(log_contract.get("forbidden_events", [])):
        fail("telemetry structured log must forbid fail event on pass")
    for field in REQUIRED_LOG_FIELDS:
        if field not in log_contract.get("required_fields", []):
            fail(f"telemetry structured log missing field {field}")
    hard_parts = load_json(safe_path(artifacts.get("hard_parts_manifest", "")), "hard_parts_manifest")
    hard_fields = set(hard_parts.get("required_log_fields", []))
    for field in ["trace_id", "runtime_mode", "query_kind", "artifact_refs", "failure_signature"]:
        if field not in hard_fields:
            fail(f"telemetry hard-parts required_log_fields missing {field}")
    hard_rows = require_list(hard_parts.get("fixture_rows"), "hard_parts_manifest.fixture_rows")
    hard_modes = {row.get("runtime_mode") for row in hard_rows if isinstance(row, dict)}
    hard_kinds = {row.get("query_kind") for row in hard_rows if isinstance(row, dict)}
    if not {"strict", "hardened"} <= hard_modes:
        fail("telemetry hard-parts rows must cover strict and hardened")
    if "hosts_lookup" not in hard_kinds:
        fail("telemetry hard-parts rows must cover hosts_lookup")
    if len(errors) == telemetry_before:
        checks["telemetry_contract"] = "pass"

status = "pass" if not errors else "fail"
if errors:
    append_log(FAIL_EVENT, "fail", failure_signature_value=failure_signature())
else:
    append_log(
        PASS_EVENT,
        "pass",
        api_family="resolver",
        symbol="all",
        evidence_kinds=["unit", "e2e", "telemetry"],
        artifact_refs=list(artifacts.values()),
        test_refs=[f"{section}:{item}" for section, item in EXPECTED_MISSING_ITEMS.items()],
    )
append_log(
    SUMMARY_EVENT,
    status,
    api_family="resolver",
    symbol="all",
    evidence_kinds=[row["symbol"] for row in symbol_summaries],
    artifact_refs=list(artifacts.values()) if artifacts else [],
    test_refs=[row["symbol"] for row in symbol_summaries],
    failure_signature_value=failure_signature(),
)

if not errors:
    checks["structured_log"] = "pass"

report = {
    "schema_version": "resolver_numeric_files_completion_contract.report.v1",
    "status": status,
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "contract": str(contract_path),
    "checks": checks,
    "summary": {
        "required_symbol_count": len(EXPECTED_SYMBOLS),
        "bound_symbol_count": len({row.get("symbol") for row in symbol_rows if isinstance(row, dict)} & EXPECTED_SYMBOLS),
        "missing_item_count": len(EXPECTED_MISSING_ITEMS),
        "event_count": len(logs),
        "events": [row["event"] for row in logs],
    },
    "symbols": symbol_summaries,
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in logs),
    encoding="utf-8",
)

if errors:
    raise SystemExit(1)

print(
    "PASS resolver numeric/files completion contract "
    f"symbols={len(symbol_summaries)} missing_items={len(EXPECTED_MISSING_ITEMS)} "
    f"events={len(logs)}"
)
PY
