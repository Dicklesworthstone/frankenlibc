#!/usr/bin/env bash
# check_resolver_nss_family_completion_contract.sh - bd-ldj.3.1 completion-debt gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RESOLVER_NSS_FAMILY_CONTRACT:-${ROOT}/tests/conformance/resolver_nss_family_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RESOLVER_NSS_FAMILY_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_RESOLVER_NSS_FAMILY_REPORT:-${OUT_DIR}/resolver_nss_family_completion_contract.report.json}"
LOG="${FRANKENLIBC_RESOLVER_NSS_FAMILY_LOG:-${OUT_DIR}/resolver_nss_family_completion_contract.log.jsonl}"
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

COMPLETION_DEBT_BEAD = "bd-ldj.3.1"
ORIGINAL_BEAD = "bd-ldj.3"
PASS_EVENT = "resolver_nss_family_completion_contract_validated"
FAIL_EVENT = "resolver_nss_family_completion_contract_failed"
SYMBOL_EVENT = "resolver_nss_family_symbol_bound"
SUMMARY_EVENT = "resolver_nss_family_completion_summary"
TRACE_ID = f"{COMPLETION_DEBT_BEAD}:resolver-nss-family-completion"
EXPECTED_SYMBOLS = {"getaddrinfo", "gethostbyname", "getpwnam", "getgrnam"}
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
}
REQUIRED_ARTIFACT_KEYS = {
    "core_resolver",
    "core_passwd",
    "core_group",
    "abi_resolver",
    "abi_passwd",
    "abi_group",
    "resolver_fixture",
    "passwd_fixture",
    "group_fixture",
    "resolver_hard_parts_manifest",
    "semantic_kernels_manifest",
    "integration_fixture",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
REQUIRED_GATE_KEYS = {
    "resolver_hard_parts",
    "semantic_kernels",
    "completion_contract",
}
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
    "fixture_case_count",
    "artifact_refs",
    "test_refs",
    "failure_signature",
]
REQUIRED_SOURCE_TEST_SECTIONS = [
    "unit_primary",
    "e2e_primary",
    "conformance_primary",
]

errors = []
logs = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "artifact_paths_exist": "fail",
    "missing_item_bindings": "fail",
    "symbol_contract": "fail",
    "fixture_case_coverage": "fail",
    "test_refs": "fail",
    "e2e_conformance_sources": "fail",
    "structured_log": "fail",
}


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fail(message):
    errors.append(message)


def safe_path(rel):
    rel_text = str(rel).rstrip("/")
    rel_path = Path(rel_text)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise ValueError(f"unsafe workspace-relative path: {rel_text}")
    return root / rel_path


def load_json(path, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{label} unreadable: {path}: {exc}")
        return {}


def require_dict(value, label):
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
        return {}
    return value


def require_list(value, label):
    if not isinstance(value, list):
        fail(f"{label} must be an array")
        return []
    return value


def file_exists(rel, label):
    try:
        path = safe_path(rel)
    except Exception as exc:
        fail(f"{label} unsafe path: {rel}: {exc}")
        return False
    if not path.is_file():
        fail(f"{label} missing file: {rel}")
        return False
    return True


def read_workspace_text(rel, label):
    try:
        return safe_path(rel).read_text(encoding="utf-8")
    except Exception as exc:
        fail(f"{label} unreadable: {rel}: {exc}")
        return ""


def file_line_ref_exists(ref):
    if not isinstance(ref, str) or ":" not in ref:
        fail(f"invalid file-line ref: {ref!r}")
        return False
    rel, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        fail(f"invalid file-line ref line: {ref}")
        return False
    if line_no <= 0:
        fail(f"file-line ref must use a positive line: {ref}")
        return False
    try:
        path = safe_path(rel)
    except Exception as exc:
        fail(f"file-line ref unsafe path: {ref}: {exc}")
        return False
    if not path.is_file():
        fail(f"file-line ref missing path: {ref}")
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no > len(lines):
        fail(f"file-line ref outside file: {ref}")
        return False
    if not lines[line_no - 1].strip():
        fail(f"file-line ref references blank line: {ref}")
        return False
    return True


def function_exists(source_text, name):
    return f"fn {name}" in source_text or f"def {name}" in source_text


def append_log(
    event,
    status,
    api_family=None,
    symbol=None,
    fixture_case_count=0,
    artifact_refs=None,
    test_refs=None,
    failure_signature="none",
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
            "fixture_case_count": fixture_case_count,
            "artifact_refs": artifact_refs or [],
            "test_refs": test_refs or [],
            "failure_signature": failure_signature,
        }
    )


def load_test_sources(evidence, artifacts):
    source_texts = {}
    for source_name, rel in require_dict(evidence.get("test_sources"), "test_sources").items():
        if not isinstance(rel, str):
            fail(f"test_sources.{source_name} must be a string")
            continue
        source_texts[source_name] = read_workspace_text(rel, f"test_sources.{source_name}")
    for source_name, rel in artifacts.items():
        if source_name not in source_texts and isinstance(rel, str) and rel.endswith(".rs"):
            source_texts[source_name] = read_workspace_text(rel, f"artifacts.{source_name}")
    return source_texts


def validate_refs(refs, source_texts, label):
    ok = True
    normalized = []
    for ref in require_list(refs, label):
        if not isinstance(ref, dict):
            fail(f"{label} entries must be objects")
            ok = False
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not isinstance(name, str):
            fail(f"{label} entries need source and name strings")
            ok = False
            continue
        text = source_texts.get(source, "")
        if not text:
            fail(f"{label}: missing source {source}")
            ok = False
            continue
        if not function_exists(text, name):
            fail(f"{label}: test ref missing {source}.{name}")
            ok = False
            continue
        normalized.append(f"{source}.{name}")
    return ok, normalized


def fixture_cases_for_symbol(artifacts, fixture_key, fixture_function):
    fixture_rel = artifacts.get(fixture_key)
    if not isinstance(fixture_rel, str):
        fail(f"required symbol fixture key {fixture_key} is missing")
        return []
    fixture = load_json(safe_path(fixture_rel), f"fixture {fixture_key}")
    cases = fixture.get("cases")
    if not isinstance(cases, list):
        fail(f"fixture {fixture_key} must contain cases")
        return []
    return [case for case in cases if isinstance(case, dict) and case.get("function") == fixture_function]


contract = load_json(contract_path, "contract")
if contract:
    checks["json_parse"] = "pass"

evidence = {}
artifacts = {}
gates = {}
source_texts = {}
symbol_rows = []
symbol_summaries = []

if isinstance(contract, dict):
    before = len(errors)
    if contract.get("schema_version") != "resolver_nss_family_completion_contract.v1":
        fail("schema_version drifted")
    if contract.get("bead") != ORIGINAL_BEAD:
        fail(f"bead must be {ORIGINAL_BEAD}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
        fail(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")
    evidence = require_dict(contract.get("completion_debt_evidence"), "completion_debt_evidence")
    if evidence.get("bead") != COMPLETION_DEBT_BEAD:
        fail(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD}")
    if evidence.get("original_bead") != ORIGINAL_BEAD:
        fail(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
    if int(evidence.get("next_audit_score_threshold", 0)) < 800:
        fail("next_audit_score_threshold must be >= 800")
    for ref in evidence.get("implementation_refs", []):
        file_line_ref_exists(ref)
    if len(errors) == before:
        checks["top_level_shape"] = "pass"

    artifacts = require_dict(evidence.get("artifacts"), "artifacts")
    gates = require_dict(evidence.get("gates"), "gates")
    artifact_before = len(errors)
    missing_artifacts = sorted(REQUIRED_ARTIFACT_KEYS - set(artifacts))
    if missing_artifacts:
        fail("artifacts missing keys: " + ", ".join(missing_artifacts))
    for key in REQUIRED_ARTIFACT_KEYS:
        rel = artifacts.get(key)
        if isinstance(rel, str):
            file_exists(rel, f"artifacts.{key}")
        else:
            fail(f"artifacts.{key} must be a string")
    missing_gates = sorted(REQUIRED_GATE_KEYS - set(gates))
    if missing_gates:
        fail("gates missing keys: " + ", ".join(missing_gates))
    for key in REQUIRED_GATE_KEYS:
        rel = gates.get(key)
        if isinstance(rel, str):
            file_exists(rel, f"gates.{key}")
        else:
            fail(f"gates.{key} must be a string")
    if len(errors) == artifact_before:
        checks["artifact_paths_exist"] = "pass"

    binding_before = len(errors)
    observed_bindings = {}
    for binding in require_list(evidence.get("missing_item_bindings"), "missing_item_bindings"):
        if not isinstance(binding, dict):
            fail("missing_item_bindings entries must be objects")
            continue
        section = binding.get("evidence_section")
        missing_item = binding.get("missing_item_id")
        if isinstance(section, str) and isinstance(missing_item, str):
            observed_bindings[section] = missing_item
    if observed_bindings != EXPECTED_MISSING_ITEMS:
        fail(f"missing item bindings drifted: {observed_bindings}")
    for section, missing_item in EXPECTED_MISSING_ITEMS.items():
        section_doc = require_dict(evidence.get(section), section)
        if section_doc.get("missing_item_id") != missing_item:
            fail(f"{section}.missing_item_id must be {missing_item}")
    if len(errors) == binding_before:
        checks["missing_item_bindings"] = "pass"

    source_texts = load_test_sources(evidence, artifacts)

    symbol_before = len(errors)
    symbol_rows = require_list(evidence.get("required_symbols"), "required_symbols")
    seen_symbols = set()
    for index, row in enumerate(symbol_rows):
        if not isinstance(row, dict):
            fail(f"required_symbols[{index}] must be an object")
            continue
        symbol = row.get("symbol")
        family = row.get("family")
        if symbol not in EXPECTED_SYMBOLS:
            fail(f"unexpected required symbol {symbol!r}")
            continue
        seen_symbols.add(symbol)
        if family not in {"resolver", "nss"}:
            fail(f"{symbol}: family must be resolver or nss")
        if not file_line_ref_exists(row.get("abi_ref")):
            fail(f"{symbol}: abi_ref must cite an existing ABI line")
        core_refs = require_list(row.get("core_refs"), f"{symbol}.core_refs")
        if not core_refs:
            fail(f"{symbol}: core_refs must be non-empty")
        for ref in core_refs:
            file_line_ref_exists(ref)
        for mode in ["strict", "hardened"]:
            if mode not in row.get("required_modes", []):
                fail(f"{symbol}: required_modes missing {mode}")
        unit_ok, _ = validate_refs(
            row.get("unit_test_refs"),
            source_texts,
            f"{symbol}.unit_test_refs",
        )
        conf_ok, test_refs = validate_refs(
            row.get("conformance_test_refs"),
            source_texts,
            f"{symbol}.conformance_test_refs",
        )
        if not unit_ok or not conf_ok:
            fail(f"{symbol}: test refs failed validation")
        cases = fixture_cases_for_symbol(artifacts, row.get("fixture"), row.get("fixture_function"))
        case_count = len(cases)
        modes = {
            str(case.get("mode"))
            for case in cases
            if isinstance(case, dict) and isinstance(case.get("mode"), str)
        }
        if case_count < int(row.get("fixture_case_min", 0)):
            fail(
                f"{symbol}: fixture case count below minimum "
                f"{case_count} < {row.get('fixture_case_min')}"
            )
        for mode in row.get("required_modes", []):
            if mode not in modes and "both" not in modes:
                fail(f"{symbol}: fixture cases missing mode {mode}")
        artifact_refs = [
            artifacts.get(row.get("fixture"), ""),
            row.get("abi_ref", ""),
            *core_refs,
        ]
        append_log(
            SYMBOL_EVENT,
            "pass",
            api_family=family,
            symbol=symbol,
            fixture_case_count=case_count,
            artifact_refs=[ref for ref in artifact_refs if isinstance(ref, str)],
            test_refs=test_refs,
        )
        symbol_summaries.append(
            {
                "symbol": symbol,
                "family": family,
                "fixture_case_count": case_count,
                "fixture": artifacts.get(row.get("fixture"), ""),
                "required_modes": row.get("required_modes", []),
            }
        )
    missing_symbols = sorted(EXPECTED_SYMBOLS - seen_symbols)
    if missing_symbols:
        fail("required_symbols missing: " + ", ".join(missing_symbols))
    if len(errors) == symbol_before:
        checks["symbol_contract"] = "pass"
        checks["fixture_case_coverage"] = "pass"

    refs_before = len(errors)
    for section in REQUIRED_SOURCE_TEST_SECTIONS:
        section_doc = require_dict(evidence.get(section), section)
        validate_refs(section_doc.get("required_test_refs"), source_texts, f"{section}.required_test_refs")
    if len(errors) == refs_before:
        checks["test_refs"] = "pass"

    source_before = len(errors)
    hard_parts = load_json(safe_path(artifacts.get("resolver_hard_parts_manifest", "")), "resolver hard-parts manifest")
    semantic = load_json(safe_path(artifacts.get("semantic_kernels_manifest", "")), "semantic kernels manifest")
    fixture_nss = read_workspace_text(artifacts.get("integration_fixture", ""), "integration fixture")
    hard_query_kinds = set(hard_parts.get("required_query_kinds", []))
    if not {"hosts_lookup", "dns_success", "dns_failure", "missing_nss_backend", "cache_consistency"} <= hard_query_kinds:
        fail("resolver hard-parts manifest lost required query-kind breadth")
    semantic_domains = set(semantic.get("required_semantic_domains", []))
    if not {"hosts", "passwd", "group", "resolv_conf", "nsswitch", "dns_cache"} <= semantic_domains:
        fail("semantic kernels manifest lost required resolver/NSS domains")
    for token in ["getpwnam", "getgrnam", "getaddrinfo"]:
        if token not in fixture_nss:
            fail(f"integration fixture missing {token}")
    if len(errors) == source_before:
        checks["e2e_conformance_sources"] = "pass"

structured_before = len(errors)
log_contract = require_dict(evidence.get("structured_log_contract"), "structured_log_contract")
required_events = set(log_contract.get("required_events", []))
if not {PASS_EVENT, SYMBOL_EVENT, SUMMARY_EVENT} <= required_events:
    fail("structured log contract missing required pass events")
if FAIL_EVENT in set(log_contract.get("forbidden_events", [])):
    pass
else:
    fail("structured log contract must forbid fail event on pass")
for field in REQUIRED_LOG_FIELDS:
    if field not in log_contract.get("required_fields", []):
        fail(f"structured log contract missing field {field}")
if len(errors) == structured_before:
    checks["structured_log"] = "pass"

status = "pass" if not errors else "fail"
if errors:
    append_log(
        FAIL_EVENT,
        "fail",
        failure_signature="resolver_nss_family_completion_contract_failed",
    )
else:
    append_log(
        PASS_EVENT,
        "pass",
        api_family="resolver+nss",
        symbol="all",
        fixture_case_count=sum(row["fixture_case_count"] for row in symbol_summaries),
        artifact_refs=list(artifacts.values()),
        test_refs=[
            f"{section}:{EXPECTED_MISSING_ITEMS[section]}"
            for section in REQUIRED_SOURCE_TEST_SECTIONS
        ],
    )
append_log(
    SUMMARY_EVENT,
    status,
    api_family="resolver+nss",
    symbol="all",
    fixture_case_count=sum(row["fixture_case_count"] for row in symbol_summaries),
    artifact_refs=list(artifacts.values()) if artifacts else [],
    test_refs=[symbol["symbol"] for symbol in symbol_summaries],
    failure_signature="none" if not errors else "resolver_nss_family_completion_contract_failed",
)

report = {
    "schema_version": "resolver_nss_family_completion_contract.report.v1",
    "status": status,
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "contract": str(contract_path),
    "checks": checks,
    "summary": {
        "required_symbol_count": len(EXPECTED_SYMBOLS),
        "bound_symbol_count": len({row.get("symbol") for row in symbol_rows if isinstance(row, dict)} & EXPECTED_SYMBOLS),
        "fixture_case_count": sum(row["fixture_case_count"] for row in symbol_summaries),
        "missing_item_count": len(EXPECTED_MISSING_ITEMS),
        "events": [row["event"] for row in logs],
    },
    "symbols": symbol_summaries,
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in logs),
    encoding="utf-8",
)

if errors:
    print("FAIL: resolver/NSS family completion contract", file=sys.stderr)
    for message in errors:
        print(f"- {message}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: resolver/NSS family completion contract "
    f"symbols={len(EXPECTED_SYMBOLS)} fixture_cases={report['summary']['fixture_case_count']}"
)
PY
