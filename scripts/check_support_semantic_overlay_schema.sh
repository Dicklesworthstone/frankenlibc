#!/usr/bin/env bash
# check_support_semantic_overlay_schema.sh -- CI gate for bd-bp8fl.1.5
#
# Validates support_semantic_overlay.v1.json against the machine-readable schema
# contract and emits normalized claim rows for downstream gates.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="${FLC_SUPPORT_SEMANTIC_SCHEMA:-${ROOT}/tests/conformance/support_semantic_overlay_schema.v1.json}"
OVERLAY="${FLC_SUPPORT_SEMANTIC_OVERLAY:-${ROOT}/tests/conformance/support_semantic_overlay.v1.json}"
SUPPORT_MATRIX="${FLC_SUPPORT_SEMANTIC_MATRIX:-${ROOT}/support_matrix.json}"
REPLACEMENT_LEVELS="${FLC_SUPPORT_SEMANTIC_REPLACEMENT_LEVELS:-${ROOT}/tests/conformance/replacement_levels.json}"
OUT_DIR="${FLC_SUPPORT_SEMANTIC_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${OUT_DIR}/support_semantic_overlay_schema.report.json"
LOG="${OUT_DIR}/support_semantic_overlay_schema.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${SCHEMA}" "${OVERLAY}" "${SUPPORT_MATRIX}" "${REPLACEMENT_LEVELS}" "${REPORT}" "${LOG}" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
schema_path = Path(sys.argv[2])
overlay_path = Path(sys.argv[3])
support_matrix_path = Path(sys.argv[4])
replacement_levels_path = Path(sys.argv[5])
report_path = Path(sys.argv[6])
log_path = Path(sys.argv[7])

errors = []
checks = {}
events = []
normalized_rows = []
duplicate_symbol_version_nodes = []
stale_source_refs = []


def rel(path):
    path = Path(path)
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def file_sha256(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return "missing"


def git_head():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def load_json(path, label):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        errors.append(f"{label}: failed to parse {path}: {exc}")
        return None


def count_lines(path):
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except Exception:
        return None


schema = load_json(schema_path, "schema") or {}
overlay = load_json(overlay_path, "support_semantic_overlay") or {}
support_matrix = load_json(support_matrix_path, "support_matrix") or {}
replacement_levels = load_json(replacement_levels_path, "replacement_levels") or {}

source_commit = git_head()
artifact_refs = [
    rel(schema_path),
    rel(overlay_path),
    rel(support_matrix_path),
    rel(replacement_levels_path),
]
trace_seed = "|".join(
    [
        schema.get("bead", "bd-bp8fl.1.5"),
        source_commit,
        file_sha256(schema_path),
        file_sha256(overlay_path),
    ]
)
trace_id = hashlib.sha256(trace_seed.encode("utf-8")).hexdigest()[:20]


def event(rule_id, row_id="", symbol="", expected="", actual="", failure_signature="", status="pass"):
    row = {
        "trace_id": trace_id,
        "bead_id": schema.get("bead", "bd-bp8fl.1.5"),
        "row_id": row_id,
        "symbol": symbol,
        "rule_id": rule_id,
        "expected": expected,
        "actual": actual,
        "artifact_refs": artifact_refs,
        "source_commit": source_commit,
        "failure_signature": failure_signature,
        "status": status,
    }
    events.append(row)
    return row


def fail(rule_id, message, row_id="", symbol="", expected="", actual="", failure_signature=""):
    errors.append(message)
    event(
        rule_id,
        row_id=row_id,
        symbol=symbol,
        expected=expected,
        actual=actual,
        failure_signature=failure_signature or rule_id,
        status="fail",
    )


def status_key(name):
    chars = []
    for index, char in enumerate(str(name)):
        if char.isupper() and index > 0:
            chars.append("_")
        chars.append(char.lower())
    return "".join(chars)


def parse_symbol_version(symbol):
    if "*" in symbol:
        return symbol, "pattern", True
    if "@@" in symbol:
        base, version = symbol.split("@@", 1)
        return base, version or "default", False
    if "@" in symbol:
        base, version = symbol.split("@", 1)
        return base, version or "non_default", False
    return symbol, "unversioned", False


def api_family_for_source(source_path, rules):
    source = str(source_path)
    for rule in rules:
        needle = str(rule.get("path_contains", ""))
        if needle and needle in source:
            return str(rule.get("id", "unknown"))
    return "unknown"


required_log_fields = [
    "trace_id",
    "bead_id",
    "row_id",
    "symbol",
    "rule_id",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
required_schema_fields = [
    "schema_version",
    "bead",
    "inputs",
    "top_level_required_fields",
    "overlay_row_required_fields",
    "normalized_claim_fields",
    "allowed_semantic_classes",
    "required_log_fields",
    "expected_current_summary",
]

schema_ok = True
for field in required_schema_fields:
    if field not in schema:
        schema_ok = False
        fail(
            "schema_shape",
            f"schema missing required field {field}",
            expected=field,
            actual="missing",
            failure_signature="schema_shape",
        )
if schema.get("schema_version") != "v1" or schema.get("bead") != "bd-bp8fl.1.5":
    schema_ok = False
    fail(
        "schema_shape",
        "schema must declare schema_version=v1 and bead=bd-bp8fl.1.5",
        expected="schema_version=v1 bead=bd-bp8fl.1.5",
        actual=f"schema_version={schema.get('schema_version')} bead={schema.get('bead')}",
        failure_signature="schema_shape",
    )
if schema.get("required_log_fields") != required_log_fields:
    schema_ok = False
    fail(
        "schema_shape",
        "schema required_log_fields must match the gate log contract",
        expected=str(required_log_fields),
        actual=str(schema.get("required_log_fields")),
        failure_signature="schema_shape",
    )
checks["schema_shape"] = "pass" if schema_ok else "fail"
if schema_ok:
    event("schema_shape", expected="schema manifest complete", actual="pass")

top_level_ok = True
for field in schema.get("top_level_required_fields", []):
    if field not in overlay:
        top_level_ok = False
        fail(
            "overlay_top_level_fields",
            f"overlay missing top-level field {field}",
            expected=field,
            actual="missing",
            failure_signature="missing_required_field",
        )
checks["overlay_top_level_fields"] = "pass" if top_level_ok else "fail"
if top_level_ok:
    event("overlay_top_level_fields", expected="required top-level fields", actual="present")

entries = overlay.get("audited_entries", [])
if not isinstance(entries, list):
    fail(
        "overlay_row_shape",
        "overlay audited_entries must be a list",
        expected="list",
        actual=type(entries).__name__,
        failure_signature="malformed_rows",
    )
    entries = []

semantic_classes = overlay.get("semantic_contract_classes", {})
allowed_semantic = set(schema.get("allowed_semantic_classes", []))
support_taxonomy = support_matrix.get("taxonomy", {})
allowed_support_statuses = {
    key for key, value in support_taxonomy.items() if isinstance(value, str)
}
allowed_support_statuses.update(str(value) for value in schema.get("extra_support_statuses", []))
allowed_oracles = set(str(value) for value in schema.get("allowed_oracle_kinds", []))
oracle_defaults = schema.get("semantic_oracle_defaults", {})
runtime_modes = [str(value) for value in schema.get("runtime_modes", [])]
replacement_level = str(schema.get("default_replacement_level", ""))
allowed_blocked_replacement_levels = set(
    str(value) for value in schema.get("blocked_semantic_replacement_levels", [])
)
replacement_level_names = {
    str(row.get("level"))
    for row in replacement_levels.get("levels", [])
    if isinstance(row, dict)
}
api_rules = schema.get("api_family_rules", [])

enum_ok = True
if set(semantic_classes) != allowed_semantic:
    enum_ok = False
    fail(
        "semantic_class_enum",
        "schema allowed_semantic_classes must match overlay semantic_contract_classes",
        expected=str(sorted(allowed_semantic)),
        actual=str(sorted(semantic_classes)),
        failure_signature="unknown_status",
    )
if replacement_level not in replacement_level_names:
    enum_ok = False
    fail(
        "replacement_level_enum",
        "schema default_replacement_level is not declared by replacement_levels.json",
        expected=str(sorted(replacement_level_names)),
        actual=replacement_level,
        failure_signature="incompatible_replacement_level",
    )
checks["schema_enums"] = "pass" if enum_ok else "fail"
if enum_ok:
    event("schema_enums", expected="semantic/support/replacement enums", actual="pass")

row_ok = True
row_ids = set()
semantic_counts = {}
seen_exact_symbol_versions = {}
symbol_reference_count = 0
exact_symbol_reference_count = 0
wildcard_symbol_reference_count = 0

for entry in entries:
    if not isinstance(entry, dict):
        row_ok = False
        fail(
            "overlay_row_shape",
            "overlay row must be an object",
            expected="object",
            actual=type(entry).__name__,
            failure_signature="malformed_rows",
        )
        continue

    row_id = str(entry.get("id", ""))
    if not row_id:
        row_ok = False
        fail(
            "overlay_row_required_fields",
            "overlay row missing id",
            expected="id",
            actual="missing",
            failure_signature="missing_required_field",
        )
    elif row_id in row_ids:
        row_ok = False
        fail(
            "overlay_row_required_fields",
            f"duplicate overlay row id {row_id}",
            row_id=row_id,
            expected="unique row id",
            actual=row_id,
            failure_signature="duplicate_row_id",
        )
    else:
        row_ids.add(row_id)

    for field in schema.get("overlay_row_required_fields", []):
        if field not in entry:
            row_ok = False
            fail(
                "overlay_row_required_fields",
                f"{row_id or '<missing-id>'}: missing required field {field}",
                row_id=row_id,
                expected=field,
                actual="missing",
                failure_signature="missing_required_field",
            )

    symbols = entry.get("symbols", [])
    if not isinstance(symbols, list) or any(not isinstance(symbol, str) for symbol in symbols):
        row_ok = False
        fail(
            "overlay_row_required_fields",
            f"{row_id}: symbols must be a list of strings",
            row_id=row_id,
            expected="list[str]",
            actual=type(symbols).__name__,
            failure_signature="malformed_symbols",
        )
        symbols = []

    support_status = str(entry.get("support_matrix_status", ""))
    semantic_class = str(entry.get("semantic_class", ""))
    semantic_counts[semantic_class] = semantic_counts.get(semantic_class, 0) + 1

    if support_status not in allowed_support_statuses:
        row_ok = False
        fail(
            "support_status_enum",
            f"{row_id}: unknown support_matrix_status {support_status}",
            row_id=row_id,
            expected=str(sorted(allowed_support_statuses)),
            actual=support_status,
            failure_signature="unknown_status",
        )
    if semantic_class not in allowed_semantic:
        row_ok = False
        fail(
            "semantic_class_enum",
            f"{row_id}: unknown semantic_class {semantic_class}",
            row_id=row_id,
            expected=str(sorted(allowed_semantic)),
            actual=semantic_class,
            failure_signature="unknown_status",
        )

    oracle_kind = str(oracle_defaults.get(semantic_class, "documented_frankenlibc_contract"))
    if oracle_kind not in allowed_oracles:
        row_ok = False
        fail(
            "oracle_kind_enum",
            f"{row_id}: oracle kind {oracle_kind} is not allowed",
            row_id=row_id,
            expected=str(sorted(allowed_oracles)),
            actual=oracle_kind,
            failure_signature="unknown_status",
        )

    if semantic_class != "full_semantics" and replacement_level not in allowed_blocked_replacement_levels:
        row_ok = False
        fail(
            "replacement_level_compatibility",
            f"{row_id}: blocked semantic row cannot claim replacement level {replacement_level}",
            row_id=row_id,
            expected=str(sorted(allowed_blocked_replacement_levels)),
            actual=replacement_level,
            failure_signature="incompatible_replacement_level",
        )

    source_path = str(entry.get("source_path", ""))
    source_line = entry.get("source_line")
    source_abs = root / source_path
    source_line_count = count_lines(source_abs)
    source_fresh = True
    if not source_path or source_line_count is None:
        source_fresh = False
        stale_source_refs.append({"row_id": row_id, "source_path": source_path, "source_line": source_line})
    elif not isinstance(source_line, int) or source_line <= 0 or source_line > source_line_count:
        source_fresh = False
        stale_source_refs.append({"row_id": row_id, "source_path": source_path, "source_line": source_line})
    if not source_fresh:
        row_ok = False
        fail(
            "source_refs_fresh",
            f"{row_id}: stale source ref {source_path}:{source_line}",
            row_id=row_id,
            expected=f"1..{source_line_count or 'missing'}",
            actual=f"{source_path}:{source_line}",
            failure_signature="stale_source_ref",
        )

    api_family = api_family_for_source(source_path, api_rules)
    if api_family == "unknown":
        row_ok = False
        fail(
            "api_family_derivation",
            f"{row_id}: unable to derive api_family from source_path",
            row_id=row_id,
            expected="known api family",
            actual=source_path,
            failure_signature="unknown_api_family",
        )

    row_symbols = symbols if symbols else ["<subsystem>"]
    for raw_symbol in row_symbols:
        symbol_reference_count += 0 if raw_symbol == "<subsystem>" else 1
        symbol, version_node, is_pattern = parse_symbol_version(raw_symbol)
        if is_pattern:
            wildcard_symbol_reference_count += 1
        elif raw_symbol != "<subsystem>":
            exact_symbol_reference_count += 1
            key = (symbol, version_node)
            previous = seen_exact_symbol_versions.get(key)
            if previous is not None:
                row_ok = False
                finding = {
                    "symbol": symbol,
                    "version_node": version_node,
                    "first_row_id": previous,
                    "duplicate_row_id": row_id,
                }
                duplicate_symbol_version_nodes.append(finding)
                fail(
                    "duplicate_symbol_version_node",
                    f"{row_id}: duplicate symbol/version {symbol}@{version_node}",
                    row_id=row_id,
                    symbol=raw_symbol,
                    expected=f"unique symbol/version, first row {previous}",
                    actual=row_id,
                    failure_signature="duplicate_symbol_version_node",
                )
            else:
                seen_exact_symbol_versions[key] = row_id

        normalized_rows.append(
            {
                "row_id": row_id,
                "symbol": symbol,
                "version_node": version_node,
                "api_family": api_family,
                "contract_status": support_status,
                "semantic_status": semantic_class,
                "oracle_kind": oracle_kind,
                "runtime_mode": runtime_modes,
                "replacement_level": replacement_level,
                "source_refs": [{"path": source_path, "line": source_line}],
                "artifact_refs": artifact_refs,
                "freshness_metadata": {
                    "source_commit": source_commit,
                    "overlay_generated_at_utc": overlay.get("generated_at_utc"),
                },
                "known_limitations": entry.get("required_followup", ""),
            }
        )

    event(
        "valid_overlay_row",
        row_id=row_id,
        symbol=",".join(symbols[:3]) if symbols else "<subsystem>",
        expected="row validates and normalizes",
        actual=semantic_class,
    )

checks["overlay_rows"] = "pass" if row_ok else "fail"

summary_ok = True
audited_summary = overlay.get("audited_summary", {})
if audited_summary.get("entries") != len(entries):
    summary_ok = False
    fail(
        "audited_summary_freshness",
        "audited_summary.entries does not match audited_entries length",
        expected=str(len(entries)),
        actual=str(audited_summary.get("entries")),
        failure_signature="stale_audited_summary",
    )
for semantic_class in allowed_semantic:
    expected_count = semantic_counts.get(semantic_class, 0)
    actual_count = audited_summary.get("by_semantic_class", {}).get(semantic_class)
    if actual_count != expected_count:
        summary_ok = False
        fail(
            "audited_summary_freshness",
            f"audited_summary count mismatch for {semantic_class}",
            row_id=semantic_class,
            expected=str(expected_count),
            actual=str(actual_count),
            failure_signature="stale_audited_summary",
        )

support_snapshot = overlay.get("support_matrix_snapshot", {}).get("status_counts", {})
for status, expected_count in support_snapshot.items():
    actual_count = support_matrix.get("counts", {}).get(status_key(status), 0)
    if actual_count != expected_count:
        summary_ok = False
        fail(
            "support_matrix_snapshot_freshness",
            f"support_matrix_snapshot count mismatch for {status}",
            row_id=status,
            expected=str(actual_count),
            actual=str(expected_count),
            failure_signature="stale_support_matrix_snapshot",
        )

checks["artifact_freshness"] = "pass" if summary_ok and not stale_source_refs else "fail"
if summary_ok and not stale_source_refs:
    event("artifact_freshness", expected="overlay summaries and source refs current", actual="pass")

required_normalized_fields = set(schema.get("normalized_claim_fields", []))
normalized_ok = True
for row in normalized_rows:
    missing = required_normalized_fields - set(row)
    if missing:
        normalized_ok = False
        fail(
            "normalized_claim_fields",
            f"{row.get('row_id')}: normalized row missing {sorted(missing)}",
            row_id=row.get("row_id", ""),
            symbol=row.get("symbol", ""),
            expected=str(sorted(required_normalized_fields)),
            actual=str(sorted(row)),
            failure_signature="missing_normalized_claim_field",
        )
checks["normalized_claim_fields"] = "pass" if normalized_ok else "fail"
if normalized_ok:
    event("normalized_claim_fields", expected="all normalized fields present", actual=str(len(normalized_rows)))

expected_summary = schema.get("expected_current_summary", {})
summary = {
    "audited_entry_count": len(entries),
    "normalized_claim_row_count": len(normalized_rows),
    "symbol_reference_count": symbol_reference_count,
    "exact_symbol_reference_count": exact_symbol_reference_count,
    "wildcard_symbol_reference_count": wildcard_symbol_reference_count,
    "duplicate_symbol_version_count": len(duplicate_symbol_version_nodes),
    "stale_source_ref_count": len(stale_source_refs),
    "semantic_class_count": len(semantic_classes),
}

expected_ok = True
if not errors:
    for key, expected_value in expected_summary.items():
        if summary.get(key) != expected_value:
            expected_ok = False
            fail(
                "expected_current_summary",
                f"current summary mismatch for {key}",
                row_id=key,
                expected=str(expected_value),
                actual=str(summary.get(key)),
                failure_signature="stale_expected_summary",
            )
checks["expected_current_summary"] = "pass" if expected_ok else "fail"

status = "pass" if all(value == "pass" for value in checks.values()) and not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": schema.get("bead", "bd-bp8fl.1.5"),
    "status": status,
    "checks": checks,
    "summary": summary,
    "normalized_claim_row_sample": normalized_rows[:5],
    "duplicate_symbol_version_nodes": duplicate_symbol_version_nodes,
    "stale_source_refs": stale_source_refs,
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as fh:
    for row in events:
        fh.write(json.dumps(row, sort_keys=True) + "\n")

print(json.dumps(report, indent=2, sort_keys=True))
if status != "pass":
    sys.exit(1)
PY
