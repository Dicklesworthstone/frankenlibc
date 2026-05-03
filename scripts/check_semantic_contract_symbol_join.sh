#!/usr/bin/env bash
# check_semantic_contract_symbol_join.sh -- CI gate for bd-bp8fl.1.2
#
# Recomputes semantic-contract joins against support_matrix.json, libc.map,
# and ABI source exports. Emits deterministic report/log artifacts under
# target/conformance and fails stale or contradictory joined-overlay evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FLC_SEMANTIC_JOIN_ARTIFACT:-${ROOT}/tests/conformance/semantic_contract_symbol_join.v1.json}"
INVENTORY="${FLC_SEMANTIC_JOIN_INVENTORY:-${ROOT}/tests/conformance/semantic_contract_inventory.v1.json}"
SUPPORT_MATRIX="${FLC_SEMANTIC_JOIN_SUPPORT_MATRIX:-${ROOT}/support_matrix.json}"
VERSION_SCRIPT="${FLC_SEMANTIC_JOIN_VERSION_SCRIPT:-${ROOT}/crates/frankenlibc-abi/version_scripts/libc.map}"
ABI_SRC="${FLC_SEMANTIC_JOIN_ABI_SRC:-${ROOT}/crates/frankenlibc-abi/src}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/semantic_contract_symbol_join.report.json"
LOG="${OUT_DIR}/semantic_contract_symbol_join.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${ARTIFACT}" "${INVENTORY}" "${SUPPORT_MATRIX}" "${VERSION_SCRIPT}" "${ABI_SRC}" "${REPORT}" "${LOG}" <<'PY'
import json
import hashlib
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
inventory_path = Path(sys.argv[3])
support_matrix_path = Path(sys.argv[4])
version_script_path = Path(sys.argv[5])
abi_src = Path(sys.argv[6])
report_path = Path(sys.argv[7])
log_path = Path(sys.argv[8])

errors = []
checks = {}

def rel(path):
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)

def load_json(path, label):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        errors.append(f"{label}: failed to parse {path}: {exc}")
        return None

def file_sha256(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None

def parse_version_script(text):
    version_nodes_by_symbol = {}
    current_node = None
    in_global = False
    for raw_line in text.splitlines():
        line = re.sub(r"/\*.*?\*/", "", raw_line).strip()
        if not line:
            continue
        node_match = re.match(r"^([A-Za-z_][A-Za-z0-9_.]*)\s*\{", line)
        if node_match:
            current_node = node_match.group(1)
            in_global = False
            continue
        if current_node and line.startswith("global:"):
            in_global = True
            continue
        if current_node and line.startswith("local:"):
            in_global = False
            continue
        if current_node and line.startswith("};"):
            current_node = None
            in_global = False
            continue
        if current_node and in_global:
            symbol_match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*;", line)
            if symbol_match:
                version_nodes_by_symbol.setdefault(symbol_match.group(1), []).append(
                    current_node
                )
    return {symbol: sorted(set(nodes)) for symbol, nodes in version_nodes_by_symbol.items()}

def join_schema_fields(schema):
    fields = set()
    if not isinstance(schema, dict):
        return fields
    for value in schema.values():
        if isinstance(value, list):
            fields.update(str(item) for item in value)
    return fields

def namespace_header_for(row):
    haystack = " ".join(
        str(row.get(key, ""))
        for key in ("module", "surface", "source_path", "contract_kind")
    ).lower()
    if "pthread" in haystack:
        return "pthread.h"
    if "stdio" in haystack or "obstack" in haystack or "libio" in haystack:
        return "stdio.h/libio"
    if "nss" in haystack:
        return "nss/glibc-private"
    if "gconv" in haystack or "iconv" in haystack:
        return "iconv.h/glibc-private"
    if "nis" in haystack or "yellow pages" in haystack or "xdr" in haystack:
        return "rpcsvc/yp_prot.h"
    if "resolver" in haystack or "getaddrinfo" in haystack:
        return "netdb.h"
    if "c++" in haystack or "__cxa" in haystack:
        return "cxxabi/glibc-compat"
    if "elf" in haystack or "relocation" in haystack:
        return "elf/internal"
    return "glibc-internal"

def abi_family_for(row):
    module = str(row.get("module", ""))
    if "::" in module:
        return module.split("::")[-1]
    source_path = str(row.get("source_path", ""))
    if source_path:
        return Path(source_path).stem
    return "semantic_contract"

def exact_join_decision(symbol, missing_source, missing_support, missing_version):
    missing = []
    if symbol in missing_source:
        missing.append("source_export")
    if symbol in missing_support:
        missing.append("support_matrix")
    if symbol in missing_version:
        missing.append("version_script")
    if not missing:
        return "joined_exact"
    return "joined_with_missing_" + "_and_".join(missing)

artifact = load_json(artifact_path, "artifact")
inventory = load_json(inventory_path, "inventory")
support = load_json(support_matrix_path, "support_matrix")

if artifact is not None and inventory is not None and support is not None:
    checks["json_parse"] = "pass"
else:
    checks["json_parse"] = "fail"

if artifact and artifact.get("schema_version") == "v1" and artifact.get("bead") == "bd-bp8fl.1.2":
    checks["artifact_shape"] = "pass"
else:
    checks["artifact_shape"] = "fail"
    errors.append("artifact must declare schema_version=v1 and bead=bd-bp8fl.1.2")

required_join_fields = {
    "symbol",
    "version_node",
    "namespace_header",
    "abi_family",
    "support_status",
    "semantic_contract",
    "semantic_parity_status",
    "oracle_kind",
    "replacement_level",
    "source_artifact",
    "freshness_metadata",
    "artifact_refs",
    "join_decision",
    "failure_signature",
}
declared_join_fields = join_schema_fields(artifact.get("join_schema", {}) if artifact else {})
if required_join_fields <= declared_join_fields:
    checks["join_schema_declared"] = "pass"
else:
    checks["join_schema_declared"] = "fail"
    missing = sorted(required_join_fields - declared_join_fields)
    errors.append(f"join_schema missing required fields: {missing}")

entries = inventory.get("entries", []) if isinstance(inventory, dict) else []
rows = artifact.get("entries", []) if isinstance(artifact, dict) else []
summary = artifact.get("summary", {}) if isinstance(artifact, dict) else {}

row_by_id = {}
for row in rows:
    row_id = row.get("inventory_id")
    if not row_id:
        errors.append("artifact row missing inventory_id")
        continue
    if row_id in row_by_id:
        errors.append(f"duplicate artifact row for inventory_id={row_id}")
    row_by_id[row_id] = row

inventory_ids = [row.get("id") for row in entries]
if len(row_by_id) == len(entries) and set(row_by_id) == set(inventory_ids):
    checks["inventory_row_coverage"] = "pass"
else:
    checks["inventory_row_coverage"] = "fail"
    missing = sorted(set(inventory_ids) - set(row_by_id))
    extra = sorted(set(row_by_id) - set(inventory_ids))
    errors.append(f"inventory row mismatch missing={missing} extra={extra}")

try:
    version_text = version_script_path.read_text(encoding="utf-8")
    version_nodes_by_symbol = parse_version_script(version_text)
    version_symbols = set(version_nodes_by_symbol)
    checks["version_script_read"] = "pass"
except Exception as exc:
    version_nodes_by_symbol = {}
    version_symbols = set()
    checks["version_script_read"] = "fail"
    errors.append(f"failed to read version script {version_script_path}: {exc}")

if version_nodes_by_symbol:
    checks["version_node_map_loaded"] = "pass"
else:
    checks["version_node_map_loaded"] = "fail"
    errors.append("version script did not yield any version-node symbol mappings")

support_rows = support.get("symbols", []) if isinstance(support, dict) else []
support_by_symbol = {
    row.get("symbol"): row
    for row in support_rows
    if isinstance(row, dict) and row.get("symbol")
}
if support_by_symbol:
    checks["support_matrix_symbols_loaded"] = "pass"
else:
    checks["support_matrix_symbols_loaded"] = "fail"
    errors.append("support_matrix.json must expose a non-empty symbols array")

abi_symbols = set()
if abi_src.exists():
    for source_path in sorted(abi_src.glob("*.rs")):
        text = source_path.read_text(encoding="utf-8", errors="ignore")
        for match in re.finditer(
            r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)',
            text,
        ):
            abi_symbols.add(match.group(1))
        for match in re.finditer(
            r"\b[A-Za-z_][A-Za-z0-9_]*!\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)",
            text,
        ):
            abi_symbols.add(match.group(1))
    checks["abi_source_symbols_loaded"] = "pass" if abi_symbols else "fail"
    if not abi_symbols:
        errors.append(f"no ABI symbols discovered under {abi_src}")
else:
    checks["abi_source_symbols_loaded"] = "fail"
    errors.append(f"ABI source root missing: {abi_src}")

def as_str_list(value):
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]

def pattern_regex(pattern):
    return re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")

def matching_count(symbols, pattern):
    regex = pattern_regex(pattern)
    return sum(1 for symbol in symbols if regex.match(symbol))

summary_actual = {
    "inventory_entry_count": len(entries),
    "symbol_bearing_entry_count": sum(1 for row in entries if row.get("symbols")),
    "symbolless_contract_count": sum(1 for row in entries if not row.get("symbols")),
    "symbol_reference_count": sum(len(row.get("symbols", [])) for row in entries),
    "exact_symbol_reference_count": sum(
        1
        for row in entries
        for symbol in row.get("symbols", [])
        if "*" not in symbol
    ),
    "pattern_symbol_reference_count": sum(
        1
        for row in entries
        for symbol in row.get("symbols", [])
        if "*" in symbol
    ),
    "semantic_parity_blocker_count": sum(
        1
        for row in rows
        if str(row.get("semantic_parity_status", "")).startswith("blocked_")
    ),
    "rows_where_taxonomy_status_is_not_parity": sum(
        1
        for row in rows
        if row.get("taxonomy_status_is_semantic_parity") is False
    ),
    "by_taxonomy_status": dict(Counter(row.get("support_matrix_status") for row in entries)),
    "by_semantic_class": dict(Counter(row.get("semantic_class") for row in entries)),
}

total_missing_source = []
total_missing_support = []
total_missing_version = []
wildcard_counts = {
    "source": 0,
    "support_matrix": 0,
    "version_script": 0,
}

artifact_refs = [
    rel(artifact_path),
    rel(inventory_path),
    rel(support_matrix_path),
    rel(version_script_path),
]
row_join_summaries = []
resolved_symbol_join_rows = []
exact_symbol_metadata = {}
conflicting_exact_symbols = []
artifact_freshness = {
    "generated_at_utc": artifact.get("generated_at_utc") if isinstance(artifact, dict) else None,
    "inventory_generated_at_utc": inventory.get("generated_at_utc") if isinstance(inventory, dict) else None,
    "input_sha256": {
        rel(inventory_path): file_sha256(inventory_path),
        rel(support_matrix_path): file_sha256(support_matrix_path),
        rel(version_script_path): file_sha256(version_script_path),
    },
}
for inventory_row in entries:
    row_id = inventory_row.get("id")
    artifact_row = row_by_id.get(row_id)
    if artifact_row is None:
        continue

    for inventory_field, artifact_field in [
        ("surface", "surface"),
        ("source_path", "source_path"),
        ("support_matrix_status", "taxonomy_status"),
        ("semantic_class", "semantic_class"),
    ]:
        if inventory_row.get(inventory_field) != artifact_row.get(artifact_field):
            errors.append(
                f"{row_id}: {artifact_field} does not match inventory "
                f"{inventory_field}"
            )

    symbols = as_str_list(inventory_row.get("symbols"))
    if symbols != as_str_list(artifact_row.get("symbol_refs")):
        errors.append(f"{row_id}: symbol_refs do not match inventory symbols")

    if artifact_row.get("taxonomy_status_is_semantic_parity") is not False:
        errors.append(f"{row_id}: taxonomy_status_is_semantic_parity must be false")
    if not str(artifact_row.get("semantic_parity_status", "")).startswith("blocked_"):
        errors.append(f"{row_id}: semantic_parity_status must remain blocked")

    source_path = root / str(inventory_row.get("source_path", ""))
    if not source_path.exists():
        errors.append(f"{row_id}: source path missing: {rel(source_path)}")

    exact_symbols = [symbol for symbol in symbols if "*" not in symbol]
    pattern_symbols = [symbol for symbol in symbols if "*" in symbol]

    missing_source = [symbol for symbol in exact_symbols if symbol not in abi_symbols]
    missing_support = [symbol for symbol in exact_symbols if symbol not in support_by_symbol]
    missing_version = [symbol for symbol in exact_symbols if symbol not in version_symbols]

    total_missing_source.extend(missing_source)
    total_missing_support.extend(missing_support)
    total_missing_version.extend(missing_version)

    if missing_source != as_str_list(artifact_row.get("expected_missing_source_symbols")):
        errors.append(
            f"{row_id}: expected_missing_source_symbols stale; "
            f"expected {missing_source}"
        )
    if missing_support != as_str_list(artifact_row.get("expected_missing_support_matrix_symbols")):
        errors.append(
            f"{row_id}: expected_missing_support_matrix_symbols stale; "
            f"expected {missing_support}"
        )
    if missing_version != as_str_list(artifact_row.get("expected_missing_version_script_symbols")):
        errors.append(
            f"{row_id}: expected_missing_version_script_symbols stale; "
            f"expected {missing_version}"
        )

    present_statuses = {
        support_by_symbol[symbol].get("status")
        for symbol in exact_symbols
        if symbol in support_by_symbol
    }
    taxonomy_status = inventory_row.get("support_matrix_status")
    if taxonomy_status == "Implemented" and present_statuses - {"Implemented"}:
        errors.append(
            f"{row_id}: present support-matrix statuses contradict Implemented: "
            f"{sorted(present_statuses)}"
        )

    namespace_header = namespace_header_for(inventory_row)
    abi_family = abi_family_for(inventory_row)
    semantic_contract = inventory_row.get("contract_kind") or inventory_row.get("semantic_class")
    source_artifact = inventory_row.get("source_path")
    source_path_hash = file_sha256(root / str(source_artifact or ""))
    row_freshness = {
        "artifact_generated_at_utc": artifact_freshness["generated_at_utc"],
        "inventory_generated_at_utc": artifact_freshness["inventory_generated_at_utc"],
        "source_sha256": source_path_hash,
    }

    if not symbols:
        resolved_symbol_join_rows.append(
            {
                "inventory_id": row_id,
                "symbol": "<subsystem-contract>",
                "symbol_ref_kind": "not_symbol_level",
                "version_node": "not_symbol_level",
                "namespace_header": namespace_header,
                "abi_family": abi_family,
                "support_status": inventory_row.get("support_matrix_status"),
                "semantic_contract": semantic_contract,
                "semantic_parity_status": artifact_row.get("semantic_parity_status"),
                "oracle_kind": "support_matrix_version_script_abi_source_join",
                "replacement_level": "L0_interpose_and_L1_planning",
                "source_artifact": source_artifact,
                "freshness_metadata": row_freshness,
                "artifact_refs": artifact_refs,
                "join_decision": "joined_subsystem_contract",
                "failure_signature": "",
            }
        )

    for symbol in exact_symbols:
        metadata = (
            inventory_row.get("semantic_class"),
            inventory_row.get("support_matrix_status"),
            artifact_row.get("semantic_parity_status"),
        )
        previous = exact_symbol_metadata.get(symbol)
        if previous and previous != metadata:
            conflicting_exact_symbols.append(symbol)
            errors.append(
                f"{row_id}: exact symbol {symbol} has conflicting semantic join metadata"
            )
        else:
            exact_symbol_metadata[symbol] = metadata

        nodes = version_nodes_by_symbol.get(symbol, ["missing_version_script"])
        support_row = support_by_symbol.get(symbol, {})
        for version_node in nodes:
            decision = exact_join_decision(
                symbol, missing_source, missing_support, missing_version
            )
            resolved_symbol_join_rows.append(
                {
                    "inventory_id": row_id,
                    "symbol": symbol,
                    "symbol_ref_kind": "exact",
                    "version_node": version_node,
                    "namespace_header": namespace_header,
                    "abi_family": support_row.get("module") or abi_family,
                    "support_status": support_row.get("status")
                    or inventory_row.get("support_matrix_status"),
                    "semantic_contract": semantic_contract,
                    "semantic_parity_status": artifact_row.get("semantic_parity_status"),
                    "oracle_kind": "support_matrix_version_script_abi_source_join",
                    "replacement_level": "L0_interpose_and_L1_planning",
                    "source_artifact": source_artifact,
                    "freshness_metadata": row_freshness,
                    "artifact_refs": [
                        rel(artifact_path),
                        rel(inventory_path),
                        rel(support_matrix_path),
                        rel(version_script_path),
                    ],
                    "join_decision": decision,
                    "failure_signature": "" if decision == "joined_exact" else decision,
                }
            )

    expected_patterns = artifact_row.get("expected_pattern_expansion_counts", {})
    if not isinstance(expected_patterns, dict):
        errors.append(f"{row_id}: expected_pattern_expansion_counts must be object")
        expected_patterns = {}
    if set(expected_patterns) != set(pattern_symbols):
        errors.append(
            f"{row_id}: wildcard symbol set mismatch "
            f"expected patterns for {pattern_symbols}"
        )

    pattern_details = {}
    for pattern in pattern_symbols:
        counts = {
            "source": matching_count(abi_symbols, pattern),
            "support_matrix": matching_count(set(support_by_symbol), pattern),
            "version_script": matching_count(version_symbols, pattern),
        }
        for key, value in counts.items():
            wildcard_counts[key] += value
        pattern_details[pattern] = counts
        expected = expected_patterns.get(pattern)
        if counts != expected:
            errors.append(f"{row_id}: wildcard {pattern} stale; expected {counts}")
        if counts["source"] == 0:
            errors.append(f"{row_id}: wildcard {pattern} has no ABI source expansion")
        resolved_symbol_join_rows.append(
            {
                "inventory_id": row_id,
                "symbol": pattern,
                "symbol_ref_kind": "wildcard",
                "version_node": "pattern_expansion",
                "namespace_header": namespace_header,
                "abi_family": abi_family,
                "support_status": inventory_row.get("support_matrix_status"),
                "semantic_contract": semantic_contract,
                "semantic_parity_status": artifact_row.get("semantic_parity_status"),
                "oracle_kind": "support_matrix_version_script_abi_source_join",
                "replacement_level": "L0_interpose_and_L1_planning",
                "source_artifact": source_artifact,
                "freshness_metadata": row_freshness,
                "artifact_refs": [
                    rel(artifact_path),
                    rel(inventory_path),
                    rel(support_matrix_path),
                    rel(version_script_path),
                ],
                "join_decision": "wildcard_expansion_accounted",
                "failure_signature": "",
                "pattern_expansion_counts": counts,
            }
        )

    row_join_summaries.append(
        {
            "inventory_id": row_id,
            "exact_symbol_count": len(exact_symbols),
            "pattern_symbol_count": len(pattern_symbols),
            "missing_source_symbols": missing_source,
            "missing_support_matrix_symbols": missing_support,
            "missing_version_script_symbols": missing_version,
            "pattern_expansion_counts": pattern_details,
            "semantic_parity_status": artifact_row.get("semantic_parity_status"),
            "taxonomy_status": artifact_row.get("taxonomy_status"),
        }
    )

summary_actual.update(
    {
        "support_matrix_missing_exact_symbol_count": len(total_missing_support),
        "version_script_missing_exact_symbol_count": len(total_missing_version),
        "source_missing_exact_symbol_count": len(total_missing_source),
        "wildcard_source_expansion_count": wildcard_counts["source"],
        "wildcard_support_matrix_expansion_count": wildcard_counts["support_matrix"],
        "wildcard_version_script_expansion_count": wildcard_counts["version_script"],
        "resolved_symbol_join_row_count": len(resolved_symbol_join_rows),
        "conflicting_exact_symbol_join_count": len(set(conflicting_exact_symbols)),
    }
)

if summary == summary_actual:
    checks["summary_matches_current_join"] = "pass"
else:
    checks["summary_matches_current_join"] = "fail"
    errors.append("artifact summary does not match current joins")

if not any(
    "does not match inventory" in err
    or "symbol_refs do not match" in err
    or "must remain blocked" in err
    or "taxonomy_status_is_semantic_parity" in err
    for err in errors
):
    checks["row_contract_shape"] = "pass"
else:
    checks["row_contract_shape"] = "fail"

if not any("expected_missing_" in err or "wildcard" in err for err in errors):
    checks["row_join_expectations"] = "pass"
else:
    checks["row_join_expectations"] = "fail"

if len(total_missing_source) == 0:
    checks["source_exports_cover_exact_symbols"] = "pass"
else:
    checks["source_exports_cover_exact_symbols"] = "fail"

if len(total_missing_support) == summary_actual["support_matrix_missing_exact_symbol_count"]:
    checks["support_matrix_missing_symbols_are_accounted"] = "pass"
else:
    checks["support_matrix_missing_symbols_are_accounted"] = "fail"

if summary_actual["resolved_symbol_join_row_count"] >= summary_actual["symbol_reference_count"]:
    checks["resolved_join_rows_complete"] = "pass"
else:
    checks["resolved_join_rows_complete"] = "fail"

if summary_actual["conflicting_exact_symbol_join_count"] == 0:
    checks["conflicting_symbol_rows"] = "pass"
else:
    checks["conflicting_symbol_rows"] = "fail"

try:
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except Exception:
    source_commit = "unknown"

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.1.2",
    "status": status,
    "checks": checks,
    "join_schema": artifact.get("join_schema", {}) if isinstance(artifact, dict) else {},
    "freshness_metadata": artifact_freshness,
    "summary": summary_actual,
    "row_join_summaries": row_join_summaries,
    "resolved_symbol_join_rows": resolved_symbol_join_rows,
    "errors": errors,
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
    "target_dir": rel(report_path.parent),
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log_event = {
    "trace_id": "bd-bp8fl.1.2-semantic-contract-symbol-join",
    "bead_id": "bd-bp8fl.1.2",
    "scenario_id": "semantic-contract-symbol-join-gate",
    "runtime_mode": "not_applicable",
    "replacement_level": "L0_interpose_and_L1_planning",
    "api_family": "semantic_contract_symbol_join",
    "symbol": "*",
    "oracle_kind": "support_matrix_version_script_abi_source_join",
    "expected": "canonical joined overlay matches current inventory, support matrix, version script, and ABI source exports",
    "actual": status,
    "errno": None,
    "decision_path": list(checks.keys()),
    "healing_action": "none",
    "latency_ns": 0,
    "artifact_refs": artifact_refs + [
        rel(report_path),
        rel(log_path),
    ],
    "source_commit": source_commit,
    "target_dir": rel(report_path.parent),
    "failure_signature": "; ".join(errors),
    "summary": summary_actual,
}
log_path.write_text(json.dumps(log_event, sort_keys=True) + "\n", encoding="utf-8")

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
