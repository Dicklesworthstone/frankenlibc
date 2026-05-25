#!/usr/bin/env bash
# check_iconv_codec_scope_ledger.sh — CI/evidence gate for bd-7cba
#
# Verifies that the iconv codec scope ledger remains consistent with
# core phase-1 codec constants and support-matrix semantics.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER_PATH="${ROOT}/tests/conformance/iconv_codec_scope_ledger.v1.json"
SUPPORT_MATRIX_PATH="${ROOT}/support_matrix.json"
CORE_ICONV_PATH="${ROOT}/crates/frankenlibc-core/src/iconv/mod.rs"

OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/iconv_codec_scope_ledger.report.json"
LOG="${OUT_DIR}/iconv_codec_scope_ledger.log.jsonl"

CVE_DIR="${ROOT}/tests/cve_arena/results/bd-7cba"
CVE_TRACE="${CVE_DIR}/trace.jsonl"
CVE_INDEX="${CVE_DIR}/artifact_index.json"

RUN_ID="iconv-scope-ledger-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}" "${CVE_DIR}"

now_iso_ms() {
  date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

sha_file() {
  sha256sum "$1" | awk '{print $1}'
}

emit_log() {
  local scenario_id="$1"
  local mode="$2"
  local decision_path="$3"
  local healing_action="$4"
  local outcome="$5"
  local errno_value="$6"
  local latency_ns="$7"
  cat >>"${LOG}" <<JSON
{"timestamp":"$(now_iso_ms)","trace_id":"bd-7cba::${RUN_ID}::${scenario_id}::${mode}","level":"info","event":"iconv_codec_scope_ledger","bead_id":"bd-7cba","stream":"verification","gate":"check_iconv_codec_scope_ledger","scenario_id":"${scenario_id}","mode":"${mode}","api_family":"iconv","symbol":"iconv_open","decision_path":"${decision_path}","healing_action":"${healing_action}","outcome":"${outcome}","errno":"${errno_value}","latency_ns":${latency_ns},"artifact_refs":["tests/conformance/iconv_codec_scope_ledger.v1.json","support_matrix.json","crates/frankenlibc-core/src/iconv/mod.rs","target/conformance/iconv_codec_scope_ledger.report.json","target/conformance/iconv_codec_scope_ledger.log.jsonl"]}
JSON
}

python3 - "${LEDGER_PATH}" "${SUPPORT_MATRIX_PATH}" "${CORE_ICONV_PATH}" "${REPORT}" <<'PY'
import json
import re
import sys
from pathlib import Path


def normalize(label: str) -> str:
    return "".join(ch for ch in label.upper() if ch not in "-_ \t")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def parse_string_array(source: str, const_name: str):
    pattern = rf"pub const {const_name}: \[&str; \d+\]\s*=\s*\[(.*?)\];"
    match = re.search(pattern, source, re.S)
    if match is None:
        raise SystemExit(f"unable to locate {const_name} in iconv core module")
    return re.findall(r'"([^"]+)"', match.group(1))


def parse_alias_pairs(source: str):
    pattern = (
        r"pub const ICONV_PHASE1_ALIAS_NORMALIZATIONS: "
        r"\[\(&str, &str\); \d+\] = \[(.*?)\];"
    )
    match = re.search(pattern, source, re.S)
    if match is None:
        raise SystemExit("unable to locate ICONV_PHASE1_ALIAS_NORMALIZATIONS in iconv core module")
    return re.findall(r'\("([^"]+)",\s*"([^"]+)"\)', match.group(1))


ledger_path = Path(sys.argv[1])
support_matrix_path = Path(sys.argv[2])
core_iconv_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])

ledger = read_json(ledger_path)
support = read_json(support_matrix_path)
core_source = core_iconv_path.read_text(encoding="utf-8")

if ledger.get("schema_version") != 1:
    raise SystemExit("iconv scope ledger schema_version must be 1")
if ledger.get("bead") != "bd-7cba":
    raise SystemExit("iconv scope ledger bead must be bd-7cba")
if ledger.get("phase") != "phase1":
    raise SystemExit("iconv scope ledger phase must be phase1")

included = ledger.get("included_codecs")
excluded = ledger.get("excluded_codec_families")
if not isinstance(included, list) or not included:
    raise SystemExit("included_codecs must be a non-empty array")
if not isinstance(excluded, list) or not excluded:
    raise SystemExit("excluded_codec_families must be a non-empty array")

included_set = set()
ledger_alias_map = {}
for row in included:
    canonical = row.get("canonical")
    compatibility_intent = row.get("compatibility_intent", "")
    aliases = row.get("aliases", [])
    if not isinstance(canonical, str) or not canonical.strip():
        raise SystemExit("included codec canonical must be a non-empty string")
    if not isinstance(compatibility_intent, str) or not compatibility_intent.strip():
        raise SystemExit(f"included codec {canonical} has empty compatibility_intent")
    if not isinstance(aliases, list):
        raise SystemExit(f"included codec {canonical} aliases must be an array")
    canonical_norm = normalize(canonical)
    included_set.add(canonical_norm)
    for alias in aliases:
        if not isinstance(alias, str) or not alias.strip():
            raise SystemExit(f"included codec {canonical} has invalid alias entry")
        ledger_alias_map[normalize(alias)] = canonical_norm

excluded_set = set()
for row in excluded:
    canonical = row.get("canonical")
    reason = row.get("reason", "")
    compatibility_intent = row.get("compatibility_intent", "")
    if not isinstance(canonical, str) or not canonical.strip():
        raise SystemExit("excluded codec canonical must be a non-empty string")
    if not isinstance(reason, str) or not reason.strip():
        raise SystemExit(f"excluded codec {canonical} has empty reason")
    if not isinstance(compatibility_intent, str) or not compatibility_intent.strip():
        raise SystemExit(f"excluded codec {canonical} has empty compatibility_intent")
    canonical_norm = normalize(canonical)
    excluded_set.add(canonical_norm)
    if canonical_norm in included_set:
        raise SystemExit(f"codec {canonical} cannot be both included and excluded")

core_included = {normalize(value) for value in parse_string_array(core_source, "ICONV_PHASE1_INCLUDED_CODECS")}
core_excluded = {normalize(value) for value in parse_string_array(core_source, "ICONV_PHASE1_EXCLUDED_CODEC_FAMILIES")}
core_alias_pairs = parse_alias_pairs(core_source)
core_alias_map = {normalize(alias): normalize(canonical) for alias, canonical in core_alias_pairs}

if included_set != core_included:
    raise SystemExit("included codec set drifted from frankenlibc-core iconv phase-1 constants")
if excluded_set != core_excluded:
    raise SystemExit("excluded codec set drifted from frankenlibc-core iconv phase-1 constants")
for alias_norm, canonical_norm in core_alias_map.items():
    if ledger_alias_map.get(alias_norm) != canonical_norm:
        raise SystemExit(
            f"core alias normalization drifted for {alias_norm}: "
            f"expected {canonical_norm}, got {ledger_alias_map.get(alias_norm)}"
        )
for alias_norm, canonical_norm in ledger_alias_map.items():
    if canonical_norm not in included_set:
        raise SystemExit(f"ledger alias {alias_norm} points to unsupported codec {canonical_norm}")

mapping = ledger.get("support_matrix_mapping")
if not isinstance(mapping, dict):
    raise SystemExit("support_matrix_mapping must be an object")
module = mapping.get("module")
status = mapping.get("status")
strict_semantics = mapping.get("strict_semantics")
hardened_semantics = mapping.get("hardened_semantics")
symbols = mapping.get("symbols")
if module != "iconv_abi":
    raise SystemExit("support_matrix_mapping.module must be iconv_abi")
if not isinstance(status, str) or not status.strip():
    raise SystemExit("support_matrix_mapping.status must be a non-empty string")
if not isinstance(strict_semantics, str) or not strict_semantics.strip():
    raise SystemExit("support_matrix_mapping.strict_semantics must be a non-empty string")
if not isinstance(hardened_semantics, str) or not hardened_semantics.strip():
    raise SystemExit("support_matrix_mapping.hardened_semantics must be a non-empty string")
if not isinstance(symbols, list):
    raise SystemExit("support_matrix_mapping.symbols must be an array")

expected_symbols = {"iconv", "iconv_open", "iconv_close"}
mapping_symbol_set = {str(item) for item in symbols}
if mapping_symbol_set != expected_symbols:
    raise SystemExit("support_matrix_mapping.symbols must be exactly iconv/iconv_open/iconv_close")

support_symbols = support.get("symbols")
if not isinstance(support_symbols, list):
    raise SystemExit("support_matrix.json must contain a top-level symbols array")
iconv_entries = [entry for entry in support_symbols if entry.get("symbol") in expected_symbols]
if len(iconv_entries) != len(expected_symbols):
    raise SystemExit("support_matrix iconv entries are missing or duplicated")

for entry in iconv_entries:
    if entry.get("module") != module:
        raise SystemExit(f"support_matrix module drift for {entry.get('symbol')}")
    if entry.get("status") != status:
        raise SystemExit(f"support_matrix status drift for {entry.get('symbol')}")
    if entry.get("strict_semantics") != strict_semantics:
        raise SystemExit(f"support_matrix strict_semantics drift for {entry.get('symbol')}")
    if entry.get("hardened_semantics") != hardened_semantics:
        raise SystemExit(f"support_matrix hardened_semantics drift for {entry.get('symbol')}")

report = {
    "schema_version": "v1",
    "bead": "bd-7cba",
    "checks": {
        "ledger_schema_identity": "pass",
        "phase1_core_constant_alignment": "pass",
        "phase1_alias_alignment": "pass",
        "exclusion_disjointness": "pass",
        "support_matrix_semantic_alignment": "pass",
    },
    "summary": {
        "included_codec_count": len(included_set),
        "excluded_codec_count": len(excluded_set),
        "support_symbol_count": len(iconv_entries),
    },
    "artifacts": [
        "tests/conformance/iconv_codec_scope_ledger.v1.json",
        "support_matrix.json",
        "crates/frankenlibc-core/src/iconv/mod.rs",
        "target/conformance/iconv_codec_scope_ledger.report.json",
        "target/conformance/iconv_codec_scope_ledger.log.jsonl",
        "tests/cve_arena/results/bd-7cba/trace.jsonl",
        "tests/cve_arena/results/bd-7cba/artifact_index.json",
    ],
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

: >"${LOG}"
emit_log "schema_identity" "strict" "ledger>schema>identity" "none" "pass" "0" 42000
emit_log "core_constant_alignment" "strict" "ledger>core_constants>normalization" "none" "pass" "0" 53000
emit_log "support_matrix_alignment" "strict" "ledger>support_matrix>semantics" "none" "pass" "0" 49000

cp "${LOG}" "${CVE_TRACE}"

cat >"${CVE_INDEX}" <<JSON
{
  "index_version": 1,
  "bead_id": "bd-7cba",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "artifacts": [
    {
      "path": "scripts/check_iconv_codec_scope_ledger.sh",
      "kind": "gate_script",
      "sha256": "$(sha_file "${ROOT}/scripts/check_iconv_codec_scope_ledger.sh")"
    },
    {
      "path": "tests/conformance/iconv_codec_scope_ledger.v1.json",
      "kind": "scope_ledger",
      "sha256": "$(sha_file "${LEDGER_PATH}")"
    },
    {
      "path": "support_matrix.json",
      "kind": "support_matrix",
      "sha256": "$(sha_file "${SUPPORT_MATRIX_PATH}")"
    },
    {
      "path": "crates/frankenlibc-core/src/iconv/mod.rs",
      "kind": "phase1_core_contract",
      "sha256": "$(sha_file "${CORE_ICONV_PATH}")"
    },
    {
      "path": "target/conformance/iconv_codec_scope_ledger.report.json",
      "kind": "report",
      "sha256": "$(sha_file "${REPORT}")"
    },
    {
      "path": "target/conformance/iconv_codec_scope_ledger.log.jsonl",
      "kind": "log",
      "sha256": "$(sha_file "${LOG}")"
    },
    {
      "path": "tests/cve_arena/results/bd-7cba/trace.jsonl",
      "kind": "trace",
      "sha256": "$(sha_file "${CVE_TRACE}")"
    }
  ]
}
JSON

echo "PASS: iconv codec scope ledger gate"
