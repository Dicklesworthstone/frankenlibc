#!/usr/bin/env bash
# check_mode_contract_lock.sh — CI gate for bd-w2c3.3.3
#
# Validates:
# 1) mode contract artifact shape and summary consistency.
# 2) FRANKENLIBC_MODE runtime/docs inventories agree on strict|hardened + immutability.
# 3) config.rs parser contract is strict/hardened-only at env boundary.
# 4) required startup/reentrant test anchors exist in config.rs.
# 5) deterministic evidence report + structured log with mode provenance fields is emitted.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${ROOT}/tests/conformance/mode_contract_lock.v1.json"
RUNTIME_INV="${ROOT}/tests/conformance/runtime_env_inventory.v1.json"
DOCS_INV="${ROOT}/tests/conformance/docs_env_inventory.v1.json"
CONFIG_RS="${ROOT}/crates/frankenlibc-membrane/src/config.rs"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/mode_contract_lock.report.json"
LOG="${OUT_DIR}/mode_contract_lock.log.jsonl"
TRACE_ID="bd-w2c3.3.3-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}"

python3 - "${ARTIFACT}" "${RUNTIME_INV}" "${DOCS_INV}" "${CONFIG_RS}" "${REPORT}" <<'PY'
import json
import pathlib
import re
import sys

artifact_path = pathlib.Path(sys.argv[1])
runtime_inv_path = pathlib.Path(sys.argv[2])
docs_inv_path = pathlib.Path(sys.argv[3])
config_rs_path = pathlib.Path(sys.argv[4])
report_path = pathlib.Path(sys.argv[5])

artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
if artifact.get("schema_version") != "v1":
    raise SystemExit(f"FAIL: schema_version must be v1, got {artifact.get('schema_version')!r}")
if artifact.get("bead") != "bd-w2c3.3.3":
    raise SystemExit(f"FAIL: bead must be bd-w2c3.3.3, got {artifact.get('bead')!r}")

contract = artifact.get("env_contract", {})
if contract.get("env_key") != "FRANKENLIBC_MODE":
    raise SystemExit("FAIL: env_contract.env_key must be FRANKENLIBC_MODE")

allowed_values = contract.get("allowed_values")
if allowed_values != ["strict", "hardened"]:
    raise SystemExit(
        f"FAIL: env_contract.allowed_values must be ['strict','hardened'], got {allowed_values!r}"
    )
if contract.get("default_value") != "strict":
    raise SystemExit("FAIL: env_contract.default_value must be strict")
if "immutable" not in str(contract.get("mutability", "")).lower():
    raise SystemExit("FAIL: env_contract.mutability must describe immutability")

required_fields = artifact.get("required_provenance_fields", [])
mandatory_fields = {
    "trace_id",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
    "resolved_mode",
    "mode_source",
    "mode_cache_state",
}
if not isinstance(required_fields, list):
    raise SystemExit("FAIL: required_provenance_fields must be an array")
missing_fields = sorted(mandatory_fields - set(required_fields))
if missing_fields:
    raise SystemExit(
        f"FAIL: required_provenance_fields missing mandatory fields: {missing_fields}"
    )

summary = artifact.get("summary", {})
if summary.get("allowed_value_count") != len(allowed_values):
    raise SystemExit("FAIL: summary.allowed_value_count mismatch")
if summary.get("required_provenance_field_count") != len(required_fields):
    raise SystemExit("FAIL: summary.required_provenance_field_count mismatch")

anchors = artifact.get("startup_reentrant_test_anchors", [])
if not isinstance(anchors, list) or not anchors:
    raise SystemExit("FAIL: startup_reentrant_test_anchors must be non-empty array")
if summary.get("startup_reentrant_anchor_count") != len(anchors):
    raise SystemExit("FAIL: summary.startup_reentrant_anchor_count mismatch")

cross = artifact.get("cross_inventory_evidence", {})
for field in ("runtime_inventory", "docs_inventory", "drift_gate", "mode_semantics_gate"):
    value = cross.get(field)
    if not isinstance(value, str) or not value:
        raise SystemExit(f"FAIL: cross_inventory_evidence.{field} must be a non-empty string")
    path = artifact_path.parents[2] / value
    if not path.exists():
        raise SystemExit(f"FAIL: cross_inventory_evidence.{field} path missing: {value}")
for gate_field in ("drift_gate", "mode_semantics_gate"):
    gate_path = artifact_path.parents[2] / cross[gate_field]
    if not gate_path.is_file():
        raise SystemExit(f"FAIL: {gate_field} must resolve to a regular file: {cross[gate_field]}")
    if (gate_path.stat().st_mode & 0o111) == 0:
        raise SystemExit(f"FAIL: {gate_field} must be executable: {cross[gate_field]}")

runtime_inv = json.loads(runtime_inv_path.read_text(encoding="utf-8"))
runtime_rows = runtime_inv.get("inventory", [])
mode_row = next((row for row in runtime_rows if row.get("env_key") == "FRANKENLIBC_MODE"), None)
if mode_row is None:
    raise SystemExit("FAIL: runtime inventory missing FRANKENLIBC_MODE row")
metadata = mode_row.get("metadata", {})
runtime_allowed = metadata.get("allowed_values")
if not isinstance(runtime_allowed, list):
    raise SystemExit(
        f"FAIL: runtime inventory FRANKENLIBC_MODE allowed_values must be an array, got {type(runtime_allowed).__name__}"
    )
runtime_allowed_set = {str(v) for v in runtime_allowed}
if not {"strict", "hardened"}.issubset(runtime_allowed_set):
    raise SystemExit(
        f"FAIL: runtime inventory FRANKENLIBC_MODE allowed_values must include strict+hardened, got {runtime_allowed!r}"
    )
for forbidden in ("off", "none", "disabled"):
    if forbidden in runtime_allowed_set:
        raise SystemExit(
            f"FAIL: runtime inventory FRANKENLIBC_MODE allowed_values must not expose benchmark-only token {forbidden!r}"
        )
if metadata.get("default_value") != "strict":
    raise SystemExit("FAIL: runtime inventory FRANKENLIBC_MODE default_value must be strict")
mutability = str(metadata.get("mutability", "")).lower()
if "immutable" not in mutability:
    raise SystemExit(
        "FAIL: runtime inventory FRANKENLIBC_MODE mutability must mention immutable"
    )
parse_rule = str(metadata.get("parse_rule", "")).lower()
if "unknown values resolve to strict" not in parse_rule:
    raise SystemExit(
        "FAIL: runtime inventory FRANKENLIBC_MODE parse_rule must state unknown values resolve to strict"
    )

docs_inv = json.loads(docs_inv_path.read_text(encoding="utf-8"))
docs_rows = docs_inv.get("keys", [])
docs_mode = next((row for row in docs_rows if row.get("env_key") == "FRANKENLIBC_MODE"), None)
if docs_mode is None:
    raise SystemExit("FAIL: docs inventory missing FRANKENLIBC_MODE row")
snippets = [str(hit.get("snippet", "")) for hit in docs_mode.get("mentions", [])]
joined = "\n".join(snippets)
if "strict" not in joined or "hardened" not in joined:
    raise SystemExit(
        "FAIL: docs inventory FRANKENLIBC_MODE mentions must include both strict and hardened"
    )

config_rs = config_rs_path.read_text(encoding="utf-8")
for anchor in anchors:
    name = anchor.get("name")
    path = anchor.get("path")
    if path != "crates/frankenlibc-membrane/src/config.rs":
        raise SystemExit(f"FAIL: unsupported anchor path {path!r}")
    if not name or f"fn {name}" not in config_rs:
        raise SystemExit(f"FAIL: missing startup/reentrant test anchor {name!r} in config.rs")

parse_fn_match = re.search(
    r"fn\s+parse_runtime_mode_env\s*\(.*?\)\s*->\s*SafetyLevel\s*\{(?P<body>.*?)\n\}",
    config_rs,
    flags=re.S,
)
if parse_fn_match is None:
    raise SystemExit("FAIL: parse_runtime_mode_env function not found in config.rs")
parse_body = parse_fn_match.group("body")
if "off" in parse_body and "SafetyLevel::Off" in parse_body:
    raise SystemExit(
        "FAIL: parse_runtime_mode_env must not map env values to SafetyLevel::Off"
    )
if '"hardened"' not in parse_body or '"strict"' not in parse_body:
    raise SystemExit(
        "FAIL: parse_runtime_mode_env must explicitly handle strict and hardened tokens"
    )

report = {
    "schema_version": "v1",
    "bead": "bd-w2c3.3.3",
    "artifact": str(artifact_path),
    "checks": {
        "artifact_shape": "pass",
        "runtime_inventory_alignment": "pass",
        "docs_inventory_alignment": "pass",
        "cross_inventory_gate_paths": "pass",
        "config_parser_contract": "pass",
        "startup_reentrant_anchors": "pass"
    },
    "summary": {
        "allowed_values": allowed_values,
        "required_provenance_fields": len(required_fields),
        "startup_reentrant_anchors": len(anchors)
    }
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(
    "PASS: mode contract lock validated "
    f"(allowed={allowed_values}, provenance_fields={len(required_fields)}, anchors={len(anchors)})"
)
PY

python3 - "${TRACE_ID}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import json
import pathlib
import sys

trace_id, artifact_path, report_path, log_path = sys.argv[1:5]
artifact = json.loads(pathlib.Path(artifact_path).read_text(encoding="utf-8"))
required = set(artifact["required_provenance_fields"])

event = {
    "trace_id": trace_id,
    "mode": "strict",
    "api_family": "runtime_config",
    "symbol": "FRANKENLIBC_MODE",
    "decision_path": "Allow",
    "healing_action": "none",
    "errno": 0,
    "latency_ns": 0,
    "artifact_refs": [artifact_path, report_path],
    "resolved_mode": "strict",
    "mode_source": "env+cache",
    "mode_cache_state": "sticky_after_first_resolution"
}
missing = sorted(required - set(event.keys()))
if missing:
    raise SystemExit(f"FAIL: emitted log event missing required provenance fields: {missing}")

with open(log_path, "w", encoding="utf-8") as f:
    f.write(json.dumps(event, separators=(",", ":")) + "\n")

print(f"PASS: wrote structured provenance log {log_path}")
print(json.dumps(event, separators=(",", ":")))
PY
