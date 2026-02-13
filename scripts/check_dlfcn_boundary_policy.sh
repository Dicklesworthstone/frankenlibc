#!/usr/bin/env bash
# check_dlfcn_boundary_policy.sh — CI gate for bd-33zg
#
# Validates:
# 1) dlfcn boundary policy artifact shape and declared contracts.
# 2) dlfcn ABI host call-through paths exactly match approved fallback policy.
# 3) support matrix, mode semantics, and docs reflect exact dlfcn status.
# 4) replacement profile keeps dlfcn in interpose allowlist and replacement-forbid posture.
# 5) deterministic report + structured JSONL log + SHA256 artifact index are emitted.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT}/tests/conformance/dlfcn_boundary_policy.v1.json"
DLFCN_ABI="${ROOT}/crates/frankenlibc-abi/src/dlfcn_abi.rs"
SUPPORT="${ROOT}/support_matrix.json"
MODE_MATRIX="${ROOT}/tests/conformance/mode_semantics_matrix.json"
REPLACEMENT_PROFILE="${ROOT}/tests/conformance/replacement_profile.json"
README="${ROOT}/README.md"
PARITY="${ROOT}/FEATURE_PARITY.md"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/dlfcn_boundary_policy.report.json"
LOG="${OUT_DIR}/dlfcn_boundary_policy.log.jsonl"
ARTIFACT_INDEX="${OUT_DIR}/dlfcn_boundary_policy.artifact_index.json"
RUN_ID="run-$(date -u +%Y%m%dT%H%M%SZ)-$$"
TRACE_ID="bd-33zg::${RUN_ID}::001"

mkdir -p "${OUT_DIR}"

python3 - "${POLICY}" "${DLFCN_ABI}" "${SUPPORT}" "${MODE_MATRIX}" "${REPLACEMENT_PROFILE}" "${README}" "${PARITY}" "${REPORT}" <<'PY'
import json
import pathlib
import re
import sys

(
    policy_path,
    dlfcn_abi_path,
    support_path,
    mode_matrix_path,
    replacement_profile_path,
    readme_path,
    parity_path,
    report_path,
) = [pathlib.Path(p) for p in sys.argv[1:9]]

policy = json.loads(policy_path.read_text(encoding="utf-8"))
if policy.get("schema_version") != "v1":
    raise SystemExit("FAIL: schema_version must be v1")
if policy.get("bead") != "bd-33zg":
    raise SystemExit("FAIL: bead must be bd-33zg")

summary = policy.get("summary", {})
required_fields = [
    "surface_classification",
    "guard_rails",
    "support_matrix_contract",
    "mode_semantics_contract",
    "docs_contract",
    "structured_log_required_fields",
]
for key in required_fields:
    if key not in policy:
        raise SystemExit(f"FAIL: policy missing required key {key!r}")

surface = policy["surface_classification"]
symbols = surface.get("symbols", [])
if symbols != ["dlopen", "dlsym", "dlclose", "dlerror"]:
    raise SystemExit(f"FAIL: unexpected dlfcn symbol set: {symbols!r}")

approved_host_calls = policy["guard_rails"].get("approved_host_calls", {})
if set(approved_host_calls) != {"dlopen", "dlsym", "dlclose"}:
    raise SystemExit("FAIL: approved_host_calls must contain dlopen,dlsym,dlclose")

abi_lines = dlfcn_abi_path.read_text(encoding="utf-8").splitlines()
call_re = re.compile(r"libc::([a-z_][a-z0-9_]*)\s*\(")
actual_counts = {k: 0 for k in approved_host_calls}
unapproved_calls = []

for lineno, line in enumerate(abi_lines, start=1):
    stripped = line.strip()
    if stripped.startswith("//"):
        continue
    for m in call_re.finditer(line):
        func = m.group(1)
        if not func.startswith("dl"):
            continue
        if func in actual_counts:
            actual_counts[func] += 1
        else:
            unapproved_calls.append(f"{dlfcn_abi_path}:{lineno} libc::{func}(...)")

if unapproved_calls:
    raise SystemExit(
        "FAIL: unapproved dlfcn host call-through detected:\n  " + "\n  ".join(unapproved_calls)
    )

for func, expected in approved_host_calls.items():
    actual = actual_counts.get(func, 0)
    if actual != expected:
        raise SystemExit(
            f"FAIL: approved host call count mismatch for {func}: expected={expected} actual={actual}"
        )

for anchor in policy["guard_rails"].get("required_code_anchors", []):
    if anchor not in dlfcn_abi_path.read_text(encoding="utf-8"):
        raise SystemExit(f"FAIL: missing required code anchor in dlfcn_abi.rs: {anchor!r}")

for forbidden in policy["guard_rails"].get("forbidden_code_patterns", []):
    if forbidden in dlfcn_abi_path.read_text(encoding="utf-8"):
        raise SystemExit(f"FAIL: forbidden dlfcn fallback pattern present: {forbidden!r}")

support = json.loads(support_path.read_text(encoding="utf-8"))
rows = support.get("symbols", [])
row_by_symbol = {str(row.get("symbol")): row for row in rows}
expected_status = policy["support_matrix_contract"]["expected_status"]
expected_strict = policy["support_matrix_contract"]["strict_semantics"]
expected_hardened = policy["support_matrix_contract"]["hardened_semantics"]

for symbol in symbols:
    if symbol not in row_by_symbol:
        raise SystemExit(f"FAIL: support_matrix missing symbol {symbol}")
    row = row_by_symbol[symbol]
    if row.get("module") != "dlfcn_abi":
        raise SystemExit(f"FAIL: support_matrix {symbol} module mismatch: {row.get('module')!r}")
    if row.get("status") != expected_status:
        raise SystemExit(
            f"FAIL: support_matrix {symbol} status mismatch: expected={expected_status} actual={row.get('status')!r}"
        )
    if row.get("strict_semantics") != expected_strict:
        raise SystemExit(
            f"FAIL: support_matrix {symbol} strict_semantics mismatch: {row.get('strict_semantics')!r}"
        )
    if row.get("hardened_semantics") != expected_hardened:
        raise SystemExit(
            f"FAIL: support_matrix {symbol} hardened_semantics mismatch: {row.get('hardened_semantics')!r}"
        )

mode_matrix = json.loads(mode_matrix_path.read_text(encoding="utf-8"))
families = mode_matrix.get("families", [])
loader = None
for fam in families:
    if fam.get("module") == "dlfcn_abi" and fam.get("family") == policy["mode_semantics_contract"]["family"]:
        loader = fam
        break
if loader is None:
    raise SystemExit("FAIL: mode_semantics_matrix missing Loader/dlfcn_abi row")
if loader.get("strict_behavior", {}).get("invalid_flags") != policy["mode_semantics_contract"]["strict_invalid_flags"]:
    raise SystemExit("FAIL: mode_semantics_matrix strict invalid_flags drift for dlfcn")
if loader.get("hardened_behavior", {}).get("invalid_flags") != policy["mode_semantics_contract"]["hardened_invalid_flags"]:
    raise SystemExit("FAIL: mode_semantics_matrix hardened invalid_flags drift for dlfcn")

replacement = json.loads(replacement_profile_path.read_text(encoding="utf-8"))
allowlist = replacement.get("interpose_allowlist", {}).get("modules", [])
if "dlfcn_abi" not in allowlist:
    raise SystemExit("FAIL: replacement_profile interpose_allowlist must include dlfcn_abi")
if replacement.get("replacement_forbidden", {}).get("enforcement") != "scripts/check_replacement_guard.sh":
    raise SystemExit("FAIL: replacement_profile replacement_forbidden.enforcement drift")

census = replacement.get("call_through_census", {}).get("modules", {}).get("dlfcn_abi", {})
if census.get("count") != 4:
    raise SystemExit("FAIL: replacement_profile dlfcn_abi call-through count must remain 4")
functions = set(census.get("functions", []))
if functions != {"dlopen", "dlsym", "dlclose"}:
    raise SystemExit(
        f"FAIL: replacement_profile dlfcn_abi functions must be dlopen/dlsym/dlclose, got {sorted(functions)!r}"
    )

docs_contract = policy.get("docs_contract", {})
doc_texts = {
    "README.md": readme_path.read_text(encoding="utf-8"),
    "FEATURE_PARITY.md": parity_path.read_text(encoding="utf-8"),
}
for doc_name, markers in docs_contract.items():
    text = doc_texts.get(doc_name)
    if text is None:
        raise SystemExit(f"FAIL: unsupported docs_contract key {doc_name!r}")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"FAIL: missing docs marker in {doc_name}: {marker!r}")

if summary.get("symbol_count") != len(symbols):
    raise SystemExit("FAIL: summary.symbol_count mismatch")
if summary.get("approved_host_call_sites") != sum(actual_counts.values()):
    raise SystemExit("FAIL: summary.approved_host_call_sites mismatch")
if summary.get("approved_fallback_paths") != len(surface["interpose_profile"].get("allowed_fallbacks", [])):
    raise SystemExit("FAIL: summary.approved_fallback_paths mismatch")
expected_doc_markers = sum(len(v) for v in docs_contract.values())
if summary.get("docs_marker_count") != expected_doc_markers:
    raise SystemExit("FAIL: summary.docs_marker_count mismatch")

report = {
    "schema_version": "v1",
    "bead": "bd-33zg",
    "artifact": str(policy_path),
    "checks": {
        "policy_shape": "pass",
        "approved_host_calls": "pass",
        "forbidden_fallback_paths": "pass",
        "support_matrix_alignment": "pass",
        "mode_semantics_alignment": "pass",
        "replacement_profile_alignment": "pass",
        "docs_alignment": "pass"
    },
    "summary": {
        "symbol_count": len(symbols),
        "approved_host_call_sites": sum(actual_counts.values()),
        "approved_host_calls": actual_counts,
        "allowed_fallbacks": len(surface["interpose_profile"].get("allowed_fallbacks", []))
    }
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(
    "PASS: dlfcn boundary policy validated "
    f"(symbols={len(symbols)}, host_calls={sum(actual_counts.values())}, fallbacks={len(surface['interpose_profile'].get('allowed_fallbacks', []))})"
)
PY

python3 - "${POLICY}" "${REPORT}" "${LOG}" "${TRACE_ID}" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

policy_path = pathlib.Path(sys.argv[1])
report_path = pathlib.Path(sys.argv[2])
log_path = pathlib.Path(sys.argv[3])
trace_id = sys.argv[4]

policy = json.loads(policy_path.read_text(encoding="utf-8"))
required = set(policy.get("structured_log_required_fields", []))

event = {
    "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    "trace_id": trace_id,
    "level": "info",
    "event": "dlfcn_boundary_policy_check",
    "bead_id": "bd-33zg",
    "stream": "conformance",
    "gate": "check_dlfcn_boundary_policy",
    "mode": "strict",
    "api_family": "Loader",
    "symbol": "dlfcn_abi",
    "outcome": "pass",
    "errno": 0,
    "latency_ns": 0,
    "artifact_refs": [str(policy_path), str(report_path)],
    "details": {
        "unapproved_fallback_outcome": policy["guard_rails"]["unapproved_fallback_outcome"]
    }
}
missing = sorted(required - set(event.keys()))
if missing:
    raise SystemExit(f"FAIL: log event missing required fields: {missing}")
log_path.write_text(json.dumps(event, separators=(",", ":")) + "\n", encoding="utf-8")
print(f"PASS: wrote structured log {log_path}")
print(json.dumps(event, separators=(",", ":")))
PY

python3 - "${POLICY}" "${REPORT}" "${LOG}" "${ARTIFACT_INDEX}" "${RUN_ID}" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

policy_path = pathlib.Path(sys.argv[1])
report_path = pathlib.Path(sys.argv[2])
log_path = pathlib.Path(sys.argv[3])
index_path = pathlib.Path(sys.argv[4])
run_id = sys.argv[5]


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

artifacts = [
    {
        "path": str(policy_path),
        "kind": "golden",
        "sha256": sha256_file(policy_path),
        "size_bytes": policy_path.stat().st_size,
        "description": "Canonical dlfcn boundary policy artifact"
    },
    {
        "path": str(report_path),
        "kind": "report",
        "sha256": sha256_file(report_path),
        "size_bytes": report_path.stat().st_size,
        "description": "dlfcn boundary policy gate report"
    },
    {
        "path": str(log_path),
        "kind": "log",
        "sha256": sha256_file(log_path),
        "size_bytes": log_path.stat().st_size,
        "description": "Structured dlfcn boundary policy JSONL log"
    }
]

index = {
    "index_version": 1,
    "run_id": run_id,
    "bead_id": "bd-33zg",
    "generated_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    "artifacts": artifacts
}
index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
print(f"PASS: wrote artifact index {index_path}")
PY

echo "check_dlfcn_boundary_policy: PASS"
