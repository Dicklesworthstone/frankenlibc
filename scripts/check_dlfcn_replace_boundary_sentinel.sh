#!/usr/bin/env bash
# check_dlfcn_replace_boundary_sentinel.sh -- bd-b92jd.5.2
#
# Fail-closed sentinel for the dlfcn replace boundary. Refuses standalone
# replacement-level promotion while interpose_only / host_handle_passthrough
# host-delegation call sites remain in dlfcn_abi.rs, and detects any new
# unannotated `resolve_host_symbol_raw("dlopen"|"dlsym"|"dlvsym"|"dlclose")`
# call appearing in the source.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL="${ROOT}/tests/conformance/dlfcn_replace_boundary_sentinel.v1.json"
SOURCE_FILE="${ROOT}/crates/frankenlibc-abi/src/dlfcn_abi.rs"
LEVELS="${ROOT}/tests/conformance/replacement_levels.json"
SUPPORT="${ROOT}/support_matrix.json"

MODE="rch"
case "${1:-}" in
  ""|--rch) MODE="rch" ;;
  --validate-only) MODE="validate-only" ;;
  --local) MODE="local" ;;
  -h|--help)
    cat <<USAGE
Usage: $0 [--rch | --validate-only | --local]
USAGE
    exit 0
    ;;
  *) echo "$0: unknown mode ${1:-}" >&2; exit 2 ;;
esac

for f in "${SENTINEL}" "${SOURCE_FILE}" "${LEVELS}" "${SUPPORT}"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required input: $f" >&2
    exit 2
  fi
done

if ! python3 -c "import json,sys" >/dev/null 2>&1; then
  echo "python3 with stdlib required" >&2
  exit 2
fi

python3 - "${SENTINEL}" "${SOURCE_FILE}" "${LEVELS}" "${SUPPORT}" <<'PY'
import json
import sys
from pathlib import Path

sentinel_path, source_path, levels_path, support_path = (Path(p) for p in sys.argv[1:5])
sentinel = json.loads(sentinel_path.read_text())
source = source_path.read_text()
lines = source.splitlines()
levels = json.loads(levels_path.read_text())
support = json.loads(support_path.read_text())

errors = []

if sentinel.get("schema_version") != "v1":
    errors.append("sentinel.schema_version must be v1")
if sentinel.get("bead") != "bd-b92jd.5.2":
    errors.append("sentinel.bead must be bd-b92jd.5.2")
if not sentinel.get("source_commit"):
    errors.append("sentinel.source_commit must be set")

required_log_fields = [
    "trace_id", "bead_id", "callsite_id", "handle_type",
    "resolution_path", "host_symbol", "annotation",
    "expected_replacement_level", "actual_replacement_level",
    "decision", "artifact_refs", "source_commit", "failure_signature",
]
if sentinel.get("required_log_fields") != required_log_fields:
    errors.append("required_log_fields must match canonical contract")

policy = sentinel.get("policy", {})
if policy.get("default_decision") != "block_until_replace_mode_evidence_current":
    errors.append("policy.default_decision drift")
if policy.get("max_total_host_callsites_at_standalone_levels") != 0:
    errors.append("max_total_host_callsites_at_standalone_levels must be 0")
standalone_levels = policy.get("standalone_replacement_levels") or []
if standalone_levels != ["L2", "L3"]:
    errors.append("standalone_replacement_levels must be ['L2', 'L3']")
for ann in ("interpose_only", "bootstrap_passthrough", "host_handle_passthrough"):
    if ann not in policy.get("allowed_at_L0", []):
        errors.append(f"allowed_at_L0 missing {ann}")
    if ann not in policy.get("allowed_at_L1", []):
        errors.append(f"allowed_at_L1 missing {ann}")
for kind in (
    "unannotated_host_callsite",
    "host_callsite_count_drift",
    "host_callsite_after_standalone_promotion",
    "missing_native_handle_guard",
    "support_matrix_drift",
    "replacement_level_drift_without_evidence",
):
    if kind not in policy.get("rejected_evidence_kinds", []):
        errors.append(f"rejected_evidence_kinds missing {kind}")

# Per-callsite anchor verification
seen_ids = set()
by_symbol = {}
by_annotation = {}
for entry in sentinel.get("host_callsites", []):
    cid = entry.get("callsite_id", "?")
    if cid in seen_ids:
        errors.append(f"duplicate callsite_id {cid}")
    seen_ids.add(cid)
    symbol = entry.get("host_symbol", "?")
    ann = entry.get("annotation", "?")
    by_symbol[symbol] = by_symbol.get(symbol, 0) + 1
    by_annotation[ann] = by_annotation.get(ann, 0) + 1
    pattern = entry.get("source_pattern", "")
    context = entry.get("context_anchor", "")
    if not pattern or not context:
        errors.append(f"callsite {cid}: source_pattern and context_anchor required")
        continue
    ctx_hits = [i for i, l in enumerate(lines) if l == context]
    if len(ctx_hits) != 1:
        errors.append(
            f"callsite {cid}: context_anchor {context!r} matched {len(ctx_hits)} times; must match 1"
        )
        continue
    anchor_idx = ctx_hits[0]
    window = lines[anchor_idx + 1 : anchor_idx + 11]
    if pattern not in window:
        errors.append(
            f"callsite {cid}: source_pattern not found within 10 lines after context_anchor at line {anchor_idx + 1}"
        )

expected = sentinel.get("expected_callsite_counts", {})
if expected.get("total") != len(sentinel.get("host_callsites", [])):
    errors.append("expected_callsite_counts.total drift")
for sym, n in (expected.get("by_host_symbol") or {}).items():
    if by_symbol.get(sym, 0) != n:
        errors.append(f"by_host_symbol[{sym}] drift: expected {n}, got {by_symbol.get(sym, 0)}")
for ann, n in (expected.get("by_annotation") or {}).items():
    if by_annotation.get(ann, 0) != n:
        errors.append(f"by_annotation[{ann}] drift: expected {n}, got {by_annotation.get(ann, 0)}")

raw_calls = source.count("crate::host_resolve::resolve_host_symbol_raw(")
expected_raw = expected.get("resolve_host_symbol_raw_calls_in_source", -1)
if raw_calls != expected_raw:
    errors.append(
        f"resolve_host_symbol_raw( call count in dlfcn_abi.rs = {raw_calls}; sentinel expected {expected_raw}; new unannotated host call detected"
    )

dlvsym_next_calls = source.count("crate::host_resolve::host_dlvsym_next_raw")
expected_dlvsym_next = expected.get("host_dlvsym_next_raw_calls", -1)
if dlvsym_next_calls != expected_dlvsym_next:
    errors.append(
        f"host_dlvsym_next_raw call count drift: got {dlvsym_next_calls}, expected {expected_dlvsym_next}"
    )

# Native-handle guards
for guard in sentinel.get("required_native_handle_guards", []):
    if guard not in source:
        errors.append(f"required native-handle guard missing: {guard}")

# Independent unannotated-call detection
declared = {e.get("host_symbol") for e in sentinel.get("host_callsites", [])}
idx = 0
needle = 'resolve_host_symbol_raw("'
while True:
    pos = source.find(needle, idx)
    if pos == -1:
        break
    start = pos + len(needle)
    end_pos = source.find('"', start)
    if end_pos == -1:
        errors.append("malformed resolve_host_symbol_raw call in dlfcn_abi.rs")
        break
    sym = source[start:end_pos]
    if sym not in declared:
        errors.append(f"drift: resolve_host_symbol_raw({sym!r}) not declared in sentinel")
    idx = end_pos

# Support matrix status check
sm_required = sentinel.get("support_matrix_required_status", {}).get("dlfcn_abi", {})
sm_actual = {
    s.get("symbol"): s.get("status")
    for s in support.get("symbols", []) or []
    if s.get("module") == "dlfcn_abi"
}
for sym, status in sm_required.items():
    if sm_actual.get(sym) != status:
        errors.append(
            f"support_matrix dlfcn_abi::{sym} status drift: got {sm_actual.get(sym)}, expected {status}"
        )

# Replacement-level promotion guard
interpose_count = sum(
    1
    for e in sentinel.get("host_callsites", [])
    if e.get("annotation") in ("interpose_only", "host_handle_passthrough")
)
current_level = levels.get("current_level")
if interpose_count > 0 and current_level in standalone_levels:
    errors.append(
        f"current_level={current_level} but {interpose_count} interpose-only / host-handle delegation site(s) remain — standalone replacement promotion blocked"
    )

print(json.dumps(
    {
        "bead": "bd-b92jd.5.2",
        "gate": "dlfcn-replace-boundary-sentinel",
        "host_callsites": len(sentinel.get("host_callsites", [])),
        "by_annotation": by_annotation,
        "by_host_symbol": by_symbol,
        "resolve_host_symbol_raw_calls_in_source": raw_calls,
        "host_dlvsym_next_raw_calls": dlvsym_next_calls,
        "current_replacement_level": current_level,
        "errors": errors,
        "status": "pass" if not errors else "fail",
    },
    indent=2,
))
sys.exit(0 if not errors else 1)
PY

if [[ "${MODE}" == "validate-only" ]]; then
  exit 0
fi

cd "${ROOT}"
if [[ "${MODE}" == "rch" ]]; then
  if ! command -v rch >/dev/null 2>&1; then
    echo "rch not available; rerun with --local if you must" >&2
    exit 2
  fi
  exec rch exec -- cargo test -p frankenlibc-harness --test dlfcn_replace_boundary_sentinel_test
fi

exec cargo test -p frankenlibc-harness --test dlfcn_replace_boundary_sentinel_test
