#!/usr/bin/env bash
# check_stdio_phase_strategy.sh — CI/evidence gate for bd-24ug
#
# Validates deterministic stdio callthrough phase split + migration plan artifact,
# and emits structured evidence logs/reports for verification matrix closure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUPPORT="${ROOT}/support_matrix.json"
ARTIFACT="${ROOT}/tests/conformance/stdio_phase_strategy.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/stdio_phase_strategy.report.json"
LOG="${OUT_DIR}/stdio_phase_strategy.log.jsonl"
CVE_DIR="${ROOT}/tests/cve_arena/results/bd-24ug"
CVE_TRACE="${CVE_DIR}/trace.jsonl"
CVE_INDEX="${CVE_DIR}/artifact_index.json"
RUN_ID="stdio-phase-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}" "${CVE_DIR}"

if [[ ! -f "${SUPPORT}" ]]; then
  echo "FAIL: missing support matrix ${SUPPORT}" >&2
  exit 1
fi
if [[ ! -f "${ARTIFACT}" ]]; then
  echo "FAIL: missing artifact ${ARTIFACT}" >&2
  exit 1
fi

python3 - "${ROOT}" "${SUPPORT}" "${ARTIFACT}" "${REPORT}" "${LOG}" "${CVE_TRACE}" "${CVE_INDEX}" "${RUN_ID}" <<'PY'
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

(
    root_raw,
    support_raw,
    artifact_raw,
    report_raw,
    log_raw,
    cve_trace_raw,
    cve_index_raw,
    run_id,
) = sys.argv[1:9]

root = Path(root_raw)
support_path = Path(support_raw)
artifact_path = Path(artifact_raw)
report_path = Path(report_raw)
log_path = Path(log_raw)
cve_trace_path = Path(cve_trace_raw)
cve_index_path = Path(cve_index_raw)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - gate error path
        fail(f"unable to parse JSON {path}: {exc}")


support = load_json(support_path)
artifact = load_json(artifact_path)

if artifact.get("schema_version") != "v1":
    fail("artifact schema_version must be v1")
if artifact.get("bead") != "bd-24ug":
    fail("artifact bead must be bd-24ug")

symbols = support.get("symbols", [])
if not isinstance(symbols, list) or not symbols:
    fail("support_matrix symbols must be non-empty array")

stdio_callthrough = sorted(
    str(row.get("symbol"))
    for row in symbols
    if row.get("status") == "GlibcCallThrough" and row.get("module") == "stdio_abi"
)
stdio_set = set(stdio_callthrough)
if not stdio_set:
    fail("no stdio_abi GlibcCallThrough symbols found in support_matrix")

phase_split = artifact.get("phase_split", {})
if not isinstance(phase_split, dict):
    fail("phase_split must be an object")

phase1 = phase_split.get("phase1_required", {})
deferred = phase_split.get("deferred_surface", {})
if not isinstance(phase1, dict) or not isinstance(deferred, dict):
    fail("phase_split.phase1_required and phase_split.deferred_surface must be objects")

phase1_symbols = [str(s) for s in phase1.get("symbols", [])]
deferred_symbols = [str(s) for s in deferred.get("symbols", [])]

if not phase1_symbols:
    fail("phase1_required.symbols must be non-empty")
if len(phase1_symbols) != len(set(phase1_symbols)):
    fail("phase1_required.symbols contains duplicates")
if len(deferred_symbols) != len(set(deferred_symbols)):
    fail("deferred_surface.symbols contains duplicates")

phase1_set = set(phase1_symbols)
deferred_set = set(deferred_symbols)

if phase1_set & deferred_set:
    overlap = sorted(phase1_set & deferred_set)
    fail(f"phase split overlap detected: {overlap}")

partition_set = phase1_set | deferred_set
if partition_set != stdio_set:
    missing = sorted(stdio_set - partition_set)
    extra = sorted(partition_set - stdio_set)
    fail(f"phase split mismatch against stdio callthrough set; missing={missing} extra={extra}")

migration = artifact.get("migration_plan", {})
if not isinstance(migration, dict):
    fail("migration_plan must be an object")
phases = migration.get("phases", [])
if not isinstance(phases, list) or not phases:
    fail("migration_plan.phases must be non-empty array")

phase_ids = []
phase_numbers = []
phase_symbol_union = []
for row in phases:
    if not isinstance(row, dict):
        fail("each migration phase must be an object")
    phase_id = str(row.get("phase_id", "")).strip()
    if not phase_id:
        fail("migration phase missing phase_id")
    phase_ids.append(phase_id)

    phase_num = int(row.get("phase", -1))
    if phase_num <= 0:
        fail(f"migration phase {phase_id} has invalid phase number {phase_num}")
    phase_numbers.append(phase_num)

    profile = str(row.get("validation_profile", ""))
    if profile not in {"Fast", "Full"}:
        fail(f"migration phase {phase_id} has invalid validation_profile {profile!r}")

    mode_scope = row.get("mode_scope", [])
    if not isinstance(mode_scope, list) or not mode_scope:
        fail(f"migration phase {phase_id} mode_scope must be non-empty array")
    for mode in mode_scope:
        if mode not in {"strict", "hardened"}:
            fail(f"migration phase {phase_id} has invalid mode_scope value {mode!r}")

    phase_symbols = [str(s) for s in row.get("symbols", [])]
    if not phase_symbols:
        fail(f"migration phase {phase_id} symbols must be non-empty array")
    if len(phase_symbols) != len(set(phase_symbols)):
        fail(f"migration phase {phase_id} has duplicate symbols")
    invalid = sorted(set(phase_symbols) - stdio_set)
    if invalid:
        fail(f"migration phase {phase_id} references unknown stdio symbols: {invalid}")

    phase_symbol_union.extend(phase_symbols)

if len(set(phase_ids)) != len(phase_ids):
    fail("migration_plan.phases contains duplicate phase_id values")
if phase_numbers != sorted(phase_numbers):
    fail("migration phases must be strictly increasing by phase")
if len(phase_symbol_union) != len(set(phase_symbol_union)):
    fail("migration phases assign a stdio symbol more than once")
if set(phase_symbol_union) != stdio_set:
    missing = sorted(stdio_set - set(phase_symbol_union))
    extra = sorted(set(phase_symbol_union) - stdio_set)
    fail(f"migration phase symbol coverage mismatch; missing={missing} extra={extra}")
if not phase1_set.issubset(set(phases[0].get("symbols", []))):
    fail("phase1_required symbols must be included in the first migration phase")

summary = artifact.get("summary", {})
if int(summary.get("total_stdio_callthrough_symbols", -1)) != len(stdio_set):
    fail("summary.total_stdio_callthrough_symbols mismatch")
if int(summary.get("phase_count", -1)) != len(phases):
    fail("summary.phase_count mismatch")
if int(summary.get("phase1_required_count", -1)) != len(phase1_set):
    fail("summary.phase1_required_count mismatch")
if int(summary.get("deferred_count", -1)) != len(deferred_set):
    fail("summary.deferred_count mismatch")

report = {
    "schema_version": "v1",
    "bead": "bd-24ug",
    "checks": {
        "artifact_schema": "pass",
        "support_matrix_alignment": "pass",
        "phase_partition_complete": "pass",
        "migration_plan_valid": "pass",
        "summary_consistent": "pass",
    },
    "summary": {
        "stdio_callthrough_count": len(stdio_set),
        "phase_count": len(phases),
        "phase1_required_count": len(phase1_set),
        "deferred_count": len(deferred_set),
        "phase_ids": phase_ids,
    },
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

now = datetime.now(timezone.utc)
timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
trace_id = f"bd-24ug::{run_id}::001"

event = {
    "timestamp": timestamp,
    "trace_id": trace_id,
    "level": "info",
    "event": "gate_result",
    "bead_id": "bd-24ug",
    "stream": "conformance",
    "gate": "check_stdio_phase_strategy",
    "mode": "strict",
    "api_family": "stdio",
    "symbol": "phase_strategy",
    "outcome": "pass",
    "errno": 0,
    "latency_ns": 0,
    "artifact_refs": [
        artifact_path.relative_to(root).as_posix(),
        report_path.relative_to(root).as_posix(),
        log_path.relative_to(root).as_posix(),
    ],
    "details": {
        "phase_count": len(phases),
        "phase1_required_count": len(phase1_set),
        "deferred_count": len(deferred_set),
    },
}
line = json.dumps(event, separators=(",", ":"))
log_path.write_text(line + "\n", encoding="utf-8")
cve_trace_path.write_text(line + "\n", encoding="utf-8")


def sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


artifact_items = []
for path in [artifact_path, report_path, log_path, cve_trace_path]:
    rel = path.relative_to(root).as_posix()
    if rel.endswith(".jsonl"):
        kind = "log"
    elif rel.endswith(".report.json"):
        kind = "report"
    elif rel.endswith("stdio_phase_strategy.v1.json"):
        kind = "golden"
    else:
        kind = "snapshot"
    artifact_items.append(
        {
            "path": rel,
            "kind": kind,
            "sha256": sha256_hex(path),
            "size_bytes": path.stat().st_size,
            "description": "bd-24ug stdio phase strategy verification artifact",
        }
    )

index = {
    "index_version": 1,
    "run_id": run_id,
    "bead_id": "bd-24ug",
    "generated_utc": timestamp,
    "artifacts": artifact_items,
}
cve_index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")

print(
    "PASS: stdio phase strategy validated "
    f"(symbols={len(stdio_set)}, phase1={len(phase1_set)}, deferred={len(deferred_set)})"
)
print(f"PASS: wrote report {report_path.relative_to(root).as_posix()}")
print(f"PASS: wrote logs {log_path.relative_to(root).as_posix()} and {cve_trace_path.relative_to(root).as_posix()}")
print(f"PASS: wrote artifact index {cve_index_path.relative_to(root).as_posix()}")
PY
