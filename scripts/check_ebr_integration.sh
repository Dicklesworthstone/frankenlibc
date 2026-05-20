#!/usr/bin/env bash
# check_ebr_integration.sh — deterministic EBR integration gate for bd-1sp.4
#
# Runs the artifact-emitting EBR integration test and validates the resulting
# structured log/report pair under target/conformance.
#
# Modes:
#   --validate-only  validate existing artifacts only (does not invoke cargo)
#   --rch (default)  delegate the Rust E2E test to rch exec
#   --local          run cargo locally (only for manual fallback)
#
# Artifact path overrides for validate-only harness tests:
#   FRANKENLIBC_EBR_E2E_REPORT=/path/to/ebr_e2e.report.json
#   FRANKENLIBC_EBR_E2E_LOG=/path/to/ebr_e2e.log.jsonl

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${FRANKENLIBC_EBR_E2E_REPORT:-${ROOT}/target/conformance/ebr_e2e.report.json}"
LOG="${FRANKENLIBC_EBR_E2E_LOG:-${ROOT}/target/conformance/ebr_e2e.log.jsonl}"

if [[ $# -gt 1 ]]; then
  echo "$0: expected at most one mode argument" >&2
  exit 2
fi

MODE="rch"
case "${1:-}" in
  ""|--rch)
    MODE="rch"
    ;;
  --validate-only)
    MODE="validate-only"
    ;;
  --local)
    MODE="local"
    ;;
  -h|--help)
    cat <<USAGE
Usage: $0 [--rch | --validate-only | --local]
  --rch (default)   Run the Rust EBR test via 'rch exec -- cargo test'.
  --validate-only   Validate existing artifacts only; never invokes cargo.
  --local           Run 'cargo test' locally for manual fallback.
USAGE
    exit 0
    ;;
  *)
    echo "$0: unknown mode ${1:-}" >&2
    exit 2
    ;;
esac

cd "${ROOT}"

echo "=== EBR Integration Gate (bd-1sp.4) ==="
if [[ "${MODE}" == "rch" ]]; then
  if ! command -v rch >/dev/null 2>&1; then
    echo "rch not available; rerun with --local only for manual fallback" >&2
    exit 2
  fi
  RCH_REQUIRE_REMOTE=1 \
    RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" \
    rch exec -- cargo test -p frankenlibc-membrane --test ebr_integration_test ebr_e2e_emits_structured_artifacts -- --nocapture
elif [[ "${MODE}" == "local" ]]; then
  cargo test -p frankenlibc-membrane --test ebr_integration_test ebr_e2e_emits_structured_artifacts -- --nocapture
fi

python3 - "${REPORT}" "${LOG}" <<'PY'
import json
import sys
from pathlib import Path

root = Path.cwd()
report_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])

if not report_path.is_absolute():
    report_path = root / report_path
if not log_path.is_absolute():
    log_path = root / log_path


def display_path(path):
    try:
        return path.relative_to(root)
    except ValueError:
        return path

if not report_path.exists():
    raise SystemExit(f"FAIL: missing report {report_path}")
if not log_path.exists():
    raise SystemExit(f"FAIL: missing log {log_path}")

report = json.loads(report_path.read_text(encoding="utf-8"))
rows = [
    json.loads(line)
    for line in log_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

required_keys = {
    "trace_id",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
}

if report.get("schema_version") != "v1":
    raise SystemExit("FAIL: report schema_version must be v1")
if report.get("bead") != "bd-1sp.4":
    raise SystemExit("FAIL: report bead must be bd-1sp.4")
if report.get("scenario_id") != "ebr_reclamation_e2e":
    raise SystemExit("FAIL: report scenario_id mismatch")

ebr = report.get("ebr", {})
if ebr.get("total_retired") != 1:
    raise SystemExit("FAIL: ebr.total_retired must be 1")
if ebr.get("total_reclaimed") != 1:
    raise SystemExit("FAIL: ebr.total_reclaimed must be 1")
if int(ebr.get("global_epoch", 0)) < 3:
    raise SystemExit("FAIL: ebr.global_epoch must be >= 3")
if sum(int(v) for v in ebr.get("pending_per_epoch", [])) != 0:
    raise SystemExit("FAIL: pending_per_epoch must sum to 0")

quarantine = report.get("quarantine", {})
if quarantine.get("reclaimed") is not True:
    raise SystemExit("FAIL: quarantine.reclaimed must be true")
if quarantine.get("pending") != 0:
    raise SystemExit("FAIL: quarantine.pending must be 0")

if len(rows) < 5:
    raise SystemExit("FAIL: expected at least 5 structured log rows")

seen_events = set()
for row in rows:
    missing = sorted(required_keys - set(row))
    if missing:
        raise SystemExit(f"FAIL: structured log row missing keys: {missing}")
    seen_events.add(row.get("event"))

for event in ("pin_guard", "retire", "epoch_advance", "quarantine_enqueue", "quarantine_release"):
    if event not in seen_events:
        raise SystemExit(f"FAIL: missing event {event!r} in structured log")

print("PASS: EBR report + structured log validated")
print(f"REPORT={display_path(report_path)}")
print(f"LOG={display_path(log_path)}")
PY
