#!/usr/bin/env bash
# Fail-closed preflight for cargo validation lanes that must use rch remotely.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${FRANKENLIBC_RCH_PREFLIGHT_OUT_DIR:-${ROOT}/target/rch-remote-admissibility}"
REPORT="${FRANKENLIBC_RCH_PREFLIGHT_REPORT:-${OUT_DIR}/rch_remote_admissibility.report.json}"
LOG="${FRANKENLIBC_RCH_PREFLIGHT_LOG:-${OUT_DIR}/rch_remote_admissibility.log.jsonl}"
APPROVAL_PACKET_SCRIPT="${ROOT}/scripts/generate_rch_pressure_approval_packet.sh"
DEFAULT_COMMAND="cargo test -p frankenlibc-harness --test standalone_owned_unwind_experiment_test -- --nocapture"

mkdir -p "${OUT_DIR}"

if [[ $# -gt 0 ]]; then
  VALIDATION_COMMAND="$*"
else
  VALIDATION_COMMAND="${FRANKENLIBC_RCH_PREFLIGHT_CMD:-${DEFAULT_COMMAND}}"
fi

DRY_RUN_OUTPUT_FILE="${FRANKENLIBC_RCH_PREFLIGHT_DRY_RUN_OUTPUT:-}"
DRY_RUN_STDOUT="${OUT_DIR}/rch_diagnose_dry_run.out"
DRY_RUN_STDERR="${OUT_DIR}/rch_diagnose_dry_run.err"
DRY_RUN_STATUS="${OUT_DIR}/rch_diagnose_dry_run.status"

if [[ -n "${DRY_RUN_OUTPUT_FILE}" ]]; then
  cp "${DRY_RUN_OUTPUT_FILE}" "${DRY_RUN_STDOUT}"
  : >"${DRY_RUN_STDERR}"
  printf '0\n' >"${DRY_RUN_STATUS}"
else
  set +e
  env \
    RCH_REQUIRE_REMOTE=1 \
    RCH_TEST_SLOTS="${RCH_TEST_SLOTS:-1}" \
    RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="${RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS:-30}" \
    RCH_PRIORITY="${RCH_PRIORITY:-high}" \
    rch diagnose --dry-run "${VALIDATION_COMMAND}" >"${DRY_RUN_STDOUT}" 2>"${DRY_RUN_STDERR}"
  status=$?
  set -e
  printf '%s\n' "${status}" >"${DRY_RUN_STATUS}"
fi

python3 - "${ROOT}" "${VALIDATION_COMMAND}" "${DRY_RUN_STDOUT}" "${DRY_RUN_STDERR}" "${DRY_RUN_STATUS}" "${REPORT}" "${LOG}" "${APPROVAL_PACKET_SCRIPT}" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
VALIDATION_COMMAND = sys.argv[2]
DRY_RUN_STDOUT = pathlib.Path(sys.argv[3])
DRY_RUN_STDERR = pathlib.Path(sys.argv[4])
DRY_RUN_STATUS = pathlib.Path(sys.argv[5])
REPORT = pathlib.Path(sys.argv[6])
LOG = pathlib.Path(sys.argv[7])
APPROVAL_PACKET_SCRIPT = pathlib.Path(sys.argv[8])


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def read_status(path: pathlib.Path) -> int | None:
    try:
        return int(read_text(path).strip())
    except ValueError:
        return None


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


stdout = read_text(DRY_RUN_STDOUT)
stderr = read_text(DRY_RUN_STDERR)
dry_run_status = read_status(DRY_RUN_STATUS)
combined = f"{stdout}\n{stderr}"

failure_signatures: list[str] = []
if "[RCH] local" in combined:
    failure_signatures.append("local_fallback_marker")
if "remote required; refusing local fallback" in combined:
    failure_signatures.append("remote_required_refusal")
if "Skip:" in stdout and "worker selection" in stdout.lower():
    failure_signatures.append("worker_selection_skipped")
elif "Skip: no admissible workers" in stdout:
    failure_signatures.append("worker_selection_skipped")
if "no admissible workers" in combined:
    failure_signatures.append("no_admissible_workers")
if "critical_pressure" in combined:
    failure_signatures.append("critical_pressure")
if "RCH-E100" in combined:
    failure_signatures.append("RCH-E100")
if "Would offload:" not in stdout:
    failure_signatures.append("missing_offload_classification")
elif "YES" not in stdout:
    failure_signatures.append("not_classified_for_offload")

if failure_signatures:
    status = "blocked"
    exit_code = 2
elif dry_run_status not in (0, None):
    status = "diagnose_failed"
    exit_code = 2
else:
    status = "admissible"
    exit_code = 0

report: dict[str, Any] = {
    "schema_version": "rch_remote_admissibility_preflight.v1",
    "bead": "bd-xkykd",
    "generated_at_utc": utc_now(),
    "validation_command": VALIDATION_COMMAND,
    "required_remote_env": "RCH_REQUIRE_REMOTE=1",
    "dry_run": {
        "stdout_path": rel(DRY_RUN_STDOUT),
        "stderr_path": rel(DRY_RUN_STDERR),
        "exit_status": dry_run_status,
        "would_offload_seen": "Would offload:" in stdout,
        "worker_selection_skipped": "Skip:" in stdout,
    },
    "status": status,
    "failure_signatures": sorted(set(failure_signatures)),
    "approval_packet_command": str(APPROVAL_PACKET_SCRIPT),
    "operator_message": (
        "Remote rch admissibility is blocked. Generate an approval packet before attempting cargo validation."
        if status != "admissible"
        else "Remote rch admissibility preflight passed."
    ),
    "local_fallback_policy": "[RCH] local is never accepted as validation proof.",
}

event = {
    "schema_version": "rch_remote_admissibility_preflight.event.v1",
    "trace_id": "bd-xkykd::rch-remote-admissibility",
    "generated_at_utc": report["generated_at_utc"],
    "status": status,
    "failure_signatures": report["failure_signatures"],
    "validation_command": VALIDATION_COMMAND,
}

REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

if status == "admissible":
    print(f"rch remote admissibility preflight passed for: {VALIDATION_COMMAND}")
else:
    print(
        "rch remote admissibility preflight blocked; run "
        f"{APPROVAL_PACKET_SCRIPT} for an approval packet. "
        f"failure_signatures={','.join(report['failure_signatures'])}",
        file=sys.stderr,
    )
sys.exit(exit_code)
PY
