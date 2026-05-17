#!/usr/bin/env bash
# Generate an approval-safe packet when rch worker selection is blocked by pressure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${FRANKENLIBC_RCH_PACKET_OUT_DIR:-${ROOT}/target/rch-pressure-approval-packet}"
REPORT="${FRANKENLIBC_RCH_PACKET_REPORT:-${OUT_DIR}/rch_pressure_approval_packet.report.json}"
MARKDOWN="${FRANKENLIBC_RCH_PACKET_MARKDOWN:-${OUT_DIR}/rch_pressure_approval_packet.approval.md}"
FOCUS_CMD="${FRANKENLIBC_RCH_PACKET_FOCUS_CMD:-cargo test -p frankenlibc-harness --test standalone_owned_unwind_experiment_test -- --nocapture}"
SSH_ENABLED="${FRANKENLIBC_RCH_PACKET_SSH:-1}"
SSH_KEY="${FRANKENLIBC_RCH_PACKET_SSH_KEY:-${HOME}/.ssh/contabo_vps_ed25519}"
SSH_TIMEOUT_SECS="${FRANKENLIBC_RCH_PACKET_SSH_TIMEOUT_SECS:-25}"
MAX_WORKERS="${FRANKENLIBC_RCH_PACKET_MAX_WORKERS:-6}"
PACKET_ID="${FRANKENLIBC_RCH_PACKET_ID:-frankenlibc-rch-pressure-$(date -u +%Y%m%dT%H%M%SZ)}"
RAW_DIR="${OUT_DIR}/raw/${PACKET_ID}"

mkdir -p "${RAW_DIR}"

capture() {
  local name="$1"
  shift
  local out="${RAW_DIR}/${name}.out"
  local err="${RAW_DIR}/${name}.err"
  local status_file="${RAW_DIR}/${name}.status"
  set +e
  "$@" >"${out}" 2>"${err}"
  local status=$?
  set -e
  printf '%s\n' "${status}" >"${status_file}"
}

capture git_status git -C "${ROOT}" status --short --branch
capture git_head git -C "${ROOT}" rev-parse HEAD
capture git_origin_main git -C "${ROOT}" rev-parse origin/main
capture git_origin_master git -C "${ROOT}" rev-parse origin/master
capture git_worktrees git -C "${ROOT}" worktree list
capture rch_status rch --json status --workers
capture rch_dry_run env \
  RCH_REQUIRE_REMOTE=1 \
  RCH_TEST_SLOTS="${RCH_TEST_SLOTS:-1}" \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="${RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS:-30}" \
  RCH_PRIORITY="${RCH_PRIORITY:-high}" \
  rch diagnose --dry-run "${FOCUS_CMD}"

if [[ "${SSH_ENABLED}" == "1" && -s "${RAW_DIR}/rch_status.out" && -r "${SSH_KEY}" ]] && command -v jq >/dev/null 2>&1; then
  mapfile -t worker_rows < <(
    jq -r '.data.daemon.workers[]? | select(.status == "healthy" and .pressure_state == "critical") | [.id, .host] | @tsv' \
      "${RAW_DIR}/rch_status.out"
  )
  for worker_row in "${worker_rows[@]:0:${MAX_WORKERS}}"; do
        IFS=$'\t' read -r worker_id host <<<"${worker_row}"
        [[ -n "${worker_id}" && -n "${host}" ]] || continue
        safe_id="$(printf '%s' "${worker_id}" | tr -cd 'A-Za-z0-9_.-')"
        set +e
        timeout "${SSH_TIMEOUT_SECS}" ssh \
          -i "${SSH_KEY}" \
          -o BatchMode=yes \
          -o StrictHostKeyChecking=accept-new \
          -o ConnectTimeout=8 \
          "ubuntu@${host}" \
          "bash -lc 'set -o pipefail
            hostname || true
            df -h / /tmp || true
            if command -v sbh >/dev/null 2>&1; then
              sbh status || true
              sudo -n sbh ballast status || true
            else
              printf \"%s\\n\" \"sbh: not installed\"
            fi
            shopt -s nullglob
            du -sh /tmp/rch-* /tmp/rch_target_* 2>/dev/null | sort -h | tail -40 || true
            find /data/projects -maxdepth 2 -type d \\( -name target -o -name \"target_*\" -o -name \"target-*\" \\) -prune -exec du -sh {} + 2>/dev/null | sort -h | tail -40 || true
            find /data/projects -maxdepth 2 -type d -name \".rch-target-*\" -prune -exec du -sh {} + 2>/dev/null | sort -h | tail -5 || true
            find /data/projects -maxdepth 5 -type d -path \"*/.rch-target-*/debug/incremental/*\" -prune -exec du -sh {} + 2>/dev/null | sort -h | tail -5 || true
          '" >"${RAW_DIR}/worker_${safe_id}.out" 2>"${RAW_DIR}/worker_${safe_id}.err"
        status=$?
        set -e
        printf '%s\n' "${status}" >"${RAW_DIR}/worker_${safe_id}.status"
  done
fi

python3 - "${ROOT}" "${RAW_DIR}" "${REPORT}" "${MARKDOWN}" "${PACKET_ID}" "${FOCUS_CMD}" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
RAW_DIR = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
MARKDOWN = pathlib.Path(sys.argv[4])
PACKET_ID = sys.argv[5]
FOCUS_CMD = sys.argv[6]


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def text(name: str) -> str:
    path = RAW_DIR / f"{name}.out"
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def err_text(name: str) -> str:
    path = RAW_DIR / f"{name}.err"
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def status(name: str) -> int | None:
    path = RAW_DIR / f"{name}.status"
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except ValueError:
        return None


def line_list(value: str) -> list[str]:
    return [line for line in value.splitlines() if line.strip()]


def scalar(value: str) -> str | None:
    lines = line_list(value)
    return lines[0] if lines else None


def load_status_json() -> dict[str, Any]:
    try:
        return json.loads(text("rch_status"))
    except Exception as exc:
        return {"success": False, "parse_error": str(exc), "raw": text("rch_status")}


def worker_probe_signature(worker_id: str, worker_status: str) -> str:
    worker_err = err_text(f"worker_{worker_id}")
    worker_out = text(f"worker_{worker_id}")
    if status(f"worker_{worker_id}") == 0:
        return "ok"
    if "RCH-E100" in worker_err or "RCH-E100" in worker_out:
        return "RCH-E100"
    if status(f"worker_{worker_id}") == 124:
        return "timeout"
    if worker_status == "disabled":
        return "not_probed"
    return "unknown"


def cleanup_candidates(worker_id: str, worker_out: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for line in worker_out.splitlines():
        match = re.match(r"^(?P<size>\S+)\s+(?P<path>/data/projects/\S+)$", line.strip())
        if not match:
            continue
        path = match.group("path")
        size = match.group("size")
        is_target_artifact = "/target" in path
        is_rch_artifact = "/.rch-target-" in path
        if not (is_target_artifact or is_rch_artifact):
            continue
        if not re.search(r"[0-9](G|T)$", size) and not (is_rch_artifact and re.search(r"[0-9](M|G|T)$", size)):
            continue
        candidate_kind = "build_incremental_dir" if "/debug/incremental/" in path else "build_target_dir"
        if candidate_kind == "build_incremental_dir" and any(
            path.startswith(f"{candidate['path'].rstrip('/')}/")
            for candidate in candidates
            if candidate.get("candidate_kind") == "build_target_dir" and "/.rch-target-" in str(candidate.get("path"))
        ):
            continue
        candidates.append(
            {
                "worker_id": worker_id,
                "path": path,
                "size_human": size,
                "size_bytes": None,
                "source_command": "bounded read-only du/find over target, .rch-target, and .rch-target debug/incremental directories",
                "candidate_kind": candidate_kind,
                "reason_it_might_help": "Build-output artifact on a worker excluded by rch pressure policy; even sub-GiB .rch-target artifacts can unblock near-threshold workers.",
                "risk_notes": "Deletion-level cleanup requires explicit written approval for this exact path.",
                "requires_explicit_approval": True,
                "executed": False,
            }
        )
    return candidates


def parse_workers(status_json: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    workers = status_json.get("data", {}).get("daemon", {}).get("workers", [])
    parsed: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    if not isinstance(workers, list):
        return parsed, candidates
    for worker in workers:
        if not isinstance(worker, dict):
            continue
        worker_id = str(worker.get("id", "unknown"))
        worker_out = text(f"worker_{worker_id}")
        worker_err = err_text(f"worker_{worker_id}")
        worker_status = str(worker.get("status", "unknown"))
        candidates.extend(cleanup_candidates(worker_id, worker_out))
        parsed.append(
            {
                "worker_id": worker_id,
                "host": worker.get("host"),
                "status": worker_status,
                "pressure_state": worker.get("pressure_state", "unknown"),
                "pressure_reason_code": worker.get("pressure_reason_code"),
                "pressure_disk_free_gb": worker.get("pressure_disk_free_gb"),
                "pressure_disk_free_ratio": worker.get("pressure_disk_free_ratio"),
                "pressure_telemetry_fresh": worker.get("pressure_telemetry_fresh"),
                "probe_command": f"ssh read-only df/sbh/du probe for {worker_id}",
                "probe_exit_status": status(f"worker_{worker_id}"),
                "probe_failure_signature": worker_probe_signature(worker_id, worker_status),
                "df_snapshot": "\n".join(
                    line for line in worker_out.splitlines() if "Filesystem" in line or " /" in line
                )
                or None,
                "sbh_snapshot": "present in raw worker output" if "sbh" in worker_out.lower() else None,
                "ballast_snapshot": "present in raw worker output" if "ballast" in worker_out.lower() else None,
                "bounded_du_findings": [
                    line
                    for line in worker_out.splitlines()
                    if re.match(r"^\S+\s+/(tmp|data)/", line.strip())
                ],
                "collection_errors": line_list(worker_err),
            }
        )
    return parsed, candidates


def dry_run_summary() -> dict[str, Any]:
    dry_run = text("rch_dry_run")
    skip_reason = None
    worker_selection_status = "unknown"
    for line in dry_run.splitlines():
        stripped = line.strip()
        if stripped.startswith("Skip:"):
            skip_reason = stripped.replace("Skip:", "", 1).strip()
            worker_selection_status = "skipped"
        elif "Select best available worker" in stripped and worker_selection_status == "unknown":
            worker_selection_status = "attempted"
    return {
        "dry_run_command": f"RCH_REQUIRE_REMOTE=1 rch diagnose --dry-run {FOCUS_CMD!r}",
        "dry_run_exit_status": status("rch_dry_run"),
        "would_offload": "Would offload:" in dry_run and "YES" in dry_run,
        "worker_selection_status": worker_selection_status,
        "skip_reason": skip_reason,
        "required_remote_env": "RCH_REQUIRE_REMOTE=1",
        "fallback_markers_rejected": ["[RCH] local", "remote required; refusing local fallback"],
        "raw_output_path": str((RAW_DIR / "rch_dry_run.out").relative_to(ROOT)),
    }


status_json = load_status_json()
workers, candidates = parse_workers(status_json)
candidate_worker_ids = sorted({candidate["worker_id"] for candidate in candidates})
candidate_paths = [candidate["path"] for candidate in candidates]

report = {
    "schema_version": "rch_pressure_approval_packet_schema.v1",
    "packet_id": PACKET_ID,
    "generated_at_utc": utc_now(),
    "project": "frankenlibc",
    "repo_state": {
        "cwd": str(ROOT),
        "branch": scalar(text("git_status")).replace("## ", "").split("...")[0]
        if scalar(text("git_status"))
        else "unknown",
        "head_commit": scalar(text("git_head")),
        "origin_main_commit": scalar(text("git_origin_main")),
        "origin_master_commit": scalar(text("git_origin_master")),
        "worktree_list": line_list(text("git_worktrees")),
        "dirty_summary": line_list(text("git_status"))[1:],
        "untracked_summary": [
            line[3:] for line in line_list(text("git_status")) if line.startswith("?? ")
        ],
    },
    "rch_gate": dry_run_summary(),
    "workers": workers,
    "cleanup_candidates": candidates,
    "approval_request": {
        "operator_summary": "rch cannot select an admissible remote worker for the focused cargo validation lane.",
        "exact_worker_ids": candidate_worker_ids,
        "exact_candidate_paths": candidate_paths,
        "why_read_only_collection_is_insufficient": "Read-only collection can identify pressure and candidates, but cannot free space under repo rules.",
        "explicit_user_text_required_before_cleanup": "The user must provide written approval naming exact paths and commands before cleanup can run.",
        "commands_not_executed": [
            "no deletion command executed",
            "no ballast release command executed",
            "no repository cleanup command executed",
        ],
    },
    "executed_actions": [
        {"action": "git repo-state inspection", "executed": True},
        {"action": "rch status", "executed": status("rch_status") is not None},
        {"action": "rch dry-run", "executed": status("rch_dry_run") is not None},
        {"action": "bounded read-only worker probes", "executed": any(w["probe_exit_status"] is not None for w in workers)},
    ],
    "validation_commands": [
        "bash -n scripts/generate_rch_pressure_approval_packet.sh",
        "jq empty tests/conformance/rch_pressure_approval_packet_schema.v1.json",
        "jq empty target/rch-pressure-approval-packet/rch_pressure_approval_packet.report.json",
        "git diff --check -- scripts/generate_rch_pressure_approval_packet.sh tests/conformance/rch_pressure_approval_packet_schema.v1.json .beads/issues.jsonl",
        "AGENT_NAME=SunnyHeron br dep cycles --json",
    ],
    "artifact_paths": [
        str(REPORT.relative_to(ROOT)),
        str(MARKDOWN.relative_to(ROOT)),
        str(RAW_DIR.relative_to(ROOT)),
    ],
}

REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    "# rch Pressure Approval Packet",
    "",
    f"- Packet: `{PACKET_ID}`",
    f"- Generated: `{report['generated_at_utc']}`",
    f"- Project: `{report['project']}`",
    f"- Branch: `{report['repo_state']['branch']}`",
    f"- Head: `{report['repo_state']['head_commit']}`",
    f"- Dry-run selection: `{report['rch_gate']['worker_selection_status']}`",
    f"- Skip reason: `{report['rch_gate']['skip_reason']}`",
    "",
    "## Cleanup Candidates",
]
if candidates:
    for candidate in candidates:
        lines.append(
            f"- `{candidate['worker_id']}` `{candidate['size_human']}` `{candidate['path']}` "
            "(requires explicit written approval; not executed)"
        )
else:
    lines.append("- No deletion-level cleanup candidates were identified by the bounded probes.")
lines.extend(
    [
        "",
        "## Approval Boundary",
        "",
        "This packet is read-only evidence. It does not authorize cleanup. The user must approve exact paths and commands in writing before any cleanup runs.",
        "",
        "Commands not executed:",
    ]
)
for item in report["approval_request"]["commands_not_executed"]:
    lines.append(f"- {item}")
MARKDOWN.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(json.dumps({"report": str(REPORT), "markdown": str(MARKDOWN), "candidates": len(candidates)}, sort_keys=True))
PY
