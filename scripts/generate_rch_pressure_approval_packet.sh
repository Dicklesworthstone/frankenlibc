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
MAX_DISABLED_PROBES="${FRANKENLIBC_RCH_PACKET_MAX_DISABLED_PROBES:-6}"
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

if [[ -s "${RAW_DIR}/rch_status.out" ]] && command -v jq >/dev/null 2>&1; then
  mapfile -t disabled_probe_ids < <(
    jq -r '
      .data.daemon.workers[]?
      | select(
          (.status != "healthy")
          or (.pressure_state == "telemetry_gap")
          or (.pressure_telemetry_fresh == false)
        )
      | .id
    ' "${RAW_DIR}/rch_status.out"
  )
  for worker_id in "${disabled_probe_ids[@]:0:${MAX_DISABLED_PROBES}}"; do
    [[ -n "${worker_id}" ]] || continue
    safe_id="$(printf '%s' "${worker_id}" | tr -cd 'A-Za-z0-9_.-')"
    capture "rch_worker_probe_${safe_id}" timeout "${SSH_TIMEOUT_SECS}" rch workers probe "${worker_id}"
  done
fi

if [[ "${SSH_ENABLED}" == "1" && -s "${RAW_DIR}/rch_status.out" && -r "${SSH_KEY}" ]] && command -v jq >/dev/null 2>&1; then
  mapfile -t worker_rows < <(
    jq -r '
      def total_gb:
        .pressure_disk_total_gb
        // (
          if (.pressure_disk_free_gb != null and .pressure_disk_free_ratio != null and .pressure_disk_free_ratio > 0)
          then (.pressure_disk_free_gb / .pressure_disk_free_ratio)
          else null
          end
        );
      def pressure_gap:
        (total_gb as $total
        | .pressure_disk_free_gb as $free
        | if ($total != null and $free != null)
          then (($total * 0.05) - $free)
          else 999999
          end);
      [
        .data.daemon.workers[]?
        | select(.status == "healthy" and .pressure_state == "critical")
        | {id, host, pressure_gap: pressure_gap}
      ]
      | sort_by(.pressure_gap, .id)
      | .[]
      | [.id, .host]
      | @tsv
    ' \
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
            find /data/projects -maxdepth 8 -type d -path \"*/.rch-target-*/debug/incremental/*\" -prune -exec du -sh {} + 2>/dev/null | sort -h | tail -5 || true
            find /data/projects -maxdepth 8 -type d -path \"*/.rch-target-*/debug/incremental/*\" -prune -exec du -s -B1 {} + 2>/dev/null | sort -n | while read -r bytes path; do
              if [ \"\${bytes}\" -ge 250000000 ]; then
                printf \"%sB %s\\n\" \"\${bytes}\" \"\${path}\"
              fi
            done | head -40 || true
          '" >"${RAW_DIR}/worker_${safe_id}.out" 2>"${RAW_DIR}/worker_${safe_id}.err"
        status=$?
        set -e
        printf '%s\n' "${status}" >"${RAW_DIR}/worker_${safe_id}.status"
  done
fi

python3 - "${ROOT}" "${RAW_DIR}" "${REPORT}" "${MARKDOWN}" "${PACKET_ID}" "${FOCUS_CMD}" "${SSH_KEY}" "${SSH_TIMEOUT_SECS}" <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
RAW_DIR = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
MARKDOWN = pathlib.Path(sys.argv[4])
PACKET_ID = sys.argv[5]
FOCUS_CMD = sys.argv[6]
SSH_KEY = sys.argv[7]
SSH_TIMEOUT_SECS = sys.argv[8]
PRECHECK_RESULTS_ENABLED = os.environ.get("FRANKENLIBC_RCH_PACKET_PRECHECK_RESULTS", "1") == "1"


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


CRITICAL_FREE_RATIO_TARGET = 0.05
MARGIN_RECOMMENDATION_SURPLUS_GB = 0.25


def float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def estimated_gap_to_target_ratio_gb(worker: dict[str, Any]) -> float | None:
    free_gb = float_or_none(worker.get("pressure_disk_free_gb"))
    total_gb = estimated_total_gb(worker)
    if free_gb is None or total_gb is None or total_gb <= 0:
        return None
    return round(max(0.0, (total_gb * CRITICAL_FREE_RATIO_TARGET) - free_gb), 3)


def estimated_total_gb(worker: dict[str, Any]) -> float | None:
    free_gb = float_or_none(worker.get("pressure_disk_free_gb"))
    total_gb = float_or_none(worker.get("pressure_disk_total_gb"))
    if total_gb is None:
        ratio = float_or_none(worker.get("pressure_disk_free_ratio"))
        if free_gb is not None and ratio is not None and ratio > 0:
            total_gb = free_gb / ratio
    return total_gb


def size_to_bytes(size: str) -> int | None:
    stripped = size.strip()
    byte_match = re.match(r"^(?P<bytes>[0-9]+)B$", stripped, re.IGNORECASE)
    if byte_match:
        return int(byte_match.group("bytes"))
    size_gb = size_to_gb(stripped)
    if size_gb is None:
        return None
    return int(size_gb * 1024 * 1024 * 1024)


def size_to_gb(size: str) -> float | None:
    stripped = size.strip()
    byte_match = re.match(r"^(?P<bytes>[0-9]+)B$", stripped, re.IGNORECASE)
    if byte_match:
        return round(int(byte_match.group("bytes")) / (1024 * 1024 * 1024), 3)
    match = re.match(r"^(?P<value>[0-9]+(?:\.[0-9]+)?)(?P<unit>[KMGT])$", stripped, re.IGNORECASE)
    if not match:
        return None
    value = float(match.group("value"))
    unit = match.group("unit").upper()
    factors = {"K": 1 / (1024 * 1024), "M": 1 / 1024, "G": 1.0, "T": 1024.0}
    return round(value * factors[unit], 3)


def read_only_pre_cleanup_checks(host: str, path: str) -> list[dict[str, str]]:
    ssh_target = shlex.quote(f"ubuntu@{host}")
    ssh_key = shlex.quote(SSH_KEY)
    ssh_prefix = f"ssh -o BatchMode=yes -o ConnectTimeout=10 -i {ssh_key} {ssh_target}"
    path_arg = shlex.quote(path)
    protect_cmd = f"if test -e {path_arg}; then find {path_arg} -name .sbh-protect -print -quit; fi"
    lsof_cmd = f"if test -e {path_arg}; then sudo -n lsof +D {path_arg} 2>&1 | head -20; fi"
    return [
        {
            "check_kind": "sbh_protect_marker_absence",
            "command": f"{ssh_prefix} {shlex.quote(protect_cmd)}",
            "expected_safe_result": "exit 0 with no stdout",
            "blocks_cleanup_if": "any stdout, ssh failure, or non-zero exit",
        },
        {
            "check_kind": "open_file_absence",
            "command": f"{ssh_prefix} {shlex.quote(lsof_cmd)}",
            "expected_safe_result": "exit 0 with no stdout",
            "blocks_cleanup_if": "any stdout, sudo authentication failure, ssh failure, or non-zero exit",
        },
    ]


def ssh_timeout() -> int:
    try:
        return max(1, int(float(SSH_TIMEOUT_SECS)))
    except ValueError:
        return 25


def trim_result_text(value: str | None) -> str:
    if value is None:
        return ""
    if len(value) <= 4000:
        return value
    return value[:4000] + "\n[truncated]"


def pre_cleanup_remote_command(check_kind: str, path: str) -> str:
    path_arg = shlex.quote(path)
    if check_kind == "sbh_protect_marker_absence":
        return f"if test -e {path_arg}; then find {path_arg} -name .sbh-protect -print -quit; fi"
    if check_kind == "open_file_absence":
        return f"if test -e {path_arg}; then sudo -n lsof +D {path_arg} 2>&1 | head -20; fi"
    return "printf '%s\\n' 'unknown pre-cleanup check kind'; exit 2"


def run_pre_cleanup_check(host: str, path: str, check_kind: str) -> dict[str, Any]:
    if not PRECHECK_RESULTS_ENABLED:
        return {
            "executed": False,
            "executed_at_utc": None,
            "exit_status": None,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "passed": False,
            "skip_reason": "FRANKENLIBC_RCH_PACKET_PRECHECK_RESULTS disabled result collection",
        }
    if not pathlib.Path(SSH_KEY).is_file():
        return {
            "executed": False,
            "executed_at_utc": None,
            "exit_status": None,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "passed": False,
            "skip_reason": "ssh key unavailable for read-only result collection",
        }
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-i",
        SSH_KEY,
        f"ubuntu@{host}",
        pre_cleanup_remote_command(check_kind, path),
    ]
    executed_at = utc_now()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=ssh_timeout(),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = trim_result_text(exc.stdout if isinstance(exc.stdout, str) else "")
        stderr = trim_result_text(exc.stderr if isinstance(exc.stderr, str) else "")
        return {
            "executed": True,
            "executed_at_utc": executed_at,
            "exit_status": None,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": True,
            "passed": False,
            "skip_reason": None,
        }
    stdout = trim_result_text(completed.stdout)
    stderr = trim_result_text(completed.stderr)
    return {
        "executed": True,
        "executed_at_utc": executed_at,
        "exit_status": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": False,
        "passed": completed.returncode == 0 and stdout == "" and stderr == "",
        "skip_reason": None,
    }


def attach_pre_cleanup_results(
    candidates: list[dict[str, Any]],
    recommended: list[dict[str, Any]],
    margin_recommended: list[dict[str, Any]],
) -> int:
    selected_keys = {
        (str(candidate.get("worker_id", "")), str(candidate.get("path", "")))
        for candidate in recommended + margin_recommended
        if isinstance(candidate, dict)
    }
    result_cache: dict[tuple[str, str, str], dict[str, Any]] = {}
    executed = 0
    for candidate in sorted(
        candidates,
        key=lambda item: (
            str(item.get("worker_id", "")),
            int(item.get("candidate_rank", 999999)),
            str(item.get("path", "")),
        ),
    ):
        key = (str(candidate.get("worker_id", "")), str(candidate.get("path", "")))
        if key not in selected_keys:
            continue
        host = str(candidate.get("host") or "")
        path = str(candidate.get("path") or "")
        if not host or not path:
            continue
        checks = candidate.get("pre_cleanup_read_only_checks")
        if not isinstance(checks, list):
            continue
        for check in checks:
            if not isinstance(check, dict) or "last_result" in check:
                continue
            check_kind = str(check.get("check_kind") or "")
            result = run_pre_cleanup_check(host, path, check_kind)
            check["last_result"] = result
            result_cache[(key[0], key[1], check_kind)] = result
            if result.get("executed") is True:
                executed += 1
    for recommendation in recommended + margin_recommended:
        key = (str(recommendation.get("worker_id", "")), str(recommendation.get("path", "")))
        checks = recommendation.get("pre_cleanup_read_only_checks")
        if not isinstance(checks, list):
            continue
        for check in checks:
            if not isinstance(check, dict):
                continue
            check_kind = str(check.get("check_kind") or "")
            result = result_cache.get((key[0], key[1], check_kind))
            if result is not None:
                check["last_result"] = dict(result)
    return executed


def raw_output_path(name: str) -> str | None:
    path = RAW_DIR / f"{name}.out"
    if not path.exists():
        return None
    return str(path.relative_to(ROOT))


def worker_probe_signature(worker_id: str, worker_status: str) -> str:
    direct_name = f"rch_worker_probe_{worker_id}"
    direct_err = err_text(direct_name)
    direct_out = text(direct_name)
    direct_status = status(direct_name)
    if direct_status == 0:
        return "ok"
    if "RCH-E100" in direct_err or "RCH-E100" in direct_out:
        return "RCH-E100"
    if direct_status == 124:
        return "timeout"
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


def cleanup_candidates(worker_id: str, worker_host: Any, worker_out: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    host = str(worker_host or worker_id)
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
        size_gb = size_to_gb(size)
        size_bytes = size_to_bytes(size)
        if size_gb is None:
            continue
        if not is_rch_artifact and not re.search(r"[0-9](G|T)$", size):
            continue
        if is_rch_artifact and size_gb < 0.1:
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
                "host": host,
                "path": path,
                "size_human": size,
                "size_bytes": size_bytes,
                "estimated_size_gb": size_gb,
                "pre_cleanup_read_only_checks": read_only_pre_cleanup_checks(host, path),
                "source_command": "bounded read-only du/find over target, .rch-target, human-sized incremental dirs, and byte-exact near-threshold .rch-target incremental dirs",
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
        direct_probe_name = f"rch_worker_probe_{worker_id}"
        direct_probe_status = status(direct_probe_name)
        candidates.extend(cleanup_candidates(worker_id, worker.get("host"), worker_out))
        parsed.append(
            {
                "worker_id": worker_id,
                "host": worker.get("host"),
                "status": worker_status,
                "pressure_state": worker.get("pressure_state", "unknown"),
                "pressure_reason_code": worker.get("pressure_reason_code"),
                "pressure_disk_free_gb": worker.get("pressure_disk_free_gb"),
                "pressure_disk_total_gb": worker.get("pressure_disk_total_gb"),
                "pressure_disk_free_ratio": worker.get("pressure_disk_free_ratio"),
                "pressure_telemetry_fresh": worker.get("pressure_telemetry_fresh"),
                "estimated_free_ratio_target": CRITICAL_FREE_RATIO_TARGET,
                "estimated_gb_needed_to_reach_target_ratio": estimated_gap_to_target_ratio_gb(worker),
                "probe_command": f"ssh read-only df/sbh/du probe for {worker_id}",
                "direct_rch_probe_command": f"timeout {SSH_TIMEOUT_SECS} rch workers probe {worker_id}"
                if direct_probe_status is not None
                else None,
                "direct_rch_probe_exit_status": direct_probe_status,
                "direct_rch_probe_raw_output_path": raw_output_path(direct_probe_name)
                if direct_probe_status is not None
                else None,
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


def rank_cleanup_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        grouped.setdefault(str(candidate.get("worker_id", "")), []).append(candidate)
    for worker_id, worker_candidates in grouped.items():
        ranked = sorted(
            worker_candidates,
            key=lambda candidate: (
                float_or_none(candidate.get("estimated_size_gb")) is None,
                float_or_none(candidate.get("estimated_size_gb")) or float("inf"),
                str(candidate.get("path", "")),
            ),
        )
        for rank, candidate in enumerate(ranked, start=1):
            candidate["candidate_rank"] = rank
    return sorted(
        candidates,
        key=lambda candidate: (
            str(candidate.get("worker_id", "")),
            int(candidate.get("candidate_rank", 999999)),
            str(candidate.get("path", "")),
        ),
    )


candidates = rank_cleanup_candidates(candidates)
candidate_worker_ids = sorted({candidate["worker_id"] for candidate in candidates})
candidate_paths = [candidate["path"] for candidate in candidates]


def estimated_post_cleanup_free_ratio(worker: dict[str, Any], candidate: dict[str, Any]) -> float | None:
    free_gb = float_or_none(worker.get("pressure_disk_free_gb"))
    total_gb = estimated_total_gb(worker)
    size_gb = float_or_none(candidate.get("estimated_size_gb"))
    if free_gb is None or total_gb is None or total_gb <= 0 or size_gb is None:
        return None
    return round((free_gb + size_gb) / total_gb, 6)


def estimated_surplus_gb_after_cleanup(worker: dict[str, Any], candidate: dict[str, Any]) -> float | None:
    gap_gb = float_or_none(worker.get("estimated_gb_needed_to_reach_target_ratio"))
    size_gb = float_or_none(candidate.get("estimated_size_gb"))
    if gap_gb is None or size_gb is None:
        return None
    return round(size_gb - gap_gb, 3)


def smallest_sufficient_candidates(workers: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recommended: list[dict[str, Any]] = []
    for worker in workers:
        if worker.get("pressure_state") != "critical":
            continue
        gap_gb = float_or_none(worker.get("estimated_gb_needed_to_reach_target_ratio"))
        if gap_gb is None or gap_gb <= 0:
            continue
        worker_candidates = [
            candidate
            for candidate in candidates
            if candidate.get("worker_id") == worker.get("worker_id")
            and float_or_none(candidate.get("estimated_size_gb")) is not None
            and float(candidate["estimated_size_gb"]) >= gap_gb
        ]
        if not worker_candidates:
            continue
        selected = min(
            worker_candidates,
            key=lambda candidate: (
                float(candidate["estimated_size_gb"]),
                int(candidate.get("candidate_rank", 999999)),
                str(candidate.get("path", "")),
            ),
        )
        recommendation = dict(selected)
        recommendation["estimated_gap_gb"] = gap_gb
        recommendation["estimated_post_cleanup_free_ratio"] = estimated_post_cleanup_free_ratio(worker, selected)
        recommendation["estimated_surplus_gb_after_cleanup"] = estimated_surplus_gb_after_cleanup(worker, selected)
        recommendation["recommendation_kind"] = "smallest_listed_candidate_meeting_estimated_gap"
        recommendation["recommendation_reason"] = (
            "smallest ranked candidate for this worker with estimated_size_gb >= "
            "estimated_gb_needed_to_reach_target_ratio"
        )
        recommended.append(recommendation)
    return sorted(
        recommended,
        key=lambda candidate: (
            str(candidate.get("worker_id", "")),
            int(candidate.get("candidate_rank", 999999)),
            str(candidate.get("path", "")),
        ),
    )


recommended_candidates = smallest_sufficient_candidates(workers, candidates)


def margin_sufficient_candidates(
    workers: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    minimum_surplus_gb: float,
) -> list[dict[str, Any]]:
    recommended: list[dict[str, Any]] = []
    for worker in workers:
        if worker.get("pressure_state") != "critical":
            continue
        gap_gb = float_or_none(worker.get("estimated_gb_needed_to_reach_target_ratio"))
        if gap_gb is None or gap_gb <= 0:
            continue
        required_size_gb = gap_gb + minimum_surplus_gb
        worker_candidates = [
            candidate
            for candidate in candidates
            if candidate.get("worker_id") == worker.get("worker_id")
            and float_or_none(candidate.get("estimated_size_gb")) is not None
            and float(candidate["estimated_size_gb"]) >= required_size_gb
        ]
        if not worker_candidates:
            continue
        selected = min(
            worker_candidates,
            key=lambda candidate: (
                float(candidate["estimated_size_gb"]),
                int(candidate.get("candidate_rank", 999999)),
                str(candidate.get("path", "")),
            ),
        )
        recommendation = dict(selected)
        recommendation["estimated_gap_gb"] = gap_gb
        recommendation["minimum_margin_surplus_gb"] = minimum_surplus_gb
        recommendation["estimated_post_cleanup_free_ratio"] = estimated_post_cleanup_free_ratio(worker, selected)
        recommendation["estimated_surplus_gb_after_cleanup"] = estimated_surplus_gb_after_cleanup(worker, selected)
        recommendation["recommendation_kind"] = "smallest_listed_candidate_meeting_estimated_gap_plus_margin"
        recommendation["recommendation_reason"] = (
            "smallest ranked candidate for this worker with estimated_size_gb >= "
            "estimated_gb_needed_to_reach_target_ratio plus the configured margin surplus"
        )
        recommended.append(recommendation)
    return sorted(
        recommended,
        key=lambda candidate: (
            str(candidate.get("worker_id", "")),
            int(candidate.get("candidate_rank", 999999)),
            str(candidate.get("path", "")),
        ),
    )


margin_recommended_candidates = margin_sufficient_candidates(
    workers,
    candidates,
    MARGIN_RECOMMENDATION_SURPLUS_GB,
)
pre_cleanup_result_count = attach_pre_cleanup_results(
    candidates,
    recommended_candidates,
    margin_recommended_candidates,
)


def selected_recommendation_entries() -> list[dict[str, Any]]:
    entries: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in recommended_candidates + margin_recommended_candidates:
        key = (str(candidate.get("worker_id", "")), str(candidate.get("path", "")))
        if key not in entries:
            entries[key] = {"candidate": candidate, "recommendation_kinds": []}
        kind = str(candidate.get("recommendation_kind") or "")
        if kind and kind not in entries[key]["recommendation_kinds"]:
            entries[key]["recommendation_kinds"].append(kind)
    return [
        entries[key]
        for key in sorted(
            entries,
            key=lambda item: (
                item[0],
                int(entries[item]["candidate"].get("candidate_rank", 999999)),
                item[1],
            ),
        )
    ]


def approval_readiness_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for entry in selected_recommendation_entries():
        candidate = entry["candidate"]
        checks = candidate.get("pre_cleanup_read_only_checks")
        check_count = len(checks) if isinstance(checks, list) else 0
        collected_count = 0
        passed_count = 0
        if isinstance(checks, list):
            for check in checks:
                if not isinstance(check, dict):
                    continue
                result = check.get("last_result")
                if not isinstance(result, dict):
                    continue
                collected_count += 1
                if result.get("passed") is True:
                    passed_count += 1

        if check_count == 0:
            approval_state = "blocked_by_missing_read_only_checks"
            blocked_by = ["read_only_checks_missing", "explicit_user_approval_required"]
        elif collected_count < check_count:
            approval_state = "needs_read_only_precheck_results"
            blocked_by = ["read_only_precheck_results_missing", "explicit_user_approval_required"]
        elif passed_count == check_count:
            approval_state = "ready_for_explicit_user_approval"
            blocked_by = ["explicit_user_approval_required"]
        else:
            approval_state = "blocked_by_read_only_precheck_result"
            blocked_by = ["read_only_precheck_failed", "explicit_user_approval_required"]

        rows.append(
            {
                "worker_id": candidate.get("worker_id"),
                "host": candidate.get("host"),
                "path": candidate.get("path"),
                "candidate_rank": candidate.get("candidate_rank"),
                "recommendation_kinds": entry["recommendation_kinds"],
                "read_only_check_count": check_count,
                "read_only_check_results_collected": collected_count,
                "read_only_check_results_passed": passed_count,
                "read_only_checks_passed": check_count > 0 and passed_count == check_count,
                "approval_state": approval_state,
                "blocked_by": blocked_by,
                "safe_to_run_without_user_approval": False,
                "exact_user_approval_required": True,
                "cleanup_executed": False,
                "next_action": "request_explicit_user_approval_for_exact_path"
                if approval_state == "ready_for_explicit_user_approval"
                else "collect_passing_read_only_precheck_results_before_requesting_user_approval",
            }
        )
    return rows


def no_candidate_diagnostics() -> dict[str, Any]:
    candidate_counts_by_worker: dict[str, int] = {}
    for candidate in candidates:
        candidate_counts_by_worker[str(candidate.get("worker_id", ""))] = (
            candidate_counts_by_worker.get(str(candidate.get("worker_id", "")), 0) + 1
        )
    critical_workers = [
        worker
        for worker in workers
        if isinstance(worker, dict) and worker.get("pressure_state") == "critical"
    ]
    critical_without_candidates = [
        str(worker.get("worker_id"))
        for worker in critical_workers
        if candidate_counts_by_worker.get(str(worker.get("worker_id")), 0) == 0
    ]
    workers_with_du_findings = [
        str(worker.get("worker_id"))
        for worker in workers
        if isinstance(worker, dict) and worker.get("bounded_du_findings")
    ]
    probe_failure_workers = [
        str(worker.get("worker_id"))
        for worker in workers
        if isinstance(worker, dict)
        and str(worker.get("probe_failure_signature") or "ok") != "ok"
    ]
    collection_error_workers = [
        str(worker.get("worker_id"))
        for worker in workers
        if isinstance(worker, dict) and worker.get("collection_errors")
    ]

    if candidates:
        status = "candidates_identified"
        next_action = "review_approval_readiness"
        summary = "Bounded read-only probes identified approval-gated cleanup candidates."
    else:
        status = "no_candidates_identified"
        next_action = "inspect_worker_probe_outputs_or_restore_worker_capacity"
        summary = (
            "RCH remains pressure-blocked, but bounded read-only probes did not identify "
            "deletion-level build-output candidates that can be elevated to approval readiness."
        )
    return {
        "status": status,
        "candidate_count": len(candidates),
        "critical_worker_count": len(critical_workers),
        "workers_with_bounded_du_findings": workers_with_du_findings,
        "critical_workers_without_candidates": critical_without_candidates,
        "probe_failure_workers": probe_failure_workers,
        "collection_error_workers": collection_error_workers,
        "diagnostic_summary": summary,
        "next_action": next_action,
    }


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
    "recommended_cleanup_candidates": recommended_candidates,
    "approval_readiness": approval_readiness_rows(),
    "no_candidate_diagnostics": no_candidate_diagnostics(),
    "approval_request": {
        "operator_summary": "rch cannot select an admissible remote worker for the focused cargo validation lane.",
        "exact_worker_ids": candidate_worker_ids,
        "exact_candidate_paths": candidate_paths,
        "smallest_sufficient_candidate_paths": [candidate["path"] for candidate in recommended_candidates],
        "minimum_margin_surplus_gb": MARGIN_RECOMMENDATION_SURPLUS_GB,
        "margin_sufficient_candidate_paths": [candidate["path"] for candidate in margin_recommended_candidates],
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
        {
            "action": "selected candidate read-only pre-cleanup result collection",
            "executed": pre_cleanup_result_count > 0 or not (recommended_candidates or margin_recommended_candidates),
        },
    ],
    "validation_commands": [
        "bash -n scripts/generate_rch_pressure_approval_packet.sh scripts/check_rch_pressure_packet_goldens.sh",
        "jq empty tests/conformance/rch_pressure_approval_packet_schema.v1.json tests/conformance/rch_pressure_approval_packet_golden.v1.json",
        "jq empty target/rch-pressure-approval-packet/rch_pressure_approval_packet.report.json",
        "bash scripts/check_rch_pressure_packet_goldens.sh",
        "git diff --check -- scripts/generate_rch_pressure_approval_packet.sh scripts/check_rch_pressure_packet_goldens.sh tests/conformance/rch_pressure_approval_packet_schema.v1.json tests/conformance/rch_pressure_approval_packet_golden.v1.json .beads/issues.jsonl",
        "AGENT_NAME=<registered-agent> br dep cycles --json",
    ],
    "artifact_paths": [
        str(REPORT.relative_to(ROOT)),
        str(MARKDOWN.relative_to(ROOT)),
        str(RAW_DIR.relative_to(ROOT)),
    ],
}

REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

critical_workers = [worker for worker in workers if worker.get("pressure_state") == "critical"]


def markdown_value(value: Any, suffix: str = "") -> str:
    numeric = float_or_none(value)
    if numeric is None:
        return "unknown"
    return f"{numeric:.2f}{suffix}"


def selected_precheck_display_candidates() -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    selected: list[dict[str, Any]] = []
    for candidate in recommended_candidates + margin_recommended_candidates:
        key = (str(candidate.get("worker_id", "")), str(candidate.get("path", "")))
        if key in seen:
            continue
        seen.add(key)
        selected.append(candidate)
    return sorted(
        selected,
        key=lambda candidate: (
            str(candidate.get("worker_id", "")),
            int(candidate.get("candidate_rank", 999999)),
            str(candidate.get("path", "")),
        ),
    )


def markdown_check_result(check: dict[str, Any]) -> str:
    result = check.get("last_result")
    if not isinstance(result, dict):
        return "result `not collected`"
    status_text = "pass" if result.get("passed") is True else "blocked"
    exit_status = result.get("exit_status")
    exit_text = "timeout" if result.get("timed_out") is True else str(exit_status)
    stdout_len = len(str(result.get("stdout", "")))
    stderr_len = len(str(result.get("stderr", "")))
    return (
        f"result `{status_text}` exit `{exit_text}` "
        f"stdout_bytes `{stdout_len}` stderr_bytes `{stderr_len}`"
    )


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
    "## Worker Pressure Gaps",
]
if critical_workers:
    for worker in critical_workers:
        ratio = float_or_none(worker.get("pressure_disk_free_ratio"))
        ratio_text = f"{ratio:.2%}" if ratio is not None else "unknown"
        gap_text = markdown_value(worker.get("estimated_gb_needed_to_reach_target_ratio"), "G")
        lines.append(
            f"- `{worker['worker_id']}` free `{markdown_value(worker.get('pressure_disk_free_gb'), 'G')}` "
            f"ratio `{ratio_text}` reason `{worker.get('pressure_reason_code')}`; "
            f"estimated `{gap_text}` to reach 5% free ratio"
        )
else:
    lines.append("- No critical-pressure workers were reported by rch status.")
lines.extend(
    [
        "",
        "## Smallest Sufficient Listed Candidates",
    ]
)
if recommended_candidates:
    for candidate in recommended_candidates:
        lines.append(
            f"- `{candidate['worker_id']}` rank `{candidate.get('candidate_rank')}` "
            f"gap `{markdown_value(candidate.get('estimated_gap_gb'), 'G')}`; "
            f"post-cleanup ratio `{markdown_value(candidate.get('estimated_post_cleanup_free_ratio'))}`; "
            f"surplus `{markdown_value(candidate.get('estimated_surplus_gb_after_cleanup'), 'G')}`; "
            f"smallest listed candidate `{candidate['size_human']}` `{candidate['path']}` "
            "(requires explicit written approval; not executed)"
        )
else:
    lines.append("- No listed cleanup candidate was large enough to clear a worker's estimated pressure gap.")
lines.extend(
    [
        "",
        "## Margin Sufficient Listed Candidates",
    ]
)
if margin_recommended_candidates:
    for candidate in margin_recommended_candidates:
        lines.append(
            f"- `{candidate['worker_id']}` rank `{candidate.get('candidate_rank')}` "
            f"gap `{markdown_value(candidate.get('estimated_gap_gb'), 'G')}`; "
            f"minimum surplus `{markdown_value(candidate.get('minimum_margin_surplus_gb'), 'G')}`; "
            f"estimated surplus `{markdown_value(candidate.get('estimated_surplus_gb_after_cleanup'), 'G')}`; "
            f"margin listed candidate `{candidate['size_human']}` `{candidate['path']}` "
            "(requires explicit written approval; not executed)"
        )
else:
    lines.append("- No listed cleanup candidate clears a worker's estimated pressure gap plus margin.")
lines.extend(
    [
        "",
        "## Read-Only Pre-Cleanup Checks",
    ]
)
display_precheck_candidates = selected_precheck_display_candidates()
if display_precheck_candidates:
    for candidate in display_precheck_candidates:
        lines.append(f"- `{candidate['worker_id']}` `{candidate['path']}`")
        for check in candidate.get("pre_cleanup_read_only_checks", []):
            lines.append(f"  - `{check['check_kind']}`: `{check['command']}`")
            lines.append(f"    - {markdown_check_result(check)}")
else:
    lines.append(
        "- No selected cleanup candidate requires pre-cleanup checks. Future candidates still require "
        "`sbh_protect_marker_absence` and `open_file_absence` before approval readiness."
    )
lines.extend(
    [
        "",
        "## Approval Readiness",
    ]
)
if report["approval_readiness"]:
    for readiness in report["approval_readiness"]:
        lines.append(
            f"- `{readiness['worker_id']}` state `{readiness['approval_state']}`; "
            f"checks `{readiness['read_only_check_results_passed']}/{readiness['read_only_check_count']}`; "
            f"safe without user approval `{str(readiness['safe_to_run_without_user_approval']).lower()}`; "
            f"`{readiness['path']}`"
        )
else:
    lines.append("- No selected candidate has reached the approval-readiness stage; safe without user approval `false`.")
lines.extend(
    [
        "",
        "## Cleanup Candidates",
    ]
)
if candidates:
    for candidate in candidates:
        lines.append(
            f"- `{candidate['worker_id']}` `{candidate['size_human']}` `{candidate['path']}` "
            "(requires explicit written approval; not executed)"
        )
else:
    lines.append("- No deletion-level cleanup candidates were identified by the bounded probes; any future cleanup candidate still requires explicit written approval; not executed.")
lines.extend(
    [
        "",
        "## No-Candidate Diagnostics",
        "",
        f"- Status: `{report['no_candidate_diagnostics']['status']}`",
        f"- Summary: {report['no_candidate_diagnostics']['diagnostic_summary']}",
        f"- Next action: `{report['no_candidate_diagnostics']['next_action']}`",
    ]
)
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
