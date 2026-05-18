#!/usr/bin/env bash
# Validate rch pressure approval packet golden fixtures and optional generated reports.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="${FRANKENLIBC_RCH_PACKET_SCHEMA:-${ROOT}/tests/conformance/rch_pressure_approval_packet_schema.v1.json}"
GOLDEN="${FRANKENLIBC_RCH_PACKET_GOLDEN:-${ROOT}/tests/conformance/rch_pressure_approval_packet_golden.v1.json}"
LIVE_REPORT="${FRANKENLIBC_RCH_PACKET_REPORT:-${ROOT}/target/rch-pressure-approval-packet/rch_pressure_approval_packet.report.json}"
LIVE_MARKDOWN="${FRANKENLIBC_RCH_PACKET_MARKDOWN:-${ROOT}/target/rch-pressure-approval-packet/rch_pressure_approval_packet.approval.md}"
OUT_DIR="${FRANKENLIBC_RCH_PACKET_GOLDEN_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${OUT_DIR}/rch_pressure_packet_goldens.report.json"
LOG="${OUT_DIR}/rch_pressure_packet_goldens.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${SCHEMA}" "${GOLDEN}" "${LIVE_REPORT}" "${LIVE_MARKDOWN}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import sys
import time
from copy import deepcopy
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
SCHEMA = pathlib.Path(sys.argv[2])
GOLDEN = pathlib.Path(sys.argv[3])
LIVE_REPORT = pathlib.Path(sys.argv[4])
LIVE_MARKDOWN = pathlib.Path(sys.argv[5])
REPORT = pathlib.Path(sys.argv[6])
LOG = pathlib.Path(sys.argv[7])
FORBIDDEN_TEXT = re.compile(
    r"\brm\b|\brmdir\b|\bunlink\b|-delete|git reset|git clean|sbh clean|sbh ballast release|sbh emergency|apt(?:-get)?\s+.*clean"
)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def all_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(all_strings(item))
        return result
    if isinstance(value, dict):
        result: list[str] = []
        for item in value.values():
            result.extend(all_strings(item))
        return result
    return []


errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def add_error(source: str, signature: str, message: str) -> None:
    errors.append({"source": source, "failure_signature": signature, "message": message})


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def estimated_total_gb(worker: dict[str, Any]) -> float | None:
    free_gb = float_or_none(worker.get("pressure_disk_free_gb"))
    total_gb = float_or_none(worker.get("pressure_disk_total_gb"))
    if total_gb is None:
        ratio = float_or_none(worker.get("pressure_disk_free_ratio"))
        if free_gb is not None and ratio is not None and ratio > 0:
            total_gb = free_gb / ratio
    return total_gb


def expected_post_cleanup_free_ratio(worker: dict[str, Any], candidate: dict[str, Any]) -> float | None:
    free_gb = float_or_none(worker.get("pressure_disk_free_gb"))
    total_gb = estimated_total_gb(worker)
    size_gb = float_or_none(candidate.get("estimated_size_gb"))
    if free_gb is None or total_gb is None or total_gb <= 0 or size_gb is None:
        return None
    return round((free_gb + size_gb) / total_gb, 6)


def expected_surplus_gb(worker: dict[str, Any], candidate: dict[str, Any]) -> float | None:
    gap_gb = float_or_none(worker.get("estimated_gb_needed_to_reach_target_ratio"))
    size_gb = float_or_none(candidate.get("estimated_size_gb"))
    if gap_gb is None or size_gb is None:
        return None
    return round(size_gb - gap_gb, 3)


def close_enough(actual: Any, expected: float | None, tolerance: float = 0.001) -> bool:
    actual_float = float_or_none(actual)
    if expected is None:
        return actual is None
    return actual_float is not None and abs(actual_float - expected) <= tolerance


REQUIRED_PRE_CLEANUP_CHECK_KINDS = {"sbh_protect_marker_absence", "open_file_absence"}
FORBIDDEN_PRE_CLEANUP_COMMAND = re.compile(
    r"\brm\b|\brmdir\b|\bunlink\b|-delete|git reset|git clean|sbh clean|sbh ballast release|sbh emergency"
)
APPROVAL_READINESS_ALLOWED_STATES = {
    "ready_for_explicit_user_approval",
    "needs_read_only_precheck_results",
    "blocked_by_read_only_precheck_result",
    "blocked_by_missing_read_only_checks",
}
NO_CANDIDATE_ALLOWED_STATUSES = {
    "candidates_identified",
    "no_candidates_identified",
}
ALLOWED_PROBE_FAILURE_SIGNATURES = {
    "ok",
    "RCH-E100",
    "timeout",
    "ssh_permission_denied",
    "sbh_permission_denied",
    "no_matches",
    "unknown",
}


def size_to_gb(size: str) -> float | None:
    stripped = size.strip()
    byte_match = re.match(r"^(?P<bytes>[0-9]+)B$", stripped, re.IGNORECASE)
    if byte_match:
        return round(int(byte_match.group("bytes")) / (1024 * 1024 * 1024), 3)
    match = re.match(r"^(?P<num>\d+(?:\.\d+)?)(?P<unit>[KMGT])$", stripped, re.IGNORECASE)
    if not match:
        return None
    value = float(match.group("num"))
    unit = match.group("unit").upper()
    if unit == "K":
        return round(value / (1024 * 1024), 3)
    if unit == "M":
        return round(value / 1024, 3)
    if unit == "G":
        return round(value, 3)
    if unit == "T":
        return round(value * 1024, 3)
    return None


def classify_bounded_du_finding(worker: dict[str, Any], line: str) -> dict[str, Any] | None:
    match = re.match(r"^(?P<size>\S+)\s+(?P<path>/(tmp|data)/\S+)$", line.strip())
    if not match:
        return None
    path = match.group("path")
    size = match.group("size")
    size_gb = size_to_gb(size)
    is_project_path = path.startswith("/data/projects/")
    is_target_artifact = "/target" in path
    is_rch_artifact = "/.rch-target-" in path
    rejection_reason = None
    if not is_project_path:
        rejection_reason = "outside_project_scope"
    elif not (is_target_artifact or is_rch_artifact):
        rejection_reason = "not_target_or_rch_artifact"
    elif size_gb is None:
        rejection_reason = "unparseable_size"
    elif not is_rch_artifact and not re.search(r"[0-9](G|T)$", size):
        rejection_reason = "target_artifact_below_human_gib_threshold"
    elif is_rch_artifact and size_gb < 0.1:
        rejection_reason = "rch_artifact_below_0_1_gb_threshold"
    return {
        "worker_id": str(worker.get("worker_id") or "unknown"),
        "host": str(worker.get("host") or worker.get("worker_id") or "unknown"),
        "path": path,
        "size_human": size,
        "estimated_size_gb": size_gb,
        "candidate_eligible": rejection_reason is None,
        "candidate_rejection_reason": rejection_reason,
    }


def expected_candidate_rejection_summary(workers: list[Any]) -> dict[str, Any]:
    rejected: list[dict[str, Any]] = []
    finding_count = 0
    for worker in workers:
        if not isinstance(worker, dict):
            continue
        for line in worker.get("bounded_du_findings", []):
            finding = classify_bounded_du_finding(worker, str(line))
            if finding is None:
                continue
            finding_count += 1
            if finding["candidate_eligible"]:
                continue
            rejected.append(
                {
                    "worker_id": finding["worker_id"],
                    "host": finding["host"],
                    "path": finding["path"],
                    "size_human": finding["size_human"],
                    "estimated_size_gb": finding["estimated_size_gb"],
                    "rejection_reason": finding["candidate_rejection_reason"],
                }
            )
    counts: dict[str, int] = {}
    for finding in rejected:
        reason = str(finding.get("rejection_reason") or "unknown")
        counts[reason] = counts.get(reason, 0) + 1
    largest_rejected = sorted(
        rejected,
        key=lambda finding: (
            float_or_none(finding.get("estimated_size_gb")) or -1.0,
            str(finding.get("worker_id") or ""),
            str(finding.get("path") or ""),
        ),
        reverse=True,
    )[:8]
    return {
        "bounded_du_finding_count": finding_count,
        "rejected_finding_count": len(rejected),
        "rejection_count_by_reason": {reason: counts[reason] for reason in sorted(counts)},
        "largest_rejected_findings": largest_rejected,
    }


def validate_pre_cleanup_checks(source: str, path: Any, checks: Any, missing_signature: str) -> None:
    if not isinstance(checks, list) or not checks:
        add_error(source, missing_signature, f"{path} must include read-only pre-cleanup checks")
        return
    seen: set[str] = set()
    for check in checks:
        if not isinstance(check, dict):
            add_error(source, "malformed_pre_cleanup_check", f"{path} has malformed pre-cleanup check")
            continue
        kind = check.get("check_kind")
        command = check.get("command")
        if kind not in REQUIRED_PRE_CLEANUP_CHECK_KINDS:
            add_error(source, "unexpected_pre_cleanup_check_kind", f"{path} has check kind {kind}")
        else:
            seen.add(str(kind))
        if not isinstance(command, str) or not command.startswith("ssh "):
            add_error(source, "invalid_pre_cleanup_check_command", f"{path} has invalid command {command}")
        else:
            if isinstance(path, str) and path not in command:
                add_error(source, "pre_cleanup_check_missing_path", f"{path} check command does not name path")
            if "-o BatchMode=yes" not in command or "-i " not in command:
                add_error(
                    source,
                    "pre_cleanup_check_may_prompt",
                    f"{path} check command must be noninteractive and name an identity file",
                )
            if "-o ConnectTimeout=" not in command:
                add_error(source, "pre_cleanup_check_missing_timeout", f"{path} check command must bound connection time")
            if FORBIDDEN_PRE_CLEANUP_COMMAND.search(command):
                add_error(source, "pre_cleanup_check_not_read_only", f"{path} check command is not read-only")
            if kind == "sbh_protect_marker_absence" and ".sbh-protect" not in command:
                add_error(source, "pre_cleanup_check_missing_protect_marker", f"{path} protect check is incomplete")
            if kind == "open_file_absence" and "lsof +D" not in command:
                add_error(source, "pre_cleanup_check_missing_lsof", f"{path} open-file check is incomplete")
        if check.get("expected_safe_result") != "exit 0 with no stdout":
            add_error(source, "invalid_pre_cleanup_expected_result", f"{path} check must expect no stdout")
        if not isinstance(check.get("blocks_cleanup_if"), str) or not check.get("blocks_cleanup_if"):
            add_error(source, "missing_pre_cleanup_blocker_text", f"{path} check must describe blockers")
        result = check.get("last_result")
        if result is not None:
            validate_pre_cleanup_result(source, path, kind, result)
    missing = REQUIRED_PRE_CLEANUP_CHECK_KINDS - seen
    if missing:
        add_error(source, "missing_pre_cleanup_check_kind", f"{path} missing checks {sorted(missing)}")


def validate_pre_cleanup_result(source: str, path: Any, kind: Any, result: Any) -> None:
    if not isinstance(result, dict):
        add_error(source, "malformed_pre_cleanup_result", f"{path} {kind} result must be an object")
        return
    executed = result.get("executed")
    if executed is not True:
        add_error(source, "pre_cleanup_result_not_executed", f"{path} {kind} result must be executed=true")
    if not isinstance(result.get("executed_at_utc"), str) or not result.get("executed_at_utc"):
        add_error(source, "missing_pre_cleanup_result_timestamp", f"{path} {kind} result must include executed_at_utc")
    timed_out = result.get("timed_out")
    if not isinstance(timed_out, bool):
        add_error(source, "invalid_pre_cleanup_result_timeout", f"{path} {kind} result timed_out must be boolean")
    exit_status = result.get("exit_status")
    if timed_out is True:
        if exit_status is not None:
            add_error(source, "invalid_pre_cleanup_timeout_status", f"{path} {kind} timed-out result must not have exit status")
    elif not isinstance(exit_status, int) or isinstance(exit_status, bool):
        add_error(source, "invalid_pre_cleanup_result_status", f"{path} {kind} result must include integer exit_status")
    stdout = result.get("stdout")
    stderr = result.get("stderr")
    if not isinstance(stdout, str):
        add_error(source, "invalid_pre_cleanup_result_stdout", f"{path} {kind} stdout must be a string")
        stdout = ""
    if not isinstance(stderr, str):
        add_error(source, "invalid_pre_cleanup_result_stderr", f"{path} {kind} stderr must be a string")
        stderr = ""
    expected_passed = (
        timed_out is False
        and exit_status == 0
        and stdout == ""
        and stderr == ""
    )
    if result.get("passed") is not expected_passed:
        add_error(source, "pre_cleanup_result_pass_mismatch", f"{path} {kind} passed flag does not match result output")


def pre_cleanup_result_counts(checks: Any) -> tuple[int, int, int]:
    if not isinstance(checks, list):
        return (0, 0, 0)
    check_count = 0
    collected_count = 0
    passed_count = 0
    for check in checks:
        if not isinstance(check, dict):
            continue
        check_count += 1
        result = check.get("last_result")
        if not isinstance(result, dict):
            continue
        collected_count += 1
        if result.get("passed") is True:
            passed_count += 1
    return (check_count, collected_count, passed_count)


def expected_approval_state(checks: Any) -> tuple[str, list[str], bool]:
    check_count, collected_count, passed_count = pre_cleanup_result_counts(checks)
    if check_count == 0:
        return (
            "blocked_by_missing_read_only_checks",
            ["read_only_checks_missing", "explicit_user_approval_required"],
            False,
        )
    if collected_count < check_count:
        return (
            "needs_read_only_precheck_results",
            ["read_only_precheck_results_missing", "explicit_user_approval_required"],
            False,
        )
    if passed_count == check_count:
        return ("ready_for_explicit_user_approval", ["explicit_user_approval_required"], True)
    return (
        "blocked_by_read_only_precheck_result",
        ["read_only_precheck_failed", "explicit_user_approval_required"],
        False,
    )


def validate_repo_state(packet: dict[str, Any], source: str) -> None:
    repo_state = packet.get("repo_state")
    if not isinstance(repo_state, dict):
        add_error(source, "missing_repo_state", "packet must include repo_state")
        return
    if repo_state.get("branch") != "main":
        add_error(source, "repo_state_branch_not_main", "packet repo_state.branch must be main")
    for field in ("head_commit", "origin_main_commit", "origin_master_commit"):
        if not isinstance(repo_state.get(field), str) or not repo_state.get(field):
            add_error(source, "missing_repo_state_commit", f"repo_state.{field} must resolve to a commit")
    origin_main = repo_state.get("origin_main_commit")
    origin_master = repo_state.get("origin_master_commit")
    if (
        isinstance(origin_main, str)
        and origin_main
        and isinstance(origin_master, str)
        and origin_master
        and origin_main != origin_master
    ):
        add_error(
            source,
            "legacy_mirror_not_synced",
            f"repo_state.origin_master_commit must match origin_main_commit: {origin_master} != {origin_main}",
        )
    worktree_list = repo_state.get("worktree_list")
    if not isinstance(worktree_list, list):
        add_error(source, "missing_repo_state_worktrees", "repo_state.worktree_list must be a list")
        worktree_list = []
    elif len(worktree_list) != 1:
        add_error(source, "worktree_count_mismatch", f"repo_state.worktree_list must contain exactly one worktree, got {len(worktree_list)}")
    for index, worktree in enumerate(worktree_list):
        if not isinstance(worktree, str) or not worktree:
            add_error(source, "malformed_repo_state_worktree", f"repo_state.worktree_list[{index}] must be a non-empty string")
            continue
        if "[main]" not in worktree:
            add_error(source, "worktree_branch_not_main", f"repo_state.worktree_list[{index}] must be on main: {worktree}")
    if not isinstance(repo_state.get("dirty_summary"), list):
        add_error(source, "missing_repo_state_dirty_summary", "repo_state.dirty_summary must be a list")
    if not isinstance(repo_state.get("untracked_summary"), list):
        add_error(source, "missing_repo_state_untracked_summary", "repo_state.untracked_summary must be a list")


def validate_no_candidate_diagnostics(
    packet: dict[str, Any],
    source: str,
    candidates: list[Any],
    workers: list[Any],
) -> None:
    diagnostics = packet.get("no_candidate_diagnostics")
    if not isinstance(diagnostics, dict):
        add_error(source, "missing_no_candidate_diagnostics", "packet must explain candidate discovery status")
        return
    status = diagnostics.get("status")
    if status not in NO_CANDIDATE_ALLOWED_STATUSES:
        add_error(source, "invalid_no_candidate_status", f"invalid no_candidate_diagnostics.status={status}")
    if diagnostics.get("candidate_count") != len(candidates):
        add_error(source, "no_candidate_count_mismatch", "no_candidate_diagnostics.candidate_count must match cleanup_candidates")
    critical_workers = [
        worker
        for worker in workers
        if isinstance(worker, dict) and worker.get("pressure_state") == "critical"
    ]
    if diagnostics.get("critical_worker_count") != len(critical_workers):
        add_error(source, "critical_worker_count_mismatch", "no_candidate_diagnostics.critical_worker_count must match workers")
    for field in (
        "workers_with_bounded_du_findings",
        "critical_workers_without_candidates",
        "probe_failure_workers",
        "collection_error_workers",
    ):
        if not isinstance(diagnostics.get(field), list) or not all(
            isinstance(item, str) for item in diagnostics.get(field, [])
        ):
            add_error(source, "invalid_no_candidate_diagnostic_list", f"no_candidate_diagnostics.{field} must be a string list")
    if not isinstance(diagnostics.get("diagnostic_summary"), str) or not diagnostics.get("diagnostic_summary"):
        add_error(source, "missing_no_candidate_summary", "no_candidate_diagnostics must include diagnostic_summary")
    if not isinstance(diagnostics.get("next_action"), str) or not diagnostics.get("next_action"):
        add_error(source, "missing_no_candidate_next_action", "no_candidate_diagnostics must include next_action")
    expected_rejection_summary = expected_candidate_rejection_summary(workers)
    if diagnostics.get("candidate_rejection_summary") != expected_rejection_summary:
        add_error(
            source,
            "candidate_rejection_summary_mismatch",
            f"candidate_rejection_summary={diagnostics.get('candidate_rejection_summary')} expected={expected_rejection_summary}",
        )
    if candidates and status != "candidates_identified":
        add_error(source, "candidate_status_mismatch", "packets with cleanup candidates must report candidates_identified")
    if not candidates and status != "no_candidates_identified":
        add_error(source, "no_candidate_status_mismatch", "packets without cleanup candidates must report no_candidates_identified")


def expected_approval_ready_summary(readiness: list[Any]) -> dict[str, Any]:
    ready_rows = [
        item
        for item in readiness
        if isinstance(item, dict) and item.get("approval_state") == "ready_for_explicit_user_approval"
    ]
    count_by_worker: dict[str, int] = {}
    ready_paths: list[str] = []
    for item in ready_rows:
        worker_id = str(item.get("worker_id") or "")
        path = str(item.get("path") or "")
        if worker_id:
            count_by_worker[worker_id] = count_by_worker.get(worker_id, 0) + 1
        if path:
            ready_paths.append(path)
    return {
        "status": "ready_for_explicit_user_approval" if ready_rows else "no_ready_candidates",
        "ready_for_explicit_user_approval_count": len(ready_rows),
        "ready_worker_ids": sorted(count_by_worker),
        "ready_candidate_count_by_worker": {
            worker_id: count_by_worker[worker_id] for worker_id in sorted(count_by_worker)
        },
        "ready_candidate_paths": ready_paths,
        "safe_to_run_without_user_approval": False,
        "exact_user_approval_required": True,
        "cleanup_executed": False,
        "next_action": "request_explicit_user_approval_for_current_ready_paths"
        if ready_rows
        else "collect_passing_read_only_precheck_results_before_requesting_user_approval",
    }


def validate_approval_ready_summary(packet: dict[str, Any], source: str, readiness: list[Any]) -> None:
    summary = packet.get("approval_ready_summary")
    if not isinstance(summary, dict):
        add_error(source, "missing_approval_ready_summary", "approval_ready_summary must be an object")
        return
    expected = expected_approval_ready_summary(readiness)
    for field, expected_value in expected.items():
        if summary.get(field) != expected_value:
            add_error(
                source,
                "approval_ready_summary_mismatch",
                f"approval_ready_summary.{field}={summary.get(field)} expected={expected_value}",
            )
    for field in expected:
        if field not in summary:
            add_error(source, "approval_ready_summary_missing_field", f"approval_ready_summary missing {field}")


def validate_packet(packet: dict[str, Any], source: str, require_rch_e100: bool) -> None:
    if packet.get("schema_version") != "rch_pressure_approval_packet_schema.v1":
        add_error(source, "schema_version", "packet schema_version mismatch")
    validate_repo_state(packet, source)
    gate = packet.get("rch_gate", {})
    dry_run_command = gate.get("dry_run_command")
    if (
        not isinstance(dry_run_command, str)
        or "rch diagnose --dry-run" not in dry_run_command
        or "cargo " not in dry_run_command
    ):
        add_error(source, "invalid_rch_dry_run_command", "rch_gate.dry_run_command must be an rch diagnose --dry-run cargo command")
    if gate.get("dry_run_exit_status") != 0:
        add_error(source, "invalid_rch_dry_run_status", "rch_gate.dry_run_exit_status must be 0")
    if gate.get("required_remote_env") != "RCH_REQUIRE_REMOTE=1":
        add_error(source, "missing_remote_env", "packet must require RCH_REQUIRE_REMOTE=1")
    if "[RCH] local" not in gate.get("fallback_markers_rejected", []):
        add_error(source, "missing_local_fallback_rejection", "packet must reject [RCH] local")
    if gate.get("would_offload") is not True:
        add_error(source, "rch_gate_not_offloadable", "rch_gate must preserve that the command would offload")
    if gate.get("worker_selection_status") != "skipped":
        add_error(source, "rch_gate_worker_selection_not_skipped", "rch_gate must preserve skipped worker selection")
    skip_reason = gate.get("skip_reason")
    if not isinstance(skip_reason, str) or "critical_pressure" not in skip_reason:
        add_error(source, "rch_gate_missing_critical_pressure", "rch_gate.skip_reason must name critical_pressure")

    workers = packet.get("workers", [])
    worker_by_id = {
        str(worker.get("worker_id")): worker
        for worker in workers
        if isinstance(worker, dict) and worker.get("worker_id") is not None
    }
    if not any(worker.get("pressure_state") == "critical" for worker in workers if isinstance(worker, dict)):
        add_error(source, "missing_critical_worker", "packet must include a critical-pressure worker")
    if require_rch_e100 and not any(worker.get("probe_failure_signature") == "RCH-E100" for worker in workers if isinstance(worker, dict)):
        add_error(source, "missing_rch_e100_worker", "packet must include a disabled/unreachable RCH-E100 worker")
    if not any(worker.get("bounded_du_findings") for worker in workers if isinstance(worker, dict)):
        add_error(source, "missing_du_findings", "packet must preserve bounded du findings")
    for worker in workers:
        if not isinstance(worker, dict) or worker.get("pressure_state") != "critical":
            continue
        worker_id = worker.get("worker_id", "<unknown>")
        probe_signature = worker.get("probe_failure_signature")
        if not isinstance(probe_signature, str) or probe_signature not in ALLOWED_PROBE_FAILURE_SIGNATURES:
            add_error(
                source,
                "invalid_probe_failure_signature",
                f"{worker_id} has invalid probe_failure_signature={probe_signature}",
            )
        target = worker.get("estimated_free_ratio_target")
        if not is_number(target):
            add_error(source, "missing_pressure_gap_target", f"{worker_id} missing numeric estimated_free_ratio_target")
        elif not (0 < float(target) <= 1):
            add_error(source, "invalid_pressure_gap_target", f"{worker_id} has invalid estimated_free_ratio_target={target}")
        gap = worker.get("estimated_gb_needed_to_reach_target_ratio")
        if gap is None:
            if worker.get("pressure_disk_free_gb") is not None or worker.get("pressure_disk_total_gb") is not None:
                add_error(source, "missing_pressure_gap_estimate", f"{worker_id} missing gap estimate despite disk metrics")
        elif not is_number(gap) or float(gap) < 0:
            add_error(source, "invalid_pressure_gap_estimate", f"{worker_id} has invalid gap estimate={gap}")
        if worker.get("pressure_disk_free_gb") is not None and not is_number(worker.get("pressure_disk_free_gb")):
            add_error(source, "invalid_pressure_free_gb", f"{worker_id} pressure_disk_free_gb is not numeric")
        if worker.get("pressure_disk_total_gb") is not None and not is_number(worker.get("pressure_disk_total_gb")):
            add_error(source, "invalid_pressure_total_gb", f"{worker_id} pressure_disk_total_gb is not numeric")
        if worker.get("pressure_disk_free_ratio") is not None and not is_number(worker.get("pressure_disk_free_ratio")):
            add_error(source, "invalid_pressure_free_ratio", f"{worker_id} pressure_disk_free_ratio is not numeric")
        sbh_snapshot = worker.get("sbh_snapshot")
        if sbh_snapshot == "present in raw worker output":
            add_error(source, "coarse_sbh_snapshot", f"{worker_id} must expose parsed SBH status details")
        elif isinstance(sbh_snapshot, str) and sbh_snapshot and "overall" not in sbh_snapshot:
            add_error(source, "malformed_sbh_snapshot", f"{worker_id} sbh_snapshot must include overall pressure status")
        ballast_snapshot = worker.get("ballast_snapshot")
        if ballast_snapshot == "present in raw worker output":
            add_error(source, "coarse_ballast_snapshot", f"{worker_id} must expose parsed ballast counts")
        elif isinstance(ballast_snapshot, str) and ballast_snapshot:
            for token in ["available_count=", "releasable_bytes=", "missing_count="]:
                if token not in ballast_snapshot:
                    add_error(source, "malformed_ballast_snapshot", f"{worker_id} ballast_snapshot missing {token}")
    for worker in workers:
        if not isinstance(worker, dict):
            continue
        worker_id = worker.get("worker_id", "<unknown>")
        direct_command = worker.get("direct_rch_probe_command")
        direct_status = worker.get("direct_rch_probe_exit_status")
        direct_raw_path = worker.get("direct_rch_probe_raw_output_path")
        if worker.get("probe_failure_signature") == "RCH-E100":
            if not isinstance(direct_command, str) or f"rch workers probe {worker_id}" not in direct_command:
                add_error(source, "missing_direct_rch_probe_command", f"{worker_id} RCH-E100 row lacks direct probe command")
            elif not direct_command.startswith("timeout "):
                add_error(source, "direct_rch_probe_unbounded", f"{worker_id} direct probe command must be timeout-bounded")
            if not isinstance(direct_status, int) or isinstance(direct_status, bool) or direct_status == 0:
                add_error(source, "missing_direct_rch_probe_status", f"{worker_id} RCH-E100 row lacks nonzero direct probe status")
            if not isinstance(direct_raw_path, str) or not direct_raw_path.endswith(f"rch_worker_probe_{worker_id}.out"):
                add_error(source, "missing_direct_rch_probe_raw_output", f"{worker_id} RCH-E100 row lacks raw output path")
        if isinstance(direct_command, str) and direct_command:
            if not direct_command.startswith("timeout ") or "rch workers probe " not in direct_command:
                add_error(source, "invalid_direct_rch_probe_command", f"{worker_id} direct probe command is malformed")
            if FORBIDDEN_PRE_CLEANUP_COMMAND.search(direct_command):
                add_error(source, "direct_rch_probe_not_read_only", f"{worker_id} direct probe command is not read-only")
            if not isinstance(direct_status, int) or isinstance(direct_status, bool):
                add_error(source, "invalid_direct_rch_probe_status", f"{worker_id} direct probe status must be an integer")
            if not isinstance(direct_raw_path, str) or not direct_raw_path:
                add_error(source, "invalid_direct_rch_probe_raw_output", f"{worker_id} direct probe must preserve a raw output path")

    candidates = packet.get("cleanup_candidates", [])
    if not isinstance(candidates, list):
        add_error(source, "malformed_cleanup_candidates", "cleanup_candidates must be a list")
        candidates = []
    validate_no_candidate_diagnostics(packet, source, candidates, workers)
    candidate_paths = set()
    candidates_by_worker: dict[str, list[dict[str, Any]]] = {}
    candidate_by_worker_path: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            add_error(source, "malformed_candidate", "cleanup candidate must be an object")
            continue
        worker_id = str(candidate.get("worker_id", ""))
        path = str(candidate.get("path", ""))
        candidates_by_worker.setdefault(worker_id, []).append(candidate)
        candidate_by_worker_path[(worker_id, path)] = candidate
        candidate_paths.add(candidate.get("path"))
        rank = candidate.get("candidate_rank")
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1:
            add_error(source, "invalid_candidate_rank", f"{candidate.get('path')} has invalid candidate_rank={rank}")
        if candidate.get("requires_explicit_approval") is not True:
            add_error(source, "candidate_not_approval_gated", f"{candidate.get('path')} lacks approval gate")
        if candidate.get("executed") is not False:
            add_error(source, "candidate_executed", f"{candidate.get('path')} must remain executed=false")
        if not str(candidate.get("path", "")).startswith("/data/projects/"):
            add_error(source, "candidate_path_scope", f"{candidate.get('path')} is outside /data/projects")
        if not isinstance(candidate.get("host"), str) or not candidate.get("host"):
            add_error(source, "missing_candidate_host", f"{candidate.get('path')} must identify its worker host")
        validate_pre_cleanup_checks(
            source,
            candidate.get("path"),
            candidate.get("pre_cleanup_read_only_checks"),
            "missing_pre_cleanup_checks",
        )
        if candidate.get("estimated_size_gb") is not None and (not is_number(candidate.get("estimated_size_gb")) or float(candidate.get("estimated_size_gb")) < 0):
            add_error(source, "invalid_candidate_size_estimate", f"{candidate.get('path')} has invalid estimated_size_gb={candidate.get('estimated_size_gb')}")
    for worker_id, worker_candidates in candidates_by_worker.items():
        ranked = sorted(
            worker_candidates,
            key=lambda candidate: (
                float_or_none(candidate.get("estimated_size_gb")) is None,
                float_or_none(candidate.get("estimated_size_gb")) or float("inf"),
                str(candidate.get("path", "")),
            ),
        )
        for expected_rank, candidate in enumerate(ranked, start=1):
            if candidate.get("candidate_rank") != expected_rank:
                add_error(
                    source,
                    "candidate_rank_mismatch",
                    f"{candidate.get('path')} rank={candidate.get('candidate_rank')} expected={expected_rank}",
                )

    recommended = packet.get("recommended_cleanup_candidates", [])
    if not isinstance(recommended, list):
        add_error(source, "malformed_recommended_candidates", "recommended_cleanup_candidates must be a list")
        recommended = []
    recommended_order = [
        (
            str(candidate.get("worker_id", "")),
            int(candidate.get("candidate_rank", 999999)) if isinstance(candidate.get("candidate_rank"), int) else 999999,
            str(candidate.get("path", "")),
        )
        for candidate in recommended
        if isinstance(candidate, dict)
    ]
    if recommended_order != sorted(recommended_order):
        add_error(source, "recommended_candidates_unsorted", "recommended cleanup candidates must be sorted by worker_id, rank, path")
    for candidate in recommended:
        if not isinstance(candidate, dict):
            add_error(source, "malformed_recommended_candidate", "recommended cleanup candidate must be an object")
            continue
        worker_id = str(candidate.get("worker_id", ""))
        path = candidate.get("path")
        worker = worker_by_id.get(worker_id)
        listed_candidate = candidate_by_worker_path.get((worker_id, str(path)))
        if path not in candidate_paths:
            add_error(source, "recommended_candidate_not_listed", f"{path} is not present in cleanup_candidates")
        elif listed_candidate is not None and candidate.get("candidate_rank") != listed_candidate.get("candidate_rank"):
            add_error(source, "recommended_candidate_rank_mismatch", f"{path} rank does not match cleanup candidate")
        if candidate.get("requires_explicit_approval") is not True:
            add_error(source, "recommended_candidate_not_approval_gated", f"{path} lacks approval gate")
        if candidate.get("executed") is not False:
            add_error(source, "recommended_candidate_executed", f"{path} must remain executed=false")
        if candidate.get("recommendation_kind") != "smallest_listed_candidate_meeting_estimated_gap":
            add_error(source, "recommended_candidate_kind", f"{path} has unexpected recommendation_kind")
        if not isinstance(candidate.get("recommendation_reason"), str) or "smallest" not in candidate.get("recommendation_reason", ""):
            add_error(source, "missing_recommendation_reason", f"{path} must explain the ranking reason")
        validate_pre_cleanup_checks(
            source,
            path,
            candidate.get("pre_cleanup_read_only_checks"),
            "recommended_candidate_missing_pre_cleanup_checks",
        )
        size_gb = candidate.get("estimated_size_gb")
        gap_gb = candidate.get("estimated_gap_gb")
        if not is_number(size_gb) or float(size_gb) < 0:
            add_error(source, "invalid_recommended_candidate_size", f"{path} has invalid estimated_size_gb={size_gb}")
        if not is_number(gap_gb) or float(gap_gb) < 0:
            add_error(source, "invalid_recommended_candidate_gap", f"{path} has invalid estimated_gap_gb={gap_gb}")
        elif is_number(size_gb) and float(size_gb) < float(gap_gb):
            add_error(source, "recommended_candidate_too_small", f"{path} is smaller than estimated gap")
        if not is_number(candidate.get("candidate_rank")) or int(candidate.get("candidate_rank")) < 1:
            add_error(source, "invalid_recommended_candidate_rank", f"{path} has invalid candidate_rank")
        if worker is not None:
            if not close_enough(
                candidate.get("estimated_post_cleanup_free_ratio"),
                expected_post_cleanup_free_ratio(worker, candidate),
                0.00001,
            ):
                add_error(source, "invalid_recommended_post_cleanup_ratio", f"{path} has invalid post-cleanup ratio")
            if not close_enough(
                candidate.get("estimated_surplus_gb_after_cleanup"),
                expected_surplus_gb(worker, candidate),
            ):
                add_error(source, "invalid_recommended_surplus", f"{path} has invalid post-cleanup surplus")
            worker_gap = float_or_none(worker.get("estimated_gb_needed_to_reach_target_ratio"))
            if worker_gap is not None:
                sufficient = [
                    item
                    for item in candidates_by_worker.get(worker_id, [])
                    if float_or_none(item.get("estimated_size_gb")) is not None
                    and float(item["estimated_size_gb"]) >= worker_gap
                ]
                if sufficient:
                    expected = min(
                        sufficient,
                        key=lambda item: (
                            float(item["estimated_size_gb"]),
                            int(item.get("candidate_rank", 999999)),
                            str(item.get("path", "")),
                        ),
                    )
                    if str(expected.get("path")) != str(path):
                        add_error(
                            source,
                            "recommended_candidate_not_smallest_sufficient",
                            f"{path} is not the smallest sufficient candidate for {worker_id}",
                        )

    approval = packet.get("approval_request", {})
    required_approval_fields = [
        "operator_summary",
        "exact_worker_ids",
        "exact_candidate_paths",
        "smallest_sufficient_candidate_paths",
        "minimum_margin_surplus_gb",
        "margin_sufficient_candidate_paths",
        "why_read_only_collection_is_insufficient",
        "explicit_user_text_required_before_cleanup",
        "commands_not_executed",
    ]
    for field in required_approval_fields:
        if field not in approval:
            add_error(source, "missing_approval_field", f"approval_request missing {field}")
    approval_text = approval.get("explicit_user_text_required_before_cleanup")
    if not isinstance(approval_text, str):
        add_error(source, "invalid_explicit_approval_text", "approval_request explicit approval text must be a string")
    else:
        lowered_approval_text = approval_text.lower()
        if (
            "written approval" not in lowered_approval_text
            or "exact" not in lowered_approval_text
            or "path" not in lowered_approval_text
            or "command" not in lowered_approval_text
            or "before cleanup" not in lowered_approval_text
        ):
            add_error(
                source,
                "explicit_approval_text_too_weak",
                "approval_request must require written approval naming exact paths and commands before cleanup",
            )
    commands_not_executed = approval.get("commands_not_executed")
    if not isinstance(commands_not_executed, list) or not all(isinstance(item, str) for item in commands_not_executed):
        add_error(source, "invalid_commands_not_executed", "approval_request.commands_not_executed must be a string list")
        commands_not_executed = []
    lowered_commands = [item.lower() for item in commands_not_executed]
    required_unexecuted_commands = {
        "deletion": "missing_unexecuted_deletion_command",
        "ballast release": "missing_unexecuted_ballast_release_command",
        "repository cleanup": "missing_unexecuted_repository_cleanup_command",
    }
    for phrase, signature in required_unexecuted_commands.items():
        if not any(phrase in item and "no " in item and "executed" in item for item in lowered_commands):
            add_error(source, signature, f"commands_not_executed must record that no {phrase} command executed")
    approval_worker_ids = approval.get("exact_worker_ids")
    expected_worker_ids = sorted(worker_id for worker_id in candidates_by_worker if worker_id)
    if not isinstance(approval_worker_ids, list) or not all(isinstance(worker_id, str) for worker_id in approval_worker_ids):
        add_error(source, "invalid_exact_worker_ids", "approval_request.exact_worker_ids must be a string list")
    elif approval_worker_ids != expected_worker_ids:
        add_error(
            source,
            "exact_worker_ids_mismatch",
            f"exact_worker_ids={approval_worker_ids} expected={expected_worker_ids}",
        )
    approval_candidate_paths = approval.get("exact_candidate_paths")
    expected_candidate_paths = [str(candidate.get("path", "")) for candidate in candidates if isinstance(candidate, dict)]
    if not isinstance(approval_candidate_paths, list) or not all(isinstance(path, str) for path in approval_candidate_paths):
        add_error(source, "invalid_exact_candidate_paths", "approval_request.exact_candidate_paths must be a string list")
        approval_candidate_paths = []
    elif approval_candidate_paths != expected_candidate_paths:
        add_error(
            source,
            "exact_candidate_paths_mismatch",
            f"exact_candidate_paths={approval_candidate_paths} expected={expected_candidate_paths}",
        )
    smallest_paths = approval.get("smallest_sufficient_candidate_paths")
    expected_smallest_paths = [str(candidate.get("path", "")) for candidate in recommended if isinstance(candidate, dict)]
    if not isinstance(smallest_paths, list) or not all(isinstance(path, str) for path in smallest_paths):
        add_error(
            source,
            "invalid_smallest_candidate_paths",
            "approval_request.smallest_sufficient_candidate_paths must be a string list",
        )
    elif smallest_paths != expected_smallest_paths:
        add_error(
            source,
            "smallest_sufficient_candidate_paths_mismatch",
            f"smallest_sufficient_candidate_paths={smallest_paths} expected={expected_smallest_paths}",
        )
    ballast_snapshots = [
        worker.get("ballast_snapshot")
        for worker in workers
        if isinstance(worker, dict)
        and isinstance(worker.get("ballast_snapshot"), str)
        and worker.get("ballast_snapshot")
    ]
    has_approval_candidates = isinstance(approval_candidate_paths, list) and bool(approval_candidate_paths)
    if (
        has_approval_candidates
        and ballast_snapshots
        and all("releasable_bytes=0" in snapshot for snapshot in ballast_snapshots)
    ):
        insufficient_reason = approval.get("why_read_only_collection_is_insufficient")
        if (
            not isinstance(insufficient_reason, str)
            or "No releasable SBH ballast" not in insufficient_reason
            or "deletion-level" not in insufficient_reason
            or ("approval" not in insufficient_reason and "cleanup" not in insufficient_reason)
        ):
            add_error(
                source,
                "approval_reason_omits_non_releasable_ballast",
                "approval_request must explain that sampled SBH ballast is not releasable",
            )
    margin_surplus = approval.get("minimum_margin_surplus_gb")
    if not is_number(margin_surplus) or float(margin_surplus) < 0:
        add_error(source, "invalid_margin_surplus", "approval_request.minimum_margin_surplus_gb must be a non-negative number")
        margin_surplus = None
    margin_paths = approval.get("margin_sufficient_candidate_paths")
    if not isinstance(margin_paths, list) or not all(isinstance(path, str) for path in margin_paths):
        add_error(source, "invalid_margin_candidate_paths", "approval_request.margin_sufficient_candidate_paths must be a string list")
        margin_paths = []
    else:
        for path in margin_paths:
            if path not in candidate_paths:
                add_error(source, "margin_candidate_not_listed", f"{path} is not present in cleanup_candidates")
    if is_number(margin_surplus):
        expected_margin_items: list[tuple[str, int, str]] = []
        for worker in workers:
            if not isinstance(worker, dict) or worker.get("pressure_state") != "critical":
                continue
            worker_id = str(worker.get("worker_id", ""))
            worker_gap = float_or_none(worker.get("estimated_gb_needed_to_reach_target_ratio"))
            if worker_gap is None:
                continue
            sufficient = [
                item
                for item in candidates_by_worker.get(worker_id, [])
                if float_or_none(item.get("estimated_size_gb")) is not None
                and float(item["estimated_size_gb"]) >= worker_gap + float(margin_surplus)
            ]
            if not sufficient:
                continue
            expected = min(
                sufficient,
                key=lambda item: (
                    float(item["estimated_size_gb"]),
                    int(item.get("candidate_rank", 999999)),
                    str(item.get("path", "")),
                ),
            )
            expected_margin_items.append(
                (
                    worker_id,
                    int(expected.get("candidate_rank", 999999))
                    if isinstance(expected.get("candidate_rank"), int)
                    else 999999,
                    str(expected.get("path")),
                )
            )
        expected_margin_paths = [path for _, _, path in sorted(expected_margin_items)]
        if isinstance(margin_paths, list) and margin_paths != expected_margin_paths:
            add_error(
                source,
                "margin_candidate_paths_mismatch",
                f"margin_sufficient_candidate_paths={margin_paths} expected={expected_margin_paths}",
            )
    selected_readiness: dict[tuple[str, str], dict[str, Any]] = {}
    expected_kinds: dict[tuple[str, str], set[str]] = {}
    for candidate in recommended:
        if not isinstance(candidate, dict):
            continue
        key = (str(candidate.get("worker_id", "")), str(candidate.get("path", "")))
        selected_readiness[key] = candidate
        expected_kinds.setdefault(key, set()).add("smallest_listed_candidate_meeting_estimated_gap")
    for path in margin_paths:
        for candidate in candidates:
            if not isinstance(candidate, dict) or str(candidate.get("path", "")) != str(path):
                continue
            key = (str(candidate.get("worker_id", "")), str(candidate.get("path", "")))
            selected_readiness.setdefault(key, candidate)
            expected_kinds.setdefault(key, set()).add("smallest_listed_candidate_meeting_estimated_gap_plus_margin")
    readiness = packet.get("approval_readiness")
    if not isinstance(readiness, list):
        add_error(source, "malformed_approval_readiness", "approval_readiness must be a list")
        readiness = []
    expected_readiness_order = sorted(
        selected_readiness,
        key=lambda key: (
            key[0],
            int(selected_readiness[key].get("candidate_rank", 999999))
            if isinstance(selected_readiness[key].get("candidate_rank"), int)
            else 999999,
            key[1],
        ),
    )
    actual_readiness_order = [
        (str(item.get("worker_id", "")), str(item.get("path", "")))
        for item in readiness
        if isinstance(item, dict)
    ]
    if actual_readiness_order != expected_readiness_order:
        add_error(
            source,
            "approval_readiness_order_mismatch",
            f"approval_readiness order={actual_readiness_order} expected={expected_readiness_order}",
        )
    for item in readiness:
        if not isinstance(item, dict):
            add_error(source, "malformed_approval_readiness_item", "approval_readiness entries must be objects")
            continue
        key = (str(item.get("worker_id", "")), str(item.get("path", "")))
        candidate = selected_readiness.get(key)
        if candidate is None:
            add_error(source, "approval_readiness_unknown_candidate", f"{key[1]} is not a selected recommendation")
            continue
        if item.get("safe_to_run_without_user_approval") is not False:
            add_error(source, "approval_readiness_claims_safe_without_user_approval", f"{key[1]} must remain user-approval gated")
        if item.get("exact_user_approval_required") is not True:
            add_error(source, "approval_readiness_missing_user_approval_gate", f"{key[1]} must require explicit user approval")
        if item.get("cleanup_executed") is not False:
            add_error(source, "approval_readiness_claims_execution", f"{key[1]} must not claim execution")
        if item.get("host") != candidate.get("host"):
            add_error(source, "approval_readiness_host_mismatch", f"{key[1]} host does not match selected candidate")
        if item.get("candidate_rank") != candidate.get("candidate_rank"):
            add_error(source, "approval_readiness_rank_mismatch", f"{key[1]} rank does not match selected candidate")
        kinds = item.get("recommendation_kinds")
        if not isinstance(kinds, list) or {str(kind) for kind in kinds} != expected_kinds.get(key, set()):
            add_error(source, "approval_readiness_kind_mismatch", f"{key[1]} recommendation kinds are incorrect")
        check_count, collected_count, passed_count = pre_cleanup_result_counts(
            candidate.get("pre_cleanup_read_only_checks")
        )
        if item.get("read_only_check_count") != check_count:
            add_error(source, "approval_readiness_check_count_mismatch", f"{key[1]} check_count mismatch")
        if item.get("read_only_check_results_collected") != collected_count:
            add_error(source, "approval_readiness_collected_count_mismatch", f"{key[1]} collected_count mismatch")
        if item.get("read_only_check_results_passed") != passed_count:
            add_error(source, "approval_readiness_passed_count_mismatch", f"{key[1]} passed_count mismatch")
        expected_state, expected_blockers, expected_passed = expected_approval_state(
            candidate.get("pre_cleanup_read_only_checks")
        )
        if item.get("approval_state") not in APPROVAL_READINESS_ALLOWED_STATES:
            add_error(source, "approval_readiness_invalid_state", f"{key[1]} has invalid approval_state")
        elif item.get("approval_state") != expected_state:
            add_error(source, "approval_readiness_state_mismatch", f"{key[1]} approval_state mismatch")
        if item.get("blocked_by") != expected_blockers:
            add_error(source, "approval_readiness_blockers_mismatch", f"{key[1]} blocked_by mismatch")
        if item.get("read_only_checks_passed") is not expected_passed:
            add_error(source, "approval_readiness_pass_flag_mismatch", f"{key[1]} read_only_checks_passed mismatch")
        next_action = item.get("next_action")
        if expected_state == "ready_for_explicit_user_approval":
            if next_action != "request_explicit_user_approval_for_exact_path":
                add_error(source, "approval_readiness_next_action_mismatch", f"{key[1]} next_action mismatch")
        elif next_action != "collect_passing_read_only_precheck_results_before_requesting_user_approval":
            add_error(source, "approval_readiness_next_action_mismatch", f"{key[1]} next_action mismatch")
    validate_approval_ready_summary(packet, source, readiness)
    if not all(item.get("executed") is True for item in packet.get("executed_actions", []) if isinstance(item, dict)):
        add_error(source, "missing_execution_log", "executed_actions must log completed read-only actions")

    for text in all_strings(packet):
        if FORBIDDEN_TEXT.search(text):
            add_error(source, "forbidden_cleanup_primitive", f"forbidden cleanup primitive appears in text: {text}")

    events.append(
        {
            "source": source,
            "candidate_count": len(candidates),
            "worker_count": len(workers),
            "status": "checked",
        }
    )


def first_critical_worker(packet: dict[str, Any]) -> dict[str, Any] | None:
    for worker in packet.get("workers", []):
        if isinstance(worker, dict) and worker.get("pressure_state") == "critical":
            return worker
    return None


def first_recommended_candidate(packet: dict[str, Any]) -> dict[str, Any] | None:
    for candidate in packet.get("recommended_cleanup_candidates", []):
        if isinstance(candidate, dict):
            return candidate
    return None


def expect_validation_failure(packet: dict[str, Any], source: str, signature: str, mutation: str) -> None:
    before_errors = len(errors)
    before_events = len(events)
    validate_packet(packet, source, require_rch_e100=False)
    observed_errors = errors[before_errors:]
    del errors[before_errors:]
    del events[before_events:]
    if any(error.get("failure_signature") == signature for error in observed_errors):
        events.append(
            {
                "source": source,
                "expected_failure_signature": signature,
                "mutation": mutation,
                "status": "negative_checked",
            }
        )
        return
    observed = sorted({str(error.get("failure_signature")) for error in observed_errors})
    add_error(
        source,
        "negative_control_missed",
        f"{mutation} did not trigger {signature}; observed={observed}",
    )


def validate_markdown_text(source: str, markdown_text: str, required_lines: list[str]) -> None:
    if FORBIDDEN_TEXT.search(markdown_text):
        add_error(source, "forbidden_live_markdown_primitive", "live markdown includes forbidden cleanup primitive")
    for line in required_lines:
        if line not in markdown_text:
            add_error(source, "missing_markdown_line", f"live markdown missing required text: {line}")


def expect_markdown_validation_failure(markdown_text: str, source: str, required_lines: list[str], signature: str, mutation: str) -> None:
    before_errors = len(errors)
    before_events = len(events)
    validate_markdown_text(source, markdown_text, required_lines)
    observed_errors = errors[before_errors:]
    del errors[before_errors:]
    del events[before_events:]
    if any(error.get("failure_signature") == signature for error in observed_errors):
        events.append(
            {
                "source": source,
                "expected_failure_signature": signature,
                "mutation": mutation,
                "status": "negative_checked",
            }
        )
        return
    observed = sorted({str(error.get("failure_signature")) for error in observed_errors})
    add_error(
        source,
        "negative_markdown_control_missed",
        f"{mutation} did not trigger {signature}; observed={observed}",
    )


def validate_negative_controls(packet: dict[str, Any], source: str) -> None:
    missing_dry_run_packet = deepcopy(packet)
    gate = missing_dry_run_packet.get("rch_gate")
    if isinstance(gate, dict) and isinstance(gate.get("dry_run_command"), str):
        gate["dry_run_command"] = gate["dry_run_command"].replace(" --dry-run", "")
        expect_validation_failure(
            missing_dry_run_packet,
            f"{source}::invalid_rch_dry_run_command",
            "invalid_rch_dry_run_command",
            "remove --dry-run from rch gate command",
        )
    else:
        add_error(source, "negative_control_no_rch_dry_run_command", "golden packet has no rch dry-run command for mutation")

    missing_pressure_skip_packet = deepcopy(packet)
    gate = missing_pressure_skip_packet.get("rch_gate")
    if isinstance(gate, dict):
        gate["skip_reason"] = "no admissible workers"
        expect_validation_failure(
            missing_pressure_skip_packet,
            f"{source}::rch_gate_missing_critical_pressure",
            "rch_gate_missing_critical_pressure",
            "remove critical_pressure from rch_gate skip reason",
        )
    else:
        add_error(source, "negative_control_no_rch_gate", "golden packet has no rch_gate for mutation")

    missing_target_packet = deepcopy(packet)
    worker = first_critical_worker(missing_target_packet)
    if worker is None:
        add_error(source, "negative_control_no_critical_worker", "golden packet has no critical worker for mutation")
    else:
        worker.pop("estimated_free_ratio_target", None)
        expect_validation_failure(
            missing_target_packet,
            f"{source}::missing_pressure_gap_target",
            "missing_pressure_gap_target",
            "remove estimated_free_ratio_target from first critical worker",
        )

    invalid_probe_signature_packet = deepcopy(packet)
    worker = first_critical_worker(invalid_probe_signature_packet)
    if worker is None:
        add_error(source, "negative_control_no_critical_worker", "golden packet has no critical worker for mutation")
    else:
        worker["probe_failure_signature"] = "mystery_probe_failure"
        expect_validation_failure(
            invalid_probe_signature_packet,
            f"{source}::invalid_probe_failure_signature",
            "invalid_probe_failure_signature",
            "replace first critical worker probe failure signature with an unknown value",
        )

    invalid_gap_packet = deepcopy(packet)
    worker = first_critical_worker(invalid_gap_packet)
    if worker is None:
        add_error(source, "negative_control_no_critical_worker", "golden packet has no critical worker for mutation")
    else:
        worker["estimated_gb_needed_to_reach_target_ratio"] = -1.0
        expect_validation_failure(
            invalid_gap_packet,
            f"{source}::invalid_pressure_gap_estimate",
            "invalid_pressure_gap_estimate",
            "set negative estimated_gb_needed_to_reach_target_ratio on first critical worker",
        )

    too_small_recommendation_packet = deepcopy(packet)
    candidate = first_recommended_candidate(too_small_recommendation_packet)
    if candidate is None:
        add_error(source, "negative_control_no_recommended_candidate", "golden packet has no recommended candidate for mutation")
    else:
        candidate["estimated_size_gb"] = 0.0
        candidate["estimated_gap_gb"] = 1.0
        expect_validation_failure(
            too_small_recommendation_packet,
            f"{source}::recommended_candidate_too_small",
            "recommended_candidate_too_small",
            "make first recommended candidate smaller than its estimated gap",
        )

    missing_recommendation_checks_packet = deepcopy(packet)
    candidate = first_recommended_candidate(missing_recommendation_checks_packet)
    if candidate is None:
        add_error(source, "negative_control_no_recommended_candidate", "golden packet has no recommended candidate for mutation")
    else:
        candidate.pop("pre_cleanup_read_only_checks", None)
        expect_validation_failure(
            missing_recommendation_checks_packet,
            f"{source}::recommended_candidate_missing_pre_cleanup_checks",
            "recommended_candidate_missing_pre_cleanup_checks",
            "remove read-only pre-cleanup checks from first recommended candidate",
        )

    missing_recommendation_reason_packet = deepcopy(packet)
    candidate = first_recommended_candidate(missing_recommendation_reason_packet)
    if candidate is None:
        add_error(source, "negative_control_no_recommended_candidate", "golden packet has no recommended candidate for mutation")
    else:
        candidate.pop("recommendation_reason", None)
        expect_validation_failure(
            missing_recommendation_reason_packet,
            f"{source}::missing_recommendation_reason",
            "missing_recommendation_reason",
            "remove recommendation_reason from first recommended candidate",
        )

    invalid_recommendation_ratio_packet = deepcopy(packet)
    candidate = first_recommended_candidate(invalid_recommendation_ratio_packet)
    if candidate is None:
        add_error(source, "negative_control_no_recommended_candidate", "golden packet has no recommended candidate for mutation")
    else:
        candidate["estimated_post_cleanup_free_ratio"] = 0.0
        expect_validation_failure(
            invalid_recommendation_ratio_packet,
            f"{source}::invalid_recommended_post_cleanup_ratio",
            "invalid_recommended_post_cleanup_ratio",
            "set incorrect estimated_post_cleanup_free_ratio on first recommended candidate",
        )

    missing_direct_probe_packet = deepcopy(packet)
    rch_e100_worker = None
    for worker in missing_direct_probe_packet.get("workers", []):
        if isinstance(worker, dict) and worker.get("probe_failure_signature") == "RCH-E100":
            rch_e100_worker = worker
            break
    if rch_e100_worker is None:
        add_error(source, "negative_control_no_rch_e100_worker", "golden packet has no RCH-E100 worker for mutation")
    else:
        rch_e100_worker.pop("direct_rch_probe_command", None)
        rch_e100_worker.pop("direct_rch_probe_exit_status", None)
        rch_e100_worker.pop("direct_rch_probe_raw_output_path", None)
        expect_validation_failure(
            missing_direct_probe_packet,
            f"{source}::missing_direct_rch_probe_command",
            "missing_direct_rch_probe_command",
            "remove direct rch probe evidence from first RCH-E100 worker",
        )

    prompting_check_packet = deepcopy(packet)
    candidate = first_recommended_candidate(prompting_check_packet)
    if candidate is None:
        add_error(source, "negative_control_no_recommended_candidate", "golden packet has no recommended candidate for mutation")
    else:
        checks = candidate.get("pre_cleanup_read_only_checks")
        if isinstance(checks, list) and checks:
            checks[0]["command"] = re.sub(r"\s-o BatchMode=yes", "", str(checks[0].get("command", "")))
            checks[0]["command"] = re.sub(r"\s-i\s+\S+", "", checks[0]["command"])
            expect_validation_failure(
                prompting_check_packet,
                f"{source}::pre_cleanup_check_may_prompt",
                "pre_cleanup_check_may_prompt",
                "remove BatchMode and identity file from first recommended pre-cleanup command",
            )
        else:
            add_error(source, "negative_control_no_pre_cleanup_check", "golden packet has no pre-cleanup check for mutation")

    coarse_ballast_packet = deepcopy(packet)
    workers = coarse_ballast_packet.get("workers")
    ballast_worker = None
    if isinstance(workers, list):
        ballast_worker = next(
            (
                worker
                for worker in workers
                if isinstance(worker, dict)
                and worker.get("pressure_state") == "critical"
                and isinstance(worker.get("ballast_snapshot"), str)
                and worker.get("ballast_snapshot")
            ),
            None,
        )
    if ballast_worker is None:
        add_error(source, "negative_control_no_ballast_worker", "golden packet has no parsed ballast worker for mutation")
    else:
        ballast_worker["sbh_snapshot"] = "present in raw worker output"
        ballast_worker["ballast_snapshot"] = "present in raw worker output"
        expect_validation_failure(
            coarse_ballast_packet,
            f"{source}::coarse_ballast_snapshot",
            "coarse_ballast_snapshot",
            "replace parsed SBH and ballast summaries with coarse raw-output markers",
        )

    generic_ballast_reason_packet = deepcopy(packet)
    approval = generic_ballast_reason_packet.get("approval_request")
    if isinstance(approval, dict):
        approval["why_read_only_collection_is_insufficient"] = (
            "Read-only collection can identify pressure and candidates, but cannot free space under repo rules."
        )
        expect_validation_failure(
            generic_ballast_reason_packet,
            f"{source}::approval_reason_omits_non_releasable_ballast",
            "approval_reason_omits_non_releasable_ballast",
            "replace non-releasable ballast approval reason with generic read-only wording",
        )
    else:
        add_error(source, "negative_control_no_approval_request", "golden packet has no approval_request for mutation")

    exact_worker_summary_packet = deepcopy(packet)
    approval = exact_worker_summary_packet.get("approval_request")
    if isinstance(approval, dict) and isinstance(approval.get("exact_worker_ids"), list) and approval["exact_worker_ids"]:
        approval["exact_worker_ids"] = approval["exact_worker_ids"][1:]
        expect_validation_failure(
            exact_worker_summary_packet,
            f"{source}::exact_worker_ids_mismatch",
            "exact_worker_ids_mismatch",
            "remove the first approval-request worker id summary row",
        )
    else:
        add_error(source, "negative_control_no_exact_worker_ids", "golden packet has no exact worker ids for mutation")

    exact_path_summary_packet = deepcopy(packet)
    approval = exact_path_summary_packet.get("approval_request")
    if isinstance(approval, dict) and isinstance(approval.get("exact_candidate_paths"), list) and approval["exact_candidate_paths"]:
        approval["exact_candidate_paths"] = approval["exact_candidate_paths"][1:]
        expect_validation_failure(
            exact_path_summary_packet,
            f"{source}::exact_candidate_paths_mismatch",
            "exact_candidate_paths_mismatch",
            "remove the first approval-request candidate path summary row",
        )
    else:
        add_error(source, "negative_control_no_exact_candidate_paths", "golden packet has no exact candidate paths for mutation")

    smallest_summary_packet = deepcopy(packet)
    approval = smallest_summary_packet.get("approval_request")
    if isinstance(approval, dict) and isinstance(approval.get("smallest_sufficient_candidate_paths"), list) and approval["smallest_sufficient_candidate_paths"]:
        approval["smallest_sufficient_candidate_paths"] = approval["smallest_sufficient_candidate_paths"][1:]
        expect_validation_failure(
            smallest_summary_packet,
            f"{source}::smallest_sufficient_candidate_paths_mismatch",
            "smallest_sufficient_candidate_paths_mismatch",
            "remove the first smallest-sufficient candidate path summary row",
        )
    else:
        add_error(
            source,
            "negative_control_no_smallest_candidate_paths",
            "golden packet has no smallest-sufficient candidate paths for mutation",
        )

    weak_approval_text_packet = deepcopy(packet)
    approval = weak_approval_text_packet.get("approval_request")
    if isinstance(approval, dict):
        approval["explicit_user_text_required_before_cleanup"] = "Operator approval is needed before cleanup."
        expect_validation_failure(
            weak_approval_text_packet,
            f"{source}::explicit_approval_text_too_weak",
            "explicit_approval_text_too_weak",
            "replace exact written approval text with generic approval wording",
        )
    else:
        add_error(source, "negative_control_no_approval_request", "golden packet has no approval_request for mutation")

    missing_command_log_packet = deepcopy(packet)
    approval = missing_command_log_packet.get("approval_request")
    if isinstance(approval, dict) and isinstance(approval.get("commands_not_executed"), list):
        approval["commands_not_executed"] = [
            item
            for item in approval["commands_not_executed"]
            if not (isinstance(item, str) and "ballast release" in item.lower())
        ]
        expect_validation_failure(
            missing_command_log_packet,
            f"{source}::missing_unexecuted_ballast_release_command",
            "missing_unexecuted_ballast_release_command",
            "remove the no-ballast-release command log entry",
        )
    else:
        add_error(source, "negative_control_no_commands_not_executed", "golden packet has no commands_not_executed list")

    stale_mirror_packet = deepcopy(packet)
    repo_state = stale_mirror_packet.get("repo_state")
    if isinstance(repo_state, dict) and isinstance(repo_state.get("origin_main_commit"), str):
        repo_state["origin_master_commit"] = "f" * 40
        expect_validation_failure(
            stale_mirror_packet,
            f"{source}::legacy_mirror_not_synced",
            "legacy_mirror_not_synced",
            "make packet repo_state.origin_master_commit differ from origin_main_commit",
        )
    else:
        add_error(source, "negative_control_no_repo_state", "golden packet has no repo_state for mutation")

    extra_worktree_packet = deepcopy(packet)
    repo_state = extra_worktree_packet.get("repo_state")
    if isinstance(repo_state, dict) and isinstance(repo_state.get("worktree_list"), list):
        repo_state["worktree_list"].append("/tmp/frankenlibc-feature-worktree  1111111 [feature/unsafe-worktree]")
        expect_validation_failure(
            extra_worktree_packet,
            f"{source}::worktree_count_mismatch",
            "worktree_count_mismatch",
            "append a feature-branch worktree to packet repo_state.worktree_list",
        )
    else:
        add_error(source, "negative_control_no_worktree_list", "golden packet has no worktree_list for mutation")

    unsafe_readiness_packet = deepcopy(packet)
    readiness = unsafe_readiness_packet.get("approval_readiness")
    if isinstance(readiness, list) and readiness and isinstance(readiness[0], dict):
        readiness[0]["safe_to_run_without_user_approval"] = True
        expect_validation_failure(
            unsafe_readiness_packet,
            f"{source}::approval_readiness_claims_safe_without_user_approval",
            "approval_readiness_claims_safe_without_user_approval",
            "make first approval readiness row claim it is safe without user approval",
        )
    else:
        add_error(source, "negative_control_no_approval_readiness", "golden packet has no approval_readiness for mutation")

    forged_summary_packet = deepcopy(packet)
    summary = forged_summary_packet.get("approval_ready_summary")
    if isinstance(summary, dict):
        summary["ready_for_explicit_user_approval_count"] = int(
            summary.get("ready_for_explicit_user_approval_count", 0)
        ) + 1
        expect_validation_failure(
            forged_summary_packet,
            f"{source}::approval_ready_summary_mismatch",
            "approval_ready_summary_mismatch",
            "make approval_ready_summary count disagree with approval_readiness rows",
        )
    else:
        add_error(source, "negative_control_no_approval_ready_summary", "golden packet has no approval_ready_summary for mutation")

    forged_rejection_packet = deepcopy(packet)
    diagnostics = forged_rejection_packet.get("no_candidate_diagnostics")
    rejection_summary = (
        diagnostics.get("candidate_rejection_summary") if isinstance(diagnostics, dict) else None
    )
    if isinstance(rejection_summary, dict):
        rejection_summary["rejected_finding_count"] = int(
            rejection_summary.get("rejected_finding_count", 0)
        ) + 1
        expect_validation_failure(
            forged_rejection_packet,
            f"{source}::candidate_rejection_summary_mismatch",
            "candidate_rejection_summary_mismatch",
            "make candidate_rejection_summary count disagree with bounded du findings",
        )
    else:
        add_error(source, "negative_control_no_candidate_rejection_summary", "golden packet has no candidate_rejection_summary for mutation")

    missing_no_candidate_diagnostics_packet = deepcopy(packet)
    missing_no_candidate_diagnostics_packet["cleanup_candidates"] = []
    missing_no_candidate_diagnostics_packet["recommended_cleanup_candidates"] = []
    missing_no_candidate_diagnostics_packet["approval_readiness"] = []
    approval = missing_no_candidate_diagnostics_packet.get("approval_request")
    if isinstance(approval, dict):
        approval["exact_worker_ids"] = []
        approval["exact_candidate_paths"] = []
        approval["smallest_sufficient_candidate_paths"] = []
        approval["margin_sufficient_candidate_paths"] = []
    missing_no_candidate_diagnostics_packet.pop("no_candidate_diagnostics", None)
    expect_validation_failure(
        missing_no_candidate_diagnostics_packet,
        f"{source}::missing_no_candidate_diagnostics",
        "missing_no_candidate_diagnostics",
        "remove no-candidate diagnostics from a packet with no cleanup candidates",
    )


def validate_no_candidate_positive_control(packet: dict[str, Any], source: str) -> None:
    synthetic = deepcopy(packet)
    synthetic["cleanup_candidates"] = []
    synthetic["recommended_cleanup_candidates"] = []
    synthetic["approval_readiness"] = []
    synthetic["approval_ready_summary"] = expected_approval_ready_summary([])
    approval = synthetic.get("approval_request")
    if isinstance(approval, dict):
        approval["exact_worker_ids"] = []
        approval["exact_candidate_paths"] = []
        approval["smallest_sufficient_candidate_paths"] = []
        approval["margin_sufficient_candidate_paths"] = []
    workers = synthetic.get("workers", [])
    critical_workers = [
        worker
        for worker in workers
        if isinstance(worker, dict) and worker.get("pressure_state") == "critical"
    ]
    synthetic["no_candidate_diagnostics"] = {
        "status": "no_candidates_identified",
        "candidate_count": 0,
        "critical_worker_count": len(critical_workers),
        "workers_with_bounded_du_findings": [
            str(worker.get("worker_id"))
            for worker in workers
            if isinstance(worker, dict) and worker.get("bounded_du_findings")
        ],
        "critical_workers_without_candidates": [
            str(worker.get("worker_id")) for worker in critical_workers
        ],
        "probe_failure_workers": [
            str(worker.get("worker_id"))
            for worker in workers
            if isinstance(worker, dict)
            and str(worker.get("probe_failure_signature") or "ok") != "ok"
        ],
        "collection_error_workers": [
            str(worker.get("worker_id"))
            for worker in workers
            if isinstance(worker, dict) and worker.get("collection_errors")
        ],
        "candidate_rejection_summary": expected_candidate_rejection_summary(workers),
        "diagnostic_summary": "Synthetic no-candidate packet preserves pressure evidence without approval-ready paths.",
        "next_action": "inspect_worker_probe_outputs_or_restore_worker_capacity",
    }
    before_errors = len(errors)
    before_events = len(events)
    validate_packet(synthetic, f"{source}::no_candidate_positive_control", require_rch_e100=True)
    observed_errors = errors[before_errors:]
    if observed_errors:
        del errors[before_errors:]
        del events[before_events:]
        observed = sorted({str(error.get("failure_signature")) for error in observed_errors})
        add_error(
            source,
            "no_candidate_positive_control_failed",
            f"synthetic no-candidate packet should validate; observed={observed}",
        )
    else:
        events.append(
            {
                "source": f"{source}::no_candidate_positive_control",
                "status": "positive_checked",
            }
        )


def require_list_contains(schema: dict[str, Any], source: str, field: str, required: set[str]) -> None:
    value = schema.get(field)
    if not isinstance(value, list):
        add_error(source, "schema_contract_missing_list", f"{field} must be a list")
        return
    present = {str(item) for item in value}
    missing = sorted(required - present)
    if missing:
        add_error(source, "schema_contract_missing_fields", f"{field} missing {missing}")


def validate_schema_contract(schema: dict[str, Any], source: str) -> None:
    if schema.get("schema_version") != "rch_pressure_approval_packet_schema.v1":
        add_error(source, "packet_schema_contract_version", "schema contract version mismatch")
    require_list_contains(
        schema,
        source,
        "required_top_level_fields",
        {
            "recommended_cleanup_candidates",
            "approval_readiness",
            "approval_ready_summary",
            "no_candidate_diagnostics",
            "validation_commands",
            "artifact_paths",
        },
    )
    require_list_contains(
        schema,
        source,
        "worker_fields",
        {
            "pressure_disk_total_gb",
            "estimated_free_ratio_target",
            "estimated_gb_needed_to_reach_target_ratio",
            "direct_rch_probe_command",
            "direct_rch_probe_exit_status",
            "direct_rch_probe_raw_output_path",
        },
    )
    require_list_contains(
        schema,
        source,
        "repo_state_fields",
        {
            "branch",
            "head_commit",
            "origin_main_commit",
            "origin_master_commit",
            "worktree_list",
            "dirty_summary",
            "untracked_summary",
        },
    )
    require_list_contains(
        schema,
        source,
        "cleanup_candidate_fields",
        {
            "host",
            "candidate_rank",
            "estimated_size_gb",
            "pre_cleanup_read_only_checks",
        },
    )
    require_list_contains(
        schema,
        source,
        "pre_cleanup_read_only_result_fields",
        {
            "executed",
            "executed_at_utc",
            "exit_status",
            "stdout",
            "stderr",
            "timed_out",
            "passed",
            "skip_reason",
        },
    )
    require_list_contains(
        schema,
        source,
        "recommended_cleanup_candidate_fields",
        {
            "candidate_rank",
            "estimated_post_cleanup_free_ratio",
            "estimated_surplus_gb_after_cleanup",
            "recommendation_reason",
        },
    )
    require_list_contains(
        schema,
        source,
        "approval_readiness_fields",
        {
            "worker_id",
            "path",
            "approval_state",
            "blocked_by",
            "safe_to_run_without_user_approval",
            "exact_user_approval_required",
            "cleanup_executed",
            "next_action",
        },
    )
    require_list_contains(
        schema,
        source,
        "approval_ready_summary_fields",
        {
            "status",
            "ready_for_explicit_user_approval_count",
            "ready_worker_ids",
            "ready_candidate_count_by_worker",
            "ready_candidate_paths",
            "safe_to_run_without_user_approval",
            "exact_user_approval_required",
            "cleanup_executed",
            "next_action",
        },
    )
    require_list_contains(
        schema,
        source,
        "no_candidate_diagnostics_fields",
        {
            "status",
            "candidate_count",
            "critical_worker_count",
            "workers_with_bounded_du_findings",
            "critical_workers_without_candidates",
            "probe_failure_workers",
            "collection_error_workers",
            "candidate_rejection_summary",
            "diagnostic_summary",
            "next_action",
        },
    )
    require_list_contains(
        schema,
        source,
        "candidate_rejection_summary_fields",
        {
            "bounded_du_finding_count",
            "rejected_finding_count",
            "rejection_count_by_reason",
            "largest_rejected_findings",
        },
    )
    require_list_contains(
        schema,
        source,
        "allowed_worker_statuses",
        {
            "healthy",
            "degraded",
            "disabled",
            "unreachable",
            "unknown",
        },
    )
    require_list_contains(
        schema,
        source,
        "allowed_probe_failure_signatures",
        ALLOWED_PROBE_FAILURE_SIGNATURES,
    )
    require_list_contains(
        schema,
        source,
        "required_failure_signatures",
        {
            "critical_pressure",
            "RCH-E100",
            "absent_or_non_releasable_ballast",
            "local_fallback_rejected",
        },
    )
    approval_contract = schema.get("approval_request_contract", {})
    if not isinstance(approval_contract, dict):
        add_error(source, "schema_contract_missing_approval_contract", "approval_request_contract must be an object")
    else:
        approval_required = approval_contract.get("must_include")
        required_approval_contract_fields = {
            "operator_summary",
            "exact_worker_ids",
            "exact_candidate_paths",
            "smallest_sufficient_candidate_paths",
            "minimum_margin_surplus_gb",
            "margin_sufficient_candidate_paths",
            "why_read_only_collection_is_insufficient",
            "explicit_user_text_required_before_cleanup",
            "commands_not_executed",
        }
        if not isinstance(approval_required, list):
            add_error(
                source,
                "schema_contract_invalid_approval_must_include",
                "approval_request_contract.must_include must be a list",
            )
        else:
            missing_required = sorted(required_approval_contract_fields - set(approval_required))
            if missing_required:
                add_error(
                    source,
                    "schema_contract_missing_approval_fields",
                    f"approval_request_contract.must_include missing {missing_required}",
                )
        approval_forbidden = approval_contract.get("must_not_include")
        forbidden_approval_contract_fields = {
            "claim_that_cleanup_already_happened",
            "cargo_validation_success_when_worker_selection_skipped",
            "implicit_permission_to_delete",
        }
        if not isinstance(approval_forbidden, list):
            add_error(
                source,
                "schema_contract_invalid_approval_must_not_include",
                "approval_request_contract.must_not_include must be a list",
            )
        else:
            missing_forbidden = sorted(forbidden_approval_contract_fields - set(approval_forbidden))
            if missing_forbidden:
                add_error(
                    source,
                    "schema_contract_missing_forbidden_approval_claims",
                    f"approval_request_contract.must_not_include missing {missing_forbidden}",
                )
    examples = schema.get("example_packets")
    if not isinstance(examples, list) or not examples:
        add_error(source, "schema_contract_missing_examples", "schema contract must include example packets")
        return
    for index, example in enumerate(examples):
        if not isinstance(example, dict):
            add_error(source, "schema_contract_bad_example", f"example {index} must be an object")
            continue
        validate_packet(example, f"{source}::example[{index}]", require_rch_e100=True)
        commands = example.get("validation_commands")
        if not isinstance(commands, list):
            add_error(source, "schema_contract_missing_validation_commands", f"example {index} missing validation_commands")
            continue
        command_text = "\n".join(str(command) for command in commands)
        if "scripts/check_rch_pressure_packet_goldens.sh" not in command_text:
            add_error(source, "schema_contract_missing_packet_checker", f"example {index} validation_commands omit packet checker")
        if "AGENT_NAME=SunnyHeron" in command_text:
            add_error(source, "schema_contract_hardcoded_agent", f"example {index} hardcodes another agent name")


schema_contract = load_json(SCHEMA)
validate_schema_contract(schema_contract, rel(SCHEMA))

golden = load_json(GOLDEN)
if golden.get("schema_version") != "rch_pressure_approval_packet_golden.v1":
    add_error(rel(GOLDEN), "golden_schema_version", "golden schema_version mismatch")
golden_report = golden.get("golden_report")
if not isinstance(golden_report, dict):
    add_error(rel(GOLDEN), "missing_golden_report", "golden_report must be an object")
else:
    validate_packet(golden_report, rel(GOLDEN), require_rch_e100=True)
    validate_no_candidate_positive_control(golden_report, rel(GOLDEN))
    validate_negative_controls(golden_report, rel(GOLDEN))

required_lines = golden.get("golden_markdown_required_lines", [])
if not isinstance(required_lines, list) or not all(isinstance(line, str) for line in required_lines):
    add_error(rel(GOLDEN), "malformed_markdown_lines", "golden_markdown_required_lines must be strings")
else:
    markdown_text = "\n".join(required_lines)
    if FORBIDDEN_TEXT.search(markdown_text):
        add_error(rel(GOLDEN), "forbidden_markdown_primitive", "required markdown lines include forbidden cleanup primitive")
    expect_markdown_validation_failure(
        markdown_text + "\nsbh clean /data/projects",
        f"{rel(GOLDEN)}::forbidden_live_markdown_primitive",
        required_lines,
        "forbidden_live_markdown_primitive",
        "append a destructive sbh cleanup primitive to markdown",
    )

if LIVE_REPORT.exists():
    validate_packet(load_json(LIVE_REPORT), rel(LIVE_REPORT), require_rch_e100=False)
if LIVE_MARKDOWN.exists() and isinstance(required_lines, list):
    live_markdown = LIVE_MARKDOWN.read_text(encoding="utf-8", errors="replace")
    validate_markdown_text(rel(LIVE_MARKDOWN), live_markdown, required_lines)

report = {
    "schema_version": "rch_pressure_packet_goldens.report.v1",
    "generated_at_utc": utc_now(),
    "schema": rel(SCHEMA),
    "golden": rel(GOLDEN),
    "live_report": rel(LIVE_REPORT) if LIVE_REPORT.exists() else None,
    "live_markdown": rel(LIVE_MARKDOWN) if LIVE_MARKDOWN.exists() else None,
    "checked_events": events,
    "errors": errors,
    "status": "pass" if not errors else "fail",
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)
if errors:
    print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
    sys.exit(1)
print(json.dumps({"status": "pass", "events": len(events)}, sort_keys=True))
PY
