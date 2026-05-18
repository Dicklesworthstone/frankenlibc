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
FORBIDDEN_TEXT = re.compile(r"\brm\b|git reset|git clean|sbh ballast release|sbh emergency|apt(?:-get)?\s+.*clean")


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
    missing = REQUIRED_PRE_CLEANUP_CHECK_KINDS - seen
    if missing:
        add_error(source, "missing_pre_cleanup_check_kind", f"{path} missing checks {sorted(missing)}")


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


def validate_packet(packet: dict[str, Any], source: str, require_rch_e100: bool) -> None:
    if packet.get("schema_version") != "rch_pressure_approval_packet_schema.v1":
        add_error(source, "schema_version", "packet schema_version mismatch")
    validate_repo_state(packet, source)
    gate = packet.get("rch_gate", {})
    if gate.get("required_remote_env") != "RCH_REQUIRE_REMOTE=1":
        add_error(source, "missing_remote_env", "packet must require RCH_REQUIRE_REMOTE=1")
    if "[RCH] local" not in gate.get("fallback_markers_rejected", []):
        add_error(source, "missing_local_fallback_rejection", "packet must reject [RCH] local")

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
    if not candidates:
        add_error(source, "missing_cleanup_candidates", "packet must include approval-only cleanup candidates")
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


def validate_negative_controls(packet: dict[str, Any], source: str) -> None:
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
        "allowed_worker_statuses",
        {
            "healthy",
            "degraded",
            "disabled",
            "unreachable",
            "unknown",
        },
    )
    approval_contract = schema.get("approval_request_contract", {})
    if not isinstance(approval_contract, dict):
        add_error(source, "schema_contract_missing_approval_contract", "approval_request_contract must be an object")
    else:
        approval_required = approval_contract.get("must_include")
        if not isinstance(approval_required, list) or "smallest_sufficient_candidate_paths" not in approval_required:
            add_error(
                source,
                "schema_contract_missing_smallest_paths",
                "approval_request_contract.must_include must name smallest_sufficient_candidate_paths",
            )
        if not isinstance(approval_required, list) or "margin_sufficient_candidate_paths" not in approval_required:
            add_error(
                source,
                "schema_contract_missing_margin_paths",
                "approval_request_contract.must_include must name margin_sufficient_candidate_paths",
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
    validate_negative_controls(golden_report, rel(GOLDEN))

required_lines = golden.get("golden_markdown_required_lines", [])
if not isinstance(required_lines, list) or not all(isinstance(line, str) for line in required_lines):
    add_error(rel(GOLDEN), "malformed_markdown_lines", "golden_markdown_required_lines must be strings")
else:
    markdown_text = "\n".join(required_lines)
    if FORBIDDEN_TEXT.search(markdown_text):
        add_error(rel(GOLDEN), "forbidden_markdown_primitive", "required markdown lines include forbidden cleanup primitive")

if LIVE_REPORT.exists():
    validate_packet(load_json(LIVE_REPORT), rel(LIVE_REPORT), require_rch_e100=False)
if LIVE_MARKDOWN.exists() and isinstance(required_lines, list):
    live_markdown = LIVE_MARKDOWN.read_text(encoding="utf-8", errors="replace")
    for line in required_lines:
        if line not in live_markdown:
            add_error(rel(LIVE_MARKDOWN), "missing_markdown_line", f"live markdown missing required text: {line}")

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
