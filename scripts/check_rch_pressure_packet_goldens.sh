#!/usr/bin/env bash
# Validate rch pressure approval packet golden fixtures and optional generated reports.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLDEN="${FRANKENLIBC_RCH_PACKET_GOLDEN:-${ROOT}/tests/conformance/rch_pressure_approval_packet_golden.v1.json}"
LIVE_REPORT="${FRANKENLIBC_RCH_PACKET_REPORT:-${ROOT}/target/rch-pressure-approval-packet/rch_pressure_approval_packet.report.json}"
LIVE_MARKDOWN="${FRANKENLIBC_RCH_PACKET_MARKDOWN:-${ROOT}/target/rch-pressure-approval-packet/rch_pressure_approval_packet.approval.md}"
OUT_DIR="${FRANKENLIBC_RCH_PACKET_GOLDEN_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${OUT_DIR}/rch_pressure_packet_goldens.report.json"
LOG="${OUT_DIR}/rch_pressure_packet_goldens.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${GOLDEN}" "${LIVE_REPORT}" "${LIVE_MARKDOWN}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import sys
import time
from copy import deepcopy
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
GOLDEN = pathlib.Path(sys.argv[2])
LIVE_REPORT = pathlib.Path(sys.argv[3])
LIVE_MARKDOWN = pathlib.Path(sys.argv[4])
REPORT = pathlib.Path(sys.argv[5])
LOG = pathlib.Path(sys.argv[6])
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


def validate_packet(packet: dict[str, Any], source: str, require_rch_e100: bool) -> None:
    if packet.get("schema_version") != "rch_pressure_approval_packet_schema.v1":
        add_error(source, "schema_version", "packet schema_version mismatch")
    gate = packet.get("rch_gate", {})
    if gate.get("required_remote_env") != "RCH_REQUIRE_REMOTE=1":
        add_error(source, "missing_remote_env", "packet must require RCH_REQUIRE_REMOTE=1")
    if "[RCH] local" not in gate.get("fallback_markers_rejected", []):
        add_error(source, "missing_local_fallback_rejection", "packet must reject [RCH] local")

    workers = packet.get("workers", [])
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

    candidates = packet.get("cleanup_candidates", [])
    if not candidates:
        add_error(source, "missing_cleanup_candidates", "packet must include approval-only cleanup candidates")
    candidate_paths = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            add_error(source, "malformed_candidate", "cleanup candidate must be an object")
            continue
        candidate_paths.add(candidate.get("path"))
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

    recommended = packet.get("recommended_cleanup_candidates", [])
    if not isinstance(recommended, list):
        add_error(source, "malformed_recommended_candidates", "recommended_cleanup_candidates must be a list")
        recommended = []
    for candidate in recommended:
        if not isinstance(candidate, dict):
            add_error(source, "malformed_recommended_candidate", "recommended cleanup candidate must be an object")
            continue
        path = candidate.get("path")
        if path not in candidate_paths:
            add_error(source, "recommended_candidate_not_listed", f"{path} is not present in cleanup_candidates")
        if candidate.get("requires_explicit_approval") is not True:
            add_error(source, "recommended_candidate_not_approval_gated", f"{path} lacks approval gate")
        if candidate.get("executed") is not False:
            add_error(source, "recommended_candidate_executed", f"{path} must remain executed=false")
        if candidate.get("recommendation_kind") != "smallest_listed_candidate_meeting_estimated_gap":
            add_error(source, "recommended_candidate_kind", f"{path} has unexpected recommendation_kind")
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

    approval = packet.get("approval_request", {})
    required_approval_fields = [
        "operator_summary",
        "exact_worker_ids",
        "exact_candidate_paths",
        "smallest_sufficient_candidate_paths",
        "why_read_only_collection_is_insufficient",
        "explicit_user_text_required_before_cleanup",
        "commands_not_executed",
    ]
    for field in required_approval_fields:
        if field not in approval:
            add_error(source, "missing_approval_field", f"approval_request missing {field}")
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
