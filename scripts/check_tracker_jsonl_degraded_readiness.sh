#!/usr/bin/env bash
# Emit a DB-free tracker readiness/staleness report from .beads/issues.jsonl.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_TRACKER_JSONL_DEGRADED_CONTRACT:-${ROOT}/tests/conformance/tracker_jsonl_degraded_readiness.v1.json}"
ISSUES="${FRANKENLIBC_TRACKER_JSONL_DEGRADED_ISSUES:-${ROOT}/.beads/issues.jsonl}"
OUT_DIR="${FRANKENLIBC_TRACKER_JSONL_DEGRADED_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_TRACKER_JSONL_DEGRADED_REPORT:-${OUT_DIR}/tracker_jsonl_degraded_readiness.report.json}"
LOG="${FRANKENLIBC_TRACKER_JSONL_DEGRADED_LOG:-${OUT_DIR}/tracker_jsonl_degraded_readiness.log.jsonl}"
MODE="${1:---validate-only}"

case "${MODE}" in
  --validate-only|--report)
    ;;
  *)
    echo "usage: $0 [--validate-only|--report]" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT}" "${ISSUES}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
ISSUES = pathlib.Path(sys.argv[3])
REPORT = pathlib.Path(sys.argv[4])
LOG = pathlib.Path(sys.argv[5])
MODE = sys.argv[6]

EXPECTED_SCHEMA = "tracker_jsonl_degraded_readiness.v1"
REPORT_SCHEMA = "tracker_jsonl_degraded_readiness.report.v1"
PASS_STATUSES = {"closed"}
ACTIVE_STATUSES = {"open", "in_progress"}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
            if isinstance(row, dict):
                rows.append(row)
    return rows


def current_commit() -> str:
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def latest_activity(issue: dict[str, Any]) -> tuple[datetime | None, str]:
    best = parse_time(issue.get("updated_at"))
    source = "updated_at" if best is not None else "missing"
    comments = issue.get("comments")
    if isinstance(comments, list):
        for comment in comments:
            if not isinstance(comment, dict):
                continue
            created = parse_time(comment.get("created_at"))
            if created is not None and (best is None or created > best):
                best = created
                source = "comment.created_at"
    return best, source


def issue_text(issue: dict[str, Any]) -> str:
    fields: list[str] = []
    for key in ("id", "title", "description", "acceptance_criteria", "notes"):
        value = issue.get(key)
        if isinstance(value, str):
            fields.append(value)
    labels = issue.get("labels")
    if isinstance(labels, list):
        fields.extend(str(item) for item in labels)
    return "\n".join(fields).lower()


def dependency_metadata(dep: dict[str, Any]) -> dict[str, Any]:
    metadata = dep.get("metadata")
    if not isinstance(metadata, str) or not metadata.strip():
        return {}
    try:
        parsed = json.loads(metadata)
    except json.JSONDecodeError:
        return {"raw": metadata}
    return parsed if isinstance(parsed, dict) else {"raw": metadata}


def is_permissioned(issue: dict[str, Any], markers: list[str]) -> tuple[bool, list[str]]:
    text = issue_text(issue)
    hits = [marker for marker in markers if marker.lower() in text]
    return bool(hits), hits


def is_cross_project(issue: dict[str, Any], markers: list[str]) -> tuple[bool, list[str]]:
    text = issue_text(issue)
    hits = [marker for marker in markers if marker.lower() in text]
    return bool(hits), hits


def artifact_references(issue: dict[str, Any], prefixes: list[str]) -> list[str]:
    text = "\n".join(
        value for key in ("title", "description", "acceptance_criteria", "notes")
        if isinstance((value := issue.get(key)), str)
    )
    candidates = re.findall(r"(?:^|[\s`'\"])((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.@:+-]+)", text)
    refs: list[str] = []
    for candidate in candidates:
        cleaned = candidate.rstrip(".,;:)")
        if any(cleaned.startswith(prefix) for prefix in prefixes) and cleaned not in refs:
            refs.append(cleaned)
    return sorted(refs)


def dependency_blockers(issue: dict[str, Any], issue_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    dependencies = issue.get("dependencies")
    if not isinstance(dependencies, list):
        return blockers
    for dep in dependencies:
        if not isinstance(dep, dict) or dep.get("type") != "blocks":
            continue
        blocker_id = dep.get("depends_on_id")
        if not isinstance(blocker_id, str) or not blocker_id:
            blockers.append({"id": None, "status": "missing", "reason": "malformed_dependency"})
            continue
        blocker = issue_by_id.get(blocker_id)
        blocker_status = blocker.get("status") if isinstance(blocker, dict) else "missing"
        if blocker_status not in PASS_STATUSES:
            metadata = dependency_metadata(dep)
            blocker_row = {
                "id": blocker_id,
                "status": blocker_status,
                "reason": "unclosed_blocks_dependency",
                "title": blocker.get("title") if isinstance(blocker, dict) else None,
                "priority": blocker.get("priority") if isinstance(blocker, dict) else None,
                "assignee": blocker.get("assignee") if isinstance(blocker, dict) else None,
                "updated_at": blocker.get("updated_at") if isinstance(blocker, dict) else None,
                "dependency_metadata": metadata,
            }
            why = metadata.get("why")
            if isinstance(why, str) and why:
                blocker_row["why"] = why
            blockers.append(blocker_row)
    return blockers


def project_issue(issue: dict[str, Any], *, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    row = {
        "id": issue.get("id"),
        "title": issue.get("title"),
        "status": issue.get("status"),
        "priority": issue.get("priority"),
        "assignee": issue.get("assignee"),
        "updated_at": issue.get("updated_at"),
        "labels": issue.get("labels") if isinstance(issue.get("labels"), list) else [],
    }
    if extra:
        row.update(extra)
    return row


def projected_ids(rows: list[dict[str, Any]]) -> list[str]:
    return [str(row["id"]) for row in rows if isinstance(row.get("id"), str)]


def in_progress_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for row in rows:
        issue_id = row.get("id")
        if not isinstance(issue_id, str):
            continue
        summary.append(
            {
                "id": issue_id,
                "assignee": row.get("assignee"),
                "age_hours": row.get("age_hours"),
                "latest_activity_at": row.get("latest_activity_at"),
                "latest_activity_source": row.get("latest_activity_source"),
            }
        )
    return sorted(
        summary,
        key=lambda item: (
            float(item.get("age_hours")) if isinstance(item.get("age_hours"), (int, float)) else -1.0,
            str(item.get("id", "")),
        ),
        reverse=True,
    )


def permissioned_approval_request(row: dict[str, Any]) -> dict[str, Any]:
    issue_id = str(row.get("id") or "")
    text = issue_text(row)
    required_env: dict[str, str] = {}
    capability_prerequisites: list[str] = []
    permission_source = "generic_permissioned_ready"
    explicit_user_approval_text = (
        "User must provide explicit written approval naming the bead id, exact command, "
        "affected paths or resources, and required ACK values before execution."
    )
    next_action = "request_explicit_permission_before_claiming_or_running"
    commands_or_workloads_not_started: list[str] = []

    if "xfstests" in text or issue_id in {"bd-rchk3", "bd-rchk3.3"}:
        permission_source = "xfstests_real_run_ack"
        required_env = {
            "XFSTESTS_REAL_RUN_ACK": "xfstests-may-mutate-test-and-scratch-devices",
            "TEST_DIR": "artifact-scoped test mount path",
            "SCRATCH_MNT": "artifact-scoped scratch mount path",
            "RESULT_BASE": "artifact-scoped result directory",
        }
        capability_prerequisites = [
            "explicit operator permission for xfstests test and scratch mutation",
            "prepared xfstests helper tree and supported V1 subset",
            "TEST_DIR and SCRATCH_MNT must identify the exact paths or devices affected",
            "RESULT_BASE must preserve raw logs, stdout, stderr, pass, fail, and not-run rows",
        ]
        explicit_user_approval_text = (
            "User must explicitly approve the exact xfstests command for this bead, name "
            "TEST_DIR, SCRATCH_MNT, RESULT_BASE, and set XFSTESTS_REAL_RUN_ACK="
            "xfstests-may-mutate-test-and-scratch-devices before execution."
        )
        next_action = "ask_operator_for_exact_xfstests_command_paths_and_ack"
        commands_or_workloads_not_started = ["xfstests_real_baseline"]
    elif (
        "swarm-workload-may-use-permissioned-large-host" in text
        or "ffs_swarm_workload_real_run_ack" in text
        or issue_id == "bd-rchk0.53.8"
    ):
        permission_source = "swarm_workload_permissioned_large_host"
        required_env = {
            "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD": "1",
            "FFS_SWARM_WORKLOAD_REAL_RUN_ACK": "swarm-workload-may-use-permissioned-large-host",
            "FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER": "configured permissioned runner",
            "RCH_REQUIRE_REMOTE": "1",
        }
        capability_prerequisites = [
            "remote runner with at least 64 logical CPUs",
            "remote runner with at least 256 GiB RAM",
            "visible NUMA topology in the host capability proof",
            "configured permissioned runner preserves manifest, logs, p99 ledger, and release-gate output",
            "local smoke or downgraded capability evidence must not upgrade public readiness",
        ]
        explicit_user_approval_text = (
            "User must explicitly approve the exact large-host swarm command for this bead, "
            "name the configured runner, confirm >=64 logical CPUs, >=256 GiB RAM, visible "
            "NUMA topology, and set FFS_SWARM_WORKLOAD_REAL_RUN_ACK="
            "swarm-workload-may-use-permissioned-large-host before execution."
        )
        next_action = "ask_operator_for_large_host_runner_command_capabilities_and_ack"
        commands_or_workloads_not_started = ["permissioned_large_host_swarm_workload"]
    else:
        capability_prerequisites = [
            "inspect the bead description, notes, labels, and blocker metadata for exact permission scope",
            "operator approval must name every affected path, device, remote host, or workload",
        ]

    return {
        "permission_source": permission_source,
        "exact_user_approval_required": True,
        "explicit_user_approval_text": explicit_user_approval_text,
        "safe_to_run_without_user_approval": False,
        "execution_not_started": True,
        "required_env": required_env,
        "capability_prerequisites": capability_prerequisites,
        "commands_or_workloads_not_started": commands_or_workloads_not_started,
        "next_action": next_action,
    }


def permissioned_ready_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for row in rows:
        issue_id = row.get("id")
        if not isinstance(issue_id, str):
            continue
        approval_request = row.get("approval_request")
        if not isinstance(approval_request, dict):
            approval_request = permissioned_approval_request(row)
        summary.append(
            {
                "id": issue_id,
                "title": row.get("title"),
                "priority": row.get("priority"),
                "permission_markers": row.get("permission_markers") if isinstance(row.get("permission_markers"), list) else [],
                "approval_request": approval_request,
            }
        )
    return sorted(summary, key=lambda item: (str(item.get("id", ""))))


def blocker_chokepoints(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, Any]] = {}
    for row in rows:
        blockers = row.get("blockers")
        if not isinstance(blockers, list):
            continue
        for blocker in blockers:
            if not isinstance(blocker, dict) or not isinstance(blocker.get("id"), str):
                continue
            blocker_id = str(blocker["id"])
            entry = counts.setdefault(
                blocker_id,
                {
                    "id": blocker_id,
                    "blocked_open_count": 0,
                    "status": blocker.get("status"),
                    "reason": blocker.get("reason"),
                    "title": blocker.get("title"),
                    "priority": blocker.get("priority"),
                    "assignee": blocker.get("assignee"),
                    "blocked_issue_ids": [],
                },
            )
            entry["blocked_open_count"] += 1
            blocked_id = row.get("id")
            if isinstance(blocked_id, str) and blocked_id not in entry["blocked_issue_ids"]:
                entry["blocked_issue_ids"].append(blocked_id)
            if entry.get("status") is None:
                entry["status"] = blocker.get("status")
            if entry.get("reason") is None:
                entry["reason"] = blocker.get("reason")
    return sorted(
        counts.values(),
        key=lambda item: (
            -int(item.get("blocked_open_count", 0)),
            str(item.get("id", "")),
        ),
    )


def blocked_open_explanations(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    explanations: list[dict[str, Any]] = []
    for row in rows:
        issue_id = row.get("id")
        if not isinstance(issue_id, str):
            continue
        blockers = row.get("blockers")
        if not isinstance(blockers, list):
            blockers = []
        explanations.append(
            {
                "id": issue_id,
                "title": row.get("title"),
                "priority": row.get("priority"),
                "blocker_ids": [
                    str(blocker.get("id"))
                    for blocker in blockers
                    if isinstance(blocker, dict) and isinstance(blocker.get("id"), str)
                ],
                "blockers": blockers,
            }
        )
    return sorted(explanations, key=lambda item: (str(item.get("id", ""))))


def recommended_next_action(
    safe_ready_ids: list[str],
    permissioned_ready_ids: list[str],
    stale_in_progress_ids: list[str],
    top_blocker_ids: list[str],
    cross_project_review_ids: list[str] | None = None,
) -> dict[str, Any]:
    if cross_project_review_ids is None:
        cross_project_review_ids = []
    if stale_in_progress_ids:
        return {
            "decision": "review_stale_in_progress",
            "reason": "stale in-progress beads are present and should be reviewed before starting new work",
            "candidate_ids": stale_in_progress_ids,
            "safe_to_claim_without_permission": False,
            "requires_user_permission": False,
        }
    if safe_ready_ids:
        return {
            "decision": "claim_safe_ready",
            "reason": "safe ready beads are available without special permission markers",
            "candidate_ids": safe_ready_ids,
            "safe_to_claim_without_permission": True,
            "requires_user_permission": False,
        }
    if permissioned_ready_ids:
        return {
            "decision": "request_explicit_permission",
            "reason": "only permissioned ready beads are available; do not claim them without the named acknowledgements or operator permission",
            "candidate_ids": permissioned_ready_ids,
            "safe_to_claim_without_permission": False,
            "requires_user_permission": True,
        }
    if cross_project_review_ids:
        return {
            "decision": "review_cross_project_rows",
            "reason": "ready-like rows contain cross-project or stale external workload markers and must not be claimed as FrankenLibC work",
            "candidate_ids": cross_project_review_ids,
            "safe_to_claim_without_permission": False,
            "requires_user_permission": False,
        }
    if top_blocker_ids:
        return {
            "decision": "work_blockers_or_wait",
            "reason": "no ready beads are available; inspect blocker chokepoints before creating new work",
            "candidate_ids": top_blocker_ids,
            "safe_to_claim_without_permission": False,
            "requires_user_permission": False,
        }
    return {
        "decision": "no_claimable_work",
        "reason": "no safe ready, permissioned ready, stale in-progress, or blocked-open work was found",
        "candidate_ids": [],
        "safe_to_claim_without_permission": False,
        "requires_user_permission": False,
    }


def is_container_parent(issue: dict[str, Any]) -> bool:
    return issue.get("issue_type") == "epic"


def analyze(rows: list[dict[str, Any]], contract: dict[str, Any]) -> dict[str, Any]:
    issue_by_id = {str(row.get("id")): row for row in rows if isinstance(row.get("id"), str)}
    permission_markers = [
        str(marker) for marker in contract.get("permission_required_markers", []) if str(marker).strip()
    ]
    cross_project_markers = [
        str(marker) for marker in contract.get("cross_project_markers", []) if str(marker).strip()
    ]
    artifact_prefixes = [
        str(prefix) for prefix in contract.get("artifact_reference_prefixes", []) if str(prefix).strip()
    ]
    stale_hours = float(contract.get("stale_in_progress_after_hours", 72))
    now = datetime.now(timezone.utc)

    ready: list[dict[str, Any]] = []
    safe_ready: list[dict[str, Any]] = []
    permissioned_ready: list[dict[str, Any]] = []
    cross_project_review: list[dict[str, Any]] = []
    blocked_open: list[dict[str, Any]] = []
    container_open: list[dict[str, Any]] = []
    stale_in_progress: list[dict[str, Any]] = []
    in_progress: list[dict[str, Any]] = []
    active_parent_children: dict[str, list[str]] = {}

    for row in rows:
        child_id = row.get("id")
        child_status = row.get("status")
        dependencies = row.get("dependencies")
        if not isinstance(child_id, str) or child_status not in ACTIVE_STATUSES or not isinstance(dependencies, list):
            continue
        for dep in dependencies:
            if not isinstance(dep, dict) or dep.get("type") != "parent-child":
                continue
            parent_id = dep.get("depends_on_id")
            if isinstance(parent_id, str) and parent_id:
                active_parent_children.setdefault(parent_id, []).append(child_id)

    for issue in rows:
        issue_id = issue.get("id")
        status = issue.get("status")
        if not isinstance(issue_id, str) or status not in ACTIVE_STATUSES:
            continue
        blockers = dependency_blockers(issue, issue_by_id)
        permissioned, markers = is_permissioned(issue, permission_markers)
        cross_project, cross_markers = is_cross_project(issue, cross_project_markers)
        if status == "open":
            if blockers:
                blocked_open.append(project_issue(issue, extra={"blockers": blockers}))
            elif issue_id in active_parent_children and is_container_parent(issue):
                container_open.append(
                    project_issue(
                        issue,
                        extra={
                            "active_child_ids": sorted(active_parent_children[issue_id]),
                            "reason": "active_parent_container",
                        },
                    )
                )
            else:
                refs = artifact_references(issue, artifact_prefixes)
                if cross_project:
                    extra = {
                        "review_reason": "cross_project_or_external_workload_marker",
                        "cross_project_markers": cross_markers,
                        "artifact_references": refs,
                        "artifact_reference_status": "present" if refs else "missing",
                        "permission_required": permissioned,
                        "permission_markers": markers,
                    }
                    if permissioned:
                        extra["approval_request"] = permissioned_approval_request(issue)
                    cross_project_review.append(project_issue(issue, extra=extra))
                    continue
                extra = {
                    "permission_required": permissioned,
                    "permission_markers": markers,
                }
                if permissioned:
                    extra["approval_request"] = permissioned_approval_request(issue)
                ready_row = project_issue(
                    issue,
                    extra=extra,
                )
                ready.append(ready_row)
                if permissioned:
                    permissioned_ready.append(ready_row)
                else:
                    safe_ready.append(ready_row)
        elif status == "in_progress":
            updated, activity_source = latest_activity(issue)
            age_hours = None
            if updated is not None:
                age_hours = round((now - updated).total_seconds() / 3600, 3)
            row = project_issue(
                issue,
                extra={
                    "age_hours": age_hours,
                    "latest_activity_at": format_time(updated),
                    "latest_activity_source": activity_source,
                    "blockers": blockers,
                },
            )
            in_progress.append(row)
            if age_hours is None or age_hours >= stale_hours:
                stale_in_progress.append(row)

    counts: dict[str, int] = {}
    for issue in rows:
        status = str(issue.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1

    return {
        "summary": {
            "total_issues": len(rows),
            "status_counts": counts,
            "ready_total": len(ready),
            "safe_ready_total": len(safe_ready),
            "permissioned_ready_total": len(permissioned_ready),
            "cross_project_review_total": len(cross_project_review),
            "blocked_open_total": len(blocked_open),
            "container_open_total": len(container_open),
            "in_progress_total": len(in_progress),
            "stale_in_progress_total": len(stale_in_progress),
            "stale_in_progress_after_hours": stale_hours,
        },
        "ready": ready,
        "safe_ready": safe_ready,
        "permissioned_ready": permissioned_ready,
        "cross_project_review": cross_project_review,
        "blocked_open": blocked_open,
        "container_open": container_open,
        "in_progress": in_progress,
        "stale_in_progress": stale_in_progress,
    }


def validate_contract(contract: dict[str, Any]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    if contract.get("schema_version") != EXPECTED_SCHEMA:
        errors.append({"failure_signature": "schema_version", "message": "schema_version mismatch"})
    if contract.get("issues_source") != ".beads/issues.jsonl":
        errors.append({"failure_signature": "issues_source", "message": "issues_source must be .beads/issues.jsonl"})
    forbidden = set(contract.get("forbidden_sources", []))
    for required in [".beads/beads.db", ".beads/issues.db", "br", "bv"]:
        if required not in forbidden:
            errors.append({"failure_signature": "forbidden_source_missing", "message": f"missing {required}"})
    if not isinstance(contract.get("required_report_fields"), list) or not contract["required_report_fields"]:
        errors.append({"failure_signature": "required_report_fields", "message": "required_report_fields missing"})
    stdout_fields = contract.get("stdout_summary_fields")
    if not isinstance(stdout_fields, list) or not stdout_fields:
        errors.append({"failure_signature": "stdout_summary_fields", "message": "stdout_summary_fields missing"})
    if float(contract.get("stale_in_progress_after_hours", 0)) <= 0:
        errors.append({"failure_signature": "stale_threshold", "message": "stale threshold must be positive"})
    if contract.get("stale_activity_sources") != ["updated_at", "comments[].created_at"]:
        errors.append(
            {
                "failure_signature": "stale_activity_sources",
                "message": "stale activity sources must include updated_at and comments[].created_at",
            }
        )
    markers = contract.get("permission_required_markers")
    if not isinstance(markers, list) or len(markers) < 5:
        errors.append({"failure_signature": "permission_markers", "message": "permission marker list too small"})
    cross_markers = contract.get("cross_project_markers")
    if not isinstance(cross_markers, list) or len(cross_markers) < 5:
        errors.append(
            {"failure_signature": "cross_project_markers", "message": "cross-project marker list too small"}
        )
    artifact_prefixes = contract.get("artifact_reference_prefixes")
    if not isinstance(artifact_prefixes, list) or len(artifact_prefixes) < 3:
        errors.append(
            {"failure_signature": "artifact_reference_prefixes", "message": "artifact reference prefixes too small"}
        )
    required_controls = contract.get("required_negative_controls")
    if not isinstance(required_controls, list) or not required_controls:
        errors.append(
            {
                "failure_signature": "required_negative_controls",
                "message": "required_negative_controls must be a non-empty list",
            }
        )
    return errors


def run_negative_controls(rows: list[dict[str, Any]], contract: dict[str, Any]) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []

    def decision_for(test_rows: list[dict[str, Any]]) -> dict[str, Any]:
        test_analysis = analyze(test_rows, contract)
        test_blockers = blocker_chokepoints(test_analysis["blocked_open"])
        return recommended_next_action(
            projected_ids(test_analysis["safe_ready"]),
            projected_ids(test_analysis["permissioned_ready"]),
            projected_ids(test_analysis["stale_in_progress"]),
            [str(row["id"]) for row in test_blockers[:5]],
            projected_ids(test_analysis["cross_project_review"]),
        )

    missing_forbidden = deepcopy(contract)
    missing_forbidden["forbidden_sources"] = [".beads/beads.db", ".beads/issues.db", "br"]
    signatures = {err["failure_signature"] for err in validate_contract(missing_forbidden)}
    controls.append(
        {
            "name": "missing_forbidden_source_fails_contract",
            "expected_signature": "forbidden_source_missing",
            "status": "pass" if "forbidden_source_missing" in signatures else "fail",
        }
    )

    base = deepcopy(rows)
    base.append(
        {
            "id": "bd-jsonl-negative-open-blocker",
            "title": "negative open blocker",
            "status": "open",
            "updated_at": "2026-05-17T00:00:00Z",
        }
    )
    base.append(
        {
            "id": "bd-jsonl-negative-blocked",
            "title": "negative blocked issue",
            "status": "open",
            "updated_at": "2026-05-17T00:00:00Z",
            "dependencies": [
                {
                    "issue_id": "bd-jsonl-negative-blocked",
                    "depends_on_id": "bd-jsonl-negative-open-blocker",
                    "type": "blocks",
                }
            ],
        }
    )
    analysis = analyze(base, contract)
    blocked_ids = {row["id"] for row in analysis["blocked_open"]}
    ready_ids = {row["id"] for row in analysis["ready"]}
    ok = "bd-jsonl-negative-blocked" in blocked_ids and "bd-jsonl-negative-blocked" not in ready_ids
    controls.append(
        {
            "name": "blocks_dependency_excludes_ready",
            "expected_signature": "blocked_by_unclosed_dependency",
            "status": "pass" if ok else "fail",
        }
    )

    stale = deepcopy(rows)
    stale.append(
        {
            "id": "bd-jsonl-negative-stale",
            "title": "negative stale in progress",
            "status": "in_progress",
            "updated_at": "2000-01-01T00:00:00Z",
        }
    )
    stale_ids = {row["id"] for row in analyze(stale, contract)["stale_in_progress"]}
    controls.append(
        {
            "name": "old_in_progress_is_stale",
            "expected_signature": "stale_in_progress_detected",
            "status": "pass" if "bd-jsonl-negative-stale" in stale_ids else "fail",
        }
    )

    recent_comment = deepcopy(rows)
    recent_comment.append(
        {
            "id": "bd-jsonl-negative-recent-comment",
            "title": "negative old updated_at but recent comment",
            "status": "in_progress",
            "updated_at": "2000-01-01T00:00:00Z",
            "comments": [
                {
                    "id": 1,
                    "author": "negative",
                    "text": "recent work evidence should prevent stale classification",
                    "created_at": utc_now(),
                }
            ],
        }
    )
    recent_analysis = analyze(recent_comment, contract)
    recent_stale_ids = {row["id"] for row in recent_analysis["stale_in_progress"]}
    recent_rows = {
        row["id"]: row
        for row in recent_analysis["in_progress"]
        if isinstance(row.get("id"), str)
    }
    recent_row = recent_rows.get("bd-jsonl-negative-recent-comment", {})
    ok = (
        "bd-jsonl-negative-recent-comment" not in recent_stale_ids
        and recent_row.get("latest_activity_source") == "comment.created_at"
    )
    controls.append(
        {
            "name": "recent_comment_prevents_stale",
            "expected_signature": "comment_activity_not_stale",
            "status": "pass" if ok else "fail",
        }
    )

    permissioned = deepcopy(rows)
    permissioned.append(
        {
            "id": "bd-jsonl-negative-permissioned",
            "title": "negative permissioned ready",
            "description": "requires explicit approval and XFSTESTS_REAL_RUN_ACK before execution",
            "status": "open",
            "updated_at": "2026-05-17T00:00:00Z",
        }
    )
    permissioned.append(
        {
            "id": "bd-jsonl-negative-safe-ready",
            "title": "negative safe ready",
            "description": "ordinary unblocked work without special permission markers",
            "status": "open",
            "updated_at": "2026-05-17T00:00:00Z",
        }
    )
    perm_analysis = analyze(permissioned, contract)
    perm_ids = {row["id"] for row in perm_analysis["permissioned_ready"]}
    safe_ids = {row["id"] for row in perm_analysis["safe_ready"]}
    ok = "bd-jsonl-negative-permissioned" in perm_ids and "bd-jsonl-negative-permissioned" not in safe_ids
    controls.append(
        {
            "name": "permissioned_ready_is_separated",
            "expected_signature": "permissioned_ready_not_safe_ready",
            "status": "pass" if ok else "fail",
        }
    )
    perm_summary_by_id = {
        str(row.get("id")): row
        for row in permissioned_ready_summary(perm_analysis["permissioned_ready"])
        if isinstance(row.get("id"), str)
    }
    approval = perm_summary_by_id.get("bd-jsonl-negative-permissioned", {}).get("approval_request", {})
    ok = (
        isinstance(approval, dict)
        and approval.get("exact_user_approval_required") is True
        and approval.get("safe_to_run_without_user_approval") is False
        and approval.get("execution_not_started") is True
        and isinstance(approval.get("explicit_user_approval_text"), str)
        and "approve" in approval["explicit_user_approval_text"]
        and isinstance(approval.get("required_env"), dict)
        and isinstance(approval.get("capability_prerequisites"), list)
        and isinstance(approval.get("next_action"), str)
        and approval["next_action"]
    )
    controls.append(
        {
            "name": "permissioned_summary_includes_approval_request",
            "expected_signature": "permissioned_summary_approval_packet",
            "status": "pass" if ok else "fail",
        }
    )
    permissioned_row = next(
        (
            row
            for row in perm_analysis["permissioned_ready"]
            if row.get("id") == "bd-jsonl-negative-permissioned"
        ),
        {},
    )
    safe_row = next(
        (
            row
            for row in perm_analysis["safe_ready"]
            if row.get("id") == "bd-jsonl-negative-safe-ready"
        ),
        {},
    )
    row_approval = permissioned_row.get("approval_request")
    ok = (
        isinstance(row_approval, dict)
        and row_approval.get("exact_user_approval_required") is True
        and row_approval.get("safe_to_run_without_user_approval") is False
        and row_approval.get("execution_not_started") is True
        and "approval_request" not in safe_row
    )
    controls.append(
        {
            "name": "permissioned_rows_include_approval_request",
            "expected_signature": "canonical_permissioned_row_approval_packet",
            "status": "pass" if ok else "fail",
        }
    )

    cross_project = deepcopy(rows)
    cross_project.append(
        {
            "id": "bd-jsonl-negative-cross-project",
            "title": "FrankenFS xfstests stale ready row",
            "description": "Run xfstests baseline for frankenfs on a permissioned large host with no FrankenLibC artifact path.",
            "status": "open",
            "updated_at": "2026-05-17T00:00:00Z",
        }
    )
    cross_project.append(
        {
            "id": "bd-jsonl-negative-frankenlibc-ready",
            "title": "FrankenLibC tracker hygiene ready row",
            "description": "Implement scripts/check_tracker_jsonl_degraded_readiness.sh and tests/conformance/tracker_jsonl_degraded_readiness.v1.json.",
            "status": "open",
            "updated_at": "2026-05-17T00:00:00Z",
        }
    )
    cross_analysis = analyze(cross_project, contract)
    cross_ids = {row["id"] for row in cross_analysis["cross_project_review"]}
    cross_ready_ids = {row["id"] for row in cross_analysis["ready"]}
    safe_ids = {row["id"] for row in cross_analysis["safe_ready"]}
    controls.append(
        {
            "name": "cross_project_ready_is_quarantined",
            "expected_signature": "cross_project_marker_not_safe_ready",
            "status": "pass"
            if "bd-jsonl-negative-cross-project" in cross_ids
            and "bd-jsonl-negative-cross-project" not in cross_ready_ids
            else "fail",
        }
    )
    cross_row = next(
        (
            row
            for row in cross_analysis["cross_project_review"]
            if row.get("id") == "bd-jsonl-negative-cross-project"
        ),
        {},
    )
    controls.append(
        {
            "name": "cross_project_review_reports_missing_artifact_reference",
            "expected_signature": "missing_frankenlibc_artifact_reference_reported",
            "status": "pass"
            if cross_row.get("artifact_reference_status") == "missing"
            and "frankenfs" in set(cross_row.get("cross_project_markers", []))
            else "fail",
        }
    )
    controls.append(
        {
            "name": "frankenlibc_ready_stays_safe",
            "expected_signature": "frankenlibc_row_remains_claimable",
            "status": "pass"
            if "bd-jsonl-negative-frankenlibc-ready" in safe_ids
            and "bd-jsonl-negative-frankenlibc-ready" not in cross_ids
            else "fail",
        }
    )

    closed_dep = deepcopy(rows)
    closed_dep.append(
        {
            "id": "bd-jsonl-negative-closed-parent",
            "title": "negative closed parent",
            "status": "closed",
            "updated_at": "2026-05-17T00:00:00Z",
        }
    )
    closed_dep.append(
        {
            "id": "bd-jsonl-negative-ready",
            "title": "negative ready issue",
            "status": "open",
            "updated_at": "2026-05-17T00:00:00Z",
            "dependencies": [
                {
                    "issue_id": "bd-jsonl-negative-ready",
                    "depends_on_id": "bd-jsonl-negative-closed-parent",
                    "type": "blocks",
                }
            ],
        }
    )
    ready_ids = {row["id"] for row in analyze(closed_dep, contract)["ready"]}
    controls.append(
        {
            "name": "closed_dependency_allows_ready",
            "expected_signature": "closed_dependency_not_blocking",
            "status": "pass" if "bd-jsonl-negative-ready" in ready_ids else "fail",
        }
    )

    metadata = deepcopy(rows)
    metadata.append(
        {
            "id": "bd-jsonl-negative-metadata-blocker",
            "title": "negative metadata blocker",
            "status": "in_progress",
            "priority": 0,
            "assignee": "negative-agent",
            "updated_at": "2026-05-17T00:00:00Z",
        }
    )
    metadata.append(
        {
            "id": "bd-jsonl-negative-metadata-blocked",
            "title": "negative metadata blocked",
            "status": "open",
            "priority": 1,
            "updated_at": "2026-05-17T00:00:00Z",
            "dependencies": [
                {
                    "issue_id": "bd-jsonl-negative-metadata-blocked",
                    "depends_on_id": "bd-jsonl-negative-metadata-blocker",
                    "type": "blocks",
                    "metadata": "{\"why\":\"negative blocker explanation\"}",
                }
            ],
        }
    )
    metadata_analysis = analyze(metadata, contract)
    metadata_explanations = {
        row["id"]: row
        for row in blocked_open_explanations(metadata_analysis["blocked_open"])
        if isinstance(row.get("id"), str)
    }
    explanation = metadata_explanations.get("bd-jsonl-negative-metadata-blocked", {})
    blocker = {}
    blockers = explanation.get("blockers")
    if isinstance(blockers, list) and blockers:
        blocker = blockers[0] if isinstance(blockers[0], dict) else {}
    ok = (
        blocker.get("id") == "bd-jsonl-negative-metadata-blocker"
        and blocker.get("title") == "negative metadata blocker"
        and blocker.get("assignee") == "negative-agent"
        and blocker.get("why") == "negative blocker explanation"
    )
    controls.append(
        {
            "name": "blocker_explanation_preserves_metadata",
            "expected_signature": "blocker_metadata_preserved",
            "status": "pass" if ok else "fail",
        }
    )

    parent = deepcopy(rows)
    parent.append(
        {
            "id": "bd-jsonl-negative-parent",
            "title": "negative active parent",
            "issue_type": "epic",
            "status": "open",
            "updated_at": "2026-05-17T00:00:00Z",
        }
    )
    parent.append(
        {
            "id": "bd-jsonl-negative-child",
            "title": "negative active child",
            "status": "open",
            "updated_at": "2026-05-17T00:00:00Z",
            "dependencies": [
                {
                    "issue_id": "bd-jsonl-negative-child",
                    "depends_on_id": "bd-jsonl-negative-parent",
                    "type": "parent-child",
                }
            ],
        }
    )
    parent_analysis = analyze(parent, contract)
    parent_ready_ids = {row["id"] for row in parent_analysis["ready"]}
    parent_container_ids = {row["id"] for row in parent_analysis["container_open"]}
    ok = "bd-jsonl-negative-parent" in parent_container_ids and "bd-jsonl-negative-parent" not in parent_ready_ids
    controls.append(
        {
            "name": "parent_with_active_child_excluded_ready",
            "expected_signature": "active_parent_container_not_ready",
            "status": "pass" if ok else "fail",
        }
    )

    action = decision_for(
        [
            {
                "id": "bd-jsonl-action-stale",
                "title": "action stale",
                "status": "in_progress",
                "updated_at": "2000-01-01T00:00:00Z",
            },
            {
                "id": "bd-jsonl-action-safe",
                "title": "action safe ready",
                "status": "open",
                "updated_at": "2026-05-17T00:00:00Z",
            },
        ]
    )
    controls.append(
        {
            "name": "action_prioritizes_stale_in_progress",
            "expected_signature": "review_stale_in_progress",
            "status": "pass"
            if action.get("decision") == "review_stale_in_progress"
            and action.get("candidate_ids") == ["bd-jsonl-action-stale"]
            else "fail",
        }
    )

    action = decision_for(
        [
            {
                "id": "bd-jsonl-action-safe",
                "title": "action safe ready",
                "status": "open",
                "updated_at": "2026-05-17T00:00:00Z",
            },
            {
                "id": "bd-jsonl-action-permissioned",
                "title": "action permissioned ready",
                "description": "requires explicit approval before execution",
                "status": "open",
                "updated_at": "2026-05-17T00:00:00Z",
            },
        ]
    )
    controls.append(
        {
            "name": "action_claims_safe_ready_before_permissioned",
            "expected_signature": "claim_safe_ready",
            "status": "pass"
            if action.get("decision") == "claim_safe_ready"
            and action.get("safe_to_claim_without_permission") is True
            and action.get("candidate_ids") == ["bd-jsonl-action-safe"]
            else "fail",
        }
    )

    action = decision_for(
        [
            {
                "id": "bd-jsonl-action-permissioned",
                "title": "action permissioned ready",
                "description": "requires explicit approval before execution",
                "status": "open",
                "updated_at": "2026-05-17T00:00:00Z",
            }
        ]
    )
    controls.append(
        {
            "name": "action_requests_permission_for_permissioned_only",
            "expected_signature": "request_explicit_permission",
            "status": "pass"
            if action.get("decision") == "request_explicit_permission"
            and action.get("requires_user_permission") is True
            and action.get("candidate_ids") == ["bd-jsonl-action-permissioned"]
            else "fail",
        }
    )

    action = decision_for(
        [
            {
                "id": "bd-jsonl-action-blocker",
                "title": "action in-progress blocker",
                "status": "in_progress",
                "updated_at": utc_now(),
            },
            {
                "id": "bd-jsonl-action-blocked",
                "title": "action blocked",
                "status": "open",
                "updated_at": "2026-05-17T00:00:00Z",
                "dependencies": [
                    {
                        "issue_id": "bd-jsonl-action-blocked",
                        "depends_on_id": "bd-jsonl-action-blocker",
                        "type": "blocks",
                    }
                ],
            },
        ]
    )
    controls.append(
        {
            "name": "action_points_to_blockers_when_no_ready",
            "expected_signature": "work_blockers_or_wait",
            "status": "pass"
            if action.get("decision") == "work_blockers_or_wait"
            and action.get("candidate_ids") == ["bd-jsonl-action-blocker"]
            else "fail",
        }
    )

    action = decision_for([])
    controls.append(
        {
            "name": "action_reports_no_claimable_work_for_empty_queue",
            "expected_signature": "no_claimable_work",
            "status": "pass" if action.get("decision") == "no_claimable_work" else "fail",
        }
    )
    return controls


contract = load_json(CONTRACT)
rows = load_jsonl(ISSUES)
errors = validate_contract(contract)
analysis = analyze(rows, contract)
blocked_chokepoints = blocker_chokepoints(analysis["blocked_open"])
safe_ready_ids = projected_ids(analysis["safe_ready"])
permissioned_ready_ids = projected_ids(analysis["permissioned_ready"])
cross_project_review_ids = projected_ids(analysis["cross_project_review"])
stale_in_progress_ids = projected_ids(analysis["stale_in_progress"])
top_blocker_ids = [str(row["id"]) for row in blocked_chokepoints[:5]]
stdout_summary = {
    "safe_ready": analysis["summary"]["safe_ready_total"],
    "safe_ready_ids": safe_ready_ids,
    "permissioned_ready": analysis["summary"]["permissioned_ready_total"],
    "permissioned_ready_ids": permissioned_ready_ids,
    "permissioned_ready_summary": permissioned_ready_summary(analysis["permissioned_ready"]),
    "cross_project_review": analysis["summary"]["cross_project_review_total"],
    "cross_project_review_ids": cross_project_review_ids,
    "stale_in_progress": analysis["summary"]["stale_in_progress_total"],
    "stale_in_progress_ids": stale_in_progress_ids,
    "blocked_open": analysis["summary"]["blocked_open_total"],
    "blocked_open_ids": projected_ids(analysis["blocked_open"]),
    "blocker_explanations": blocked_open_explanations(analysis["blocked_open"]),
    "blocked_by_counts": blocked_chokepoints,
    "top_blocker_ids": top_blocker_ids,
    "in_progress": analysis["summary"]["in_progress_total"],
    "in_progress_ids": projected_ids(analysis["in_progress"]),
    "in_progress_age_summary": in_progress_summary(analysis["in_progress"]),
    "stale_threshold_hours": analysis["summary"]["stale_in_progress_after_hours"],
}
stdout_summary["recommended_next_action"] = recommended_next_action(
    safe_ready_ids,
    permissioned_ready_ids,
    stale_in_progress_ids,
    top_blocker_ids,
    cross_project_review_ids,
)
negative_controls = run_negative_controls(rows, contract)
required_controls = {str(name) for name in contract.get("required_negative_controls", [])}
observed_controls = {str(control.get("name")) for control in negative_controls}
missing_controls = sorted(required_controls - observed_controls)
if missing_controls:
    errors.append(
        {
            "failure_signature": "missing_negative_control",
            "message": f"missing required negative controls: {missing_controls}",
        }
    )
for control in negative_controls:
    if control["status"] != "pass":
        errors.append(
            {
                "failure_signature": "negative_control_failed",
                "message": f"{control['name']} did not emit {control['expected_signature']}",
            }
        )

report = {
    "schema_version": REPORT_SCHEMA,
    "status": "fail" if errors else "pass",
    "mode": MODE,
    "generated_at_utc": utc_now(),
    "source_commit": current_commit(),
    "report_path": rel(REPORT),
    "log_path": rel(LOG),
    "data_sources": [rel(ISSUES)],
    "forbidden_sources": contract.get("forbidden_sources", []),
    "db_accessed": False,
    "stdout_summary": stdout_summary,
    "summary": analysis["summary"],
    "safe_ready": analysis["safe_ready"],
    "permissioned_ready": analysis["permissioned_ready"],
    "cross_project_review": analysis["cross_project_review"],
    "blocked_open": analysis["blocked_open"],
    "blocker_explanations": stdout_summary["blocker_explanations"],
    "container_open": analysis["container_open"],
    "stale_in_progress": analysis["stale_in_progress"],
    "in_progress": analysis["in_progress"],
    "negative_controls": negative_controls,
    "failures": errors,
}

required_fields = contract.get("required_report_fields", [])
for field in required_fields:
    if field not in report:
        errors.append({"failure_signature": "missing_report_field", "message": f"missing report field {field}"})
stdout_fields = contract.get("stdout_summary_fields", [])
if isinstance(stdout_fields, list):
    for field in stdout_fields:
        if field not in stdout_summary:
            errors.append({"failure_signature": "missing_stdout_summary_field", "message": f"missing stdout summary field {field}"})
report["status"] = "fail" if errors else "pass"
report["failures"] = errors

events = [
    {
        "event": "tracker_jsonl_degraded_readiness",
        "status": report["status"],
        "source": rel(ISSUES),
        "safe_ready_total": report["summary"]["safe_ready_total"],
        "permissioned_ready_total": report["summary"]["permissioned_ready_total"],
        "cross_project_review_total": report["summary"]["cross_project_review_total"],
        "stale_in_progress_total": report["summary"]["stale_in_progress_total"],
        "source_commit": report["source_commit"],
    }
]
for control in negative_controls:
    events.append({"event": "negative_control", **control})

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n", encoding="utf-8")

if errors:
    print(json.dumps({"status": "fail", "failures": errors[:8], "report": rel(REPORT)}))
    raise SystemExit(1)

print(
    json.dumps(
        {
            "status": "pass",
            "report": rel(REPORT),
            **stdout_summary,
        },
        sort_keys=True,
    )
)
PY
