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


def is_permissioned(issue: dict[str, Any], markers: list[str]) -> tuple[bool, list[str]]:
    text = issue_text(issue)
    hits = [marker for marker in markers if marker.lower() in text]
    return bool(hits), hits


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
            blockers.append({"id": blocker_id, "status": blocker_status, "reason": "unclosed_blocks_dependency"})
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


def is_container_parent(issue: dict[str, Any]) -> bool:
    return issue.get("issue_type") == "epic"


def analyze(rows: list[dict[str, Any]], contract: dict[str, Any]) -> dict[str, Any]:
    issue_by_id = {str(row.get("id")): row for row in rows if isinstance(row.get("id"), str)}
    permission_markers = [
        str(marker) for marker in contract.get("permission_required_markers", []) if str(marker).strip()
    ]
    stale_hours = float(contract.get("stale_in_progress_after_hours", 72))
    now = datetime.now(timezone.utc)

    ready: list[dict[str, Any]] = []
    safe_ready: list[dict[str, Any]] = []
    permissioned_ready: list[dict[str, Any]] = []
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
                ready_row = project_issue(
                    issue,
                    extra={
                        "permission_required": permissioned,
                        "permission_markers": markers,
                    },
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
            "blocked_open_total": len(blocked_open),
            "container_open_total": len(container_open),
            "in_progress_total": len(in_progress),
            "stale_in_progress_total": len(stale_in_progress),
            "stale_in_progress_after_hours": stale_hours,
        },
        "ready": ready,
        "safe_ready": safe_ready,
        "permissioned_ready": permissioned_ready,
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
    return controls


contract = load_json(CONTRACT)
rows = load_jsonl(ISSUES)
errors = validate_contract(contract)
analysis = analyze(rows, contract)
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
    "data_sources": [rel(ISSUES)],
    "forbidden_sources": contract.get("forbidden_sources", []),
    "db_accessed": False,
    "summary": analysis["summary"],
    "safe_ready": analysis["safe_ready"],
    "permissioned_ready": analysis["permissioned_ready"],
    "blocked_open": analysis["blocked_open"],
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
report["status"] = "fail" if errors else "pass"
report["failures"] = errors

events = [
    {
        "event": "tracker_jsonl_degraded_readiness",
        "status": report["status"],
        "source": rel(ISSUES),
        "safe_ready_total": report["summary"]["safe_ready_total"],
        "permissioned_ready_total": report["summary"]["permissioned_ready_total"],
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
            "safe_ready": report["summary"]["safe_ready_total"],
            "permissioned_ready": report["summary"]["permissioned_ready_total"],
            "stale_in_progress": report["summary"]["stale_in_progress_total"],
            "report": rel(REPORT),
        },
        sort_keys=True,
    )
)
PY
