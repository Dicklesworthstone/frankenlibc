#!/usr/bin/env python3
"""Generate the reality-check bridge import reconciliation artifact (bd-bp8fl.2.2)."""

from __future__ import annotations

import argparse
import difflib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BEAD_ID = "bd-bp8fl.2.2"
TRACE_ID = "bd-bp8fl-2-2-reality-bridge-import-v1"
MIN_BRIDGE_GENERATED_AT = "2026-05-01T00:00:00Z"

BACKLOG_TARGETS: dict[str, list[str]] = {
    "rchk-001": [
        "bd-bp8fl.1",
        "bd-bp8fl.1.1",
        "bd-bp8fl.1.2",
        "bd-bp8fl.1.3",
        "bd-bp8fl.1.4",
        "bd-bp8fl.1.5",
        "bd-bp8fl.1.6",
    ],
    "rchk-002": ["bd-bp8fl.2.3", "bd-bp8fl.4.1", "bd-bp8fl.4.3"],
    "rchk-003": ["bd-bp8fl.2", "bd-bp8fl.2.1", "bd-bp8fl.2.2", "bd-bp8fl.2.3"],
    "rchk-004": [
        "bd-bp8fl.3",
        "bd-bp8fl.3.1",
        "bd-bp8fl.3.2",
        "bd-bp8fl.3.3",
        "bd-bp8fl.3.4",
        "bd-bp8fl.3.5",
        "bd-bp8fl.3.6",
        "bd-bp8fl.3.7",
        "bd-bp8fl.3.8",
        "bd-bp8fl.3.9",
        "bd-bp8fl.3.10",
        "bd-bp8fl.3.11",
        "bd-bp8fl.3.12",
        "bd-bp8fl.3.13",
        "bd-bp8fl.3.14",
    ],
    "rchk-005": [
        "bd-bp8fl.4",
        "bd-bp8fl.4.1",
        "bd-bp8fl.4.2",
        "bd-bp8fl.4.3",
        "bd-bp8fl.4.4",
    ],
    "rchk-006": ["bd-bp8fl.3.5", "bd-bp8fl.6", "bd-bp8fl.6.4"],
    "rchk-007": [
        "bd-bp8fl.6",
        "bd-bp8fl.6.1",
        "bd-bp8fl.6.2",
        "bd-bp8fl.6.3",
        "bd-bp8fl.6.4",
        "bd-bp8fl.6.5",
        "bd-bp8fl.6.6",
        "bd-bp8fl.6.7",
    ],
    "rchk-008": [
        "bd-bp8fl.5",
        "bd-bp8fl.5.1",
        "bd-bp8fl.5.2",
        "bd-bp8fl.5.3",
        "bd-bp8fl.5.4",
        "bd-bp8fl.5.5",
        "bd-bp8fl.5.6",
        "bd-bp8fl.5.7",
        "bd-bp8fl.5.8",
        "bd-bp8fl.5.9",
    ],
    "rchk-009": [
        "bd-bp8fl.7",
        "bd-bp8fl.7.1",
        "bd-bp8fl.7.2",
        "bd-bp8fl.7.3",
        "bd-bp8fl.7.4",
        "bd-bp8fl.7.5",
        "bd-bp8fl.7.6",
        "bd-bp8fl.7.7",
    ],
    "rchk-010": [
        "bd-bp8fl.8",
        "bd-bp8fl.8.1",
        "bd-bp8fl.8.2",
        "bd-bp8fl.8.3",
        "bd-bp8fl.8.4",
        "bd-bp8fl.8.5",
        "bd-bp8fl.8.6",
    ],
}

BATCH_FOLLOWUP_BEADS: dict[str, str] = {
    "fpg-claim-control": "bd-bp8fl.3.5",
    "fpg-reverse-runtime-core": "bd-bp8fl.3.6",
    "fpg-reverse-loader-process-abi": "bd-bp8fl.3.7",
    "fpg-proof-core-safety": "bd-bp8fl.3.8",
    "fpg-proof-online-control": "bd-bp8fl.3.9",
    "fpg-proof-coverage-interaction": "bd-bp8fl.3.10",
    "fpg-proof-algebraic-topological": "bd-bp8fl.3.11",
    "fpg-gap-summary-evidence-foundation": "bd-bp8fl.3.12",
    "fpg-gap-summary-ported-surface-evidence": "bd-bp8fl.3.13",
    "fpg-gap-summary-runtime-monitor-evidence": "bd-bp8fl.3.14",
}

STATUS_TRANSLATION: dict[str, dict[str, Any]] = {
    "started": {"target_statuses": ["open", "in_progress"], "action": "reconciled_to_active_beads"},
    "pending": {"target_statuses": ["open"], "action": "reconciled_to_open_beads"},
    "blocked_on_br": {
        "target_statuses": ["open", "in_progress", "closed"],
        "action": "reconciled_to_tracker_recovery_beads",
    },
    "done_for_this_pass": {
        "target_statuses": ["closed"],
        "action": "preserved_as_closed_evidence_beads",
    },
    "isolated_for_this_pass": {
        "target_statuses": ["open", "in_progress", "closed"],
        "action": "reconciled_to_validation_hygiene_beads",
    },
}


@dataclass(frozen=True)
class Issue:
    issue_id: str
    title: str
    status: str
    priority: int
    labels: list[str]
    dependencies: list[str]
    acceptance_text: str


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"cannot parse JSON artifact {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"JSON artifact must be an object: {path}")
    return payload


def load_issues(path: Path) -> dict[str, Issue]:
    issues: dict[str, Issue] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"cannot parse issue JSONL row {path}:{exc.lineno}: {exc}") from exc
        issue_id = str(obj.get("id", "")).strip()
        if not issue_id:
            continue
        deps = sorted(
            {
                str(dep.get("depends_on_id", "")).strip()
                for dep in obj.get("dependencies", [])
                if isinstance(dep, dict) and dep.get("depends_on_id")
            }
        )
        labels = [str(label) for label in obj.get("labels", []) if isinstance(label, str)]
        try:
            priority = int(obj.get("priority", 4))
        except Exception:
            priority = 4
        acceptance = str(obj.get("acceptance_criteria") or "")
        description = str(obj.get("description") or "")
        if not acceptance and "Acceptance:" in description:
            acceptance = description[description.index("Acceptance:") :]
        issues[issue_id] = Issue(
            issue_id=issue_id,
            title=str(obj.get("title", "")),
            status=str(obj.get("status", "unknown")),
            priority=priority,
            labels=labels,
            dependencies=deps,
            acceptance_text=acceptance,
        )
    return issues


def priority_to_int(priority: Any) -> int:
    text = str(priority).strip().upper()
    if text.startswith("P") and text[1:].isdigit():
        return int(text[1:])
    try:
        return int(text)
    except Exception:
        return 4


def validate_unique(values: list[str]) -> list[str]:
    counts = Counter(values)
    return sorted(value for value, count in counts.items() if count > 1)


def source_freshness(*, generated_at: str | None) -> dict[str, Any]:
    if not generated_at:
        return {
            "generated_at_utc": None,
            "minimum_generated_at_utc": MIN_BRIDGE_GENERATED_AT,
            "state": "missing_generated_at",
        }
    return {
        "generated_at_utc": generated_at,
        "minimum_generated_at_utc": MIN_BRIDGE_GENERATED_AT,
        "state": "fresh" if generated_at >= MIN_BRIDGE_GENERATED_AT else "stale",
    }


def issue_summary(issue: Issue | None) -> dict[str, Any]:
    if issue is None:
        return {
            "exists": False,
            "priority": None,
            "labels": [],
            "dependencies": [],
            "has_acceptance": False,
        }
    return {
        "exists": True,
        "priority": issue.priority,
        "labels": issue.labels,
        "dependencies": issue.dependencies,
        "has_acceptance": bool(issue.acceptance_text.strip()),
    }


def build_backlog_rows(
    *,
    backlog: dict[str, Any],
    issues: dict[str, Issue],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    work_items = backlog.get("work_items", [])
    duplicate_ids = validate_unique([str(item.get("id", "")) for item in work_items if isinstance(item, dict)])
    for duplicate in duplicate_ids:
        rejected.append(
            {
                "import_source": "reality_check_bridge_backlog",
                "source_row_id": duplicate,
                "reason": "duplicate_source_row",
            }
        )
    for item in work_items:
        if not isinstance(item, dict):
            rejected.append(
                {
                    "import_source": "reality_check_bridge_backlog",
                    "source_row_id": "<non-object>",
                    "reason": "missing_required_field",
                }
            )
            continue
        source_id = str(item.get("id", "")).strip()
        title = str(item.get("title", "")).strip()
        if not source_id or not title:
            rejected.append(
                {
                    "import_source": "reality_check_bridge_backlog",
                    "source_row_id": source_id or "<missing>",
                    "reason": "missing_required_field",
                }
            )
            continue
        targets = BACKLOG_TARGETS.get(source_id, [])
        if not targets:
            rejected.append(
                {
                    "import_source": "reality_check_bridge_backlog",
                    "source_row_id": source_id,
                    "reason": "missing_import_mapping",
                }
            )
            continue
        summaries = {target: issue_summary(issues.get(target)) for target in targets}
        missing_targets = [target for target, summary in summaries.items() if not summary["exists"]]
        missing_acceptance = [
            target
            for target, summary in summaries.items()
            if summary["exists"] and not summary["has_acceptance"]
        ]
        status = str(item.get("status", "pending"))
        translation = STATUS_TRANSLATION.get(status, STATUS_TRANSLATION["pending"])
        primary = targets[0]
        row = {
            "import_source": "reality_check_bridge_backlog",
            "source_row_id": source_id,
            "title": title,
            "source_status": status,
            "status_translation": translation,
            "source_priority": str(item.get("priority", "")),
            "target_priority": priority_to_int(item.get("priority")),
            "primary_target_issue_id": primary,
            "target_issue_ids": targets,
            "target_issue_summaries": summaries,
            "artifact_refs": item.get("evidence_paths", []),
            "subtask_count": len(item.get("subtasks", [])),
            "source_freshness": source_freshness(generated_at=backlog.get("generated_at_utc")),
            "expected": {
                "source_row_preserved": True,
                "target_issue_count": len(targets),
                "missing_target_issues": 0,
                "missing_acceptance_targets": 0,
            },
            "actual": {
                "source_row_preserved": True,
                "target_issue_count": len(targets),
                "missing_target_issues": len(missing_targets),
                "missing_acceptance_targets": len(missing_acceptance),
            },
            "failure_signature": "ok"
            if not missing_targets and not missing_acceptance
            else "missing_target_or_acceptance",
        }
        rows.append(row)
    return rows, rejected


def build_batch_lookup(groups: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    lookup: dict[str, dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []
    for batch in groups.get("batches", []):
        if not isinstance(batch, dict):
            continue
        batch_id = str(batch.get("batch_id", "")).strip()
        followup = BATCH_FOLLOWUP_BEADS.get(batch_id, "")
        if not batch_id or not followup:
            rejected.append(
                {
                    "import_source": "feature_parity_gap_groups",
                    "source_row_id": batch_id or "<missing>",
                    "reason": "missing_followup_mapping",
                }
            )
            continue
        for gap_id in batch.get("gap_ids", []):
            gap_key = str(gap_id)
            if gap_key in lookup:
                rejected.append(
                    {
                        "import_source": "feature_parity_gap_groups",
                        "source_row_id": gap_key,
                        "reason": "duplicate_gap_mapping",
                    }
                )
                continue
            lookup[gap_key] = {
                "batch_id": batch_id,
                "target_issue_id": followup,
                "priority": int(batch.get("priority", 4)),
                "artifact_refs": batch.get("evidence_artifacts", []),
                "oracle_kind": batch.get("oracle_kind", ""),
                "replacement_levels": batch.get("replacement_levels", []),
                "closure_blockers": batch.get("closure_blockers", []),
            }
    return lookup, rejected


def build_feature_gap_rows(
    *,
    ledger: dict[str, Any],
    groups: dict[str, Any],
    issues: dict[str, Issue],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    lookup, rejected = build_batch_lookup(groups)
    rows: list[dict[str, Any]] = []
    gaps = ledger.get("gaps", [])
    duplicate_gap_ids = validate_unique([str(gap.get("gap_id", "")) for gap in gaps if isinstance(gap, dict)])
    for duplicate in duplicate_gap_ids:
        rejected.append(
            {
                "import_source": "feature_parity_gap_ledger",
                "source_row_id": duplicate,
                "reason": "duplicate_source_row",
            }
        )
    for gap in gaps:
        if not isinstance(gap, dict):
            rejected.append(
                {
                    "import_source": "feature_parity_gap_ledger",
                    "source_row_id": "<non-object>",
                    "reason": "missing_required_field",
                }
            )
            continue
        gap_id = str(gap.get("gap_id", "")).strip()
        if not gap_id:
            rejected.append(
                {
                    "import_source": "feature_parity_gap_ledger",
                    "source_row_id": "<missing>",
                    "reason": "missing_required_field",
                }
            )
            continue
        mapping = lookup.get(gap_id)
        if mapping is None:
            rejected.append(
                {
                    "import_source": "feature_parity_gap_ledger",
                    "source_row_id": gap_id,
                    "reason": "missing_import_mapping",
                }
            )
            continue
        target = mapping["target_issue_id"]
        issue = issues.get(target)
        summary = issue_summary(issue)
        expected_deps = ["bd-bp8fl.3", "bd-bp8fl.3.1"]
        missing_deps = [dep for dep in expected_deps if dep not in summary["dependencies"]]
        failure = "ok"
        if not summary["exists"]:
            failure = "missing_target_issue"
        elif missing_deps:
            failure = "missing_dependency"
        elif not summary["has_acceptance"]:
            failure = "missing_acceptance"
        rows.append(
            {
                "import_source": "feature_parity_gap_ledger",
                "source_row_id": gap_id,
                "source_section": str(gap.get("section", "")),
                "source_status": str(gap.get("status", "")),
                "source_kind": str(gap.get("kind", "")),
                "batch_id": mapping["batch_id"],
                "target_issue_id": target,
                "target_issue_summary": summary,
                "parent_epic": "bd-bp8fl.3",
                "expected_dependencies": expected_deps,
                "missing_dependencies": missing_deps,
                "priority": mapping["priority"],
                "artifact_refs": mapping["artifact_refs"],
                "oracle_kind": mapping["oracle_kind"],
                "replacement_levels": mapping["replacement_levels"],
                "closure_blockers": mapping["closure_blockers"],
                "source_freshness": source_freshness(generated_at=groups.get("generated_at_utc")),
                "expected": {
                    "gap_preserved_once": True,
                    "target_issue_exists": True,
                    "expected_dependencies": expected_deps,
                    "has_acceptance": True,
                },
                "actual": {
                    "gap_preserved_once": True,
                    "target_issue_exists": summary["exists"],
                    "actual_dependencies": summary["dependencies"],
                    "has_acceptance": summary["has_acceptance"],
                },
                "failure_signature": failure,
            }
        )
    return rows, rejected


def build_payload(
    *,
    backlog_path: Path,
    ledger_path: Path,
    groups_path: Path,
    issues_path: Path,
) -> dict[str, Any]:
    backlog = load_json(backlog_path)
    ledger = load_json(ledger_path)
    groups = load_json(groups_path)
    issues = load_issues(issues_path)
    backlog_rows, backlog_rejected = build_backlog_rows(backlog=backlog, issues=issues)
    feature_rows, feature_rejected = build_feature_gap_rows(
        ledger=ledger,
        groups=groups,
        issues=issues,
    )
    rejected = backlog_rejected + feature_rejected
    missing_target_count = sum(
        1
        for row in backlog_rows
        for summary in row["target_issue_summaries"].values()
        if not summary["exists"]
    ) + sum(1 for row in feature_rows if not row["target_issue_summary"]["exists"])
    missing_acceptance_count = sum(
        1
        for row in backlog_rows
        for summary in row["target_issue_summaries"].values()
        if summary["exists"] and not summary["has_acceptance"]
    ) + sum(
        1
        for row in feature_rows
        if row["target_issue_summary"]["exists"] and not row["target_issue_summary"]["has_acceptance"]
    )
    missing_dependency_count = sum(len(row["missing_dependencies"]) for row in feature_rows)
    stale_source_count = sum(
        1
        for row in backlog_rows + feature_rows
        if row["source_freshness"]["state"] != "fresh"
    )
    target_ids = sorted(
        {
            target
            for row in backlog_rows
            for target in row["target_issue_ids"]
        }
        | {row["target_issue_id"] for row in feature_rows}
    )
    ledger_summary = ledger.get("summary", {})
    summary = {
        "backlog_source_rows": len(backlog.get("work_items", [])),
        "backlog_import_rows": len(backlog_rows),
        "feature_ledger_rows": int(ledger_summary.get("row_count", len(ledger.get("rows", [])))),
        "feature_ledger_unresolved_gaps": int(ledger_summary.get("gap_count", len(ledger.get("gaps", [])))),
        "feature_gap_import_rows": len(feature_rows),
        "feature_gap_batches": len(groups.get("batches", [])),
        "unique_target_issue_count": len(target_ids),
        "rejected_row_count": len(rejected),
        "missing_target_issue_count": missing_target_count,
        "missing_acceptance_target_count": missing_acceptance_count,
        "missing_dependency_count": missing_dependency_count,
        "stale_source_snapshot_count": stale_source_count,
        "lost_feature_gap_count": int(ledger_summary.get("gap_count", 0)) - len(feature_rows),
    }
    return {
        "schema_version": "v1",
        "bead": BEAD_ID,
        "trace_id": TRACE_ID,
        "generated_at_utc": backlog.get("generated_at_utc", "unknown"),
        "purpose": (
            "Define and verify the live-bead import mapping for the reality-check bridge "
            "backlog and feature parity gap ledger."
        ),
        "sources": {
            "reality_check_bridge_backlog": backlog_path.as_posix(),
            "feature_parity_gap_ledger": ledger_path.as_posix(),
            "feature_parity_gap_groups": groups_path.as_posix(),
            "issues": issues_path.as_posix(),
        },
        "import_mapping_contract": {
            "source_of_truth": "JSONL-visible br beads plus deterministic conformance artifacts",
            "row_policy": "Every backlog work_item and every unresolved ledger gap maps to at least one live bd-bp8fl bead.",
            "status_translation": STATUS_TRANSLATION,
            "priority_translation": "P0/P1/P2 map to br priorities 0/1/2.",
            "dependency_policy": (
                "Feature-ledger gap follow-up beads must depend on bd-bp8fl.3 and "
                "bd-bp8fl.3.1 so grouping remains the import prerequisite."
            ),
            "acceptance_policy": (
                "A target bead must expose acceptance_criteria or an inline Acceptance: block "
                "in its description."
            ),
            "source_freshness_policy": {
                "minimum_generated_at_utc": MIN_BRIDGE_GENERATED_AT,
                "stale_source_snapshots_fail": True,
            },
        },
        "summary": summary,
        "target_issue_ids": target_ids,
        "rejected_rows": rejected,
        "backlog_import_rows": backlog_rows,
        "feature_gap_import_rows": feature_rows,
        "negative_fixture_cases": [
            "duplicate_source_row",
            "missing_required_field",
            "stale_source_snapshot",
            "missing_dependency",
            "missing_acceptance",
            "no_feature_loss",
        ],
    }


def run_check(expected_path: Path, payload: dict[str, Any]) -> int:
    if not expected_path.exists():
        print(f"FAIL: missing output file: {expected_path}")
        return 1
    rendered = canonical_json(payload)
    current = expected_path.read_text(encoding="utf-8")
    if current != rendered:
        print(
            "FAIL: reality bridge import reconciliation drift detected. "
            "Regenerate with scripts/generate_reality_bridge_import_reconciliation.py"
        )
        for line in list(
            difflib.unified_diff(
                current.splitlines(),
                rendered.splitlines(),
                fromfile=expected_path.as_posix(),
                tofile="generated",
                lineterm="",
            )
        )[:80]:
            print(line)
        return 1
    summary = payload["summary"]
    if summary["rejected_row_count"] != 0:
        print(f"FAIL: rejected rows present: {summary['rejected_row_count']}")
        return 1
    if summary["missing_target_issue_count"] != 0:
        print(f"FAIL: missing target issues: {summary['missing_target_issue_count']}")
        return 1
    if summary["missing_acceptance_target_count"] != 0:
        print(f"FAIL: missing target acceptance: {summary['missing_acceptance_target_count']}")
        return 1
    if summary["missing_dependency_count"] != 0:
        print(f"FAIL: missing dependency edges: {summary['missing_dependency_count']}")
        return 1
    if summary["stale_source_snapshot_count"] != 0:
        print(f"FAIL: stale source snapshots: {summary['stale_source_snapshot_count']}")
        return 1
    if summary["lost_feature_gap_count"] != 0:
        print(f"FAIL: lost feature gaps: {summary['lost_feature_gap_count']}")
        return 1
    print(
        "PASS: reality bridge import reconciliation is up-to-date "
        f"(backlog_rows={summary['backlog_import_rows']}, "
        f"feature_gaps={summary['feature_gap_import_rows']}, "
        f"targets={summary['unique_target_issue_count']})"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate bd-bp8fl.2.2 import reconciliation.")
    parser.add_argument(
        "--backlog",
        type=Path,
        default=Path("tests/conformance/reality_check_bridge_backlog.v1.json"),
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        default=Path("tests/conformance/feature_parity_gap_ledger.v1.json"),
    )
    parser.add_argument(
        "--groups",
        type=Path,
        default=Path("tests/conformance/feature_parity_gap_groups.v1.json"),
    )
    parser.add_argument("--issues", type=Path, default=Path(".beads/issues.jsonl"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tests/conformance/reality_bridge_import_reconciliation.v1.json"),
    )
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()

    payload = build_payload(
        backlog_path=args.backlog,
        ledger_path=args.ledger,
        groups_path=args.groups,
        issues_path=args.issues,
    )
    if args.check:
        return run_check(args.output, payload)
    rendered = canonical_json(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    if args.stdout:
        print(rendered, end="")
    print(
        f"Wrote {args.output} "
        f"(backlog_rows={payload['summary']['backlog_import_rows']}, "
        f"feature_gaps={payload['summary']['feature_gap_import_rows']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
