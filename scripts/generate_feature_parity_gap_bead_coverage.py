#!/usr/bin/env python3
"""Generate gap->bead coverage + burndown dashboard artifacts (bd-w2c3.1.3)."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ACTIVE_OWNER_STATUSES = {"open", "in_progress", "blocked", "deferred"}


@dataclass(frozen=True)
class IssueRow:
    issue_id: str
    title: str
    status: str
    priority: int
    assignee: str | None
    dependencies: list[str]


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def owner_for_gap(gap: dict[str, Any]) -> str:
    kind = str(gap.get("kind", ""))
    if kind == "machine_delta_drift":
        delta_id = str(gap.get("delta_id", ""))
        if delta_id == "machine.support_vs_reality":
            return "bd-w2c3.10.1"
        if delta_id == "machine.replacement_vs_reality":
            return "bd-w2c3.2.3"
        return "bd-w2c3.1.2"
    if kind == "parse_error":
        return "bd-w2c3.1.1"
    section_owner = {
        "macro_targets": "bd-w2c3.1",
        "runtime_math": "bd-w2c3.5",
        "reverse_core": "bd-w2c3.4",
        "proof_math": "bd-w2c3.6",
        "gap_summary": "bd-w2c3.10",
    }
    return section_owner.get(str(gap.get("section", "")), "bd-w2c3.1.3")


def first_source_path(provenance: Any) -> str:
    if isinstance(provenance, dict):
        return str(provenance.get("path", "unknown"))
    if isinstance(provenance, list) and provenance:
        first = provenance[0]
        if isinstance(first, dict):
            return str(first.get("path", "unknown"))
    return "unknown"


def load_issues(path: Path) -> dict[str, IssueRow]:
    issues: dict[str, IssueRow] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        obj = json.loads(line)
        issue_id = str(obj.get("id", "")).strip()
        if not issue_id:
            continue
        deps: list[str] = []
        for dep in obj.get("dependencies", []):
            if not isinstance(dep, dict):
                continue
            dep_id = str(dep.get("depends_on_id", "")).strip()
            if dep_id:
                deps.append(dep_id)
        priority_raw = obj.get("priority", 4)
        try:
            priority = int(priority_raw)
        except Exception:
            priority = 4
        assignee = obj.get("assignee")
        issues[issue_id] = IssueRow(
            issue_id=issue_id,
            title=str(obj.get("title", "")),
            status=str(obj.get("status", "unknown")),
            priority=priority,
            assignee=str(assignee) if assignee is not None else None,
            dependencies=sorted(set(deps)),
        )
    return issues


def dependency_path_to_root(
    issue_id: str,
    issues: dict[str, IssueRow],
    *,
    max_depth: int = 24,
) -> list[str]:
    if issue_id not in issues:
        return [issue_id]
    path = [issue_id]
    seen = {issue_id}
    current = issue_id
    for _ in range(max_depth):
        deps = issues[current].dependencies
        if not deps:
            break
        next_id = sorted(deps)[0]
        path.append(next_id)
        if next_id in seen or next_id not in issues:
            break
        seen.add(next_id)
        current = next_id
    return path


def blocker_dependencies(issue_id: str, issues: dict[str, IssueRow]) -> list[dict[str, Any]]:
    row = issues.get(issue_id)
    if row is None:
        return []
    out: list[dict[str, Any]] = []
    for dep in row.dependencies:
        dep_row = issues.get(dep)
        status = dep_row.status if dep_row else "missing"
        if status != "closed":
            out.append({"issue_id": dep, "status": status})
    return out


def expected_actual_for_gap(
    *,
    gap: dict[str, Any],
    delta_lookup: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    kind = str(gap.get("kind", ""))
    if kind == "feature_parity_row_status":
        return {
            "expected": {"status": "DONE"},
            "actual": {"status": str(gap.get("status", "UNKNOWN"))},
        }
    if kind == "machine_delta_drift":
        delta_id = str(gap.get("delta_id", ""))
        delta = delta_lookup.get(delta_id, {})
        return {
            "expected": delta.get("expected", {}),
            "actual": delta.get("actual", {}),
        }
    if kind == "parse_error":
        return {"expected": {"parse_errors": 0}, "actual": {"message": gap.get("message", "")}}
    return {"expected": {}, "actual": {}}


def lookup_bv_blocker_chain(issue_id: str) -> dict[str, Any]:
    cmd = ["bv", "--robot-blocker-chain", issue_id]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        payload = json.loads(out)
        result = payload.get("result", {})
        chain = result.get("chain", [])
        root_blockers = result.get("root_blockers", [])
        return {
            "available": True,
            "is_blocked": bool(result.get("is_blocked", False)),
            "chain_length": int(result.get("chain_length", 0)),
            "root_blockers": [str(x) for x in root_blockers if isinstance(x, str)],
            "chain_ids": [
                str(node.get("id", "")) for node in chain if isinstance(node, dict) and node.get("id")
            ],
        }
    except Exception as exc:
        return {
            "available": False,
            "is_blocked": False,
            "chain_length": 0,
            "root_blockers": [],
            "chain_ids": [],
            "error": str(exc),
        }


def generate_dashboard_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Feature Parity Gap→Bead Coverage Dashboard (bd-w2c3.1.3)",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Total unresolved gaps: **{summary['total_unresolved_gaps']}**",
        f"- Covered gaps: **{summary['covered_gaps']}**",
        f"- Uncovered gaps: **{summary['uncovered_gaps']}**",
        f"- Active-owner gaps: **{summary['active_owner_gaps']}**",
        f"- Closed/missing-owner gaps: **{summary['inactive_owner_gaps']}**",
        "",
        "## Critical Blockers",
        "",
    ]

    critical = payload.get("critical_blockers", [])
    if not critical:
        lines.append("- None")
    else:
        for row in critical:
            lines.append(
                "- "
                f"`{row['owner_bead']}` status=`{row['owner_status']}` "
                f"gaps={row['gap_count']} p{row['priority']}"
            )

    lines.extend(
        [
            "",
            "## Dependency Bottlenecks",
            "",
            "| Owner Bead | Owner Status | Gap Count | Blocked Deps | BV Chain |",
            "|---|---|---:|---:|---:|",
        ]
    )
    for row in payload.get("dependency_bottlenecks", []):
        lines.append(
            "| "
            f"`{row['owner_bead']}` | `{row['owner_status']}` | {row['gap_count']} | "
            f"{row['blocked_dependency_count']} | {row['bv_chain_length']} |"
        )

    lines.extend(
        [
            "",
            "## Uncovered Gaps",
            "",
        ]
    )
    uncovered = [r for r in payload.get("rows", []) if not r.get("owner_found", False)]
    if not uncovered:
        lines.append("- None")
    else:
        for row in uncovered:
            lines.append(
                "- "
                f"`{row['gap_id']}` from `{row['source_file']}` "
                f"(owner `{row['owner_bead']}` not found)"
            )
    lines.append("")
    return "\n".join(lines)


def build_payload(
    *,
    gap_ledger_path: Path,
    issues_path: Path,
) -> dict[str, Any]:
    gap_ledger = json.loads(gap_ledger_path.read_text(encoding="utf-8"))
    issues = load_issues(issues_path)
    deltas = gap_ledger.get("deltas", [])
    delta_lookup = {
        str(d.get("delta_id")): d for d in deltas if isinstance(d, dict) and d.get("delta_id")
    }

    rows: list[dict[str, Any]] = []
    owner_gap_counts: Counter[str] = Counter()
    owner_blocked_dep_counts: Counter[str] = Counter()
    for gap in gap_ledger.get("gaps", []):
        if not isinstance(gap, dict):
            continue
        gap_id = str(gap.get("gap_id", "")).strip()
        if not gap_id:
            continue
        owner_bead = owner_for_gap(gap)
        owner = issues.get(owner_bead)
        owner_status = owner.status if owner else "missing"
        owner_found = owner is not None
        owner_active = owner_status in ACTIVE_OWNER_STATUSES
        path = dependency_path_to_root(owner_bead, issues)
        blocking = blocker_dependencies(owner_bead, issues)
        expected_vs_actual = expected_actual_for_gap(gap=gap, delta_lookup=delta_lookup)
        source = first_source_path(gap.get("provenance"))
        row = {
            "gap_id": gap_id,
            "gap_kind": str(gap.get("kind", "")),
            "section": str(gap.get("section", "")),
            "message": str(gap.get("message", "")),
            "status": str(gap.get("status", "")),
            "owner_bead": owner_bead,
            "owner_found": owner_found,
            "owner_status": owner_status,
            "owner_active": owner_active,
            "owner_assignee": owner.assignee if owner else None,
            "owner_priority": owner.priority if owner else None,
            "owner_title": owner.title if owner else "",
            "dependency_path": path,
            "blocking_dependencies": blocking,
            "source_file": source,
            "expected_vs_actual": expected_vs_actual,
        }
        rows.append(row)
        owner_gap_counts[owner_bead] += 1
        owner_blocked_dep_counts[owner_bead] += len(blocking)

    rows.sort(key=lambda r: (r["owner_bead"], r["gap_id"]))

    unique_owners = sorted(owner_gap_counts.keys())
    chain_verification = {
        owner: lookup_bv_blocker_chain(owner) for owner in unique_owners if owner and owner in issues
    }
    for row in rows:
        bv = chain_verification.get(row["owner_bead"])
        row["bv_blocker_chain"] = bv if bv is not None else {"available": False}

    critical_blockers: list[dict[str, Any]] = []
    for owner, gap_count in sorted(owner_gap_counts.items(), key=lambda i: (-i[1], i[0])):
        row = issues.get(owner)
        status = row.status if row else "missing"
        if status in ACTIVE_OWNER_STATUSES:
            continue
        critical_blockers.append(
            {
                "owner_bead": owner,
                "owner_status": status,
                "gap_count": gap_count,
                "priority": row.priority if row else 4,
                "assignee": row.assignee if row else None,
                "dependency_path": dependency_path_to_root(owner, issues),
            }
        )

    bottleneck_rows: list[dict[str, Any]] = []
    for owner, gap_count in sorted(owner_gap_counts.items(), key=lambda i: (-i[1], i[0]))[:15]:
        row = issues.get(owner)
        chain = chain_verification.get(owner, {})
        bottleneck_rows.append(
            {
                "owner_bead": owner,
                "owner_status": row.status if row else "missing",
                "gap_count": gap_count,
                "blocked_dependency_count": owner_blocked_dep_counts[owner],
                "priority": row.priority if row else 4,
                "assignee": row.assignee if row else None,
                "bv_chain_length": int(chain.get("chain_length", 0)) if isinstance(chain, dict) else 0,
                "bv_root_blockers": chain.get("root_blockers", []) if isinstance(chain, dict) else [],
            }
        )

    total = len(rows)
    covered = sum(1 for r in rows if r["owner_found"])
    active = sum(1 for r in rows if r["owner_active"])
    uncovered = total - covered
    inactive = total - active

    generated_at = str(gap_ledger.get("generated_at", "")).strip() or datetime.now(
        timezone.utc
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    summary = {
        "total_unresolved_gaps": total,
        "covered_gaps": covered,
        "uncovered_gaps": uncovered,
        "active_owner_gaps": active,
        "inactive_owner_gaps": inactive,
        "owner_count": len(unique_owners),
        "critical_blocker_count": len(critical_blockers),
    }

    return {
        "schema_version": "v1",
        "bead": "bd-w2c3.1.3",
        "generated_at": generated_at,
        "sources": {
            "feature_parity_gap_ledger": gap_ledger_path.as_posix(),
            "issues": issues_path.as_posix(),
        },
        "summary": summary,
        "critical_blockers": critical_blockers,
        "dependency_bottlenecks": bottleneck_rows,
        "rows": rows,
        "chain_verification": chain_verification,
    }


def run_check(expected_path: Path, expected_md_path: Path, payload: dict[str, Any]) -> int:
    rendered_json = canonical_json(payload)
    rendered_md = generate_dashboard_markdown(payload)
    if not expected_path.exists():
        print(f"FAIL: missing output file: {expected_path}")
        return 1
    if not expected_md_path.exists():
        print(f"FAIL: missing output file: {expected_md_path}")
        return 1
    current_json = expected_path.read_text(encoding="utf-8")
    current_md = expected_md_path.read_text(encoding="utf-8")
    if current_json != rendered_json or current_md != rendered_md:
        print(
            "FAIL: feature parity gap-bead coverage drift detected. "
            "Regenerate with scripts/generate_feature_parity_gap_bead_coverage.py"
        )
        return 1
    print(
        "PASS: feature parity gap-bead coverage is up-to-date "
        f"(gaps={payload['summary']['total_unresolved_gaps']}, "
        f"uncovered={payload['summary']['uncovered_gaps']}, "
        f"critical_blockers={payload['summary']['critical_blocker_count']})"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic feature parity gap->bead coverage.")
    parser.add_argument(
        "--gap-ledger",
        type=Path,
        default=Path("tests/conformance/feature_parity_gap_ledger.v1.json"),
        help="Path to feature parity gap ledger JSON",
    )
    parser.add_argument(
        "--issues",
        type=Path,
        default=Path(".beads/issues.jsonl"),
        help="Path to beads issue JSONL",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("tests/conformance/feature_parity_gap_bead_coverage.v1.json"),
        help="Output JSON path",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=Path("tests/conformance/feature_parity_gap_bead_dashboard.v1.md"),
        help="Output markdown dashboard path",
    )
    parser.add_argument("--check", action="store_true", help="Fail if generated output differs")
    parser.add_argument("--stdout", action="store_true", help="Print JSON output to stdout")
    args = parser.parse_args()

    payload = build_payload(gap_ledger_path=args.gap_ledger, issues_path=args.issues)
    if args.check:
        return run_check(args.output_json, args.output_md, payload)

    rendered_json = canonical_json(payload)
    rendered_md = generate_dashboard_markdown(payload)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(rendered_json, encoding="utf-8")
    args.output_md.write_text(rendered_md, encoding="utf-8")

    if args.stdout:
        print(rendered_json, end="")
    print(
        f"Wrote {args.output_json} and {args.output_md} "
        f"(gaps={payload['summary']['total_unresolved_gaps']}, "
        f"uncovered={payload['summary']['uncovered_gaps']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
