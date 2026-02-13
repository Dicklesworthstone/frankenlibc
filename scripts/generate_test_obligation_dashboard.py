#!/usr/bin/env python3
"""Generate coverage dashboard + closure blockers artifact for bd-3cco."""

from __future__ import annotations

import argparse
import json
import unittest
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REQUIRED_CATEGORIES = [
    "unit_tests",
    "e2e_scripts",
    "structured_logs",
    "perf_evidence",
    "conformance_fixtures",
    "golden_artifacts",
]

TRACKED_STATUSES = {"open", "in_progress", "blocked", "deferred"}

GENERIC_LABELS = {
    "ci",
    "critique",
    "testing",
    "verification",
    "reporting",
    "execution",
    "feature-parity",
    "gap-closure",
    "implementation",
}


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def infer_subsystem(labels: list[str], row_stream: str | None) -> str:
    stream = (row_stream or "").strip().lower()
    for label in labels:
        norm = str(label).strip().lower()
        if norm and norm not in GENERIC_LABELS:
            if stream:
                return f"{stream}/{norm}"
            return norm
    return stream or "general"


def normalize_status(status: str) -> str:
    token = status.strip().lower()
    if token in {"complete", "partial", "missing", "not_required"}:
        return token
    return "missing"


def blocker_name_for_category(category: str) -> str:
    mapping = {
        "unit_tests": "missing_unit",
        "e2e_scripts": "missing_e2e",
        "structured_logs": "missing_logs",
        "perf_evidence": "missing_perf",
        "conformance_fixtures": "missing_fixtures",
        "golden_artifacts": "missing_golden_artifacts",
    }
    return mapping.get(category, f"missing_{category}")


def derive_blockers(entry: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    obligations = entry.get("obligations", {})
    coverage = entry.get("coverage", {})
    row = entry.get("row", {})
    row_blockers = set(str(x) for x in row.get("close_blockers", []) if isinstance(x, str))

    for category in REQUIRED_CATEGORIES:
        ob = obligations.get(category, {})
        required = bool(ob.get("required", False))
        if not required:
            continue
        cov = coverage.get(category, {})
        status = normalize_status(str(cov.get("status", "missing")))
        if status == "complete":
            continue
        blocker_name = blocker_name_for_category(category)
        out.append(
            {
                "blocker": blocker_name,
                "category": category,
                "coverage_status": status,
                "present_in_row_close_blockers": blocker_name in row_blockers,
            }
        )
    return out


def build_payload(matrix: dict[str, Any]) -> dict[str, Any]:
    entries = matrix.get("entries", [])
    generated_at = str(matrix.get("generated_utc", "")).strip() or datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")

    coverage_by_subsystem: dict[str, dict[str, Any]] = {}
    blocker_rows: list[dict[str, Any]] = []
    by_bead: list[dict[str, Any]] = []
    blocker_counts = Counter()
    category_missing_counts = Counter()

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        bead_id = str(entry.get("bead_id", "")).strip()
        if not bead_id:
            continue
        status = str(entry.get("status", "unknown"))
        if status not in TRACKED_STATUSES:
            continue
        priority = int(entry.get("priority", 4))
        labels = [str(x) for x in entry.get("labels", []) if isinstance(x, str)]
        row = entry.get("row", {})
        stream = str(row.get("stream", "")).strip().lower() or None
        subsystem = infer_subsystem(labels, stream)
        obligations = entry.get("obligations", {})
        coverage = entry.get("coverage", {})

        if subsystem not in coverage_by_subsystem:
            coverage_by_subsystem[subsystem] = {
                "subsystem": subsystem,
                "stream": stream or "general",
                "bead_count": 0,
                "categories": {
                    c: {"required": 0, "complete": 0, "partial": 0, "missing": 0}
                    for c in REQUIRED_CATEGORIES
                },
            }
        group = coverage_by_subsystem[subsystem]
        group["bead_count"] += 1

        blockers = derive_blockers(entry)
        by_bead.append(
            {
                "bead_id": bead_id,
                "title": str(entry.get("title", "")),
                "status": status,
                "priority": priority,
                "assignee": entry.get("assignee"),
                "subsystem": subsystem,
                "stream": stream or "general",
                "required_categories": sum(
                    1
                    for c in REQUIRED_CATEGORIES
                    if bool(obligations.get(c, {}).get("required", False))
                ),
                "blocker_count": len(blockers),
            }
        )

        for category in REQUIRED_CATEGORIES:
            category_ob = obligations.get(category, {})
            if not bool(category_ob.get("required", False)):
                continue
            category_cov = coverage.get(category, {})
            cov_status = normalize_status(str(category_cov.get("status", "missing")))
            if cov_status == "not_required":
                cov_status = "missing"
            group["categories"][category]["required"] += 1
            group["categories"][category][cov_status] += 1
            if cov_status != "complete":
                category_missing_counts[category] += 1

        for blocker in blockers:
            blocker_counts[blocker["blocker"]] += 1
            blocker_rows.append(
                {
                    "bead_id": bead_id,
                    "title": str(entry.get("title", "")),
                    "bead_status": status,
                    "priority": priority,
                    "subsystem": subsystem,
                    "stream": stream or "general",
                    "blocker": blocker["blocker"],
                    "category": blocker["category"],
                    "coverage_status": blocker["coverage_status"],
                    "present_in_row_close_blockers": blocker["present_in_row_close_blockers"],
                    "unit_cmds": row.get("unit_cmds", []),
                    "e2e_cmds": row.get("e2e_cmds", []),
                    "artifact_paths": row.get("artifact_paths", []),
                    "log_schema_refs": row.get("log_schema_refs", []),
                }
            )

    by_bead.sort(key=lambda r: (r["status"], r["priority"], r["bead_id"]))
    blocker_rows.sort(key=lambda r: (r["bead_status"], r["priority"], r["bead_id"], r["blocker"]))

    subsystems = [coverage_by_subsystem[k] for k in sorted(coverage_by_subsystem)]
    summary = {
        "entry_count": len(by_bead),
        "subsystem_count": len(subsystems),
        "blocker_count": len(blocker_rows),
        "blocked_bead_count": sum(1 for r in by_bead if r["blocker_count"] > 0),
        "by_blocker": dict(sorted(blocker_counts.items())),
        "by_category_missing": dict(sorted(category_missing_counts.items())),
    }
    return {
        "schema_version": "v1",
        "bead": "bd-3cco",
        "generated_at": generated_at,
        "source": "tests/conformance/verification_matrix.json",
        "summary": summary,
        "coverage_by_subsystem": subsystems,
        "blockers": blocker_rows,
        "by_bead": by_bead,
    }


class DashboardUnitTests(unittest.TestCase):
    def test_infer_subsystem_prefers_specific_label(self) -> None:
        labels = ["critique", "testing", "startup", "verification"]
        self.assertEqual(infer_subsystem(labels, "e2e"), "e2e/startup")

    def test_blockers_derive_from_missing_required_categories(self) -> None:
        entry = {
            "obligations": {
                "unit_tests": {"required": True},
                "e2e_scripts": {"required": True},
                "structured_logs": {"required": False},
            },
            "coverage": {
                "unit_tests": {"status": "missing"},
                "e2e_scripts": {"status": "partial"},
                "structured_logs": {"status": "not_required"},
            },
            "row": {"close_blockers": ["missing_unit"]},
        }
        blockers = derive_blockers(entry)
        names = {b["blocker"] for b in blockers}
        self.assertEqual(names, {"missing_unit", "missing_e2e"})
        row_map = {b["blocker"]: b["present_in_row_close_blockers"] for b in blockers}
        self.assertTrue(row_map["missing_unit"])
        self.assertFalse(row_map["missing_e2e"])


def run_self_tests() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DashboardUnitTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def run_check(output_path: Path, payload: dict[str, Any]) -> int:
    rendered = canonical_json(payload)
    if not output_path.exists():
        print(f"FAIL: missing output file: {output_path}")
        return 1
    current = output_path.read_text(encoding="utf-8")
    if current != rendered:
        print(
            "FAIL: test obligation dashboard drift detected. "
            "Regenerate with scripts/generate_test_obligation_dashboard.py"
        )
        return 1
    print(
        "PASS: test obligation dashboard is up-to-date "
        f"(entries={payload['summary']['entry_count']}, blockers={payload['summary']['blocker_count']})"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate test-obligation dashboard + blocker extraction.")
    parser.add_argument(
        "--matrix",
        type=Path,
        default=Path("tests/conformance/verification_matrix.json"),
        help="Path to verification matrix JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tests/conformance/test_obligation_dashboard.v1.json"),
        help="Output dashboard path",
    )
    parser.add_argument("--check", action="store_true", help="Fail if output differs from generated content")
    parser.add_argument("--self-test", action="store_true", help="Run generator unit tests and exit")
    parser.add_argument("--stdout", action="store_true", help="Print generated JSON")
    args = parser.parse_args()

    if args.self_test:
        return run_self_tests()

    matrix = json.loads(args.matrix.read_text(encoding="utf-8"))
    payload = build_payload(matrix)
    rendered = canonical_json(payload)

    if args.check:
        return run_check(args.output, payload)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    if args.stdout:
        print(rendered, end="")
    print(
        f"Wrote {args.output} "
        f"(entries={payload['summary']['entry_count']}, blockers={payload['summary']['blocker_count']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
