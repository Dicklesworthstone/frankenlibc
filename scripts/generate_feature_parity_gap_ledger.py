#!/usr/bin/env python3
"""Generate FEATURE_PARITY gap ledger vs machine artifacts (bd-w2c3.1.1)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATUS_DONE = "DONE"
STATUS_IN_PROGRESS = "IN_PROGRESS"
STATUS_PLANNED = "PLANNED"
STATUS_UNKNOWN = "UNKNOWN"
ALLOWED_STATUSES = {STATUS_DONE, STATUS_IN_PROGRESS, STATUS_PLANNED, STATUS_UNKNOWN}

SECTION_HEADERS: dict[str, tuple[str, list[str], int, int]] = {
    # section_key: (heading, column_names, key_column_index, status_column_index)
    "macro_targets": ("## Macro Coverage Targets", ["Area", "Target", "Status"], 0, 2),
    "runtime_math": (
        "## Runtime Math Kernel Matrix",
        ["Runtime Kernel", "Live Role", "Status"],
        0,
        2,
    ),
    "reverse_core": (
        "## Reverse Core Coverage Matrix",
        ["Surface", "Failure Target", "Required Runtime Artifact", "Status"],
        0,
        3,
    ),
    "proof_math": ("## Proof and Math Matrix", ["Obligation", "Evidence Artifact", "Status"], 0, 2),
}

GAP_SUMMARY_HEADER = "## Gap Summary"
GAP_SUMMARY_RE = re.compile(r"^(\d+)\.\s+(.*)$")


@dataclass(frozen=True)
class ParseError:
    section: str
    line: int
    message: str


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def normalize_key(value: str) -> str:
    norm = re.sub(r"`+", "", value.lower())
    norm = re.sub(r"[^a-z0-9]+", "-", norm).strip("-")
    return norm or "row"


def make_row_id(section: str, primary_key: str) -> str:
    key = f"{section}:{normalize_key(primary_key)}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"fp-{normalize_key(section)}-{digest}"


def parse_status(raw: str) -> str:
    token = raw.strip().upper()
    if token in ALLOWED_STATUSES:
        return token
    if token in {"ACHIEVED", "COMPLETE"}:
        return STATUS_DONE
    if token in {"OPEN", "PENDING"}:
        return STATUS_IN_PROGRESS
    return STATUS_UNKNOWN


def parse_table_cells(line: str) -> list[str] | None:
    text = line.strip()
    if not text.startswith("|"):
        return None
    parts = [p.strip() for p in text.split("|")]
    if len(parts) < 3:
        return None
    # split() around pipes yields leading/trailing empty cells for proper rows.
    return parts[1:-1]


def is_separator_row(cells: list[str]) -> bool:
    if not cells:
        return False
    return all(re.fullmatch(r":?-{3,}:?", c.replace(" ", "")) is not None for c in cells)


def parse_section_rows(
    lines: list[str],
    section_key: str,
    heading: str,
    columns: list[str],
    key_col: int,
    status_col: int,
    source_path: str,
) -> tuple[list[dict[str, Any]], list[ParseError]]:
    errors: list[ParseError] = []
    rows: list[dict[str, Any]] = []
    heading_idx = next((i for i, line in enumerate(lines) if line.strip() == heading), None)
    if heading_idx is None:
        errors.append(ParseError(section=section_key, line=1, message=f"missing heading: {heading}"))
        return rows, errors

    seen_primary: dict[str, int] = {}
    in_table = False
    for line_no in range(heading_idx + 1, len(lines)):
        line = lines[line_no]
        stripped = line.strip()

        # stop on next section
        if stripped.startswith("## ") and stripped != heading:
            break

        cells = parse_table_cells(line)
        if cells is None:
            if in_table and stripped:
                # exited table body
                break
            continue

        if is_separator_row(cells):
            in_table = True
            continue
        in_table = True

        # Skip markdown table header row if encountered in body scan.
        if [c.strip().lower() for c in cells] == [c.strip().lower() for c in columns]:
            continue

        if len(cells) != len(columns):
            errors.append(
                ParseError(
                    section=section_key,
                    line=line_no + 1,
                    message=f"malformed row: expected {len(columns)} columns, got {len(cells)}",
                )
            )
            continue

        primary = cells[key_col]
        if not primary:
            errors.append(
                ParseError(section=section_key, line=line_no + 1, message="missing primary key column")
            )
            continue
        if primary in seen_primary:
            first_line = seen_primary[primary]
            errors.append(
                ParseError(
                    section=section_key,
                    line=line_no + 1,
                    message=f"duplicate row key '{primary}' (first seen at line {first_line})",
                )
            )
        else:
            seen_primary[primary] = line_no + 1

        col_map = {columns[i]: cells[i] for i in range(len(columns))}
        rows.append(
            {
                "row_id": make_row_id(section_key, primary),
                "section": section_key,
                "primary_key": primary,
                "status": parse_status(cells[status_col]),
                "columns": col_map,
                "provenance": {"path": source_path, "line": line_no + 1},
            }
        )

    if not rows:
        errors.append(ParseError(section=section_key, line=heading_idx + 1, message="no table rows parsed"))
    return rows, errors


def parse_gap_summary(lines: list[str], source_path: str) -> tuple[list[dict[str, Any]], list[ParseError]]:
    errors: list[ParseError] = []
    rows: list[dict[str, Any]] = []
    header_idx = next((i for i, line in enumerate(lines) if line.strip() == GAP_SUMMARY_HEADER), None)
    if header_idx is None:
        errors.append(ParseError(section="gap_summary", line=1, message=f"missing heading: {GAP_SUMMARY_HEADER}"))
        return rows, errors

    seen_keys: dict[str, int] = {}
    for line_no in range(header_idx + 1, len(lines)):
        line = lines[line_no].rstrip()
        stripped = line.strip()
        if stripped.startswith("## ") and stripped != GAP_SUMMARY_HEADER:
            break
        if not stripped:
            continue
        m = GAP_SUMMARY_RE.match(stripped)
        if not m:
            continue

        ordinal = int(m.group(1))
        body = m.group(2).strip()
        is_struck = "~~" in body
        normalized_body = re.sub(r"~~", "", body).strip()
        key = f"{ordinal}:{normalize_key(normalized_body)}"
        if key in seen_keys:
            errors.append(
                ParseError(
                    section="gap_summary",
                    line=line_no + 1,
                    message=f"duplicate gap summary key '{key}' (first seen at line {seen_keys[key]})",
                )
            )
        else:
            seen_keys[key] = line_no + 1

        rows.append(
            {
                "row_id": make_row_id("gap_summary", key),
                "section": "gap_summary",
                "primary_key": str(ordinal),
                "status": STATUS_DONE if is_struck else STATUS_IN_PROGRESS,
                "columns": {"ordinal": str(ordinal), "entry": normalized_body},
                "provenance": {"path": source_path, "line": line_no + 1},
            }
        )
    if not rows:
        errors.append(ParseError(section="gap_summary", line=header_idx + 1, message="no numbered entries parsed"))
    return rows, errors


def parse_feature_parity(path: Path) -> tuple[dict[str, list[dict[str, Any]]], list[ParseError]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    sections: dict[str, list[dict[str, Any]]] = {}
    errors: list[ParseError] = []
    source = path.as_posix()

    for section_key, spec in SECTION_HEADERS.items():
        heading, columns, key_col, status_col = spec
        parsed_rows, parse_errors = parse_section_rows(
            lines=lines,
            section_key=section_key,
            heading=heading,
            columns=columns,
            key_col=key_col,
            status_col=status_col,
            source_path=source,
        )
        sections[section_key] = parsed_rows
        errors.extend(parse_errors)

    gap_rows, gap_errors = parse_gap_summary(lines, source_path=source)
    sections["gap_summary"] = gap_rows
    errors.extend(gap_errors)
    return sections, errors


def detect_status_transitions(
    previous_rows: list[dict[str, Any]], current_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    previous_by_id = {row["row_id"]: row for row in previous_rows}
    transitions: list[dict[str, Any]] = []
    for row in current_rows:
        before = previous_by_id.get(row["row_id"])
        if not before:
            continue
        old = str(before.get("status", STATUS_UNKNOWN))
        new = str(row.get("status", STATUS_UNKNOWN))
        if old != new:
            transitions.append(
                {
                    "row_id": row["row_id"],
                    "section": row["section"],
                    "primary_key": row["primary_key"],
                    "from_status": old,
                    "to_status": new,
                }
            )
    return sorted(transitions, key=lambda r: r["row_id"])


def flatten_rows(sections: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for key in ["macro_targets", "runtime_math", "reverse_core", "proof_math", "gap_summary"]:
        merged.extend(sections.get(key, []))
    return merged


def machine_deltas(
    support_matrix: dict[str, Any],
    reality_report: dict[str, Any],
    replacement_levels: dict[str, Any],
) -> list[dict[str, Any]]:
    deltas: list[dict[str, Any]] = []

    summary = support_matrix.get("summary", {})
    support_total = int(support_matrix.get("total_exported", 0))
    support_counts = {
        "implemented": int(summary.get("Implemented", 0)),
        "raw_syscall": int(summary.get("RawSyscall", 0)),
        "glibc_call_through": int(summary.get("GlibcCallThrough", 0)),
        "stub": int(summary.get("Stub", 0)),
    }
    support_sum = sum(support_counts.values())
    support_ok = support_sum == support_total and len(support_matrix.get("symbols", [])) == support_total
    deltas.append(
        {
            "delta_id": "machine.support_classification_complete",
            "status": "ok" if support_ok else "drift",
            "expected": {"sum_counts_equals_total": True, "symbols_count_equals_total": True},
            "actual": {
                "sum_counts_equals_total": support_sum == support_total,
                "symbols_count_equals_total": len(support_matrix.get("symbols", [])) == support_total,
                "support_total_exported": support_total,
                "support_count_sum": support_sum,
            },
            "message": "support_matrix classification completeness",
            "provenance": [{"path": "support_matrix.json"}],
        }
    )

    reality_counts = reality_report.get("counts", {})
    reality_total = int(reality_report.get("total_exported", 0))
    reality_norm = {
        "implemented": int(reality_counts.get("implemented", 0)),
        "raw_syscall": int(reality_counts.get("raw_syscall", 0)),
        "glibc_call_through": int(reality_counts.get("glibc_call_through", 0)),
        "stub": int(reality_counts.get("stub", 0)),
    }
    support_vs_reality_ok = support_total == reality_total and support_counts == reality_norm
    deltas.append(
        {
            "delta_id": "machine.support_vs_reality",
            "status": "ok" if support_vs_reality_ok else "drift",
            "expected": {"support_counts": support_counts, "support_total": support_total},
            "actual": {"reality_counts": reality_norm, "reality_total": reality_total},
            "message": "support_matrix and reality_report should agree",
            "provenance": [
                {"path": "support_matrix.json"},
                {"path": "tests/conformance/reality_report.v1.json"},
            ],
        }
    )

    current_assessment = replacement_levels.get("current_assessment", {})
    replacement_norm = {
        "implemented": int(current_assessment.get("implemented", 0)),
        "raw_syscall": int(current_assessment.get("raw_syscall", 0)),
        "glibc_call_through": int(current_assessment.get("callthrough", 0)),
        "stub": int(current_assessment.get("stub", 0)),
    }
    replacement_total = int(current_assessment.get("total_symbols", 0))
    replacement_ok = replacement_norm == reality_norm and replacement_total == reality_total
    deltas.append(
        {
            "delta_id": "machine.replacement_vs_reality",
            "status": "ok" if replacement_ok else "drift",
            "expected": {"reality_counts": reality_norm, "reality_total": reality_total},
            "actual": {"replacement_counts": replacement_norm, "replacement_total": replacement_total},
            "message": "replacement_levels current_assessment should match reality_report",
            "provenance": [
                {"path": "tests/conformance/replacement_levels.json"},
                {"path": "tests/conformance/reality_report.v1.json"},
            ],
        }
    )

    return deltas


def macro_delta_rows(
    macro_rows: list[dict[str, Any]],
    support_matrix: dict[str, Any],
    reality_report: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    summary = support_matrix.get("summary", {})
    support_total = int(support_matrix.get("total_exported", 0))
    reality_counts = reality_report.get("counts", {})
    callthrough = int(reality_counts.get("glibc_call_through", 0))
    stubs = int(reality_counts.get("stub", 0))
    support_classification_done = (
        int(summary.get("Implemented", 0))
        + int(summary.get("RawSyscall", 0))
        + int(summary.get("GlibcCallThrough", 0))
        + int(summary.get("Stub", 0))
        == support_total
    )

    for row in macro_rows:
        area = row["columns"]["Area"].strip().lower()
        declared_status = row["status"]
        expected_status = STATUS_UNKNOWN
        rationale = "no direct machine signal mapped"

        if "exported symbol classification" in area:
            expected_status = STATUS_DONE if support_classification_done else STATUS_IN_PROGRESS
            rationale = "derived from support_matrix classification coverage"
        elif "replacement completeness" in area:
            expected_status = STATUS_DONE if callthrough == 0 and stubs == 0 else STATUS_IN_PROGRESS
            rationale = "derived from reality_report callthrough/stub counts"

        if expected_status == STATUS_UNKNOWN:
            continue

        aligned = expected_status == declared_status
        rows.append(
            {
                "delta_id": f"macro.{row['row_id']}",
                "status": "ok" if aligned else "drift",
                "expected": {"status": expected_status},
                "actual": {"status": declared_status},
                "message": rationale,
                "row_id": row["row_id"],
                "provenance": [row["provenance"]],
            }
        )

    return rows


def build_gap_ledger(
    *,
    feature_parity_path: Path,
    support_matrix_path: Path,
    reality_report_path: Path,
    replacement_levels_path: Path,
    previous_output: dict[str, Any] | None,
) -> dict[str, Any]:
    sections, parse_errors = parse_feature_parity(feature_parity_path)
    support = json.loads(support_matrix_path.read_text(encoding="utf-8"))
    reality = json.loads(reality_report_path.read_text(encoding="utf-8"))
    replacement = json.loads(replacement_levels_path.read_text(encoding="utf-8"))

    rows = flatten_rows(sections)
    base_deltas = machine_deltas(support, reality, replacement)
    macro_deltas = macro_delta_rows(sections["macro_targets"], support, reality)
    deltas = base_deltas + macro_deltas

    previous_rows = []
    if previous_output and isinstance(previous_output.get("rows"), list):
        previous_rows = previous_output["rows"]
    transitions = detect_status_transitions(previous_rows, rows)

    gaps: list[dict[str, Any]] = []
    for row in rows:
        if row["status"] != STATUS_DONE:
            gaps.append(
                {
                    "gap_id": row["row_id"],
                    "kind": "feature_parity_row_status",
                    "section": row["section"],
                    "status": row["status"],
                    "primary_key": row["primary_key"],
                    "provenance": row["provenance"],
                }
            )
    for delta in deltas:
        if delta["status"] != "ok":
            gaps.append(
                {
                    "gap_id": f"gap-{normalize_key(delta['delta_id'])}",
                    "kind": "machine_delta_drift",
                    "delta_id": delta["delta_id"],
                    "status": "drift",
                    "message": delta["message"],
                    "provenance": delta["provenance"],
                }
            )
    for err in parse_errors:
        gaps.append(
            {
                "gap_id": f"parse-{normalize_key(err.section)}-{err.line}",
                "kind": "parse_error",
                "section": err.section,
                "status": "ERROR",
                "message": err.message,
                "provenance": {"path": feature_parity_path.as_posix(), "line": err.line},
            }
        )

    status_counts: dict[str, int] = {}
    for row in rows:
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1

    generated_at = (
        str(reality.get("generated_at_utc", "")).strip()
        or str(support.get("generated_at_utc", "")).strip()
        or str(replacement.get("generated_at_utc", "")).strip()
        or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )

    return {
        "schema_version": "v1",
        "bead": "bd-w2c3.1.1",
        "generated_at": generated_at,
        "sources": {
            "feature_parity": feature_parity_path.as_posix(),
            "support_matrix": support_matrix_path.as_posix(),
            "reality_report": reality_report_path.as_posix(),
            "replacement_levels": replacement_levels_path.as_posix(),
        },
        "rows": rows,
        "deltas": deltas,
        "status_transitions": transitions,
        "gaps": gaps,
        "parse_errors": [
            {"section": e.section, "line": e.line, "message": e.message} for e in parse_errors
        ],
        "summary": {
            "row_count": len(rows),
            "gap_count": len(gaps),
            "delta_count": len(deltas),
            "drift_delta_count": sum(1 for d in deltas if d["status"] != "ok"),
            "parse_error_count": len(parse_errors),
            "status_counts": status_counts,
            "transition_count": len(transitions),
        },
    }


class ParserUnitTests(unittest.TestCase):
    def test_malformed_row_is_reported(self) -> None:
        lines = [
            "## Macro Coverage Targets",
            "",
            "| Area | Target | Status |",
            "|---|---|---|",
            "| only one |",
        ]
        rows, errors = parse_section_rows(
            lines=lines,
            section_key="macro_targets",
            heading="## Macro Coverage Targets",
            columns=["Area", "Target", "Status"],
            key_col=0,
            status_col=2,
            source_path="FEATURE_PARITY.md",
        )
        self.assertEqual(rows, [])
        self.assertTrue(any("malformed row" in e.message for e in errors))

    def test_duplicate_row_is_reported(self) -> None:
        lines = [
            "## Macro Coverage Targets",
            "| Area | Target | Status |",
            "|---|---|---|",
            "| Exported symbol classification | 100% | DONE |",
            "| Exported symbol classification | 100% | IN_PROGRESS |",
        ]
        rows, errors = parse_section_rows(
            lines=lines,
            section_key="macro_targets",
            heading="## Macro Coverage Targets",
            columns=["Area", "Target", "Status"],
            key_col=0,
            status_col=2,
            source_path="FEATURE_PARITY.md",
        )
        self.assertEqual(len(rows), 2)
        self.assertTrue(any("duplicate row key" in e.message for e in errors))

    def test_status_transition_detection(self) -> None:
        old = [
            {
                "row_id": "fp-macro-targets-aaaa",
                "section": "macro_targets",
                "primary_key": "Exported symbol classification",
                "status": STATUS_IN_PROGRESS,
            }
        ]
        new = [
            {
                "row_id": "fp-macro-targets-aaaa",
                "section": "macro_targets",
                "primary_key": "Exported symbol classification",
                "status": STATUS_DONE,
            }
        ]
        transitions = detect_status_transitions(old, new)
        self.assertEqual(len(transitions), 1)
        self.assertEqual(transitions[0]["from_status"], STATUS_IN_PROGRESS)
        self.assertEqual(transitions[0]["to_status"], STATUS_DONE)


def run_self_tests() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ParserUnitTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic FEATURE_PARITY gap ledger.")
    parser.add_argument(
        "--feature-parity",
        type=Path,
        default=Path("FEATURE_PARITY.md"),
        help="Path to FEATURE_PARITY markdown",
    )
    parser.add_argument(
        "--support-matrix",
        type=Path,
        default=Path("support_matrix.json"),
        help="Path to support_matrix artifact",
    )
    parser.add_argument(
        "--reality-report",
        type=Path,
        default=Path("tests/conformance/reality_report.v1.json"),
        help="Path to canonical reality report",
    )
    parser.add_argument(
        "--replacement-levels",
        type=Path,
        default=Path("tests/conformance/replacement_levels.json"),
        help="Path to replacement levels artifact",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tests/conformance/feature_parity_gap_ledger.v1.json"),
        help="Output JSON path",
    )
    parser.add_argument("--check", action="store_true", help="Fail if output differs from generated content")
    parser.add_argument("--stdout", action="store_true", help="Print generated output to stdout")
    parser.add_argument("--self-test", action="store_true", help="Run parser unit tests and exit")
    args = parser.parse_args()

    if args.self_test:
        return run_self_tests()

    previous_output: dict[str, Any] | None = None
    if args.output.exists():
        try:
            previous_output = json.loads(args.output.read_text(encoding="utf-8"))
        except Exception:
            previous_output = None

    ledger = build_gap_ledger(
        feature_parity_path=args.feature_parity,
        support_matrix_path=args.support_matrix,
        reality_report_path=args.reality_report,
        replacement_levels_path=args.replacement_levels,
        previous_output=previous_output,
    )
    rendered = canonical_json(ledger)

    if args.stdout:
        sys.stdout.write(rendered)

    if args.check:
        if not args.output.exists():
            print(f"FAIL: missing output file: {args.output}", file=sys.stderr)
            return 1
        current = args.output.read_text(encoding="utf-8")
        if current != rendered:
            print(
                "FAIL: feature parity gap ledger drift detected. "
                "Regenerate with scripts/generate_feature_parity_gap_ledger.py",
                file=sys.stderr,
            )
            return 1
        print(
            "PASS: feature parity gap ledger is up-to-date "
            f"(rows={ledger['summary']['row_count']}, gaps={ledger['summary']['gap_count']})"
        )
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(
        f"Wrote {args.output} "
        f"(rows={ledger['summary']['row_count']}, gaps={ledger['summary']['gap_count']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
