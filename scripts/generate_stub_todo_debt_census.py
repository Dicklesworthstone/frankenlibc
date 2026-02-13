#!/usr/bin/env python3
"""Generate unified exported stub/TODO debt census artifact (bd-1pbw).

This artifact reconciles:
1) Exported taxonomy truth from support_matrix.json.
2) Critical source-level TODO/unimplemented debt in ABI/core paths.
3) Deterministic risk-ranked debt priorities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

BEAD_ID = "bd-1pbw"
SCHEMA_VERSION = "v1"

TODO_RE = re.compile(r"\btodo!\s*\(")
UNIMPLEMENTED_RE = re.compile(r"\bunimplemented!\s*\(")
PENDING_PANIC_RE = re.compile(r"\bpanic!\s*\(")
FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MSG_RE = re.compile(r"(?:todo|unimplemented|panic)!\s*\(\s*\"([^\"]*)\"")

STATUS_ORDER = ["Implemented", "RawSyscall", "GlibcCallThrough", "Stub", "DefaultStub"]

FAMILY_WEIGHTS = {
    "threading": 42,
    "setjmp": 40,
    "terminal": 34,
    "resolver": 32,
    "iconv": 30,
    "locale": 28,
    "stdlib": 20,
}

STATUS_WEIGHTS = {
    "Stub": 38,
    "GlibcCallThrough": 32,
    "RawSyscall": 26,
    "Implemented": 20,
    None: 24,
}

MACRO_WEIGHTS = {
    "unimplemented!": 22,
    "todo!": 18,
    "panic_pending!": 14,
}

CRITICAL_FAMILY_BY_SYMBOL = {
    "setjmp": "setjmp",
    "longjmp": "setjmp",
    "tcgetattr": "terminal",
    "tcsetattr": "terminal",
    "getaddrinfo": "resolver",
    "freeaddrinfo": "resolver",
    "getnameinfo": "resolver",
    "gai_strerror": "resolver",
    "setlocale": "locale",
    "localeconv": "locale",
    "iconv_open": "iconv",
    "iconv": "iconv",
    "iconv_close": "iconv",
    "rand": "stdlib",
    "srand": "stdlib",
    "getenv": "stdlib",
    "setenv": "stdlib",
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def classify_family(symbol: str) -> str:
    if symbol in CRITICAL_FAMILY_BY_SYMBOL:
        return CRITICAL_FAMILY_BY_SYMBOL[symbol]
    if symbol.startswith("pthread_"):
        return "threading"
    if symbol.startswith("iconv"):
        return "iconv"
    if symbol.startswith("locale") or symbol.startswith("nl_langinfo"):
        return "locale"
    if symbol.startswith("tc"):
        return "terminal"
    return "other"


def parse_debt_macro(line: str) -> str | None:
    if TODO_RE.search(line):
        return "todo!"
    if UNIMPLEMENTED_RE.search(line):
        return "unimplemented!"
    if PENDING_PANIC_RE.search(line):
        lowered = line.lower()
        if "pending" in lowered or "todo" in lowered or "unimplemented" in lowered:
            return "panic_pending!"
    return None


def extract_message(line: str) -> str:
    match = MSG_RE.search(line)
    if not match:
        return ""
    return match.group(1).strip()


def scan_source_debt(
    workspace_root: Path,
    scan_roots: list[Path],
    support_symbols: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for scan_root in sorted(scan_roots, key=lambda p: p.as_posix()):
        for path in sorted(scan_root.rglob("*.rs")):
            path_str = path.as_posix()
            if "/tests/" in path_str:
                continue

            lines = path.read_text(encoding="utf-8").splitlines()
            # Keep scan focused on production code; test modules are usually at file tail.
            for idx, line in enumerate(lines):
                if line.strip().startswith("#[cfg(test)]"):
                    lines = lines[:idx]
                    break

            current_fn: str | None = None
            for line_no, line in enumerate(lines, start=1):
                fn_match = FN_RE.search(line)
                if fn_match:
                    current_fn = fn_match.group(1)

                macro = parse_debt_macro(line)
                if not macro or not current_fn:
                    continue

                family = classify_family(current_fn)
                if family == "other":
                    continue

                support = support_symbols.get(current_fn)
                support_status = support.get("status") if support else None
                in_support = support is not None
                support_module = support.get("module") if support else None
                perf_class = support.get("perf_class") if support else None

                family_weight = FAMILY_WEIGHTS.get(family, 20)
                macro_weight = MACRO_WEIGHTS.get(macro, 10)
                status_weight = STATUS_WEIGHTS.get(support_status, STATUS_WEIGHTS[None])
                visibility_weight = 20 if in_support else 28
                shadow_penalty = 10 if in_support and support_status in {"Implemented", "RawSyscall"} else 0
                occurrence_risk = (
                    family_weight
                    + macro_weight
                    + status_weight
                    + visibility_weight
                    + shadow_penalty
                )

                rows.append(
                    {
                        "symbol": current_fn,
                        "family": family,
                        "macro": macro,
                        "message": extract_message(line),
                        "path": path.relative_to(workspace_root).as_posix(),
                        "line": line_no,
                        "in_support_matrix": in_support,
                        "support_status": support_status,
                        "support_module": support_module,
                        "perf_class": perf_class,
                        "debt_scope": "exported_shadow_debt" if in_support else "critical_non_exported_debt",
                        "occurrence_risk_score": occurrence_risk,
                    }
                )

    rows.sort(
        key=lambda row: (
            row["debt_scope"],
            row["family"],
            row["symbol"],
            row["path"],
            row["line"],
            row["macro"],
        )
    )
    return rows


def risk_tier(score: int) -> str:
    if score >= 120:
        return "critical"
    if score >= 95:
        return "high"
    if score >= 70:
        return "medium"
    return "low"


def build_risk_ranking(source_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_symbol: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in source_rows:
        by_symbol[row["symbol"]].append(row)

    ranking: list[dict[str, Any]] = []
    for symbol, rows in by_symbol.items():
        representative = rows[0]
        support_status = representative.get("support_status")
        in_support = bool(representative.get("in_support_matrix"))
        family = str(representative["family"])
        scope = str(representative["debt_scope"])
        occurrences = len(rows)

        max_occurrence_risk = max(int(row["occurrence_risk_score"]) for row in rows)
        occurrence_bonus = min(occurrences * 4, 16)
        hidden_debt_bonus = 8 if not in_support else 0
        score = max_occurrence_risk + occurrence_bonus + hidden_debt_bonus

        rationale = [
            f"family={family}",
            f"scope={scope}",
            f"support_status={support_status if support_status is not None else 'non_exported'}",
            f"occurrences={occurrences}",
        ]
        if not in_support:
            rationale.append("hidden_from_exported_taxonomy=true")
        if support_status in {"Implemented", "RawSyscall"}:
            rationale.append("shadow_debt_against_reported_status=true")

        ranking.append(
            {
                "symbol": symbol,
                "family": family,
                "debt_scope": scope,
                "in_support_matrix": in_support,
                "support_status": support_status,
                "occurrences": occurrences,
                "risk_score": score,
                "risk_tier": risk_tier(score),
                "rationale": rationale,
                "locations": sorted(
                    {f"{row['path']}:{row['line']}" for row in rows}
                ),
            }
        )

    ranking.sort(
        key=lambda row: (
            -int(row["risk_score"]),
            str(row["family"]),
            str(row["symbol"]),
        )
    )
    for idx, row in enumerate(ranking, start=1):
        row["rank"] = idx
    return ranking


def build_exported_view(matrix: dict[str, Any]) -> dict[str, Any]:
    symbols = matrix.get("symbols", [])
    declared_summary = dict(matrix.get("summary", {}))

    derived_counter: Counter[str] = Counter()
    for row in symbols:
        derived_counter[str(row.get("status", ""))] += 1

    derived_summary = {status: int(derived_counter.get(status, 0)) for status in STATUS_ORDER}
    delta_rows = []
    for status in STATUS_ORDER:
        declared = int(declared_summary.get(status, 0))
        derived = int(derived_summary.get(status, 0))
        delta_rows.append(
            {
                "status": status,
                "declared": declared,
                "derived": derived,
                "delta_derived_minus_declared": derived - declared,
            }
        )

    stub_rows = [
        {
            "symbol": str(row.get("symbol", "")),
            "module": str(row.get("module", "")),
            "perf_class": str(row.get("perf_class", "")),
            "priority": int(row.get("priority", 0)),
        }
        for row in symbols
        if row.get("status") == "Stub"
    ]
    stub_rows.sort(key=lambda row: (row["module"], row["symbol"]))

    non_implemented_rows = [
        {
            "symbol": str(row.get("symbol", "")),
            "status": str(row.get("status", "")),
            "module": str(row.get("module", "")),
            "perf_class": str(row.get("perf_class", "")),
            "priority": int(row.get("priority", 0)),
        }
        for row in symbols
        if row.get("status") in {"Stub", "GlibcCallThrough"}
    ]
    non_implemented_rows.sort(
        key=lambda row: (row["status"], row["module"], row["symbol"])
    )

    return {
        "declared_summary": declared_summary,
        "derived_summary": derived_summary,
        "summary_delta": delta_rows,
        "total_exported_declared": int(matrix.get("total_exported", 0)),
        "total_exported_derived": len(symbols),
        "stub_symbols": stub_rows,
        "non_implemented_exported_symbols": non_implemented_rows,
    }


def build_payload(support_matrix_path: Path, scan_roots: list[Path]) -> dict[str, Any]:
    workspace_root = support_matrix_path.resolve().parent
    matrix = _load_json(support_matrix_path)
    support_symbols = {
        str(row.get("symbol", "")): row
        for row in matrix.get("symbols", [])
        if isinstance(row, dict) and row.get("symbol")
    }

    exported_view = build_exported_view(matrix)
    source_rows = scan_source_debt(workspace_root, scan_roots, support_symbols)
    risk_rows = build_risk_ranking(source_rows)

    unique_symbols = sorted({row["symbol"] for row in source_rows})
    by_scope = Counter(row["debt_scope"] for row in source_rows)
    by_family = Counter(row["family"] for row in source_rows)

    matrix_deltas = [
        row
        for row in exported_view["summary_delta"]
        if int(row["delta_derived_minus_declared"]) != 0
    ]

    critical_non_exported_symbols = sorted(
        {
            row["symbol"]
            for row in source_rows
            if not bool(row["in_support_matrix"])
        }
    )
    critical_exported_shadow_symbols = sorted(
        {
            row["symbol"]
            for row in source_rows
            if bool(row["in_support_matrix"])
        }
    )

    top_item = risk_rows[0] if risk_rows else None

    payload = {
        "schema_version": SCHEMA_VERSION,
        "bead": BEAD_ID,
        "description": (
            "Unified stub/TODO debt census combining exported taxonomy status with "
            "critical non-exported source debt and deterministic risk ranking."
        ),
        "source": {
            "support_matrix_path": support_matrix_path.relative_to(workspace_root).as_posix(),
            "support_matrix_sha256": _sha256(support_matrix_path),
            "scan_roots": [root.relative_to(workspace_root).as_posix() for root in scan_roots],
            "detection_macros": ["todo!", "unimplemented!", "panic!(pending-only)"],
        },
        "exported_taxonomy_view": exported_view,
        "critical_source_debt": {
            "occurrence_count": len(source_rows),
            "unique_symbol_count": len(unique_symbols),
            "by_scope": dict(sorted(by_scope.items())),
            "by_family": dict(sorted(by_family.items())),
            "entries": source_rows,
        },
        "risk_policy": {
            "family_weights": FAMILY_WEIGHTS,
            "status_weights": {
                status if status is not None else "non_exported": weight
                for status, weight in STATUS_WEIGHTS.items()
            },
            "macro_weights": MACRO_WEIGHTS,
            "score_formula": (
                "risk_score = max(occurrence_risk_score) + min(occurrences*4,16) + "
                "hidden_debt_bonus(non_exported=8)"
            ),
        },
        "risk_ranked_debt": risk_rows,
        "reconciliation": {
            "exported_stub_count": len(exported_view["stub_symbols"]),
            "exported_non_implemented_count": len(
                exported_view["non_implemented_exported_symbols"]
            ),
            "critical_non_exported_todo_count": len(critical_non_exported_symbols),
            "critical_exported_shadow_todo_count": len(critical_exported_shadow_symbols),
            "critical_non_exported_symbols": critical_non_exported_symbols,
            "critical_exported_shadow_symbols": critical_exported_shadow_symbols,
            "matrix_summary_deltas": matrix_deltas,
            "ambiguity_resolved": True,
            "notes": [
                "Exported status and source debt are reported in separate sections to avoid blind spots.",
                "Non-exported critical TODO debt is explicitly ranked so hidden backlog cannot be mistaken for zero debt.",
            ],
        },
        "summary": {
            "priority_item_count": len(risk_rows),
            "top_priority_symbol": top_item["symbol"] if top_item else None,
            "top_priority_risk_score": top_item["risk_score"] if top_item else 0,
            "critical_non_exported_share_pct": (
                round(
                    (len(critical_non_exported_symbols) / len(unique_symbols)) * 100.0,
                    2,
                )
                if unique_symbols
                else 0.0
            ),
            "nonzero_matrix_delta_count": len(matrix_deltas),
        },
    }
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--support-matrix",
        type=Path,
        default=Path("support_matrix.json"),
        help="Path to support_matrix.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tests/conformance/stub_todo_debt_census.v1.json"),
        help="Output artifact path",
    )
    parser.add_argument(
        "--scan-root",
        action="append",
        dest="scan_roots",
        default=[],
        help="Additional scan root(s). Defaults to core and abi source roots.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check mode: fail if output differs from generated payload",
    )
    args = parser.parse_args()

    support_matrix_path = args.support_matrix.resolve()
    workspace_root = support_matrix_path.parent

    if args.scan_roots:
        scan_roots = [(workspace_root / Path(root)).resolve() for root in args.scan_roots]
    else:
        scan_roots = [
            (workspace_root / "crates/frankenlibc-core/src").resolve(),
            (workspace_root / "crates/frankenlibc-abi/src").resolve(),
        ]

    for scan_root in scan_roots:
        if not scan_root.exists():
            print(f"FAIL: missing scan root {scan_root}")
            return 1

    payload = build_payload(support_matrix_path, scan_roots)

    if args.check:
        if not args.output.exists():
            print(f"FAIL: missing artifact {args.output}")
            return 1
        existing = _load_json(args.output)
        if _json_canonical(existing) != _json_canonical(payload):
            print(f"FAIL: {args.output} is stale. Regenerate with:")
            print(
                f"  {Path(__file__).as_posix()} "
                f"--support-matrix {args.support_matrix.as_posix()} "
                f"--output {args.output.as_posix()}"
            )
            return 1
        print(
            "PASS: unified stub/TODO debt census artifact is current "
            f"(priority_items={payload['summary']['priority_item_count']}, "
            f"non_exported={payload['reconciliation']['critical_non_exported_todo_count']})"
        )
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        f"Wrote {args.output} "
        f"(priority_items={payload['summary']['priority_item_count']}, "
        f"non_exported={payload['reconciliation']['critical_non_exported_todo_count']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
