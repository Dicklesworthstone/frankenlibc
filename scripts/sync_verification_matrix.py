#!/usr/bin/env python3
"""
Sync `tests/conformance/verification_matrix.json` with the current bead graph.

This is a maintenance helper intended to keep CI gates green when new critique
beads are added:
- Ensures every open/in_progress critique bead has a matrix entry.
- Auto-backfills missing entries with a deterministic, placeholder row contract.
- Recomputes dashboard statistics (including by_obligation_type).

Non-goals:
- Do NOT delete stale rows for closed beads; closure gating relies on historical
  matrix rows for closed critique beads.

Usage:
  python3 scripts/sync_verification_matrix.py --write
  python3 scripts/sync_verification_matrix.py --check
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
MATRIX_PATH = WORKSPACE_ROOT / "tests/conformance/verification_matrix.json"


def _repo_path_from_env(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    if not value:
        return default
    path = Path(value)
    return path if path.is_absolute() else WORKSPACE_ROOT / path


BEADS_PATH = _repo_path_from_env(
    "FRANKENLIBC_VERIFICATION_MATRIX_BEADS",
    WORKSPACE_ROOT / ".beads/issues.jsonl",
)

OBLIGATION_TYPES = [
    "unit_tests",
    "e2e_scripts",
    "structured_logs",
    "perf_evidence",
    "conformance_fixtures",
    "golden_artifacts",
]


def _now_utc_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def _contains_any(haystack: str, needles: Iterable[str]) -> bool:
    h = haystack.lower()
    return any(n.lower() in h for n in needles)


def _infer_stream(labels: List[str], title: str, description: str) -> str:
    # Keep this conservative; stream is mostly for dashboards and clustering.
    lset = {l.lower() for l in labels}
    blob = f"{title}\n{description}"

    if "math" in lset or _contains_any(blob, ["runtime-math", "math governance", "monitor"]):
        return "math"
    if "perf" in lset or _contains_any(blob, ["perf", "benchmark", "latency", "profil"]):
        return "perf"
    if "stubs" in lset or "stub" in lset or _contains_any(blob, ["stub", "retire stubs"]):
        return "stubs"
    if "docs" in lset or "spec" in lset or _contains_any(blob, ["spec", "contract", "docs"]):
        return "docs"
    if "e2e" in lset or _contains_any(blob, ["e2e", "end-to-end", "ld_preload"]):
        return "e2e"
    return "syscall"


@dataclass(frozen=True)
class RequirementFlags:
    unit_tests: bool
    e2e_scripts: bool
    structured_logs: bool
    perf_evidence: bool
    conformance_fixtures: bool
    golden_artifacts: bool


def _infer_requirements(labels: List[str], title: str, description: str) -> RequirementFlags:
    # Baseline: for critique work we default to unit tests + structured logs + golden artifacts.
    # Heuristics for additional obligations are intentionally simple and can be refined per-bead.
    lset = {l.lower() for l in labels}
    blob = f"{title}\n{description}"

    e2e = "e2e" in lset or _contains_any(blob, ["e2e", "end-to-end", "ld_preload"])
    perf = "perf" in lset or _contains_any(blob, ["perf", "benchmark", "latency", "overhead"])
    fixtures = (
        "conformance" in lset
        or "posix" in lset
        or _contains_any(blob, ["fixture", "fixtures", "conformance"])
    )

    return RequirementFlags(
        unit_tests=True,
        e2e_scripts=e2e,
        structured_logs=True,
        perf_evidence=perf,
        conformance_fixtures=fixtures,
        golden_artifacts=True,
    )


def _make_obligations(req: RequirementFlags) -> Dict[str, Dict[str, Any]]:
    def ob(required: bool, scope: str) -> Dict[str, Any]:
        return {"required": required, "scope": scope}

    return {
        "unit_tests": ob(True, "happy-path, negative, adversarial, regression"),
        "e2e_scripts": ob(req.e2e_scripts, "deterministic strict/hardened scenarios" if req.e2e_scripts else ""),
        "structured_logs": ob(True, "JSONL with trace_id, mode, symbol, outcome, errno, timing"),
        "perf_evidence": ob(req.perf_evidence, "overhead targets (strict<20ns, hardened<200ns)" if req.perf_evidence else ""),
        "conformance_fixtures": ob(req.conformance_fixtures, "fixture packs with spec traceability" if req.conformance_fixtures else ""),
        "golden_artifacts": ob(True, "SHA256-verified golden output files"),
    }


def _make_coverage(req: RequirementFlags) -> Dict[str, Dict[str, Any]]:
    def cov_required() -> Dict[str, Any]:
        return {"status": "missing", "artifacts": ""}

    def cov_not_required() -> Dict[str, Any]:
        return {"status": "not_required"}

    return {
        "unit_tests": cov_required(),
        "e2e_scripts": cov_required() if req.e2e_scripts else cov_not_required(),
        "structured_logs": cov_required(),
        "perf_evidence": cov_required() if req.perf_evidence else cov_not_required(),
        "conformance_fixtures": cov_required() if req.conformance_fixtures else cov_not_required(),
        "golden_artifacts": cov_required(),
    }


def _summarize_coverage(coverage: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    counts = {"complete": 0, "partial": 0, "missing": 0}
    required = 0
    for v in coverage.values():
        st = str(v.get("status", "missing"))
        if st == "not_required":
            continue
        required += 1
        if st in counts:
            counts[st] += 1
        else:
            counts["missing"] += 1

    if required == 0:
        overall = "complete"
    elif counts["missing"] == required:
        overall = "missing"
    elif counts["missing"] == 0 and counts["partial"] == 0:
        overall = "complete"
    else:
        overall = "partial"

    return {
        "overall": overall,
        "required": required,
        "complete": counts["complete"],
        "partial": counts["partial"],
        "missing": counts["missing"],
    }


def _close_blockers_for(req: RequirementFlags) -> List[str]:
    blockers = ["missing_unit", "missing_logs", "missing_golden_artifacts"]
    if req.e2e_scripts:
        blockers.append("missing_e2e")
    if req.perf_evidence:
        blockers.append("missing_perf_proof")
    if req.conformance_fixtures:
        blockers.append("missing_fixtures")
    return blockers


def _make_backfill_row(bead_id: str, stream: str, req: RequirementFlags) -> Dict[str, Any]:
    # Keep these rows non-empty to satisfy the v1 row contract; they are placeholders
    # that should be refined as evidence lands.
    unit_cmds = [
        "cargo test -p frankenlibc-harness --tests -- --nocapture",
    ]
    e2e_cmds: List[str] = []
    perf_refs: List[str] = []
    if req.e2e_scripts:
        e2e_cmds = ["scripts/check_e2e_suite.sh"]
    if req.perf_evidence:
        perf_refs = ["scripts/perf_gate.sh"]

    return {
        "bead_id": bead_id,
        "stream": stream,
        "status": "missing",
        "unit_cmds": unit_cmds,
        "e2e_cmds": e2e_cmds,
        "expected_assertions": [
            "matrix row exists and will be refined with bead-specific evidence before closure"
        ],
        "log_schema_refs": ["tests/conformance/log_schema.json"],
        "artifact_paths": [
            f"tests/cve_arena/results/{bead_id}/trace.jsonl",
            f"tests/cve_arena/results/{bead_id}/artifact_index.json",
        ],
        "perf_proof_refs": perf_refs,
        "close_blockers": _close_blockers_for(req),
        "notes": f"Auto-backfilled row for {bead_id}; refine commands/artifacts as implementation evidence lands.",
    }


def _make_missing_entry(bead: Dict[str, Any]) -> Dict[str, Any]:
    bead_id = str(bead.get("id", ""))
    title = str(bead.get("title", ""))
    description = str(bead.get("description", ""))
    priority = int(bead.get("priority", 99))
    status = str(bead.get("status", "open"))
    assignee = bead.get("assignee", None)
    labels = bead.get("labels", [])
    if not isinstance(labels, list):
        labels = []

    req = _infer_requirements([str(l) for l in labels], title, description)
    obligations = _make_obligations(req)
    coverage = _make_coverage(req)
    coverage_summary = _summarize_coverage(coverage)
    stream = _infer_stream([str(l) for l in labels], title, description)

    return {
        "bead_id": bead_id,
        "title": title,
        "priority": priority,
        "status": status,
        "assignee": assignee,
        "labels": [str(l) for l in labels],
        "dependencies": [],
        "obligations": obligations,
        "coverage": coverage,
        "coverage_summary": coverage_summary,
        "row": _make_backfill_row(bead_id, stream, req),
    }


def _recompute_dashboard(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_cov: Dict[str, int] = {"complete": 0, "partial": 0, "missing": 0}
    by_priority: Dict[str, Dict[str, int]] = {}
    by_stream: Dict[str, Dict[str, int]] = {}
    by_obligation: Dict[str, Dict[str, int]] = {}

    # Initialize obligation stats
    for ot in OBLIGATION_TYPES:
        by_obligation[ot] = {"required": 0, "complete": 0, "partial": 0, "missing": 0}

    def bump_bucket(bucket: Dict[str, Dict[str, int]], key: str, overall: str) -> None:
        row = bucket.setdefault(key, {"total": 0, "complete": 0, "partial": 0, "missing": 0})
        row["total"] += 1
        if overall in ("complete", "partial", "missing"):
            row[overall] += 1

    for e in entries:
        overall = str(e.get("coverage_summary", {}).get("overall", "missing"))
        if overall not in by_cov:
            overall = "missing"
        by_cov[overall] += 1

        prio = f"P{int(e.get('priority', 99))}"
        bump_bucket(by_priority, prio, overall)

        stream = str(e.get("row", {}).get("stream", "syscall"))
        bump_bucket(by_stream, stream, overall)

        cov = e.get("coverage", {})
        if isinstance(cov, dict):
            for ot in OBLIGATION_TYPES:
                st = str(cov.get(ot, {}).get("status", "missing"))
                if st == "not_required":
                    continue
                by_obligation[ot]["required"] += 1
                if st in ("complete", "partial", "missing"):
                    by_obligation[ot][st] += 1
                else:
                    by_obligation[ot]["missing"] += 1

    # Ensure stable ordering by priority key
    def prio_key(k: str) -> Tuple[int, str]:
        m = re.match(r"^P(\\d+)$", k)
        return (int(m.group(1)) if m else 99, k)

    by_priority = {k: by_priority[k] for k in sorted(by_priority.keys(), key=prio_key)}
    by_stream = {k: by_stream[k] for k in sorted(by_stream.keys())}
    by_obligation = {k: by_obligation[k] for k in OBLIGATION_TYPES}

    return {
        "total_critique_beads": len(entries),
        "total_entries": len(entries),
        "by_coverage_status": by_cov,
        "by_priority": by_priority,
        "by_obligation_type": by_obligation,
        "by_stream": by_stream,
    }


def _sync_matrix(matrix: Dict[str, Any], beads: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    entries: List[Dict[str, Any]] = matrix.get("entries", [])
    if not isinstance(entries, list):
        raise SystemExit("verification_matrix.json: entries must be an array")

    entry_by_id: Dict[str, Dict[str, Any]] = {}
    for e in entries:
        bid = str(e.get("bead_id", ""))
        if not bid:
            continue
        entry_by_id[bid] = e

    critique_open: Dict[str, Dict[str, Any]] = {}
    for b in beads:
        labels = b.get("labels", [])
        status = str(b.get("status", ""))
        if not isinstance(labels, list):
            continue
        if "critique" in labels and status in ("open", "in_progress"):
            critique_open[str(b["id"])] = b

    added: List[str] = []
    updated_meta: List[str] = []

    for bid, bead in sorted(critique_open.items()):
        if bid not in entry_by_id:
            entry_by_id[bid] = _make_missing_entry(bead)
            added.append(bid)
            continue

        # Keep the detailed evidence fields, but refresh metadata for drift-resilience.
        e = entry_by_id[bid]
        before = (e.get("title"), e.get("priority"), e.get("status"), e.get("assignee"), e.get("labels"))
        e["title"] = bead.get("title", e.get("title"))
        e["priority"] = bead.get("priority", e.get("priority"))
        e["status"] = bead.get("status", e.get("status"))
        e["assignee"] = bead.get("assignee", e.get("assignee"))
        e["labels"] = bead.get("labels", e.get("labels", []))
        after = (e.get("title"), e.get("priority"), e.get("status"), e.get("assignee"), e.get("labels"))
        if before != after:
            updated_meta.append(bid)

    out_entries = [entry_by_id[bid] for bid in sorted(entry_by_id.keys())]
    matrix["generated_utc"] = _now_utc_z()
    matrix["entries"] = out_entries
    matrix["dashboard"] = _recompute_dashboard(out_entries)

    report = {
        "critique_open_count": len(critique_open),
        "existing_entries": len(entries),
        "final_entries": len(out_entries),
        "added": added,
        "updated_meta": updated_meta,
    }
    return matrix, report


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync verification_matrix.json with .beads/issues.jsonl")
    parser.add_argument("--write", action="store_true", help="Write changes to verification_matrix.json")
    parser.add_argument("--check", action="store_true", help="Fail if changes would be made")
    args = parser.parse_args()

    if not MATRIX_PATH.is_file():
        raise SystemExit(f"missing matrix file: {MATRIX_PATH}")
    if not BEADS_PATH.is_file():
        raise SystemExit(f"missing beads file: {BEADS_PATH}")

    matrix = _load_json(MATRIX_PATH)
    beads = _load_jsonl(BEADS_PATH)

    updated, report = _sync_matrix(matrix, beads)

    if args.check:
        # Compare normalized JSON (exclude generated_utc which is expected to change).
        original = _load_json(MATRIX_PATH)
        updated_cmp = json.loads(json.dumps(updated))
        original_cmp = json.loads(json.dumps(original))
        updated_cmp["generated_utc"] = "CHECK"
        original_cmp["generated_utc"] = "CHECK"
        if updated_cmp != original_cmp:
            print(json.dumps(report, indent=2))
            raise SystemExit("verification_matrix.json is out of sync (run with --write)")
        return 0

    if not args.write:
        print(json.dumps(report, indent=2))
        return 0

    MATRIX_PATH.write_text(
        json.dumps(updated, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
