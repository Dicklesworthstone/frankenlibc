#!/usr/bin/env bash
# check_ws3_taxonomy_honesty_e2e.sh -- E2E gate for bd-smp21.5.
#
# Replays the WS-3 source-derived host-delegation census, checks the README
# native-coverage badge against support_matrix.json, and verifies the L1
# replacement-level contract remains aligned with the support taxonomy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_WS3_TAXONOMY_HONESTY_REPORT:-${OUT_DIR}/ws3_taxonomy_honesty_e2e.report.json}"
LOG="${FRANKENLIBC_WS3_TAXONOMY_HONESTY_LOG:-${OUT_DIR}/ws3_taxonomy_honesty_e2e.log.jsonl}"
HOST_REPORT="${FRANKENLIBC_WS3_TAXONOMY_HONESTY_HOST_REPORT:-${OUT_DIR}/ws3_taxonomy_honesty.host_delegation_census.report.json}"
HOST_LOG="${FRANKENLIBC_WS3_TAXONOMY_HONESTY_HOST_LOG:-${OUT_DIR}/ws3_taxonomy_honesty.host_delegation_census.log.jsonl}"
GENERATED_CENSUS="${FRANKENLIBC_WS3_TAXONOMY_HONESTY_GENERATED_CENSUS:-${OUT_DIR}/ws3_taxonomy_honesty.host_delegation_census.generated.json}"
LEVELS_REPORT="${FRANKENLIBC_WS3_TAXONOMY_HONESTY_LEVELS_REPORT:-${OUT_DIR}/ws3_taxonomy_honesty.replacement_levels.report.json}"
LEVELS_LOG="${FRANKENLIBC_WS3_TAXONOMY_HONESTY_LEVELS_LOG:-${OUT_DIR}/ws3_taxonomy_honesty.replacement_levels.log.jsonl}"

mkdir -p \
  "$(dirname "${REPORT}")" \
  "$(dirname "${LOG}")" \
  "$(dirname "${HOST_REPORT}")" \
  "$(dirname "${HOST_LOG}")" \
  "$(dirname "${GENERATED_CENSUS}")" \
  "$(dirname "${LEVELS_REPORT}")" \
  "$(dirname "${LEVELS_LOG}")"

python3 "${ROOT}/scripts/generate_host_delegation_census.py" --output "${GENERATED_CENSUS}"

FLC_REPLACEMENT_LEVELS_REPORT_PATH="${LEVELS_REPORT}" \
FLC_REPLACEMENT_LEVELS_LOG_PATH="${LEVELS_LOG}" \
  bash "${ROOT}/scripts/check_replacement_levels.sh"

python3 - "${ROOT}" "${REPORT}" "${LOG}" "${HOST_REPORT}" "${HOST_LOG}" "${GENERATED_CENSUS}" "${LEVELS_REPORT}" "${LEVELS_LOG}" <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
REPORT = pathlib.Path(sys.argv[2])
LOG = pathlib.Path(sys.argv[3])
HOST_REPORT = pathlib.Path(sys.argv[4])
HOST_LOG = pathlib.Path(sys.argv[5])
GENERATED_CENSUS = pathlib.Path(sys.argv[6])
LEVELS_REPORT = pathlib.Path(sys.argv[7])
LEVELS_LOG = pathlib.Path(sys.argv[8])

BEAD = "bd-smp21.5"
SCHEMA = "ws3_taxonomy_honesty_e2e.report.v1"

SUPPORT_MATRIX = ROOT / "support_matrix.json"
HOST_CENSUS = ROOT / "tests/conformance/host_delegation_census.v1.json"
REPLACEMENT_LEVELS = ROOT / "tests/conformance/replacement_levels.json"
README = pathlib.Path(
    os.environ.get("FRANKENLIBC_WS3_TAXONOMY_HONESTY_README", str(ROOT / "README.md"))
)
CONTRACT = ROOT / "tests/conformance/ws3_taxonomy_honesty_e2e_completion_contract.v1.json"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def pct(part: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(part * 100.0 / total, 1)


def status_counts(matrix: dict[str, Any]) -> dict[str, int]:
    counts = {
        "Implemented": 0,
        "RawSyscall": 0,
        "WrapsHostLibc": 0,
        "GlibcCallThrough": 0,
        "Stub": 0,
    }
    for row in matrix.get("symbols", []):
        if not isinstance(row, dict):
            continue
        status = row.get("status")
        if status in counts:
            counts[status] += 1
    return counts


def parse_readme_badge(text: str) -> float | None:
    match = re.search(r"native_coverage-([0-9]+(?:\.[0-9]+)?)%25", text)
    if not match:
        return None
    return float(match.group(1))


def parse_readme_native_phrase(text: str) -> float | None:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)%\s+native coverage", text, re.I)
    if not match:
        return None
    return float(match.group(1))


def event(
    trace_id: str,
    source_commit: str,
    name: str,
    status: str,
    failure_signature: str,
    summary: dict[str, Any],
    artifact_refs: list[str],
) -> dict[str, Any]:
    return {
        "timestamp": now_utc(),
        "trace_id": trace_id,
        "event": name,
        "level": "info" if status == "pass" else "error",
        "bead_id": BEAD,
        "status": status,
        "source_commit": source_commit,
        "failure_signature": failure_signature,
        "summary": summary,
        "artifact_refs": artifact_refs,
    }


def main() -> int:
    timestamp = now_utc()
    trace_id = f"{BEAD}:taxonomy-honesty:{int(time.time())}:{os.getpid()}"
    source_commit = git_head()
    matrix = load_json(SUPPORT_MATRIX)
    census = load_json(GENERATED_CENSUS)
    levels = load_json(REPLACEMENT_LEVELS)
    levels_report = load_json(LEVELS_REPORT)
    readme = README.read_text(encoding="utf-8")

    counts = status_counts(matrix)
    total = len(matrix.get("symbols", []))
    implemented = counts["Implemented"]
    raw_syscall = counts["RawSyscall"]
    wraps_host = counts["WrapsHostLibc"]
    glibc_callthrough = counts["GlibcCallThrough"]
    stub = counts["Stub"]
    native = implemented + raw_syscall
    callthrough = wraps_host + glibc_callthrough
    native_pct = pct(native, total)
    callthrough_pct = pct(callthrough, total)

    symbol_status = {
        row.get("symbol"): row.get("status")
        for row in matrix.get("symbols", [])
        if isinstance(row, dict)
    }
    host_delegating_implemented = sorted(
        row.get("symbol")
        for row in census.get("symbol_census", [])
        if symbol_status.get(row.get("symbol")) == "Implemented"
    )

    badge_pct = parse_readme_badge(readme)
    phrase_pct = parse_readme_native_phrase(readme)
    stale_patterns = [
        r"native_coverage-100%25",
        r"100(?:\.0)?%\s+native",
        r"3,705\s+`Implemented`",
        r"4,119\s+symbols,\s+all\s+native",
    ]
    stale_matches = [
        pattern for pattern in stale_patterns if re.search(pattern, readme, re.I)
    ]

    assessment = levels.get("current_assessment", {})
    assessment_expectations = {
        "total_symbols": total,
        "implemented": implemented,
        "raw_syscall": raw_syscall,
        "native": native,
        "wraps_host_libc": wraps_host,
        "glibc_callthrough": glibc_callthrough,
        "callthrough": callthrough,
        "stub": stub,
    }
    assessment_mismatches = {
        key: {"expected": expected, "actual": assessment.get(key)}
        for key, expected in assessment_expectations.items()
        if assessment.get(key) != expected
    }

    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    def add_check(name: str, ok: bool, details: dict[str, Any]) -> None:
        checks.append({"name": name, "status": "pass" if ok else "fail", "details": details})
        if not ok:
            errors.append(name)

    census_summary = census.get("summary", {})
    census_anchors = census.get("required_anchor_symbols", [])
    census_anchor_present_count = len(
        [row for row in census_anchors if isinstance(row, dict) and row.get("present")]
    )
    census_shape_errors = []
    if census.get("schema_version") != "host_delegation_census.v1":
        census_shape_errors.append("schema_version_mismatch")
    if not isinstance(census.get("symbol_census"), list):
        census_shape_errors.append("symbol_census_not_array")
    if not isinstance(census.get("callsite_census"), list):
        census_shape_errors.append("callsite_census_not_array")
    if census_summary.get("required_anchor_present_count") != census_anchor_present_count:
        census_shape_errors.append("anchor_count_mismatch")

    add_check(
        "host_delegation_census_replayed",
        not census_shape_errors,
        {
            "host_report": rel(HOST_REPORT),
            "host_log": rel(HOST_LOG),
            "generated_census": rel(GENERATED_CENSUS),
            "summary": census_summary,
            "errors": census_shape_errors,
        },
    )
    add_check(
        "implemented_rows_have_no_host_delegation",
        not host_delegating_implemented,
        {
            "implemented_host_delegation_count": len(host_delegating_implemented),
            "examples": host_delegating_implemented[:20],
        },
    )
    add_check(
        "readme_native_coverage_badge_matches_support_matrix",
        badge_pct == native_pct,
        {"badge_pct": badge_pct, "expected_native_pct": native_pct},
    )
    add_check(
        "readme_native_coverage_phrase_matches_support_matrix",
        phrase_pct == native_pct,
        {"phrase_pct": phrase_pct, "expected_native_pct": native_pct},
    )
    add_check(
        "readme_contains_no_stale_100_percent_native_patterns",
        not stale_matches,
        {"stale_patterns": stale_matches},
    )
    add_check(
        "replacement_levels_gate_replayed",
        levels_report.get("status") == "pass",
        {
            "levels_report": rel(LEVELS_REPORT),
            "levels_log": rel(LEVELS_LOG),
            "current_level": levels.get("current_level"),
        },
    )
    add_check(
        "replacement_levels_assessment_matches_support_matrix",
        not assessment_mismatches,
        {"mismatches": assessment_mismatches},
    )
    add_check(
        "l1_remains_host_backed_interpose_not_standalone",
        levels.get("current_level") == "L1"
        and levels.get("release_tag_policy", {}).get("current_release_level") == "L1"
        and callthrough > 0
        and stub == 0,
        {
            "current_level": levels.get("current_level"),
            "current_release_level": levels.get("release_tag_policy", {}).get("current_release_level"),
            "host_backed_count": callthrough,
            "stub_count": stub,
        },
    )

    status = "fail" if errors else "pass"
    failure_signature = "none" if not errors else errors[0]
    summary = {
        "total_symbols": total,
        "implemented": implemented,
        "raw_syscall": raw_syscall,
        "native": native,
        "wraps_host_libc": wraps_host,
        "glibc_callthrough": glibc_callthrough,
        "callthrough": callthrough,
        "stub": stub,
        "native_pct": native_pct,
        "callthrough_pct": callthrough_pct,
        "readme_badge_pct": badge_pct,
        "readme_phrase_pct": phrase_pct,
        "host_delegating_symbol_count": census.get("summary", {}).get("host_delegating_symbol_count"),
        "implemented_host_delegation_count": len(host_delegating_implemented),
    }
    host_report_payload = {
        "schema_version": "ws3_taxonomy_honesty_host_delegation_census.report.v1",
        "bead": BEAD,
        "status": checks[0]["status"],
        "failure_signature": "none" if checks[0]["status"] == "pass" else "host_delegation_census_replayed",
        "summary": checks[0]["details"]["summary"],
        "errors": checks[0]["details"]["errors"],
        "artifact_refs": [rel(GENERATED_CENSUS), rel(HOST_REPORT), rel(HOST_LOG)],
    }
    HOST_REPORT.write_text(
        json.dumps(host_report_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    HOST_LOG.write_text(
        json.dumps(
            event(
                trace_id,
                source_commit,
                "host_delegation_census_generated",
                checks[0]["status"],
                host_report_payload["failure_signature"],
                host_report_payload["summary"],
                host_report_payload["artifact_refs"],
            ),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )

    artifact_refs = [
        rel(SUPPORT_MATRIX),
        rel(HOST_CENSUS),
        rel(GENERATED_CENSUS),
        rel(REPLACEMENT_LEVELS),
        rel(README),
        rel(REPORT),
        rel(LOG),
        rel(HOST_REPORT),
        rel(HOST_LOG),
        rel(LEVELS_REPORT),
        rel(LEVELS_LOG),
    ]
    if CONTRACT.exists():
        artifact_refs.append(rel(CONTRACT))

    events = [
        event(trace_id, source_commit, "host_delegation_census_replayed", checks[0]["status"], "none" if checks[0]["status"] == "pass" else checks[0]["name"], checks[0]["details"], artifact_refs),
        event(trace_id, source_commit, "implemented_host_delegation_checked", checks[1]["status"], "none" if checks[1]["status"] == "pass" else checks[1]["name"], checks[1]["details"], artifact_refs),
        event(trace_id, source_commit, "readme_native_badge_checked", checks[2]["status"], "none" if checks[2]["status"] == "pass" else checks[2]["name"], checks[2]["details"], artifact_refs),
        event(trace_id, source_commit, "replacement_levels_gate_replayed", checks[5]["status"], "none" if checks[5]["status"] == "pass" else checks[5]["name"], checks[5]["details"], artifact_refs),
        event(trace_id, source_commit, "ws3_taxonomy_honesty_e2e_validated" if status == "pass" else "ws3_taxonomy_honesty_e2e_failed", status, failure_signature, summary, artifact_refs),
    ]

    report = {
        "schema_version": SCHEMA,
        "bead": BEAD,
        "generated_at_utc": timestamp,
        "source_commit": source_commit,
        "trace_id": trace_id,
        "status": status,
        "failure_signature": failure_signature,
        "summary": summary,
        "checks": checks,
        "artifact_refs": artifact_refs,
        "required_events": [
            "host_delegation_census_replayed",
            "implemented_host_delegation_checked",
            "readme_native_badge_checked",
            "replacement_levels_gate_replayed",
            "ws3_taxonomy_honesty_e2e_validated",
            "ws3_taxonomy_honesty_e2e_failed",
        ],
        "required_log_fields": [
            "timestamp",
            "trace_id",
            "event",
            "level",
            "bead_id",
            "status",
            "source_commit",
            "failure_signature",
            "summary",
            "artifact_refs",
        ],
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in events),
        encoding="utf-8",
    )

    if errors:
        print(f"FAIL ws3 taxonomy honesty e2e: {failure_signature}")
        print(f"Report: {rel(REPORT)}")
        return 1
    print(
        "PASS ws3 taxonomy honesty e2e "
        f"native={native}/{total} ({native_pct}%) "
        f"host_backed={callthrough}/{total} ({callthrough_pct}%)"
    )
    print(f"Report: {rel(REPORT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
