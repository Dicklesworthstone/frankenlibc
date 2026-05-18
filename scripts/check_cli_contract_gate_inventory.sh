#!/usr/bin/env bash
# Emit a no-cargo inventory of tracked CLI contract gates and missing invariant candidates.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_CLI_CONTRACT_GATE_INVENTORY:-${ROOT}/tests/conformance/cli_contract_gate_inventory.v1.json}"
OUT_DIR="${FRANKENLIBC_CLI_CONTRACT_GATE_INVENTORY_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_CLI_CONTRACT_GATE_INVENTORY_REPORT:-${OUT_DIR}/cli_contract_gate_inventory.report.json}"
LOG="${FRANKENLIBC_CLI_CONTRACT_GATE_INVENTORY_LOG:-${OUT_DIR}/cli_contract_gate_inventory.log.jsonl}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
from copy import deepcopy
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
LOG = pathlib.Path(sys.argv[4])

EXPECTED_SCHEMA = "cli_contract_gate_inventory.v1"
REPORT_SCHEMA = "cli_contract_gate_inventory.report.v1"


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def git_lines(*args: str) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        return []
    return [line for line in proc.stdout.splitlines() if line.strip()]


def current_commit() -> str:
    lines = git_lines("rev-parse", "HEAD")
    return lines[0] if lines else "unknown"


def string_list(value: Any, context: str, errors: list[dict[str, str]], *, min_len: int = 1) -> list[str]:
    if not isinstance(value, list) or len(value) < min_len:
        errors.append({"failure_signature": context, "message": f"{context} must be a list with at least {min_len} entries"})
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item:
            result.append(item)
        else:
            errors.append({"failure_signature": context, "message": f"{context} contains a non-string item"})
    return result


def candidate_rows(contract: dict[str, Any], errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    candidates = contract.get("candidate_invariants")
    if not isinstance(candidates, list) or not candidates:
        errors.append({"failure_signature": "missing_candidate_invariants", "message": "candidate_invariants must be non-empty"})
        return []
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        source = f"candidate_invariants[{index}]"
        if not isinstance(candidate, dict):
            errors.append({"failure_signature": "malformed_candidate", "message": f"{source} must be an object"})
            continue
        candidate_id = candidate.get("id")
        if not isinstance(candidate_id, str) or not candidate_id:
            errors.append({"failure_signature": "missing_candidate_id", "message": f"{source}.id missing"})
            continue
        if candidate_id in seen:
            errors.append({"failure_signature": "duplicate_candidate_id", "message": f"duplicate candidate {candidate_id}"})
        seen.add(candidate_id)
        if not isinstance(candidate.get("priority"), int) or candidate["priority"] < 0:
            errors.append({"failure_signature": "invalid_candidate_priority", "message": f"{candidate_id} priority must be non-negative integer"})
        for key in ("filename_markers", "dirty_path_markers"):
            string_list(candidate.get(key), f"{candidate_id}.{key}", errors)
        if not isinstance(candidate.get("recommendation_title"), str) or not candidate["recommendation_title"]:
            errors.append({"failure_signature": "missing_recommendation_title", "message": f"{candidate_id} title missing"})
        rows.append(candidate)
    return rows


def tracked_cli_contract_tests() -> list[str]:
    return sorted(
        set(
            git_lines("ls-files", "crates/frankenlibc-harness/tests/*cli_contract*test.rs")
            + git_lines("ls-files", "crates/frankenlibc-harness/tests/*cli_contract*.rs")
        )
    )


def dirty_paths() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in git_lines("status", "--porcelain=v1"):
        if len(line) < 4:
            continue
        status = line[:2].strip() or line[:2]
        path = line[3:]
        if "cli_contract" in path:
            rows.append({"status_code": status, "path": path})
    return rows


def matches_any(path: str, markers: list[str]) -> bool:
    path_lower = path.lower()
    return any(marker.lower() in path_lower for marker in markers)


def analyze_candidates(
    candidates: list[dict[str, Any]],
    tracked_paths: list[str],
    dirty: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]]]:
    rows: list[dict[str, Any]] = []
    recommendations: list[dict[str, Any]] = []
    pending_dirty: list[dict[str, str]] = []
    for candidate in candidates:
        filename_markers = [str(item) for item in candidate.get("filename_markers", [])]
        dirty_markers = [str(item) for item in candidate.get("dirty_path_markers", [])]
        tracked_matches = [path for path in tracked_paths if matches_any(path, filename_markers)]
        dirty_matches = [row for row in dirty if matches_any(row["path"], dirty_markers)]
        if tracked_matches:
            status = "implemented_tracked"
        elif dirty_matches:
            status = "pending_dirty_unvalidated"
            for match in dirty_matches:
                pending_dirty.append(
                    {
                        "candidate_id": str(candidate["id"]),
                        "path": match["path"],
                        "status_code": match["status_code"],
                    }
                )
        else:
            status = "missing_recommended"
        row = {
            "id": candidate["id"],
            "priority": candidate["priority"],
            "status": status,
            "tracked_match_count": len(tracked_matches),
            "tracked_matches": tracked_matches[:8],
            "dirty_match_count": len(dirty_matches),
            "dirty_matches": dirty_matches,
            "recommendation_title": candidate["recommendation_title"],
            "rationale": candidate.get("rationale"),
        }
        rows.append(row)
        if status == "missing_recommended":
            recommendations.append(
                {
                    "candidate_id": candidate["id"],
                    "priority": candidate["priority"],
                    "title": candidate["recommendation_title"],
                    "rationale": candidate.get("rationale"),
                }
            )
    recommendations.sort(key=lambda row: (int(row["priority"]), str(row["candidate_id"])))
    pending_dirty.sort(key=lambda row: (row["candidate_id"], row["path"]))
    return rows, recommendations, pending_dirty


def validate_contract(contract: dict[str, Any]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    if contract.get("schema_version") != EXPECTED_SCHEMA:
        errors.append({"failure_signature": "schema_version", "message": "schema_version mismatch"})
    scanner = contract.get("scanner")
    if not isinstance(scanner, dict):
        errors.append({"failure_signature": "missing_scanner", "message": "scanner must be an object"})
        scanner = {}
    if scanner.get("tracked_glob") != "crates/frankenlibc-harness/tests/*cli_contract*test.rs":
        errors.append({"failure_signature": "tracked_glob_mismatch", "message": "tracked_glob mismatch"})
    if scanner.get("output_path") != "target/conformance/cli_contract_gate_inventory.report.json":
        errors.append({"failure_signature": "output_path_mismatch", "message": "output_path mismatch"})
    if scanner.get("log_path") != "target/conformance/cli_contract_gate_inventory.log.jsonl":
        errors.append({"failure_signature": "log_path_mismatch", "message": "log_path mismatch"})
    if not isinstance(scanner.get("minimum_tracked_gate_count"), int) or scanner["minimum_tracked_gate_count"] < 1:
        errors.append({"failure_signature": "invalid_minimum_tracked_gate_count", "message": "minimum tracked gate count must be positive"})
    required_fields = set(string_list(contract.get("required_report_fields"), "required_report_fields", errors))
    for field in {
        "schema_version",
        "status",
        "source_commit",
        "report_path",
        "log_path",
        "tracked_gate_count",
        "dirty_pending_candidates",
        "candidate_invariants",
        "recommendations",
        "negative_controls",
        "failures",
    }:
        if field not in required_fields:
            errors.append({"failure_signature": "required_report_field_missing", "message": f"missing required report field {field}"})
    candidate_rows(contract, errors)
    required_controls = string_list(contract.get("required_negative_controls"), "required_negative_controls", errors)
    for control in {
        "tracked_gate_count_threshold_fails",
        "dirty_candidate_not_recommended",
        "duplicate_candidate_id_fails",
        "missing_report_field_fails",
    }:
        if control not in required_controls:
            errors.append({"failure_signature": "required_negative_control_missing", "message": f"missing negative control {control}"})
    return errors


def build_report(contract: dict[str, Any]) -> dict[str, Any]:
    errors = validate_contract(contract)
    candidates = candidate_rows(contract, errors)
    tracked_paths = tracked_cli_contract_tests()
    dirty = dirty_paths()
    candidate_statuses, recommendations, pending_dirty = analyze_candidates(candidates, tracked_paths, dirty)
    scanner = contract.get("scanner", {}) if isinstance(contract.get("scanner"), dict) else {}
    minimum = scanner.get("minimum_tracked_gate_count", 0)
    if isinstance(minimum, int) and len(tracked_paths) < minimum:
        errors.append(
            {
                "failure_signature": "tracked_gate_count_below_minimum",
                "message": f"tracked gate count {len(tracked_paths)} < {minimum}",
            }
        )
    report = {
        "schema_version": REPORT_SCHEMA,
        "status": "fail" if errors else "pass",
        "generated_at_utc": utc_now(),
        "source_commit": current_commit(),
        "report_path": rel(REPORT),
        "log_path": rel(LOG),
        "tracked_gate_count": len(tracked_paths),
        "tracked_gate_sample": tracked_paths[:12],
        "dirty_cli_contract_paths": dirty,
        "dirty_pending_candidates": pending_dirty,
        "candidate_invariants": candidate_statuses,
        "recommendations": recommendations,
        "negative_controls": [],
        "failures": errors,
    }
    for field in contract.get("required_report_fields", []):
        if field not in report:
            errors.append({"failure_signature": "missing_report_field", "message": f"report omitted {field}"})
    report["status"] = "fail" if errors else "pass"
    report["failures"] = errors
    return report


def run_negative_controls(contract: dict[str, Any], report: dict[str, Any]) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []

    high_threshold = deepcopy(contract)
    high_threshold.setdefault("scanner", {})["minimum_tracked_gate_count"] = 999999
    high_report = build_report(high_threshold)
    high_sigs = [err["failure_signature"] for err in high_report["failures"]]
    controls.append(
        {
            "control_id": "tracked_gate_count_threshold_fails",
            "expected_signature": "tracked_gate_count_below_minimum",
            "observed_signatures": high_sigs,
            "status": "pass" if "tracked_gate_count_below_minimum" in high_sigs else "fail",
        }
    )

    synthetic_candidate = {
        "id": "synthetic_dirty_candidate",
        "priority": 0,
        "filename_markers": ["synthetic_dirty_candidate"],
        "dirty_path_markers": ["synthetic_dirty_candidate"],
        "recommendation_title": "synthetic dirty candidate",
        "rationale": "negative control",
    }
    rows, recommendations, pending = analyze_candidates(
        [synthetic_candidate],
        [],
        [{"status_code": "??", "path": "crates/frankenlibc-harness/tests/synthetic_dirty_candidate_test.rs"}],
    )
    dirty_ok = (
        rows
        and rows[0]["status"] == "pending_dirty_unvalidated"
        and not recommendations
        and pending
    )
    controls.append(
        {
            "control_id": "dirty_candidate_not_recommended",
            "expected_signature": "pending_dirty_unvalidated",
            "observed_signatures": [rows[0]["status"] if rows else "missing_row"],
            "status": "pass" if dirty_ok else "fail",
        }
    )

    duplicate = deepcopy(contract)
    if isinstance(duplicate.get("candidate_invariants"), list) and duplicate["candidate_invariants"]:
        duplicate["candidate_invariants"].append(deepcopy(duplicate["candidate_invariants"][0]))
    duplicate_errors = validate_contract(duplicate)
    duplicate_sigs = [err["failure_signature"] for err in duplicate_errors]
    controls.append(
        {
            "control_id": "duplicate_candidate_id_fails",
            "expected_signature": "duplicate_candidate_id",
            "observed_signatures": duplicate_sigs,
            "status": "pass" if "duplicate_candidate_id" in duplicate_sigs else "fail",
        }
    )

    stripped_report = dict(report)
    stripped_report.pop("report_path", None)
    missing = "missing_report_field" if "report_path" not in stripped_report else "unexpected_report_path"
    controls.append(
        {
            "control_id": "missing_report_field_fails",
            "expected_signature": "missing_report_field",
            "observed_signatures": [missing],
            "status": "pass" if missing == "missing_report_field" else "fail",
        }
    )

    return controls


contract = load_json(CONTRACT)
report = build_report(contract)
negative_controls = run_negative_controls(contract, report)
for control in negative_controls:
    if control["status"] != "pass":
        report["failures"].append(
            {
                "failure_signature": "negative_control_failed",
                "message": f"{control['control_id']} failed",
            }
        )
report["negative_controls"] = negative_controls
report["status"] = "fail" if report["failures"] else "pass"

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
events = [
    {
        "event": "cli_contract_gate_inventory",
        "status": report["status"],
        "tracked_gate_count": report["tracked_gate_count"],
        "recommendation_count": len(report["recommendations"]),
        "dirty_pending_count": len(report["dirty_pending_candidates"]),
        "source_commit": report["source_commit"],
    }
]
events.extend({"event": "negative_control", **control} for control in negative_controls)
LOG.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n", encoding="utf-8")

print(
    json.dumps(
        {
            "status": report["status"],
            "tracked_gate_count": report["tracked_gate_count"],
            "dirty_pending_count": len(report["dirty_pending_candidates"]),
            "recommendation_count": len(report["recommendations"]),
            "report": report["report_path"],
        },
        sort_keys=True,
    )
)
if report["failures"]:
    raise SystemExit(1)
PY
