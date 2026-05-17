#!/usr/bin/env bash
# check_abi_loader_reentrancy_lock_census.sh -- fail-closed gate for bd-esbow
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_ABI_REENTRANCY_LOCK_CENSUS_CONTRACT:-${ROOT}/tests/conformance/abi_loader_reentrancy_lock_census.v1.json}"
OUT_DIR="${FRANKENLIBC_ABI_REENTRANCY_LOCK_CENSUS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_ABI_REENTRANCY_LOCK_CENSUS_REPORT:-${OUT_DIR}/abi_loader_reentrancy_lock_census.report.json}"
LOG="${FRANKENLIBC_ABI_REENTRANCY_LOCK_CENSUS_LOG:-${OUT_DIR}/abi_loader_reentrancy_lock_census.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

MANIFEST_ID = "abi-loader-reentrancy-lock-census"
BEAD_ID = "bd-esbow"
REQUIRED_EVENTS = {
    "abi_reentrancy_census_source_commit",
    "abi_reentrancy_census_scan",
    "abi_reentrancy_census_classification",
    "abi_reentrancy_census_summary",
}
PATTERNS = {
    "lazy_lock_static": re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?static\s+[A-Z0-9_]+\s*:[^\n;]*\bLazyLock\b", re.MULTILINE),
    "once_lock_static": re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?static\s+[A-Z0-9_]+\s*:[^\n;]*\bOnceLock\b", re.MULTILINE),
    "thread_local_macro": re.compile(r"\b(?:std::)?thread_local!\s*\{"),
    "static_mutex": re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?static\s+[A-Z0-9_]+\s*:[^\n;]*(?:std::sync::)?Mutex\b", re.MULTILINE),
    "static_condvar": re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?static\s+[A-Z0-9_]+\s*:[^\n;]*(?:std::sync::)?Condvar\b", re.MULTILINE),
    "std_env_var": re.compile(r"\bstd::env::var(?:_os)?\s*\("),
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def event(event_name: str, status: str, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "bead": BEAD_ID,
        "event": event_name,
        "status": status,
        "timestamp": utc_now(),
        "trace_id": f"{BEAD_ID}::{event_name}",
    }
    row.update(extra)
    return row


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def load_contract(errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(contract_path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(errors, f"contract unreadable: {rel(contract_path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        fail(errors, "contract must be a JSON object")
        return {}
    return value


def git_output(args: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def validate_contract_shape(contract: dict[str, Any], errors: list[str]) -> None:
    if contract.get("manifest_id") != MANIFEST_ID:
        fail(errors, f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        fail(errors, f"bead must be {BEAD_ID}")
    patterns = contract.get("patterns")
    if not isinstance(patterns, dict) or set(patterns) != set(PATTERNS):
        fail(errors, f"patterns must be exactly {sorted(PATTERNS)}")
    if not isinstance(contract.get("scan_roots"), list) or not contract["scan_roots"]:
        fail(errors, "scan_roots must be a non-empty array")
    if not isinstance(contract.get("classified_surfaces"), list) or not contract["classified_surfaces"]:
        fail(errors, "classified_surfaces must be a non-empty array")
    events = set(contract.get("required_telemetry_events") or [])
    if events != REQUIRED_EVENTS:
        fail(errors, f"required_telemetry_events must be exactly {sorted(REQUIRED_EVENTS)}")


def validate_source_commit(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> None:
    source_commit = contract.get("source_commit")
    if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        fail(errors, "source_commit must be a 40-character git hash")
        rows.append(event("abi_reentrancy_census_source_commit", "fail", source_commit=source_commit))
        return

    code, _, stderr = git_output(["cat-file", "-e", f"{source_commit}^{{commit}}"])
    if code != 0:
        fail(errors, f"source_commit {source_commit} is not a reachable commit: {stderr.strip()}")
        rows.append(event("abi_reentrancy_census_source_commit", "fail", source_commit=source_commit))
        return

    freshness = contract.get("source_commit_freshness")
    if isinstance(freshness, dict) and freshness.get("require_no_scan_root_changes_since_source_commit") is True:
        roots = [item for item in contract.get("scan_roots", []) if isinstance(item, str) and item]
        code, stdout, stderr = git_output(["diff", "--name-only", f"{source_commit}..HEAD", "--", *roots])
        if code != 0:
            fail(errors, f"git diff for source_commit freshness failed: {stderr.strip()}")
        changed = [line for line in stdout.splitlines() if line.strip()]
        if changed:
            fail(errors, f"source_commit_freshness scan roots changed since {source_commit}: {changed}")
        rows.append(
            event(
                "abi_reentrancy_census_source_commit",
                "pass" if not changed and code == 0 else "fail",
                source_commit=source_commit,
                changed_scan_roots=changed,
            )
        )
    else:
        rows.append(event("abi_reentrancy_census_source_commit", "pass", source_commit=source_commit))


def iter_scan_files(scan_roots: list[Any], errors: list[str]) -> list[Path]:
    files: list[Path] = []
    for item in scan_roots:
        if not isinstance(item, str) or not item:
            fail(errors, "scan_roots entries must be non-empty strings")
            continue
        path = (root / item).resolve()
        try:
            path.relative_to(root.resolve())
        except Exception:
            fail(errors, f"scan root escapes workspace: {item}")
            continue
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(path.rglob("*.rs")))
        else:
            fail(errors, f"scan root missing: {item}")
    return sorted(set(files))


def scan_files(files: list[Path], rows: list[dict[str, Any]], errors: list[str]) -> dict[str, dict[str, int]]:
    actual: dict[str, dict[str, int]] = {}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as exc:
            fail(errors, f"scan file unreadable: {rel(path)}: {exc}")
            continue
        counts = {name: len(pattern.findall(text)) for name, pattern in PATTERNS.items()}
        counts = {name: count for name, count in counts.items() if count}
        if counts:
            actual[rel(path)] = counts
    rows.append(
        event(
            "abi_reentrancy_census_scan",
            "pass",
            scanned_file_count=len(files),
            surface_file_count=len(actual),
            surface_totals=surface_totals(actual),
        )
    )
    return actual


def surface_totals(counts_by_file: dict[str, dict[str, int]]) -> dict[str, int]:
    totals = {name: 0 for name in PATTERNS}
    for counts in counts_by_file.values():
        for name, count in counts.items():
            totals[name] = totals.get(name, 0) + int(count)
    return {name: count for name, count in totals.items() if count}


def expected_counts(contract: dict[str, Any], errors: list[str]) -> dict[str, dict[str, int]]:
    expected: dict[str, dict[str, int]] = {}
    for index, entry in enumerate(contract.get("classified_surfaces", [])):
        if not isinstance(entry, dict):
            fail(errors, f"classified_surfaces[{index}] must be an object")
            continue
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            fail(errors, f"classified_surfaces[{index}].path missing")
            continue
        if path in expected:
            fail(errors, f"duplicate classification for {path}")
        classification = entry.get("classification")
        rationale = entry.get("risk_rationale")
        if not isinstance(classification, str) or not classification:
            fail(errors, f"{path} classification missing")
        if not isinstance(rationale, str) or len(rationale) < 20:
            fail(errors, f"{path} risk_rationale must be a meaningful string")
        counts = entry.get("counts")
        if not isinstance(counts, dict) or not counts:
            fail(errors, f"{path} counts must be a non-empty object")
            continue
        clean_counts: dict[str, int] = {}
        for name, value in counts.items():
            if name not in PATTERNS:
                fail(errors, f"{path} unknown pattern {name}")
            elif not isinstance(value, int) or value <= 0:
                fail(errors, f"{path}.{name} count must be a positive integer")
            else:
                clean_counts[name] = value
        expected[path] = clean_counts
    return expected


def validate_classification(
    actual: dict[str, dict[str, int]],
    expected: dict[str, dict[str, int]],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    actual_keys = set(actual)
    expected_keys = set(expected)
    for path in sorted(actual_keys - expected_keys):
        fail(errors, f"unclassified_surface: {path} has {actual[path]}")
    for path in sorted(expected_keys - actual_keys):
        fail(errors, f"classified_surface_missing_from_scan: {path} expected {expected[path]}")
    for path in sorted(actual_keys & expected_keys):
        if actual[path] != expected[path]:
            fail(errors, f"count_drift: {path} expected {expected[path]}, actual {actual[path]}")
    rows.append(
        event(
            "abi_reentrancy_census_classification",
            "pass" if not errors else "fail",
            classified_file_count=len(expected),
            actual_file_count=len(actual),
            expected_surface_totals=surface_totals(expected),
            actual_surface_totals=surface_totals(actual),
        )
    )


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_contract(errors)
if contract:
    validate_contract_shape(contract, errors)
    validate_source_commit(contract, errors, rows)
    files = iter_scan_files(contract.get("scan_roots", []), errors)
    actual = scan_files(files, rows, errors)
    expected = expected_counts(contract, errors)
    validate_classification(actual, expected, errors, rows)

status = "fail" if errors else "pass"
report = {
    "actual_surface_totals": surface_totals(actual) if "actual" in locals() else {},
    "bead": BEAD_ID,
    "classified_file_count": len(expected) if "expected" in locals() else 0,
    "errors": errors,
    "manifest_id": contract.get("manifest_id") if isinstance(contract, dict) else None,
    "report_schema": "abi_loader_reentrancy_lock_census.report.v1",
    "scanned_file_count": len(files) if "files" in locals() else 0,
    "source_commit": contract.get("source_commit") if isinstance(contract, dict) else None,
    "status": status,
    "timestamp": utc_now(),
}
rows.append(event("abi_reentrancy_census_summary", status, error_count=len(errors), report_path=rel(report_path)))
write_json(report_path, report)
write_jsonl(log_path, rows)

if errors:
    print("abi_loader_reentrancy_lock_census: FAIL")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)

print(
    "abi_loader_reentrancy_lock_census: PASS "
    f"files={report['classified_file_count']} totals={json.dumps(report['actual_surface_totals'], sort_keys=True)}"
)
PY
