#!/usr/bin/env bash
# check_resume_stash_conflict_completion_contract.sh -- bd-jirj3.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RESUME_STASH_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/resume_stash_conflict_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RESUME_STASH_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_RESUME_STASH_COMPLETION_REPORT:-${OUT_DIR}/resume_stash_conflict_completion_contract.report.json}"
LOG="${FRANKENLIBC_RESUME_STASH_COMPLETION_LOG:-${OUT_DIR}/resume_stash_conflict_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
out_dir = Path(sys.argv[5])
source_commit = sys.argv[6]

SCHEMA = "resume_stash_conflict_completion_contract.v1"
BEAD_ID = "bd-jirj3.1"
ORIGINAL_BEAD = "bd-jirj3"
TRACE_ID = "bd-jirj3.1::resume-stash-conflict::completion::v1"
REQUIRED_ARTIFACT_IDS = {
    "original_tracker_row",
    "perf_regression_prevention_artifact",
    "uncovered_hotpath_manifest",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_MISSING_ITEMS = {"tests.conformance.primary"}
REQUIRED_EVENTS = {
    "source_artifacts_validated",
    "git_index_validated",
    "conflict_markers_absent",
    "json_artifacts_validated",
    "missing_item_bindings_validated",
    "test_surfaces_validated",
    "resume_stash_conflict_completion_contract_validated",
}
REQUIRED_TESTS = {
    "contract_binds_resume_stash_conflict_conformance_sources",
    "checker_accepts_clean_resume_stash_contract",
    "checker_rejects_missing_conformance_binding",
    "checker_rejects_conflict_marker_probe",
}
DEFAULT_TEXT_EXTENSIONS = {
    ".c",
    ".h",
    ".json",
    ".jsonl",
    ".map",
    ".md",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
DEFAULT_JSON_ROOTS = {
    "tests/conformance",
    "tests/cve_arena",
    "tests/release",
    "tests/runtime_math",
}
SKIP_PREFIXES = (
    ".beads/",
    ".git/",
    "legacy_glibc_code/",
    "target/",
)
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "unmerged_index_entries",
    "conflict_marker_found",
    "malformed_json_artifact",
    "missing_conformance_binding",
    "missing_test_surface",
]

events: list[dict[str, Any]] = []
errors: list[dict[str, str]] = []
artifact_refs: set[str] = {str(contract_path)}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "resume_stash_conflict_completion_contract_failed"


def event(name: str, status: str, failure_signature: str = "none", **fields: Any) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "event": name,
        "status": status,
        "source_commit": source_commit,
        "target_dir": rel(out_dir),
        "failure_signature": failure_signature,
        "artifact_refs": sorted(artifact_refs),
        **fields,
    }


def load_json(path: Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def as_array(value: Any, context: str, signature: str = "malformed_contract") -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def as_object(value: Any, context: str, signature: str = "malformed_contract") -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def string_set(value: Any, context: str, signature: str = "malformed_contract") -> set[str]:
    rows = as_array(value, context, signature)
    result = {row for row in rows if isinstance(row, str)}
    if len(result) != len(rows):
        add_error(signature, f"{context} must contain only strings")
    return result


def git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def tracked_files() -> list[str]:
    proc = git(["ls-files"])
    if proc.returncode != 0:
        add_error("git_index_unavailable", proc.stderr.strip() or "git ls-files failed")
        return []
    return [line for line in proc.stdout.splitlines() if line]


def should_skip(path: str) -> bool:
    return path.startswith(SKIP_PREFIXES)


def validate_source_artifacts(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    artifacts = as_array(contract.get("source_artifacts"), "source_artifacts")
    by_id: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        row = as_object(artifact, "source_artifacts[]")
        artifact_id = row.get("id")
        path_text = row.get("path")
        if not isinstance(artifact_id, str) or not isinstance(path_text, str):
            add_error("malformed_contract", "source_artifacts rows require string id and path")
            continue
        by_id[artifact_id] = row
        path = resolve(path_text)
        artifact_refs.add(path_text)
        if not path.exists():
            add_error("missing_source_artifact", f"{artifact_id} missing at {path_text}")
            continue
        terms = string_set(row.get("required_terms", []), f"source_artifacts[{artifact_id}].required_terms")
        if terms:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                add_error("missing_source_artifact", f"{path_text} is not readable as utf-8")
                continue
            for term in sorted(terms):
                if term not in text:
                    add_error(
                        "missing_source_artifact",
                        f"{artifact_id} at {path_text} missing term {term!r}",
                    )
    missing_ids = sorted(REQUIRED_ARTIFACT_IDS - set(by_id))
    for artifact_id in missing_ids:
        add_error("missing_source_artifact", f"missing source artifact id {artifact_id}")
    events.append(event("source_artifacts_validated", "pass" if not missing_ids else "fail", artifact_count=len(by_id)))
    return by_id


def validate_git_index() -> int:
    proc = git(["ls-files", "-u"])
    if proc.returncode != 0:
        add_error("git_index_unavailable", proc.stderr.strip() or "git ls-files -u failed")
        return 0
    rows = [line for line in proc.stdout.splitlines() if line]
    if rows:
        add_error("unmerged_index_entries", f"{len(rows)} unmerged index entries remain")
    events.append(event("git_index_validated", "pass" if not rows else "fail", unmerged_entry_count=len(rows)))
    return len(rows)


def validate_conflict_markers(contract: dict[str, Any], files: list[str]) -> int:
    completion = as_object(contract.get("completion_contract"), "completion_contract")
    marker_prefixes = tuple(
        sorted(string_set(completion.get("conflict_marker_prefixes", []), "conflict_marker_prefixes"))
    ) or ("<<<<<<<", ">>>>>>>", "|||||||")
    text_extensions = (
        string_set(completion.get("tracked_text_extensions", []), "tracked_text_extensions")
        or DEFAULT_TEXT_EXTENSIONS
    )
    probe_paths = string_set(completion.get("conflict_marker_probe_paths", []), "conflict_marker_probe_paths")
    scan_paths: list[Path] = []
    for path_text in files:
        if should_skip(path_text):
            continue
        path = Path(path_text)
        if path.suffix in text_extensions or path.name in {"Cargo.toml", "Cargo.lock"}:
            scan_paths.append(root / path)
    scan_paths.extend(resolve(path_text) for path_text in sorted(probe_paths))

    finding_count = 0
    for path in scan_paths:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (FileNotFoundError, UnicodeDecodeError):
            continue
        for line_no, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            if any(stripped.startswith(prefix) for prefix in marker_prefixes):
                finding_count += 1
                add_error("conflict_marker_found", f"{rel(path)}:{line_no}: {stripped[:80]}")
    events.append(
        event(
            "conflict_markers_absent",
            "pass" if finding_count == 0 else "fail",
            scanned_file_count=len(scan_paths),
            marker_count=finding_count,
        )
    )
    return finding_count


def json_paths(contract: dict[str, Any], files: list[str]) -> list[Path]:
    completion = as_object(contract.get("completion_contract"), "completion_contract")
    json_roots = string_set(completion.get("json_artifact_roots", []), "json_artifact_roots") or DEFAULT_JSON_ROOTS
    probe_paths = string_set(completion.get("json_artifact_probe_paths", []), "json_artifact_probe_paths")
    paths: list[Path] = []
    for path_text in files:
        if should_skip(path_text):
            continue
        path = Path(path_text)
        if path.suffix not in {".json", ".jsonl"}:
            continue
        if any(path_text == root_name or path_text.startswith(f"{root_name}/") for root_name in json_roots):
            paths.append(root / path)
    paths.extend(resolve(path_text) for path_text in sorted(probe_paths))
    return paths


def validate_json_artifacts(paths: list[Path]) -> tuple[int, int]:
    json_count = 0
    jsonl_count = 0
    for path in paths:
        artifact_refs.add(rel(path))
        try:
            text = path.read_text(encoding="utf-8")
            if path.suffix == ".jsonl":
                jsonl_count += 1
                for line_no, line in enumerate(text.splitlines(), start=1):
                    if line.strip():
                        json.loads(line)
            else:
                json_count += 1
                json.loads(text)
        except Exception as exc:
            add_error("malformed_json_artifact", f"{rel(path)}: {exc}")
    malformed = sum(1 for error in errors if error["failure_signature"] == "malformed_json_artifact")
    events.append(
        event(
            "json_artifacts_validated",
            "pass" if malformed == 0 else "fail",
            json_artifact_count=json_count,
            jsonl_artifact_count=jsonl_count,
        )
    )
    return json_count, jsonl_count


def validate_missing_item_bindings(contract: dict[str, Any]) -> None:
    completion = as_object(contract.get("completion_contract"), "completion_contract")
    missing_items = string_set(completion.get("missing_item_ids"), "completion_contract.missing_item_ids")
    if missing_items != REQUIRED_MISSING_ITEMS:
        add_error(
            "missing_conformance_binding",
            f"missing_item_ids must be {sorted(REQUIRED_MISSING_ITEMS)}, got {sorted(missing_items)}",
        )
    bindings = as_array(contract.get("missing_item_bindings"), "missing_item_bindings")
    bound_items = {
        row.get("missing_item_id")
        for row in bindings
        if isinstance(row, dict) and isinstance(row.get("missing_item_id"), str)
    }
    if not REQUIRED_MISSING_ITEMS.issubset(bound_items):
        add_error("missing_conformance_binding", "tests.conformance.primary binding is missing")
    events.append(
        event(
            "missing_item_bindings_validated",
            "pass"
            if not any(error["failure_signature"] == "missing_conformance_binding" for error in errors)
            else "fail",
            binding_count=len(bound_items),
        )
    )


def validate_test_surfaces(by_id: dict[str, dict[str, Any]], contract: dict[str, Any]) -> None:
    test_path = by_id.get("completion_harness_test", {}).get("path", "")
    gate_path = by_id.get("completion_gate", {}).get("path", "")
    missing: list[str] = []
    for path_text, terms in [
        (test_path, REQUIRED_TESTS),
        (gate_path, REQUIRED_EVENTS | {"git ls-files -u", "malformed_json_artifact"}),
    ]:
        if not path_text:
            missing.append("missing test or gate path")
            continue
        path = resolve(path_text)
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as exc:
            missing.append(f"cannot read {path_text}: {exc}")
            continue
        for term in sorted(terms):
            if term not in text:
                missing.append(f"{path_text} missing term {term}")
    for item in missing:
        add_error("missing_test_surface", item)
    events.append(event("test_surfaces_validated", "pass" if not missing else "fail", required_test_count=len(REQUIRED_TESTS)))


def finish(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        events.append(event("resume_stash_conflict_completion_contract_validated", "pass"))
    else:
        events.append(event("resume_stash_conflict_completion_contract_failed", "fail", primary_signature()))
    report = {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": status,
        "summary": {**summary, "event_count": len(events)},
        "artifact_refs": sorted(artifact_refs),
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, events)
    if errors:
        print(f"FAIL: resume stash conflict completion contract errors={len(errors)}")
        for error in errors[:12]:
            print(f"- {error['failure_signature']}: {error['message']}")
        sys.exit(1)
    print(
        "PASS: resume stash conflict completion contract "
        f"tracked={summary.get('tracked_file_count', 0)} "
        f"json={summary.get('json_artifact_count', 0)} "
        f"jsonl={summary.get('jsonl_artifact_count', 0)}"
    )


contract = load_json(contract_path, "completion_contract")
contract_obj = as_object(contract, "contract")
if contract_obj.get("schema_version") != SCHEMA:
    add_error("malformed_contract", f"schema_version must be {SCHEMA}")
if contract_obj.get("bead_id") != BEAD_ID:
    add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
if contract_obj.get("original_bead") != ORIGINAL_BEAD:
    add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")

source_by_id = validate_source_artifacts(contract_obj)
tracked = tracked_files()
unmerged_count = validate_git_index()
marker_count = validate_conflict_markers(contract_obj, tracked)
json_count, jsonl_count = validate_json_artifacts(json_paths(contract_obj, tracked))
validate_missing_item_bindings(contract_obj)
validate_test_surfaces(source_by_id, contract_obj)

finish(
    {
        "tracked_file_count": len(tracked),
        "unmerged_entry_count": unmerged_count,
        "conflict_marker_count": marker_count,
        "json_artifact_count": json_count,
        "jsonl_artifact_count": jsonl_count,
    }
)
PY
