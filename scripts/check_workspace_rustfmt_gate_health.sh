#!/usr/bin/env bash
# check_workspace_rustfmt_gate_health.sh -- rustfmt quarantine gate for bd-bp8fl.7.1
#
# The repo currently has broad rustfmt drift across shared ABI surfaces. This
# gate makes that drift explicit: the command passes only when the live
# `cargo fmt --check` drift set exactly matches the quarantine artifact.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_RUSTFMT_GATE_HEALTH:-${ROOT}/tests/conformance/workspace_rustfmt_gate_health.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_RUSTFMT_GATE_REPORT:-${OUT_DIR}/workspace_rustfmt_gate_health.report.json}"
LOG="${FRANKENLIBC_RUSTFMT_GATE_LOG:-${OUT_DIR}/workspace_rustfmt_gate_health.log.jsonl}"
FMT_OUTPUT="${FRANKENLIBC_RUSTFMT_GATE_OUTPUT:-${OUT_DIR}/workspace_rustfmt_gate_health.cargo-fmt.txt}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" "${FMT_OUTPUT}" <<'PY'
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
fmt_output_path = Path(sys.argv[5])

errors = []

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def relpath(path_text: str) -> str:
    path = Path(path_text)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return path.as_posix()
    return path.as_posix()

try:
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"FAIL: cannot load {artifact_path}: {exc}", file=sys.stderr)
    sys.exit(1)

if artifact.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if artifact.get("bead") != "bd-bp8fl.7.1":
    errors.append("bead must be bd-bp8fl.7.1")
if artifact.get("status") != "quarantined":
    errors.append("status must be quarantined")

quarantine = artifact.get("quarantine", {})
expected_files = sorted(set(quarantine.get("files", [])))
declared_count = quarantine.get("file_count")
if declared_count != len(expected_files):
    errors.append(f"file_count={declared_count} does not match files length={len(expected_files)}")

missing_paths = [path for path in expected_files if not (root / path).exists()]
if missing_paths:
    errors.append("quarantined files missing from workspace: " + ", ".join(missing_paths))

cmd = ["cargo", "fmt", "--check"]
proc = subprocess.run(
    cmd,
    cwd=root,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)
fmt_output_path.write_text(proc.stdout, encoding="utf-8")

actual_files = []
for line in proc.stdout.splitlines():
    if line.startswith("Diff in "):
        path_part = line[len("Diff in "):].split(":", 1)[0]
        actual_files.append(relpath(path_part))
actual_all_files = sorted(set(actual_files))

tracked_proc = subprocess.run(
    ["git", "ls-files"],
    cwd=root,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
tracked_files = set(tracked_proc.stdout.splitlines())
actual_files = sorted(path for path in actual_all_files if path in tracked_files)
ignored_untracked = sorted(set(actual_all_files) - tracked_files)

extra = sorted(set(actual_files) - set(expected_files))
missing = sorted(set(expected_files) - set(actual_files))

if proc.returncode == 0 and expected_files:
    errors.append("cargo fmt --check passed but quarantine still lists files")
if proc.returncode != 0 and not actual_files:
    errors.append("cargo fmt --check failed but no rustfmt drift files were parsed")
if extra:
    errors.append("unquarantined rustfmt drift: " + ", ".join(extra))
if missing:
    errors.append("stale quarantined rustfmt entries: " + ", ".join(missing))

status = "pass" if not errors else "fail"
source_commit = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    cwd=root,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
).stdout.strip()

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.7.1",
    "generated_at_utc": utc_now(),
    "status": status,
    "trace_id": artifact.get("trace_id"),
    "command": " ".join(cmd),
    "exit_status": proc.returncode,
    "validation_scope": "workspace-rustfmt-quarantine",
    "owner": quarantine.get("owner_bead"),
    "expected_count": len(expected_files),
    "actual_count": len(actual_files),
    "ignored_untracked_count": len(ignored_untracked),
    "ignored_untracked": ignored_untracked,
    "extra_unquarantined": extra,
    "missing_from_live_drift": missing,
    "artifact_refs": [artifact_path.relative_to(root).as_posix(), fmt_output_path.relative_to(root).as_posix()],
    "source_commit": source_commit,
    "target_dir": "target/conformance",
    "failure_signature": "rustfmt_drift_set_mismatch" if errors else "rustfmt_drift_matches_quarantine",
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

with log_path.open("w", encoding="utf-8") as log:
    for path in expected_files:
        record = {
            "trace_id": artifact.get("trace_id"),
            "bead_id": "bd-bp8fl.7.1",
            "command": "cargo fmt --check",
            "exit_status": proc.returncode,
            "validation_scope": "workspace-rustfmt-quarantine",
            "owner": quarantine.get("owner_bead"),
            "expected": "present_in_rustfmt_drift",
            "actual": "present_in_rustfmt_drift" if path in actual_files else "absent_from_rustfmt_drift",
            "artifact_refs": [artifact_path.relative_to(root).as_posix()],
            "source_commit": source_commit,
            "target_dir": "target/conformance",
            "file_path": path,
            "failure_signature": "ok" if path in actual_files else "stale_quarantine_entry",
        }
        log.write(json.dumps(record, sort_keys=True) + "\n")
    for path in extra:
        record = {
            "trace_id": artifact.get("trace_id"),
            "bead_id": "bd-bp8fl.7.1",
            "command": "cargo fmt --check",
            "exit_status": proc.returncode,
            "validation_scope": "workspace-rustfmt-quarantine",
            "owner": quarantine.get("owner_bead"),
            "expected": "not_present_in_rustfmt_drift",
            "actual": "present_in_rustfmt_drift",
            "artifact_refs": [artifact_path.relative_to(root).as_posix()],
            "source_commit": source_commit,
            "target_dir": "target/conformance",
            "file_path": path,
            "failure_signature": "unquarantined_rustfmt_drift",
        }
        log.write(json.dumps(record, sort_keys=True) + "\n")

if errors:
    print("FAIL: workspace rustfmt gate health mismatch")
    for error in errors:
        print(f"  - {error}")
    sys.exit(1)

print(f"PASS: rustfmt drift matches quarantine ({len(actual_files)} files)")
print(f"report: {report_path.relative_to(root)}")
print(f"log: {log_path.relative_to(root)}")
PY
