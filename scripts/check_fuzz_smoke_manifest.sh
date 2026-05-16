#!/usr/bin/env bash
# check_fuzz_smoke_manifest.sh - bd-n0apt.3
# Validate the representative fuzz smoke tier and optional remote rch proof report.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST="$REPO_ROOT/tests/conformance/fuzz_smoke_manifest.v1.json"
REPORT="$REPO_ROOT/target/conformance/fuzz_smoke_manifest.report.json"
PROOF=""
PRINT_COMMANDS=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --manifest)
            MANIFEST="$2"
            shift 2
            ;;
        --report)
            REPORT="$2"
            shift 2
            ;;
        --proof)
            PROOF="$2"
            shift 2
            ;;
        --repo-root)
            REPO_ROOT="$2"
            shift 2
            ;;
        --print-commands)
            PRINT_COMMANDS=true
            shift
            ;;
        -h|--help)
            echo "usage: $0 [--manifest path] [--proof path] [--report path] [--repo-root path] [--print-commands]"
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

mkdir -p "$(dirname "$REPORT")"

python3 - "$REPO_ROOT" "$MANIFEST" "$REPORT" "$PROOF" "$PRINT_COMMANDS" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

repo_root = pathlib.Path(sys.argv[1]).resolve()
manifest_path = pathlib.Path(sys.argv[2]).resolve()
report_path = pathlib.Path(sys.argv[3]).resolve()
proof_path = pathlib.Path(sys.argv[4]).resolve() if sys.argv[4] else None
print_commands = sys.argv[5] == "true"

with manifest_path.open(encoding="utf-8") as fh:
    manifest = json.load(fh)

policy = manifest.get("policy", {})
min_corpus_files = int(policy.get("min_corpus_files", 1))
fallback_marker = str(policy.get("local_fallback_marker", "[RCH] local (remote execution failed)"))
require_done_runs = bool(policy.get("require_done_runs_at_least_corpus_files", True))
forbid_shell_wrapped = bool(policy.get("forbid_shell_wrapped_cargo", True))
smoke_targets = manifest.get("smoke_targets", [])

errors = []
warnings = []
target_reports = []

fuzz_root = repo_root / "crates" / "frankenlibc-fuzz"
target_dir = fuzz_root / "fuzz_targets"
corpus_root = fuzz_root / "corpus"

def rel(path: pathlib.Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)

def add_error(target: str, code: str, message: str):
    errors.append(
        {
            "target": target,
            "severity": "error",
            "code": code,
            "message": message,
        }
    )

def add_warning(target: str, code: str, message: str):
    warnings.append(
        {
            "target": target,
            "severity": "warning",
            "code": code,
            "message": message,
        }
    )

def smoke_command(target: str, corpus_path: str) -> str:
    target_dir_name = f"/tmp/rch_target_frankenlibc_fuzz_smoke_{target}"
    return (
        "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env "
        f"CARGO_TARGET_DIR={target_dir_name} "
        f"cargo run --manifest-path crates/frankenlibc-fuzz/Cargo.toml --bin {target} "
        f"-- -runs=1 {corpus_path}"
    )

def file_count(path: pathlib.Path) -> int:
    if not path.is_dir():
        return 0
    return sum(1 for child in path.iterdir() if child.is_file())

def text_contains_local_fallback(value) -> bool:
    if value is None:
        return False
    text = str(value)
    return fallback_marker in text or "local (remote execution failed)" in text

def command_has_remote_shape(command: str, target: str, corpus_path: str) -> list[str]:
    failures = []
    required = [
        "RCH_FORCE_REMOTE=true",
        "rch exec --",
        "CARGO_TARGET_DIR=",
        "cargo run",
        "--manifest-path crates/frankenlibc-fuzz/Cargo.toml",
        f"--bin {target}",
        f"-runs=1 {corpus_path}",
    ]
    for token in required:
        if token not in command:
            failures.append(f"missing_remote_command_token:{token}")
    if forbid_shell_wrapped and ("bash -c" in command or "sh -c" in command):
        failures.append("shell_wrapped_cargo")
    return failures

seen = set()
if not smoke_targets:
    add_error("<manifest>", "empty_smoke_targets", "manifest must list at least one smoke target")

ordered_targets = [item.get("target") for item in smoke_targets]
if ordered_targets != sorted(ordered_targets):
    add_error("<manifest>", "nondeterministic_target_order", "smoke_targets must be sorted by target")

for item in smoke_targets:
    target = str(item.get("target", ""))
    corpus_path = str(item.get("corpus_path", ""))
    expected_corpus_path = f"crates/frankenlibc-fuzz/corpus/{target}"
    target_path = target_dir / f"{target}.rs"
    corpus_dir = repo_root / corpus_path
    command = smoke_command(target, corpus_path)
    count = file_count(corpus_dir)

    if not target:
        add_error("<manifest>", "missing_target_name", "smoke target entry is missing target")
        continue
    if target in seen:
        add_error(target, "duplicate_target", f"{target} is listed more than once")
    seen.add(target)
    if corpus_path != expected_corpus_path:
        add_error(
            target,
            "wrong_manifest_corpus_path",
            f"{target} corpus_path must be {expected_corpus_path}, got {corpus_path}",
        )
    if not target_path.is_file():
        add_error(target, "missing_fuzz_target_source", f"missing fuzz target source {rel(target_path)}")
    if not corpus_dir.is_dir():
        add_error(target, "missing_corpus_dir", f"missing corpus directory {rel(corpus_dir)}")
    if count < min_corpus_files:
        add_error(target, "below_min_corpus_files", f"{target} has {count} corpus files")

    target_reports.append(
        {
            "target": target,
            "source_path": rel(target_path),
            "corpus_path": corpus_path,
            "corpus_file_count": count,
            "command": command,
            "reason": item.get("reason", ""),
        }
    )

proof_reports = []
proof_checked = proof_path is not None
if proof_path is not None:
    if not proof_path.is_file():
        add_error("<proof>", "missing_proof_file", f"missing proof file {proof_path}")
        proof = {}
    else:
        with proof_path.open(encoding="utf-8") as fh:
            proof = json.load(fh)
    if proof.get("schema_version") != manifest.get("artifacts", {}).get("proof_schema", "fuzz_smoke_proof.v1"):
        add_error("<proof>", "wrong_proof_schema", "proof schema_version does not match manifest proof_schema")
    proof_entries = proof.get("commands", [])
    if not isinstance(proof_entries, list):
        add_error("<proof>", "commands_not_array", "proof commands must be an array")
        proof_entries = []
    proof_by_target = {}
    for entry in proof_entries:
        target = str(entry.get("target", ""))
        if target:
            proof_by_target.setdefault(target, []).append(entry)

    for target_report in target_reports:
        target = target_report["target"]
        entries = proof_by_target.get(target, [])
        if not entries:
            add_error(target, "missing_remote_proof", f"proof missing command report for {target}")
            continue
        if len(entries) > 1:
            add_error(target, "duplicate_remote_proof", f"proof has multiple command reports for {target}")
        entry = entries[0]
        command = str(entry.get("command", ""))
        corpus_path = str(entry.get("corpus_path", ""))
        worker = str(entry.get("worker", ""))
        exit_code = entry.get("exit_code")
        done_runs = entry.get("done_runs")
        stdout_summary = str(entry.get("stdout_summary", ""))
        stderr_summary = str(entry.get("stderr_summary", ""))
        raw_output = str(entry.get("raw_output", ""))

        required_fields = ["target", "corpus_path", "worker", "exit_code", "done_runs", "stdout_summary", "command"]
        for field in required_fields:
            if field not in entry or entry.get(field) in (None, ""):
                add_error(target, f"missing_remote_proof_field:{field}", f"{target} proof is missing {field}")

        if corpus_path != target_report["corpus_path"]:
            add_error(
                target,
                "wrong_proof_corpus_path",
                f"{target} proof corpus_path must be {target_report['corpus_path']}, got {corpus_path}",
            )
        if not worker or worker == "local":
            add_error(target, "invalid_remote_worker", f"{target} proof worker must name a remote worker")
        if exit_code != 0:
            add_error(target, "nonzero_exit_code", f"{target} proof exit_code must be 0")
        if not isinstance(done_runs, int):
            add_error(target, "missing_done_runs", f"{target} proof done_runs must be an integer")
        elif require_done_runs and done_runs < target_report["corpus_file_count"]:
            add_error(
                target,
                "done_runs_below_corpus_file_count",
                f"{target} proof done_runs {done_runs} below corpus file count {target_report['corpus_file_count']}",
            )
        if "Done " not in stdout_summary or " runs" not in stdout_summary:
            add_error(target, "missing_done_runs_summary", f"{target} proof stdout_summary must include Done N runs")
        for code in command_has_remote_shape(command, target, target_report["corpus_path"]):
            add_error(target, code, f"{target} command has invalid remote shape: {command}")
        if any(text_contains_local_fallback(value) for value in [command, stdout_summary, stderr_summary, raw_output]):
            add_error(target, "local_rch_fallback_marker", f"{target} proof contains local rch fallback marker")

        proof_reports.append(
            {
                "target": target,
                "worker": worker,
                "exit_code": exit_code,
                "done_runs": done_runs,
                "stdout_summary": stdout_summary,
                "command": command,
            }
        )

manifest_bytes = manifest_path.read_bytes()
proof_digest = None
if proof_path is not None and proof_path.is_file():
    proof_digest = hashlib.sha256(proof_path.read_bytes()).hexdigest()

summary = {
    "status": "pass" if not errors else "fail",
    "target_count": len(target_reports),
    "proof_checked": proof_checked,
    "proof_command_count": len(proof_reports),
    "total_corpus_files": sum(item["corpus_file_count"] for item in target_reports),
    "error_count": len(errors),
    "warning_count": len(warnings),
}
report = {
    "schema_version": "fuzz_smoke_manifest.report.v1",
    "bead": manifest.get("bead"),
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "manifest": {
        "path": rel(manifest_path),
        "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    },
    "proof": {
        "path": rel(proof_path) if proof_path else None,
        "sha256": proof_digest,
        "checked": proof_checked,
    },
    "summary": summary,
    "target_reports": target_reports,
    "proof_reports": proof_reports,
    "findings": {
        "errors": errors,
        "warnings": warnings,
    },
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if print_commands:
    for target_report in target_reports:
        print(target_report["command"])

print("=== Fuzz Smoke Manifest Gate (bd-n0apt.3) ===")
print(f"Targets:        {summary['target_count']}")
print(f"Corpus files:   {summary['total_corpus_files']}")
print(f"Proof checked:  {'yes' if proof_checked else 'no'}")
print(f"Proof commands: {summary['proof_command_count']}")
print(f"Errors:         {summary['error_count']}")
print(f"Report:         {report_path}")

if errors:
    print("\nErrors:")
    for finding in errors:
        print(f"  - {finding['target']}: {finding['code']}")
    raise SystemExit(1)

if proof_checked:
    print("\ncheck_fuzz_smoke_manifest: PASS")
else:
    print("\ncheck_fuzz_smoke_manifest: PASS (manifest only)")
PY
