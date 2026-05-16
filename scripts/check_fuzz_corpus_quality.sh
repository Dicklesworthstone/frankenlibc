#!/usr/bin/env bash
# check_fuzz_corpus_quality.sh — bd-n0apt.2
# Inventory fuzz target corpus quality and directed-seed conventions.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST="$REPO_ROOT/tests/conformance/fuzz_corpus_quality.v1.json"
REPORT="$REPO_ROOT/target/conformance/fuzz_corpus_quality.report.json"

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
        --repo-root)
            REPO_ROOT="$2"
            shift 2
            ;;
        -h|--help)
            echo "usage: $0 [--manifest path] [--report path] [--repo-root path]"
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

mkdir -p "$(dirname "$REPORT")"

python3 - "$REPO_ROOT" "$MANIFEST" "$REPORT" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

repo_root = pathlib.Path(sys.argv[1]).resolve()
manifest_path = pathlib.Path(sys.argv[2]).resolve()
report_path = pathlib.Path(sys.argv[3]).resolve()

with manifest_path.open(encoding="utf-8") as fh:
    manifest = json.load(fh)

policy = manifest.get("policy", {})
min_corpus_files = int(policy.get("min_corpus_files", 1))
advisory_min_corpus_files = int(policy.get("advisory_min_corpus_files", 15))
required_targets = set(policy.get("required_targets", []))
required_directed = policy.get("required_directed_targets", {})

fuzz_root = repo_root / "crates" / "frankenlibc-fuzz"
target_dir = fuzz_root / "fuzz_targets"
corpus_root = fuzz_root / "corpus"

errors = []
warnings = []
assessments = []
target_files = sorted(target_dir.glob("fuzz_*.rs"))
target_names = {path.stem for path in target_files}

missing_required_targets = sorted(required_targets - target_names)
for target in missing_required_targets:
    errors.append(
        {
            "target": target,
            "severity": "error",
            "code": "missing_required_target",
            "message": f"required target {target} has no fuzz target source",
        }
    )

def read_bytes(path: pathlib.Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""

def readable_seed_files(files):
    return [
        path
        for path in files
        if path.name.startswith("seed_directed_") or path.name.startswith("seed_directive_")
    ]

def source_has_directive_parser(source: str) -> bool:
    signals = [
        "strip_prefix(b\"",
        "try_directive",
        "directed_input",
        "input_from_bytes",
        "seed files can force",
        "Seed files can force",
    ]
    return any(signal in source for signal in signals)

def seed_prefix_present(files, prefix: str) -> bool:
    raw_prefix = prefix.encode("utf-8")
    return any(read_bytes(path).lstrip().startswith(raw_prefix) for path in files)

for target_path in target_files:
    target = target_path.stem
    corpus_dir = corpus_root / target
    source = target_path.read_text(encoding="utf-8", errors="replace")
    corpus_files = sorted([path for path in corpus_dir.glob("*") if path.is_file()]) if corpus_dir.is_dir() else []
    readable_files = readable_seed_files(corpus_files)
    has_directive_parser = source_has_directive_parser(source)
    smoke_command = (
        "RCH_FORCE_REMOTE=true rch exec -- env CARGO_TARGET_DIR=<target> "
        f"cargo run --manifest-path crates/frankenlibc-fuzz/Cargo.toml --bin {target} "
        f"-- -runs=1 crates/frankenlibc-fuzz/corpus/{target}"
    )

    target_errors = []
    target_warnings = []
    if not corpus_dir.is_dir():
        target_errors.append("missing_corpus_dir")
    if len(corpus_files) < min_corpus_files:
        target_errors.append("below_min_corpus_files")
    if len(corpus_files) < advisory_min_corpus_files:
        target_warnings.append("below_advisory_corpus_files")
    if not readable_files:
        target_warnings.append("no_readable_directed_seed_files")
    if not has_directive_parser:
        target_warnings.append("no_source_directive_parser_signal")

    directed_policy = required_directed.get(target)
    if directed_policy:
        min_readable = int(directed_policy.get("min_readable_seed_files", 1))
        if len(readable_files) < min_readable:
            target_errors.append("below_required_readable_seed_files")
        for prefix in directed_policy.get("required_prefixes", []):
            if not seed_prefix_present(readable_files, prefix):
                target_errors.append(f"missing_required_seed_prefix:{prefix}")
        if not has_directive_parser:
            target_errors.append("missing_required_directive_parser")

    for code in target_errors:
        errors.append(
            {
                "target": target,
                "severity": "error",
                "code": code,
                "message": f"{target}: {code}",
            }
        )
    for code in target_warnings:
        warnings.append(
            {
                "target": target,
                "severity": "warning",
                "code": code,
                "message": f"{target}: {code}",
            }
        )

    assessments.append(
        {
            "target": target,
            "source_path": str(target_path.relative_to(repo_root)),
            "corpus_path": str(corpus_dir.relative_to(repo_root)),
            "corpus_dir_exists": corpus_dir.is_dir(),
            "corpus_file_count": len(corpus_files),
            "readable_seed_file_count": len(readable_files),
            "readable_seed_files": [path.name for path in readable_files],
            "source_has_directive_parser_signal": has_directive_parser,
            "smoke_command": smoke_command,
            "errors": target_errors,
            "warnings": target_warnings,
        }
    )

summary = {
    "status": "pass" if not errors else "fail",
    "total_targets": len(assessments),
    "targets_with_corpus": sum(1 for item in assessments if item["corpus_dir_exists"]),
    "targets_with_readable_seeds": sum(1 for item in assessments if item["readable_seed_file_count"] > 0),
    "targets_with_directive_parser_signal": sum(
        1 for item in assessments if item["source_has_directive_parser_signal"]
    ),
    "targets_below_advisory_corpus_files": sorted(
        item["target"] for item in assessments if "below_advisory_corpus_files" in item["warnings"]
    ),
    "targets_without_readable_seeds": sorted(
        item["target"] for item in assessments if "no_readable_directed_seed_files" in item["warnings"]
    ),
    "error_count": len(errors),
    "warning_count": len(warnings),
}

manifest_bytes = manifest_path.read_bytes()
report = {
    "schema_version": "fuzz_corpus_quality.report.v1",
    "bead": manifest.get("bead"),
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "manifest": {
        "path": str(manifest_path.relative_to(repo_root)) if manifest_path.is_relative_to(repo_root) else str(manifest_path),
        "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    },
    "policy": policy,
    "summary": summary,
    "target_assessments": assessments,
    "findings": {
        "errors": errors,
        "warnings": warnings,
    },
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

print("=== Fuzz Corpus Quality Gate (bd-n0apt.2) ===")
print(f"Targets:                 {summary['total_targets']}")
print(f"Targets with corpus:     {summary['targets_with_corpus']}")
print(f"Targets with readable:   {summary['targets_with_readable_seeds']}")
print(f"Directive parser signal: {summary['targets_with_directive_parser_signal']}")
print(f"Warnings:                {summary['warning_count']}")
print(f"Errors:                  {summary['error_count']}")
print(f"Report:                  {report_path}")

if errors:
    print("\nErrors:")
    for finding in errors:
        print(f"  - {finding['target']}: {finding['code']}")
    raise SystemExit(1)

print("\ncheck_fuzz_corpus_quality: PASS")
PY
