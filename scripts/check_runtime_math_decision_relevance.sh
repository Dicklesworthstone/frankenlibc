#!/usr/bin/env bash
# check_runtime_math_decision_relevance.sh -- read-only bd-24x.1 proof gate.
#
# Validates that every public runtime_math module has a concrete runtime
# decision target and emits deterministic JSON/JSONL telemetry.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_RUNTIME_MATH_DECISION_RELEVANCE_ARTIFACT:-${ROOT}/tests/runtime_math/runtime_math_decision_relevance.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MATH_DECISION_RELEVANCE_TARGET_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_DECISION_RELEVANCE_REPORT:-${OUT_DIR}/runtime_math_decision_relevance.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_DECISION_RELEVANCE_LOG:-${OUT_DIR}/runtime_math_decision_relevance.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"FAIL: cannot load {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def source_commit():
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


def declared_runtime_modules(mod_rs_path):
    modules = []
    pattern = re.compile(r"^\s*pub\s+mod\s+([A-Za-z0-9_]+)\s*;")
    for line in mod_rs_path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            modules.append(match.group(1))
    return sorted(set(modules))


def decision_surface(decision_target, surface_patterns):
    for surface, needle in surface_patterns.items():
        if needle in decision_target:
            return surface
    return ""


artifact = load_json(artifact_path)
sources = artifact["source_artifacts"]
mod_rs_path = root / sources["module_registry"]
matrix_path = root / sources["classification_matrix"]
linkage_path = root / sources["linkage_ledger"]
manifest_path = root / sources["production_manifest"]

matrix = load_json(matrix_path)
linkage = load_json(linkage_path)
manifest = load_json(manifest_path)
surface_patterns = artifact["decision_surface_patterns"]
commit = source_commit()
now = utc_now()

public_modules = declared_runtime_modules(mod_rs_path)
matrix_rows = {
    row.get("module"): row
    for row in matrix.get("modules", [])
    if isinstance(row, dict) and isinstance(row.get("module"), str)
}
linkage_rows = linkage.get("modules", {})
if not isinstance(linkage_rows, dict):
    linkage_rows = {}

public_set = set(public_modules)
matrix_set = set(matrix_rows)
linkage_set = set(linkage_rows)

missing_from_classification = sorted(public_set - matrix_set)
missing_from_linkage = sorted(public_set - linkage_set)
extra_classification_modules = sorted(matrix_set - public_set)
extra_linkage_modules = sorted(linkage_set - public_set)

logs = []
failed_modules = []
module_rows = []


def add_log(module, row, expected, actual, failure_signature, outcome):
    logs.append(
        {
            "trace_id": f"{artifact['bead']}::runtime-math-decision-relevance::{module}",
            "bead_id": artifact["bead"],
            "module": module,
            "module_path": f"crates/frankenlibc-membrane/src/runtime_math/{module}.rs",
            "classification": row.get("classification", ""),
            "linkage_status": row.get("linkage_status", ""),
            "decision_target": row.get("decision_target", ""),
            "decision_surface": row.get("decision_surface", ""),
            "expected": expected,
            "actual": actual,
            "artifact_refs": [rel(artifact_path), rel(matrix_path), rel(linkage_path), rel(mod_rs_path)],
            "source_commit": commit,
            "failure_signature": failure_signature,
            "outcome": outcome,
        }
    )


for module in public_modules:
    matrix_row = matrix_rows.get(module, {})
    linkage_row = linkage_rows.get(module, {})
    target = linkage_row.get("decision_target", "") if isinstance(linkage_row, dict) else ""
    surface = decision_surface(target, surface_patterns)
    row = {
        "module": module,
        "module_path": f"crates/frankenlibc-membrane/src/runtime_math/{module}.rs",
        "classification": matrix_row.get("classification", ""),
        "linkage_status": linkage_row.get("linkage_status", ""),
        "decision_target": target,
        "decision_surface": surface,
        "action_outputs": linkage_row.get("action_outputs", []),
        "evidence_inputs": linkage_row.get("evidence_inputs", []),
        "fallback_when_data_missing": linkage_row.get("fallback_when_data_missing", ""),
        "invariant": linkage_row.get("invariant", ""),
        "source_refs": {
            "module_registry": rel(mod_rs_path),
            "classification_matrix": f"{rel(matrix_path)}#/modules/{module}",
            "linkage_ledger": f"{rel(linkage_path)}#/modules/{module}",
            "production_manifest": rel(manifest_path),
        },
    }
    module_rows.append(row)

    failures = []
    if module not in matrix_rows:
        failures.append("missing_classification_row")
    if module not in linkage_rows:
        failures.append("missing_linkage_row")
    if not target or "RuntimeMathKernel::" not in target:
        failures.append("missing_decision_target")
    if not surface:
        failures.append("missing_decision_surface")
    if not row["action_outputs"]:
        failures.append("missing_action_outputs")
    if not row["evidence_inputs"]:
        failures.append("missing_evidence_inputs")
    if not row["fallback_when_data_missing"]:
        failures.append("missing_fallback")
    if not row["invariant"]:
        failures.append("missing_invariant")

    if failures:
        failed_modules.append({"module": module, "failures": failures})
        add_log(
            module,
            row,
            "classification + linkage rows with concrete RuntimeMathKernel decision surface",
            ", ".join(failures),
            failures[0],
            "fail",
        )
    else:
        add_log(
            module,
            row,
            "classification + linkage rows with concrete RuntimeMathKernel decision surface",
            row["decision_target"],
            "runtime_math_decision_relevance_present",
            "pass",
        )

for module in missing_from_classification:
    if module not in public_set:
        continue
for module in missing_from_linkage:
    if module not in public_set:
        continue
for module in extra_classification_modules:
    failed_modules.append({"module": module, "failures": ["unexpected_classification_module"]})
for module in extra_linkage_modules:
    failed_modules.append({"module": module, "failures": ["unexpected_linkage_module"]})

classification_counts = Counter(row["classification"] for row in module_rows)
linkage_status_counts = Counter(row["linkage_status"] for row in module_rows)
decision_surface_counts = Counter(row["decision_surface"] for row in module_rows)

errors = []
if missing_from_classification:
    errors.append(f"missing classification rows: {', '.join(missing_from_classification)}")
if missing_from_linkage:
    errors.append(f"missing linkage rows: {', '.join(missing_from_linkage)}")
if extra_classification_modules:
    errors.append(f"unexpected classification rows: {', '.join(extra_classification_modules)}")
if extra_linkage_modules:
    errors.append(f"unexpected linkage rows: {', '.join(extra_linkage_modules)}")
if failed_modules:
    errors.append(f"failed module rows: {len(failed_modules)}")

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": artifact["bead"],
    "generated_at_utc": now,
    "source_commit": commit,
    "module_count": len(module_rows),
    "public_module_count": len(public_modules),
    "expected_public_module_count": artifact["runtime_module_scope"]["expected_public_module_count"],
    "classification_counts": dict(sorted(classification_counts.items())),
    "linkage_status_counts": dict(sorted(linkage_status_counts.items())),
    "decision_surface_counts": dict(sorted(decision_surface_counts.items())),
    "missing_from_classification": missing_from_classification,
    "missing_from_linkage": missing_from_linkage,
    "extra_classification_modules": extra_classification_modules,
    "extra_linkage_modules": extra_linkage_modules,
    "failed_modules": failed_modules,
    "module_rows": module_rows,
    "artifact_refs": [rel(artifact_path), rel(mod_rs_path), rel(matrix_path), rel(linkage_path), rel(manifest_path)],
    "status": status,
    "errors": errors,
    "log_path": rel(log_path),
}

if report["public_module_count"] != report["expected_public_module_count"]:
    report["status"] = "fail"
    report["errors"].append(
        f"public module count mismatch: expected {report['expected_public_module_count']} actual {report['public_module_count']}"
    )

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in sorted(logs, key=lambda item: item["module"])),
    encoding="utf-8",
)

if report["status"] != "pass":
    print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
    sys.exit(1)

print(
    "PASS: runtime_math decision relevance covers "
    f"{report['module_count']} public modules across {len(report['decision_surface_counts'])} decision surfaces."
)
print(f"Structured logs: {rel(log_path)}")
print(f"Report: {rel(report_path)}")
PY
