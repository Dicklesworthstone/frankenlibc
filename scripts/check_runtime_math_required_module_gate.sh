#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${RUNTIME_MATH_REQUIRED_MODULE_GATE_CONTRACT:-$ROOT/tests/runtime_math/runtime_math_required_module_gate.v1.json}"
REPORT="${RUNTIME_MATH_REQUIRED_MODULE_GATE_REPORT:-$ROOT/target/conformance/runtime_math_required_module_gate.report.json}"
LOG="${RUNTIME_MATH_REQUIRED_MODULE_GATE_LOG:-$ROOT/target/conformance/runtime_math_required_module_gate.log.jsonl}"
MOD_RS="${RUNTIME_MATH_REQUIRED_MODULE_GATE_MOD_RS:-$ROOT/crates/frankenlibc-membrane/src/runtime_math/mod.rs}"
LINKAGE="${RUNTIME_MATH_REQUIRED_MODULE_GATE_LINKAGE:-$ROOT/tests/runtime_math/runtime_math_linkage.v1.json}"
MATRIX="${RUNTIME_MATH_REQUIRED_MODULE_GATE_MATRIX:-$ROOT/tests/runtime_math/runtime_math_classification_matrix.v1.json}"
MANIFEST="${RUNTIME_MATH_REQUIRED_MODULE_GATE_MANIFEST:-$ROOT/tests/runtime_math/production_kernel_manifest.v1.json}"
GOVERNANCE="${RUNTIME_MATH_REQUIRED_MODULE_GATE_GOVERNANCE:-$ROOT/tests/conformance/math_governance.json}"
AGENTS_DOC="${RUNTIME_MATH_REQUIRED_MODULE_GATE_AGENTS:-$ROOT/AGENTS.md}"
LIB_RS="${RUNTIME_MATH_REQUIRED_MODULE_GATE_LIB_RS:-$ROOT/crates/frankenlibc-membrane/src/lib.rs}"
MODE="validate-only"

if [[ $# -gt 0 ]]; then
  case "$1" in
    --validate-only)
      MODE="validate-only"
      shift
      ;;
    *)
      MODE="unknown:$1"
      shift
      ;;
  esac
fi

if [[ $# -gt 0 ]]; then
  MODE="unknown:$1"
fi

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" "$MODE" "$MOD_RS" "$LINKAGE" "$MATRIX" "$MANIFEST" "$GOVERNANCE" "$AGENTS_DOC" "$LIB_RS" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import time
from collections import Counter

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
mode = sys.argv[5]
mod_rs_path = pathlib.Path(sys.argv[6])
linkage_path = pathlib.Path(sys.argv[7])
matrix_path = pathlib.Path(sys.argv[8])
manifest_path = pathlib.Path(sys.argv[9])
governance_path = pathlib.Path(sys.argv[10])
agents_path = pathlib.Path(sys.argv[11])
lib_rs_path = pathlib.Path(sys.argv[12])
start_ns = time.time_ns()

EXPECTED_SCHEMA = "runtime_math_required_module_gate.v1"
EXPECTED_BEAD = "bd-0agsk.12"
EXPECTED_COMMAND = "scripts/check_runtime_math_required_module_gate.sh --validate-only"
EXPECTED_TODOS = {"TODO-0801", "TODO-0802", "TODO-0803", "TODO-0804", "TODO-0805"}


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except subprocess.CalledProcessError:
        return "unknown"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def finish(outcome: str, signature: str, message: str, **summary):
    report = {
        "schema_version": "runtime_math_required_module_gate.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": f"runtime-math-required-module-gate-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{id(summary)}",
        "source_commit": git_head(),
        "mode": mode,
        "outcome": outcome,
        "failure_signature": signature,
        "message": message,
        "contract": str(contract_path),
        "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
        "inputs": {
            "mod_rs": rel(mod_rs_path),
            "linkage": rel(linkage_path),
            "matrix": rel(matrix_path),
            "manifest": rel(manifest_path),
            "governance": rel(governance_path),
            "agents": rel(agents_path),
            "lib_rs": rel(lib_rs_path),
        },
        "summary": summary,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_event = {
        "timestamp": now_utc(),
        "event": "runtime_math_required_module_gate_validated" if outcome == "pass" else "runtime_math_required_module_gate_failed",
        "bead": EXPECTED_BEAD,
        "outcome": outcome,
        "failure_signature": signature,
        "contract": str(contract_path),
        "summary": summary,
    }
    log_path.write_text(json.dumps(log_event, sort_keys=True) + "\n", encoding="utf-8")
    if outcome != "pass":
        raise SystemExit(f"FAIL[{signature}]: {message}")


def fail(signature: str, message: str, **summary):
    finish("fail", signature, message, **summary)


def require(condition: bool, signature: str, message: str, **summary):
    if not condition:
        fail(signature, message, **summary)


def non_empty(value, field: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), "field_missing", f"{field} must be a non-empty string", field=field)
    return value


def module_set_from_governance(gov: dict) -> set[str]:
    modules: set[str] = set()
    for rows in gov.get("classifications", {}).values():
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("module"), str):
                modules.add(row["module"])
    return modules


def classification_map(matrix: dict) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in matrix.get("modules", []):
        if isinstance(row, dict) and isinstance(row.get("module"), str):
            result[row["module"]] = str(row.get("classification", ""))
    return result


if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")

for path, label in [
    (contract_path, "contract"),
    (mod_rs_path, "runtime_math/mod.rs"),
    (linkage_path, "linkage"),
    (matrix_path, "classification matrix"),
    (manifest_path, "production manifest"),
    (governance_path, "governance"),
    (agents_path, "AGENTS.md"),
    (lib_rs_path, "membrane lib.rs"),
]:
    require(path.is_file(), "input_missing", f"{label} missing: {path}", label=label, path=str(path))

contract = load_json(contract_path)
linkage = load_json(linkage_path)
matrix = load_json(matrix_path)
manifest = load_json(manifest_path)
governance = load_json(governance_path)
mod_text = mod_rs_path.read_text(encoding="utf-8")
agents_text = agents_path.read_text(encoding="utf-8")
lib_text = lib_rs_path.read_text(encoding="utf-8")

require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected schema_version", actual=contract.get("schema_version"))
require(contract.get("generated_by_bead") == EXPECTED_BEAD, "generated_by_bead", "unexpected generated_by_bead", actual=contract.get("generated_by_bead"))
require(set(contract.get("source_todo_ids", [])) == EXPECTED_TODOS, "todo_set_drift", "source TODO ids drifted", actual=contract.get("source_todo_ids"))
require(contract.get("canonical_command") == EXPECTED_COMMAND, "canonical_command", "unexpected canonical_command", actual=contract.get("canonical_command"))

for rel_path in contract.get("input_artifacts", []):
    require((root / rel_path).is_file(), "input_artifact_missing", f"input artifact missing: {rel_path}", artifact=rel_path)

prior = contract.get("prior_gate_inventory", [])
require(isinstance(prior, list) and len(prior) >= 3, "prior_gate_inventory_missing", "prior gate inventory must list existing linkage/classification/proof gates")
for row in prior:
    gate_id = non_empty(row.get("gate_id"), "prior_gate_inventory.gate_id")
    artifact = non_empty(row.get("artifact"), f"{gate_id}.artifact")
    checker = non_empty(row.get("checker"), f"{gate_id}.checker")
    require(row.get("duplicates_current_gate") is False, "duplicate_gate_claim", f"{gate_id}: duplicates_current_gate must be false", gate_id=gate_id)
    if not artifact.startswith("target/"):
        require((root / artifact).is_file(), "prior_gate_artifact_missing", f"{gate_id}: prior artifact missing", artifact=artifact)
    require((root / checker).is_file(), "prior_gate_checker_missing", f"{gate_id}: prior checker missing", checker=checker)
    require(row.get("current_gate_adds"), "prior_gate_adds_missing", f"{gate_id}: current_gate_adds must describe non-duplicative coverage", gate_id=gate_id)

runtime_mods = set(re.findall(r"^pub mod ([a-z_]+);", mod_text, re.MULTILINE))
runtime_rs_files = {
    path.stem
    for path in (root / "crates/frankenlibc-membrane/src/runtime_math").glob("*.rs")
    if path.name != "mod.rs"
}
link_modules = set(linkage.get("modules", {}).keys())
matrix_modules = {
    str(row.get("module"))
    for row in matrix.get("modules", [])
    if isinstance(row, dict) and isinstance(row.get("module"), str)
}
gov_modules = module_set_from_governance(governance)
prod_modules = set(manifest.get("production_modules", []))
research_only_modules = set(manifest.get("research_only_modules", []))
manifest_modules = prod_modules | research_only_modules
classifications = classification_map(matrix)

auxiliary_rows = contract.get("auxiliary_runtime_math_sources", [])
require(isinstance(auxiliary_rows, list), "auxiliary_rows_invalid", "auxiliary_runtime_math_sources must be an array")
auxiliary_modules = {non_empty(row.get("module"), "auxiliary.module") for row in auxiliary_rows if isinstance(row, dict)}
source_only = runtime_rs_files - runtime_mods
require(source_only == auxiliary_modules, "missing_module", "runtime_math .rs files not declared in mod.rs must match auxiliary classifications", source_only=sorted(source_only), auxiliary=sorted(auxiliary_modules))
for row in auxiliary_rows:
    module = non_empty(row.get("module"), "auxiliary.module")
    source_path = root / non_empty(row.get("source_path"), f"{module}.source_path")
    linked_from = non_empty(row.get("linked_from"), f"{module}.linked_from")
    require(source_path.is_file(), "auxiliary_source_missing", f"{module}: auxiliary source missing", module=module, source_path=str(source_path))
    require(row.get("classification") == "crate_root_support_module", "auxiliary_classification", f"{module}: auxiliary classification drifted", module=module)
    require(f"pub mod {module};" in lib_text or f"mod {module};" in lib_text, "auxiliary_link_missing", f"{module}: crate root link missing", module=module, linked_from=linked_from)

missing_linkage = sorted(runtime_mods - link_modules)
extra_linkage = sorted(link_modules - runtime_mods)
require(not missing_linkage and not extra_linkage, "unlinked_module", "runtime_math mod.rs and linkage modules must match", missing=missing_linkage, extra=extra_linkage)

missing_matrix = sorted(runtime_mods - matrix_modules)
extra_matrix = sorted(matrix_modules - runtime_mods)
require(not missing_matrix and not extra_matrix, "classification_module_drift", "runtime_math mod.rs and classification matrix modules must match", missing=missing_matrix, extra=extra_matrix)

missing_governance = sorted(runtime_mods - gov_modules)
extra_governance = sorted(gov_modules - runtime_mods)
require(not missing_governance and not extra_governance, "governance_module_drift", "runtime_math mod.rs and governance module sets must match", missing=missing_governance, extra=extra_governance)

missing_manifest = sorted(runtime_mods - manifest_modules)
extra_manifest = sorted(manifest_modules - runtime_mods)
require(not missing_manifest and not extra_manifest, "manifest_module_drift", "runtime_math mod.rs and production manifest module sets must match", missing=missing_manifest, extra=extra_manifest)

research_in_prod = sorted(module for module in prod_modules if classifications.get(module) == "research")
require(not research_in_prod, "retired_module_leakage", "research/retired modules must not appear in production manifest", modules=research_in_prod)
for module in research_only_modules:
    require(classifications.get(module) == "research", "research_manifest_classification", f"{module}: research_only manifest row must be classified research", module=module, classification=classifications.get(module))

counts = Counter(classifications.values())
expected = contract.get("expected_current", {})
require(expected.get("runtime_math_pub_mod_count") == len(runtime_mods), "count_drift", "runtime_math pub mod count drifted", declared=expected.get("runtime_math_pub_mod_count"), actual=len(runtime_mods))
require(expected.get("runtime_math_rs_file_count") == len(runtime_rs_files), "count_drift", "runtime_math .rs file count drifted", declared=expected.get("runtime_math_rs_file_count"), actual=len(runtime_rs_files))
require(expected.get("auxiliary_runtime_math_source_count") == len(auxiliary_modules), "count_drift", "auxiliary source count drifted", declared=expected.get("auxiliary_runtime_math_source_count"), actual=len(auxiliary_modules))
require(expected.get("linkage_module_count") == len(link_modules), "count_drift", "linkage module count drifted", declared=expected.get("linkage_module_count"), actual=len(link_modules))
require(expected.get("classification_module_count") == len(matrix_modules), "count_drift", "classification module count drifted", declared=expected.get("classification_module_count"), actual=len(matrix_modules))
require(expected.get("governance_module_count") == len(gov_modules), "count_drift", "governance module count drifted", declared=expected.get("governance_module_count"), actual=len(gov_modules))
require(expected.get("production_manifest_modules") == len(prod_modules), "count_drift", "production manifest count drifted", declared=expected.get("production_manifest_modules"), actual=len(prod_modules))
require(expected.get("research_only_manifest_modules") == len(research_only_modules), "count_drift", "research-only manifest count drifted", declared=expected.get("research_only_manifest_modules"), actual=len(research_only_modules))
require(expected.get("classification_counts") == {key: counts[key] for key in sorted(counts)}, "classification_count_drift", "classification count summary drifted", declared=expected.get("classification_counts"), actual={key: counts[key] for key in sorted(counts)})
require(expected.get("research_modules_currently_in_production_manifest") == len(research_in_prod), "retired_module_leakage", "research production leakage count drifted", declared=expected.get("research_modules_currently_in_production_manifest"), actual=len(research_in_prod))

docs_rows = contract.get("docs_mandatory_module_audit", [])
require(isinstance(docs_rows, list) and docs_rows, "docs_mandatory_rows_missing", "docs_mandatory_module_audit must be non-empty")
linked_docs = 0
stale_docs = 0
seen_docs: set[str] = set()
for row in docs_rows:
    module = non_empty(row.get("module"), "docs.module")
    require(module not in seen_docs, "duplicate_docs_module", f"{module}: duplicate docs audit row", module=module)
    seen_docs.add(module)
    doc_token = non_empty(row.get("doc_token"), f"{module}.doc_token")
    classification = non_empty(row.get("classification"), f"{module}.classification")
    expected_source = root / non_empty(row.get("expected_source"), f"{module}.expected_source")
    require(doc_token in agents_text, "docs_token_missing", f"{module}: AGENTS mandatory token missing", module=module, token=doc_token)
    require(expected_source.is_file(), "docs_source_missing", f"{module}: expected source missing", module=module, source=str(expected_source))
    if classification == "runtime_math_linked":
        linked_docs += 1
        require(module in runtime_mods, "docs_runtime_module_missing", f"{module}: documented runtime_math module is not linked from mod.rs", module=module)
        require(module in link_modules and module in matrix_modules, "docs_runtime_module_missing", f"{module}: documented runtime_math module lacks linkage/classification", module=module)
    elif classification == "documented_as_runtime_math_but_standalone":
        stale_docs += 1
        require(module not in runtime_mods, "stale_doc_classification_drift", f"{module}: stale-doc row now appears in runtime_math/mod.rs", module=module)
        require(f"pub mod {module};" in lib_text, "standalone_link_missing", f"{module}: standalone module not linked from membrane lib.rs", module=module)
        require(isinstance(row.get("stale_doc_note"), str) and row["stale_doc_note"].strip(), "stale_doc_note_missing", f"{module}: stale-doc classification needs a note", module=module)
    else:
        fail("docs_classification_invalid", f"{module}: invalid docs classification {classification}", module=module)

require(expected.get("docs_mandatory_rows") == len(docs_rows), "docs_mandatory_row_count", "docs mandatory row count drifted", declared=expected.get("docs_mandatory_rows"), actual=len(docs_rows))
require(expected.get("docs_runtime_math_linked_rows") == linked_docs, "docs_linked_count", "docs linked count drifted", declared=expected.get("docs_runtime_math_linked_rows"), actual=linked_docs)
require(expected.get("docs_stale_external_rows") == stale_docs, "docs_stale_count", "docs stale external count drifted", declared=expected.get("docs_stale_external_rows"), actual=stale_docs)

negative_signatures = {
    row.get("expected_failure_signature")
    for row in contract.get("negative_tests", [])
    if isinstance(row, dict)
}
for signature in contract.get("required_failure_signatures", []):
    require(signature in negative_signatures, "negative_test_missing", f"missing negative test declaration for {signature}", expected_signature=signature)

finish(
    "pass",
    "none",
    "runtime_math required-module gate validated",
    runtime_math_pub_mod_count=len(runtime_mods),
    runtime_math_rs_file_count=len(runtime_rs_files),
    auxiliary_runtime_math_sources=sorted(auxiliary_modules),
    classification_counts={key: counts[key] for key in sorted(counts)},
    production_manifest_modules=len(prod_modules),
    research_only_manifest_modules=len(research_only_modules),
    docs_runtime_math_linked_rows=linked_docs,
    docs_stale_external_rows=stale_docs,
)
PY

echo "PASS: runtime_math required-module gate validated"
