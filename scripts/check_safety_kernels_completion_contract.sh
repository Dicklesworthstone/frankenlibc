#!/usr/bin/env bash
# check_safety_kernels_completion_contract.sh - bd-5vr.2.1 completion evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_SAFETY_KERNELS_CONTRACT:-${ROOT}/tests/conformance/safety_kernels_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_SAFETY_KERNELS_REPORT:-${ROOT}/target/conformance/safety_kernels_completion_contract.report.json}"
LOG="${FRANKENLIBC_SAFETY_KERNELS_LOG:-${ROOT}/target/conformance/safety_kernels_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

ORIGINAL_BEAD = "bd-5vr.2"
COMPLETION_DEBT_BEAD = "bd-5vr.2.1"
REQUIRED_KERNELS = {
    "galois_connection",
    "runtime_barrier",
    "sos_barrier",
    "sos_invariant",
    "hji_reachability",
}
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
REQUIRED_EVENT = "safety_kernels_completion_contract_validated"
REQUIRED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "kernel_count",
    "unit_test_refs",
    "e2e_test_refs",
    "artifact_refs",
    "failure_signature",
}


def rel(path):
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def workspace_path(path_text):
    path = Path(str(path_text))
    if path.is_absolute():
        return path
    return root / path


def as_list(value):
    return value if isinstance(value, list) else []


def require(condition, message, errors):
    if not condition:
        errors.append(message)


def load_json(path, label, errors):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}


def read_source(path_text, source_name, errors):
    if not isinstance(path_text, str) or not path_text:
        errors.append(f"test_sources.{source_name} missing")
        return ""
    path = workspace_path(path_text)
    if not path.is_file():
        errors.append(f"test_sources.{source_name} path missing: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"test_sources.{source_name} unreadable: {path_text}: {exc}")
        return ""


def assert_file_line_ref(ref, errors):
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"invalid file-line ref: {ref!r}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        errors.append(f"invalid file-line ref line: {ref}")
        return
    path = workspace_path(path_text)
    if line_no <= 0 or not path.is_file():
        errors.append(f"file-line ref missing path or positive line: {ref}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no > len(lines) or not lines[line_no - 1].strip():
        errors.append(f"file-line ref should point to a non-empty line: {ref}")


def function_exists(source_text, name):
    return f"fn {name}(" in source_text or f"fn {name}<" in source_text


def validate_test_section(section_name, missing_item_id, evidence, source_texts, errors):
    section = evidence.get(section_name)
    if not isinstance(section, dict):
        errors.append(f"{section_name} missing")
        return []
    require(
        section.get("missing_item_id") == missing_item_id,
        f"{section_name}.missing_item_id must be {missing_item_id}",
        errors,
    )
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        errors.append(f"{section_name}.required_test_refs missing")
        return []

    found = []
    for ref in refs:
        if not isinstance(ref, dict):
            errors.append(f"{section_name}.required_test_refs entry must be object")
            continue
        source_key = ref.get("source")
        name = ref.get("name")
        if not isinstance(source_key, str) or source_key not in source_texts:
            errors.append(f"{section_name} references undeclared source {source_key!r}")
            continue
        if not isinstance(name, str) or not function_exists(source_texts[source_key], name):
            errors.append(f"{section_name} references missing test {source_key}::{name}")
            continue
        found.append(f"{source_key}::{name}")

    for command in as_list(section.get("required_commands")):
        if not isinstance(command, str):
            errors.append(f"{section_name}.required_commands entry must be string")
            continue
        if "cargo " in command and not (
            "rch exec" in command or command.startswith("rch cargo ")
        ):
            errors.append(f"{section_name} cargo command must be rch-backed: {command}")
        if (
            "check_runtime_math_hji_viability_proofs.sh" in command
            or "check_runtime_math_linkage_proofs.sh" in command
        ) and not command.startswith("rch exec"):
            errors.append(f"{section_name} cargo-bearing gate must be run through rch: {command}")
    return found


errors = []
contract = load_json(contract_path, "contract", errors)
source_contract = contract.get("source_contract")
evidence = contract.get("completion_debt_evidence")
if not isinstance(source_contract, dict):
    errors.append("source_contract must be an object")
    source_contract = {}
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}

require(contract.get("schema_version") == "safety_kernels_completion_contract.v1", "schema_version mismatch", errors)
require(contract.get("bead") == ORIGINAL_BEAD, f"bead must be {ORIGINAL_BEAD}", errors)
require(
    contract.get("completion_debt_bead") == COMPLETION_DEBT_BEAD,
    f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}",
    errors,
)
require(
    int(contract.get("next_audit_score_threshold", 0)) >= 800,
    "next_audit_score_threshold must be >= 800",
    errors,
)
require(evidence.get("bead") == COMPLETION_DEBT_BEAD, f"evidence.bead must be {COMPLETION_DEBT_BEAD}", errors)
require(evidence.get("original_bead") == ORIGINAL_BEAD, f"evidence.original_bead must be {ORIGINAL_BEAD}", errors)
require(set(as_list(evidence.get("missing_items"))) == REQUIRED_MISSING_ITEMS, "missing_items mismatch", errors)

kernels = source_contract.get("kernels")
if not isinstance(kernels, list):
    errors.append("source_contract.kernels must be a list")
    kernels = []
kernel_names = {kernel.get("name") for kernel in kernels if isinstance(kernel, dict)}
require(REQUIRED_KERNELS <= kernel_names, f"missing kernels: {sorted(REQUIRED_KERNELS - kernel_names)}", errors)

runtime_linkage = load_json(root / "tests/runtime_math/runtime_math_linkage.v1.json", "runtime linkage", errors)
linkage_modules = runtime_linkage.get("modules", {})
production_manifest = load_json(
    root / "tests/runtime_math/production_kernel_manifest.v1.json",
    "production kernel manifest",
    errors,
)
manifest_modules = set(as_list(production_manifest.get("production_modules"))) | set(
    as_list(production_manifest.get("research_only_modules"))
)
proof_traceability = load_json(
    root / "tests/conformance/proof_traceability_check.json",
    "proof traceability check",
    errors,
)

for kernel in kernels:
    if not isinstance(kernel, dict):
        errors.append("source_contract.kernels entries must be objects")
        continue
    name = kernel.get("name")
    module_path = kernel.get("module_path")
    require(isinstance(name, str) and name, "kernel.name missing", errors)
    require(isinstance(module_path, str) and workspace_path(module_path).is_file(), f"{name}.module_path missing: {module_path}", errors)
    for ref in as_list(kernel.get("implementation_refs")) + as_list(kernel.get("proof_refs")):
        assert_file_line_ref(ref, errors)
    proof_note = kernel.get("proof_note")
    if proof_note is not None:
        require(workspace_path(proof_note).is_file(), f"{name}.proof_note missing: {proof_note}", errors)
    linkage_name = kernel.get("runtime_linkage_module")
    if linkage_name:
        require(linkage_name in linkage_modules, f"{name}.runtime_linkage_module missing from linkage ledger", errors)
        require(linkage_name in manifest_modules, f"{name}.runtime_linkage_module missing from production manifest", errors)
    for obligation_id in as_list(kernel.get("proof_obligations")):
        require(str(obligation_id) in json.dumps(proof_traceability), f"{name}.proof_obligation missing from traceability: {obligation_id}", errors)

artifact_refs = []
for artifact in as_list(source_contract.get("required_artifacts")):
    if not isinstance(artifact, str):
        errors.append("source_contract.required_artifacts entries must be strings")
        continue
    artifact_refs.append(artifact)
    require(workspace_path(artifact).is_file(), f"required artifact missing: {artifact}", errors)

hji_artifact = load_json(root / "tests/runtime_math/hji_viability_computation.json", "HJI viability artifact", errors)
require(hji_artifact.get("model") == "discrete_hji_risk_latency_adverse", "HJI model drifted", errors)
require(hji_artifact.get("state_count") == 64, "HJI state_count must be 64", errors)
require(hji_artifact.get("safe_kernel_volume") == 48, "HJI safe_kernel_volume must be 48", errors)
require(len(as_list(hji_artifact.get("boundary_witnesses"))) >= 5, "HJI boundary witnesses must cover at least five states", errors)

test_sources = evidence.get("test_sources")
if not isinstance(test_sources, dict):
    errors.append("test_sources must be an object")
    test_sources = {}
source_texts = {
    key: read_source(path, key, errors)
    for key, path in test_sources.items()
}

unit_test_refs = validate_test_section(
    "unit_primary",
    "tests.unit.primary",
    evidence,
    source_texts,
    errors,
)
e2e_test_refs = validate_test_section(
    "e2e_primary",
    "tests.e2e.primary",
    evidence,
    source_texts,
    errors,
)

for script in as_list(evidence.get("e2e_primary", {}).get("required_scripts")):
    if not isinstance(script, str):
        errors.append("e2e_primary.required_scripts entries must be strings")
        continue
    script_path = workspace_path(script)
    require(script_path.is_file(), f"required script missing: {script}", errors)
    require(script_path.stat().st_mode & 0o111, f"required script must be executable: {script}", errors)

gate = evidence.get("gate")
if not isinstance(gate, str) or not workspace_path(gate).is_file():
    errors.append("completion_debt_evidence.gate missing")
else:
    require(workspace_path(gate).stat().st_mode & 0o111, f"completion gate must be executable: {gate}", errors)

telemetry = evidence.get("telemetry_primary")
if not isinstance(telemetry, dict):
    errors.append("telemetry_primary missing")
    telemetry = {}
require(telemetry.get("required_events") == [REQUIRED_EVENT], "telemetry_primary.required_events drifted", errors)
required_fields = set(as_list(telemetry.get("required_fields")))
require(REQUIRED_TELEMETRY_FIELDS <= required_fields, "telemetry_primary.required_fields missing keys", errors)
for ref in as_list(telemetry.get("required_test_refs")):
    if not isinstance(ref, dict):
        errors.append("telemetry_primary.required_test_refs entry must be object")
        continue
    source_key = ref.get("source")
    name = ref.get("name")
    if not isinstance(source_key, str) or source_key not in source_texts:
        errors.append(f"telemetry_primary references undeclared source {source_key!r}")
    elif not isinstance(name, str) or not function_exists(source_texts[source_key], name):
        errors.append(f"telemetry_primary references missing test {source_key}::{name}")

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
status = "pass" if not errors else "fail"
failure_signature = "none" if status == "pass" else "safety_kernels_completion_contract_failed"
artifact_refs = sorted(set(artifact_refs + [rel(contract_path), rel(report_path), rel(log_path)]))
row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD}:safety_kernels",
    "event": REQUIRED_EVENT,
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "kernel_count": len(kernel_names),
    "unit_test_refs": sorted(set(unit_test_refs)),
    "e2e_test_refs": sorted(set(e2e_test_refs)),
    "artifact_refs": artifact_refs,
    "failure_signature": failure_signature,
}
report = {
    "schema_version": "safety_kernels_completion_contract.report.v1",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "contract": rel(contract_path),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "kernel_count": len(kernel_names),
    "kernel_names": sorted(str(name) for name in kernel_names if isinstance(name, str)),
    "unit_test_refs": sorted(set(unit_test_refs)),
    "e2e_test_refs": sorted(set(e2e_test_refs)),
    "artifact_refs": artifact_refs,
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"REPORT={rel(report_path)}")
print(f"LOG={rel(log_path)}")
for error in errors:
    print(f"ERROR: {error}")

if errors:
    sys.exit(1)
PY
