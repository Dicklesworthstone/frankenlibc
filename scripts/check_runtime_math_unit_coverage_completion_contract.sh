#!/usr/bin/env bash
# check_runtime_math_unit_coverage_completion_contract.sh - bd-5vr.6.1 completion evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_UNIT_COVERAGE_CONTRACT:-${ROOT}/tests/conformance/runtime_math_unit_coverage_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_UNIT_COVERAGE_REPORT:-${ROOT}/target/conformance/runtime_math_unit_coverage_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_UNIT_COVERAGE_LOG:-${ROOT}/target/conformance/runtime_math_unit_coverage_completion_contract.log.jsonl}"
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

ORIGINAL_BEAD = "bd-5vr.6"
COMPLETION_DEBT_BEAD = "bd-5vr.6.1"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.property.primary",
}
REQUIRED_COVERAGE_GROUPS = {
    "per_kernel_correctness",
    "numerical_stability",
    "certificate_verification",
    "property_coverage",
    "deterministic_e2e",
}
REQUIRED_EVENT = "runtime_math_unit_coverage_completion_contract_validated"
REQUIRED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "coverage_group_count",
    "unit_test_refs",
    "e2e_test_refs",
    "property_test_refs",
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


def validate_test_refs(section_name, refs, source_texts, errors):
    found = []
    if not isinstance(refs, list) or not refs:
        errors.append(f"{section_name}.required_test_refs missing")
        return found
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
    return found


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
    found = validate_test_refs(
        section_name,
        section.get("required_test_refs"),
        source_texts,
        errors,
    )
    for command in as_list(section.get("required_commands")):
        if not isinstance(command, str):
            errors.append(f"{section_name}.required_commands entry must be string")
            continue
        if "cargo " in command and not (
            "rch exec" in command or command.startswith("rch cargo ")
        ):
            errors.append(f"{section_name} cargo command must be rch-backed: {command}")
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

require(
    contract.get("schema_version") == "runtime_math_unit_coverage_completion_contract.v1",
    "schema_version mismatch",
    errors,
)
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

test_sources = evidence.get("test_sources")
if not isinstance(test_sources, dict):
    errors.append("test_sources must be an object")
    test_sources = {}
source_texts = {
    key: read_source(path, key, errors)
    for key, path in test_sources.items()
}

coverage_groups = source_contract.get("coverage_groups")
if not isinstance(coverage_groups, list):
    errors.append("source_contract.coverage_groups must be a list")
    coverage_groups = []
coverage_group_names = {
    group.get("name")
    for group in coverage_groups
    if isinstance(group, dict)
}
require(
    REQUIRED_COVERAGE_GROUPS <= coverage_group_names,
    f"missing coverage groups: {sorted(REQUIRED_COVERAGE_GROUPS - coverage_group_names)}",
    errors,
)

coverage_test_refs = []
for group in coverage_groups:
    if not isinstance(group, dict):
        errors.append("source_contract.coverage_groups entries must be objects")
        continue
    name = group.get("name")
    require(isinstance(name, str) and name, "coverage group name missing", errors)
    for ref in as_list(group.get("implementation_refs")):
        assert_file_line_ref(ref, errors)
    coverage_test_refs.extend(
        validate_test_refs(
            f"coverage_groups.{name}",
            group.get("required_test_refs"),
            source_texts,
            errors,
        )
    )

artifact_refs = []
for artifact in as_list(source_contract.get("required_artifacts")):
    if not isinstance(artifact, str):
        errors.append("source_contract.required_artifacts entries must be strings")
        continue
    artifact_refs.append(artifact)
    require(workspace_path(artifact).is_file(), f"required artifact missing: {artifact}", errors)

production_manifest = load_json(
    root / "tests/runtime_math/production_kernel_manifest.v1.json",
    "production kernel manifest",
    errors,
)
manifest_modules = set(as_list(production_manifest.get("production_modules"))) | set(
    as_list(production_manifest.get("research_only_modules"))
)
require(
    len(manifest_modules) >= 69,
    "production kernel manifest should cover the checked-in runtime-math module set",
    errors,
)
require(
    production_manifest.get("source_mod_rs") == "crates/frankenlibc-membrane/src/runtime_math/mod.rs",
    "production kernel manifest source_mod_rs drifted",
    errors,
)
runtime_linkage = load_json(
    root / "tests/runtime_math/runtime_math_linkage.v1.json",
    "runtime math linkage",
    errors,
)
linkage_modules = runtime_linkage.get("modules", {})
require(isinstance(linkage_modules, dict) and len(linkage_modules) >= 69, "runtime linkage should cover the checked-in runtime-math module set", errors)
require(
    isinstance(linkage_modules, dict) and len(linkage_modules) == len(manifest_modules),
    "runtime linkage and production manifest module counts should match",
    errors,
)
classification_matrix = load_json(
    root / "tests/runtime_math/runtime_math_classification_matrix.v1.json",
    "runtime math classification matrix",
    errors,
)
require(
    classification_matrix.get("schema_version") in {"runtime_math_classification_matrix.v1", "v1"},
    "classification matrix schema drifted",
    errors,
)
golden = load_json(
    root / "tests/runtime_math/golden/kernel_snapshot_smoke.v1.json",
    "runtime math golden snapshot",
    errors,
)
require(isinstance(golden, dict) and len(golden) > 0, "runtime math golden snapshot must be non-empty", errors)
sha256sums = workspace_path("tests/runtime_math/golden/sha256sums.txt")
if sha256sums.is_file():
    require(
        "kernel_snapshot_smoke.v1.json" in sha256sums.read_text(encoding="utf-8"),
        "golden sha256sums must include kernel snapshot",
        errors,
    )

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
property_test_refs = validate_test_section(
    "property_primary",
    "tests.property.primary",
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
failure_signature = "none" if status == "pass" else "runtime_math_unit_coverage_completion_contract_failed"
artifact_refs = sorted(set(artifact_refs + [rel(contract_path), rel(report_path), rel(log_path)]))
row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD}:runtime_math_unit_coverage",
    "event": REQUIRED_EVENT,
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "coverage_group_count": len(coverage_group_names),
    "unit_test_refs": sorted(set(unit_test_refs)),
    "e2e_test_refs": sorted(set(e2e_test_refs)),
    "property_test_refs": sorted(set(property_test_refs)),
    "artifact_refs": artifact_refs,
    "failure_signature": failure_signature,
}
report = {
    "schema_version": "runtime_math_unit_coverage_completion_contract.report.v1",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "contract": rel(contract_path),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "coverage_group_count": len(coverage_group_names),
    "coverage_groups": sorted(str(name) for name in coverage_group_names if isinstance(name, str)),
    "coverage_test_refs": sorted(set(coverage_test_refs)),
    "unit_test_refs": sorted(set(unit_test_refs)),
    "e2e_test_refs": sorted(set(e2e_test_refs)),
    "property_test_refs": sorted(set(property_test_refs)),
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
