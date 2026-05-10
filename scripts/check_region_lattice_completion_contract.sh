#!/usr/bin/env bash
# check_region_lattice_completion_contract.sh — bd-32e.3.1 completion-debt evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_REGION_LATTICE_CONTRACT:-${ROOT}/tests/conformance/region_lattice_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_REGION_LATTICE_REPORT:-${ROOT}/target/conformance/region_lattice_completion_contract.report.json}"
LOG="${FRANKENLIBC_REGION_LATTICE_LOG:-${ROOT}/target/conformance/region_lattice_completion_contract.log.jsonl}"
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

COMPLETION_DEBT_BEAD = "bd-32e.3.1"
ORIGINAL_BEAD = "bd-32e.3"
REQUIRED_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}
REQUIRED_EVENT = "region_lattice_completion_contract_validated"
REQUIRED_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "law_count",
    "test_refs",
    "artifact_refs",
    "failure_signature",
}


def rel(path):
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


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
    path = root / path_text
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
    path = root / path_text
    if line_no <= 0 or not path.is_file():
        errors.append(f"file-line ref missing path or positive line: {ref}")
        return
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if line_no > line_count:
        errors.append(f"file-line ref outside file: {ref}")


def function_exists(source_text, name):
    return f"fn {name}(" in source_text


errors = []
contract = load_json(contract_path, "contract", errors)
evidence = contract.get("completion_debt_evidence")
source_contract = contract.get("source_contract")
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}
if not isinstance(source_contract, dict):
    errors.append("source_contract must be an object")
    source_contract = {}

if contract.get("bead") != ORIGINAL_BEAD:
    errors.append(f"bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")
if evidence.get("bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD}")
if evidence.get("original_bead") != ORIGINAL_BEAD:
    errors.append(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
if evidence.get("next_audit_score_threshold", 0) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

states = source_contract.get("lattice_states", [])
if states != ["Valid", "Readable", "Writable", "Quarantined", "Freed", "Invalid", "Unknown"]:
    errors.append("lattice_states drifted from SafetyState rank order")
laws = source_contract.get("required_laws", [])
if not isinstance(laws, list) or len(laws) < 10:
    errors.append("required_laws must name the lattice proof obligations")

for ref in source_contract.get("implementation_refs", []) + source_contract.get("proof_refs", []):
    assert_file_line_ref(ref, errors)

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict):
    errors.append("test_sources must be an object")
    test_sources = {}
source_texts = {
    key: read_source(path, key, errors)
    for key, path in test_sources.items()
}

test_refs = []
for section, missing_item_id in REQUIRED_SECTIONS.items():
    block = evidence.get(section)
    if not isinstance(block, dict):
        errors.append(f"{section} missing")
        continue
    if block.get("missing_item_id") != missing_item_id:
        errors.append(f"{section}.missing_item_id must be {missing_item_id}")
    refs = block.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        errors.append(f"{section}.required_test_refs missing")
        continue
    for ref in refs:
        if not isinstance(ref, dict):
            errors.append(f"{section}.required_test_refs entry must be object")
            continue
        source_key = ref.get("source")
        name = ref.get("name")
        if not isinstance(source_key, str) or source_key not in source_texts:
            errors.append(f"{section} references undeclared source {source_key!r}")
            continue
        if not isinstance(name, str) or not function_exists(source_texts[source_key], name):
            errors.append(f"{section} references missing test {source_key}::{name}")
            continue
        test_refs.append(f"{source_key}::{name}")

gate = evidence.get("gate")
if not isinstance(gate, str) or not (root / gate).is_file():
    errors.append("completion_debt_evidence.gate missing")
elif not (root / gate).stat().st_mode & 0o111:
    errors.append(f"completion_debt_evidence.gate must be executable: {gate}")

telemetry = evidence.get("telemetry_primary", {})
events = telemetry.get("required_events")
if events != [REQUIRED_EVENT]:
    errors.append("telemetry_primary.required_events drifted")
fields = telemetry.get("required_fields")
if not isinstance(fields, list) or not REQUIRED_FIELDS <= set(fields):
    errors.append("telemetry_primary.required_fields missing required keys")

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
status = "pass" if not errors else "fail"
failure_signature = "none" if not errors else "region_lattice_contract_validation_error"
artifact_refs = [rel(contract_path), rel(report_path), rel(log_path)]
row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD}:region_lattice",
    "event": REQUIRED_EVENT,
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "law_count": len(laws) if isinstance(laws, list) else 0,
    "test_refs": sorted(set(test_refs)),
    "artifact_refs": artifact_refs,
    "failure_signature": failure_signature,
}
report = {
    "schema_version": "region_lattice_completion_contract.report.v1",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "contract": rel(contract_path),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "law_count": len(laws) if isinstance(laws, list) else 0,
    "test_refs": sorted(set(test_refs)),
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
