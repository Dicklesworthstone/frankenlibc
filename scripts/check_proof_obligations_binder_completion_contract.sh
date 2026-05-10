#!/usr/bin/env bash
# check_proof_obligations_binder_completion_contract.sh - bd-5fw.4.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_PROOF_BINDER_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/proof_obligations_binder_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_PROOF_BINDER_COMPLETION_REPORT:-${OUT_DIR}/proof_obligations_binder_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_PROOF_BINDER_COMPLETION_LOG:-${OUT_DIR}/proof_obligations_binder_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT_PATH}" "${REPORT_PATH}" "${LOG_PATH}" <<'PY'
import json
import subprocess
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

errors = []
events = []


def load_json(path):
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        errors.append(f"failed to load {path}: {exc}")
        return {}


def rel_path(path_s):
    path = Path(path_s)
    return path if path.is_absolute() else root / path


def require(condition, message):
    if not condition:
        errors.append(message)


def as_list(value):
    return value if isinstance(value, list) else []


def file_line_ref_exists(file_line_ref):
    if ":" not in file_line_ref:
        errors.append(f"file-line ref should contain ':' ({file_line_ref})")
        return False
    path_s, line_s = file_line_ref.rsplit(":", 1)
    try:
        line_no = int(line_s)
    except ValueError:
        errors.append(f"file-line ref line is not numeric: {file_line_ref}")
        return False
    if line_no < 1:
        errors.append(f"file-line ref line must be positive: {file_line_ref}")
        return False
    path = rel_path(path_s)
    if not path.is_file():
        errors.append(f"file-line ref path missing: {file_line_ref}")
        return False
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if line_no > len(lines) or not lines[line_no - 1].strip():
        errors.append(f"file-line ref should point to a non-empty line: {file_line_ref}")
        return False
    return True


def run_static_gate(command):
    started = time.monotonic_ns()
    result = subprocess.run(
        ["bash", *command.split()[1:]],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    latency_ns = time.monotonic_ns() - started
    if result.returncode != 0:
        errors.append(
            f"{command} failed with {result.returncode}: stdout={result.stdout} stderr={result.stderr}"
        )
    return result.returncode == 0, latency_ns


def emit_event(event, status, details, latency_ns=0):
    row = {
        "trace_id": f"bd-5fw.4.1:{event}",
        "mode": "strict",
        "api_family": "proof_binder",
        "symbol": "proof_obligations_binder",
        "decision_path": "completion_contract+proof_binder+static_gate+structured_telemetry",
        "healing_action": "none",
        "errno": 0 if status == "pass" else 1,
        "latency_ns": int(latency_ns),
        "artifact_refs": [
            "tests/conformance/proof_obligations_binder_completion_contract.v1.json",
            "tests/conformance/proof_obligations_binder.v1.json",
            "tests/conformance/proof_binder_validation.v1.json",
            "tests/conformance/proof_traceability_check.json",
            "tests/conformance/fpg_proof_core_safety_gate.v1.json",
            "tests/conformance/proof_traceability_freshness_gate.v1.json",
            "scripts/check_proof_obligations_binder_completion_contract.sh",
        ],
        "event": event,
        "status": status,
        "bead_id": "bd-5fw.4",
        "completion_debt_bead": "bd-5fw.4.1",
        "failure_signature": "none" if status == "pass" else "proof_obligations_binder_completion_contract_failed",
        "details": details,
    }
    events.append(row)
    return row


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
policy = evidence.get("proof_binder_contract", {})
telemetry = evidence.get("telemetry_primary", {})

require(contract.get("schema") == "proof_obligations_binder_completion_contract.v1", "contract schema mismatch")
require(contract.get("bead") == "bd-5fw.4", "contract bead must be bd-5fw.4")
require(contract.get("completion_debt_bead") == "bd-5fw.4.1", "completion_debt_bead must be bd-5fw.4.1")
require(set(evidence.get("missing_items", [])) == {"tests.e2e.primary", "telemetry.primary"}, "missing_items mismatch")

for ref in as_list(evidence.get("implementation_refs")):
    file_line_ref_exists(str(ref))

required_fields = telemetry.get("required_fields", [])
for field in [
    "trace_id",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
    "event",
    "status",
    "bead_id",
    "completion_debt_bead",
    "failure_signature",
]:
    require(field in required_fields, f"telemetry required_fields missing {field}")

binder = load_json(rel_path(policy.get("binder_path", "")))
validation = load_json(rel_path(policy.get("validation_path", "")))
traceability = load_json(rel_path(policy.get("traceability_path", "")))
freshness_gate = load_json(rel_path(policy.get("freshness_gate", "")))
proof_core_gate = load_json(rel_path(policy.get("proof_core_gate", "")))

obligations = as_list(binder.get("obligations"))
obligation_ids = [ob.get("id") for ob in obligations]
categories = sorted((binder.get("categories") or {}).keys())
source_refs = [ref for ob in obligations for ref in as_list(ob.get("source_refs"))]
evidence_artifacts = sorted({item for ob in obligations for item in as_list(ob.get("evidence_artifacts"))})
gate_scripts = sorted({item for ob in obligations for item in as_list(ob.get("gates"))})

require(len(obligations) >= int(policy.get("minimum_obligations", 0)), "binder obligation count below contract minimum")
require(len(categories) >= int(policy.get("minimum_categories", 0)), "binder category count below contract minimum")
require(len(source_refs) >= int(policy.get("minimum_source_refs", 0)), "binder source_ref count below contract minimum")
require(len(evidence_artifacts) >= int(policy.get("minimum_unique_evidence_artifacts", 0)), "binder evidence artifact count below contract minimum")
require(len(gate_scripts) >= int(policy.get("minimum_unique_gate_scripts", 0)), "binder gate script count below contract minimum")

for obligation_id in policy.get("required_obligation_ids", []):
    require(obligation_id in obligation_ids, f"required obligation missing: {obligation_id}")
for category in policy.get("required_categories", []):
    require(category in categories, f"required category missing: {category}")
for gate_script in policy.get("required_gate_scripts", []):
    require(gate_script in gate_scripts or rel_path(gate_script).is_file(), f"required gate script missing: {gate_script}")
for artifact in policy.get("required_evidence_artifacts", []):
    require(artifact in evidence_artifacts or rel_path(artifact).is_file(), f"required evidence artifact missing: {artifact}")

require(validation.get("binder_valid") is True, "proof_binder_validation.binder_valid must be true")
require(traceability.get("binder_valid") is True, "proof_traceability_check.binder_valid must be true")
require(validation.get("total_violations") == 0, "proof_binder_validation.total_violations must be 0")
require(validation.get("total_obligations") == len(obligations), "validation total_obligations must match binder")
require(len(as_list(traceability.get("obligations"))) == len(obligations), "traceability obligation count must match binder")

require(freshness_gate.get("freshness_policy", {}).get("default_decision") == "block_until_all_source_refs_resolve", "freshness gate policy drift")
require(proof_core_gate.get("claim_policy", {}).get("default_decision") == "block_until_proof_witness_current", "proof-core gate policy drift")
require(len(as_list(proof_core_gate.get("rows"))) >= 7, "proof-core gate must keep seven rows")

for section in ["e2e_primary"]:
    for command in evidence.get(section, {}).get("required_commands", []):
        if "cargo test" in command:
            require("rch exec" in command or command.startswith("rch cargo "), f"{section} cargo command must be rch-backed: {command}")

emit_event(
    "proof_obligations_binder_contract_validated",
    "pass" if not errors else "fail",
    {
        "obligations": len(obligations),
        "categories": len(categories),
        "source_refs": len(source_refs),
        "evidence_artifacts": len(evidence_artifacts),
        "gate_scripts": len(gate_scripts),
    },
)

gate_latency = 0
for command in [
    "bash scripts/check_proof_traceability_freshness.sh --validate-only",
    "bash scripts/check_fpg_proof_core_safety_gate.sh --validate-only",
]:
    _, latency_ns = run_static_gate(command)
    gate_latency += latency_ns

emit_event(
    "proof_obligations_binder_e2e_validated",
    "pass" if not errors else "fail",
    {
        "scripts": evidence.get("e2e_primary", {}).get("required_scripts", []),
        "commands": evidence.get("e2e_primary", {}).get("required_commands", []),
    },
    gate_latency,
)

required_events = set(telemetry.get("required_events", []))
actual_events = {row["event"] for row in events}
if not required_events.issubset(actual_events | {"proof_obligations_binder_telemetry_validated"}):
    errors.append(f"telemetry required_events mismatch: missing {sorted(required_events - actual_events)}")

emit_event(
    "proof_obligations_binder_telemetry_validated",
    "pass" if not errors else "fail",
    {"required_fields": required_fields, "required_events": sorted(required_events)},
)

status = "pass" if not errors else "fail"
for row in events:
    if status == "fail":
        row["status"] = "fail"
        row["errno"] = 1
        row["failure_signature"] = "proof_obligations_binder_completion_contract_failed"

log_path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in events) + "\n")
report = {
    "schema": "proof_obligations_binder_completion_contract.report.v1",
    "status": status,
    "bead": "bd-5fw.4",
    "completion_debt_bead": "bd-5fw.4.1",
    "errors": errors,
    "summary": {
        "obligation_count": len(obligations),
        "category_count": len(categories),
        "source_ref_count": len(source_refs),
        "unique_evidence_artifact_count": len(evidence_artifacts),
        "unique_gate_script_count": len(gate_scripts),
        "proof_core_rows": len(as_list(proof_core_gate.get("rows"))),
        "event_count": len(events),
    },
    "required_fields": required_fields,
    "events": [row["event"] for row in events],
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

if errors:
    print(f"FAIL: proof obligations binder completion contract ({len(errors)} errors)", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: proof obligations binder completion contract "
    f"(obligations={len(obligations)}, categories={len(categories)}, "
    f"source_refs={len(source_refs)}, proof_core_rows={len(as_list(proof_core_gate.get('rows')))}, "
    f"report={report_path.relative_to(root)})"
)
PY
