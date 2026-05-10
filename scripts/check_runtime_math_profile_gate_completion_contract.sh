#!/usr/bin/env bash
# check_runtime_math_profile_gate_completion_contract.sh - bd-1iya.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_RUNTIME_MATH_PROFILE_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/runtime_math_profile_gate_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_RUNTIME_MATH_PROFILE_COMPLETION_REPORT:-${OUT_DIR}/runtime_math_profile_gate_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_RUNTIME_MATH_PROFILE_COMPLETION_LOG:-${OUT_DIR}/runtime_math_profile_gate_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}"

export FLC_ROOT="${ROOT}"
export FLC_CONTRACT_PATH="${CONTRACT_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"
export FLC_LOG_PATH="${LOG_PATH}"

python3 - <<'PY'
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import tomllib

root = Path(os.environ["FLC_ROOT"])
contract_path = Path(os.environ["FLC_CONTRACT_PATH"])
report_path = Path(os.environ["FLC_REPORT_PATH"])
log_path = Path(os.environ["FLC_LOG_PATH"])
ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

errors: list[str] = []
events: list[dict[str, Any]] = []

REQUIRED_EVENTS = {
    "runtime_math_profile_gate_feature_architecture_validated",
    "runtime_math_profile_gate_unit_evidence_validated",
    "runtime_math_profile_gate_completion_contract_validated",
    "runtime_math_profile_gate_completion_contract_failed",
}

REQUIRED_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "mode",
    "api_family",
    "symbol",
    "outcome",
    "errno",
    "timing_ns",
    "artifact_refs",
    "failure_signature",
}

REQUIRED_FEATURE_BINDINGS = {
    'default = ["runtime-math-production"]',
    "runtime-math-production = []",
    'runtime-math-research = ["runtime-math-production"]',
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def rel_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay under workspace root: {value}")
    return root / path


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


SOURCE_COMMIT = source_commit()


def event_payload(event: str, status: str, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "timestamp": ts,
        "trace_id": f"bd-1iya.1:{event}",
        "event": event,
        "completion_debt_bead": "bd-1iya.1",
        "original_bead": "bd-1iya",
        "source_commit": SOURCE_COMMIT,
        "status": status,
        "mode": "build_profile",
        "api_family": "runtime_math",
        "symbol": "runtime_math_profile_gate",
        "outcome": status,
        "errno": 0 if status in {"pass", "info"} else 1,
        "timing_ns": 0,
        "artifact_refs": [
            "tests/conformance/runtime_math_profile_gate_completion_contract.v1.json",
            "scripts/check_runtime_math_profile_gate_completion_contract.sh",
            "scripts/check_runtime_math_profile_gates.sh",
            "crates/frankenlibc-harness/tests/runtime_math_profile_gates_test.rs",
        ],
        "failure_signature": "none" if status in {"pass", "info"} else "runtime_math_profile_gate_completion_contract_failed",
        "details": details or {},
    }


def check_file_line_ref(ref: str) -> None:
    if ":" not in ref:
        errors.append(f"implementation ref missing line separator: {ref}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        errors.append(f"implementation ref has invalid line: {ref}")
        return
    path = rel_path(path_text)
    if not path.is_file():
        errors.append(f"implementation ref path missing: {ref}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no < 1 or line_no > len(lines) or not lines[line_no - 1].strip():
        errors.append(f"implementation ref does not point to non-empty line: {ref}")


def require_test_fn(path: Path, name: str) -> None:
    text = path.read_text(encoding="utf-8")
    if f"fn {name}" not in text:
        errors.append(f"{path.relative_to(root)} missing test function {name}")


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})

if contract.get("schema") != "runtime_math_profile_gate_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != "bd-1iya":
    errors.append("bead must be bd-1iya")
if contract.get("completion_debt_bead") != "bd-1iya.1":
    errors.append("completion_debt_bead must be bd-1iya.1")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

artifact_paths: dict[str, Path] = {}
for name, value in artifacts.items():
    try:
        path = rel_path(str(value))
    except ValueError as exc:
        errors.append(str(exc))
        continue
    artifact_paths[name] = path
    if not path.is_file():
        errors.append(f"artifact {name} missing: {value}")

for ref in evidence.get("implementation_refs", []):
    check_file_line_ref(str(ref))

production_manifest = load_json(artifact_paths["production_manifest"])
membrane_cargo = artifact_paths["membrane_cargo"].read_text(encoding="utf-8")
membrane_lib = artifact_paths["membrane_lib"].read_text(encoding="utf-8")
profile_gate_script = artifact_paths["profile_gate_script"].read_text(encoding="utf-8")
ci_script = artifact_paths["ci_script"].read_text(encoding="utf-8")
verification_matrix = load_json(artifact_paths["verification_matrix"])

with artifact_paths["membrane_cargo"].open("rb") as handle:
    cargo_toml = tomllib.load(handle)
features = cargo_toml.get("features", {})

flag = evidence.get("flag_architecture", {})
if flag.get("missing_item_id") != "flag.architecture":
    errors.append("flag_architecture missing_item_id mismatch")
if production_manifest.get("default_feature_set") != flag.get("default_feature_set"):
    errors.append("production manifest default_feature_set does not match contract")
if production_manifest.get("optional_feature_set") != flag.get("optional_feature_set"):
    errors.append("production manifest optional_feature_set does not match contract")
if features.get("default") != ["runtime-math-production"]:
    errors.append("Cargo default feature set must be runtime-math-production")
if features.get("runtime-math-production") != []:
    errors.append("Cargo runtime-math-production feature must be empty")
if features.get("runtime-math-research") != ["runtime-math-production"]:
    errors.append("Cargo runtime-math-research must depend on runtime-math-production")

feature_bindings = set(flag.get("required_feature_bindings", []))
missing_feature_bindings = sorted(REQUIRED_FEATURE_BINDINGS - feature_bindings)
if missing_feature_bindings:
    errors.append(f"required_feature_bindings missing {missing_feature_bindings}")
for binding in REQUIRED_FEATURE_BINDINGS:
    if binding not in membrane_cargo:
        errors.append(f"membrane Cargo.toml missing binding {binding}")

compile_guard = str(flag.get("required_compile_guard", ""))
if not compile_guard or compile_guard not in membrane_lib:
    errors.append("membrane lib.rs missing runtime-math-production compile guard")

profile_matrix = flag.get("profile_matrix", {})
for key in ["default_build", "research_build", "no_default_build"]:
    row = profile_matrix.get(key, {})
    command = str(row.get("command", ""))
    if "rch exec" not in command:
        errors.append(f"profile_matrix.{key}.command must use rch exec")
if profile_matrix.get("default_build", {}).get("expect_success") is not True:
    errors.append("default_build must expect success")
if profile_matrix.get("research_build", {}).get("expect_success") is not True:
    errors.append("research_build must expect success")
if profile_matrix.get("no_default_build", {}).get("expect_success") is not False:
    errors.append("no_default_build must expect failure")

for snippet in [
    'cmd="cargo check -p frankenlibc-membrane --all-targets"',
    'cmd="cargo check -p frankenlibc-membrane --all-targets --features runtime-math-research"',
    'cmd="cargo check -p frankenlibc-membrane --all-targets --no-default-features"',
    'expect_success=False',
    'target/conformance/runtime_math_profile_gates.log.jsonl',
    'target/conformance/runtime_math_profile_gates.report.json',
]:
    if snippet not in profile_gate_script:
        errors.append(f"profile gate script missing {snippet}")

if "scripts/check_runtime_math_profile_gates.sh" not in ci_script:
    errors.append("ci.sh must invoke check_runtime_math_profile_gates.sh")

unit = evidence.get("unit_primary", {})
if unit.get("missing_item_id") != "tests.unit.primary":
    errors.append("unit_primary missing_item_id mismatch")
test_sources = evidence.get("test_sources", {})
source_paths = {
    name: rel_path(path)
    for name, path in test_sources.items()
}
for test_ref in unit.get("required_test_refs", []):
    source_name = test_ref.get("source")
    test_name = test_ref.get("name")
    if source_name not in source_paths:
        errors.append(f"unknown test source {source_name}")
        continue
    require_test_fn(source_paths[source_name], str(test_name))
for command in unit.get("required_commands", []):
    command_text = str(command)
    if "cargo " in command_text and "rch exec" not in command_text:
        errors.append(f"unit command must offload cargo through rch: {command_text}")

if isinstance(verification_matrix, list):
    matrix_rows = verification_matrix
else:
    matrix_rows = verification_matrix.get("entries", verification_matrix.get("beads", []))
row = next((item for item in matrix_rows if item.get("bead_id") == "bd-1iya"), None)
if row is None:
    errors.append("verification_matrix missing bd-1iya row")
else:
    coverage = row.get("coverage", {})
    if coverage.get("unit_tests", {}).get("status") != "complete":
        errors.append("verification matrix unit_tests coverage must be complete")
    if coverage.get("structured_logs", {}).get("status") != "complete":
        errors.append("verification matrix structured_logs coverage must be complete")
    if row.get("coverage_summary", {}).get("overall") != "complete":
        errors.append("verification matrix coverage summary must be complete")

telemetry = evidence.get("telemetry_evidence", {})
events = []
required_events = set(telemetry.get("required_events", []))
required_fields = set(telemetry.get("required_fields", []))
if not REQUIRED_EVENTS.issubset(required_events):
    errors.append("telemetry_evidence.required_events missing completion events")
if not REQUIRED_FIELDS.issubset(required_fields):
    errors.append("telemetry_evidence.required_fields missing required fields")

events.append(event_payload("runtime_math_profile_gate_feature_architecture_validated", "info"))
events.append(event_payload("runtime_math_profile_gate_unit_evidence_validated", "info"))

status = "pass" if not errors else "fail"
events.append(
    event_payload(
        "runtime_math_profile_gate_completion_contract_validated"
        if status == "pass"
        else "runtime_math_profile_gate_completion_contract_failed",
        status,
        details={"error_count": len(errors)},
    )
)

for row_event in events:
    missing = REQUIRED_FIELDS - set(row_event)
    if missing:
        errors.append(f"internal telemetry row missing fields {sorted(missing)}")

report = {
    "schema": "runtime_math_profile_gate_completion_contract.report.v1",
    "status": "pass" if not errors else "fail",
    "generated_at": ts,
    "source_commit": SOURCE_COMMIT,
    "completion_debt_bead": "bd-1iya.1",
    "original_bead": "bd-1iya",
    "summary": {
        "default_feature_set": production_manifest.get("default_feature_set"),
        "optional_feature_set": production_manifest.get("optional_feature_set"),
        "required_feature_binding_count": len(REQUIRED_FEATURE_BINDINGS),
        "required_test_ref_count": len(unit.get("required_test_refs", [])),
        "profile_matrix_count": len(profile_matrix),
        "verification_matrix_status": "complete" if row is not None else "missing",
    },
    "errors": errors,
    "artifacts": {
        "contract": str(contract_path.relative_to(root)) if contract_path.is_relative_to(root) else str(contract_path),
        "log_jsonl": str(log_path.relative_to(root)) if log_path.is_relative_to(root) else str(log_path),
    },
}

log_path.parent.mkdir(parents=True, exist_ok=True)
with log_path.open("w", encoding="utf-8") as handle:
    for row_event in events:
        handle.write(json.dumps(row_event, sort_keys=True))
        handle.write("\n")
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(
        f"FAIL: runtime math profile gate completion contract errors={len(errors)} "
        f"report={report_path.relative_to(root)}"
    )
    raise SystemExit(1)

print(
    "PASS: runtime math profile gate completion contract "
    f"(features={production_manifest.get('default_feature_set')}+{production_manifest.get('optional_feature_set')}, "
    f"report={report_path.relative_to(root)})"
)
PY
