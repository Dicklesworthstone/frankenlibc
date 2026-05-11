#!/usr/bin/env bash
# check_allocator_e2e_conformance_completion_contract.sh
#
# Completion-debt gate for bd-2x5.5.1. Binds the existing allocator
# strict/hardened E2E gate and allocator conformance fixture coverage to the
# audit-required E2E + conformance evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_ALLOCATOR_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/allocator_e2e_conformance_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_ALLOCATOR_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/allocator_e2e_conformance_completion}"
REPORT="${FRANKENLIBC_ALLOCATOR_COMPLETION_REPORT:-${OUT_DIR}/allocator_e2e_conformance_completion.report.json}"
LOG="${FRANKENLIBC_ALLOCATOR_COMPLETION_LOG:-${OUT_DIR}/allocator_e2e_conformance_completion.log.jsonl}"
RUN_SOURCE_E2E="${FRANKENLIBC_ALLOCATOR_COMPLETION_RUN_SOURCE_E2E:-0}"

mkdir -p "${OUT_DIR}"

ROOT_ARG="${ROOT}" \
CONTRACT_ARG="${CONTRACT}" \
REPORT_ARG="${REPORT}" \
LOG_ARG="${LOG}" \
RUN_SOURCE_E2E_ARG="${RUN_SOURCE_E2E}" \
python3 - <<'PY'
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ["ROOT_ARG"])
CONTRACT = Path(os.environ["CONTRACT_ARG"])
REPORT = Path(os.environ["REPORT_ARG"])
LOG = Path(os.environ["LOG_ARG"])
RUN_SOURCE_E2E = os.environ["RUN_SOURCE_E2E_ARG"] == "1"

EXPECTED_BEAD = "bd-2x5.5.1"
EXPECTED_ORIGINAL_BEAD = "bd-2x5.5"
REQUIRED_OBLIGATIONS = {"tests.e2e.primary", "tests.conformance.primary"}
REQUIRED_LOG_EVENTS = [
    "allocator_completion_source_binding",
    "allocator_completion_conformance_binding",
    "allocator_completion_e2e_status",
    "allocator_completion_summary",
]


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def repo_path(reference: str) -> Path:
    path = Path(reference)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        fail("unsafe source artifact path", f"path must be repo-relative: {reference}")
    return ROOT / path


def load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception as err:
        fail("invalid JSON artifact", f"{rel(path)} did not parse as JSON: {err}")


def read_text(path: Path) -> str:
    try:
        return path.read_text()
    except Exception as err:
        fail("missing source artifact", f"{rel(path)} could not be read: {err}")


log_rows = []
failures = []


def emit(event: str, outcome: str, **details) -> None:
    row = {
        "timestamp": "2026-05-10T00:00:00Z",
        "trace_id": f"{EXPECTED_BEAD}::{event}",
        "bead_id": EXPECTED_BEAD,
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "event": event,
        "outcome": outcome,
        "mode": details.pop("mode", "both"),
        "api_family": "allocator",
        "symbol": details.pop("symbol", "malloc/free/calloc/realloc"),
        "decision_path": details.pop("decision_path", "CompletionEvidenceBinding"),
        "healing_action": details.pop("healing_action", "None"),
        "errno": details.pop("errno", 0),
        "latency_ns": details.pop("latency_ns", 0),
        "artifact_refs": details.pop("artifact_refs", []),
    }
    row.update(details)
    log_rows.append(row)


def fail(signature: str, message: str, **details) -> None:
    failures.append({"signature": signature, "message": message, **details})


def require(condition: bool, signature: str, message: str, **details) -> None:
    if not condition:
        fail(signature, message, **details)


contract = load_json(CONTRACT)
require(
    contract.get("schema_version") == "allocator_e2e_conformance_completion_contract.v1",
    "contract schema mismatch",
    "contract schema_version must be allocator_e2e_conformance_completion_contract.v1",
)
require(contract.get("bead") == EXPECTED_BEAD, "contract bead mismatch", f"bead must be {EXPECTED_BEAD}")
require(
    contract.get("original_bead") == EXPECTED_ORIGINAL_BEAD,
    "contract original bead mismatch",
    f"original_bead must be {EXPECTED_ORIGINAL_BEAD}",
)

source_artifacts = contract.get("source_artifacts", {})
for key in [
    "allocator_e2e_gate",
    "fixture_spec",
    "allocator_fixture",
    "integration_fixtures",
    "source_tests",
]:
    require(key in source_artifacts, "missing source artifact binding", f"missing source_artifacts.{key}")

obligation_ids = {row.get("id") for row in contract.get("completion_obligations", [])}
missing_obligations = sorted(REQUIRED_OBLIGATIONS - obligation_ids)
require(
    not missing_obligations,
    "missing completion obligation",
    f"missing obligations: {missing_obligations}",
)

gate_path = repo_path(source_artifacts["allocator_e2e_gate"]["path"])
fixture_spec_path = repo_path(source_artifacts["fixture_spec"]["path"])
allocator_fixture_path = repo_path(source_artifacts["allocator_fixture"]["path"])

for label, path in [
    ("allocator e2e gate", gate_path),
    ("fixture spec", fixture_spec_path),
    ("allocator fixture", allocator_fixture_path),
]:
    require(path.is_file(), "missing source artifact", f"{label} missing: {rel(path)}")

if gate_path.is_file():
    require(
        os.access(gate_path, os.X_OK),
        "allocator e2e gate not executable",
        f"{rel(gate_path)} must be executable",
    )
    gate_text = read_text(gate_path)
    for marker in source_artifacts["allocator_e2e_gate"].get("required_markers", []):
        require(
            marker in gate_text,
            "missing allocator e2e gate marker",
            f"allocator e2e gate missing marker: {marker}",
        )

fixture_spec = load_json(fixture_spec_path)
fixtures = fixture_spec.get("fixtures", [])
fixtures_by_id = {row.get("id"): row for row in fixtures}
for fixture_id in source_artifacts["fixture_spec"].get("required_fixtures", []):
    require(
        fixture_id in fixtures_by_id,
        "allocator fixture spec missing required fixture",
        f"fixture spec missing {fixture_id}",
    )

stress = fixtures_by_id.get("fixture_malloc_stress", {})
stress_symbols = set(stress.get("covered_symbols", []))
missing_stress_symbols = sorted(
    set(source_artifacts["fixture_spec"].get("required_stress_symbols", [])) - stress_symbols
)
require(
    not missing_stress_symbols,
    "allocator stress fixture missing glibc differential coverage",
    f"fixture_malloc_stress missing symbols: {missing_stress_symbols}",
)
require(
    int(stress.get("tests", 0)) >= int(source_artifacts["fixture_spec"].get("minimum_stress_tests", 0)),
    "allocator stress fixture below test minimum",
    f"fixture_malloc_stress tests={stress.get('tests')}",
)
require(
    "-pthread" in stress.get("link_flags", []),
    "allocator stress fixture missing pthread linkage",
    "fixture_malloc_stress must link with -pthread",
)
for mode in ["strict", "hardened"]:
    mode_expectation = stress.get("mode_expectations", {}).get(mode, {})
    require(
        mode_expectation.get("expected_exit") == 0,
        "allocator stress fixture missing mode expectation",
        f"fixture_malloc_stress {mode} expected_exit must be 0",
    )
    require(
        "fixture_malloc_stress: PASS" in mode_expectation.get("expected_stdout_contains", ""),
        "allocator stress fixture missing mode expectation",
        f"fixture_malloc_stress {mode} expected_stdout_contains must include PASS marker",
    )

allocator_fixture = load_json(allocator_fixture_path)
require(
    allocator_fixture.get("family") == "allocator",
    "allocator fixture family mismatch",
    "allocator fixture family must be allocator",
)
cases = allocator_fixture.get("cases", [])
require(
    len(cases) >= int(source_artifacts["allocator_fixture"].get("minimum_cases", 0)),
    "allocator fixture below case minimum",
    f"allocator fixture has {len(cases)} cases",
)
case_functions = {row.get("function") for row in cases}
missing_functions = sorted(
    set(source_artifacts["allocator_fixture"].get("required_functions", [])) - case_functions
)
require(
    not missing_functions,
    "allocator fixture missing required POSIX function",
    f"allocator fixture missing functions: {missing_functions}",
)
for row in cases:
    name = row.get("name", "<unnamed>")
    require(
        "POSIX" in row.get("spec_section", ""),
        "allocator fixture missing POSIX reference",
        f"case {name} missing POSIX spec reference",
    )
    require(
        row.get("expected_errno") == 0,
        "allocator fixture unexpected errno",
        f"case {name} expected_errno={row.get('expected_errno')}",
    )
    require(
        row.get("mode") in {"strict", "hardened", "both"},
        "allocator fixture invalid mode",
        f"case {name} mode={row.get('mode')}",
    )

for source in source_artifacts["integration_fixtures"].get("required_sources", []):
    source_path = repo_path(source["path"])
    require(source_path.is_file(), "missing source artifact", f"{source['id']} missing: {rel(source_path)}")
    source_text = read_text(source_path) if source_path.is_file() else ""
    for marker in source.get("required_markers", []):
        require(
            marker in source_text,
            "integration fixture missing marker",
            f"{source['id']} missing marker: {marker}",
        )

source_tests = source_artifacts["source_tests"]
for group_name, group in source_tests.items():
    test_path = repo_path(group["path"])
    require(test_path.is_file(), "missing source artifact", f"{group_name} missing: {rel(test_path)}")
    test_text = read_text(test_path) if test_path.is_file() else ""
    for function_name in group.get("required_functions", []):
        require(
            f"fn {function_name}" in test_text,
            "missing allocator source test binding",
            f"{group_name} missing test function: {function_name}",
        )

emit(
    "allocator_completion_source_binding",
    "pass" if not failures else "fail",
    artifact_refs=[rel(gate_path), rel(fixture_spec_path), rel(allocator_fixture_path)],
)
emit(
    "allocator_completion_conformance_binding",
    "pass" if not failures else "fail",
    artifact_refs=[
        rel(allocator_fixture_path),
        rel(fixture_spec_path),
        "crates/frankenlibc-harness/tests/allocator_conformance_test.rs",
        "crates/frankenlibc-harness/tests/c_fixture_suite_test.rs",
    ],
)

source_e2e = {"status": "skipped", "reason": "set FRANKENLIBC_ALLOCATOR_COMPLETION_RUN_SOURCE_E2E=1 to execute"}
if RUN_SOURCE_E2E and not failures:
    run = subprocess.run(
        ["bash", str(gate_path)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    source_e2e = {
        "status": "pass" if run.returncode == 0 else "fail",
        "exit_code": run.returncode,
        "stdout_tail": run.stdout.splitlines()[-20:],
        "stderr_tail": run.stderr.splitlines()[-20:],
    }
    if run.returncode != 0:
        fail("allocator source e2e gate failed", "scripts/check_allocator_e2e.sh failed", **source_e2e)

emit(
    "allocator_completion_e2e_status",
    source_e2e["status"],
    mode="strict+hardened",
    artifact_refs=[rel(gate_path), "target/allocator_e2e"],
    source_e2e=source_e2e,
)

required_log_fields = set(contract.get("completion_log_contract", {}).get("required_fields", []))
for row in log_rows:
    missing_fields = sorted(required_log_fields - set(row))
    if missing_fields:
        fail(
            "allocator completion log missing required field",
            f"event {row.get('event')} missing log fields: {missing_fields}",
        )

emit(
    "allocator_completion_summary",
    "pass" if not failures else "fail",
    artifact_refs=[rel(CONTRACT), rel(REPORT), rel(LOG)],
    source_e2e=source_e2e,
)

payload = {
    "schema_version": "allocator_e2e_conformance_completion_report.v1",
    "bead": EXPECTED_BEAD,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "outcome": "pass" if not failures else "fail",
    "failure_signature": None if not failures else failures[0]["signature"],
    "failures": failures,
    "summary": {
        "required_obligations": sorted(REQUIRED_OBLIGATIONS),
        "fixture_spec_count": len(fixtures),
        "allocator_fixture_cases": len(cases),
        "stress_symbols": sorted(stress_symbols),
        "source_e2e": source_e2e,
    },
}

REPORT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows))

if failures:
    print(f"check_allocator_e2e_conformance_completion_contract: FAIL {failures[0]['signature']}", file=sys.stderr)
    print(json.dumps(payload, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)

print(
    "check_allocator_e2e_conformance_completion_contract: PASS "
    f"fixtures={len(fixtures)} allocator_cases={len(cases)} source_e2e={source_e2e['status']}"
)
PY
