#!/usr/bin/env bash
# check_fixture_verification_regression_completion_contract.sh — bd-2hh.5.1
# Validates completion evidence for conformance fixture verification and
# regression detection without rewriting the checked-in bd-2hh.5 report.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_FIXTURE_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/fixture_verification_regression_completion_contract.v1.json}"
SOURCE_REPORT="${FRANKENLIBC_FIXTURE_COMPLETION_SOURCE_REPORT:-}"
OUT_DIR="${FRANKENLIBC_FIXTURE_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_FIXTURE_COMPLETION_REPORT:-${OUT_DIR}/fixture_verification_regression_completion_contract.report.json}"
LOG="${FRANKENLIBC_FIXTURE_COMPLETION_LOG:-${OUT_DIR}/fixture_verification_regression_completion_contract.log.jsonl}"
GENERATED="${FRANKENLIBC_FIXTURE_COMPLETION_GENERATED:-${OUT_DIR}/fixture_verification_regression_completion_contract.generated.v1.json}"
GENERATED_LOG="${FRANKENLIBC_FIXTURE_COMPLETION_GENERATED_LOG:-${OUT_DIR}/fixture_verification_regression_completion_contract.generated.log.jsonl}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT}" "${SOURCE_REPORT}" "${REPORT}" "${LOG}" "${GENERATED}" "${GENERATED_LOG}" <<'PY'
import json
import pathlib
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
source_report_override = sys.argv[3]
report_path = pathlib.Path(sys.argv[4])
log_path = pathlib.Path(sys.argv[5])
generated_path = pathlib.Path(sys.argv[6])
generated_log_path = pathlib.Path(sys.argv[7])
started_ns = time.time_ns()

EXPECTED_SCHEMA = "fixture_verification_regression_completion_contract.v1"
EXPECTED_BEAD = "bd-2hh.5.1"
EXPECTED_ORIGINAL_BEAD = "bd-2hh.5"


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def repo_path(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    return path if path.is_absolute() else root / path


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


events = []


def emit(event: str, outcome: str, details: dict):
    row = {
        "timestamp": "2026-05-10T00:00:00Z",
        "trace_id": f"{EXPECTED_BEAD}::fixture-verification-regression::{event}",
        "bead_id": EXPECTED_BEAD,
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "mode": "completion-contract",
        "api_family": "conformance",
        "symbol": "fixture_verification_regression",
        "decision_path": "conformance::fixture_verification_regression::completion",
        "healing_action": None,
        "errno": 0,
        "latency_ns": 0,
        "artifact_refs": [rel(contract_path), rel(report_path)],
        "event": event,
        "outcome": outcome,
        **details,
    }
    events.append(row)


def finish(outcome: str, failure_signature: str | None, summary: dict):
    duration_ms = (time.time_ns() - started_ns) // 1_000_000
    report = {
        "schema_version": "fixture_verification_regression_completion_contract.report.v1",
        "bead": EXPECTED_BEAD,
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "outcome": outcome,
        "failure_signature": failure_signature,
        "duration_ms": duration_ms,
        "summary": summary,
        "generated_artifacts": {
            "report": rel(report_path),
            "log": rel(log_path),
            "replayed_fixture_report": rel(generated_path),
            "replayed_fixture_log": rel(generated_log_path),
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")


def fail(signature: str, message: str, **details):
    details = {"message": message, **details}
    emit("fixture_verification_regression_completion_failed", "fail", details)
    finish("fail", signature, details)
    raise SystemExit(f"FAIL: {signature}: {message}")


if not contract_path.is_file():
    fail("contract missing", f"missing contract: {contract_path}")

contract = load_json(contract_path)
if contract.get("schema_version") != EXPECTED_SCHEMA:
    fail("contract schema mismatch", f"schema_version must be {EXPECTED_SCHEMA}")
if contract.get("bead") != EXPECTED_BEAD:
    fail("contract bead mismatch", f"bead must be {EXPECTED_BEAD}")
if contract.get("original_bead") != EXPECTED_ORIGINAL_BEAD:
    fail("contract original bead mismatch", f"original_bead must be {EXPECTED_ORIGINAL_BEAD}")

source_artifacts = contract.get("source_artifacts", {})
required_artifact_keys = {"generator", "source_gate", "source_report", "source_unit_tests", "fixture_root"}
missing_artifacts = sorted(required_artifact_keys - set(source_artifacts))
if missing_artifacts:
    fail("missing source artifact binding", f"missing source_artifacts entries: {missing_artifacts}")

generator_path = repo_path(source_artifacts["generator"]["path"])
source_gate_path = repo_path(source_artifacts["source_gate"]["path"])
source_unit_test_path = repo_path(source_artifacts["source_unit_tests"]["path"])
source_report_path = repo_path(source_report_override or source_artifacts["source_report"]["path"])
fixture_root_path = repo_path(source_artifacts["fixture_root"]["path"])

for label, path in [
    ("generator", generator_path),
    ("source gate", source_gate_path),
    ("source unit test", source_unit_test_path),
    ("source report", source_report_path),
]:
    if not path.is_file():
        fail("missing source artifact", f"{label} artifact missing: {rel(path)}")

if not fixture_root_path.is_dir():
    fail("fixture root missing", f"fixture root missing: {rel(fixture_root_path)}")

if not source_gate_path.stat().st_mode & 0o111:
    fail("source gate not executable", f"source gate must be executable: {rel(source_gate_path)}")

generator_text = read_text(generator_path)
for marker in source_artifacts["generator"].get("required_markers", []):
    if marker not in generator_text:
        fail("missing generator binding", f"generator missing marker: {marker}")

source_gate_text = read_text(source_gate_path)
for marker in source_artifacts["source_gate"].get("required_markers", []):
    if marker not in source_gate_text:
        fail("missing source gate binding", f"source gate missing marker: {marker}")

source_unit_test_text = read_text(source_unit_test_path)
for function_name in source_artifacts["source_unit_tests"].get("required_functions", []):
    if f"fn {function_name}" not in source_unit_test_text:
        fail("missing source unit binding", f"source unit test missing function: {function_name}")

obligation_ids = {row.get("id") for row in contract.get("completion_obligations", [])}
for required_id in ("tests.unit.primary", "tests.e2e.primary", "tests.conformance.primary"):
    if required_id not in obligation_ids:
        fail("missing completion obligation", f"missing completion obligation: {required_id}")

fixture_files = sorted(fixture_root_path.glob("*.json"))
fixture_min = int(source_artifacts["fixture_root"].get("minimum_fixture_files", 0))
if len(fixture_files) < fixture_min:
    fail(
        "fixture inventory below completion minimum",
        f"fixture root has {len(fixture_files)} files, expected >= {fixture_min}",
    )

source_report = load_json(source_report_path)
if source_report.get("schema_version") != "v1":
    fail("source report schema mismatch", "source report schema_version must be v1")
if source_report.get("bead") != EXPECTED_ORIGINAL_BEAD:
    fail("source report bead mismatch", f"source report bead must be {EXPECTED_ORIGINAL_BEAD}")

summary = source_report.get("summary", {})
regression = source_report.get("regression_detection", {})
baseline = source_report.get("regression_baseline", {})
source_report_contract = source_artifacts["source_report"]

total_fixture_files = int(summary.get("total_fixture_files", 0))
valid_fixture_files = int(summary.get("valid_fixture_files", 0))
invalid_fixture_files = int(summary.get("invalid_fixture_files", -1))
total_cases = int(summary.get("total_cases", 0))
total_issues = int(summary.get("total_issues", -1))
unique_symbols = int(summary.get("unique_symbols", 0))
baseline_symbols = int(baseline.get("symbol_count", 0))
baseline_cases = int(baseline.get("total_cases", 0))

if total_fixture_files < int(source_report_contract["minimum_fixture_files"]):
    fail("fixture inventory below completion minimum", f"source report fixture count is {total_fixture_files}")
if valid_fixture_files != total_fixture_files:
    fail("source report contains invalid fixtures", f"valid_fixture_files={valid_fixture_files} total={total_fixture_files}")
if invalid_fixture_files != int(source_report_contract["expected_invalid_fixture_files"]):
    fail("source report contains invalid fixtures", f"invalid_fixture_files={invalid_fixture_files}")
if total_issues != int(source_report_contract["expected_issue_count"]):
    fail("source report contains format issues", f"total_issues={total_issues}")
if total_cases < int(source_report_contract["minimum_cases"]):
    fail("fixture case inventory below completion minimum", f"total_cases={total_cases}")
if unique_symbols < int(source_report_contract["minimum_symbols"]) or baseline_symbols < int(source_report_contract["minimum_symbols"]):
    fail(
        "fixture regression baseline below completion minimum",
        f"unique_symbols={unique_symbols} baseline_symbols={baseline_symbols}",
    )
if baseline_cases != total_cases:
    fail("fixture regression baseline case drift", f"baseline_cases={baseline_cases} total_cases={total_cases}")
if summary.get("determinism_verified") is not True:
    fail("fixture determinism not verified", "summary.determinism_verified must be true")
if regression.get("status") != source_report_contract["expected_regression_status"]:
    fail("fixture regression status not clean", f"regression status is {regression.get('status')!r}")
baseline_digest = regression.get("baseline_fixture_digest")
if not isinstance(baseline_digest, str) or len(baseline_digest) != 64:
    fail("fixture regression baseline digest invalid", "baseline digest must be a 64-character sha256")

fixture_results = source_report.get("fixture_results", [])
fixture_hashes = source_report.get("fixture_hashes", {})
if len(fixture_results) != total_fixture_files:
    fail("fixture result count drift", f"fixture_results={len(fixture_results)} total={total_fixture_files}")
if len(fixture_hashes) != total_fixture_files:
    fail("fixture hash count drift", f"fixture_hashes={len(fixture_hashes)} total={total_fixture_files}")
for row in fixture_results:
    if row.get("valid") is not True:
        fail("source report contains invalid fixtures", f"invalid fixture result: {row.get('file')}")
    if not row.get("fixture_hash"):
        fail("fixture hash missing", f"missing fixture hash for {row.get('file')}")

timestamp = source_artifacts["generator"].get("deterministic_timestamp", "2026-05-10T00:00:00Z")
run = subprocess.run(
    [
        "python3",
        str(generator_path),
        "-o",
        str(generated_path),
        "--timestamp",
        timestamp,
        "--log",
        str(generated_log_path),
    ],
    cwd=root,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
if run.returncode != 0:
    fail(
        "generator replay failed",
        "generator replay into target/conformance failed",
        stdout=run.stdout,
        stderr=run.stderr,
    )
if not generated_path.is_file() or not generated_log_path.is_file():
    fail("generator replay missing artifacts", "generator did not emit report and log")

generated = load_json(generated_path)
generated_summary = generated.get("summary", {})
if generated.get("generated_at") != timestamp:
    fail("generated timestamp drift", f"generated_at={generated.get('generated_at')!r}")
for key in [
    "total_fixture_files",
    "valid_fixture_files",
    "invalid_fixture_files",
    "total_cases",
    "total_issues",
    "unique_symbols",
    "determinism_verified",
]:
    if generated_summary.get(key) != summary.get(key):
        fail(
            "generated fixture report drifted from checked-in source report",
            f"summary.{key}: generated={generated_summary.get(key)!r} source={summary.get(key)!r}",
        )
if generated.get("regression_detection", {}).get("baseline_fixture_digest") != baseline_digest:
    fail(
        "generated fixture report drifted from checked-in source report",
        "generated baseline digest differs from source report",
    )

required_log_fields = set(contract.get("generated_log_contract", {}).get("required_fields", []))
log_rows = []
for line_no, raw in enumerate(generated_log_path.read_text(encoding="utf-8").splitlines(), 1):
    if not raw.strip():
        continue
    try:
        row = json.loads(raw)
    except json.JSONDecodeError as err:
        fail("generated log invalid json", f"generated log line {line_no} invalid JSON: {err}")
    missing = sorted(required_log_fields - set(row))
    if missing:
        fail("generated log missing required field", f"line {line_no} missing fields: {missing}")
    log_rows.append(row)

minimum_rows = int(contract.get("generated_log_contract", {}).get("minimum_rows", 0))
if len(log_rows) < minimum_rows:
    fail("generated log below completion minimum", f"generated log rows={len(log_rows)} expected >= {minimum_rows}")

events_seen = {row.get("event") for row in log_rows}
for event_name in [
    contract["generated_log_contract"]["summary_event"],
    contract["generated_log_contract"]["per_fixture_event"],
]:
    if event_name not in events_seen:
        fail("generated log missing event", f"generated log missing event: {event_name}")

emit(
    "source_artifacts_and_bindings_validated",
    "pass",
    {
        "fixture_files": total_fixture_files,
        "total_cases": total_cases,
        "baseline_symbols": baseline_symbols,
    },
)
emit(
    "fixture_generator_replayed",
    "pass",
    {
        "generated_report": rel(generated_path),
        "generated_log": rel(generated_log_path),
        "generated_log_rows": len(log_rows),
    },
)
emit(
    "fixture_verification_regression_completion_contract_validated",
    "pass",
    {
        "obligations": sorted(obligation_ids),
        "baseline_digest": baseline_digest,
    },
)

summary_out = {
    "fixture_files": total_fixture_files,
    "valid_fixture_files": valid_fixture_files,
    "total_cases": total_cases,
    "baseline_symbols": baseline_symbols,
    "generated_log_rows": len(log_rows),
    "baseline_digest": baseline_digest,
}
finish("pass", None, summary_out)
print(
    "PASS: fixture verification regression completion "
    f"fixtures={total_fixture_files} cases={total_cases} symbols={baseline_symbols}"
)
PY
