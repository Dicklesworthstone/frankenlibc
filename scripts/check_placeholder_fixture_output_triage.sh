#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${PLACEHOLDER_FIXTURE_OUTPUT_TRIAGE_CONTRACT:-$ROOT/tests/conformance/placeholder_fixture_output_triage.v1.json}"
REPORT="${PLACEHOLDER_FIXTURE_OUTPUT_TRIAGE_REPORT:-$ROOT/target/conformance/placeholder_fixture_output_triage.report.json}"
LOG="${PLACEHOLDER_FIXTURE_OUTPUT_TRIAGE_LOG:-$ROOT/target/conformance/placeholder_fixture_output_triage.log.jsonl}"
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

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" "$MODE" <<'PY'
import json
import pathlib
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
mode = sys.argv[5]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "placeholder_fixture_output_triage.v1"
EXPECTED_BEAD = "bd-0agsk.14"
EXPECTED_COMMAND = "scripts/check_placeholder_fixture_output_triage.sh --validate-only"


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def read_text(rel_path: str) -> str:
    path = root / rel_path
    if not path.is_file():
        fail("path_missing", f"required path missing: {rel_path}", path=rel_path)
    return path.read_text(encoding="utf-8")


def git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or "<empty stderr>"
        raise SystemExit(f"FAIL[source_commit_unavailable]: git rev-parse HEAD failed: {stderr}")
    commit = result.stdout.strip()
    if not commit:
        raise SystemExit("FAIL[source_commit_empty]: git rev-parse HEAD returned empty output")
    return commit


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def finish(outcome: str, signature: str, message: str, **summary):
    report = {
        "schema_version": "placeholder_fixture_output_triage.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": f"placeholder-fixture-output-triage-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{id(summary)}",
        "source_commit": source_commit,
        "mode": mode,
        "outcome": outcome,
        "failure_signature": signature,
        "message": message,
        "contract": str(contract_path),
        "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
        "summary": summary,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    event = {
        "timestamp": now_utc(),
        "event": "placeholder_fixture_output_triage_validated" if outcome == "pass" else "placeholder_fixture_output_triage_failed",
        "bead": EXPECTED_BEAD,
        "source_commit": source_commit,
        "outcome": outcome,
        "failure_signature": signature,
        "contract": str(contract_path),
        "summary": summary,
    }
    log_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
    if outcome != "pass":
        raise SystemExit(f"FAIL[{signature}]: {message}")


def fail(signature: str, message: str, **summary):
    finish("fail", signature, message, **summary)


def require(condition: bool, signature: str, message: str, **summary):
    if not condition:
        fail(signature, message, **summary)


def count_expected_tokens(fixture_path: pathlib.Path, allowed: set[str]) -> dict[str, int]:
    fixture = load_json(fixture_path)
    counts = {token: 0 for token in sorted(allowed)}
    for case in fixture.get("cases", []):
        expected = case.get("expected_output")
        if expected in counts:
            counts[expected] += 1
    return counts


source_commit = git_head()

if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")

require(contract_path.is_file(), "contract_missing", f"missing contract: {contract_path}")
contract = load_json(contract_path)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected schema_version", actual=contract.get("schema_version"))
require(contract.get("generated_by_bead") == EXPECTED_BEAD, "generated_by_bead", "unexpected generated_by_bead", actual=contract.get("generated_by_bead"))
require(contract.get("canonical_command") == EXPECTED_COMMAND, "canonical_command", "unexpected canonical_command", actual=contract.get("canonical_command"))

for rel in contract.get("input_artifacts", []):
    require((root / rel).is_file(), "input_artifact_missing", f"input artifact missing: {rel}", artifact=rel)

summary = contract.get("triage_summary", {})
findings = contract.get("triage_findings", [])
require(isinstance(findings, list) and findings, "findings_missing", "triage_findings must be non-empty")
require(summary.get("finding_count") == len(findings), "finding_count_mismatch", "finding_count does not match triage findings", declared=summary.get("finding_count"), actual=len(findings))

real_blockers = [finding for finding in findings if finding.get("real_blocker") is True]
require(summary.get("confirmed_real_blocker_count") == len(real_blockers), "real_blocker_count_mismatch", "confirmed blocker count drifted", declared=summary.get("confirmed_real_blocker_count"), actual=len(real_blockers))
if real_blockers:
    follow_ups = summary.get("follow_up_beads_created", [])
    require(bool(follow_ups), "real_blocker_without_follow_up", "real blockers require follow-up bead ids")
else:
    require(summary.get("follow_up_beads_created") == [], "unexpected_follow_up_beads", "no follow-up beads should be declared without real blockers")

arch = load_json(root / "tests/conformance/architecture_todo_reconciliation.v1.json")
scan_findings = arch.get("scan_findings", [])
source_rows = [
    row for row in scan_findings
    if row.get("kind") == "placeholder_fixture_output_comment"
    and row.get("source") == "crates/frankenlibc_conformance/src/lib.rs"
    and EXPECTED_BEAD in row.get("target_beads", [])
]
require(source_rows, "source_finding_missing", "architecture reconciliation no longer routes placeholder comment to bd-0agsk.14")

source_text = read_text("crates/frankenlibc_conformance/src/lib.rs")
for token in [
    "time_ops.json uses symbolic outputs",
    "calls the live ABI entrypoints",
    "termios_ops.json uses the flexible 0_OR_ENOTTY token",
    "normalizes ENOTTY failures",
]:
    require(token in source_text, "source_comment_token_missing", f"source comment missing token: {token}", token=token)

for function, token in [
    ("execute_time_case", "frankenlibc_abi::time_abi::time"),
    ("execute_clock_case", "frankenlibc_abi::time_abi::clock"),
    ("execute_localtime_r_case", "frankenlibc_abi::time_abi::localtime_r"),
    ("execute_tcgetattr_case", "frankenlibc_abi::termios_abi::tcgetattr"),
]:
    require(function in source_text and token in source_text, "executor_token_missing", f"executor token missing for {function}", function=function, token=token)

for token in ["POSITIVE_INT", "NON_NEGATIVE", "TM_STRUCT", "0_OR_ENOTTY", "impl_errno == libc::ENOTTY"]:
    require(token in source_text, "normalization_token_missing", f"normalization token missing: {token}", token=token)

time_counts = count_expected_tokens(root / "tests/conformance/fixtures/time_ops.json", {"POSITIVE_INT", "NON_NEGATIVE", "TM_STRUCT"})
termios_counts = count_expected_tokens(root / "tests/conformance/fixtures/termios_ops.json", {"0_OR_ENOTTY"})
require(sum(time_counts.values()) == 4, "time_placeholder_count_drift", "time_ops placeholder count drifted", counts=time_counts)
require(termios_counts.get("0_OR_ENOTTY") == 2, "termios_placeholder_count_drift", "termios 0_OR_ENOTTY count drifted", counts=termios_counts)

time_test = read_text("crates/frankenlibc-harness/tests/time_ops_conformance_test.rs")
termios_test = read_text("crates/frankenlibc-harness/tests/termios_ops_conformance_test.rs")
for token in ["time_ops_fixture_cases_match_execute_fixture_case", "time_ops_fixture_executes_with_host_parity_via_harness_matrix", "placeholder expected_output strings"]:
    require(token in time_test, "time_harness_token_missing", f"time harness token missing: {token}", token=token)
for token in ["termios_ops_fixture_executes_with_host_parity_via_harness_matrix", "expected_output"]:
    require(token in termios_test, "termios_harness_token_missing", f"termios harness token missing: {token}", token=token)

finish(
    "pass",
    "none",
    "placeholder fixture-output triage validated",
    finding_count=len(findings),
    real_blocker_count=len(real_blockers),
    time_placeholder_counts=time_counts,
    termios_placeholder_counts=termios_counts,
)
PY

echo "PASS: placeholder fixture-output triage validated"
