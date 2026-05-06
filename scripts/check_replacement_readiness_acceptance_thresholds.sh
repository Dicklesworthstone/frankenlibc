#!/usr/bin/env bash
# Validate replacement-readiness acceptance thresholds against current evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${REPLACEMENT_READINESS_THRESHOLDS_CONTRACT:-${ROOT}/tests/conformance/replacement_readiness_acceptance_thresholds.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${REPLACEMENT_READINESS_THRESHOLDS_REPORT:-${OUT_DIR}/replacement_readiness_acceptance_thresholds.report.json}"
LOG="${REPLACEMENT_READINESS_THRESHOLDS_LOG:-${OUT_DIR}/replacement_readiness_acceptance_thresholds.log.jsonl}"
TRACE_ID="bd-0agsk.17::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"

MODE="validate-only"
if [[ $# -gt 0 ]]; then
  case "$1" in
    --validate-only)
      MODE="validate-only"
      shift
      ;;
    *)
      MODE="unknown:${1}"
      shift
      ;;
  esac
fi

if [[ $# -gt 0 ]]; then
  MODE="unknown:${1}"
fi

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${TRACE_ID}" "${MODE}" <<'PY'
import json
import pathlib
import subprocess
import sys
import time
from collections import Counter

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
trace_id = sys.argv[5]
mode = sys.argv[6]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "replacement_readiness_acceptance_thresholds.v1"
EXPECTED_BEAD = "bd-0agsk.17"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def write_event(report: dict, event_name: str) -> None:
    event = {
        "timestamp": now_utc(),
        "trace_id": trace_id,
        "level": "error" if report.get("outcome") == "fail" else "info",
        "event": event_name,
        "bead_id": EXPECTED_BEAD,
        "source_commit": report.get("source_commit"),
        "artifact_refs": [str(contract_path), str(report_path)],
        "outcome": report.get("outcome"),
        "failure_signature": report.get("failure_signature"),
        "duration_ms": report.get("duration_ms"),
        "details": report.get("summary", {}),
    }
    log_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")


def finish(report: dict, event_name: str) -> None:
    report["duration_ms"] = (time.time_ns() - start_ns) // 1_000_000
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_event(report, event_name)


def fail(signature: str, message: str, **extra) -> None:
    report = {
        "schema_version": "replacement_readiness_acceptance_thresholds.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": trace_id,
        "source_commit": extra.pop("source_commit", None),
        "mode": mode,
        "outcome": "fail",
        "failure_signature": signature,
        "failure_message": message,
        "contract": str(contract_path),
        "summary": extra,
    }
    finish(report, "replacement_readiness_acceptance_thresholds_failed")
    raise SystemExit(f"FAIL[{signature}]: {message}")


def resolve_input(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    if not path.is_absolute():
        path = root / path
    return path


def run_gate(command: str, source_commit: str) -> dict:
    result = subprocess.run(
        command.split(),
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(
            "replacement_readiness_upstream_gate_failed",
            f"upstream gate failed: {command}",
            source_commit=source_commit,
            command=command,
            stdout=result.stdout[-4000:],
            stderr=result.stderr[-4000:],
            exit_code=result.returncode,
        )
    return {"command": command, "exit_code": result.returncode}


if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")

if not contract_path.is_file():
    fail("replacement_readiness_contract_missing", f"contract file missing: {contract_path}")

try:
    contract = load_json(contract_path)
except (OSError, json.JSONDecodeError) as err:
    fail("replacement_readiness_contract_invalid_json", f"contract JSON could not be loaded: {err}")

source_commit = git_head()
if contract.get("schema_version") != EXPECTED_SCHEMA:
    fail(
        "replacement_readiness_contract_wrong_schema",
        f"schema_version must be {EXPECTED_SCHEMA}",
        source_commit=source_commit,
    )
if contract.get("generated_by_bead") != EXPECTED_BEAD:
    fail(
        "replacement_readiness_contract_wrong_bead",
        f"generated_by_bead must be {EXPECTED_BEAD}",
        source_commit=source_commit,
    )

policy = contract.get("readiness_policy", {})
if policy.get("claim_gate_decision_when_any_family_fails") != "blocked":
    fail("replacement_readiness_policy_invalid", "family failure decision must be blocked", source_commit=source_commit)
if policy.get("aggregate_support_green_not_sufficient") is not True:
    fail("replacement_readiness_policy_invalid", "aggregate support green must not be sufficient", source_commit=source_commit)
if policy.get("minimum_supported_status_pct") != 100.0:
    fail("replacement_readiness_policy_invalid", "minimum_supported_status_pct must be 100.0", source_commit=source_commit)
if policy.get("maximum_missing_exports_per_family") != 0:
    fail("replacement_readiness_policy_invalid", "maximum_missing_exports_per_family must be 0", source_commit=source_commit)
if policy.get("maximum_residual_callthrough_count") != 0:
    fail("replacement_readiness_policy_invalid", "maximum_residual_callthrough_count must be 0", source_commit=source_commit)
if policy.get("required_family_coverage_decision") != "pass":
    fail("replacement_readiness_policy_invalid", "required_family_coverage_decision must be pass", source_commit=source_commit)

input_artifacts = contract.get("input_artifacts", {})
required_inputs = [
    "support_matrix",
    "support_reality_drift_triage",
    "residual_replacement_callthrough_blockers",
    "hardened_mode_coverage_inventory",
    "family_coverage_thresholds",
]
input_paths: dict[str, pathlib.Path] = {}
for key in required_inputs:
    value = input_artifacts.get(key)
    if not isinstance(value, str) or not value:
        fail("replacement_readiness_input_missing", f"input_artifacts.{key} must be a non-empty path", source_commit=source_commit)
    path = resolve_input(value)
    if not path.is_file():
        fail("replacement_readiness_input_missing", f"input artifact missing: {path}", source_commit=source_commit, input_key=key)
    input_paths[key] = path

gate_results = []
for command in contract.get("input_gates", []):
    if not isinstance(command, str) or not command.strip():
        fail("replacement_readiness_input_missing", "input_gates entries must be non-empty commands", source_commit=source_commit)
    gate_results.append(run_gate(command, source_commit))

support = load_json(input_paths["support_matrix"])
drift = load_json(input_paths["support_reality_drift_triage"])
residual = load_json(input_paths["residual_replacement_callthrough_blockers"])
hardened = load_json(input_paths["hardened_mode_coverage_inventory"])
family_thresholds = load_json(input_paths["family_coverage_thresholds"])

supported_statuses = set(policy.get("supported_statuses", []))
if supported_statuses != {"Implemented", "RawSyscall"}:
    fail("replacement_readiness_policy_invalid", "supported_statuses must be Implemented + RawSyscall", source_commit=source_commit)

status_by_family: dict[str, Counter] = {}
for symbol in support.get("symbols", []):
    if not isinstance(symbol, dict):
        continue
    family = symbol.get("module")
    status = symbol.get("status")
    if isinstance(family, str) and isinstance(status, str):
        status_by_family.setdefault(family, Counter())[status] += 1

support_symbol_count = sum(sum(counter.values()) for counter in status_by_family.values())
support_supported_symbol_count = sum(
    sum(count for status, count in counter.items() if status in supported_statuses)
    for counter in status_by_family.values()
)
aggregate_support_green = support_symbol_count > 0 and support_symbol_count == support_supported_symbol_count

missing_exports_by_family = Counter()
missing_export_symbols: dict[str, list[str]] = {}
for bucket in drift.get("delta_buckets", []):
    if not isinstance(bucket, dict) or bucket.get("classification") != "missing_export":
        continue
    family = bucket.get("owner_family")
    symbols = bucket.get("symbols", [])
    if isinstance(family, str) and isinstance(symbols, list):
        missing_exports_by_family[family] += len(symbols)
        missing_export_symbols.setdefault(family, []).extend(str(symbol) for symbol in symbols)

residual_forbidden_count = int(residual.get("current_truth", {}).get("residual_forbidden_count", -1))
hardened_gap_groups = [
    group.get("id")
    for group in hardened.get("risk_groups", [])
    if isinstance(group, dict) and group.get("coverage_status") == "gap_identified"
]

records = family_thresholds.get("threshold_records", [])
if not isinstance(records, list) or not records:
    fail("replacement_readiness_family_missing", "family coverage threshold records must be non-empty", source_commit=source_commit)

family_reports = []
for record in records:
    family = record.get("family_id")
    if not isinstance(family, str) or not family:
        fail("replacement_readiness_family_missing", "threshold record missing family_id", source_commit=source_commit)
    status_counter = status_by_family.get(family, Counter())
    status_total = sum(status_counter.values())
    status_supported = sum(count for status, count in status_counter.items() if status in supported_statuses)
    status_pct = 100.0 if status_total == 0 else round(status_supported * 100.0 / status_total, 2)

    failures = []
    if status_total == 0 or status_pct < float(policy["minimum_supported_status_pct"]):
        failures.append("unsupported_status")
    missing_export_count = int(missing_exports_by_family[family])
    if missing_export_count > int(policy["maximum_missing_exports_per_family"]):
        failures.append("missing_version_export")
    if residual_forbidden_count > int(policy["maximum_residual_callthrough_count"]):
        failures.append("residual_callthrough")
    if record.get("decision") != policy["required_family_coverage_decision"]:
        failures.append("fixture_threshold_failed")

    decision = "pass" if not failures else "fail"
    family_reports.append(
        {
            "family_id": family,
            "decision": decision,
            "failure_reasons": failures,
            "support_symbol_count": status_total,
            "support_supported_symbol_count": status_supported,
            "supported_status_pct": status_pct,
            "missing_export_count": missing_export_count,
            "missing_export_symbols": missing_export_symbols.get(family, []),
            "residual_forbidden_callthrough_count": residual_forbidden_count,
            "family_coverage_decision": record.get("decision"),
            "family_coverage_failure_signature": record.get("failure_signature"),
            "target_uncovered_symbols": record.get("symbol_count", {}).get("uncovered"),
            "artifact_refs": [
                str(input_paths["support_matrix"]),
                str(input_paths["support_reality_drift_triage"]),
                str(input_paths["residual_replacement_callthrough_blockers"]),
                str(input_paths["family_coverage_thresholds"]),
            ],
        }
    )

family_pass_count = sum(1 for row in family_reports if row["decision"] == "pass")
family_fail_count = sum(1 for row in family_reports if row["decision"] == "fail")
claim_gate_decision = "ready" if family_fail_count == 0 else policy["claim_gate_decision_when_any_family_fails"]
actual_summary = {
    "family_count": len(family_reports),
    "family_pass_count": family_pass_count,
    "family_fail_count": family_fail_count,
    "aggregate_support_green": aggregate_support_green,
    "support_symbol_count": support_symbol_count,
    "support_supported_symbol_count": support_supported_symbol_count,
    "missing_export_count": sum(missing_exports_by_family.values()),
    "families_with_missing_exports": sorted(missing_exports_by_family),
    "residual_forbidden_callthrough_count": residual_forbidden_count,
    "family_coverage_fail_count": sum(1 for record in records if record.get("decision") == "fail"),
    "hardened_coverage_gap_group_count": len(hardened_gap_groups),
    "claim_gate_decision": claim_gate_decision,
}

expected_summary = contract.get("expected_current_summary", {})
if actual_summary != expected_summary:
    fail(
        "replacement_readiness_summary_mismatch",
        "expected_current_summary does not match current evidence",
        source_commit=source_commit,
        expected=expected_summary,
        actual=actual_summary,
    )

if aggregate_support_green and family_fail_count and claim_gate_decision != "blocked":
    fail(
        "replacement_readiness_aggregate_overclaim",
        "aggregate support status is green but family failures must block readiness",
        source_commit=source_commit,
        family_fail_count=family_fail_count,
        claim_gate_decision=claim_gate_decision,
    )

top_failed = sorted(
    [row for row in family_reports if row["decision"] == "fail"],
    key=lambda row: (-(row["target_uncovered_symbols"] or 0), row["family_id"]),
)[:12]

report = {
    "schema_version": "replacement_readiness_acceptance_thresholds.report.v1",
    "bead": EXPECTED_BEAD,
    "trace_id": trace_id,
    "source_commit": source_commit,
    "mode": mode,
    "outcome": "pass",
    "failure_signature": None,
    "contract": str(contract_path),
    "summary": {
        **actual_summary,
        "input_gate_results": gate_results,
        "hardened_gap_groups": hardened_gap_groups,
        "top_failed_families": top_failed,
    },
    "family_decisions": family_reports,
}
finish(report, "replacement_readiness_acceptance_thresholds_validated")
print(
    "PASS: replacement readiness thresholds validated "
    f"families={len(family_reports)} decision={claim_gate_decision} "
    f"family_failures={family_fail_count} missing_exports={actual_summary['missing_export_count']}"
)
PY
