#!/usr/bin/env bash
# Gate for bd-juvqm.6: strict/hardened decision-trace minimizer.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MANIFEST="${STRICT_HARDENED_DECISION_TRACE_MINIMIZER_MANIFEST:-$ROOT/tests/conformance/strict_hardened_decision_trace_minimizer.v1.json}"
REPORT="${STRICT_HARDENED_DECISION_TRACE_MINIMIZER_REPORT:-$ROOT/target/conformance/strict_hardened_decision_trace_minimizer.report.json}"
LOG="${STRICT_HARDENED_DECISION_TRACE_MINIMIZER_LOG:-$ROOT/target/conformance/strict_hardened_decision_trace_minimizer.log.jsonl}"
MODE="validate-only"
CASE_FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --validate-only)
      MODE="validate-only"
      shift
      ;;
    --case)
      CASE_FILTER="${2:-}"
      if [[ -z "$CASE_FILTER" ]]; then
        echo "FAIL[missing_case_arg]: --case requires a case_id" >&2
        exit 1
      fi
      shift 2
      ;;
    *)
      MODE="unknown:$1"
      shift
      ;;
  esac
done

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$MANIFEST" "$REPORT" "$LOG" "$MODE" "$CASE_FILTER" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
from collections import OrderedDict

root = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
mode = sys.argv[5]
case_filter = sys.argv[6]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "strict_hardened_decision_trace_minimizer.v1"
EXPECTED_MANIFEST = "strict-hardened-decision-trace-minimizer"
EXPECTED_BEAD = "bd-juvqm.6"
EXPECTED_CHECKER = "scripts/check_strict_hardened_decision_trace_minimizer.sh --validate-only"
EXPECTED_REPORT = "target/conformance/strict_hardened_decision_trace_minimizer.report.json"
EXPECTED_LOG = "target/conformance/strict_hardened_decision_trace_minimizer.log.jsonl"
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "bead",
    "trace_id",
    "source_commit",
    "mode",
    "case_filter",
    "outcome",
    "failure_signature",
    "message",
    "manifest",
    "duration_ms",
    "summary",
    "report_path",
    "log_path",
    "report_contract_fields",
    "contract_status",
    "contract_errors",
}
REPORT_CONTRACT_FIELDS: list[str] = []
CONTRACT_ERRORS: list[str] = []


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip()
    except Exception:
        return "unknown"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def finish(outcome: str, signature: str, message: str, **summary) -> None:
    duration_ns = time.time_ns() - start_ns
    report = {
        "schema_version": "strict_hardened_decision_trace_minimizer.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": "strict-hardened-decision-trace-minimizer",
        "source_commit": git_head(),
        "mode": mode,
        "case_filter": case_filter,
        "outcome": outcome,
        "failure_signature": signature,
        "message": message,
        "manifest": rel(manifest_path),
        "duration_ms": duration_ns // 1_000_000,
        "summary": summary,
        "report_path": rel(report_path),
        "log_path": rel(log_path),
        "report_contract_fields": REPORT_CONTRACT_FIELDS,
        "contract_status": "pending",
        "contract_errors": [],
    }
    contract_errors = list(CONTRACT_ERRORS)
    missing_report_fields = [field for field in REPORT_CONTRACT_FIELDS if field not in report]
    if missing_report_fields:
        contract_errors.append(f"missing_report_field:{','.join(missing_report_fields)}")
    report["contract_status"] = "pass" if not contract_errors else "fail"
    report["contract_errors"] = contract_errors
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_row = {
        "timestamp": now_utc(),
        "event": "strict_hardened_decision_trace_minimizer_validated"
        if outcome == "pass"
        else "strict_hardened_decision_trace_minimizer_failed",
        "trace_id": "strict-hardened-decision-trace-minimizer",
        "mode": mode,
        "api_family": "harness",
        "symbol": "decision_trace_minimizer",
        "decision_path": outcome,
        "latency_ns": duration_ns,
        "artifact_refs": [rel(manifest_path), rel(report_path)],
        "bead": EXPECTED_BEAD,
        "failure_signature": signature,
    }
    log_path.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")
    if outcome != "pass" or contract_errors:
        raise SystemExit(f"FAIL[{signature}]: {message}")


def fail(signature: str, message: str, **summary) -> None:
    finish("fail", signature, message, **summary)


def require(condition: bool, signature: str, message: str, **summary) -> None:
    if not condition:
        fail(signature, message, **summary)


def load_manifest() -> dict:
    require(manifest_path.is_file(), "input_missing", f"manifest missing: {manifest_path}")
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        fail("json_parse", f"manifest is not valid JSON: {err}")
    raise AssertionError("unreachable")


def non_empty_string(value: dict, key: str, context: str) -> str:
    item = value.get(key)
    require(isinstance(item, str) and item, "missing_string", f"{context}.{key} must be a non-empty string")
    return item


def non_empty_list(value: dict, key: str, context: str) -> list:
    item = value.get(key)
    require(isinstance(item, list) and item, "missing_array", f"{context}.{key} must be a non-empty array")
    return item


def report_contract_field_list(manifest: dict) -> list[str]:
    report_contract = manifest.get("report_contract")
    if not isinstance(report_contract, dict):
        return []
    fields = report_contract.get("must_materialize")
    if not isinstance(fields, list):
        return []
    return [field for field in fields if isinstance(field, str) and field]


def validate_report_contract(manifest: dict) -> list[str]:
    errors: list[str] = []
    report_contract = manifest.get("report_contract")
    if not isinstance(report_contract, dict):
        return ["report_contract_not_object"]
    if report_contract.get("output_path") != rel(report_path):
        errors.append("report_contract_output_path_mismatch")
    if report_contract.get("log_path") != rel(log_path):
        errors.append("report_contract_log_path_mismatch")
    fields = set(report_contract_field_list(manifest))
    missing = sorted(REQUIRED_REPORT_FIELDS - fields)
    if missing:
        errors.append(f"report_contract_missing_required_field:{','.join(missing)}")
    return errors


def row_key(row: dict, identity_fields: list[str]) -> tuple:
    return tuple(row[field] for field in identity_fields)


def row_projection(row: dict, fields: list[str]) -> tuple:
    return tuple(json.dumps(row.get(field), sort_keys=True) for field in fields)


def changed_fields(left: dict, right: dict, fields: list[str]) -> list[str]:
    return [
        field
        for field in fields
        if json.dumps(left.get(field), sort_keys=True)
        != json.dumps(right.get(field), sort_keys=True)
    ]


def collect_artifact_refs(rows: list[dict], case_refs: list[str]) -> list[str]:
    refs = set(case_refs)
    for row in rows:
        refs.update(row.get("artifact_refs", []))
    return sorted(refs)


def minimize_case(case: dict, identity_fields: list[str], divergence_fields: list[str], row_fields: list[str]) -> dict:
    case_id = non_empty_string(case, "case_id", "trace_case")
    case_schema = non_empty_string(case, "schema_version", case_id)
    artifact_refs = non_empty_list(case, "artifact_refs", case_id)
    replay_command = non_empty_string(case, "replay_command", case_id)
    expected_signature = non_empty_string(case, "expected_failure_signature", case_id)
    rows = non_empty_list(case, "rows", case_id)

    ordered_pairs: "OrderedDict[tuple, dict[str, tuple[int, dict]]]" = OrderedDict()
    for index, row in enumerate(rows):
        require(isinstance(row, dict), "row_not_object", f"{case_id}.rows[{index}] must be an object")
        for field in row_fields:
            require(field in row, "missing_required_row_field", f"{case_id}.rows[{index}] missing {field}", case_id=case_id, field=field)
        require(row["schema_version"] == case_schema, "row_schema_mismatch", f"{case_id}.rows[{index}] schema_version mismatches case schema")
        require(row["mode"] in {"strict", "hardened"}, "unsupported_mode", f"{case_id}.rows[{index}] mode must be strict or hardened")
        require(isinstance(row["artifact_refs"], list) and row["artifact_refs"], "missing_row_artifact_refs", f"{case_id}.rows[{index}] artifact_refs must be non-empty")
        key = row_key(row, identity_fields)
        modes = ordered_pairs.setdefault(key, {})
        require(row["mode"] not in modes, "duplicate_mode_row", f"{case_id} has duplicate {row['mode']} row for {key}")
        modes[row["mode"]] = (index, row)

    for key, modes in ordered_pairs.items():
        require({"strict", "hardened"}.issubset(modes), "missing_mode_pair", f"{case_id} missing strict/hardened pair for {key}", case_id=case_id, key=list(key))

    first_divergence = None
    equivalent_keys = set()
    for key, modes in ordered_pairs.items():
        strict_index, strict_row = modes["strict"]
        hardened_index, hardened_row = modes["hardened"]
        if row_projection(strict_row, divergence_fields) != row_projection(hardened_row, divergence_fields):
            first_divergence = (
                key,
                strict_index,
                hardened_index,
                strict_row,
                hardened_row,
                changed_fields(strict_row, hardened_row, divergence_fields),
            )
            break
        equivalent_keys.add(key)

    dropped_rows = []
    if first_divergence is None:
        require(expected_signature == "no_divergence", "expected_failure_signature_mismatch", f"{case_id} expected no_divergence signature")
        for index, row in enumerate(rows):
            dropped_rows.append(
                {
                    "row_index": index,
                    "trace_id": row["trace_id"],
                    "reason": "no_divergence_control",
                }
            )
        return {
            "case_id": case_id,
            "source_kind": case.get("source_kind", "runtime_decision_jsonl"),
            "source_commit": git_head(),
            "original_artifact_refs": collect_artifact_refs(rows, artifact_refs),
            "minimized_trace": [],
            "dropped_rows": dropped_rows,
            "replay_command": replay_command,
            "expected_failure_signature": "no_divergence",
            "first_divergent_key": None,
        }

    key, strict_index, hardened_index, strict_row, hardened_row, changed = first_divergence
    signature = "mode_divergence:" + ",".join(changed)
    require(signature == expected_signature, "expected_failure_signature_mismatch", f"{case_id} expected {expected_signature}, computed {signature}")
    keep = {strict_index, hardened_index}
    for index, row in enumerate(rows):
        if index in keep:
            continue
        reason = "pre_divergence_equivalent" if row_key(row, identity_fields) in equivalent_keys else "post_divergence_irrelevant"
        dropped_rows.append(
            {
                "row_index": index,
                "trace_id": row["trace_id"],
                "reason": reason,
            }
        )
    minimized_trace = [
        {"original_index": strict_index, **strict_row},
        {"original_index": hardened_index, **hardened_row},
    ]
    return {
        "case_id": case_id,
        "source_kind": case.get("source_kind", "runtime_decision_jsonl"),
        "source_commit": git_head(),
        "original_artifact_refs": collect_artifact_refs(rows, artifact_refs),
        "minimized_trace": minimized_trace,
        "dropped_rows": dropped_rows,
        "replay_command": replay_command,
        "expected_failure_signature": signature,
        "first_divergent_key": dict(zip(identity_fields, key)),
    }


def validate() -> None:
    global CONTRACT_ERRORS, REPORT_CONTRACT_FIELDS
    if mode != "validate-only":
        fail("unknown_mode", f"only --validate-only is supported; got {mode}")

    manifest = load_manifest()
    REPORT_CONTRACT_FIELDS = report_contract_field_list(manifest)
    CONTRACT_ERRORS = validate_report_contract(manifest)
    if CONTRACT_ERRORS:
        fail(
            "report_contract",
            "report_contract must bind output/log paths and required report fields",
            contract_errors=CONTRACT_ERRORS,
        )
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected schema_version")
    require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id", "unexpected manifest_id")
    require(manifest.get("bead") == EXPECTED_BEAD, "bead", "unexpected bead")
    require(manifest.get("canonical_checker") == EXPECTED_CHECKER, "canonical_checker", "unexpected canonical_checker")
    require(len(non_empty_string(manifest, "regeneration_note", "manifest")) >= 40, "regeneration_note_missing", "regeneration_note must describe update policy")

    input_contract = manifest.get("input_contract")
    require(isinstance(input_contract, dict), "missing_input_contract", "input_contract must be an object")
    identity_fields = [str(field) for field in non_empty_list(input_contract, "identity_key_fields", "input_contract")]
    row_fields = [str(field) for field in non_empty_list(input_contract, "required_row_fields", "input_contract")]
    divergence_fields = [str(field) for field in non_empty_list(input_contract, "divergence_fields", "input_contract")]
    require({"strict", "hardened"} == set(non_empty_list(input_contract, "required_modes", "input_contract")), "required_modes", "required_modes must be strict+hardened")
    for field in identity_fields + divergence_fields + ["mode", "artifact_refs", "schema_version", "trace_id"]:
        require(field in row_fields, "required_field_coverage", f"required_row_fields must include {field}")

    output_contract = manifest.get("output_contract")
    require(isinstance(output_contract, dict), "missing_output_contract", "output_contract must be an object")
    required_bundle_fields = set(non_empty_list(output_contract, "required_bundle_fields", "output_contract"))
    for field in ["case_id", "source_commit", "original_artifact_refs", "minimized_trace", "dropped_rows", "replay_command", "expected_failure_signature"]:
        require(field in required_bundle_fields, "bundle_contract_missing_field", f"output bundle contract missing {field}")

    trace_cases = non_empty_list(manifest, "trace_cases", "manifest")
    if case_filter:
        trace_cases = [case for case in trace_cases if case.get("case_id") == case_filter]
        require(trace_cases, "unknown_case", f"no trace_case found for --case {case_filter}")

    bundles = [
        minimize_case(case, identity_fields, divergence_fields, row_fields)
        for case in trace_cases
    ]
    divergent = [bundle for bundle in bundles if bundle["expected_failure_signature"] != "no_divergence"]
    no_divergence = [bundle for bundle in bundles if bundle["expected_failure_signature"] == "no_divergence"]
    if not case_filter:
        require(divergent, "missing_divergence_case", "at least one divergent synthetic case is required")
        require(no_divergence, "missing_no_divergence_case", "at least one no-divergence control is required")

    finish(
        "pass",
        "none",
        "strict/hardened decision trace minimizer contract passed",
        case_count=len(bundles),
        divergent_case_count=len(divergent),
        no_divergence_case_count=len(no_divergence),
        bundles=bundles,
    )


validate()
PY
