#!/usr/bin/env bash
# check_user_visible_diagnostics.sh -- deterministic diagnostic catalog gate for bd-bp8fl.10.5
#
# Validates the user-visible diagnostic catalog, semantic-overlay lookups,
# replacement-level mapping, redaction policy, strict/hardened differences, and
# claim-blocking negative cases. Emits stable user-facing diagnostic examples
# plus structured report/log artifacts under target/conformance.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FLC_USER_DIAGNOSTICS_ARTIFACT:-${ROOT}/tests/conformance/user_visible_diagnostics.v1.json}"
OUT_DIR="${FLC_USER_DIAGNOSTICS_OUT_DIR:-${ROOT}/target/conformance/user_visible_diagnostics.outputs}"
REPORT="${FLC_USER_DIAGNOSTICS_REPORT:-${ROOT}/target/conformance/user_visible_diagnostics.report.json}"
LOG="${FLC_USER_DIAGNOSTICS_LOG:-${ROOT}/target/conformance/user_visible_diagnostics.log.jsonl}"
MODE="${1:---emit-fixtures}"

case "${MODE}" in
  --emit-fixtures|--dry-run|--validate-only)
    ;;
  *)
    echo "usage: $0 [--emit-fixtures|--dry-run|--validate-only]" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${ARTIFACT}" "${OUT_DIR}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])
mode = sys.argv[6]

REQUIRED_TYPES = {
    "native_behavior",
    "host_delegation",
    "raw_syscall",
    "deterministic_fallback",
    "hardened_repair",
    "denial",
    "unsupported_symbol",
    "noop_fallback",
}
CLAIM_BLOCKED_TYPES = {
    "host_delegation",
    "deterministic_fallback",
    "denial",
    "unsupported_symbol",
    "noop_fallback",
}
ALLOWED_SUPPORT_CLAIMS = {"never", "on_current_evidence"}
REQUIRED_RECORD_FIELDS = [
    "scenario_id",
    "diagnostic_type",
    "symbol",
    "api_family",
    "runtime_mode",
    "replacement_level",
    "support_status",
    "semantic_join_inventory_id",
    "semantic_class",
    "decision_path",
    "healing_action",
    "diagnostic_code",
    "user_message_id",
    "user_message",
    "support_claim",
    "artifact_refs",
    "evidence_status",
    "source_commit",
    "failure_signature",
    "expected_output",
]
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "scenario_id",
    "symbol",
    "api_family",
    "runtime_mode",
    "replacement_level",
    "decision_path",
    "healing_action",
    "diagnostic_code",
    "user_message_id",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]

errors = []
checks = {}
log_rows = []
output_refs = []


def load_json(path, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label}: failed to parse {path}: {exc}")
        return {}


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def artifact_path_exists(ref):
    path = root / str(ref).split("#", 1)[0]
    return path.exists()


def current_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


source_commit = current_commit()
artifact = load_json(artifact_path, "artifact")
support = load_json(root / artifact.get("inputs", {}).get("support_matrix", ""), "support_matrix")
semantic_join = load_json(
    root / artifact.get("inputs", {}).get("semantic_join", ""), "semantic_join"
)
replacement_levels = load_json(
    root / artifact.get("inputs", {}).get("replacement_levels", ""),
    "replacement_levels",
)
repair_deny_matrix = load_json(
    root / artifact.get("inputs", {}).get("hardened_repair_deny_matrix", ""),
    "hardened_repair_deny_matrix",
)

if artifact.get("schema_version") == "v1" and artifact.get("bead") == "bd-bp8fl.10.5":
    checks["artifact_shape"] = "pass"
else:
    checks["artifact_shape"] = "fail"
    errors.append("artifact must declare schema_version=v1 and bead=bd-bp8fl.10.5")

inputs = artifact.get("inputs", {})
missing_inputs = [
    ref for ref in inputs.values() if not (root / str(ref).split("#", 1)[0]).exists()
]
if inputs and not missing_inputs:
    checks["input_artifacts_exist"] = "pass"
else:
    checks["input_artifacts_exist"] = "fail"
    errors.append(f"missing input artifacts: {missing_inputs}")

if artifact.get("required_record_fields") == REQUIRED_RECORD_FIELDS:
    checks["required_record_fields"] = "pass"
else:
    checks["required_record_fields"] = "fail"
    errors.append("required_record_fields must match the diagnostic record schema")

if artifact.get("required_log_fields") == REQUIRED_LOG_FIELDS:
    checks["required_log_fields"] = "pass"
else:
    checks["required_log_fields"] = "fail"
    errors.append("required_log_fields must match the structured log schema")

type_rows = artifact.get("diagnostic_types", [])
type_by_id = {
    row.get("id"): row for row in type_rows if isinstance(row, dict) and row.get("id")
}
if set(type_by_id) == REQUIRED_TYPES:
    checks["diagnostic_type_coverage"] = "pass"
else:
    checks["diagnostic_type_coverage"] = "fail"
    errors.append(
        f"diagnostic_types must cover {sorted(REQUIRED_TYPES)}, got {sorted(type_by_id)}"
    )

code_by_type = {
    type_id: row.get("diagnostic_code") for type_id, row in type_by_id.items()
}
message_id_by_type = {
    type_id: row.get("user_message_id") for type_id, row in type_by_id.items()
}

support_by_symbol = {
    row.get("symbol"): row
    for row in support.get("symbols", [])
    if isinstance(row, dict) and row.get("symbol")
}
semantic_by_id = {
    row.get("inventory_id"): row
    for row in semantic_join.get("entries", [])
    if isinstance(row, dict) and row.get("inventory_id")
}
levels = {
    row.get("level")
    for row in replacement_levels.get("levels", [])
    if isinstance(row, dict) and row.get("level")
}
repair_deny_entries = [
    row for row in repair_deny_matrix.get("entries", []) if isinstance(row, dict)
]

records = artifact.get("records", [])
records_by_id = {}
type_counts = Counter()
mode_counts = Counter()
claim_counts = Counter()
stable_outputs = {}
record_errors_before = len(errors)
for row in records:
    scenario_id = row.get("scenario_id", "<missing>")
    if scenario_id in records_by_id:
        errors.append(f"duplicate scenario_id {scenario_id}")
    records_by_id[scenario_id] = row

    for field in REQUIRED_RECORD_FIELDS:
        if field not in row:
            errors.append(f"{scenario_id}: missing record field {field}")

    diagnostic_type = row.get("diagnostic_type")
    type_counts[diagnostic_type] += 1
    mode_counts[row.get("runtime_mode")] += 1
    claim_counts[row.get("support_claim")] += 1

    if diagnostic_type not in REQUIRED_TYPES:
        errors.append(f"{scenario_id}: unknown diagnostic_type {diagnostic_type}")
        continue

    if row.get("diagnostic_code") != code_by_type.get(diagnostic_type):
        errors.append(f"{scenario_id}: diagnostic_code does not match diagnostic_type")
    if row.get("user_message_id") != message_id_by_type.get(diagnostic_type):
        errors.append(f"{scenario_id}: user_message_id does not match diagnostic_type")

    if row.get("support_claim") not in ALLOWED_SUPPORT_CLAIMS:
        errors.append(f"{scenario_id}: unsupported support_claim {row.get('support_claim')}")
    if diagnostic_type in CLAIM_BLOCKED_TYPES and row.get("support_claim") != "never":
        errors.append(f"{scenario_id}: claim-blocked diagnostic must set support_claim=never")
    if row.get("replacement_level") not in levels:
        errors.append(f"{scenario_id}: unknown replacement_level {row.get('replacement_level')}")
    if row.get("runtime_mode") not in {"strict", "hardened"}:
        errors.append(f"{scenario_id}: runtime_mode must be strict or hardened")

    symbol = row.get("symbol")
    support_row = support_by_symbol.get(symbol)
    if support_row is None:
        if diagnostic_type == "host_delegation" and row.get("evidence_status") == "not_current_support_matrix":
            pass
        else:
            errors.append(f"{scenario_id}: symbol {symbol} missing from support_matrix")
    elif support_row.get("status") != row.get("support_status"):
        errors.append(
            f"{scenario_id}: support_status expected {support_row.get('status')} got {row.get('support_status')}"
        )

    semantic_id = row.get("semantic_join_inventory_id")
    if semantic_id is not None:
        semantic_row = semantic_by_id.get(semantic_id)
        if semantic_row is None:
            errors.append(f"{scenario_id}: missing semantic join row {semantic_id}")
        else:
            if row.get("semantic_class") != semantic_row.get("semantic_class"):
                errors.append(f"{scenario_id}: semantic_class does not match semantic join row")
            if symbol not in semantic_row.get("symbol_refs", []):
                errors.append(f"{scenario_id}: semantic join row does not reference {symbol}")

    for artifact_ref in row.get("artifact_refs", []):
        if not artifact_path_exists(artifact_ref):
            errors.append(f"{scenario_id}: missing artifact_ref {artifact_ref}")

    user_message = str(row.get("user_message", ""))
    forbidden = [
        frag
        for frag in artifact.get("diagnostic_policy", {})
        .get("redaction", {})
        .get("forbidden_user_message_fragments", [])
        if frag.lower() in user_message.lower()
    ]
    if forbidden:
        errors.append(f"{scenario_id}: user_message contains forbidden fragments {forbidden}")

    expected_output = (
        f"{row.get('diagnostic_code')} {symbol} {row.get('runtime_mode')} "
        f"{row.get('replacement_level')}: {row.get('user_message')}"
    )
    if row.get("expected_output") != expected_output:
        errors.append(f"{scenario_id}: expected_output does not match stable template")
    stable_outputs[scenario_id] = expected_output

    if row.get("source_commit") != "HEAD":
        errors.append(f"{scenario_id}: source_commit must be HEAD for current-source replay")

    if diagnostic_type in {"hardened_repair", "denial"}:
        wanted_decision = "Repair" if diagnostic_type == "hardened_repair" else "Deny"
        matches = [
            entry
            for entry in repair_deny_entries
            if entry.get("symbol") == symbol
            and entry.get("decision_path") == wanted_decision
            and entry.get("healing_action") == row.get("healing_action")
        ]
        if not matches:
            errors.append(f"{scenario_id}: missing matching repair/deny matrix row")

if len(records_by_id) == len(records) and records:
    checks["record_ids_unique"] = "pass"
else:
    checks["record_ids_unique"] = "fail"

if not errors[record_errors_before:]:
    checks["record_contracts"] = "pass"
else:
    checks["record_contracts"] = "fail"

if set(type_counts) == REQUIRED_TYPES and all(type_counts[t] >= 1 for t in REQUIRED_TYPES):
    checks["record_type_coverage"] = "pass"
else:
    checks["record_type_coverage"] = "fail"
    errors.append(f"records must cover every diagnostic type, got {dict(type_counts)}")

pair_errors_before = len(errors)
for pair in artifact.get("mode_pairs", []):
    strict = records_by_id.get(pair.get("strict_record"))
    hardened = records_by_id.get(pair.get("hardened_record"))
    if strict is None or hardened is None:
        errors.append(f"mode pair missing records: {pair}")
        continue
    if strict.get("symbol") != hardened.get("symbol"):
        errors.append(f"mode pair symbols differ: {pair}")
    if strict.get("runtime_mode") != "strict" or hardened.get("runtime_mode") != "hardened":
        errors.append(f"mode pair modes are wrong: {pair}")
    if strict.get("decision_path") == hardened.get("decision_path"):
        errors.append(f"mode pair decision paths must differ: {pair}")
    if strict.get("healing_action") != "None" or hardened.get("healing_action") == "None":
        errors.append(f"mode pair must show hardened repair delta: {pair}")
checks["strict_hardened_difference"] = "pass" if len(errors) == pair_errors_before else "fail"

negative_errors_before = len(errors)
for neg in artifact.get("negative_claim_tests", []):
    record = records_by_id.get(neg.get("record"))
    if record is None:
        errors.append(f"{neg.get('scenario_id')}: missing referenced record")
        continue
    if neg.get("expected_result") != "claim_blocked":
        errors.append(f"{neg.get('scenario_id')}: expected_result must be claim_blocked")
    if record.get("support_claim") != "never":
        errors.append(f"{neg.get('scenario_id')}: referenced record must set support_claim=never")
    if neg.get("failure_signature") != record.get("failure_signature"):
        errors.append(f"{neg.get('scenario_id')}: failure_signature mismatch")
checks["negative_claim_tests"] = "pass" if len(errors) == negative_errors_before else "fail"

summary = artifact.get("summary", {})
expected_summary = {
    "diagnostic_type_count": len(REQUIRED_TYPES),
    "record_count": len(records),
    "stable_output_count": len(stable_outputs),
    "required_log_field_count": len(REQUIRED_LOG_FIELDS),
    "negative_claim_test_count": len(artifact.get("negative_claim_tests", [])),
    "strict_records": mode_counts["strict"],
    "hardened_records": mode_counts["hardened"],
    "support_claim_never_count": claim_counts["never"],
    "support_claim_on_current_evidence_count": claim_counts["on_current_evidence"],
}
if all(summary.get(key) == value for key, value in expected_summary.items()):
    checks["summary_matches_records"] = "pass"
else:
    checks["summary_matches_records"] = "fail"
    errors.append(f"summary mismatch expected={expected_summary} actual={summary}")

out_dir.mkdir(parents=True, exist_ok=True)
for row in records:
    scenario_id = row.get("scenario_id")
    output_text = stable_outputs.get(scenario_id, "")
    if mode in {"--emit-fixtures", "--dry-run"}:
        output_path = out_dir / f"{scenario_id}.txt"
        output_path.write_text(output_text + "\n", encoding="utf-8")
        output_refs.append(rel(output_path))
    log_row = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "user_visible_diagnostic",
        "trace_id": f"bd-bp8fl.10.5::{scenario_id}",
        "bead_id": "bd-bp8fl.10.5",
        "scenario_id": scenario_id,
        "symbol": row.get("symbol"),
        "api_family": row.get("api_family"),
        "runtime_mode": row.get("runtime_mode"),
        "replacement_level": row.get("replacement_level"),
        "decision_path": row.get("decision_path"),
        "healing_action": row.get("healing_action"),
        "diagnostic_code": row.get("diagnostic_code"),
        "user_message_id": row.get("user_message_id"),
        "artifact_refs": row.get("artifact_refs"),
        "source_commit": source_commit,
        "failure_signature": row.get("failure_signature"),
        "support_claim": row.get("support_claim"),
        "output": output_text,
    }
    for field in REQUIRED_LOG_FIELDS:
        if field not in log_row:
            errors.append(f"{scenario_id}: emitted log row missing {field}")
    log_rows.append(log_row)

if log_rows and all(field in log_rows[0] for field in REQUIRED_LOG_FIELDS):
    checks["structured_log_rows"] = "pass"
else:
    checks["structured_log_rows"] = "fail"

log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows),
    encoding="utf-8",
)

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.10.5",
    "mode": mode,
    "status": status,
    "checks": checks,
    "summary": {
        **expected_summary,
        "diagnostic_types": sorted(REQUIRED_TYPES),
        "blocked_diagnostic_types": sorted(CLAIM_BLOCKED_TYPES),
        "emitted_log_rows": len(log_rows),
        "emitted_output_files": len(output_refs),
        "source_commit": source_commit,
    },
    "artifact_refs": [
        rel(artifact_path),
        rel(report_path),
        rel(log_path),
        *output_refs,
    ],
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    sys.exit(1)
PY
