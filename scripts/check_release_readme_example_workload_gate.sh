#!/usr/bin/env bash
# check_release_readme_example_workload_gate.sh -- bd-bp8fl.10.4 README/release example workload-evidence gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${FRANKENLIBC_RELEASE_README_EXAMPLE_GATE:-${ROOT}/tests/conformance/release_readme_example_workload_gate.v1.json}"
OUT_DIR="${FRANKENLIBC_RELEASE_README_EXAMPLE_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_RELEASE_README_EXAMPLE_REPORT:-${OUT_DIR}/release_readme_example_workload_gate.report.json}"
LOG="${FRANKENLIBC_RELEASE_README_EXAMPLE_LOG:-${OUT_DIR}/release_readme_example_workload_gate.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONFIG}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
config_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "claim_id",
    "doc_surface",
    "workload_id",
    "replacement_level",
    "runtime_mode",
    "expected_decision",
    "actual_decision",
    "evidence_refs",
    "source_commit",
    "failure_signature",
]

errors: list[str] = []
logs: list[dict[str, object]] = []


def load_json(path: Path, name: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{name}: cannot load {path}: {exc}")
        return {}


def repo_path(rel: str) -> Path:
    path = Path(rel)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay inside repo: {rel}")
    return root / path


def read_text(rel: str) -> str:
    try:
        return repo_path(rel).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def exists(rel: str) -> bool:
    try:
        return repo_path(rel).exists()
    except ValueError:
        return False


def append_log(
    *,
    claim_id: str,
    doc_surface: str,
    workload_id: str,
    replacement_level: str,
    runtime_modes: list[str],
    expected_decision: str,
    actual_decision: str,
    evidence_refs: list[str],
    failure_signature: str,
) -> None:
    modes = runtime_modes if runtime_modes else ["unspecified"]
    for mode in modes:
        logs.append(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "trace_id": f"bd-bp8fl.10.4::{claim_id}::{mode}",
                "bead_id": "bd-bp8fl.10.4",
                "claim_id": claim_id,
                "doc_surface": doc_surface,
                "workload_id": workload_id,
                "replacement_level": replacement_level,
                "runtime_mode": mode,
                "expected_decision": expected_decision,
                "actual_decision": actual_decision,
                "evidence_refs": evidence_refs,
                "source_commit": source_commit,
                "failure_signature": failure_signature,
            }
        )


def support_symbols(support_matrix: object) -> set[str]:
    if not isinstance(support_matrix, dict):
        return set()
    rows = support_matrix.get("symbols", [])
    if not isinstance(rows, list):
        return set()
    return {str(row.get("symbol")) for row in rows if isinstance(row, dict) and row.get("symbol")}


def semantic_ids(overlay: object) -> set[str]:
    if not isinstance(overlay, dict):
        return set()
    rows = overlay.get("audited_entries", [])
    if not isinstance(rows, list):
        return set()
    return {str(row.get("id")) for row in rows if isinstance(row, dict) and row.get("id")}


def workload_info(matrix: object) -> dict[str, dict[str, object]]:
    if not isinstance(matrix, dict):
        return {}
    rows = matrix.get("workloads", [])
    if not isinstance(rows, list):
        return {}
    return {str(row.get("id")): row for row in rows if isinstance(row, dict) and row.get("id")}


def replacement_current_level(levels: object) -> str:
    if isinstance(levels, dict):
        return str(levels.get("current_level", ""))
    return ""


def replacement_levels(levels: object) -> set[str]:
    if not isinstance(levels, dict):
        return set()
    rows = levels.get("levels", [])
    if not isinstance(rows, list):
        return set()
    return {str(row.get("level")) for row in rows if isinstance(row, dict) and row.get("level")}


def smoke_mode_status(smoke: object, mode: str) -> str:
    if not isinstance(smoke, dict):
        return ""
    modes = smoke.get("modes", {})
    if not isinstance(modes, dict):
        return ""
    row = modes.get(mode, {})
    if not isinstance(row, dict):
        return ""
    return str(row.get("status", ""))


def smoke_overall_failed(smoke: object) -> bool | None:
    if not isinstance(smoke, dict):
        return None
    summary = smoke.get("summary", {})
    if not isinstance(summary, dict):
        return None
    value = summary.get("overall_failed")
    return value if isinstance(value, bool) else None


def compatibility_report_pass(report: object) -> bool:
    if not isinstance(report, dict):
        return False
    return report.get("status") == "pass" and report.get("summary", {}).get("errors") == 0


config = load_json(config_path, "release_readme_example_gate")
if not isinstance(config, dict):
    errors.append("config must be a JSON object")
    config = {}

if config.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if config.get("bead") != "bd-bp8fl.10.4":
    errors.append("bead must be bd-bp8fl.10.4")
if config.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_log_fields must match bd-bp8fl.10.4 contract")

inputs = config.get("inputs", {})
if not isinstance(inputs, dict):
    errors.append("inputs must be an object")
    inputs = {}

for name, rel in inputs.items():
    if not isinstance(rel, str) or not exists(rel):
        errors.append(f"input {name} missing: {rel}")

workloads = workload_info(load_json(repo_path(str(inputs.get("user_workload_acceptance_matrix", ""))), "user_workload_acceptance_matrix") if inputs.get("user_workload_acceptance_matrix") else {})
support = support_symbols(load_json(repo_path(str(inputs.get("support_matrix", ""))), "support_matrix") if inputs.get("support_matrix") else {})
semantics = semantic_ids(load_json(repo_path(str(inputs.get("semantic_overlay", ""))), "semantic_overlay") if inputs.get("semantic_overlay") else {})
levels_artifact = load_json(repo_path(str(inputs.get("replacement_levels", ""))), "replacement_levels") if inputs.get("replacement_levels") else {}
known_levels = replacement_levels(levels_artifact)
current_level = replacement_current_level(levels_artifact)
smoke = load_json(repo_path(str(inputs.get("smoke_summary", ""))), "smoke_summary") if inputs.get("smoke_summary") else {}
compat = load_json(repo_path(str(inputs.get("compatibility_report", ""))), "compatibility_report") if inputs.get("compatibility_report") else {}

ci = config.get("ci_integration", {})
if isinstance(ci, dict) and ci.get("required") is True:
    ci_file = str(ci.get("ci_file", ""))
    gate_script = str(ci.get("gate_script", ""))
    if not ci_file or not gate_script or gate_script not in read_text(ci_file):
        errors.append(f"ci hook missing: {ci_file} must invoke {gate_script}")


def decide(mapping: dict[str, object]) -> tuple[str, str, list[str]]:
    doc_surface = str(mapping.get("doc_surface", ""))
    doc_text = read_text(doc_surface)
    required_tokens = [str(token) for token in mapping.get("required_tokens", [])]
    missing_tokens = [token for token in required_tokens if token not in doc_text]
    if missing_tokens:
        return "block", "release_example_missing_doc_token", missing_tokens

    workload_id = str(mapping.get("workload_id", ""))
    workload = workloads.get(workload_id)
    if not workload:
        return "block", "release_example_missing_workload_row", [workload_id]

    runtime_modes = [str(mode) for mode in mapping.get("runtime_modes", [])]
    workload_modes = set(str(mode) for mode in workload.get("runtime_modes", [])) if isinstance(workload, dict) else set()
    missing_modes = [mode for mode in runtime_modes if mode not in workload_modes]
    if missing_modes:
        return "block", "release_example_missing_workload_row", missing_modes

    level = str(mapping.get("replacement_level", ""))
    if level not in known_levels:
        return "block", "release_example_unsupported_replacement_level", [level]

    advertise = mapping.get("advertises_support") is True
    if advertise and current_level and level > current_level:
        return "block", "release_example_unsupported_replacement_level", [f"{level}>{current_level}"]

    missing_symbols = [symbol for symbol in mapping.get("support_matrix_symbols", []) if str(symbol) not in support]
    if missing_symbols:
        return "block", "release_example_missing_support_matrix_row", [str(symbol) for symbol in missing_symbols]

    missing_semantics = [row_id for row_id in mapping.get("semantic_overlay_ids", []) if str(row_id) not in semantics]
    if missing_semantics:
        return "block", "release_example_missing_semantic_overlay_row", [str(row_id) for row_id in missing_semantics]

    evidence_refs = [str(ref) for ref in mapping.get("evidence_refs", [])]
    missing_refs = [ref for ref in evidence_refs if not exists(ref)]
    if missing_refs:
        return "block", "release_example_missing_compatibility_report", missing_refs

    if not compatibility_report_pass(compat):
        return "block", "release_example_missing_compatibility_report", [str(inputs.get("compatibility_report", ""))]

    smoke_expectation = mapping.get("smoke_expectation", {})
    if isinstance(smoke_expectation, dict):
        expected_overall = smoke_expectation.get("overall_failed")
        if isinstance(expected_overall, bool) and smoke_overall_failed(smoke) != expected_overall:
            return "block", "release_example_stale_smoke_evidence", ["overall_failed"]
        required_status = smoke_expectation.get("required_mode_status", {})
        if isinstance(required_status, dict):
            for mode, expected in required_status.items():
                if smoke_mode_status(smoke, str(mode)) != str(expected):
                    return "block", "release_example_stale_smoke_evidence", [str(mode)]

    freshness = str(mapping.get("freshness_state", ""))
    if advertise and freshness != "current":
        return "block", "release_example_stale_smoke_evidence", [freshness]

    if not advertise:
        token = str(mapping.get("known_limitation_token", ""))
        if not token or token not in doc_text:
            return "block", "release_example_unsupported_replacement_level", [token]
        return "allow_known_limitation", "none", []

    return "allow", "none", []


mappings = config.get("claim_mappings", [])
if not isinstance(mappings, list):
    errors.append("claim_mappings must be an array")
    mappings = []

mapping_reports: list[dict[str, object]] = []
for mapping in mappings:
    if not isinstance(mapping, dict):
        errors.append("claim mapping must be an object")
        continue
    claim_id = str(mapping.get("claim_id", ""))
    expected = str(mapping.get("expected_decision", ""))
    expected_failure = str(mapping.get("expected_failure_signature", ""))
    actual, failure, details = decide(mapping)
    if actual != expected:
        errors.append(f"{claim_id}: decision mismatch expected {expected} actual {actual}")
    if expected_failure and failure != expected_failure:
        errors.append(f"{claim_id}: failure mismatch expected {expected_failure} actual {failure}")
    evidence_refs = [str(ref) for ref in mapping.get("evidence_refs", [])]
    runtime_modes = [str(mode) for mode in mapping.get("runtime_modes", [])]
    append_log(
        claim_id=claim_id,
        doc_surface=str(mapping.get("doc_surface", "")),
        workload_id=str(mapping.get("workload_id", "")),
        replacement_level=str(mapping.get("replacement_level", "")),
        runtime_modes=runtime_modes,
        expected_decision=expected,
        actual_decision=actual,
        evidence_refs=evidence_refs,
        failure_signature=failure,
    )
    mapping_reports.append(
        {
            "claim_id": claim_id,
            "doc_surface": str(mapping.get("doc_surface", "")),
            "workload_id": str(mapping.get("workload_id", "")),
            "replacement_level": str(mapping.get("replacement_level", "")),
            "runtime_modes": runtime_modes,
            "expected_decision": expected,
            "actual_decision": actual,
            "failure_signature": failure,
            "details": details,
        }
    )

allowed_supported = sum(1 for row in mapping_reports if row["actual_decision"] == "allow")
allowed_limitations = sum(1 for row in mapping_reports if row["actual_decision"] == "allow_known_limitation")
summary = config.get("summary", {}) if isinstance(config.get("summary"), dict) else {}
if len(mappings) != summary.get("claim_mapping_count"):
    errors.append("claim_mapping_count mismatch")
if allowed_supported != summary.get("allowed_supported_count"):
    errors.append(f"allowed_supported_count mismatch: expected {summary.get('allowed_supported_count')} actual {allowed_supported}")
if allowed_limitations != summary.get("allowed_known_limitation_count"):
    errors.append(f"allowed_known_limitation_count mismatch: expected {summary.get('allowed_known_limitation_count')} actual {allowed_limitations}")

for row in logs:
    missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
    if missing:
        errors.append(f"log row missing required fields: {missing}")

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.10.4",
    "status": "pass" if not errors else "fail",
    "source_commit": source_commit,
    "summary": {
        "claim_mapping_count": len(mappings),
        "allowed_supported_count": allowed_supported,
        "allowed_known_limitation_count": allowed_limitations,
        "log_rows": len(logs),
    },
    "mappings": mapping_reports,
    "errors": errors,
    "artifact_refs": [
        str(config_path),
        str(report_path),
        str(log_path),
        "scripts/ci.sh",
    ],
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in logs), encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if not errors else 1)
PY
