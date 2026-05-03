#!/usr/bin/env bash
# check_feature_parity_claim_evidence.sh -- bd-bp8fl.3.4 claim-advancement CI gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${FRANKENLIBC_CLAIM_EVIDENCE_GATE:-${ROOT}/tests/conformance/feature_parity_claim_evidence_gate.v1.json}"
OUT_DIR="${FRANKENLIBC_CLAIM_EVIDENCE_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_CLAIM_EVIDENCE_REPORT:-${OUT_DIR}/feature_parity_claim_evidence_gate.report.json}"
LOG="${FRANKENLIBC_CLAIM_EVIDENCE_LOG:-${OUT_DIR}/feature_parity_claim_evidence_gate.log.jsonl}"
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
    "claim_surface",
    "claim_id",
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


def read_surface(rel: str) -> str:
    try:
        return repo_path(rel).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def evidence_exists(rel: str) -> bool:
    try:
        return repo_path(rel).exists()
    except ValueError:
        return False


def append_log(
    *,
    claim_surface: str,
    claim_id: str,
    expected_decision: str,
    actual_decision: str,
    evidence_refs: list[str],
    failure_signature: str,
    scenario_id: str | None = None,
) -> None:
    row = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trace_id": f"bd-bp8fl.3.4::{scenario_id or claim_id}",
        "bead_id": "bd-bp8fl.3.4",
        "claim_surface": claim_surface,
        "claim_id": claim_id,
        "expected_decision": expected_decision,
        "actual_decision": actual_decision,
        "evidence_refs": evidence_refs,
        "source_commit": source_commit,
        "failure_signature": failure_signature,
    }
    logs.append(row)


config = load_json(config_path, "claim_evidence_gate")
if not isinstance(config, dict):
    errors.append("config must be a JSON object")
    config = {}

if config.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if config.get("bead") != "bd-bp8fl.3.4":
    errors.append("bead must be bd-bp8fl.3.4")
if config.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_log_fields must match bd-bp8fl.3.4 contract")

surfaces = config.get("claim_surfaces", [])
if not isinstance(surfaces, list):
    errors.append("claim_surfaces must be an array")
    surfaces = []
surface_by_id: dict[str, dict[str, object]] = {}

for surface in surfaces:
    if not isinstance(surface, dict):
        errors.append("claim surface must be an object")
        continue
    claim_id = str(surface.get("claim_id", ""))
    claim_surface = str(surface.get("claim_surface", ""))
    surface_by_id[claim_id] = surface
    required_tokens = [str(token) for token in surface.get("required_tokens", [])]
    evidence_refs = [str(ref) for ref in surface.get("evidence_refs", [])]
    surface_text = read_surface(claim_surface)
    missing_tokens = [token for token in required_tokens if token not in surface_text]
    missing_refs = [ref for ref in evidence_refs if not evidence_exists(ref)]
    if not claim_id:
        errors.append("claim surface missing claim_id")
    if not claim_surface or not evidence_exists(claim_surface):
        errors.append(f"{claim_id}: claim surface missing: {claim_surface}")
    if missing_tokens:
        errors.append(f"{claim_id}: missing claim tokens: {missing_tokens}")
    if missing_refs:
        errors.append(f"{claim_id}: missing evidence refs: {missing_refs}")
    actual = "block" if missing_tokens or missing_refs else "allow"
    failure = "none" if actual == "allow" else "claim_surface_missing_binding"
    append_log(
        claim_surface=claim_surface,
        claim_id=claim_id,
        expected_decision="allow",
        actual_decision=actual,
        evidence_refs=evidence_refs,
        failure_signature=failure,
    )

ci = config.get("ci_integration", {})
if isinstance(ci, dict) and ci.get("required") is True:
    ci_file = str(ci.get("ci_file", ""))
    gate_script = str(ci.get("gate_script", ""))
    ci_text = read_surface(ci_file)
    if not ci_file or not gate_script or gate_script not in ci_text:
        errors.append(f"ci hook missing: {ci_file} must invoke {gate_script}")
        append_log(
            claim_surface=ci_file,
            claim_id="ci-integration",
            expected_decision="allow",
            actual_decision="block",
            evidence_refs=[gate_script],
            failure_signature="ci_hook_missing",
        )


def decide_scenario(scenario: dict[str, object]) -> tuple[str, str, list[str]]:
    evidence_refs = [str(ref) for ref in scenario.get("evidence_refs", [])]
    required_refs = [str(ref) for ref in scenario.get("required_evidence_refs", [])]
    missing_required = [ref for ref in required_refs if ref not in evidence_refs]
    missing_existing = [ref for ref in evidence_refs if not evidence_exists(ref)]
    if missing_required or missing_existing:
        return "block", "claim_advancement_missing_evidence", missing_required + missing_existing
    if str(scenario.get("source_commit_state", "current")) != "current":
        return "block", "claim_advancement_stale_evidence", []
    if str(scenario.get("contradiction_state", "clear")) == "contradictory":
        return "block", "claim_advancement_contradictory_evidence", []
    return "allow", "none", []


scenarios = config.get("scenarios", [])
if not isinstance(scenarios, list):
    errors.append("scenarios must be an array")
    scenarios = []

scenario_reports: list[dict[str, object]] = []
for scenario in scenarios:
    if not isinstance(scenario, dict):
        errors.append("scenario must be an object")
        continue
    scenario_id = str(scenario.get("scenario_id", ""))
    claim_id = str(scenario.get("claim_id", ""))
    claim_surface = str(scenario.get("claim_surface", ""))
    expected_decision = str(scenario.get("expected_decision", ""))
    expected_failure = str(scenario.get("expected_failure_signature", ""))
    evidence_refs = [str(ref) for ref in scenario.get("evidence_refs", [])]
    if claim_id not in surface_by_id:
        errors.append(f"{scenario_id}: unknown claim_id {claim_id}")
    actual_decision, failure_signature, missing_refs = decide_scenario(scenario)
    if actual_decision != expected_decision:
        errors.append(
            f"{scenario_id}: decision mismatch expected {expected_decision} actual {actual_decision}"
        )
    if expected_failure and failure_signature != expected_failure:
        errors.append(
            f"{scenario_id}: failure mismatch expected {expected_failure} actual {failure_signature}"
        )
    append_log(
        claim_surface=claim_surface,
        claim_id=claim_id,
        expected_decision=expected_decision,
        actual_decision=actual_decision,
        evidence_refs=evidence_refs,
        failure_signature=failure_signature,
        scenario_id=scenario_id,
    )
    scenario_reports.append(
        {
            "scenario_id": scenario_id,
            "claim_id": claim_id,
            "claim_surface": claim_surface,
            "expected_decision": expected_decision,
            "actual_decision": actual_decision,
            "failure_signature": failure_signature,
            "missing_refs": missing_refs,
        }
    )

summary = config.get("summary", {}) if isinstance(config.get("summary"), dict) else {}
blocked = sum(1 for row in scenario_reports if row["actual_decision"] == "block")
allowed = sum(1 for row in scenario_reports if row["actual_decision"] == "allow")
if len(surfaces) != summary.get("claim_surface_count"):
    errors.append("claim_surface_count mismatch")
if len(scenarios) != summary.get("scenario_count"):
    errors.append("scenario_count mismatch")
if blocked != summary.get("blocked_scenario_count"):
    errors.append(f"blocked_scenario_count mismatch: expected {summary.get('blocked_scenario_count')} actual {blocked}")
if allowed != summary.get("allowed_scenario_count"):
    errors.append(f"allowed_scenario_count mismatch: expected {summary.get('allowed_scenario_count')} actual {allowed}")

for row in logs:
    missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
    if missing:
        errors.append(f"log row missing required fields: {missing}")

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.3.4",
    "status": "pass" if not errors else "fail",
    "source_commit": source_commit,
    "summary": {
        "claim_surface_count": len(surfaces),
        "scenario_count": len(scenarios),
        "blocked_scenario_count": blocked,
        "allowed_scenario_count": allowed,
        "log_rows": len(logs),
    },
    "scenarios": scenario_reports,
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
