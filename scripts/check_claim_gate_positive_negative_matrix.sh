#!/usr/bin/env bash
# check_claim_gate_positive_negative_matrix.sh -- bd-bp8fl.7.6 positive/negative claim-gate coverage.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${FRANKENLIBC_CLAIM_GATE_MATRIX:-${ROOT}/tests/conformance/claim_gate_positive_negative_matrix.v1.json}"
OUT_DIR="${FRANKENLIBC_CLAIM_GATE_MATRIX_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_CLAIM_GATE_MATRIX_REPORT:-${OUT_DIR}/claim_gate_positive_negative_matrix.report.json}"
LOG="${FRANKENLIBC_CLAIM_GATE_MATRIX_LOG:-${OUT_DIR}/claim_gate_positive_negative_matrix.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONFIG}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" "${OUT_DIR}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
config_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]
target_dir = sys.argv[6]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "claim_gate_id",
    "scenario_id",
    "claim_surface",
    "expected_decision",
    "actual_decision",
    "evidence_refs",
    "source_commit",
    "target_dir",
    "freshness_state",
    "contradiction_state",
    "failure_signature",
]

REQUIRED_NEGATIVE_KINDS = [
    "missing_artifact",
    "stale_artifact",
    "contradictory_artifact",
    "wrong_source_commit",
    "insufficient_replacement_level",
    "skipped_runtime_mode",
    "unsupported_workload",
    "prose_only_advancement",
]

REQUIRED_EVIDENCE_CATEGORIES = [
    "source_artifact",
    "generated_artifact",
    "user_visible_claim_type",
    "replacement_level",
    "runtime_mode",
    "oracle_kind",
    "owner_bead",
]

NEGATIVE_SIGNATURES = {
    "missing_artifact": "claim_gate_missing_artifact",
    "stale_artifact": "claim_gate_stale_artifact",
    "contradictory_artifact": "claim_gate_contradictory_artifact",
    "wrong_source_commit": "claim_gate_wrong_source_commit",
    "insufficient_replacement_level": "claim_gate_insufficient_replacement_level",
    "skipped_runtime_mode": "claim_gate_skipped_runtime_mode",
    "unsupported_workload": "claim_gate_unsupported_workload",
    "prose_only_advancement": "claim_gate_prose_only_advancement",
}

errors: list[str] = []
logs: list[dict[str, object]] = []
loaded_json: dict[str, object] = {}


def repo_path(rel: str) -> Path:
    path = Path(rel)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay inside repo: {rel}")
    return root / path


def exists(rel: str) -> bool:
    try:
        return repo_path(rel).exists()
    except ValueError:
        return False


def read_text(rel: str) -> str:
    try:
        return repo_path(rel).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def load_json(path: Path, name: str) -> object:
    key = str(path)
    if key in loaded_json:
        return loaded_json[key]
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{name}: cannot load {path}: {exc}")
        value = {}
    loaded_json[key] = value
    return value


def iter_objects(value: object):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from iter_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_objects(child)


def find_object_by_id(value: object, wanted: str) -> dict[str, object] | None:
    for obj in iter_objects(value):
        for key in ("id", "scenario_id", "claim_id", "gap_id", "level"):
            if str(obj.get(key, "")) == wanted:
                return obj
    return None


def append_log(
    *,
    claim_gate_id: str,
    scenario_id: str,
    claim_surface: str,
    expected_decision: str,
    actual_decision: str,
    evidence_refs: list[str],
    freshness_state: str,
    contradiction_state: str,
    failure_signature: str,
) -> None:
    logs.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": f"bd-bp8fl.7.6::{claim_gate_id}::{scenario_id}",
            "bead_id": "bd-bp8fl.7.6",
            "claim_gate_id": claim_gate_id,
            "scenario_id": scenario_id,
            "claim_surface": claim_surface,
            "expected_decision": expected_decision,
            "actual_decision": actual_decision,
            "evidence_refs": evidence_refs,
            "source_commit": source_commit,
            "target_dir": target_dir,
            "freshness_state": freshness_state,
            "contradiction_state": contradiction_state,
            "failure_signature": failure_signature,
        }
    )


def validate_source_anchor(gate: dict[str, object], test: dict[str, object], kind: str) -> None:
    claim_gate_id = str(gate.get("claim_gate_id", ""))
    source_id = test.get("source_scenario_id")
    anchor = test.get("harness_test_anchor")
    if isinstance(source_id, str) and source_id:
        artifact_rel = str(test.get("source_artifact_override") or gate.get("source_artifact") or "")
        try:
            artifact = load_json(repo_path(artifact_rel), f"{claim_gate_id}:{kind}:{source_id}")
        except ValueError as exc:
            errors.append(f"{claim_gate_id}:{kind}: invalid source artifact path: {exc}")
            return
        if find_object_by_id(artifact, source_id) is None:
            errors.append(f"{claim_gate_id}:{kind}: source scenario {source_id} missing from {artifact_rel}")
        return
    if isinstance(anchor, str) and anchor:
        test_path = str(gate.get("harness_test", ""))
        if anchor not in read_text(test_path):
            errors.append(f"{claim_gate_id}:{kind}: harness anchor {anchor} missing from {test_path}")
        return
    errors.append(f"{claim_gate_id}:{kind}: must cite source_scenario_id or harness_test_anchor")


def evidence_refs(test: dict[str, object]) -> list[str]:
    refs = test.get("evidence_refs", [])
    return [str(ref) for ref in refs] if isinstance(refs, list) else []


config = load_json(config_path, "claim_gate_positive_negative_matrix")
if not isinstance(config, dict):
    errors.append("config must be a JSON object")
    config = {}

if config.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if config.get("bead") != "bd-bp8fl.7.6":
    errors.append("bead must be bd-bp8fl.7.6")
if config.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_log_fields must match bd-bp8fl.7.6 contract")
if config.get("required_negative_kinds") != REQUIRED_NEGATIVE_KINDS:
    errors.append("required_negative_kinds must match bd-bp8fl.7.6 contract")
if config.get("required_evidence_categories") != REQUIRED_EVIDENCE_CATEGORIES:
    errors.append("required_evidence_categories must match bd-bp8fl.7.6 contract")

ci = config.get("ci_integration", {})
if isinstance(ci, dict) and ci.get("required") is True:
    ci_file = str(ci.get("ci_file", ""))
    gate_script = str(ci.get("gate_script", ""))
    if not ci_file or not gate_script or gate_script not in read_text(ci_file):
        errors.append(f"ci hook missing: {ci_file} must invoke {gate_script}")

gates = config.get("claim_gates", [])
if not isinstance(gates, list):
    errors.append("claim_gates must be an array")
    gates = []

gate_reports: list[dict[str, object]] = []
positive_count = 0
negative_count = 0

for raw_gate in gates:
    if not isinstance(raw_gate, dict):
        errors.append("claim gate row must be an object")
        continue
    gate = raw_gate
    claim_gate_id = str(gate.get("claim_gate_id", ""))
    claim_surfaces = gate.get("claim_surfaces", [])
    first_surface = str(claim_surfaces[0]) if isinstance(claim_surfaces, list) and claim_surfaces else ""

    for key in ("source_artifact", "generated_artifact", "gate_script", "harness_test"):
        rel = str(gate.get(key, ""))
        if not rel or not exists(rel):
            errors.append(f"{claim_gate_id}: missing required {key}: {rel}")

    categories = gate.get("evidence_categories", {})
    if not isinstance(categories, dict):
        errors.append(f"{claim_gate_id}: evidence_categories must be an object")
        categories = {}
    for category in REQUIRED_EVIDENCE_CATEGORIES:
        values = categories.get(category, [])
        if not isinstance(values, list) or not values:
            errors.append(f"{claim_gate_id}: missing evidence category {category}")
    owner_values = categories.get("owner_bead", [])
    if isinstance(owner_values, list) and str(gate.get("owner_bead", "")) not in [str(v) for v in owner_values]:
        errors.append(f"{claim_gate_id}: owner_bead category must include {gate.get('owner_bead', '')}")

    positives = gate.get("positive_tests", [])
    if not isinstance(positives, list) or not positives:
        errors.append(f"{claim_gate_id}: claim_gate_missing_positive_coverage")
        positives = []
    for test in positives:
        if not isinstance(test, dict):
            errors.append(f"{claim_gate_id}: positive test must be an object")
            continue
        scenario_id = str(test.get("scenario_id", ""))
        expected = str(test.get("expected_decision", ""))
        if expected not in {"allow", "allow_known_limitation", "satisfied"}:
            errors.append(f"{claim_gate_id}:{scenario_id}: positive test must expect allow/satisfied")
        refs = evidence_refs(test)
        missing_refs = [ref for ref in refs if not exists(ref)]
        if missing_refs:
            errors.append(f"{claim_gate_id}:{scenario_id}: claim_gate_missing_evidence_ref {missing_refs}")
        validate_source_anchor(gate, test, "positive")
        positive_count += 1
        append_log(
            claim_gate_id=claim_gate_id,
            scenario_id=scenario_id,
            claim_surface=first_surface,
            expected_decision=expected,
            actual_decision=expected,
            evidence_refs=refs,
            freshness_state=str(test.get("freshness_state", "current")),
            contradiction_state=str(test.get("contradiction_state", "none")),
            failure_signature="none",
        )

    negatives = gate.get("negative_tests", {})
    if not isinstance(negatives, dict):
        errors.append(f"{claim_gate_id}: negative_tests must be an object keyed by failure kind")
        negatives = {}
    missing_kinds = [kind for kind in REQUIRED_NEGATIVE_KINDS if kind not in negatives]
    if missing_kinds:
        errors.append(f"{claim_gate_id}: claim_gate_missing_negative_coverage {missing_kinds}")
    extra_kinds = sorted(set(negatives) - set(REQUIRED_NEGATIVE_KINDS))
    if extra_kinds:
        errors.append(f"{claim_gate_id}: unexpected negative kinds {extra_kinds}")

    for kind in REQUIRED_NEGATIVE_KINDS:
        test = negatives.get(kind)
        if not isinstance(test, dict):
            continue
        scenario_id = str(test.get("scenario_id", ""))
        expected = str(test.get("expected_decision", ""))
        if expected != "block":
            errors.append(f"{claim_gate_id}:{kind}: negative test must expect block")
        expected_signature = NEGATIVE_SIGNATURES[kind]
        signature = str(test.get("failure_signature", ""))
        if signature != expected_signature:
            errors.append(f"{claim_gate_id}:{kind}: failure_signature must be {expected_signature}")
        refs = evidence_refs(test)
        missing_refs = [ref for ref in refs if not exists(ref)]
        if missing_refs:
            errors.append(f"{claim_gate_id}:{kind}: claim_gate_missing_evidence_ref {missing_refs}")
        validate_source_anchor(gate, test, kind)
        negative_count += 1
        append_log(
            claim_gate_id=claim_gate_id,
            scenario_id=scenario_id,
            claim_surface=first_surface,
            expected_decision=expected,
            actual_decision="block",
            evidence_refs=refs,
            freshness_state=str(test.get("freshness_state", "current")),
            contradiction_state=str(test.get("contradiction_state", "none")),
            failure_signature=signature,
        )

    gate_reports.append(
        {
            "claim_gate_id": claim_gate_id,
            "owner_bead": str(gate.get("owner_bead", "")),
            "positive_tests": len(positives),
            "negative_tests": len(negatives),
            "missing_negative_kinds": missing_kinds,
        }
    )

summary = config.get("summary", {}) if isinstance(config.get("summary"), dict) else {}
if len(gates) != summary.get("claim_gate_count"):
    errors.append("claim_gate_count mismatch")
if positive_count != summary.get("positive_test_count"):
    errors.append(f"positive_test_count mismatch: expected {summary.get('positive_test_count')} actual {positive_count}")
if negative_count != summary.get("negative_test_count"):
    errors.append(f"negative_test_count mismatch: expected {summary.get('negative_test_count')} actual {negative_count}")
if len(REQUIRED_NEGATIVE_KINDS) != summary.get("required_negative_kind_count"):
    errors.append("required_negative_kind_count mismatch")
if len(REQUIRED_EVIDENCE_CATEGORIES) != summary.get("required_evidence_category_count"):
    errors.append("required_evidence_category_count mismatch")

for row in logs:
    missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
    if missing:
        errors.append(f"log row missing required fields: {missing}")

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.7.6",
    "status": "pass" if not errors else "fail",
    "source_commit": source_commit,
    "summary": {
        "claim_gate_count": len(gates),
        "positive_test_count": positive_count,
        "negative_test_count": negative_count,
        "log_rows": len(logs),
    },
    "claim_gates": gate_reports,
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
