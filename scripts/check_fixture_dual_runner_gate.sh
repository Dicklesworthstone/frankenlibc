#!/usr/bin/env bash
# check_fixture_dual_runner_gate.sh -- bd-bp8fl.4.2 direct+isolated fixture runner gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${FRANKENLIBC_FIXTURE_DUAL_RUNNER_GATE:-${ROOT}/tests/conformance/fixture_dual_runner_gate.v1.json}"
OUT_DIR="${FRANKENLIBC_FIXTURE_DUAL_RUNNER_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_FIXTURE_DUAL_RUNNER_REPORT:-${OUT_DIR}/fixture_dual_runner_gate.report.json}"
LOG="${FRANKENLIBC_FIXTURE_DUAL_RUNNER_LOG:-${OUT_DIR}/fixture_dual_runner_gate.log.jsonl}"
TARGET_DIR="${FRANKENLIBC_FIXTURE_DUAL_RUNNER_TARGET_DIR:-${CARGO_TARGET_DIR:-unset}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONFIG}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" "${TARGET_DIR}" <<'PY'
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

REQUIRED_MANIFEST_FIELDS = [
    "direct_runner",
    "isolated_runner",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "expected",
    "timeout_ms",
    "environment",
    "cleanup",
    "artifact_paths",
]

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "runner_kind",
    "runtime_mode",
    "replacement_level",
    "expected",
    "actual",
    "errno",
    "duration_ms",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]

BLOCKED_SIGNATURES = {
    "direct_runner_missing",
    "isolated_runner_missing",
    "direct_runner_mismatch",
    "isolated_runner_mismatch",
    "isolated_runner_timeout",
    "stale_artifact",
    "env_cleanup_missing",
}

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
    fixture_id: str,
    runner_kind: str,
    runtime_mode: str,
    replacement_level: str,
    expected: str,
    actual: str,
    artifact_refs: list[str],
    failure_signature: str,
    scenario_id: str,
) -> None:
    logs.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": f"bd-bp8fl.4.2::{scenario_id}",
            "bead_id": "bd-bp8fl.4.2",
            "fixture_id": fixture_id,
            "runner_kind": runner_kind,
            "runtime_mode": runtime_mode,
            "replacement_level": replacement_level,
            "expected": expected,
            "actual": actual,
            "errno": 0 if failure_signature == "none" else 1,
            "duration_ms": 0,
            "artifact_refs": artifact_refs,
            "source_commit": source_commit,
            "target_dir": target_dir,
            "failure_signature": failure_signature,
        }
    )


def decide_scenario(scenario: dict[str, object]) -> tuple[str, str]:
    direct_actual = str(scenario.get("direct_actual", "missing"))
    isolated_actual = str(scenario.get("isolated_actual", "missing"))
    if direct_actual == "missing":
        return "block", "direct_runner_missing"
    if isolated_actual == "missing":
        return "block", "isolated_runner_missing"
    if direct_actual != str(scenario.get("direct_expected", "pass")):
        return "block", "direct_runner_mismatch"
    if isolated_actual == "timeout":
        return "block", "isolated_runner_timeout"
    if isolated_actual != str(scenario.get("isolated_expected", "pass")):
        return "block", "isolated_runner_mismatch"
    if str(scenario.get("artifact_state", "current")) != "current":
        return "block", "stale_artifact"
    if str(scenario.get("env_cleanup_state", "clean")) != "clean":
        return "block", "env_cleanup_missing"
    return "allow", "none"


config = load_json(config_path, "fixture_dual_runner_gate")
if not isinstance(config, dict):
    errors.append("config must be an object")
    config = {}

if config.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if config.get("bead") != "bd-bp8fl.4.2":
    errors.append("bead must be bd-bp8fl.4.2")
if config.get("required_manifest_fields") != REQUIRED_MANIFEST_FIELDS:
    errors.append("required_manifest_fields mismatch")
if config.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_log_fields mismatch")

policy = config.get("runner_policy", {})
if isinstance(policy, dict):
    declared = set(policy.get("blocked_signatures", []))
    missing = BLOCKED_SIGNATURES - declared
    if missing:
        errors.append(f"runner_policy missing blocked signatures: {sorted(missing)}")
else:
    errors.append("runner_policy must be an object")

inputs = config.get("inputs", {})
if not isinstance(inputs, dict):
    errors.append("inputs must be an object")
else:
    for key, rel in inputs.items():
        if not exists(str(rel)):
            errors.append(f"input {key} missing: {rel}")

families = config.get("fixture_families", [])
if not isinstance(families, list):
    errors.append("fixture_families must be an array")
    families = []

family_by_id: dict[str, dict[str, object]] = {}
for family in families:
    if not isinstance(family, dict):
        errors.append("fixture family row must be an object")
        continue
    fixture_id = str(family.get("fixture_id", ""))
    family_by_id[fixture_id] = family
    for field in REQUIRED_MANIFEST_FIELDS:
        if field not in family:
            errors.append(f"{fixture_id}: missing manifest field {field}")
    fixture_manifest = str(family.get("fixture_manifest", ""))
    test_file = str(family.get("test_file", ""))
    artifact_refs = [str(ref) for ref in family.get("artifact_paths", [])]
    missing_artifacts = [ref for ref in artifact_refs if not exists(ref)]
    if not exists(fixture_manifest):
        errors.append(f"{fixture_id}: fixture_manifest missing: {fixture_manifest}")
    if not exists(test_file):
        errors.append(f"{fixture_id}: test_file missing: {test_file}")
    if missing_artifacts:
        errors.append(f"{fixture_id}: artifact paths missing: {missing_artifacts}")
    fixture_doc = load_json(repo_path(fixture_manifest), fixture_id) if exists(fixture_manifest) else {}
    if isinstance(fixture_doc, dict) and not fixture_doc.get("cases"):
        errors.append(f"{fixture_id}: fixture manifest must contain cases")
    test_text = read_text(test_file)
    direct_missing = [
        str(fragment)
        for fragment in family.get("required_direct_tokens", [])
        if str(fragment) not in test_text
    ]
    isolated_missing = [
        str(fragment)
        for fragment in family.get("required_isolated_tokens", [])
        if str(fragment) not in test_text
    ]
    cleanup = family.get("cleanup", {})
    if isinstance(cleanup, dict):
        for cleanup_field in ["stdin_closed", "stderr_captured", "env_restored"]:
            if cleanup.get(cleanup_field) is not True:
                errors.append(f"{fixture_id}: cleanup.{cleanup_field} must be true")
    else:
        errors.append(f"{fixture_id}: cleanup must be an object")
    modes = set(family.get("runtime_modes", []))
    if modes != {"strict", "hardened"}:
        errors.append(f"{fixture_id}: runtime_modes must be strict+hardened")
    append_log(
        fixture_id=fixture_id,
        runner_kind="direct",
        runtime_mode=str(family.get("runtime_mode", "")),
        replacement_level=str(family.get("replacement_level", "")),
        expected=str(family.get("expected", "")),
        actual="present" if not direct_missing else "missing",
        artifact_refs=artifact_refs,
        failure_signature="none" if not direct_missing else "direct_runner_missing",
        scenario_id=f"{fixture_id}:direct",
    )
    append_log(
        fixture_id=fixture_id,
        runner_kind="isolated",
        runtime_mode=str(family.get("runtime_mode", "")),
        replacement_level=str(family.get("replacement_level", "")),
        expected=str(family.get("expected", "")),
        actual="present" if not isolated_missing else "missing",
        artifact_refs=artifact_refs,
        failure_signature="none" if not isolated_missing else "isolated_runner_missing",
        scenario_id=f"{fixture_id}:isolated",
    )
    if direct_missing:
        errors.append(f"{fixture_id}: direct_runner_missing: missing direct runner fragments: {direct_missing}")
    if isolated_missing:
        errors.append(f"{fixture_id}: isolated_runner_missing: missing isolated runner fragments: {isolated_missing}")

ci = config.get("ci_integration", {})
if isinstance(ci, dict) and ci.get("required") is True:
    ci_file = str(ci.get("ci_file", ""))
    gate_script = str(ci.get("gate_script", ""))
    if gate_script not in read_text(ci_file):
        errors.append(f"ci hook missing: {ci_file} must invoke {gate_script}")

scenarios = config.get("replay_scenarios", [])
if not isinstance(scenarios, list):
    errors.append("replay_scenarios must be an array")
    scenarios = []

scenario_reports: list[dict[str, object]] = []
for scenario in scenarios:
    if not isinstance(scenario, dict):
        errors.append("replay scenario must be an object")
        continue
    scenario_id = str(scenario.get("scenario_id", ""))
    fixture_id = str(scenario.get("fixture_id", ""))
    family = family_by_id.get(fixture_id, {})
    if fixture_id not in family_by_id:
        errors.append(f"{scenario_id}: unknown fixture_id {fixture_id}")
    actual_decision, failure_signature = decide_scenario(scenario)
    expected_decision = str(scenario.get("expected_decision", ""))
    expected_failure = str(scenario.get("expected_failure_signature", ""))
    if actual_decision != expected_decision:
        errors.append(f"{scenario_id}: decision mismatch expected {expected_decision} actual {actual_decision}")
    if failure_signature != expected_failure:
        errors.append(f"{scenario_id}: failure mismatch expected {expected_failure} actual {failure_signature}")
    artifact_refs = [str(ref) for ref in family.get("artifact_paths", [])]
    append_log(
        fixture_id=fixture_id,
        runner_kind=str(scenario.get("runner_kind", "")),
        runtime_mode=str(family.get("runtime_mode", "strict+hardened")),
        replacement_level=str(family.get("replacement_level", "L0")),
        expected=f"direct={scenario.get('direct_expected')} isolated={scenario.get('isolated_expected')}",
        actual=f"direct={scenario.get('direct_actual')} isolated={scenario.get('isolated_actual')}",
        artifact_refs=artifact_refs,
        failure_signature=failure_signature,
        scenario_id=scenario_id,
    )
    scenario_reports.append(
        {
            "scenario_id": scenario_id,
            "fixture_id": fixture_id,
            "runner_kind": str(scenario.get("runner_kind", "")),
            "expected_decision": expected_decision,
            "actual_decision": actual_decision,
            "failure_signature": failure_signature,
        }
    )

summary = config.get("summary", {}) if isinstance(config.get("summary"), dict) else {}
allowed = sum(1 for row in scenario_reports if row["actual_decision"] == "allow")
blocked = sum(1 for row in scenario_reports if row["actual_decision"] == "block")
if len(families) != summary.get("fixture_family_count"):
    errors.append("fixture_family_count mismatch")
if len(scenarios) != summary.get("scenario_count"):
    errors.append("scenario_count mismatch")
if allowed != summary.get("allowed_scenario_count"):
    errors.append(f"allowed_scenario_count mismatch: expected {summary.get('allowed_scenario_count')} actual {allowed}")
if blocked != summary.get("blocked_scenario_count"):
    errors.append(f"blocked_scenario_count mismatch: expected {summary.get('blocked_scenario_count')} actual {blocked}")

for row in logs:
    missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
    if missing:
        errors.append(f"log row missing required fields: {missing}")

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.4.2",
    "status": "pass" if not errors else "fail",
    "source_commit": source_commit,
    "target_dir": target_dir,
    "summary": {
        "fixture_family_count": len(families),
        "runtime_mode_count": summary.get("runtime_mode_count"),
        "scenario_count": len(scenarios),
        "allowed_scenario_count": allowed,
        "blocked_scenario_count": blocked,
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
