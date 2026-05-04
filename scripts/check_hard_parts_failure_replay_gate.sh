#!/usr/bin/env bash
# check_hard_parts_failure_replay_gate.sh -- bd-bp8fl.5.9 replay-standard gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FRANKENLIBC_HARD_PARTS_REPLAY_GATE:-${ROOT}/tests/conformance/hard_parts_failure_replay_gate.v1.json}"
OUT_DIR="${FRANKENLIBC_HARD_PARTS_REPLAY_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_HARD_PARTS_REPLAY_REPORT:-${OUT_DIR}/hard_parts_failure_replay_gate.report.json}"
LOG="${FRANKENLIBC_HARD_PARTS_REPLAY_LOG:-${OUT_DIR}/hard_parts_failure_replay_gate.log.jsonl}"
TARGET_DIR="${FRANKENLIBC_HARD_PARTS_REPLAY_TARGET_DIR:-${OUT_DIR}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"
ARCH="$(uname -m 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" "${TARGET_DIR}" "${ARCH}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]
target_dir = sys.argv[6]
arch = sys.argv[7]

BEAD_ID = "bd-bp8fl.5.9"
GATE_ID = "hard-parts-failure-replay-gate-v1"
REQUIRED_FAMILIES = {
    "resolver_nss",
    "locale_iconv",
    "loader_symbol",
    "stdio_error_state",
    "pthread_cancellation",
    "math_fenv",
    "signal_setjmp",
}
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "failure_family",
    "scenario_id",
    "seed",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "status",
    "decision_path",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "cleanup_state",
    "failure_signature",
]
REQUIRED_DIAGNOSTICS = {
    "stale_artifact",
    "wrong_architecture",
    "missing_fixture",
    "nondeterministic_output",
    "oracle_mismatch",
}
SIGNATURE_PRIORITY = [
    "malformed_artifact",
    "missing_field",
    "stale_artifact",
    "wrong_architecture",
    "missing_fixture",
    "unsupported_scenario_class",
    "nondeterministic_output",
    "oracle_mismatch",
]

errors: list[tuple[str, str]] = []
logs: list[dict] = []


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fail(signature: str, message: str) -> None:
    errors.append((signature, message))


def load_json(path: Path, label: str):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("malformed_artifact", f"{label}: cannot parse {path}: {exc}")
        return {}


def resolve(path_text) -> Path:
    path = Path(str(path_text))
    return path if path.is_absolute() else root / path


def require_object(value, ctx: str) -> dict:
    if isinstance(value, dict):
        return value
    fail("missing_field", f"{ctx}: must be object")
    return {}


def require_string(row: dict, field: str, ctx: str) -> str:
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty string")
    return ""


def require_array(row: dict, field: str, ctx: str) -> list:
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty array")
    return []


def existing_path(path_text, ctx: str) -> None:
    path = resolve(path_text)
    if not path.exists():
        fail("missing_fixture", f"{ctx}: missing path {path_text}")


def source_commit_ok(marker: str) -> bool:
    return marker in ("current", "unknown", source_commit)


manifest = load_json(manifest_path, "manifest")
manifest = require_object(manifest, "manifest")

if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields mismatch")

freshness = require_object(manifest.get("freshness"), "freshness")
required_commit = str(freshness.get("required_source_commit", ""))
if not source_commit_ok(required_commit):
    fail(
        "stale_artifact",
        f"freshness.required_source_commit {required_commit!r} does not match current {source_commit}",
    )

supported_arches = manifest.get("supported_architectures")
if not isinstance(supported_arches, list) or arch not in {str(item) for item in supported_arches}:
    fail("wrong_architecture", f"architecture {arch!r} is not supported by manifest")

sources = require_object(manifest.get("sources"), "sources")
for key in [
    "hard_parts_truth_table",
    "hard_parts_e2e_catalog",
    "hard_parts_e2e_failure_matrix",
    "oracle_precedence_divergence",
    "fixture_dual_runner_gate",
]:
    source_path = sources.get(key)
    if not isinstance(source_path, str) or not source_path:
        fail("missing_field", f"sources.{key}: must be non-empty string")
    else:
        existing_path(source_path, f"sources.{key}")

oracle_doc = load_json(resolve(sources.get("oracle_precedence_divergence", "")), "oracle_precedence")
oracle_kinds = {
    str(row.get("id"))
    for row in oracle_doc.get("oracle_kinds", [])
    if isinstance(row, dict)
}
divergence_classes = {
    str(row.get("id"))
    for row in oracle_doc.get("divergence_classifications", [])
    if isinstance(row, dict)
}

diagnostics = manifest.get("diagnostic_signatures", [])
diagnostic_ids = {
    str(row.get("id"))
    for row in diagnostics
    if isinstance(row, dict) and isinstance(row.get("id"), str)
}
missing_diagnostics = sorted(REQUIRED_DIAGNOSTICS - diagnostic_ids)
if missing_diagnostics:
    fail("missing_field", f"diagnostic_signatures missing {missing_diagnostics}")

families_seen: set[str] = set()
runner_counts = {"direct": 0, "isolated": 0}
scenarios = manifest.get("scenarios")
if not isinstance(scenarios, list) or not scenarios:
    fail("missing_field", "scenarios must be a non-empty array")
    scenarios = []

for index, scenario_value in enumerate(scenarios):
    scenario = require_object(scenario_value, f"scenarios[{index}]")
    ctx = f"scenarios[{index}]"
    scenario_id = require_string(scenario, "scenario_id", ctx)
    failure_family = require_string(scenario, "failure_family", ctx)
    seed = require_string(scenario, "seed", ctx)
    runtime_modes = [str(mode) for mode in require_array(scenario, "runtime_modes", ctx)]
    replacement_level = require_string(scenario, "replacement_level", ctx)
    oracle_kind = require_string(scenario, "oracle_kind", ctx)
    allowed_divergence = require_string(scenario, "allowed_divergence", ctx)

    if failure_family not in REQUIRED_FAMILIES:
        fail("unsupported_scenario_class", f"{ctx}.failure_family {failure_family!r} is unsupported")
    else:
        families_seen.add(failure_family)

    if replacement_level not in {"L0", "L1", "L2", "L3"}:
        fail("missing_field", f"{ctx}.replacement_level must be L0/L1/L2/L3")
    for mode in runtime_modes:
        if mode not in {"strict", "hardened"}:
            fail("missing_field", f"{ctx}.runtime_modes includes invalid mode {mode!r}")

    if oracle_kind not in oracle_kinds:
        fail("oracle_mismatch", f"{ctx}.oracle_kind {oracle_kind!r} is not declared")
    if allowed_divergence not in divergence_classes:
        fail(
            "oracle_mismatch",
            f"{ctx}.allowed_divergence {allowed_divergence!r} is not declared",
        )

    input_artifact = require_object(scenario.get("input_artifact"), f"{ctx}.input_artifact")
    input_path = require_string(input_artifact, "path", f"{ctx}.input_artifact")
    if input_path:
        existing_path(input_path, f"{ctx}.input_artifact.path")

    expected = require_object(scenario.get("expected"), f"{ctx}.expected")
    for field in ["outcome", "errno", "status", "decision_path"]:
        require_string(expected, field, f"{ctx}.expected")

    cleanup = require_object(scenario.get("cleanup"), f"{ctx}.cleanup")
    cleanup_state = require_string(cleanup, "state", f"{ctx}.cleanup")
    if cleanup.get("required") is not True:
        fail("missing_field", f"{ctx}.cleanup.required must be true")

    require_object(scenario.get("environment"), f"{ctx}.environment")
    require_string(scenario, "minimization_notes", ctx)
    determinism = require_object(scenario.get("determinism"), f"{ctx}.determinism")
    require_string(determinism, "replay_key", f"{ctx}.determinism")
    require_string(determinism, "nondeterminism_guard", f"{ctx}.determinism")
    if int(determinism.get("stability_iterations", 0)) < 2:
        fail("nondeterministic_output", f"{ctx}.determinism.stability_iterations must be >= 2")

    scenario_artifact_refs = [input_path] if input_path else []
    for runner_field, expected_kind in [
        ("direct_runner", "direct"),
        ("isolated_runner", "isolated"),
    ]:
        runner = require_object(scenario.get(runner_field), f"{ctx}.{runner_field}")
        runner_kind = require_string(runner, "runner_kind", f"{ctx}.{runner_field}")
        command = require_string(runner, "command", f"{ctx}.{runner_field}")
        artifact_refs = [str(ref) for ref in require_array(runner, "artifact_refs", f"{ctx}.{runner_field}")]
        if runner_kind != expected_kind:
            fail("missing_field", f"{ctx}.{runner_field}.runner_kind must be {expected_kind}")
        if "rch exec -- cargo" in command and " -p frankenlibc-harness" not in command:
            fail("missing_field", f"{ctx}.{runner_field}.command must scope cargo to -p frankenlibc-harness")
        for artifact_ref in artifact_refs:
            existing_path(artifact_ref, f"{ctx}.{runner_field}.artifact_refs")
        runner_counts[expected_kind] += 1
        scenario_artifact_refs.extend(artifact_refs)

        for runtime_mode in runtime_modes:
            logs.append(
                {
                    "timestamp": now(),
                    "trace_id": f"{BEAD_ID}::{scenario_id}::{runner_kind}::{runtime_mode}",
                    "bead_id": BEAD_ID,
                    "failure_family": failure_family,
                    "scenario_id": scenario_id,
                    "seed": seed,
                    "runtime_mode": runtime_mode,
                    "replacement_level": replacement_level,
                    "oracle_kind": oracle_kind,
                    "expected": expected,
                    "actual": {
                        "runner_kind": runner_kind,
                        "command": command,
                        "replay_binding": "schema_and_artifacts_validated",
                    },
                    "errno": expected.get("errno"),
                    "status": expected.get("status"),
                    "decision_path": expected.get("decision_path"),
                    "artifact_refs": sorted(set(scenario_artifact_refs)),
                    "source_commit": source_commit,
                    "target_dir": target_dir,
                    "cleanup_state": cleanup_state,
                    "failure_signature": "ok",
                }
            )

missing_families = sorted(REQUIRED_FAMILIES - families_seen)
if missing_families:
    fail("unsupported_scenario_class", f"missing required failure families: {missing_families}")

summary = manifest.get("summary", {})
if isinstance(summary, dict):
    if int(summary.get("scenario_count", -1)) != len(scenarios):
        fail("stale_artifact", "summary.scenario_count does not match scenarios length")
    if int(summary.get("required_family_count", -1)) != len(REQUIRED_FAMILIES):
        fail("stale_artifact", "summary.required_family_count does not match required families")
else:
    fail("missing_field", "summary must be object")

error_signatures = [signature for signature, _ in errors]
primary_signature = ""
for signature in SIGNATURE_PRIORITY:
    if signature in error_signatures:
        primary_signature = signature
        break

if errors:
    logs.append(
        {
            "timestamp": now(),
            "trace_id": f"{BEAD_ID}::gate::fail",
            "bead_id": BEAD_ID,
            "failure_family": "all",
            "scenario_id": GATE_ID,
            "seed": "gate",
            "runtime_mode": "strict+hardened",
            "replacement_level": "L0-L3",
            "oracle_kind": "gate_validator",
            "expected": "hard-parts replay gate manifest is current and replayable",
            "actual": [message for _, message in errors],
            "errno": "0",
            "status": "fail",
            "decision_path": "manifest->schema->artifact->oracle->runner->fail",
            "artifact_refs": [str(manifest_path)],
            "source_commit": source_commit,
            "target_dir": target_dir,
            "cleanup_state": "not_run",
            "failure_signature": primary_signature or "gate_validation_failed",
        }
    )

report = {
    "schema_version": "v1",
    "bead_id": BEAD_ID,
    "gate_id": GATE_ID,
    "status": "fail" if errors else "pass",
    "source_commit": source_commit,
    "target_dir": target_dir,
    "summary": {
        "scenario_count": len(scenarios),
        "required_family_count": len(REQUIRED_FAMILIES),
        "covered_family_count": len(families_seen),
        "direct_runner_count": runner_counts["direct"],
        "isolated_runner_count": runner_counts["isolated"],
        "log_row_count": len(logs),
        "diagnostic_signature_count": len(diagnostic_ids),
        "required_diagnostic_signatures": sorted(REQUIRED_DIAGNOSTICS),
    },
    "covered_families": sorted(families_seen),
    "diagnostic_signatures": sorted(diagnostic_ids),
    "errors": [{"failure_signature": signature, "message": message} for signature, message in errors],
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in logs),
    encoding="utf-8",
)

if errors:
    raise SystemExit(1)
PY
