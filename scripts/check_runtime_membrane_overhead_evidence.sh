#!/usr/bin/env bash
# Validate runtime membrane overhead evidence goldens and optional live reports.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLDEN="${FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_GOLDEN:-${ROOT}/tests/conformance/runtime_membrane_overhead_evidence_golden.v1.json}"
LIVE_REPORT="${FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_REPORT:-${ROOT}/target/conformance/runtime_membrane_overhead/runtime_membrane_overhead.report.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MEMBRANE_OVERHEAD_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${OUT_DIR}/runtime_membrane_overhead_evidence.report.json"
LOG="${OUT_DIR}/runtime_membrane_overhead_evidence.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${GOLDEN}" "${LIVE_REPORT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
from copy import deepcopy
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
GOLDEN = pathlib.Path(sys.argv[2])
LIVE_REPORT = pathlib.Path(sys.argv[3])
REPORT = pathlib.Path(sys.argv[4])
LOG = pathlib.Path(sys.argv[5])

EXPECTED_SCHEMA = "runtime_membrane_overhead_evidence.v1"
EXPECTED_GOLDEN_SCHEMA = "runtime_membrane_overhead_evidence_golden.v1"
EXPECTED_REMOTE_ENV = "RCH_REQUIRE_REMOTE=1"
REJECTED_LOCAL_MARKER = "[RCH] local"
DECISION_FIELDS = [
    "allow_count",
    "full_validate_count",
    "repair_count",
    "deny_count",
]


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def current_head() -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def add_error(source: str, signature: str, message: str) -> None:
    errors.append({"source": source, "failure_signature": signature, "message": message})


def budget_for_mode(packet: dict[str, Any], mode: str) -> float | None:
    for row in packet.get("budgets", []):
        if isinstance(row, dict) and row.get("mode") == mode and is_number(row.get("target_budget_ns")):
            return float(row["target_budget_ns"])
    return None


def validate_measurement(packet: dict[str, Any], row: dict[str, Any], source: str, index: int) -> None:
    row_source = f"{source}::measurement[{index}]"
    mode = row.get("mode")
    family = row.get("abi_family")
    if not isinstance(family, str) or not family:
        add_error(row_source, "missing_family_field", "measurement must name abi_family")
    if mode not in packet.get("required_modes", []):
        add_error(row_source, "unknown_mode", f"measurement mode {mode!r} is not required/recognized")
    sample_count = row.get("sample_count")
    if not isinstance(sample_count, int) or isinstance(sample_count, bool) or sample_count <= 0:
        add_error(row_source, "invalid_sample_count", f"invalid sample_count={sample_count!r}")

    quantiles = row.get("quantiles_ns")
    if not isinstance(quantiles, dict):
        add_error(row_source, "invalid_quantile", "quantiles_ns must be an object")
        return
    p50 = quantiles.get("p50")
    p95 = quantiles.get("p95")
    p99 = quantiles.get("p99")
    if not all(is_number(value) and float(value) >= 0 for value in [p50, p95, p99]):
        add_error(row_source, "invalid_quantile", f"quantiles must be non-negative numbers: {quantiles!r}")
        return
    if not (float(p50) <= float(p95) <= float(p99)):
        add_error(row_source, "invalid_quantile", f"quantiles must be ordered p50 <= p95 <= p99: {quantiles!r}")

    target = row.get("target_budget_ns")
    mode_target = budget_for_mode(packet, str(mode))
    if not is_number(target) or float(target) <= 0:
        add_error(row_source, "missing_budget", f"invalid target_budget_ns={target!r}")
    elif mode_target is not None and float(target) != mode_target:
        add_error(row_source, "budget_mismatch", f"{mode} row target {target} does not match mode budget {mode_target}")
    elif float(p99) > float(target):
        add_error(row_source, "budget_regression", f"p99={p99} exceeds target_budget_ns={target}")
    if row.get("budget_status") != "pass":
        add_error(row_source, "budget_regression", f"budget_status must be pass, got {row.get('budget_status')!r}")

    telemetry = row.get("runtime_math_decision_summary")
    if not isinstance(telemetry, dict) or telemetry.get("telemetry_present") is not True:
        add_error(row_source, "missing_runtime_math_telemetry", "runtime_math_decision_summary is missing or not marked present")
        return
    for field in DECISION_FIELDS:
        value = telemetry.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            add_error(row_source, "invalid_runtime_math_telemetry", f"{field} must be a non-negative integer")
    if not isinstance(telemetry.get("validation_profile"), str) or not telemetry.get("validation_profile"):
        add_error(row_source, "invalid_runtime_math_telemetry", "validation_profile is required")
    if not isinstance(row.get("artifact_refs"), list) or not row.get("artifact_refs") or not all(isinstance(item, str) and item for item in row.get("artifact_refs", [])):
        add_error(row_source, "missing_artifact_refs", "artifact_refs must be a non-empty string list")


def validate_packet(packet: dict[str, Any], source: str, require_current_claim_source: bool) -> None:
    if packet.get("schema_version") != EXPECTED_SCHEMA:
        add_error(source, "schema_version", "runtime membrane overhead evidence schema_version mismatch")

    claim_policy = packet.get("claim_policy", {})
    claim_allowed = claim_policy.get("claim_allowed")
    if claim_allowed is not False and claim_allowed is not True:
        add_error(source, "invalid_claim_policy", "claim_policy.claim_allowed must be boolean")
    if claim_allowed is True or require_current_claim_source:
        if packet.get("source_commit") != CURRENT_HEAD:
            add_error(source, "stale_source_commit", "live claim evidence must carry current git HEAD")
    if packet.get("evidence_kind") == "schema_golden" and claim_allowed is not False:
        add_error(source, "schema_golden_claim_allowed", "schema goldens must not allow claims")

    rch = packet.get("rch_proof", {})
    if rch.get("required_remote_env") != EXPECTED_REMOTE_ENV:
        add_error(source, "missing_rch_remote", "rch_proof must require RCH_REQUIRE_REMOTE=1")
    if rch.get("offload_required") is not True:
        add_error(source, "missing_rch_remote", "rch_proof.offload_required must be true")
    command = rch.get("command")
    if not isinstance(command, str) or "rch exec" not in command:
        add_error(source, "missing_rch_remote", "rch_proof.command must use rch exec")
    if REJECTED_LOCAL_MARKER not in rch.get("fallback_markers_rejected", []):
        add_error(source, "missing_local_fallback_rejection", "rch_proof must reject [RCH] local fallback")
    if rch.get("local_fallback_seen") is not False:
        add_error(source, "local_fallback_seen", "runtime membrane overhead evidence must not include local fallback")
    if not isinstance(rch.get("transcript_artifact"), str) or not rch.get("transcript_artifact"):
        add_error(source, "missing_transcript_artifact", "rch transcript artifact is required")

    required_families = packet.get("required_families", [])
    required_modes = packet.get("required_modes", [])
    if not isinstance(required_families, list) or not all(isinstance(item, str) and item for item in required_families):
        add_error(source, "malformed_required_families", "required_families must be non-empty strings")
        required_families = []
    if not isinstance(required_modes, list) or not all(item in {"strict", "hardened"} for item in required_modes):
        add_error(source, "malformed_required_modes", "required_modes must contain strict/hardened")
        required_modes = []

    measurements = packet.get("measurements", [])
    if not isinstance(measurements, list) or not measurements:
        add_error(source, "missing_measurements", "measurements must be a non-empty list")
        measurements = []
    seen_families = {row.get("abi_family") for row in measurements if isinstance(row, dict)}
    seen_modes = {row.get("mode") for row in measurements if isinstance(row, dict)}
    for family in required_families:
        if family not in seen_families:
            add_error(source, "missing_family", f"missing required ABI family {family}")
    for mode in required_modes:
        if mode not in seen_modes:
            add_error(source, "missing_mode", f"missing required mode {mode}")

    for index, row in enumerate(measurements):
        if not isinstance(row, dict):
            add_error(source, "malformed_measurement", f"measurement {index} must be an object")
            continue
        validate_measurement(packet, row, source, index)

    events.append(
        {
            "source": source,
            "status": "checked",
            "measurement_count": len(measurements),
            "required_family_count": len(required_families),
            "required_mode_count": len(required_modes),
        }
    )


def first_measurement(packet: dict[str, Any]) -> dict[str, Any] | None:
    for row in packet.get("measurements", []):
        if isinstance(row, dict):
            return row
    return None


def expect_validation_failure(packet: dict[str, Any], source: str, signature: str, mutation: str) -> None:
    before_errors = len(errors)
    before_events = len(events)
    validate_packet(packet, source, require_current_claim_source=False)
    observed_errors = errors[before_errors:]
    del errors[before_errors:]
    del events[before_events:]
    if any(error.get("failure_signature") == signature for error in observed_errors):
        events.append(
            {
                "source": source,
                "status": "negative_checked",
                "expected_failure_signature": signature,
                "mutation": mutation,
            }
        )
        return
    observed = sorted({str(error.get("failure_signature")) for error in observed_errors})
    add_error(source, "negative_control_missed", f"{mutation} did not trigger {signature}; observed={observed}")


def validate_negative_controls(packet: dict[str, Any], source: str) -> None:
    stale = deepcopy(packet)
    stale["source_commit"] = "0000000000000000000000000000000000000000"
    stale.setdefault("claim_policy", {})["claim_allowed"] = True
    expect_validation_failure(stale, f"{source}::stale_source_commit", "stale_source_commit", "allow claim with stale source_commit")

    missing_rch = deepcopy(packet)
    missing_rch.setdefault("rch_proof", {}).pop("required_remote_env", None)
    expect_validation_failure(missing_rch, f"{source}::missing_rch_remote", "missing_rch_remote", "remove required_remote_env")

    local = deepcopy(packet)
    local.setdefault("rch_proof", {})["local_fallback_seen"] = True
    expect_validation_failure(local, f"{source}::local_fallback_seen", "local_fallback_seen", "mark local fallback as seen")

    missing_family = deepcopy(packet)
    missing_family["measurements"] = [
        row for row in missing_family.get("measurements", []) if not (isinstance(row, dict) and row.get("abi_family") == "malloc")
    ]
    expect_validation_failure(missing_family, f"{source}::missing_family", "missing_family", "remove malloc measurements")

    missing_mode = deepcopy(packet)
    missing_mode["measurements"] = [
        row for row in missing_mode.get("measurements", []) if not (isinstance(row, dict) and row.get("mode") == "hardened")
    ]
    expect_validation_failure(missing_mode, f"{source}::missing_mode", "missing_mode", "remove hardened measurements")

    invalid_quantile = deepcopy(packet)
    row = first_measurement(invalid_quantile)
    if row is None:
        add_error(source, "negative_control_no_measurement", "golden packet has no measurement for mutation")
    else:
        row.setdefault("quantiles_ns", {})["p99"] = -1.0
        expect_validation_failure(invalid_quantile, f"{source}::invalid_quantile", "invalid_quantile", "make p99 negative")

    regression = deepcopy(packet)
    row = first_measurement(regression)
    if row is None:
        add_error(source, "negative_control_no_measurement", "golden packet has no measurement for mutation")
    else:
        row.setdefault("quantiles_ns", {})["p99"] = float(row.get("target_budget_ns", 0)) + 1.0
        expect_validation_failure(regression, f"{source}::budget_regression", "budget_regression", "make p99 exceed budget")

    missing_telemetry = deepcopy(packet)
    row = first_measurement(missing_telemetry)
    if row is None:
        add_error(source, "negative_control_no_measurement", "golden packet has no measurement for mutation")
    else:
        row.pop("runtime_math_decision_summary", None)
        expect_validation_failure(
            missing_telemetry,
            f"{source}::missing_runtime_math_telemetry",
            "missing_runtime_math_telemetry",
            "remove runtime-math decision telemetry",
        )


CURRENT_HEAD = current_head()
golden = load_json(GOLDEN)
if golden.get("schema_version") != EXPECTED_GOLDEN_SCHEMA:
    add_error(rel(GOLDEN), "golden_schema_version", "golden schema_version mismatch")
golden_report = golden.get("golden_report")
if not isinstance(golden_report, dict):
    add_error(rel(GOLDEN), "missing_golden_report", "golden_report must be an object")
else:
    validate_packet(golden_report, rel(GOLDEN), require_current_claim_source=False)
    validate_negative_controls(golden_report, rel(GOLDEN))

expected_negatives = golden.get("negative_controls_expected", [])
if not isinstance(expected_negatives, list) or not all(isinstance(item, str) for item in expected_negatives):
    add_error(rel(GOLDEN), "malformed_negative_controls", "negative_controls_expected must be a string list")
else:
    observed = {event.get("expected_failure_signature") for event in events if event.get("status") == "negative_checked"}
    missing = sorted(set(expected_negatives) - observed)
    if missing:
        add_error(rel(GOLDEN), "missing_negative_control", f"missing negative controls {missing}")

if LIVE_REPORT.exists():
    validate_packet(load_json(LIVE_REPORT), rel(LIVE_REPORT), require_current_claim_source=True)

report = {
    "schema_version": "runtime_membrane_overhead_evidence_checker.v1",
    "generated_at_utc": utc_now(),
    "current_head": CURRENT_HEAD,
    "golden": rel(GOLDEN),
    "live_report": rel(LIVE_REPORT) if LIVE_REPORT.exists() else None,
    "checked_events": events,
    "errors": errors,
    "status": "pass" if not errors else "fail",
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)
if errors:
    print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
    sys.exit(1)
print(json.dumps({"status": "pass", "events": len(events)}, sort_keys=True))
PY
