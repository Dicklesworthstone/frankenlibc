#!/usr/bin/env bash
# check_pressure_sensing.sh — CI gate for bd-w2c3.7.1
# Validates deterministic pressure sensing regime transitions and emits
# structured evidence artifacts for replay/triage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Pressure Sensing Gate (bd-w2c3.7.1) ==="

MODULE="$REPO_ROOT/crates/frankenlibc-membrane/src/pressure_sensor.rs"
FIXTURE="$REPO_ROOT/tests/conformance/fixtures/pressure_sensing.json"
SCENARIO="$REPO_ROOT/tests/conformance/pressure_sensing_scenarios.v1.json"
REPORT_PATH="$REPO_ROOT/target/conformance/pressure_sensing.report.json"
LOG_PATH="$REPO_ROOT/target/conformance/pressure_sensing.log.jsonl"

if [ ! -f "$MODULE" ]; then
    echo "FAIL: pressure_sensor.rs not found"
    exit 1
fi
if [ ! -f "$FIXTURE" ]; then
    echo "FAIL: pressure_sensing.json fixture not found"
    exit 1
fi
if [ ! -f "$SCENARIO" ]; then
    echo "FAIL: pressure_sensing_scenarios.v1.json not found"
    exit 1
fi

echo "Module: $(wc -l < "$MODULE") lines"
mkdir -p "$(dirname "$REPORT_PATH")"

echo "--- Running pressure_sensor unit tests ---"
cargo test -p frankenlibc-membrane pressure_sensor:: -- --nocapture

python3 - "$FIXTURE" "$SCENARIO" "$REPORT_PATH" "$LOG_PATH" "$REPO_ROOT" <<'PY'
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

fixture_path = sys.argv[1]
scenario_path = sys.argv[2]
report_path = sys.argv[3]
log_path = sys.argv[4]
repo_root = sys.argv[5]
harness_cargo_path = os.path.join(repo_root, "crates/frankenlibc-harness/Cargo.toml")

EWMA_ALPHA = 0.2
W_SCHEDULER_DELAY = 0.25
W_QUEUE_DEPTH = 0.20
W_ERROR_BURST = 0.20
W_LATENCY_ENVELOPE = 0.20
W_RESOURCE_PRESSURE = 0.15
CAP_SCHEDULER_DELAY_NS = 10_000_000.0
CAP_QUEUE_DEPTH = 1000.0
CAP_ERROR_BURST = 50.0
CAP_LATENCY_ENVELOPE_NS = 50_000_000.0

with open(fixture_path, encoding="utf-8") as f:
    fixture = json.load(f)
with open(scenario_path, encoding="utf-8") as f:
    scenario_doc = json.load(f)

errors = []

cases = fixture.get("cases", [])
if not cases:
    errors.append("fixture has no cases")

strict_count = sum(1 for c in cases if c.get("mode") == "strict")
hardened_count = sum(1 for c in cases if c.get("mode") == "hardened")
if strict_count == 0:
    errors.append("fixture has no strict-mode cases")
if hardened_count == 0:
    errors.append("fixture has no hardened-mode cases")

if fixture.get("family") != "pressure_sensing":
    errors.append(f"unexpected fixture family {fixture.get('family')!r}")

thresholds = scenario_doc.get("thresholds", {})
required_threshold_keys = [
    "pressured_enter",
    "pressured_exit",
    "overloaded_enter",
    "overloaded_exit",
    "cooldown_epochs",
    "recovery_hold_epochs",
]
for key in required_threshold_keys:
    if key not in thresholds:
        errors.append(f"missing threshold key {key!r}")

pe = float(thresholds.get("pressured_enter", 0.0))
px = float(thresholds.get("pressured_exit", 0.0))
oe = float(thresholds.get("overloaded_enter", 0.0))
ox = float(thresholds.get("overloaded_exit", 0.0))
if not (px < pe < oe and px < ox < oe):
    errors.append("threshold ordering invalid: need pressured_exit < pressured_enter < overloaded_enter and pressured_exit < overloaded_exit < overloaded_enter")

if int(thresholds.get("cooldown_epochs", 0)) <= 0:
    errors.append("cooldown_epochs must be > 0")
if int(thresholds.get("recovery_hold_epochs", 0)) <= 0:
    errors.append("recovery_hold_epochs must be > 0")

scenarios = scenario_doc.get("scenarios", [])
if not scenarios:
    errors.append("scenario fixture has no scenarios")

if not os.path.exists(harness_cargo_path):
    errors.append("missing harness cargo manifest for tooling contract checks")
    harness_cargo_content = ""
else:
    with open(harness_cargo_path, encoding="utf-8") as f:
        harness_cargo_content = f.read()

tooling_contract = {
    "cargo_manifest": os.path.relpath(harness_cargo_path, repo_root),
    "has_asupersync_dependency": "asupersync-conformance" in harness_cargo_content,
    "asupersync_feature_present": "asupersync-tooling" in harness_cargo_content
    and "dep:asupersync-conformance" in harness_cargo_content,
    "frankentui_feature_present": "frankentui-ui" in harness_cargo_content
    and "dep:ftui-harness" in harness_cargo_content,
}
tooling_contract["default_enables_asupersync_tooling"] = (
    'default = ["asupersync-tooling"]' in harness_cargo_content
)
tooling_contract["frankentui_dependency_set_complete"] = all(
    token in harness_cargo_content
    for token in (
        "ftui-harness",
        "ftui-core",
        "ftui-layout",
        "ftui-render",
        "ftui-style",
        "ftui-widgets",
    )
)
for key, enabled in tooling_contract.items():
    if key == "cargo_manifest":
        continue
    if not enabled:
        errors.append(f"tooling contract check failed: {key}")

def normalize_signal(inputs):
    return {
        "scheduler_delay_ns": float(inputs["scheduler_delay_ns"]),
        "queue_depth": float(inputs["queue_depth"]),
        "error_burst_count": float(inputs["error_burst_count"]),
        "latency_envelope_ns": float(inputs["latency_envelope_ns"]),
        "resource_pressure_pct": float(inputs["resource_pressure_pct"]),
    }

signal_by_name = {}
for case in cases:
    name = case.get("name", "")
    inputs = case.get("inputs", {})
    if not isinstance(inputs, dict):
        continue
    numeric_inputs = {
        "scheduler_delay_ns",
        "queue_depth",
        "error_burst_count",
        "latency_envelope_ns",
        "resource_pressure_pct",
    }
    if not numeric_inputs.issubset(inputs.keys()):
        continue
    if "nominal_under_calm" in name:
        signal_by_name["calm"] = normalize_signal(inputs)
    elif "escalate_to_pressured" in name:
        signal_by_name["moderate"] = normalize_signal(inputs)
    elif "escalate_to_overloaded" in name:
        signal_by_name["heavy"] = normalize_signal(inputs)

for required_signal in ("calm", "moderate", "heavy"):
    if required_signal not in signal_by_name:
        errors.append(f"fixture missing representative {required_signal} signal profile")

def composite_score(sig):
    s_delay = min(max(sig["scheduler_delay_ns"] / CAP_SCHEDULER_DELAY_NS * 100.0, 0.0), 100.0)
    s_queue = min(max(sig["queue_depth"] / CAP_QUEUE_DEPTH * 100.0, 0.0), 100.0)
    s_error = min(max(sig["error_burst_count"] / CAP_ERROR_BURST * 100.0, 0.0), 100.0)
    s_latency = min(max(sig["latency_envelope_ns"] / CAP_LATENCY_ENVELOPE_NS * 100.0, 0.0), 100.0)
    s_resource = min(max(sig["resource_pressure_pct"], 0.0), 100.0)
    return (
        W_SCHEDULER_DELAY * s_delay
        + W_QUEUE_DEPTH * s_queue
        + W_ERROR_BURST * s_error
        + W_LATENCY_ENVELOPE * s_latency
        + W_RESOURCE_PRESSURE * s_resource
    )

class Sensor:
    def __init__(self, th):
        self.regime = "Nominal"
        self.th = th
        self.pressure_score = 0.0
        self.pending_streak = 0
        self.pending_escalate = False
        self.recovery_remaining = 0
        self.transitions = 0
        self.epoch = 0

    def _accumulate_pending(self, escalate):
        if self.pending_escalate == escalate:
            self.pending_streak += 1
        else:
            self.pending_escalate = escalate
            self.pending_streak = 1

    def _reset_pending(self):
        self.pending_streak = 0

    def _transition_to(self, regime):
        if self.regime != regime:
            self.regime = regime
            self.transitions += 1
            self.pending_streak = 0

    def observe(self, sig):
        self.epoch += 1
        raw = composite_score(sig)
        if self.epoch == 1:
            self.pressure_score = raw
        else:
            self.pressure_score = EWMA_ALPHA * raw + (1.0 - EWMA_ALPHA) * self.pressure_score

        score = self.pressure_score
        th = self.th
        cooldown = int(th["cooldown_epochs"])

        if self.regime == "Nominal":
            if score >= th["pressured_enter"]:
                self._accumulate_pending(True)
                if self.pending_streak >= cooldown:
                    self._transition_to("Pressured")
            else:
                self._reset_pending()
        elif self.regime == "Pressured":
            if score >= th["overloaded_enter"]:
                self._accumulate_pending(True)
                if self.pending_streak >= cooldown:
                    self._transition_to("Overloaded")
            elif score < th["pressured_exit"]:
                self._accumulate_pending(False)
                if self.pending_streak >= cooldown:
                    self._transition_to("Nominal")
            else:
                self._reset_pending()
        elif self.regime == "Overloaded":
            if score < th["overloaded_exit"]:
                self._accumulate_pending(False)
                if self.pending_streak >= cooldown:
                    self._transition_to("Recovery")
                    self.recovery_remaining = int(th["recovery_hold_epochs"])
            else:
                self._reset_pending()
        else:  # Recovery
            if score >= th["overloaded_enter"]:
                self._accumulate_pending(True)
                if self.pending_streak >= cooldown:
                    self._transition_to("Overloaded")
            elif self.recovery_remaining > 0:
                self.recovery_remaining -= 1
                self._reset_pending()
            else:
                if score >= th["pressured_enter"]:
                    self._transition_to("Pressured")
                else:
                    self._transition_to("Nominal")

        return self.regime

def build_sequence(pattern, epochs):
    pattern = pattern.strip()
    seq = []
    if pattern in ("calm", "moderate", "heavy"):
        return [signal_by_name[pattern]] * epochs
    if pattern.startswith("alternate moderate/calm"):
        for i in range(epochs):
            seq.append(signal_by_name["moderate"] if i % 2 == 0 else signal_by_name["calm"])
        return seq

    normalized = pattern.replace(" then ", " ").replace(",", " ")
    segments = [segment for segment in normalized.split() if segment]
    for segment in segments:
        segment = segment.strip()
        match = re.fullmatch(r"(calm|moderate|heavy)\*(\d+)", segment)
        if not match:
            raise ValueError(f"Unsupported signal_pattern segment: {segment!r}")
        signal_name = match.group(1)
        count = int(match.group(2))
        seq.extend([signal_by_name[signal_name]] * count)

    if len(seq) < epochs and seq:
        seq.extend([seq[-1]] * (epochs - len(seq)))
    if len(seq) > epochs:
        seq = seq[:epochs]
    return seq

scenario_results = []
for scenario in scenarios:
    scenario_start = time.time_ns()
    sid = scenario.get("id", "unknown")
    pattern = scenario.get("signal_pattern", "")
    epochs = int(scenario.get("epochs", 0))
    if epochs <= 0:
        errors.append(f"scenario {sid}: epochs must be > 0")
        continue

    try:
        sequence = build_sequence(pattern, epochs)
    except Exception as exc:
        errors.append(f"scenario {sid}: failed to build signal sequence: {exc}")
        continue
    if len(sequence) != epochs:
        errors.append(f"scenario {sid}: built sequence length {len(sequence)} != epochs {epochs}")
        continue

    sensor = Sensor(thresholds)
    history = []
    for sig in sequence:
        history.append(sensor.observe(sig))

    final_regime = history[-1] if history else "Nominal"
    visited = sorted(set(history))
    status = "pass"
    findings = []

    if "expected_final_regime" in scenario and final_regime != scenario["expected_final_regime"]:
        status = "fail"
        findings.append(
            f"expected_final_regime={scenario['expected_final_regime']} got={final_regime}"
        )
    if "expected_transitions" in scenario and sensor.transitions != int(scenario["expected_transitions"]):
        status = "fail"
        findings.append(
            f"expected_transitions={scenario['expected_transitions']} got={sensor.transitions}"
        )
    if "expected_min_transitions" in scenario and sensor.transitions < int(scenario["expected_min_transitions"]):
        status = "fail"
        findings.append(
            f"expected_min_transitions={scenario['expected_min_transitions']} got={sensor.transitions}"
        )
    if "max_transitions" in scenario and sensor.transitions > int(scenario["max_transitions"]):
        status = "fail"
        findings.append(f"max_transitions={scenario['max_transitions']} exceeded: {sensor.transitions}")
    if "expected_regimes_visited" in scenario:
        expected = set(scenario["expected_regimes_visited"])
        seen = set(history)
        missing = sorted(expected - seen)
        if missing:
            status = "fail"
            findings.append(f"missing expected regimes: {missing}")
    if scenario.get("expected_sees_recovery", False) and "Recovery" not in history:
        status = "fail"
        findings.append("expected Recovery state not observed")
    if scenario.get("expected_sees_re_escalation", False):
        saw_recovery = "Recovery" in history
        saw_overloaded_after_recovery = False
        if saw_recovery:
            first_recovery_idx = history.index("Recovery")
            saw_overloaded_after_recovery = "Overloaded" in history[first_recovery_idx + 1 :]
        if not (saw_recovery and saw_overloaded_after_recovery):
            status = "fail"
            findings.append("expected re-escalation Overloaded after Recovery not observed")

    if status == "fail":
        errors.append(f"scenario {sid} failed: {'; '.join(findings)}")

    scenario_results.append(
        {
            "id": sid,
            "status": status,
            "epochs": epochs,
            "signal_pattern": pattern,
            "final_regime": final_regime,
            "transitions": sensor.transitions,
            "visited_regimes": visited,
            "findings": findings,
            "latency_ns": time.time_ns() - scenario_start,
        }
    )

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": "bd-w2c3.7.1",
    "generated_at": generated_at,
    "status": status,
    "summary": {
        "scenario_count": len(scenario_results),
        "passed": sum(1 for r in scenario_results if r["status"] == "pass"),
        "failed": sum(1 for r in scenario_results if r["status"] != "pass"),
        "strict_fixture_cases": strict_count,
        "hardened_fixture_cases": hardened_count,
        "errors": len(errors),
    },
    "thresholds": thresholds,
    "scenarios": scenario_results,
    "findings": errors,
    "artifacts_consumed": {
        "fixture": os.path.relpath(fixture_path, repo_root),
        "scenario": os.path.relpath(scenario_path, repo_root),
        "harness_cargo_manifest": os.path.relpath(harness_cargo_path, repo_root),
    },
    "artifacts_emitted": {
        "report": os.path.relpath(report_path, repo_root),
        "structured_log": os.path.relpath(log_path, repo_root),
    },
    "tooling_contract": tooling_contract,
}

with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
    f.write("\n")

trace_prefix = (
    "bd-w2c3.7.1::pressure-sensing::"
    + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    + f"::{os.getpid()}"
)
with open(log_path, "w", encoding="utf-8") as f:
    for row in scenario_results:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "trace_id": f"{trace_prefix}::{row['id']}",
            "level": "info" if row["status"] == "pass" else "error",
            "event": "pressure_sensing_scenario",
            "bead_id": "bd-w2c3.7.1",
            "mode": "strict",
            "api_family": "pressure_sensing",
            "symbol": "PressureSensor::observe",
            "decision_path": "signals+ewma+hysteresis+cooldown+recovery_hold+tooling_contract",
            "healing_action": "None",
            "errno": 0 if row["status"] == "pass" else 1,
            "latency_ns": row["latency_ns"],
            "artifact_refs": [
                os.path.relpath(fixture_path, repo_root),
                os.path.relpath(scenario_path, repo_root),
                os.path.relpath(report_path, repo_root),
                os.path.relpath(log_path, repo_root),
                os.path.relpath(harness_cargo_path, repo_root),
            ],
            "scenario_id": row["id"],
            "outcome": row["status"],
            "details": {
                "final_regime": row["final_regime"],
                "transitions": row["transitions"],
                "visited_regimes": row["visited_regimes"],
                "findings": row["findings"],
                "tooling_contract": tooling_contract,
            },
        }
        f.write(json.dumps(event, separators=(",", ":")) + "\n")

print(f"Fixture: {len(cases)} cases (strict={strict_count}, hardened={hardened_count})")
print(f"Scenarios: {len(scenario_results)}")
print(f"Thresholds: valid ordering (PE={pe} > PX={px}, OE={oe} > OX={ox})")
print(f"Report: {os.path.relpath(report_path, repo_root)}")
print(f"Structured log: {os.path.relpath(log_path, repo_root)}")

if errors:
    print("\nFAIL:")
    for err in errors:
        print(f" - {err}")
    sys.exit(1)

print("\ncheck_pressure_sensing: PASS")
PY
