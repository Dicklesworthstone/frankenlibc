#!/usr/bin/env bash
# check_gate_drift.sh -- WS-0 Bayesian change-point gate-drift monitor.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SERIES="${FRANKENLIBC_GATE_DRIFT_SERIES:-$ROOT/tests/conformance/gate_drift_series.v1.json}"
REPORT="${FRANKENLIBC_GATE_DRIFT_REPORT:-$ROOT/target/conformance/gate_drift.report.json}"

mkdir -p "$(dirname "$REPORT")"

python3 - "$ROOT" "$SERIES" "$REPORT" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
SERIES = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])

SCHEMA = "gate_drift_series.v1"
REPORT_SCHEMA = "gate_drift_report.v1"
WARMUP_COUNT = 32
HAZARD_LAMBDA = 200.0
SHORT_WINDOW = 16
DRIFT_THRESHOLD = 0.30
CHANGEPOINT_THRESHOLD = 0.60
MAX_RUN_LENGTH = 256
MIN_ACTIVE_PROB = 1e-300

errors: list[dict[str, str]] = []


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


class ChangePoint:
    def __init__(self) -> None:
        self.probs = [0.0] * MAX_RUN_LENGTH
        self.adverse = [0.0] * MAX_RUN_LENGTH
        self.total = [0.0] * MAX_RUN_LENGTH
        self.probs[0] = 1.0
        self.current_max = 0
        self.observations = 0
        self.shift_count = 0
        self.change_point_count = 0
        self.state = "Calibrating"
        self.max_short_mass = 0.0
        self.flagged_once = False

    def observe(self, adverse: bool) -> None:
        self.observations += 1
        x = 1.0 if adverse else 0.0
        if adverse:
            self.shift_count += 1

        max_rl = self.current_max
        while max_rl > 0 and self.probs[max_rl] < MIN_ACTIVE_PROB:
            max_rl -= 1
        pre_trim_next_max = min(max_rl + 1, MAX_RUN_LENGTH - 1)
        new_probs = [0.0] * MAX_RUN_LENGTH
        new_adverse = [0.0] * MAX_RUN_LENGTH
        new_total = [0.0] * MAX_RUN_LENGTH
        reset_mass = 0.0

        for run_length in range(max_rl, -1, -1):
            prior = self.probs[run_length]
            if prior < MIN_ACTIVE_PROB:
                continue
            alpha_post = 1.0 + self.adverse[run_length]
            beta_post = 1.0 + (self.total[run_length] - self.adverse[run_length])
            pred_adverse = alpha_post / (alpha_post + beta_post)
            likelihood = pred_adverse if adverse else 1.0 - pred_adverse
            weighted = prior * likelihood
            hazard = 1.0 / (run_length + HAZARD_LAMBDA)
            reset_mass += weighted * hazard
            next_run_length = run_length + 1
            if next_run_length < MAX_RUN_LENGTH:
                new_probs[next_run_length] = weighted * (1.0 - hazard)
                new_adverse[next_run_length] = self.adverse[run_length] + x
                new_total[next_run_length] = self.total[run_length] + 1.0

        new_probs[0] = reset_mass
        new_adverse[0] = x
        new_total[0] = 1.0

        new_max = pre_trim_next_max
        while new_max > 0 and new_probs[new_max] < MIN_ACTIVE_PROB:
            new_max -= 1
        norm = sum(new_probs[: new_max + 1])
        if norm > 0.0:
            inv = 1.0 / norm
            for index in range(new_max + 1):
                new_probs[index] *= inv
        else:
            new_probs[0] = 1.0

        self.probs = new_probs
        self.adverse = new_adverse
        self.total = new_total
        self.current_max = new_max
        short_limit = min(SHORT_WINDOW, new_max + 1)
        short_mass = sum(self.probs[:short_limit])

        previous = self.state
        if self.observations < WARMUP_COUNT:
            self.state = "Calibrating"
        elif short_mass >= CHANGEPOINT_THRESHOLD:
            self.state = "ChangePoint"
        elif short_mass >= DRIFT_THRESHOLD:
            self.state = "Drift"
        else:
            self.state = "Stable"
        if self.state == "ChangePoint" and previous != "ChangePoint":
            self.change_point_count += 1
        self.max_short_mass = max(self.max_short_mass, short_mass)
        if self.observations >= WARMUP_COUNT and self.state in {"Drift", "ChangePoint"}:
            self.flagged_once = True

    def summary(self, gate: str) -> dict[str, Any]:
        short_limit = min(SHORT_WINDOW, self.current_max + 1)
        short_mass = sum(self.probs[:short_limit])
        return {
            "gate": gate,
            "observations": self.observations,
            "uncorrelated_shifts": self.shift_count,
            "state": self.state,
            "posterior_short_mass": short_mass,
            "max_posterior_short_mass": self.max_short_mass,
            "change_point_count": self.change_point_count,
            "flagged": self.flagged_once,
        }


def load_series() -> dict[str, Any] | None:
    try:
        value = json.loads(SERIES.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("gate_drift_series_unreadable", f"cannot read {rel(SERIES)}: {exc}")
        return None
    if not isinstance(value, dict):
        add_error("gate_drift_series_malformed", "series root must be an object")
        return None
    if value.get("schema_version") != SCHEMA:
        add_error("gate_drift_series_malformed", f"schema_version must be {SCHEMA}")
    if not isinstance(value.get("streams"), list) or not value["streams"]:
        add_error("gate_drift_series_malformed", "streams must be a non-empty array")
    return value


def observation_is_adverse(observation: dict[str, Any], gate: str, index: int) -> bool:
    for field in ["passed", "expected_passed", "code_delta"]:
        if not isinstance(observation.get(field), bool):
            add_error(
                "gate_drift_observation_malformed",
                f"{gate}[{index}].{field} must be boolean",
            )
            return True
    return bool(observation["passed"] != observation["expected_passed"] and not observation["code_delta"])


series = load_series()
gate_summaries: list[dict[str, Any]] = []
if series is not None and isinstance(series.get("streams"), list):
    for stream_index, stream in enumerate(series["streams"]):
        if not isinstance(stream, dict):
            add_error("gate_drift_series_malformed", f"streams[{stream_index}] must be an object")
            continue
        gate = stream.get("gate")
        observations = stream.get("observations")
        if not isinstance(gate, str) or not gate:
            add_error("gate_drift_series_malformed", f"streams[{stream_index}].gate must be non-empty")
            continue
        if not isinstance(observations, list) or not observations:
            add_error("gate_drift_series_malformed", f"{gate}.observations must be non-empty")
            continue
        monitor = ChangePoint()
        for obs_index, observation in enumerate(observations):
            if not isinstance(observation, dict):
                add_error("gate_drift_observation_malformed", f"{gate}[{obs_index}] must be an object")
                monitor.observe(True)
                continue
            monitor.observe(observation_is_adverse(observation, gate, obs_index))
        summary = monitor.summary(gate)
        gate_summaries.append(summary)
        if summary["flagged"]:
            add_error(
                "gate_drift_uncorrelated_changepoint",
                f"{gate} entered {summary['state']} after {summary['uncorrelated_shifts']} uncorrelated outcome shifts",
            )

status = "fail" if errors else "pass"
failure_signature = errors[0]["failure_signature"] if errors else "none"
report = {
    "schema_version": REPORT_SCHEMA,
    "generated_at_utc": now_utc(),
    "source_commit": git_head(),
    "series": rel(SERIES),
    "status": status,
    "failure_signature": failure_signature,
    "parameters": {
        "warmup_count": WARMUP_COUNT,
        "hazard_lambda": HAZARD_LAMBDA,
        "short_window": SHORT_WINDOW,
        "drift_threshold": DRIFT_THRESHOLD,
        "changepoint_threshold": CHANGEPOINT_THRESHOLD,
        "max_run_length": MAX_RUN_LENGTH,
    },
    "gate_summaries": gate_summaries,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL gate drift {failure_signature}: flagged_gates={sum(1 for g in gate_summaries if g['flagged'])}")
    sys.exit(1)
print(f"PASS gate drift gates={len(gate_summaries)} flagged_gates=0")
PY
