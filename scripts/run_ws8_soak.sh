#!/usr/bin/env bash
# run_ws8_soak.sh -- WS-8 standalone replacement soak orchestrator.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${WS8_SOAK_MANIFEST:-${ROOT}/tests/conformance/ws8_soak.v1.json}"
OUT_DIR="${WS8_SOAK_OUT_DIR:-${ROOT}/target/conformance/ws8_soak}"
REPORT="${WS8_SOAK_REPORT:-${OUT_DIR}/ws8_soak.report.json}"
LOG="${WS8_SOAK_LOG:-${OUT_DIR}/ws8_soak.log.jsonl}"
TARGET_ROOT="${WS8_SOAK_TARGET_ROOT:-${ROOT}/target/ws8_soak}"
RUN_ID="${WS8_SOAK_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
MODE="${1:---run}"

case "${MODE}" in
  --run|--validate-only|--smoke)
    ;;
  *)
    echo "usage: $0 [--run|--validate-only|--smoke]" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_DIR}" "${TARGET_ROOT}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${TARGET_ROOT}" "${RUN_ID}" "${MODE}" <<'PY'
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
target_root = Path(sys.argv[5])
run_id = sys.argv[6]
mode = sys.argv[7]

SCHEMA = "ws8_soak.v1"
REPORT_SCHEMA = "ws8_soak.report.v1"
BEAD = "bd-38x82.4"
PARENT = "bd-38x82"

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []
iterations: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    value = Path(path)
    try:
        return value.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def current_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


SOURCE_COMMIT = current_commit()


def add_error(source: str, signature: str, message: str) -> None:
    errors.append({"source": source, "failure_signature": signature, "message": message})


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(rel(path), "ws8_soak_invalid_manifest", f"cannot parse JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        add_error(rel(path), "ws8_soak_invalid_manifest", "JSON root must be an object")
        return {}
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        add_error(name, "ws8_soak_invalid_manifest", f"{name} must be an integer")
        return default


def append_event(
    *,
    event: str,
    iteration: int,
    iteration_run_id: str,
    status: str,
    proof_status: str,
    failure_signature: str,
    artifact_refs: list[str] | None = None,
) -> None:
    events.append(
        {
            "timestamp": utc_now(),
            "event": event,
            "bead": BEAD,
            "mode": mode,
            "iteration": iteration,
            "run_id": iteration_run_id,
            "status": status,
            "proof_status": proof_status,
            "failure_signature": failure_signature,
            "source_commit": SOURCE_COMMIT,
            "target_dir": str(target_root),
            "artifact_refs": artifact_refs or [],
        }
    )


def string_field(value: dict[str, Any], key: str, default: str = "") -> str:
    item = value.get(key)
    return item if isinstance(item, str) else default


def list_field(value: dict[str, Any], key: str) -> list[Any]:
    item = value.get(key)
    return item if isinstance(item, list) else []


manifest = load_json(manifest_path)
policy = manifest.get("soak_policy")
if not isinstance(policy, dict):
    policy = {}
    add_error(rel(manifest_path), "ws8_soak_invalid_manifest", "soak_policy must be an object")

if manifest.get("schema_version") != SCHEMA:
    add_error(rel(manifest_path), "ws8_soak_invalid_manifest", f"schema_version must be {SCHEMA}")
if manifest.get("bead") != BEAD:
    add_error(rel(manifest_path), "ws8_soak_invalid_manifest", f"bead must be {BEAD}")
if manifest.get("parent_bead") != PARENT:
    add_error(rel(manifest_path), "ws8_soak_invalid_manifest", f"parent_bead must be {PARENT}")

inputs = manifest.get("inputs") if isinstance(manifest.get("inputs"), dict) else {}
runner_rel = string_field(inputs, "standalone_link_run_smoke_runner", "scripts/check_standalone_link_run_smoke.sh")
runner = root / runner_rel
smoke_manifest_rel = string_field(inputs, "standalone_link_run_smoke_manifest", "tests/conformance/standalone_link_run_smoke.v1.json")
smoke_manifest = root / smoke_manifest_rel

for input_name, input_path in inputs.items():
    if isinstance(input_path, str) and not (root / input_path).exists():
        add_error(input_name, "ws8_soak_invalid_manifest", f"input path does not exist: {input_path}")
if not runner.exists():
    add_error(rel(runner), "ws8_soak_invalid_manifest", "standalone smoke runner is missing")

contract_duration = int(policy.get("duration_seconds", 86400)) if isinstance(policy.get("duration_seconds", 86400), int) else 86400
minimum_iterations = int(policy.get("minimum_iterations", 1)) if isinstance(policy.get("minimum_iterations", 1), int) else 1
duration_seconds = int_env("WS8_SOAK_DURATION_SECONDS", contract_duration)
minimum_iterations = int_env("WS8_SOAK_MINIMUM_ITERATIONS", minimum_iterations)
max_iterations_env = os.environ.get("WS8_SOAK_MAX_ITERATIONS")
max_iterations = None if max_iterations_env in {None, ""} else int_env("WS8_SOAK_MAX_ITERATIONS", 0)
sleep_seconds = max(int_env("WS8_SOAK_SLEEP_SECONDS", 0), 0)

if contract_duration < 86400:
    add_error(rel(manifest_path), "ws8_soak_duration_too_short", "contract duration_seconds must be at least 86400")
if mode == "--run" and duration_seconds < contract_duration:
    add_error("WS8_SOAK_DURATION_SECONDS", "ws8_soak_duration_too_short", "full evidence mode must run for the contract duration")
if minimum_iterations < 1:
    add_error("WS8_SOAK_MINIMUM_ITERATIONS", "ws8_soak_invalid_manifest", "minimum iterations must be >= 1")
if max_iterations is not None and max_iterations < 1:
    add_error("WS8_SOAK_MAX_ITERATIONS", "ws8_soak_invalid_manifest", "max iterations must be >= 1 when set")

required_log_fields = set(str(item) for item in list_field(manifest, "required_log_fields"))
for field in [
    "event",
    "bead",
    "mode",
    "iteration",
    "run_id",
    "status",
    "proof_status",
    "failure_signature",
    "source_commit",
    "target_dir",
    "artifact_refs",
]:
    if field not in required_log_fields:
        add_error(rel(manifest_path), "ws8_soak_invalid_manifest", f"required_log_fields missing {field}")


def run_iteration(iteration: int, runner_mode: str) -> dict[str, Any]:
    iteration_run_id = f"{run_id}-iter-{iteration:04d}"
    iteration_dir = target_root / iteration_run_id
    iteration_report = iteration_dir / "standalone_link_run_smoke.report.json"
    iteration_log = iteration_dir / "standalone_link_run_smoke.log.jsonl"
    smoke_target = iteration_dir / "standalone_link_run_smoke"
    append_event(
        event="iteration_start",
        iteration=iteration,
        iteration_run_id=iteration_run_id,
        status="running",
        proof_status="pending",
        failure_signature="none",
        artifact_refs=[rel(iteration_report), rel(iteration_log)],
    )
    env = os.environ.copy()
    env.update(
        {
            "STANDALONE_SMOKE_MANIFEST": str(smoke_manifest),
            "STANDALONE_SMOKE_RUN_ID": iteration_run_id,
            "STANDALONE_SMOKE_TARGET_DIR": str(smoke_target),
            "STANDALONE_SMOKE_REPORT": str(iteration_report),
            "STANDALONE_SMOKE_LOG": str(iteration_log),
        }
    )
    started = time.monotonic()
    proc = subprocess.run(
        [str(runner), runner_mode],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    elapsed = time.monotonic() - started
    if not iteration_report.exists():
        row = {
            "iteration": iteration,
            "run_id": iteration_run_id,
            "runner_mode": runner_mode,
            "status": "fail",
            "runner_exit_code": proc.returncode,
            "duration_seconds": elapsed,
            "failure_signature": "ws8_soak_runner_report_missing",
            "artifact_refs": [rel(iteration_dir)],
            "stdout_excerpt": proc.stdout[-4000:],
            "stderr_excerpt": proc.stderr[-4000:],
        }
        append_event(
            event="iteration_complete",
            iteration=iteration,
            iteration_run_id=iteration_run_id,
            status="fail",
            proof_status="runner_report_missing",
            failure_signature="ws8_soak_runner_report_missing",
            artifact_refs=row["artifact_refs"],
        )
        return row
    report = load_json(iteration_report)
    artifact_refs = [rel(iteration_report), rel(iteration_log), rel(iteration_dir)]
    artifact_refs.extend(str(item) for item in list_field(report, "artifact_refs") if isinstance(item, str))
    row = classify_iteration(iteration, iteration_run_id, runner_mode, proc.returncode, elapsed, report, artifact_refs)
    append_event(
        event="iteration_complete",
        iteration=iteration,
        iteration_run_id=iteration_run_id,
        status=row["status"],
        proof_status=row["proof_status"],
        failure_signature=row["failure_signature"],
        artifact_refs=artifact_refs,
    )
    return row


def classify_iteration(
    iteration: int,
    iteration_run_id: str,
    runner_mode: str,
    returncode: int,
    elapsed: float,
    report: dict[str, Any],
    artifact_refs: list[str],
) -> dict[str, Any]:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    rows = list_field(report, "rows")
    report_errors = list_field(report, "errors")
    tolerated_runner_errors: list[str] = []
    positive_divergences = 0
    negative_leaks = 0
    positive_passed = 0
    negative_blocked = 0
    crash_count = 0
    for smoke_row in rows:
        if not isinstance(smoke_row, dict):
            continue
        negative_case = bool(smoke_row.get("negative_case"))
        for result in list_field(smoke_row, "candidate_results"):
            if not isinstance(result, dict):
                continue
            actual = result.get("actual_status")
            failure = str(result.get("failure_signature", ""))
            if negative_case:
                if actual == "claim_blocked":
                    negative_blocked += 1
                else:
                    negative_leaks += 1
            elif actual == "pass":
                positive_passed += 1
            else:
                positive_divergences += 1
            if actual == "fail" or failure in {"loader_startup_failure", "exit_mismatch", "startup_timeout"}:
                crash_count += 1

    artifact_state = report.get("artifact_state") if isinstance(report.get("artifact_state"), dict) else {}
    artifact_current = artifact_state.get("status") == "current"
    claim_status = report.get("claim_status")
    runner_failed = returncode != 0 or report.get("status") != "pass"
    if (
        mode == "--smoke"
        and runner_mode == "--validate-only"
        and claim_status == "schema_validated"
        and set(str(error) for error in report_errors)
        <= {"replacement_levels current_level and release_tag_policy must remain L0"}
    ):
        tolerated_runner_errors = [str(error) for error in report_errors]
        runner_failed = False
    baseline_failures = int(summary.get("baseline_failed", 0) or 0)

    failure_signature = "none"
    proof_status = "iteration_passed"
    status = "pass"
    if runner_failed:
        status = "fail"
        proof_status = "runner_failed"
        failure_signature = "ws8_soak_runner_failed"
    elif mode == "--run" and not artifact_current:
        status = "fail"
        proof_status = "standalone_artifact_not_current"
        failure_signature = "ws8_soak_standalone_artifact_not_current"
    elif mode == "--run" and claim_status != policy.get("accepted_claim_status", "standalone_evidence_passed"):
        status = "fail"
        proof_status = "standalone_claim_blocked"
        failure_signature = "ws8_soak_standalone_artifact_not_current"
    elif positive_divergences:
        status = "fail"
        proof_status = "positive_divergence"
        failure_signature = "ws8_soak_positive_divergence"
    elif negative_leaks:
        status = "fail"
        proof_status = "negative_claim_leak"
        failure_signature = "ws8_soak_negative_claim_leak"

    return {
        "iteration": iteration,
        "run_id": iteration_run_id,
        "runner_mode": runner_mode,
        "status": status,
        "proof_status": proof_status,
        "runner_exit_code": returncode,
        "runner_failed": runner_failed,
        "runner_failure_tolerated": bool(tolerated_runner_errors),
        "tolerated_runner_errors": tolerated_runner_errors,
        "duration_seconds": elapsed,
        "failure_signature": failure_signature,
        "runner_report_status": report.get("status"),
        "runner_claim_status": claim_status,
        "artifact_state": artifact_state,
        "summary": summary,
        "positive_candidate_passed": positive_passed,
        "positive_candidate_divergences": positive_divergences,
        "negative_candidate_blocked": negative_blocked,
        "negative_candidate_leaks": negative_leaks,
        "baseline_failures": baseline_failures,
        "crash_count": crash_count,
        "artifact_refs": artifact_refs,
    }


started_at = time.monotonic()
append_event(
    event="soak_start",
    iteration=0,
    iteration_run_id=run_id,
    status="running",
    proof_status="pending",
    failure_signature="none",
    artifact_refs=[rel(manifest_path)],
)

if not errors and mode in {"--smoke", "--run"}:
    runner_mode = "--validate-only" if mode == "--smoke" else "--run"
    iteration = 0
    while True:
        iteration += 1
        iterations.append(run_iteration(iteration, runner_mode))
        observed = time.monotonic() - started_at
        if sleep_seconds and mode == "--run":
            time.sleep(sleep_seconds)
        if max_iterations is not None and iteration >= max_iterations:
            break
        if mode == "--smoke":
            break
        if observed >= duration_seconds and iteration >= minimum_iterations:
            break

observed_duration = time.monotonic() - started_at

summary = {
    "positive_candidate_passed": sum(int(row.get("positive_candidate_passed", 0) or 0) for row in iterations),
    "positive_candidate_divergences": sum(int(row.get("positive_candidate_divergences", 0) or 0) for row in iterations),
    "negative_candidate_blocked": sum(int(row.get("negative_candidate_blocked", 0) or 0) for row in iterations),
    "negative_candidate_leaks": sum(int(row.get("negative_candidate_leaks", 0) or 0) for row in iterations),
    "baseline_failures": sum(int(row.get("baseline_failures", 0) or 0) for row in iterations),
    "runner_failures": sum(1 for row in iterations if row.get("runner_failed") is True),
    "crash_count": sum(int(row.get("crash_count", 0) or 0) for row in iterations),
    "claim_blocked_iterations": sum(1 for row in iterations if row.get("runner_claim_status") == "claim_blocked"),
    "current_artifact_iterations": sum(1 for row in iterations if row.get("artifact_state", {}).get("status") == "current"),
}

proof_status = "contract_validated"
status = "pass"
if errors:
    status = "fail"
    proof_status = "contract_invalid"
elif mode == "--smoke":
    proof_status = "orchestrator_smoke_passed" if all(row.get("status") == "pass" for row in iterations) else "orchestrator_smoke_failed"
    status = "pass" if proof_status == "orchestrator_smoke_passed" else "fail"
elif mode == "--run":
    if observed_duration < duration_seconds:
        add_error("duration", "ws8_soak_duration_too_short", "observed duration is shorter than requested")
    if len(iterations) < minimum_iterations:
        add_error("iterations", "ws8_soak_invalid_manifest", "minimum iteration count was not reached")
    if any(row.get("status") != "pass" for row in iterations):
        for row in iterations:
            if row.get("status") != "pass":
                add_error(row.get("run_id", "iteration"), row.get("failure_signature", "ws8_soak_runner_failed"), row.get("proof_status", "iteration failed"))
    if not errors and summary["positive_candidate_divergences"] == 0 and summary["negative_candidate_leaks"] == 0 and summary["crash_count"] == 0:
        proof_status = "soak_evidence_passed"
        status = "pass"
    else:
        proof_status = "soak_evidence_failed"
        status = "fail"
else:
    proof_status = "contract_validated"

failure_signatures = sorted({error["failure_signature"] for error in errors})
if not failure_signatures and iterations:
    failure_signatures = sorted({str(row.get("failure_signature")) for row in iterations if row.get("failure_signature") not in {None, "none"}})

artifact_refs = [rel(manifest_path), rel(report_path), rel(log_path), rel(target_root)]
for row in iterations:
    artifact_refs.extend(str(item) for item in row.get("artifact_refs", []) if isinstance(item, str))
artifact_refs = sorted(set(artifact_refs))

report = {
    "schema_version": REPORT_SCHEMA,
    "bead": BEAD,
    "parent_bead": PARENT,
    "mode": mode,
    "status": status,
    "proof_status": proof_status,
    "run_id": run_id,
    "generated_at_utc": utc_now(),
    "source_commit": SOURCE_COMMIT,
    "manifest": rel(manifest_path),
    "duration_seconds_required": duration_seconds,
    "duration_seconds_observed": observed_duration,
    "contract_duration_seconds": contract_duration,
    "minimum_iterations": minimum_iterations,
    "iteration_count": len(iterations),
    "target_dir": str(target_root),
    "summary": summary,
    "iterations": iterations,
    "errors": errors,
    "failure_signatures": failure_signatures,
    "artifact_refs": artifact_refs,
    "required_log_fields": sorted(required_log_fields),
    "next_safe_action": manifest.get("next_safe_action"),
}

append_event(
    event="soak_summary",
    iteration=len(iterations),
    iteration_run_id=run_id,
    status=status,
    proof_status=proof_status,
    failure_signature="none" if status == "pass" else (failure_signatures[0] if failure_signatures else "ws8_soak_runner_failed"),
    artifact_refs=artifact_refs,
)

write_json(report_path, report)
write_jsonl(log_path, events)
print(json.dumps(report, indent=2, sort_keys=True))
raise SystemExit(0 if status == "pass" else 1)
PY
