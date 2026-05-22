#!/usr/bin/env bash
# check_ws9_e2e_anti_recurrence.sh -- bd-iu3fb.5 WS9 end-to-end anti-recurrence gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_WS9_E2E_CONTRACT:-$ROOT/tests/conformance/ws9_e2e_anti_recurrence_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_WS9_E2E_OUT_DIR:-$ROOT/target/conformance/ws9_e2e_anti_recurrence}"
REPORT="${FRANKENLIBC_WS9_E2E_REPORT:-$OUT_DIR/ws9_e2e_anti_recurrence.report.json}"
LOG="${FRANKENLIBC_WS9_E2E_LOG:-$OUT_DIR/ws9_e2e_anti_recurrence.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" OUT_DIR="$OUT_DIR" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import shutil
import stat
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"]).resolve()
CONTRACT = pathlib.Path(os.environ["CONTRACT"]).resolve()
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"]).resolve()
REPORT = pathlib.Path(os.environ["REPORT"]).resolve()
LOG = pathlib.Path(os.environ["LOG"]).resolve()

EXPECTED_SCHEMA = "ws9_e2e_anti_recurrence_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "ws9_e2e_anti_recurrence.report.v1"
BEAD_ID = "bd-iu3fb.5"
PARENT_BEAD = "bd-iu3fb"

REQUIRED_SCENARIOS = {
    "faked_closure_rejected",
    "queue_empty_triggers_reality_check",
    "unmet_milestone_blocks_closure",
    "ws9_child_companion_tests_pass",
}
REQUIRED_EVENTS = {
    "ws9_contract_validated",
    "ws9_faked_closure_rejected",
    "ws9_queue_empty_trigger_fired",
    "ws9_unmet_milestone_blocked",
    "ws9_child_companion_tests_pass",
    "ws9_e2e_complete",
}
REQUIRED_SOURCE_IDS = {
    "bead_closure_freshness_script",
    "bead_closure_freshness_policy",
    "proof_carrying_completion_contract",
    "queue_empty_trigger_script",
    "queue_empty_trigger_completion_contract",
    "milestone_closure_script",
    "milestone_vision_goals",
    "ws9_e2e_script",
    "ws9_e2e_contract",
    "ws9_e2e_test",
}

events: list[dict[str, Any]] = []
errors: list[str] = []
scenario_results: list[dict[str, Any]] = []


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except Exception:
        return path.as_posix()


def append_event(
    event: str,
    status: str,
    scenario: str,
    *,
    command: str | None = None,
    exit_code: int | None = None,
    artifact_refs: list[str] | None = None,
    failure_signature: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    events.append(
        {
            "timestamp": now_utc(),
            "trace_id": f"{BEAD_ID}:ws9-e2e",
            "event": event,
            "bead_id": BEAD_ID,
            "parent_bead": PARENT_BEAD,
            "status": status,
            "scenario": scenario,
            "command": command or "",
            "exit_code": exit_code,
            "artifact_refs": artifact_refs or [],
            "failure_signature": failure_signature or ("none" if status == "pass" else "ws9_e2e_failure"),
            "details": details or {},
        }
    )


def write_outputs(status: str) -> None:
    if status != "pass" and not any(event["event"] == "ws9_e2e_complete" for event in events):
        append_event(
            "ws9_e2e_complete",
            "fail",
            "overall",
            artifact_refs=[rel(CONTRACT), rel(REPORT), rel(LOG)],
            failure_signature="ws9_e2e_incomplete",
            details={"error_count": len(errors)},
        )
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "bead_id": BEAD_ID,
        "parent_bead": PARENT_BEAD,
        "status": status,
        "generated_at_utc": now_utc(),
        "source_commit": git_head(),
        "contract": rel(CONTRACT),
        "scenario_results": scenario_results,
        "events": events,
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}


def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def repo_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        errors.append(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"{context} must stay repo-relative: {path_text}")
        return None
    full = (ROOT / path).resolve()
    if full != ROOT and ROOT not in full.parents:
        errors.append(f"{context} escapes repo root: {path_text}")
        return None
    if not full.exists():
        errors.append(f"{context} references missing path: {path_text}")
        return None
    return full


def read_contract() -> dict[str, Any]:
    manifest = load_json(CONTRACT, "WS9 e2e contract")
    if not isinstance(manifest, dict):
        errors.append("WS9 e2e contract must be a JSON object")
        return {}

    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
    require(manifest.get("bead_id") == BEAD_ID, "bead_id mismatch")
    require(manifest.get("parent_bead") == PARENT_BEAD, "parent_bead mismatch")

    sources = manifest.get("source_artifacts")
    if not isinstance(sources, dict):
        errors.append("source_artifacts must be an object")
        sources = {}
    else:
        require(REQUIRED_SOURCE_IDS <= set(sources), f"source_artifacts missing {sorted(REQUIRED_SOURCE_IDS - set(sources))}")
        for source_id, source_spec in sources.items():
            if not isinstance(source_spec, dict):
                errors.append(f"source_artifacts.{source_id} must be an object")
                continue
            path = repo_path(source_spec.get("path"), f"source_artifacts.{source_id}.path")
            if path is None:
                continue
            for needle in source_spec.get("required_text", []):
                if not isinstance(needle, str) or not needle:
                    errors.append(f"source_artifacts.{source_id}.required_text entries must be non-empty strings")
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except Exception as exc:
                    errors.append(f"source_artifacts.{source_id} is unreadable: {exc}")
                    continue
                if needle not in text:
                    errors.append(f"source_artifacts.{source_id} missing required text {needle!r}")

    scenario_ids = {
        item.get("id")
        for item in manifest.get("required_scenarios", [])
        if isinstance(item, dict)
    }
    require(scenario_ids == REQUIRED_SCENARIOS, f"required_scenarios mismatch: {sorted(str(item) for item in scenario_ids)}")

    event_ids = set(manifest.get("required_events", [])) if isinstance(manifest.get("required_events"), list) else set()
    require(REQUIRED_EVENTS <= event_ids, f"required_events missing {sorted(REQUIRED_EVENTS - event_ids)}")

    companion_tests = manifest.get("companion_unit_tests")
    if not isinstance(companion_tests, list) or not companion_tests:
        errors.append("companion_unit_tests must be a non-empty array")
    else:
        bead_ids = {item.get("bead_id") for item in companion_tests if isinstance(item, dict)}
        require({"bd-iu3fb.1", "bd-iu3fb.2", "bd-iu3fb.3", "bd-iu3fb.5"} <= bead_ids, "companion_unit_tests missing WS9 bead coverage")
        for index, item in enumerate(companion_tests):
            if not isinstance(item, dict):
                errors.append(f"companion_unit_tests[{index}] must be an object")
                continue
            command = item.get("command")
            if not isinstance(command, str) or not command:
                errors.append(f"companion_unit_tests[{index}].command must be a non-empty string")

    for command in manifest.get("validation_commands", []):
        if not isinstance(command, str):
            errors.append("validation_commands entries must be strings")
            continue
        if "cargo " in command and "rch exec -- cargo " not in command:
            errors.append(f"cargo validation command must use rch: {command}")

    append_event(
        "ws9_contract_validated",
        "pass" if not errors else "fail",
        "contract",
        artifact_refs=[rel(CONTRACT)],
        details={
            "source_count": len(sources) if isinstance(sources, dict) else 0,
            "scenario_count": len(scenario_ids),
            "event_count": len(event_ids),
        },
    )
    return manifest


def run_command(
    command: list[str] | str,
    *,
    env: dict[str, str] | None = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=merged_env,
        shell=isinstance(command, str),
        check=False,
    )


def record_scenario(
    scenario: str,
    status: str,
    *,
    command: str,
    exit_code: int,
    artifact_refs: list[str],
    details: dict[str, Any] | None = None,
) -> None:
    scenario_results.append(
        {
            "id": scenario,
            "status": status,
            "command": command,
            "exit_code": exit_code,
            "artifact_refs": artifact_refs,
            "details": details or {},
        }
    )


def scenario_faked_closure_rejected() -> None:
    scenario = "faked_closure_rejected"
    scenario_dir = OUT_DIR / scenario
    scenario_dir.mkdir(parents=True, exist_ok=True)
    beads = scenario_dir / "issues.jsonl"
    policy = scenario_dir / "policy.json"
    ledger = scenario_dir / "evidence_ledger.jsonl"
    contract = scenario_dir / "fake_unverifiable_completion_contract.v1.json"
    contract_rel = rel(contract)
    report = scenario_dir / "bead_closure_freshness.report.json"
    good_hash = "a" * 64
    fake_hash = "b" * 64

    policy.write_text(
        json.dumps(
            {
                "schema_version": "bead_closure_freshness_policy.v1",
                "effective_after_utc": "2026-05-21T08:00:00Z",
                "enforce_reality_check_after_effective": True,
                "enforced_labels": ["reality-check"],
                "enforced_bead_ids": ["bd-ws9-faked"],
                "required_freshness_state_fields": [
                    "generated_at_utc",
                    "source_commit",
                    "generator_command",
                    "tool_version",
                    "chain_hash",
                ],
                "window_start_sources": ["artifact.bead_status_window.in_progress_at_utc", "bead.updated_at"],
                "require_ledger_chain_hash": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    beads.write_text(
        json.dumps(
            {
                "id": "bd-ws9-faked",
                "status": "closed",
                "labels": ["reality-check"],
                "created_at": "2026-05-22T03:00:00Z",
                "updated_at": "2026-05-22T03:10:00Z",
                "closed_at": "2026-05-22T03:30:00Z",
                "close_reason": f"completion_artifact: {contract_rel}",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    contract.write_text(
        json.dumps(
            {
                "schema_version": "completion_contract.v1",
                "bead_id": "bd-ws9-faked",
                "freshness_state": {
                    "generated_at_utc": "2026-05-22T03:20:00Z",
                    "source_commit": "1111111111111111111111111111111111111111",
                    "generator_command": "synthetic faked closure",
                    "tool_version": "ws9-e2e",
                    "chain_hash": fake_hash,
                },
                "bead_status_window": {
                    "in_progress_at_utc": "2026-05-22T03:10:00Z",
                    "closed_at_utc": "2026-05-22T03:30:00Z",
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    ledger.write_text(json.dumps({"chain_hash": good_hash}, sort_keys=True) + "\n", encoding="utf-8")

    command = "bash scripts/check_bead_closure_freshness.sh"
    proc = run_command(
        ["bash", "scripts/check_bead_closure_freshness.sh"],
        env={
            "FRANKENLIBC_BEAD_CLOSURE_POLICY": str(policy),
            "FRANKENLIBC_BEADS_JSONL": str(beads),
            "FRANKENLIBC_EVIDENCE_LEDGER": str(ledger),
            "FRANKENLIBC_BEAD_CLOSURE_REPORT": str(report),
        },
    )
    report_doc = load_json(report, "faked closure report") if report.exists() else {}
    signatures = {
        error.get("failure_signature")
        for error in report_doc.get("errors", [])
        if isinstance(error, dict)
    }
    passed = proc.returncode == 1 and "bead_closure_chain_hash_missing" in signatures
    if not passed:
        errors.append(f"{scenario} failed: exit={proc.returncode} signatures={sorted(str(item) for item in signatures)}")
    record_scenario(
        scenario,
        "pass" if passed else "fail",
        command=command,
        exit_code=proc.returncode,
        artifact_refs=[rel(beads), rel(policy), rel(ledger), rel(contract), rel(report)],
        details={"failure_signatures": sorted(str(item) for item in signatures)},
    )
    append_event(
        "ws9_faked_closure_rejected",
        "pass" if passed else "fail",
        scenario,
        command=command,
        exit_code=proc.returncode,
        artifact_refs=[rel(report), rel(contract)],
        failure_signature="none" if passed else "ws9_fake_closure_not_rejected",
        details={"failure_signatures": sorted(str(item) for item in signatures)},
    )


def write_fake_br(fake_bin: pathlib.Path) -> pathlib.Path:
    fake_bin.mkdir(parents=True, exist_ok=True)
    fake_br = fake_bin / "br"
    fake_br.write_text(
        """#!/usr/bin/env bash
case " $* " in
  *" ready --json "*)
    printf '[]\\n'
    exit 0
    ;;
  *" list --status open --json "*)
    printf '[]\\n'
    exit 0
    ;;
  *)
    printf 'unexpected fake br invocation: %s\\n' "$*" >&2
    exit 1
    ;;
esac
""",
        encoding="utf-8",
    )
    fake_br.chmod(fake_br.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return fake_br


def scenario_queue_empty_triggers_reality_check() -> None:
    scenario = "queue_empty_triggers_reality_check"
    scenario_dir = OUT_DIR / scenario
    scenario_dir.mkdir(parents=True, exist_ok=True)
    fake_bin = scenario_dir / "bin"
    write_fake_br(fake_bin)
    report = scenario_dir / "queue_empty_reality_trigger.report.json"
    command = "bash scripts/check_queue_empty_reality_trigger.sh --trigger-only --json"
    proc = run_command(
        ["bash", "scripts/check_queue_empty_reality_trigger.sh", "--trigger-only", "--json"],
        env={
            "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "FRANKENLIBC_QUEUE_TRIGGER_REPORT": str(report),
            "FRANKENLIBC_QUEUE_TRIGGER_TRACE_ID": f"{BEAD_ID}:queue-empty-synthetic",
        },
    )
    report_doc = load_json(report, "queue-empty trigger report") if report.exists() else {}
    passed = (
        proc.returncode == 2
        and report_doc.get("trigger_condition") == "queue_empty"
        and report_doc.get("outcome") == "trigger_condition_met"
        and report_doc.get("trigger_only_mode") is True
    )
    if not passed:
        errors.append(f"{scenario} failed: exit={proc.returncode} report_outcome={report_doc.get('outcome')!r}")
    record_scenario(
        scenario,
        "pass" if passed else "fail",
        command=command,
        exit_code=proc.returncode,
        artifact_refs=[rel(report), rel(fake_bin / "br")],
        details={
            "trigger_condition": report_doc.get("trigger_condition"),
            "outcome": report_doc.get("outcome"),
            "ready_count": report_doc.get("ready_count"),
            "open_count": report_doc.get("open_count"),
        },
    )
    append_event(
        "ws9_queue_empty_trigger_fired",
        "pass" if passed else "fail",
        scenario,
        command=command,
        exit_code=proc.returncode,
        artifact_refs=[rel(report)],
        failure_signature="none" if passed else "ws9_queue_empty_trigger_missing",
        details={
            "trigger_condition": report_doc.get("trigger_condition"),
            "outcome": report_doc.get("outcome"),
            "ready_count": report_doc.get("ready_count"),
            "open_count": report_doc.get("open_count"),
        },
    )


def scenario_unmet_milestone_blocks_closure() -> None:
    scenario = "unmet_milestone_blocks_closure"
    scenario_dir = OUT_DIR / scenario
    scenario_dir.mkdir(parents=True, exist_ok=True)
    report = scenario_dir / "milestone_closure.report.json"
    command = "bash scripts/check_milestone_closure.sh test-unmet-required"
    proc = run_command(
        ["bash", "scripts/check_milestone_closure.sh", "test-unmet-required"],
        env={"FRANKENLIBC_MILESTONE_REPORT": str(report)},
    )
    report_doc = load_json(report, "milestone closure report") if report.exists() else {}
    e_process = report_doc.get("e_process", {}) if isinstance(report_doc, dict) else {}
    passed = (
        proc.returncode == 1
        and report_doc.get("closure_allowed") is False
        and e_process.get("all_required_met") is False
    )
    if not passed:
        errors.append(
            f"{scenario} failed: exit={proc.returncode} closure_allowed={report_doc.get('closure_allowed')!r}"
        )
    record_scenario(
        scenario,
        "pass" if passed else "fail",
        command=command,
        exit_code=proc.returncode,
        artifact_refs=[rel(report), "tests/conformance/milestone_vision_goals.v1.json"],
        details={
            "closure_allowed": report_doc.get("closure_allowed"),
            "all_required_met": e_process.get("all_required_met"),
            "e_value": e_process.get("e_value"),
        },
    )
    append_event(
        "ws9_unmet_milestone_blocked",
        "pass" if passed else "fail",
        scenario,
        command=command,
        exit_code=proc.returncode,
        artifact_refs=[rel(report)],
        failure_signature="none" if passed else "ws9_unmet_milestone_allowed",
        details={
            "closure_allowed": report_doc.get("closure_allowed"),
            "all_required_met": e_process.get("all_required_met"),
            "e_value": e_process.get("e_value"),
        },
    )


def scenario_child_companion_tests_pass(manifest: dict[str, Any]) -> None:
    scenario = "ws9_child_companion_tests_pass"
    companion_tests = manifest.get("companion_unit_tests", [])
    all_passed = True
    details: list[dict[str, Any]] = []
    for item in companion_tests:
        if not isinstance(item, dict):
            all_passed = False
            continue
        command = item.get("command", "")
        extra_env: dict[str, str] = {}
        artifact_refs: list[str] = [rel(CONTRACT)]
        if item.get("bead_id") == "bd-iu3fb.2":
            fake_bin = OUT_DIR / scenario / "companion_bd_iu3fb_2_bin"
            write_fake_br(fake_bin)
            extra_env["PATH"] = f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"
            artifact_refs.append(rel(fake_bin / "br"))
        proc = run_command(command, env=extra_env, timeout=300)
        passed = proc.returncode == 0
        if not passed:
            all_passed = False
        details.append(
            {
                "bead_id": item.get("bead_id"),
                "name": item.get("name"),
                "command": command,
                "exit_code": proc.returncode,
                "status": "pass" if passed else "fail",
            }
        )
    if not all_passed:
        errors.append(f"{scenario} failed: at least one WS9 companion test failed")
    record_scenario(
        scenario,
        "pass" if all_passed else "fail",
        command="; ".join(str(item.get("command", "")) for item in companion_tests if isinstance(item, dict)),
        exit_code=0 if all_passed else 1,
        artifact_refs=[rel(CONTRACT)],
        details={"companion_tests": details},
    )
    append_event(
        "ws9_child_companion_tests_pass",
        "pass" if all_passed else "fail",
        scenario,
        command="companion_unit_tests",
        exit_code=0 if all_passed else 1,
        artifact_refs=[rel(CONTRACT)],
        failure_signature="none" if all_passed else "ws9_companion_unit_test_failed",
        details={"companion_tests": details},
    )


def main() -> int:
    manifest = read_contract()
    if errors:
        write_outputs("fail")
        print(f"FAIL ws9 e2e anti-recurrence contract validation errors={len(errors)}")
        return 1

    scenario_faked_closure_rejected()
    scenario_queue_empty_triggers_reality_check()
    scenario_unmet_milestone_blocks_closure()
    scenario_child_companion_tests_pass(manifest)

    status = "fail" if errors else "pass"
    append_event(
        "ws9_e2e_complete",
        status,
        "overall",
        artifact_refs=[rel(REPORT), rel(LOG)],
        failure_signature="none" if status == "pass" else "ws9_e2e_failure",
        details={"scenario_count": len(scenario_results), "error_count": len(errors)},
    )
    write_outputs(status)
    if errors:
        print(f"FAIL ws9 e2e anti-recurrence errors={len(errors)} report={rel(REPORT)}")
        return 1
    print(f"PASS ws9 e2e anti-recurrence scenarios={len(scenario_results)} report={rel(REPORT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
