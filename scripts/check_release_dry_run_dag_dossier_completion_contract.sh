#!/usr/bin/env bash
# check_release_dry_run_dag_dossier_completion_contract.sh - bd-w2c3.10.2.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RELEASE_DRY_RUN_COMPLETION_CONTRACT:-$ROOT/tests/conformance/release_dry_run_dag_dossier_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RELEASE_DRY_RUN_COMPLETION_OUT_DIR:-$ROOT/target/conformance/release_dry_run_dag_dossier_completion_contract}"
REPORT="${FRANKENLIBC_RELEASE_DRY_RUN_COMPLETION_REPORT:-$OUT_DIR/release_dry_run_dag_dossier_completion_contract.report.json}"
LOG="${FRANKENLIBC_RELEASE_DRY_RUN_COMPLETION_LOG:-$OUT_DIR/release_dry_run_dag_dossier_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "release_dry_run_dag_dossier_completion_contract.v1"
EXPECTED_MANIFEST = "bd-w2c3.10.2.1-release-dry-run-dag-dossier-completion-contract"
SOURCE_BEAD = "bd-w2c3.10.2"
COMPLETION_BEAD = "bd-w2c3.10.2.1"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
source_gate_results: dict[str, Any] = {}


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def load_jsonl(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"{label} is not readable: {rel(path)}: {exc}")
        return rows
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            err(f"{label} line {index} is not valid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            err(f"{label} line {index} must be an object")
            continue
        rows.append(row)
    return rows


def as_string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def artifact_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must be repo-relative without parent traversal: {path_text}")
        return None
    full = ROOT / path
    if not full.is_file():
        err(f"{context} references missing file: {path_text}")
        return None
    return full


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


SOURCE_COMMIT = source_commit()


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "source_bead": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "event": event,
            "status": status,
            "gate_count": details.get("gate_count", 0),
            "passed": details.get("passed", 0),
            "failed": details.get("failed", 0),
            "skipped": details.get("skipped", 0),
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "release_dry_run_dag_dossier_completion_failed",
            "details": details,
        }
    )


def check_file_line_ref(file_line_ref: str) -> None:
    if ":" not in file_line_ref:
        err(f"implementation ref missing line separator: {file_line_ref}")
        return
    path_text, line_text = file_line_ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        err(f"implementation ref has invalid line number: {file_line_ref}")
        return
    path = artifact_path(path_text, f"implementation_refs.{file_line_ref}")
    if path is None:
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no < 1 or line_no > len(lines) or not lines[line_no - 1].strip():
        err(f"implementation ref does not point to a non-empty line: {file_line_ref}")


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}(" in text or f"fn {name}<" in text or f"def {name}(" in text


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("source_artifacts", {})
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    out: dict[str, str] = {}
    for artifact_id, path_text in artifacts.items():
        artifact_path(path_text, f"source_artifacts.{artifact_id}")
        if isinstance(path_text, str):
            out[str(artifact_id)] = path_text
    return out


def validate_test_refs(manifest: dict[str, Any], artifacts: dict[str, str]) -> None:
    source_cache: dict[str, str] = {}
    bindings = manifest.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        err("missing_item_bindings must be a non-empty array")
        return
    found_items: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing_item_bindings entries must be objects")
            continue
        item_id = binding.get("id")
        if not isinstance(item_id, str):
            err("missing_item_bindings entry missing id")
            continue
        found_items.add(item_id)
        refs = binding.get("required_test_refs")
        if not isinstance(refs, list) or not refs:
            err(f"missing_item_bindings.{item_id}.required_test_refs must be non-empty")
            continue
        for index, ref_obj in enumerate(refs):
            if not isinstance(ref_obj, dict):
                err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] must be an object")
                continue
            source_id = ref_obj.get("source")
            name = ref_obj.get("name")
            if not isinstance(source_id, str) or source_id not in artifacts:
                err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] references unknown source {source_id!r}")
                continue
            if source_id not in source_cache:
                path = artifact_path(artifacts[source_id], f"test_source.{source_id}")
                source_cache[source_id] = path.read_text(encoding="utf-8") if path else ""
            if not isinstance(name, str) or not function_exists(source_cache[source_id], name):
                err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] missing test {source_id}::{name}")
        commands = as_string_list(binding.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands")
        if item_id == "tests.conformance.primary":
            for required in [
                "jq empty tests/conformance/release_dry_run_dag_dossier_completion_contract.v1.json",
                "bash -n scripts/check_release_dry_run_dag_dossier_completion_contract.sh",
                "bash scripts/check_release_dry_run_dag_dossier_completion_contract.sh",
            ]:
                if required not in commands:
                    err(f"tests.conformance.primary.required_commands missing {required!r}")
    missing_items = REQUIRED_MISSING_ITEMS - found_items
    extra_items = found_items - REQUIRED_MISSING_ITEMS
    if missing_items or extra_items:
        err(f"missing_item_bindings ids mismatch: missing={sorted(missing_items)} extra={sorted(extra_items)}")


def validate_dag(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest.get("release_dry_run_contract", {})
    if not isinstance(contract, dict):
        err("release_dry_run_contract must be an object")
        return {}
    dag_path = artifact_path(artifacts.get("release_gate_dag"), "source_artifacts.release_gate_dag")
    dag = load_json(dag_path, "release gate DAG") if dag_path else {}
    expected_sequence = as_string_list(contract.get("expected_gate_sequence"), "release_dry_run_contract.expected_gate_sequence")
    required_gate_fields = set(as_string_list(contract.get("required_gate_fields"), "release_dry_run_contract.required_gate_fields"))
    if dag.get("schema_version") != 1:
        err("release_gate_dag.schema_version must be 1")
    gates = dag.get("gates")
    if not isinstance(gates, list) or not gates:
        err("release_gate_dag.gates must be a non-empty array")
        gates = []
    gate_names: list[str] = []
    seen: set[str] = set()
    for index, gate in enumerate(gates):
        if not isinstance(gate, dict):
            err(f"release_gate_dag.gates[{index}] must be an object")
            continue
        missing_fields = required_gate_fields - set(gate)
        if missing_fields:
            err(f"release_gate_dag.gates[{index}] missing fields {sorted(missing_fields)}")
        name = gate.get("gate_name")
        if not isinstance(name, str) or not name:
            err(f"release_gate_dag.gates[{index}] missing gate_name")
            continue
        gate_names.append(name)
        deps = gate.get("depends_on")
        if not isinstance(deps, list):
            err(f"release_gate_dag.{name}.depends_on must be an array")
            deps = []
        for dep in deps:
            if dep not in seen:
                err(f"release_gate_dag.{name} dependency {dep!r} does not appear before gate")
        if gate.get("critical") is not True:
            err(f"release_gate_dag.{name}.critical must be true")
        seen.add(name)
    if gate_names != expected_sequence:
        err(f"release_gate_dag gate sequence mismatch: expected={expected_sequence} actual={gate_names}")
    expected_count = contract.get("expected_gate_count")
    if expected_count != len(gates):
        err(f"release_gate_dag expected_gate_count mismatch: expected={expected_count} actual={len(gates)}")
    append_event(
        "release_dry_run_manifest_verified",
        "pass" if not errors else "fail",
        [artifacts.get("release_gate_dag", "")],
        {"gate_count": len(gates), "gate_sequence": gate_names},
    )
    return {"contract": contract, "dag": dag, "gate_names": gate_names}


def run_command(name: str, args: list[str], env: dict[str, str] | None = None, expect_success: bool = True) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    proc = subprocess.run(
        args,
        cwd=ROOT,
        env=merged_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    source_gate_results[name] = {
        "args": args,
        "status": "pass" if proc.returncode == 0 else "fail",
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout.strip().splitlines()[-5:],
        "stderr_tail": proc.stderr.strip().splitlines()[-5:],
    }
    if expect_success and proc.returncode != 0:
        err(f"{name} failed with exit {proc.returncode}: stdout={proc.stdout[-800:]} stderr={proc.stderr[-800:]}")
    if not expect_success and proc.returncode == 0:
        err(f"{name} was expected to fail but passed")
    return proc


def validate_dossier(path: pathlib.Path, contract: dict[str, Any], expected_status: str = "pass") -> dict[str, Any]:
    dossier = load_json(path, f"{expected_status} release dry-run dossier")
    required_fields = set(as_string_list(contract.get("required_dossier_fields"), "release_dry_run_contract.required_dossier_fields"))
    required_summary_fields = set(as_string_list(contract.get("required_dossier_summary_fields"), "release_dry_run_contract.required_dossier_summary_fields"))
    missing = required_fields - set(dossier)
    if missing:
        err(f"{expected_status} dossier missing fields {sorted(missing)}")
    if dossier.get("schema_version") != 2:
        err(f"{expected_status} dossier schema_version must be 2")
    if dossier.get("bead") != SOURCE_BEAD:
        err(f"{expected_status} dossier bead must be {SOURCE_BEAD}")
    if dossier.get("mode") != "dry-run":
        err(f"{expected_status} dossier mode must be dry-run")
    summary = dossier.get("summary")
    if not isinstance(summary, dict):
        err(f"{expected_status} dossier.summary must be an object")
        summary = {}
    missing_summary = required_summary_fields - set(summary)
    if missing_summary:
        err(f"{expected_status} dossier.summary missing fields {sorted(missing_summary)}")
    if expected_status == "pass":
        if summary.get("verdict") != "PASS":
            err("success dossier verdict must be PASS")
        if summary.get("failed") != 0:
            err("success dossier failed count must be 0")
        if summary.get("total") != summary.get("passed") + summary.get("skipped", 0):
            err("success dossier total must equal passed + skipped")
    return dossier


def validate_log_rows(path: pathlib.Path, contract: dict[str, Any], expected_gate_count: int, expected_sequence: list[str]) -> list[dict[str, Any]]:
    rows = load_jsonl(path, "release dry-run JSONL log")
    required_log_fields = set(as_string_list(contract.get("required_log_fields"), "release_dry_run_contract.required_log_fields"))
    if len(rows) != expected_gate_count:
        err(f"release dry-run log row count mismatch: expected={expected_gate_count} actual={len(rows)}")
    row_names: list[str] = []
    for index, row in enumerate(rows):
        missing = required_log_fields - set(row)
        if missing:
            err(f"release dry-run log row {index + 1} missing fields {sorted(missing)}")
        name = row.get("gate_name")
        if isinstance(name, str):
            row_names.append(name)
        if row.get("critical") is not True:
            err(f"release dry-run log row {index + 1} critical must be true")
    if row_names != expected_sequence:
        err(f"release dry-run log gate sequence mismatch: expected={expected_sequence} actual={row_names}")
    return rows


def validate_success_state(path: pathlib.Path, contract: dict[str, Any]) -> dict[str, Any]:
    state = load_json(path, "release dry-run success state")
    required_state_fields = set(as_string_list(contract.get("required_state_fields"), "release_dry_run_contract.required_state_fields"))
    missing = required_state_fields - set(state)
    if missing:
        err(f"release dry-run success state missing fields {sorted(missing)}")
    if state.get("status") != "success":
        err("release dry-run success state status must be success")
    if state.get("resume_token") != "":
        err("release dry-run success state resume_token must be empty")
    return state


def replay_release_dry_run(manifest_state: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest_state.get("contract", {})
    expected_sequence = manifest_state.get("gate_names", [])
    expected_gate_count = contract.get("expected_gate_count", 0)
    runner = ROOT / artifacts["release_dry_run_runner"]

    pass_dossier = OUT_DIR / "generated.release_dry_run.dossier.json"
    pass_state = OUT_DIR / "generated.release_dry_run.state.json"
    pass_log = OUT_DIR / "generated.release_dry_run.log.jsonl"
    run_command(
        "release_dry_run_direct",
        [
            "bash",
            str(runner),
            "--mode",
            "dry-run",
            "--trace-id",
            f"{COMPLETION_BEAD}:direct-pass",
            "--dossier-path",
            str(pass_dossier),
            "--state-path",
            str(pass_state),
            "--log-path",
            str(pass_log),
        ],
    )
    dossier = validate_dossier(pass_dossier, contract, "pass")
    state = validate_success_state(pass_state, contract)
    rows = validate_log_rows(pass_log, contract, expected_gate_count, expected_sequence)
    summary = dossier.get("summary", {}) if isinstance(dossier.get("summary"), dict) else {}
    append_event(
        "release_dry_run_dossier_replayed",
        "pass" if not errors else "fail",
        [rel(pass_dossier), rel(pass_state), rel(pass_log)],
        {
            "gate_count": dossier.get("gate_count", 0),
            "passed": summary.get("passed", 0),
            "failed": summary.get("failed", 0),
            "skipped": summary.get("skipped", 0),
            "state_status": state.get("status"),
            "log_rows": len(rows),
        },
    )
    return {"dossier": dossier, "state": state, "rows": rows, "paths": {"dossier": pass_dossier, "state": pass_state, "log": pass_log}}


def replay_fail_fast_resume(manifest_state: dict[str, Any], artifacts: dict[str, str]) -> None:
    contract = manifest_state.get("contract", {})
    expected_sequence = manifest_state.get("gate_names", [])
    expected_gate_count = contract.get("expected_gate_count", 0)
    fail_gate = contract.get("fail_fast_gate")
    runner = ROOT / artifacts["release_dry_run_runner"]

    fail_dossier = OUT_DIR / "generated.release_dry_run.fail.dossier.json"
    fail_state = OUT_DIR / "generated.release_dry_run.fail.state.json"
    fail_log = OUT_DIR / "generated.release_dry_run.fail.log.jsonl"
    run_command(
        "release_dry_run_fail_fast",
        [
            "bash",
            str(runner),
            "--mode",
            "dry-run",
            "--trace-id",
            f"{COMPLETION_BEAD}:fail-fast",
            "--dossier-path",
            str(fail_dossier),
            "--state-path",
            str(fail_state),
            "--log-path",
            str(fail_log),
        ],
        env={"FRANKENLIBC_RELEASE_SIMULATE_FAIL_GATE": str(fail_gate)},
        expect_success=False,
    )
    fail_state_json = load_json(fail_state, "release dry-run fail-fast state")
    token = fail_state_json.get("resume_token")
    if not isinstance(token, str) or not token.startswith(str(contract.get("resume_token_prefix", "v1:"))):
        err("fail-fast state must emit a v1 resume token")
    if fail_state_json.get("failed_gate") != fail_gate:
        err(f"fail-fast state failed_gate must be {fail_gate}")
    fail_rows = load_jsonl(fail_log, "release dry-run fail-fast log")
    if not fail_rows or fail_rows[-1].get("status") != "fail":
        err("fail-fast log must end with a fail row")

    resume_dossier = OUT_DIR / "generated.release_dry_run.resume.dossier.json"
    resume_state = OUT_DIR / "generated.release_dry_run.resume.state.json"
    resume_log = OUT_DIR / "generated.release_dry_run.resume.log.jsonl"
    if isinstance(token, str):
        run_command(
            "release_dry_run_resume",
            [
                "bash",
                str(runner),
                "--mode",
                "dry-run",
                "--resume-token",
                token,
                "--trace-id",
                f"{COMPLETION_BEAD}:resume",
                "--dossier-path",
                str(resume_dossier),
                "--state-path",
                str(resume_state),
                "--log-path",
                str(resume_log),
            ],
        )
        resume_dossier_json = validate_dossier(resume_dossier, contract, "resume")
        resume_rows = validate_log_rows(resume_log, contract, expected_gate_count, expected_sequence)
        fail_index = expected_sequence.index(fail_gate) if fail_gate in expected_sequence else -1
        for row in resume_rows[:fail_index]:
            if row.get("status") != contract.get("expected_resume_skipped_status"):
                err("resume rows before failed gate must be resume_skip")
        if fail_index >= 0 and resume_rows[fail_index].get("status") != "pass":
            err("resume row at failed gate must pass after clearing failure env")
        resume_summary = resume_dossier_json.get("summary", {}) if isinstance(resume_dossier_json.get("summary"), dict) else {}
        append_event(
            "release_dry_run_fail_fast_resume_verified",
            "pass" if not errors else "fail",
            [rel(fail_state), rel(fail_log), rel(resume_dossier), rel(resume_state), rel(resume_log)],
            {
                "gate_count": resume_dossier_json.get("gate_count", 0),
                "passed": resume_summary.get("passed", 0),
                "failed": resume_summary.get("failed", 0),
                "skipped": resume_summary.get("skipped", 0),
                "failed_gate": fail_gate,
                "resume_token_prefix": token.split(":")[0] if isinstance(token, str) else "",
            },
        )


def replay_source_checker(artifacts: dict[str, str]) -> None:
    checker = ROOT / artifacts["release_dry_run_checker"]
    checker_dossier = OUT_DIR / "generated.source_checker.dossier.json"
    run_command(
        "release_dry_run_source_checker",
        ["bash", str(checker), str(checker_dossier)],
        env={"FRANKENLIBC_TMPDIR": str(OUT_DIR)},
    )
    dossier = load_json(checker_dossier, "source checker dossier")
    summary = dossier.get("summary", {}) if isinstance(dossier.get("summary"), dict) else {}
    if summary.get("verdict") != "PASS":
        err("source checker dossier verdict must be PASS")
    append_event(
        "release_dry_run_source_checker_replayed",
        "pass" if not errors else "fail",
        [rel(checker_dossier), artifacts["release_dry_run_checker"]],
        {
            "gate_count": dossier.get("gate_count", 0),
            "passed": summary.get("passed", 0),
            "failed": summary.get("failed", 0),
            "skipped": summary.get("skipped", 0),
        },
    )


def validate_telemetry_contract(manifest: dict[str, Any], status: str) -> None:
    telemetry = manifest.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
    if status == "pass":
        actual_events = {event.get("event") for event in events}
        missing = required_events - actual_events
        if missing:
            err(f"telemetry_contract.required_events missing emitted events {sorted(missing)}")
    required_log_fields = set(as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    for index, event in enumerate(events):
        missing_fields = required_log_fields - set(event)
        if missing_fields:
            err(f"telemetry event {index + 1} missing fields {sorted(missing_fields)}")


def write_outputs(manifest: dict[str, Any], status: str, completion_summary: dict[str, Any], generated: dict[str, Any]) -> None:
    telemetry = manifest.get("telemetry_contract", {}) if isinstance(manifest.get("telemetry_contract"), dict) else {}
    report = {
        "schema_version": "release_dry_run_dag_dossier_completion_contract.report.v1",
        "manifest_id": EXPECTED_MANIFEST,
        "source_bead": SOURCE_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "source_commit": SOURCE_COMMIT,
        "completion_summary": completion_summary,
        "generated_dossier": generated.get("dossier", {}),
        "generated_state": generated.get("state", {}),
        "source_gate_results": source_gate_results,
        "events": events,
        "errors": errors,
    }
    required_report_fields = set(as_string_list(telemetry.get("required_report_fields", []), "telemetry_contract.required_report_fields", allow_empty=True))
    missing_report_fields = required_report_fields - set(report)
    if missing_report_fields:
        report["errors"].append(f"report missing required fields {sorted(missing_report_fields)}")
        report["status"] = "fail"
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with LOG.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True))
            handle.write("\n")


def main() -> int:
    manifest = load_json(CONTRACT, "completion contract")
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        err(f"schema_version must be {EXPECTED_SCHEMA}")
    if manifest.get("manifest_id") != EXPECTED_MANIFEST:
        err(f"manifest_id must be {EXPECTED_MANIFEST}")
    if manifest.get("original_bead") != SOURCE_BEAD:
        err(f"original_bead must be {SOURCE_BEAD}")
    if manifest.get("completion_debt_bead") != COMPLETION_BEAD:
        err(f"completion_debt_bead must be {COMPLETION_BEAD}")
    if manifest.get("next_audit_score_threshold", 0) < 800:
        err("next_audit_score_threshold must be at least 800")

    artifacts = validate_source_artifacts(manifest)
    for ref in as_string_list(manifest.get("implementation_refs"), "implementation_refs"):
        check_file_line_ref(ref)
    validate_test_refs(manifest, artifacts)

    manifest_state = validate_dag(manifest, artifacts)
    generated = replay_release_dry_run(manifest_state, artifacts) if artifacts else {}
    if artifacts:
        replay_fail_fast_resume(manifest_state, artifacts)
        replay_source_checker(artifacts)

    summary = {}
    if isinstance(generated, dict) and isinstance(generated.get("dossier"), dict):
        dossier_summary = generated["dossier"].get("summary", {})
        summary = {
            "gate_count": generated["dossier"].get("gate_count", 0),
            "passed": dossier_summary.get("passed", 0) if isinstance(dossier_summary, dict) else 0,
            "failed": dossier_summary.get("failed", 0) if isinstance(dossier_summary, dict) else 0,
            "skipped": dossier_summary.get("skipped", 0) if isinstance(dossier_summary, dict) else 0,
        }
    status = "fail" if errors else "pass"
    append_event(
        "release_dry_run_completion_contract_pass" if status == "pass" else "release_dry_run_completion_contract_fail",
        status,
        [rel(CONTRACT), rel(REPORT), rel(LOG)],
        summary,
    )
    validate_telemetry_contract(manifest, status)
    status = "fail" if errors else "pass"
    write_outputs(manifest, status, summary, generated if isinstance(generated, dict) else {})

    if errors:
        print(f"FAIL: release dry-run completion contract found {len(errors)} error(s)")
        for message in errors:
            print(f"  - {message}")
        print(f"Report: {REPORT}")
        print(f"Log: {LOG}")
        return 1

    print(
        "PASS: release dry-run DAG/dossier completion contract validated "
        f"(gate_count={summary.get('gate_count', 0)} passed={summary.get('passed', 0)})"
    )
    print(f"Report: {REPORT}")
    print(f"Log: {LOG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
