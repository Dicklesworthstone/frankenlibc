#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FULL_RELEASE_REHEARSAL_COMPLETION_CONTRACT:-$ROOT/tests/release/full_release_rehearsal_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_FULL_RELEASE_REHEARSAL_COMPLETION_OUT_DIR:-$ROOT/target/release/full_release_rehearsal_completion_contract}"
REPORT="${FRANKENLIBC_FULL_RELEASE_REHEARSAL_COMPLETION_REPORT:-$OUT_DIR/full_release_rehearsal_completion_contract.report.json}"
LOG="${FRANKENLIBC_FULL_RELEASE_REHEARSAL_COMPLETION_LOG:-$OUT_DIR/full_release_rehearsal_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "full_release_rehearsal_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "full_release_rehearsal_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-226.1-full-release-rehearsal-completion-contract"
SOURCE_BEAD = "bd-226"
COMPLETION_BEAD = "bd-226.1"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
command_results: dict[str, Any] = {}


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


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
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"{label} is not readable: {rel(path)}: {exc}")
        return []

    rows: list[dict[str, Any]] = []
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


def repo_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must be repo-relative without parent traversal: {path_text}")
        return None
    full = ROOT / path
    if not full.exists():
        err(f"{context} references missing path: {path_text}")
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


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any] | None = None) -> None:
    events.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "source_bead": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "full_release_rehearsal_completion_failed",
            "details": details or {},
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
    path = repo_path(path_text, f"implementation_refs.{file_line_ref}")
    if path is None or not path.is_file():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        err(f"implementation ref path is not UTF-8 text: {file_line_ref}")
        return
    if line_no < 1 or line_no > len(lines) or not lines[line_no - 1].strip():
        err(f"implementation ref does not point to a non-empty line: {file_line_ref}")


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}(" in text or f"fn {name}<" in text or f"def {name}(" in text


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    found: dict[str, str] = {}
    for artifact_id, path_text in artifacts.items():
        path = repo_path(path_text, f"source_artifacts.{artifact_id}")
        if path is not None and isinstance(path_text, str):
            found[str(artifact_id)] = path_text
    return found


def validate_bindings(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    bindings = manifest.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        err("missing_item_bindings must be a non-empty array")
        return {"binding_count": 0, "test_refs": 0}

    source_cache: dict[str, str] = {}
    found_items: set[str] = set()
    test_ref_count = 0
    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing_item_bindings entries must be objects")
            continue
        item_id = binding.get("id")
        if not isinstance(item_id, str) or not item_id:
            err("missing_item_bindings entry missing id")
            continue
        found_items.add(item_id)
        commands = as_string_list(binding.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands")
        refs = binding.get("required_test_refs")
        if not isinstance(refs, list) or not refs:
            err(f"missing_item_bindings.{item_id}.required_test_refs must be non-empty")
            refs = []
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
                source_path = repo_path(artifacts[source_id], f"test_source.{source_id}")
                source_cache[source_id] = source_path.read_text(encoding="utf-8") if source_path and source_path.is_file() else ""
            if not isinstance(name, str) or not function_exists(source_cache[source_id], name):
                err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] missing test {source_id}::{name}")
            else:
                test_ref_count += 1

        if item_id == "tests.unit.primary":
            require(any("release_dag_schema_valid" in command for command in commands), "unit binding must cite release DAG schema test")
            require(any("full_release_rehearsal_completion_contract_test" in command for command in commands), "unit binding must cite completion harness test")
        if item_id == "tests.e2e.primary":
            require(any("check_release_dry_run.sh" in command for command in commands), "e2e binding must cite release dry-run checker")
            require(any("check_full_release_rehearsal_completion_contract.sh" in command for command in commands), "e2e binding must cite completion checker")
        if item_id == "tests.conformance.primary":
            for required in [
                "jq empty tests/release/full_release_rehearsal_completion_contract.v1.json",
                "bash -n scripts/check_full_release_rehearsal_completion_contract.sh",
                "bash scripts/check_replacement_levels.sh",
                "bash scripts/check_full_release_rehearsal_completion_contract.sh",
            ]:
                require(required in commands, f"conformance binding missing required command {required!r}")

    missing = REQUIRED_MISSING_ITEMS - found_items
    extra = found_items - REQUIRED_MISSING_ITEMS
    if missing or extra:
        err(f"missing_item_bindings ids mismatch: missing={sorted(missing)} extra={sorted(extra)}")
    return {"binding_count": len(bindings), "test_refs": test_ref_count}


def validate_ci_script(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    path = repo_path(artifacts.get("ci_script"), "source_artifacts.ci_script")
    text = path.read_text(encoding="utf-8") if path and path.is_file() else ""
    markers = as_string_list(
        manifest.get("required_rehearsal_contract", {}).get("ci_script_markers"),
        "required_rehearsal_contract.ci_script_markers",
    )
    for marker in markers:
        require(marker in text, f"ci_script missing marker {marker!r}")
    append_event(
        "full_release_rehearsal_sources_bound",
        "pass" if not errors else "fail",
        [artifacts.get("ci_script", ""), artifacts.get("release_gate_dag", "")],
        {"ci_markers": len(markers)},
    )
    return {"ci_markers": len(markers)}


def validate_dag(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest.get("required_rehearsal_contract", {})
    if not isinstance(contract, dict):
        err("required_rehearsal_contract must be an object")
        contract = {}
    dag_path = repo_path(artifacts.get("release_gate_dag"), "source_artifacts.release_gate_dag")
    dag = load_json(dag_path, "release gate DAG") if dag_path and dag_path.is_file() else {}
    require(dag.get("schema_version") == 1, "release_gate_dag.schema_version must be 1")
    expected_sequence = as_string_list(contract.get("release_gate_sequence"), "required_rehearsal_contract.release_gate_sequence")
    required_fields = set(as_string_list(contract.get("release_gate_required_fields"), "required_rehearsal_contract.release_gate_required_fields"))
    command_markers = as_string_list(contract.get("release_gate_command_markers"), "required_rehearsal_contract.release_gate_command_markers")
    gates = dag.get("gates")
    if not isinstance(gates, list) or not gates:
        err("release_gate_dag.gates must be a non-empty array")
        gates = []
    gate_names: list[str] = []
    command_blob = ""
    seen: set[str] = set()
    for index, gate in enumerate(gates):
        if not isinstance(gate, dict):
            err(f"release_gate_dag.gates[{index}] must be an object")
            continue
        missing_fields = required_fields - set(gate)
        if missing_fields:
            err(f"release_gate_dag.gates[{index}] missing fields {sorted(missing_fields)}")
        name = gate.get("gate_name")
        if not isinstance(name, str) or not name:
            err(f"release_gate_dag.gates[{index}] missing gate_name")
            continue
        gate_names.append(name)
        command = gate.get("command")
        if isinstance(command, str):
            command_blob += "\n" + command
        deps = gate.get("depends_on")
        if not isinstance(deps, list):
            err(f"release_gate_dag.{name}.depends_on must be an array")
            deps = []
        for dep in deps:
            if dep not in seen:
                err(f"release_gate_dag.{name} dependency {dep!r} does not appear before gate")
        require(gate.get("critical") is True, f"release_gate_dag.{name}.critical must be true")
        seen.add(name)
    require(gate_names == expected_sequence, f"release_gate_dag gate sequence mismatch: expected={expected_sequence} actual={gate_names}")
    for marker in command_markers:
        require(marker in command_blob, f"release gate DAG missing command marker {marker!r}")
    return {"gate_names": gate_names, "gate_count": len(gates)}


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
    command_results[name] = {
        "args": args,
        "status": "pass" if proc.returncode == 0 else "fail",
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout.strip().splitlines()[-8:],
        "stderr_tail": proc.stderr.strip().splitlines()[-8:],
    }
    if expect_success and proc.returncode != 0:
        err(f"{name} failed with exit {proc.returncode}: stdout={proc.stdout[-1000:]} stderr={proc.stderr[-1000:]}")
    if not expect_success and proc.returncode == 0:
        err(f"{name} was expected to fail but passed")
    return proc


def validate_dry_run_dossier(path: pathlib.Path, expected_gate_count: int) -> dict[str, Any]:
    dossier = load_json(path, "release dry-run dossier")
    dry_contract = {}
    if "manifest" in globals():
        dry_contract = manifest.get("required_rehearsal_contract", {}).get("dry_run", {})
    expected_schema = int(dry_contract.get("expected_schema_version", 2)) if isinstance(dry_contract, dict) else 2
    require(dossier.get("schema_version") == expected_schema, f"dry-run dossier schema_version must be {expected_schema}")
    require(dossier.get("bead") == "bd-w2c3.10.2", "dry-run dossier must bind bd-w2c3.10.2 source bead")
    require(dossier.get("mode") == "dry-run", "dry-run dossier mode must be dry-run")
    require(dossier.get("gate_count") == expected_gate_count, f"dry-run dossier gate_count must be {expected_gate_count}")
    summary = dossier.get("summary")
    if not isinstance(summary, dict):
        err("dry-run dossier.summary must be an object")
        summary = {}
    require(summary.get("verdict") == "PASS", "dry-run dossier verdict must be PASS")
    require(summary.get("failed") == 0, "dry-run dossier failed count must be 0")
    return dossier


def validate_log(path: pathlib.Path, expected_gate_count: int, expected_sequence: list[str], required_log_fields: set[str]) -> list[dict[str, Any]]:
    rows = load_jsonl(path, "release dry-run log")
    require(len(rows) == expected_gate_count, f"release dry-run log rows expected={expected_gate_count} actual={len(rows)}")
    names: list[str] = []
    for index, row in enumerate(rows):
        missing = required_log_fields - set(row)
        if missing:
            err(f"release dry-run log row {index + 1} missing fields {sorted(missing)}")
        name = row.get("gate_name")
        if isinstance(name, str):
            names.append(name)
        require(row.get("critical") is True, f"release dry-run log row {index + 1} critical must be true")
    require(names == expected_sequence, f"release dry-run log sequence mismatch: expected={expected_sequence} actual={names}")
    return rows


def replay_release_dry_run(manifest_value: dict[str, Any], artifacts: dict[str, str], dag_summary: dict[str, Any]) -> dict[str, Any]:
    dry = manifest_value.get("required_rehearsal_contract", {}).get("dry_run", {})
    if not isinstance(dry, dict):
        err("required_rehearsal_contract.dry_run must be an object")
        dry = {}
    expected_sequence = dag_summary.get("gate_names", [])
    expected_gate_count = int(dry.get("expected_gate_count", dag_summary.get("gate_count", 0)))
    required_log_fields = set(as_string_list(dry.get("required_log_fields"), "required_rehearsal_contract.dry_run.required_log_fields"))
    runner = repo_path(artifacts.get("release_dry_run_runner"), "source_artifacts.release_dry_run_runner")
    if runner is None:
        return {}

    pass_dossier = OUT_DIR / "generated.full_release_rehearsal.pass.dossier.json"
    pass_state = OUT_DIR / "generated.full_release_rehearsal.pass.state.json"
    pass_log = OUT_DIR / "generated.full_release_rehearsal.pass.log.jsonl"
    run_command(
        "release_dry_run_pass",
        [
            "bash",
            str(runner),
            "--mode",
            "dry-run",
            "--trace-id",
            f"{COMPLETION_BEAD}:pass",
            "--dossier-path",
            str(pass_dossier),
            "--state-path",
            str(pass_state),
            "--log-path",
            str(pass_log),
        ],
    )
    pass_json = validate_dry_run_dossier(pass_dossier, expected_gate_count)
    pass_rows = validate_log(pass_log, expected_gate_count, expected_sequence, required_log_fields)
    state = load_json(pass_state, "release dry-run success state")
    require(state.get("status") == "success", "release dry-run success state must be success")
    require(state.get("resume_token") == "", "release dry-run success state resume token must be empty")

    fail_gate = dry.get("fail_fast_gate", "e2e")
    fail_state = OUT_DIR / "generated.full_release_rehearsal.fail.state.json"
    fail_log = OUT_DIR / "generated.full_release_rehearsal.fail.log.jsonl"
    fail_dossier = OUT_DIR / "generated.full_release_rehearsal.fail.dossier.json"
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
    require(isinstance(token, str) and token.startswith("v1:"), "fail-fast state must emit a v1 resume token")
    require(fail_state_json.get("failed_gate") == fail_gate, f"fail-fast failed_gate must be {fail_gate}")

    resume_dossier = OUT_DIR / "generated.full_release_rehearsal.resume.dossier.json"
    resume_state = OUT_DIR / "generated.full_release_rehearsal.resume.state.json"
    resume_log = OUT_DIR / "generated.full_release_rehearsal.resume.log.jsonl"
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
        resume_json = validate_dry_run_dossier(resume_dossier, expected_gate_count)
        resume_rows = validate_log(resume_log, expected_gate_count, expected_sequence, required_log_fields)
        fail_index = expected_sequence.index(fail_gate) if fail_gate in expected_sequence else -1
        expected_skip = dry.get("expected_resume_skipped_status", "resume_skip")
        if fail_index >= 0:
            for row in resume_rows[:fail_index]:
                require(row.get("status") == expected_skip, "resume rows before failed gate must be resume_skip")
            require(resume_rows[fail_index].get("status") == "pass", "resume row at failed gate must pass")
        summary = resume_json.get("summary", {}) if isinstance(resume_json.get("summary"), dict) else {}
        append_event(
            "full_release_rehearsal_dag_replayed",
            "pass" if not errors else "fail",
            [rel(pass_dossier), rel(pass_state), rel(pass_log), rel(resume_dossier), rel(resume_state), rel(resume_log)],
            {
                "gate_count": expected_gate_count,
                "pass_rows": len(pass_rows),
                "resume_passed": summary.get("passed", 0),
                "resume_skipped": summary.get("skipped", 0),
                "fail_gate": fail_gate,
            },
        )
    return {"dossier": pass_json, "state": state, "rows": pass_rows}


def validate_dossier_report(manifest_value: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    dossier_contract = manifest_value.get("required_rehearsal_contract", {}).get("dossier", {})
    if not isinstance(dossier_contract, dict):
        err("required_rehearsal_contract.dossier must be an object")
        dossier_contract = {}
    report_path = repo_path(artifacts.get("release_dossier_report"), "source_artifacts.release_dossier_report")
    report = load_json(report_path, "release dossier report") if report_path and report_path.is_file() else {}
    require(report.get("status") == dossier_contract.get("required_status"), "release dossier status mismatch")
    require(report.get("verdict") == dossier_contract.get("required_verdict"), "release dossier verdict mismatch")
    summary = report.get("summary")
    if not isinstance(summary, dict):
        err("release dossier summary must be an object")
        summary = {}
    require(int(summary.get("total_artifacts", 0)) >= int(dossier_contract.get("min_total_artifacts", 0)), "release dossier total_artifacts below contract floor")
    require(int(summary.get("valid", 0)) >= int(dossier_contract.get("min_valid_artifacts", 0)), "release dossier valid artifact count below contract floor")
    require(int(summary.get("critical_missing", -1)) == int(dossier_contract.get("required_critical_missing", 0)), "release dossier critical_missing mismatch")
    require(int(summary.get("errors", -1)) == int(dossier_contract.get("required_errors", 0)), "release dossier errors mismatch")
    integrity = report.get("integrity_index")
    if not isinstance(integrity, dict):
        err("release dossier integrity_index must be an object")
        integrity = {}
    for artifact_id in as_string_list(dossier_contract.get("required_integrity_ids"), "required_rehearsal_contract.dossier.required_integrity_ids"):
        require(artifact_id in integrity, f"release dossier integrity_index missing {artifact_id}")
    hook = report.get("release_notes_hook")
    if not isinstance(hook, dict):
        err("release dossier release_notes_hook must be an object")
        hook = {}
    for field in as_string_list(dossier_contract.get("required_release_notes_fields"), "required_rehearsal_contract.dossier.required_release_notes_fields"):
        require(field in hook, f"release_notes_hook missing field {field}")
    append_event(
        "full_release_rehearsal_dossier_bound",
        "pass" if not errors else "fail",
        [artifacts.get("release_dossier_report", ""), artifacts.get("release_dossier_validator", "")],
        {
            "total_artifacts": summary.get("total_artifacts", 0),
            "valid": summary.get("valid", 0),
            "critical_missing": summary.get("critical_missing", 0),
            "release_note_candidates": summary.get("release_note_candidates", 0),
        },
    )
    return {"summary": summary, "integrity_count": len(integrity)}


def validate_smoke_summary(manifest_value: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    smoke_contract = manifest_value.get("required_rehearsal_contract", {}).get("ld_preload_smoke", {})
    if not isinstance(smoke_contract, dict):
        err("required_rehearsal_contract.ld_preload_smoke must be an object")
        smoke_contract = {}
    smoke_path = repo_path(artifacts.get("ld_preload_smoke_summary"), "source_artifacts.ld_preload_smoke_summary")
    smoke = load_json(smoke_path, "LD_PRELOAD smoke summary") if smoke_path and smoke_path.is_file() else {}
    require(smoke.get("schema_version") == "v1", "LD_PRELOAD smoke summary schema_version must be v1")
    summary = smoke.get("summary")
    if not isinstance(summary, dict):
        err("LD_PRELOAD smoke summary must be an object")
        summary = {}
    checks = [
        ("total_cases", "expected_total_cases"),
        ("passes", "expected_passes"),
        ("fails", "expected_fails"),
        ("skips", "expected_skips"),
    ]
    for actual_key, expected_key in checks:
        require(int(summary.get(actual_key, -1)) == int(smoke_contract.get(expected_key, -2)), f"LD_PRELOAD smoke summary {actual_key} drift")
    require(summary.get("overall_failed") is False, "LD_PRELOAD smoke summary overall_failed must be false")
    modes = smoke.get("modes")
    if not isinstance(modes, dict):
        err("LD_PRELOAD smoke modes must be an object")
        modes = {}
    for mode in as_string_list(smoke_contract.get("required_modes"), "required_rehearsal_contract.ld_preload_smoke.required_modes"):
        mode_summary = modes.get(mode)
        if not isinstance(mode_summary, dict):
            err(f"LD_PRELOAD smoke missing mode {mode}")
            continue
        require(mode_summary.get("status") == smoke_contract.get("expected_mode_status"), f"LD_PRELOAD smoke {mode} status drift")
        for actual_key, expected_key in [
            ("total_cases", "expected_mode_total_cases"),
            ("passes", "expected_mode_passes"),
            ("fails", "expected_mode_fails"),
            ("skips", "expected_mode_skips"),
        ]:
            require(int(mode_summary.get(actual_key, -1)) == int(smoke_contract.get(expected_key, -2)), f"LD_PRELOAD smoke {mode}.{actual_key} drift")
    expected_skips = set(as_string_list(smoke_contract.get("expected_optional_skip_binaries"), "required_rehearsal_contract.ld_preload_smoke.expected_optional_skip_binaries"))
    actual_skips = set(as_string_list(smoke.get("optional_skip_binaries"), "ld_preload_smoke_summary.optional_skip_binaries"))
    require(actual_skips == expected_skips, f"LD_PRELOAD smoke optional skips mismatch: expected={sorted(expected_skips)} actual={sorted(actual_skips)}")
    append_event(
        "full_release_rehearsal_smoke_bound",
        "pass" if not errors else "fail",
        [artifacts.get("ld_preload_smoke_summary", ""), artifacts.get("ld_preload_smoke_runner", "")],
        {
            "total_cases": summary.get("total_cases", 0),
            "passes": summary.get("passes", 0),
            "fails": summary.get("fails", 0),
            "skips": summary.get("skips", 0),
        },
    )
    return {"summary": summary, "modes": sorted(modes)}


def validate_replacement_levels(artifacts: dict[str, str]) -> None:
    checker = repo_path(artifacts.get("replacement_levels_checker"), "source_artifacts.replacement_levels_checker")
    if checker is None:
        return
    run_command("replacement_levels_checker", ["bash", str(checker)])


def validate_telemetry(manifest_value: dict[str, Any], status: str) -> None:
    telemetry = manifest_value.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return
    required_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_contract.required_fields"))
    for index, event in enumerate(events):
        missing = required_fields - set(event)
        if missing:
            err(f"telemetry event {index + 1} missing fields {sorted(missing)}")
    if status == "pass":
        emitted = {str(event.get("event")) for event in events}
        required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
        missing_events = required_events - emitted
        if missing_events:
            err(f"telemetry missing required events {sorted(missing_events)}")


def write_outputs(manifest_value: dict[str, Any], status: str, summaries: dict[str, Any]) -> None:
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": EXPECTED_MANIFEST,
        "source_bead": SOURCE_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "source_commit": SOURCE_COMMIT,
        "summaries": summaries,
        "command_results": command_results,
        "events": events,
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("manifest_id") == EXPECTED_MANIFEST, f"manifest_id must be {EXPECTED_MANIFEST}")
require(manifest.get("original_bead") == SOURCE_BEAD, f"original_bead must be {SOURCE_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
require(int(manifest.get("next_audit_score_threshold", 0)) >= 800, "next_audit_score_threshold must be at least 800")

artifacts = validate_source_artifacts(manifest)
for ref in as_string_list(manifest.get("implementation_refs"), "implementation_refs"):
    check_file_line_ref(ref)
binding_summary = validate_bindings(manifest, artifacts)
ci_summary = validate_ci_script(manifest, artifacts)
dag_summary = validate_dag(manifest, artifacts)
dry_summary = replay_release_dry_run(manifest, artifacts, dag_summary)
dossier_summary = validate_dossier_report(manifest, artifacts)
smoke_summary = validate_smoke_summary(manifest, artifacts)
validate_replacement_levels(artifacts)

status = "fail" if errors else "pass"
append_event(
    "full_release_rehearsal_completion_contract_pass" if status == "pass" else "full_release_rehearsal_completion_contract_fail",
    status,
    [rel(CONTRACT), rel(REPORT), rel(LOG)],
    {
        "bindings": binding_summary,
        "gates": dag_summary.get("gate_count", 0),
        "dossier_status": dossier_summary.get("summary", {}).get("errors", 0),
        "smoke_fails": smoke_summary.get("summary", {}).get("fails", 0),
    },
)
validate_telemetry(manifest, status)
status = "fail" if errors else "pass"
write_outputs(
    manifest,
    status,
    {
        "bindings": binding_summary,
        "ci": ci_summary,
        "dag": dag_summary,
        "dry_run": dry_summary,
        "dossier": dossier_summary,
        "smoke": smoke_summary,
    },
)

if errors:
    print(f"full_release_rehearsal_completion_contract: FAIL errors={len(errors)}")
    for message in errors:
        print(f"ERROR: {message}")
    print(f"Report: {REPORT}")
    print(f"Log: {LOG}")
    raise SystemExit(1)

print(
    "full_release_rehearsal_completion_contract: PASS "
    f"bindings={binding_summary['binding_count']} "
    f"gates={dag_summary.get('gate_count', 0)} "
    f"smoke={smoke_summary.get('summary', {}).get('passes', 0)}/"
    f"{smoke_summary.get('summary', {}).get('fails', 0)}/"
    f"{smoke_summary.get('summary', {}).get('skips', 0)}"
)
print(f"Report: {REPORT}")
print(f"Log: {LOG}")
PY
