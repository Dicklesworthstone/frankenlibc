#!/usr/bin/env bash
# Validate bd-5fw.2.1 release-gate orchestration completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RELEASE_GATE_ORCH_CONTRACT:-${1:-${ROOT}/tests/conformance/release_gate_orchestration_completion_contract.v1.json}}"
OUT_DIR="${FRANKENLIBC_RELEASE_GATE_ORCH_OUT_DIR:-${2:-${ROOT}/target/conformance}}"
REPORT="${FRANKENLIBC_RELEASE_GATE_ORCH_REPORT:-${OUT_DIR}/release_gate_orchestration_completion_contract.report.json}"
LOG="${FRANKENLIBC_RELEASE_GATE_ORCH_LOG:-${OUT_DIR}/release_gate_orchestration_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1]).resolve()
contract_path = Path(sys.argv[2]).resolve()
report_path = Path(sys.argv[3]).resolve()
log_path = Path(sys.argv[4]).resolve()
out_dir = Path(sys.argv[5]).resolve()
source_commit = sys.argv[6]

SCHEMA = "release_gate_orchestration_completion_contract.v1"
BEAD_ID = "bd-5fw.2.1"
ORIGINAL_BEAD = "bd-5fw.2"
TRACE_ID = "bd-5fw.2.1::release-gate-orchestration::v1"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.integration.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "destructive_command",
    "missing_completion_binding",
    "gate_sequence_mismatch",
    "gate_dependency_mismatch",
    "runbook_semantics_missing",
    "release_dry_run_failed",
    "release_dry_run_artifact_invalid",
    "source_checker_failed",
    "completion_output_contract_failed",
]

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {row["failure_signature"] for row in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "completion_contract_failed"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("malformed_contract", f"{label}: cannot parse {rel(path)}: {exc}")
        return {}


def require(condition: bool, signature: str, message: str) -> None:
    if not condition:
        add_error(signature, message)


def require_array(row: dict[str, Any], field: str, ctx: str) -> list[Any]:
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    add_error("malformed_contract", f"{ctx}.{field} must be a non-empty array")
    return []


def string_list(row: dict[str, Any], field: str, ctx: str) -> list[str]:
    values = require_array(row, field, ctx)
    result: list[str] = []
    for index, value in enumerate(values):
        if isinstance(value, str) and value:
            result.append(value)
        else:
            add_error("malformed_contract", f"{ctx}.{field}[{index}] must be a non-empty string")
    return result


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def resolve_ref(ref: str) -> Path:
    path_text = ref.split(":", 1)[0] if ":" in ref else ref
    return resolve(path_text)


def event(
    name: str,
    status: str,
    scenario_id: str,
    expected: Any,
    actual: Any,
    artifact_refs: list[str],
    failure_signature: str = "none",
) -> dict[str, Any]:
    return {
        "timestamp": now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "scenario_id": scenario_id,
        "event": name,
        "status": status,
        "expected": expected,
        "actual": actual,
        "artifact_refs": sorted(set(artifact_refs)),
        "source_commit": source_commit,
        "target_dir": rel(out_dir),
        "failure_signature": failure_signature,
    }


def base_artifacts(extra: list[str] | None = None) -> list[str]:
    return [rel(contract_path), rel(report_path), rel(log_path), *(extra or [])]


def fail_report(stage: str, extra_artifacts: list[str] | None = None) -> None:
    artifacts = sorted(set(base_artifacts(extra_artifacts)))
    events.append(
        event(
            f"{stage}_failed",
            "fail",
            stage,
            "completion contract passes",
            primary_signature(),
            artifacts,
            primary_signature(),
        )
    )
    report = {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": "fail",
        "summary": {
            "gate_count": 0,
            "missing_item_count": 0,
            "pass_rows": 0,
            "resume_skip_rows": 0,
            "log_row_count": len(events),
        },
        "gate_contract": {},
        "missing_item_bindings": [],
        "source_artifacts": [],
        "generated_artifacts": extra_artifacts or [],
        "artifact_refs": artifacts,
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, events)
    raise SystemExit(1)


def command_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("TMPDIR", "/data/tmp" if Path("/data/tmp").is_dir() else str(root / "target"))
    if extra:
        env.update(extra)
    return env


def run_command(argv: list[str], label: str, extra_env: dict[str, str] | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str] | None:
    try:
        completed = subprocess.run(
            argv,
            cwd=root,
            env=command_env(extra_env),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        add_error("release_dry_run_failed", f"{label} timed out: {shlex.join(argv)}")
        return None
    return completed


def read_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        body = path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error("release_dry_run_artifact_invalid", f"{label}: cannot read {rel(path)}: {exc}")
        return rows
    for index, line in enumerate(body.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except Exception as exc:
            add_error("release_dry_run_artifact_invalid", f"{label}: invalid JSONL row {index}: {exc}")
            continue
        if isinstance(value, dict):
            rows.append(value)
        else:
            add_error("release_dry_run_artifact_invalid", f"{label}: row {index} must be an object")
    return rows


def validate_source_artifacts(contract: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for index, artifact in enumerate(require_array(contract, "source_artifacts", "contract")):
        if not isinstance(artifact, dict):
            add_error("malformed_contract", f"source_artifacts[{index}] must be an object")
            continue
        artifact_id = artifact.get("id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            add_error("malformed_contract", f"source_artifacts[{index}].id must be non-empty")
        if not isinstance(path_text, str) or not path_text:
            add_error("malformed_contract", f"source_artifacts[{index}].path must be non-empty")
            continue
        path = resolve(path_text)
        refs.append(rel(path))
        if not path.exists():
            add_error("missing_source_artifact", f"{artifact_id or index}: missing {rel(path)}")
    if not errors:
        events.append(
            event(
                "source_artifacts_validated",
                "pass",
                "source-artifacts",
                "all source artifacts exist",
                len(refs),
                refs,
            )
        )
    return refs


def validate_read_only_policy(contract: dict[str, Any]) -> None:
    policy = contract.get("read_only_policy", {})
    if not isinstance(policy, dict):
        add_error("malformed_contract", "read_only_policy must be an object")
        return
    commands = " ".join(string_list(policy, "allowed_commands", "read_only_policy"))
    forbidden = string_list(policy, "forbidden_command_fragments", "read_only_policy")
    for fragment in forbidden:
        if fragment in commands:
            add_error("destructive_command", f"allowed command contains forbidden fragment {fragment!r}")


def validate_bindings(contract: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = contract.get("completion_debt_evidence", {})
    if not isinstance(evidence, dict):
        add_error("malformed_contract", "completion_debt_evidence must be an object")
        return []
    bindings = require_array(evidence, "missing_item_bindings", "completion_debt_evidence")
    seen: set[str] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            add_error("malformed_contract", f"missing_item_bindings[{index}] must be an object")
            continue
        spec = binding.get("spec_item")
        if isinstance(spec, str) and spec:
            seen.add(spec)
        else:
            add_error("malformed_contract", f"missing_item_bindings[{index}].spec_item must be non-empty")
        for field in ("implementation_refs", "test_refs", "required_positive_tests"):
            for ref in string_list(binding, field, f"missing_item_bindings[{index}]"):
                if field.endswith("_refs") and not resolve_ref(ref).exists():
                    add_error("missing_source_artifact", f"{spec}: referenced path missing: {ref}")
        if spec == "tests.conformance.primary":
            require(
                bool(binding.get("required_negative_tests")),
                "missing_completion_binding",
                "tests.conformance.primary must include fail-closed negative tests",
            )
    missing = sorted(REQUIRED_MISSING_ITEMS - seen)
    extra = sorted(seen - REQUIRED_MISSING_ITEMS)
    for spec in missing:
        add_error("missing_completion_binding", f"missing completion binding for {spec}")
    for spec in extra:
        add_error("malformed_contract", f"unexpected completion binding {spec}")
    if not missing and not extra and not any(e["failure_signature"] == "missing_completion_binding" for e in errors):
        events.append(
            event(
                "completion_bindings_validated",
                "pass",
                "completion-bindings",
                sorted(REQUIRED_MISSING_ITEMS),
                sorted(seen),
                [rel(contract_path)],
            )
        )
    return [row for row in bindings if isinstance(row, dict)]


def validate_subsequence(full: list[str], subsequence: list[str]) -> bool:
    cursor = 0
    for gate in full:
        if cursor < len(subsequence) and gate == subsequence[cursor]:
            cursor += 1
    return cursor == len(subsequence)


def validate_runbook(path: Path) -> None:
    try:
        body = path.read_text(encoding="utf-8").lower()
    except Exception as exc:
        add_error("runbook_semantics_missing", f"cannot read runbook {rel(path)}: {exc}")
        return
    for term in ("fail-fast", "resume token", "resume_skip", "prereq_hash"):
        if term not in body:
            add_error("runbook_semantics_missing", f"runbook missing term {term!r}")


def validate_dag(contract: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    gate_contract = contract.get("gate_contract", {})
    if not isinstance(gate_contract, dict):
        add_error("malformed_contract", "gate_contract must be an object")
        return [], {}
    dag_path = resolve(str(gate_contract.get("dag_path", "")))
    dag = load_json(dag_path, "release gate DAG")
    if not isinstance(dag, dict):
        add_error("malformed_contract", "release gate DAG must be an object")
        return [], {}
    expected_full = string_list(gate_contract, "expected_full_gate_sequence", "gate_contract")
    required_subsequence = string_list(gate_contract, "original_required_gate_subsequence", "gate_contract")
    required_fields = string_list(gate_contract, "required_gate_fields", "gate_contract")
    gates = dag.get("gates")
    if not isinstance(gates, list) or not gates:
        add_error("gate_sequence_mismatch", "release gate DAG must contain non-empty gates")
        return [], dag
    actual = []
    seen: set[str] = set()
    for index, gate in enumerate(gates):
        if not isinstance(gate, dict):
            add_error("gate_sequence_mismatch", f"gate[{index}] must be an object")
            continue
        name = gate.get("gate_name")
        if isinstance(name, str) and name:
            actual.append(name)
        else:
            add_error("gate_sequence_mismatch", f"gate[{index}] missing gate_name")
            continue
        for field in required_fields:
            if field not in gate:
                add_error("gate_sequence_mismatch", f"{name}: missing required field {field}")
        deps = gate.get("depends_on")
        if not isinstance(deps, list):
            add_error("gate_dependency_mismatch", f"{name}: depends_on must be an array")
        else:
            for dep in deps:
                if dep not in seen:
                    add_error("gate_dependency_mismatch", f"{name}: dependency {dep!r} must appear earlier")
        seen.add(name)
    if actual != expected_full:
        add_error("gate_sequence_mismatch", f"expected gate sequence {expected_full}, got {actual}")
    if not validate_subsequence(actual, required_subsequence):
        add_error("gate_sequence_mismatch", f"original required sequence {required_subsequence} is not a subsequence of {actual}")
    ordering = dag.get("gate_ordering_policy")
    require(isinstance(ordering, dict), "gate_sequence_mismatch", "DAG gate_ordering_policy must be an object")
    if isinstance(ordering, dict):
        require(ordering.get("fail_fast") is True, "gate_sequence_mismatch", "DAG fail_fast must be true")
        token_format = str(ordering.get("resume_token_format", ""))
        require(token_format.startswith(str(gate_contract.get("resume_token_prefix", "v1:"))), "gate_sequence_mismatch", "resume token format must use v1 prefix")
    structured = dag.get("structured_log_requirements")
    require(isinstance(structured, dict), "gate_sequence_mismatch", "DAG structured_log_requirements must be an object")
    if isinstance(structured, dict):
        required_log = set(string_list(gate_contract, "required_log_fields", "gate_contract"))
        actual_log = set(structured.get("required_fields", []))
        require({"trace_id", "gate_name", "prereq_hash", "status", "duration_ms", "resume_token"}.issubset(actual_log), "gate_sequence_mismatch", "DAG structured log basics missing")
        require(required_log.issuperset(actual_log), "malformed_contract", "manifest required_log_fields must cover DAG structured log fields")
    validate_runbook(resolve(str(gate_contract.get("runbook_path", ""))))
    if not any(e["failure_signature"] in {"gate_sequence_mismatch", "gate_dependency_mismatch", "runbook_semantics_missing"} for e in errors):
        events.append(
            event(
                "release_gate_dag_validated",
                "pass",
                "release-gate-dag",
                expected_full,
                actual,
                [rel(dag_path), rel(resolve(str(gate_contract.get("runbook_path", ""))))],
            )
        )
    return actual, dag


def validate_required_fields(value: dict[str, Any], fields: list[str], label: str, signature: str) -> None:
    for field in fields:
        if field not in value:
            add_error(signature, f"{label}: missing field {field}")


def validate_log_rows(rows: list[dict[str, Any]], expected_sequence: list[str], required_fields: list[str], label: str) -> None:
    if len(rows) != len(expected_sequence):
        add_error("release_dry_run_artifact_invalid", f"{label}: expected {len(expected_sequence)} log rows, got {len(rows)}")
    for index, row in enumerate(rows):
        validate_required_fields(row, required_fields, f"{label}[{index}]", "release_dry_run_artifact_invalid")
        if index < len(expected_sequence) and row.get("gate_name") != expected_sequence[index]:
            add_error("release_dry_run_artifact_invalid", f"{label}[{index}]: gate order drifted")
        if row.get("gate_index") != index:
            add_error("release_dry_run_artifact_invalid", f"{label}[{index}]: gate_index drifted")


def replay_release_dry_run(contract: dict[str, Any], expected_sequence: list[str]) -> dict[str, Any]:
    gate_contract = contract.get("gate_contract", {})
    if not isinstance(gate_contract, dict):
        return {}
    runner = resolve(str(gate_contract.get("runner_path", "")))
    required_log_fields = string_list(gate_contract, "required_log_fields", "gate_contract")
    required_dossier_fields = string_list(gate_contract, "required_dossier_fields", "gate_contract")
    required_summary_fields = string_list(gate_contract, "required_dossier_summary_fields", "gate_contract")
    required_state_fields = string_list(gate_contract, "required_state_fields", "gate_contract")
    fail_gate = str(gate_contract.get("fail_fast_gate", "e2e"))
    fail_index = expected_sequence.index(fail_gate) if fail_gate in expected_sequence else -1
    generated: dict[str, str] = {}

    pass_log = out_dir / "generated.release_gate_orchestration.pass.log.jsonl"
    pass_state = out_dir / "generated.release_gate_orchestration.pass.state.json"
    pass_dossier = out_dir / "generated.release_gate_orchestration.pass.dossier.json"
    trace_base = "bd-5fw.2.1-release-gate-orchestration"
    pass_run = run_command(
        [
            "bash",
            str(runner),
            "--mode",
            "dry-run",
            "--trace-id",
            f"{trace_base}-pass",
            "--log-path",
            str(pass_log),
            "--state-path",
            str(pass_state),
            "--dossier-path",
            str(pass_dossier),
        ],
        "release dry-run pass",
    )
    if pass_run is None or pass_run.returncode != 0:
        stderr = "" if pass_run is None else pass_run.stderr[-1200:]
        add_error("release_dry_run_failed", f"release dry-run pass failed: {stderr}")
        return generated
    pass_json = load_json(pass_dossier, "release dry-run pass dossier")
    pass_state_json = load_json(pass_state, "release dry-run pass state")
    pass_rows = read_jsonl(pass_log, "release dry-run pass log")
    if isinstance(pass_json, dict):
        validate_required_fields(pass_json, required_dossier_fields, "pass dossier", "release_dry_run_artifact_invalid")
        summary = pass_json.get("summary", {}) if isinstance(pass_json.get("summary"), dict) else {}
        validate_required_fields(summary, required_summary_fields, "pass dossier summary", "release_dry_run_artifact_invalid")
        require(pass_json.get("gate_count") == len(expected_sequence), "release_dry_run_artifact_invalid", "pass dossier gate_count mismatch")
        require(summary.get("verdict") == "PASS", "release_dry_run_artifact_invalid", "pass dossier verdict must be PASS")
        require(summary.get("passed") == len(expected_sequence), "release_dry_run_artifact_invalid", "pass dossier passed count mismatch")
    if isinstance(pass_state_json, dict):
        validate_required_fields(pass_state_json, required_state_fields, "pass state", "release_dry_run_artifact_invalid")
        require(pass_state_json.get("status") == "success", "release_dry_run_artifact_invalid", "pass state status must be success")
        require(pass_state_json.get("resume_token") == "", "release_dry_run_artifact_invalid", "pass state resume_token must be empty")
    validate_log_rows(pass_rows, expected_sequence, required_log_fields, "pass log")
    generated.update({"pass_log": rel(pass_log), "pass_state": rel(pass_state), "pass_dossier": rel(pass_dossier)})
    events.append(
        event(
            "release_dry_run_pass_replayed",
            "pass",
            "dry-run-pass",
            len(expected_sequence),
            len(pass_rows),
            [rel(pass_log), rel(pass_state), rel(pass_dossier)],
        )
    )

    fail_log = out_dir / "generated.release_gate_orchestration.fail_fast.log.jsonl"
    fail_state = out_dir / "generated.release_gate_orchestration.fail_fast.state.json"
    fail_dossier = out_dir / "generated.release_gate_orchestration.fail_fast.dossier.json"
    fail_run = run_command(
        [
            "bash",
            str(runner),
            "--mode",
            "dry-run",
            "--trace-id",
            f"{trace_base}-fail-fast",
            "--log-path",
            str(fail_log),
            "--state-path",
            str(fail_state),
            "--dossier-path",
            str(fail_dossier),
        ],
        "release dry-run fail-fast",
        {"FRANKENLIBC_RELEASE_SIMULATE_FAIL_GATE": fail_gate},
    )
    if fail_run is None or fail_run.returncode == 0:
        add_error("release_dry_run_failed", "release dry-run fail-fast must return non-zero")
        return generated
    fail_state_json = load_json(fail_state, "release dry-run fail-fast state")
    fail_rows = read_jsonl(fail_log, "release dry-run fail-fast log")
    token = ""
    if isinstance(fail_state_json, dict):
        token = str(fail_state_json.get("resume_token", ""))
        require(fail_state_json.get("failed_gate") == fail_gate, "release_dry_run_artifact_invalid", f"fail-fast failed_gate must be {fail_gate}")
        require(fail_state_json.get("failed_gate_index") == fail_index, "release_dry_run_artifact_invalid", "fail-fast failed_gate_index mismatch")
        require(token.startswith(str(gate_contract.get("resume_token_prefix", "v1:"))), "release_dry_run_artifact_invalid", "fail-fast token must use v1 prefix")
    require(bool(fail_rows) and fail_rows[-1].get("status") == "fail", "release_dry_run_artifact_invalid", "fail-fast log must end with fail row")

    resume_log = out_dir / "generated.release_gate_orchestration.resume.log.jsonl"
    resume_state = out_dir / "generated.release_gate_orchestration.resume.state.json"
    resume_dossier = out_dir / "generated.release_gate_orchestration.resume.dossier.json"
    resume_run = run_command(
        [
            "bash",
            str(runner),
            "--mode",
            "dry-run",
            "--resume-token",
            token,
            "--trace-id",
            f"{trace_base}-resume",
            "--log-path",
            str(resume_log),
            "--state-path",
            str(resume_state),
            "--dossier-path",
            str(resume_dossier),
        ],
        "release dry-run resume",
    )
    if resume_run is None or resume_run.returncode != 0:
        stderr = "" if resume_run is None else resume_run.stderr[-1200:]
        add_error("release_dry_run_failed", f"release dry-run resume failed: {stderr}")
        return generated
    resume_json = load_json(resume_dossier, "release dry-run resume dossier")
    resume_rows = read_jsonl(resume_log, "release dry-run resume log")
    validate_log_rows(resume_rows, expected_sequence, required_log_fields, "resume log")
    expected_skip = str(gate_contract.get("expected_resume_skipped_status", "resume_skip"))
    if fail_index >= 0:
        for row in resume_rows[:fail_index]:
            require(row.get("status") == expected_skip, "release_dry_run_artifact_invalid", "resume rows before failed gate must be resume_skip")
        require(resume_rows[fail_index].get("status") == "pass", "release_dry_run_artifact_invalid", "resume row at failed gate must pass")
    if isinstance(resume_json, dict):
        summary = resume_json.get("summary", {}) if isinstance(resume_json.get("summary"), dict) else {}
        require(summary.get("verdict") == "PASS", "release_dry_run_artifact_invalid", "resume dossier verdict must be PASS")
        require(summary.get("skipped") == fail_index, "release_dry_run_artifact_invalid", "resume skipped count mismatch")
    generated.update(
        {
            "fail_log": rel(fail_log),
            "fail_state": rel(fail_state),
            "resume_log": rel(resume_log),
            "resume_state": rel(resume_state),
            "resume_dossier": rel(resume_dossier),
        }
    )
    events.append(
        event(
            "release_dry_run_fail_fast_resume_replayed",
            "pass",
            "dry-run-fail-fast-resume",
            {"fail_gate": fail_gate, "resume_skip_rows": fail_index},
            {"token_prefix": token.split(":", 1)[0], "resume_rows": len(resume_rows)},
            [rel(fail_log), rel(fail_state), rel(resume_log), rel(resume_state), rel(resume_dossier)],
        )
    )
    return generated


def replay_source_checker(contract: dict[str, Any]) -> str:
    gate_contract = contract.get("gate_contract", {})
    if not isinstance(gate_contract, dict):
        return ""
    dossier = out_dir / "release_gate_orchestration.source_checker.dossier.json"
    completed = run_command(
        ["bash", str(resolve("scripts/check_release_dry_run.sh")), str(dossier)],
        "release dry-run source checker",
    )
    if completed is None or completed.returncode != 0:
        stderr = "" if completed is None else completed.stderr[-1200:]
        add_error("source_checker_failed", f"check_release_dry_run.sh failed: {stderr}")
        return rel(dossier)
    events.append(
        event(
            "release_dry_run_source_checker_replayed",
            "pass",
            "source-checker",
            "check_release_dry_run.sh exits 0",
            "pass",
            [rel(dossier)],
        )
    )
    return rel(dossier)


def validate_output_contract(contract: dict[str, Any], report: dict[str, Any], log_rows: list[dict[str, Any]]) -> None:
    output = contract.get("completion_output_contract", {})
    if not isinstance(output, dict):
        add_error("malformed_contract", "completion_output_contract must be an object")
        return
    for field in string_list(output, "required_report_fields", "completion_output_contract"):
        if field not in report:
            add_error("completion_output_contract_failed", f"report missing field {field}")
    required_log = string_list(output, "required_log_fields", "completion_output_contract")
    for index, row in enumerate(log_rows):
        for field in required_log:
            if field not in row:
                add_error("completion_output_contract_failed", f"log row {index} missing field {field}")
    present_events = {str(row.get("event", "")) for row in log_rows}
    for event_name in string_list(output, "required_events", "completion_output_contract"):
        if event_name not in present_events:
            add_error("completion_output_contract_failed", f"missing output event {event_name}")


contract = load_json(contract_path, "completion contract")
if not isinstance(contract, dict):
    fail_report("load_contract")

require(contract.get("schema_version") == SCHEMA, "malformed_contract", "schema_version mismatch")
require(contract.get("bead") == BEAD_ID, "malformed_contract", "bead mismatch")
require(contract.get("original_bead") == ORIGINAL_BEAD, "malformed_contract", "original_bead mismatch")
require(contract.get("trace_id") == TRACE_ID, "malformed_contract", "trace_id mismatch")
source_refs = validate_source_artifacts(contract)
validate_read_only_policy(contract)
bindings = validate_bindings(contract)
expected_sequence, dag = validate_dag(contract)
if errors:
    fail_report("static_validation", source_refs)

generated = replay_release_dry_run(contract, expected_sequence)
source_checker_dossier = replay_source_checker(contract)
if source_checker_dossier:
    generated["source_checker_dossier"] = source_checker_dossier
if errors:
    fail_report("replay_validation", source_refs + list(generated.values()))

events.append(
    event(
        "release_gate_orchestration_completion_contract_pass",
        "pass",
        "completion-output",
        "all static and replay checks pass",
        {
            "gate_count": len(expected_sequence),
            "missing_item_count": len(bindings),
            "generated_artifacts": len(generated),
        },
        source_refs + list(generated.values()),
    )
)

report = {
    "schema_version": f"{SCHEMA}.report",
    "bead_id": BEAD_ID,
    "original_bead": ORIGINAL_BEAD,
    "trace_id": TRACE_ID,
    "source_commit": source_commit,
    "status": "pass",
    "summary": {
        "gate_count": len(expected_sequence),
        "missing_item_count": len(bindings),
        "pass_rows": len([row for row in events if row["status"] == "pass"]),
        "resume_skip_rows": expected_sequence.index(str(contract["gate_contract"]["fail_fast_gate"])),
        "log_row_count": len(events),
    },
    "gate_contract": {
        "expected_full_gate_sequence": expected_sequence,
        "original_required_gate_subsequence": contract["gate_contract"]["original_required_gate_subsequence"],
        "fail_fast_gate": contract["gate_contract"]["fail_fast_gate"],
        "resume_token_prefix": contract["gate_contract"]["resume_token_prefix"],
    },
    "missing_item_bindings": [row["spec_item"] for row in bindings],
    "source_artifacts": source_refs,
    "generated_artifacts": generated,
    "artifact_refs": sorted(set(base_artifacts(source_refs + list(generated.values())))),
    "errors": [],
}

validate_output_contract(contract, report, events)
if errors:
    fail_report("output_contract", source_refs + list(generated.values()))

write_json(report_path, report)
write_jsonl(log_path, events)
print(
    "PASS release_gate_orchestration_completion_contract "
    f"gates={len(expected_sequence)} bindings={len(bindings)} events={len(events)} "
    f"report={rel(report_path)} log={rel(log_path)}"
)
PY
