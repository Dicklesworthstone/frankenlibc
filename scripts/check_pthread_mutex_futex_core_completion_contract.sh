#!/usr/bin/env bash
# check_pthread_mutex_futex_core_completion_contract.sh - bd-z84.1 completion evidence gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_PTHREAD_MUTEX_FUTEX_CORE_CONTRACT:-${ROOT}/tests/conformance/pthread_mutex_futex_core_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_PTHREAD_MUTEX_FUTEX_CORE_OUT_DIR:-${ROOT}/target/conformance/pthread_mutex_futex_core_completion_contract}"
REPORT="${FRANKENLIBC_PTHREAD_MUTEX_FUTEX_CORE_REPORT:-${OUT_DIR}/pthread_mutex_futex_core_completion_contract.report.json}"
LOG="${FRANKENLIBC_PTHREAD_MUTEX_FUTEX_CORE_LOG:-${OUT_DIR}/pthread_mutex_futex_core_completion_contract.log.jsonl}"
GATE_DIR="${FRANKENLIBC_PTHREAD_MUTEX_FUTEX_CORE_GATE_DIR:-${OUT_DIR}/prior_gates}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")" "${GATE_DIR}"

ROOT="${ROOT}" \
CONTRACT="${CONTRACT}" \
REPORT="${REPORT}" \
LOG="${LOG}" \
GATE_DIR="${GATE_DIR}" \
python3 - <<'PY'
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
GATE_DIR = pathlib.Path(os.environ["GATE_DIR"])

EXPECTED_SCHEMA = "pthread_mutex_futex_core_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "pthread_mutex_futex_core_completion_contract.report.v1"
EXPECTED_LOG_SCHEMA = "pthread_mutex_futex_core_completion_contract.log.v1"
EXPECTED_BEAD = "bd-z84.1"
EXPECTED_ORIGINAL_BEAD = "bd-z84"
EXPECTED_TRACE_ID = "bd-z84.1::pthread-mutex-futex-core::completion::v1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary": "unit",
    "tests.e2e.primary": "e2e",
    "telemetry.primary": "telemetry",
}
EXPECTED_SOURCE_KEYS = {
    "core_mutex",
    "abi_mutex",
    "abi_mutex_core_test",
    "conformance_fixture",
    "conformance_harness",
    "e2e_fixture",
    "e2e_gate",
    "semantics_contract",
    "semantics_gate",
    "semantics_harness",
    "callthrough_contract",
    "callthrough_gate",
    "callthrough_harness",
    "state_invariants_contract",
    "state_invariants_gate",
    "state_invariants_harness",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
EXPECTED_MUTEX_SYMBOLS = {
    "pthread_mutex_destroy",
    "pthread_mutex_init",
    "pthread_mutex_lock",
    "pthread_mutex_trylock",
    "pthread_mutex_unlock",
}
EXPECTED_PRIOR_GATES = {"semantics", "callthrough", "state_invariants"}
PASS_EVENTS = [
    "pthread_mutex_futex_core.sources_validated",
    "pthread_mutex_futex_core.unit_binding",
    "pthread_mutex_futex_core.e2e_binding",
    "pthread_mutex_futex_core.prior_gates_replayed",
    "pthread_mutex_futex_core.telemetry_contract",
    "pthread_mutex_futex_core.completion_contract_validated",
]
FAIL_EVENT = "pthread_mutex_futex_core.completion_contract_failed"

errors: list[str] = []
events: list[dict[str, Any]] = []
prior_gate_results: dict[str, dict[str, Any]] = {}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


SOURCE_COMMIT = git_head()


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def emit(event: str, outcome: str = "pass", **details: Any) -> None:
    timestamp = now()
    events.append(
        {
            "timestamp": timestamp,
            "ts": timestamp,
            "trace_id": EXPECTED_TRACE_ID,
            "schema_version": EXPECTED_LOG_SCHEMA,
            "level": "info" if outcome == "pass" else "error",
            "event": event,
            "bead_id": EXPECTED_BEAD,
            "original_bead": EXPECTED_ORIGINAL_BEAD,
            "stream": "conformance",
            "gate": "pthread_mutex_futex_core_completion_contract",
            "scenario_id": event,
            "mode": "strict",
            "api_family": "pthread",
            "symbol": "pthread_mutex",
            "oracle_kind": "completion_contract",
            "expected": "pass",
            "actual": outcome,
            "decision_path": "unit->e2e->semantics->callthrough->state-invariants",
            "outcome": outcome,
            "errno": 0,
            "latency_ns": 0,
            "source_commit": SOURCE_COMMIT,
            "failure_signature": "" if outcome == "pass" else "; ".join(errors[:3]),
            "artifact_refs": [rel(CONTRACT)],
            "details": details,
        }
    )


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


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


def as_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        err(f"{label} must be an object")
        return {}
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        err(f"{label} must be an array")
        return []
    return value


def repo_path(path_text: Any, label: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{label} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{label} must stay repo-relative: {path_text}")
        return None
    full = ROOT / path
    if not full.exists():
        err(f"{label} references missing path: {path_text}")
        return None
    return full


def validate_line_ref(ref: Any, label: str) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        err(f"{label} must be file:line")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        err(f"{label} has invalid line number: {ref}")
        return
    path = repo_path(path_text, label)
    if path is None or not path.is_file():
        err(f"{label} references missing file: {ref}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines):
        err(f"{label} references line past EOF: {ref}")
    elif not lines[line_no - 1].strip():
        err(f"{label} references blank line: {ref}")


def source_text(source_artifacts: dict[str, Any], key: str) -> str:
    path_text = source_artifacts.get(key)
    path = repo_path(path_text, f"source_artifacts.{key}")
    if path is None or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def validate_sources(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        err("contract_identity: schema_version mismatch")
    if manifest.get("bead_id") != EXPECTED_BEAD:
        err("contract_identity: bead_id mismatch")
    if manifest.get("original_bead") != EXPECTED_ORIGINAL_BEAD:
        err("contract_identity: original_bead mismatch")
    if manifest.get("trace_id") != EXPECTED_TRACE_ID:
        err("contract_identity: trace_id mismatch")

    artifacts = as_object(manifest.get("source_artifacts"), "source_artifacts")
    keys = set(artifacts)
    if keys != EXPECTED_SOURCE_KEYS:
        err(f"source_artifacts mismatch: expected={sorted(EXPECTED_SOURCE_KEYS)} got={sorted(keys)}")
    for key, path_text in artifacts.items():
        repo_path(path_text, f"source_artifacts.{key}")

    anchors = as_object(manifest.get("source_anchors"), "source_anchors")
    anchor_count = 0
    for key, needles in anchors.items():
        if key not in artifacts:
            err(f"source_anchors references unknown artifact: {key}")
            continue
        text = source_text(artifacts, key)
        for needle in as_list(needles, f"source_anchors.{key}"):
            if not isinstance(needle, str) or not needle:
                err(f"source_anchors.{key} contains a non-string needle")
                continue
            if needle not in text:
                err(f"source_anchor_missing: {key} missing {needle!r}")
            anchor_count += 1
    emit("pthread_mutex_futex_core.sources_validated", source_artifact_count=len(keys), anchor_count=anchor_count)
    return artifacts


def validate_completion_contract(manifest: dict[str, Any]) -> dict[str, Any]:
    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    missing = {item for item in as_list(contract.get("missing_item_ids"), "completion_contract.missing_item_ids") if isinstance(item, str)}
    if missing != set(EXPECTED_MISSING_ITEMS):
        err(f"missing_item_ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing)}")
    symbols = {item for item in as_list(contract.get("required_mutex_symbols"), "completion_contract.required_mutex_symbols") if isinstance(item, str)}
    if symbols != EXPECTED_MUTEX_SYMBOLS:
        err(f"required_mutex_symbols mismatch: expected={sorted(EXPECTED_MUTEX_SYMBOLS)} got={sorted(symbols)}")
    unit_tests = as_list(contract.get("required_unit_tests"), "completion_contract.required_unit_tests")
    if len(unit_tests) < 5:
        err("required_unit_tests must bind at least five futex mutex tests")
    e2e_artifacts = set()
    for path_text in as_list(contract.get("required_e2e_artifacts"), "completion_contract.required_e2e_artifacts"):
        if isinstance(path_text, str):
            e2e_artifacts.add(path_text)
            repo_path(path_text, "completion_contract.required_e2e_artifacts")
    if e2e_artifacts != {"tests/integration/fixture_pthread_mutex_adversarial.c", "scripts/bd1qy_mutex_fixture_run.sh"}:
        err(f"required_e2e_artifacts mismatch: {sorted(e2e_artifacts)}")
    gates = as_list(contract.get("required_prior_gates"), "completion_contract.required_prior_gates")
    gate_ids = {gate.get("id") for gate in gates if isinstance(gate, dict)}
    if gate_ids != EXPECTED_PRIOR_GATES:
        err(f"required_prior_gates mismatch: expected={sorted(EXPECTED_PRIOR_GATES)} got={sorted(gate_ids)}")
    return contract


def validate_missing_bindings(manifest: dict[str, Any]) -> int:
    bindings = as_list(manifest.get("missing_item_bindings"), "missing_item_bindings")
    actual: dict[str, str] = {}
    for index, binding in enumerate(bindings):
        binding_obj = as_object(binding, f"missing_item_bindings[{index}]")
        item_id = binding_obj.get("id")
        kind = binding_obj.get("kind")
        if isinstance(item_id, str) and isinstance(kind, str):
            actual[item_id] = kind
        else:
            err(f"missing_item_bindings[{index}] id/kind must be strings")
            continue
        for field in ("implementation_refs", "test_refs", "required_commands"):
            values = as_list(binding_obj.get(field), f"missing_item_bindings.{item_id}.{field}")
            if not values:
                err(f"missing_item_bindings.{item_id}.{field} must be non-empty")
            for value in values:
                if field == "required_commands":
                    if not isinstance(value, str) or not value:
                        err(f"required command for {item_id} must be a non-empty string")
                    elif " cargo " in f" {value} " and "rch exec -- cargo" not in value:
                        err(f"cargo_not_rch: {item_id} command must use rch: {value}")
                    continue
                validate_line_ref(value, f"missing_item_bindings.{item_id}.{field}")
        if item_id == "telemetry.primary":
            telemetry_refs = as_list(binding_obj.get("telemetry_refs"), "missing_item_bindings.telemetry.primary.telemetry_refs")
            for ref in telemetry_refs:
                validate_line_ref(ref, "missing_item_bindings.telemetry.primary.telemetry_refs")
            events = [event for event in as_list(binding_obj.get("required_events"), "missing_item_bindings.telemetry.primary.required_events") if isinstance(event, str)]
            if events != PASS_EVENTS:
                err(f"telemetry required_events mismatch: expected={PASS_EVENTS} got={events}")
    if actual != EXPECTED_MISSING_ITEMS:
        if "tests.e2e.primary" not in actual:
            err("missing_e2e_binding: tests.e2e.primary")
        if "tests.unit.primary" not in actual:
            err("missing_unit_binding: tests.unit.primary")
        if "telemetry.primary" not in actual:
            err("missing_telemetry_binding: telemetry.primary")
        err(f"missing_item_bindings mismatch: expected={EXPECTED_MISSING_ITEMS} got={actual}")
    emit("pthread_mutex_futex_core.unit_binding", unit_binding_count=1)
    emit("pthread_mutex_futex_core.e2e_binding", e2e_binding_count=1)
    return len(actual)


def run_prior_gate(gate: dict[str, Any]) -> None:
    gate_id = str(gate.get("id", ""))
    script = str(gate.get("script", ""))
    marker = str(gate.get("pass_marker", ""))
    script_path = repo_path(script, f"required_prior_gates.{gate_id}.script")
    if script_path is None:
        return
    gate_out_dir = GATE_DIR / gate_id
    gate_out_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    if gate_id == "semantics":
        env.update(
            {
                "FRANKENLIBC_PTHREAD_MUTEX_SEMANTICS_OUT_DIR": str(gate_out_dir),
                "FRANKENLIBC_PTHREAD_MUTEX_SEMANTICS_REPORT": str(gate_out_dir / "report.json"),
                "FRANKENLIBC_PTHREAD_MUTEX_SEMANTICS_LOG": str(gate_out_dir / "events.jsonl"),
            }
        )
    elif gate_id == "callthrough":
        env.update(
            {
                "FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_REPORT": str(gate_out_dir / "report.json"),
                "FRANKENLIBC_PTHREAD_MUTEX_CALLTHROUGH_LOG": str(gate_out_dir / "events.jsonl"),
            }
        )
    elif gate_id == "state_invariants":
        env.update(
            {
                "FRANKENLIBC_PTHREAD_MUTEX_STATE_INVARIANTS_REPORT": str(gate_out_dir / "report.json"),
                "FRANKENLIBC_PTHREAD_MUTEX_STATE_INVARIANTS_LOG": str(gate_out_dir / "events.jsonl"),
            }
        )
    result = subprocess.run(["bash", script], cwd=ROOT, text=True, capture_output=True, check=False, env=env)
    output = result.stdout + result.stderr
    output_path = gate_out_dir / "output.txt"
    output_path.write_text(output, encoding="utf-8")
    prior_gate_results[gate_id] = {
        "script": script,
        "exit_code": result.returncode,
        "marker": marker,
        "output": rel(output_path),
    }
    if result.returncode != 0:
        err(f"prior_gate_failed: {gate_id} exit={result.returncode}: {output[-1200:]}")
    if marker not in output:
        err(f"prior_gate_marker_missing: {gate_id} marker={marker!r}")


def replay_prior_gates(contract: dict[str, Any]) -> None:
    gates = as_list(contract.get("required_prior_gates"), "completion_contract.required_prior_gates")
    for gate in gates:
        if isinstance(gate, dict):
            run_prior_gate(gate)
    emit("pthread_mutex_futex_core.prior_gates_replayed", gate_count=len(prior_gate_results))


def validate_telemetry(manifest: dict[str, Any]) -> None:
    telemetry = as_object(manifest.get("telemetry_contract"), "telemetry_contract")
    if telemetry.get("report_schema_version") != EXPECTED_REPORT_SCHEMA:
        err("telemetry_contract.report_schema_version mismatch")
    if telemetry.get("log_schema_version") != EXPECTED_LOG_SCHEMA:
        err("telemetry_contract.log_schema_version mismatch")
    pass_events = [event for event in as_list(telemetry.get("pass_events"), "telemetry_contract.pass_events") if isinstance(event, str)]
    if pass_events != PASS_EVENTS:
        err(f"telemetry_contract.pass_events mismatch: expected={PASS_EVENTS} got={pass_events}")
    if telemetry.get("fail_event") != FAIL_EVENT:
        err("telemetry_contract.fail_event mismatch")
    emit("pthread_mutex_futex_core.telemetry_contract", required_event_count=len(pass_events))


def write_outputs(status: str, summary: dict[str, Any]) -> None:
    final_event = "pthread_mutex_futex_core.completion_contract_validated" if status == "pass" else FAIL_EVENT
    emit(final_event, status if status in {"pass", "fail", "error", "skip", "timeout"} else "error", summary=summary)
    event_names = [row["event"] for row in events]
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "status": status,
        "generated_at": now(),
        "source_commit": SOURCE_COMMIT,
        "completion_debt_bead": EXPECTED_BEAD,
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "trace_id": EXPECTED_TRACE_ID,
        "summary": summary,
        "prior_gate_results": prior_gate_results,
        "events": event_names,
        "errors": errors,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, events)


def main() -> int:
    manifest = load_json(CONTRACT, "completion contract")
    source_artifacts = validate_sources(manifest)
    contract = validate_completion_contract(manifest)
    missing_count = validate_missing_bindings(manifest)
    validate_telemetry(manifest)
    if not errors:
        replay_prior_gates(contract)
    summary = {
        "source_artifacts": len(source_artifacts),
        "missing_item_count": missing_count,
        "prior_gate_count": len(prior_gate_results),
        "unit_test_count": len(contract.get("required_unit_tests", [])) if isinstance(contract.get("required_unit_tests"), list) else 0,
        "mutex_symbol_count": len(contract.get("required_mutex_symbols", [])) if isinstance(contract.get("required_mutex_symbols"), list) else 0,
    }
    if errors:
        write_outputs("fail", summary)
        for message in errors:
            print(message, file=sys.stderr)
        return 1
    write_outputs("pass", summary)
    print(
        "PASS: pthread mutex futex-core completion contract "
        f"sources={summary['source_artifacts']} "
        f"missing_items={summary['missing_item_count']} "
        f"unit_tests={summary['unit_test_count']} "
        f"prior_gates={summary['prior_gate_count']}"
    )
    return 0


raise SystemExit(main())
PY
