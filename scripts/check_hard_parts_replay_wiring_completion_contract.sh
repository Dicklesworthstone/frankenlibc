#!/usr/bin/env bash
# check_hard_parts_replay_wiring_completion_contract.sh -- bd-bp8fl.2.8.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_HARD_PARTS_REPLAY_WIRING_CONTRACT:-${ROOT}/tests/conformance/hard_parts_replay_wiring_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_HARD_PARTS_REPLAY_WIRING_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_HARD_PARTS_REPLAY_WIRING_REPORT:-${OUT_DIR}/hard_parts_replay_wiring_completion_contract.report.json}"
LOG="${FRANKENLIBC_HARD_PARTS_REPLAY_WIRING_LOG:-${OUT_DIR}/hard_parts_replay_wiring_completion_contract.log.jsonl}"
TARGET_DIR="${FRANKENLIBC_HARD_PARTS_REPLAY_WIRING_TARGET_DIR:-${OUT_DIR}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" "${TARGET_DIR}" <<'PY'
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
out_dir = Path(sys.argv[5])
source_commit = sys.argv[6]
target_dir = sys.argv[7]

SCHEMA = "hard_parts_replay_wiring_completion_contract.v1"
BEAD_ID = "bd-bp8fl.2.8.1"
ORIGINAL_BEAD = "bd-bp8fl.2.8"
GATE_BEAD = "bd-bp8fl.5.9"
TRACE_ID = "bd-bp8fl.2.8.1::hard-parts-replay-wiring::v1"
REQUIRED_CHILDREN = [f"bd-bp8fl.5.{index}" for index in range(1, 9)]
REQUIRED_GATE_DEPENDENTS = [ORIGINAL_BEAD, *REQUIRED_CHILDREN]
REQUIRED_EVENTS = {
    "source_artifacts_validated",
    "source_replay_validated",
    "dependency_wiring_verified",
    "hard_parts_replay_wiring_completion_contract_validated",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "destructive_tracker_command",
    "missing_source_artifact",
    "source_replay_failed",
    "missing_tracker_dependency",
    "tracker_cycle_detected",
    "missing_completion_binding",
    "completion_output_contract_failed",
]

errors: list[dict] = []
events: list[dict] = []


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {str(row.get("failure_signature")) for row in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "completion_contract_failed"


def load_json(path: Path, label: str):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("malformed_contract", f"{label}: cannot parse {rel(path)}: {exc}")
        return {}


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def event(name: str, status: str, artifact_refs: list[str], failure_signature: str = "none") -> dict:
    return {
        "timestamp": now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "event": name,
        "status": status,
        "artifact_refs": sorted(set(artifact_refs)),
        "source_commit": source_commit,
        "target_dir": target_dir,
        "failure_signature": failure_signature,
    }


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def require_string(row: dict, field: str, ctx: str) -> str:
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    add_error("malformed_contract", f"{ctx}.{field}: must be non-empty string")
    return ""


def require_array(row: dict, field: str, ctx: str) -> list:
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    add_error("malformed_contract", f"{ctx}.{field}: must be non-empty array")
    return []


def fail_report(stage: str, extra_artifacts: list[str] | None = None) -> None:
    artifact_refs = [rel(contract_path), *(extra_artifacts or [])]
    events.append(event(stage, "fail", artifact_refs, primary_signature()))
    report = {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "replay_gate_bead": GATE_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": "fail",
        "summary": {
            "source_artifact_count": 0,
            "source_replay_status": "not_run",
            "dependency_edge_count": 0,
            "missing_item_count": 0,
            "log_row_count": len(events),
        },
        "source_replay": {},
        "dependency_wiring": {},
        "missing_item_bindings": [],
        "artifact_refs": sorted(set(artifact_refs)),
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, events)
    raise SystemExit(1)


contract = load_json(contract_path, "contract")
if not isinstance(contract, dict):
    add_error("malformed_contract", "contract must be a JSON object")
    fail_report("contract_parse_failed")

if contract.get("schema_version") != SCHEMA:
    add_error("malformed_contract", f"schema_version must be {SCHEMA}")
if contract.get("bead_id") != BEAD_ID:
    add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
if contract.get("original_bead") != ORIGINAL_BEAD:
    add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
if contract.get("replay_gate_bead") != GATE_BEAD:
    add_error("malformed_contract", f"replay_gate_bead must be {GATE_BEAD}")
if contract.get("trace_id") != TRACE_ID:
    add_error("malformed_contract", f"trace_id must be {TRACE_ID}")

source_artifacts = require_array(contract, "source_artifacts", "contract")
source_artifact_refs: list[str] = []
for index, artifact in enumerate(source_artifacts):
    if not isinstance(artifact, dict):
        add_error("malformed_contract", f"source_artifacts[{index}] must be object")
        continue
    artifact_id = require_string(artifact, "id", f"source_artifacts[{index}]")
    path_text = require_string(artifact, "path", f"source_artifacts[{index}]")
    require_string(artifact, "role", f"source_artifacts[{index}]")
    if not path_text:
        continue
    path = resolve(path_text)
    if not path.exists():
        add_error("missing_source_artifact", f"{artifact_id}: missing {path_text}")
    else:
        source_artifact_refs.append(path_text)

if errors:
    fail_report("source_artifacts_failed", source_artifact_refs)
events.append(event("source_artifacts_validated", "pass", source_artifact_refs))

dependency_wiring = contract.get("dependency_wiring")
if not isinstance(dependency_wiring, dict):
    add_error("malformed_contract", "dependency_wiring must be object")
    fail_report("dependency_wiring_contract_failed", source_artifact_refs)

for command_text in require_array(dependency_wiring, "read_only_commands", "dependency_wiring"):
    if not isinstance(command_text, str) or not command_text:
        add_error("malformed_contract", "read_only_commands entries must be non-empty strings")
        continue
    forbidden = [
        fragment
        for fragment in dependency_wiring.get("forbidden_command_fragments", [])
        if isinstance(fragment, str) and fragment and fragment in command_text
    ]
    if forbidden:
        add_error(
            "destructive_tracker_command",
            f"read_only command {command_text!r} contains forbidden fragments {forbidden}",
        )
    argv = shlex.split(command_text)
    if argv[:2] not in (["br", "show"], ["br", "dep"]):
        add_error("destructive_tracker_command", f"unsupported tracker command {command_text!r}")
    if "--no-db" not in argv or "--json" not in argv:
        add_error("destructive_tracker_command", f"tracker command must use --no-db --json: {command_text!r}")
if errors:
    fail_report("read_only_tracker_policy_failed", source_artifact_refs)

missing_item_bindings = require_array(contract, "missing_item_bindings", "contract")
unit_bindings = [row for row in missing_item_bindings if isinstance(row, dict) and row.get("spec_item") == "tests.unit.primary"]
if len(unit_bindings) != 1:
    add_error("missing_completion_binding", "exactly one tests.unit.primary binding is required")
else:
    binding = unit_bindings[0]
    for field in ["implementation_refs", "test_refs", "required_positive_tests", "required_negative_tests"]:
        refs = require_array(binding, field, "missing_item_bindings[tests.unit.primary]")
        if field.endswith("_refs"):
            for ref_text in refs:
                if not isinstance(ref_text, str) or not resolve(ref_text).exists():
                    add_error("missing_completion_binding", f"{field} contains missing path {ref_text!r}")
if errors:
    fail_report("missing_item_binding_failed", source_artifact_refs)

source_replay = contract.get("source_replay")
if not isinstance(source_replay, dict):
    add_error("malformed_contract", "source_replay must be object")
    fail_report("source_replay_contract_failed", source_artifact_refs)

source_out = out_dir / "hard_parts_replay_wiring_source"
source_report = source_out / "source-hard-parts-replay.report.json"
source_log = source_out / "source-hard-parts-replay.log.jsonl"
source_env = os.environ.copy()
source_env.update(
    {
        "FRANKENLIBC_HARD_PARTS_REPLAY_GATE": str(resolve(require_string(source_replay, "manifest", "source_replay"))),
        "FRANKENLIBC_HARD_PARTS_REPLAY_OUT_DIR": str(source_out),
        "FRANKENLIBC_HARD_PARTS_REPLAY_REPORT": str(source_report),
        "FRANKENLIBC_HARD_PARTS_REPLAY_LOG": str(source_log),
        "FRANKENLIBC_HARD_PARTS_REPLAY_TARGET_DIR": str(source_out),
    }
)
source_checker = resolve(require_string(source_replay, "checker", "source_replay"))
try:
    completed = subprocess.run(
        ["bash", str(source_checker)],
        cwd=root,
        env=source_env,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
except subprocess.TimeoutExpired:
    add_error("source_replay_failed", "source hard-parts replay checker timed out")
    fail_report("source_replay_failed", [rel(source_checker), rel(source_report), rel(source_log)])

if completed.returncode != 0:
    add_error(
        "source_replay_failed",
        "source hard-parts replay checker failed "
        f"rc={completed.returncode} stdout={completed.stdout[-1200:]} stderr={completed.stderr[-1200:]}",
    )
    fail_report("source_replay_failed", [rel(source_checker), rel(source_report), rel(source_log)])

source_report_json = load_json(source_report, "source replay report")
if source_report_json.get("status") != source_replay.get("required_status"):
    add_error("source_replay_failed", "source replay report did not pass")
summary = source_report_json.get("summary", {})
for key, expected in source_replay.get("required_summary", {}).items():
    if not isinstance(summary, dict) or summary.get(key) != expected:
        add_error("source_replay_failed", f"source replay summary {key} expected {expected}, got {summary.get(key) if isinstance(summary, dict) else None}")
for field in source_replay.get("required_report_fields", []):
    if field not in source_report_json:
        add_error("source_replay_failed", f"source replay report missing field {field}")
try:
    source_log_rows = [
        json.loads(line)
        for line in source_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
except Exception as exc:
    add_error("source_replay_failed", f"source replay log cannot be parsed: {exc}")
    source_log_rows = []
for row in source_log_rows:
    for field in source_replay.get("required_log_fields", []):
        if field not in row:
            add_error("source_replay_failed", f"source replay log row missing field {field}")
if errors:
    fail_report("source_replay_report_failed", [rel(source_checker), rel(source_report), rel(source_log)])
events.append(event("source_replay_validated", "pass", [rel(source_checker), rel(source_report), rel(source_log)]))


def run_json_command(command_text: str):
    try:
        completed = subprocess.run(
            shlex.split(command_text),
            cwd=root,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        add_error("missing_tracker_dependency", f"tracker command timed out: {command_text}")
        return None
    if completed.returncode != 0:
        add_error(
            "missing_tracker_dependency",
            f"tracker command failed rc={completed.returncode}: {command_text}; stderr={completed.stderr[-800:]}",
        )
        return None
    try:
        return json.loads(completed.stdout)
    except Exception as exc:
        add_error("missing_tracker_dependency", f"tracker command produced invalid JSON: {command_text}: {exc}")
        return None


gate_bead = dependency_wiring.get("gate_bead")
if gate_bead != GATE_BEAD:
    add_error("missing_tracker_dependency", f"dependency_wiring.gate_bead must be {GATE_BEAD}")
if dependency_wiring.get("required_closed_children") != REQUIRED_CHILDREN:
    add_error("missing_tracker_dependency", f"required_closed_children must be {REQUIRED_CHILDREN}")
if dependency_wiring.get("required_gate_dependents") != REQUIRED_GATE_DEPENDENTS:
    add_error("missing_tracker_dependency", f"required_gate_dependents must be {REQUIRED_GATE_DEPENDENTS}")

edge_count = 0
for child in REQUIRED_CHILDREN:
    rows = run_json_command(f"br show {child} --no-db --json")
    if not isinstance(rows, list) or not rows:
        continue
    row = rows[0]
    if row.get("status") != dependency_wiring.get("required_child_status"):
        add_error("missing_tracker_dependency", f"{child} status is {row.get('status')}, expected closed")
    deps = row.get("dependencies") or []
    matching = [
        dep for dep in deps
        if dep.get("id") == GATE_BEAD and dep.get("dependency_type") == dependency_wiring.get("required_dependency_type")
    ]
    if not matching:
        add_error("missing_tracker_dependency", f"{child} is not wired to {GATE_BEAD} as a blocks dependency")
    else:
        edge_count += 1

gate_rows = run_json_command(f"br show {GATE_BEAD} --no-db --json")
if isinstance(gate_rows, list) and gate_rows:
    gate_row = gate_rows[0]
    if gate_row.get("status") != dependency_wiring.get("required_gate_status"):
        add_error("missing_tracker_dependency", f"{GATE_BEAD} status is {gate_row.get('status')}, expected closed")
    dependents = gate_row.get("dependents") or []
    dependent_ids = {
        dep.get("id")
        for dep in dependents
        if dep.get("dependency_type") == dependency_wiring.get("required_dependency_type")
    }
    missing = sorted(set(REQUIRED_GATE_DEPENDENTS) - dependent_ids)
    if missing:
        add_error("missing_tracker_dependency", f"{GATE_BEAD} missing expected blocks dependents {missing}")

cycles = run_json_command("br dep cycles --no-db --json")
if isinstance(cycles, dict) and int(cycles.get("count", -1)) != 0:
    add_error("tracker_cycle_detected", f"tracker dependency cycles reported: {cycles}")
if errors:
    fail_report("dependency_wiring_failed", [rel(source_report), rel(source_log)])
events.append(
    event(
        "dependency_wiring_verified",
        "pass",
        [rel(contract_path), rel(source_report), rel(source_log), ".beads/issues.jsonl"],
    )
)

completion_output = contract.get("completion_output_contract", {})
if not isinstance(completion_output, dict):
    add_error("completion_output_contract_failed", "completion_output_contract must be object")
for required in REQUIRED_EVENTS:
    if required not in {row.get("event") for row in events} and required != "hard_parts_replay_wiring_completion_contract_validated":
        add_error("completion_output_contract_failed", f"missing required event {required}")

artifact_refs = sorted(
    set(
        [
            rel(contract_path),
            rel(report_path),
            rel(log_path),
            rel(source_report),
            rel(source_log),
            *source_artifact_refs,
        ]
    )
)
summary = {
    "source_artifact_count": len(source_artifact_refs),
    "source_replay_status": source_report_json.get("status"),
    "source_replay_log_rows": len(source_log_rows),
    "dependency_edge_count": edge_count,
    "required_child_count": len(REQUIRED_CHILDREN),
    "missing_item_count": len(missing_item_bindings),
    "log_row_count": len(events) + 1,
    "tracker_mode": dependency_wiring.get("tracker_mode"),
}
events.append(
    event(
        "hard_parts_replay_wiring_completion_contract_validated",
        "pass",
        artifact_refs,
    )
)
report = {
    "schema_version": f"{SCHEMA}.report",
    "bead_id": BEAD_ID,
    "original_bead": ORIGINAL_BEAD,
    "replay_gate_bead": GATE_BEAD,
    "trace_id": TRACE_ID,
    "source_commit": source_commit,
    "status": "pass",
    "summary": summary,
    "source_replay": {
        "checker": rel(source_checker),
        "report": rel(source_report),
        "log": rel(source_log),
        "status": source_report_json.get("status"),
        "summary": source_report_json.get("summary", {}),
    },
    "dependency_wiring": {
        "gate_bead": GATE_BEAD,
        "required_children": REQUIRED_CHILDREN,
        "required_gate_dependents": REQUIRED_GATE_DEPENDENTS,
        "verified_edge_count": edge_count,
        "cycle_count": 0,
    },
    "missing_item_bindings": missing_item_bindings,
    "artifact_refs": artifact_refs,
    "errors": [],
}
for field in completion_output.get("required_report_fields", []):
    if field not in report:
        add_error("completion_output_contract_failed", f"report missing required field {field}")
for row in events:
    for field in completion_output.get("required_log_fields", []):
        if field not in row:
            add_error("completion_output_contract_failed", f"log event {row.get('event')} missing field {field}")
if REQUIRED_EVENTS - {row.get("event") for row in events}:
    add_error("completion_output_contract_failed", f"missing events {sorted(REQUIRED_EVENTS - {row.get('event') for row in events})}")
if errors:
    fail_report("completion_output_contract_failed", artifact_refs)

write_json(report_path, report)
write_jsonl(log_path, events)
print(
    "PASS: hard-parts replay wiring completion contract validated "
    f"source_artifacts={summary['source_artifact_count']} "
    f"dependency_edges={summary['dependency_edge_count']} "
    f"log_rows={summary['log_row_count']}"
)
PY
