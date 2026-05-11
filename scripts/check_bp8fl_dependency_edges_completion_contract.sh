#!/usr/bin/env bash
# Validate bd-bp8fl.2.9.1 dependency-edge completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_BP8FL_DEPENDENCY_EDGES_CONTRACT:-${1:-${ROOT}/tests/conformance/bp8fl_dependency_edges_completion_contract.v1.json}}"
OUT_DIR="${FRANKENLIBC_BP8FL_DEPENDENCY_EDGES_OUT_DIR:-${2:-${ROOT}/target/conformance}}"
REPORT="${FRANKENLIBC_BP8FL_DEPENDENCY_EDGES_REPORT:-${OUT_DIR}/bp8fl_dependency_edges_completion_contract.report.json}"
LOG="${FRANKENLIBC_BP8FL_DEPENDENCY_EDGES_LOG:-${OUT_DIR}/bp8fl_dependency_edges_completion_contract.log.jsonl}"
TARGET_DIR="${FRANKENLIBC_BP8FL_DEPENDENCY_EDGES_TARGET_DIR:-${OUT_DIR}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${TARGET_DIR}" "${SOURCE_COMMIT}" <<'PY'
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
target_dir = sys.argv[5]
source_commit = sys.argv[6]
tracker_fixture_path = os.environ.get("FRANKENLIBC_BP8FL_DEPENDENCY_EDGES_TRACKER_FIXTURE")
tracker_fixture: dict[str, Any] | None = None

SCHEMA = "bp8fl_dependency_edges_completion_contract.v1"
BEAD_ID = "bd-bp8fl.2.9.1"
ORIGINAL_BEAD = "bd-bp8fl.2.9"
TRACE_ID = "bd-bp8fl.2.9.1::dependency-edges::v1"
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "destructive_tracker_command",
    "missing_completion_binding",
    "tracker_command_failed",
    "missing_tracker_dependency",
    "tracker_cycle_detected",
    "bv_cycle_break_failed",
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


if tracker_fixture_path:
    loaded_fixture = load_json(Path(tracker_fixture_path), "tracker fixture")
    if isinstance(loaded_fixture, dict):
        tracker_fixture = loaded_fixture
    else:
        add_error("malformed_contract", "tracker fixture must be a JSON object")


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def require(condition: bool, signature: str, message: str) -> None:
    if not condition:
        add_error(signature, message)


def require_string(row: dict[str, Any], field: str, ctx: str) -> str:
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    add_error("malformed_contract", f"{ctx}.{field} must be a non-empty string")
    return ""


def require_array(row: dict[str, Any], field: str, ctx: str) -> list[Any]:
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    add_error("malformed_contract", f"{ctx}.{field} must be a non-empty array")
    return []


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
        "target_dir": target_dir,
        "failure_signature": failure_signature,
    }


def fail_report(stage: str, source_artifact_refs: list[str] | None = None) -> None:
    artifact_refs = sorted(set([rel(contract_path), rel(report_path), rel(log_path), *(source_artifact_refs or [])]))
    events.append(
        event(
            f"{stage}_failed",
            "fail",
            stage,
            "completion contract passes",
            primary_signature(),
            artifact_refs,
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
            "verified_edge_count": 0,
            "required_edge_count": 0,
            "cycle_count": None,
            "bv_cycle_count": None,
            "log_row_count": len(events),
        },
        "dependency_edges": [],
        "cycle_proof": {},
        "bv_cycle_break": {},
        "missing_item_bindings": [],
        "source_artifacts": source_artifact_refs or [],
        "artifact_refs": artifact_refs,
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, events)
    raise SystemExit(1)


def command_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("TMPDIR", "/data/tmp" if Path("/data/tmp").is_dir() else str(root / "target"))
    return env


def run_json_command(argv: list[str], failure_signature: str, timeout: int = 90) -> Any | None:
    if tracker_fixture is not None:
        if argv[:2] == ["br", "show"] and len(argv) >= 3:
            shows = tracker_fixture.get("shows")
            if isinstance(shows, dict) and argv[2] in shows:
                return shows[argv[2]]
            add_error(failure_signature, f"tracker fixture missing br show row for {argv[2]}")
            return None
        if argv == ["br", "dep", "cycles", "--no-db", "--json"]:
            cycles = tracker_fixture.get("cycles")
            if isinstance(cycles, dict):
                return cycles
            add_error(failure_signature, "tracker fixture missing cycles object")
            return None
        if argv == ["bv", "--robot-insights"]:
            insights = tracker_fixture.get("bv_insights")
            if isinstance(insights, dict):
                return insights
            add_error(failure_signature, "tracker fixture missing bv_insights object")
            return None
        add_error(failure_signature, f"tracker fixture does not support command {shlex.join(argv)}")
        return None

    try:
        completed = subprocess.run(
            argv,
            cwd=root,
            env=command_env(),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        add_error(failure_signature, f"command timed out: {shlex.join(argv)}")
        return None
    if completed.returncode != 0:
        add_error(
            failure_signature,
            f"command failed rc={completed.returncode}: {shlex.join(argv)}; stderr={completed.stderr[-1200:]}",
        )
        return None
    try:
        return json.loads(completed.stdout)
    except Exception as exc:
        add_error(failure_signature, f"command produced invalid JSON: {shlex.join(argv)}: {exc}")
        return None


def validate_source_artifacts(contract: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    source_artifacts = require_array(contract, "source_artifacts", "contract")
    for index, artifact in enumerate(source_artifacts):
        if not isinstance(artifact, dict):
            add_error("malformed_contract", f"source_artifacts[{index}] must be an object")
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
            refs.append(path_text)
    if errors:
        fail_report("source_artifacts", refs)
    events.append(
        event(
            "source_artifacts_validated",
            "pass",
            "source-artifacts",
            "all declared source artifacts exist",
            len(refs),
            refs,
        )
    )
    return refs


def validate_manifest_shape(contract: dict[str, Any]) -> None:
    require(contract.get("schema_version") == SCHEMA, "malformed_contract", f"schema_version must be {SCHEMA}")
    require(contract.get("bead") == BEAD_ID, "malformed_contract", f"bead must be {BEAD_ID}")
    require(contract.get("original_bead") == ORIGINAL_BEAD, "malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
    require(contract.get("trace_id") == TRACE_ID, "malformed_contract", f"trace_id must be {TRACE_ID}")


def validate_read_only_policy(dependency_edges: dict[str, Any], source_artifact_refs: list[str]) -> None:
    forbidden_fragments = [
        fragment
        for fragment in dependency_edges.get("forbidden_command_fragments", [])
        if isinstance(fragment, str) and fragment
    ]
    for command_text in require_array(dependency_edges, "read_only_commands", "dependency_edges"):
        if not isinstance(command_text, str) or not command_text:
            add_error("malformed_contract", "read_only_commands entries must be non-empty strings")
            continue
        forbidden = [fragment for fragment in forbidden_fragments if fragment in command_text]
        if forbidden:
            add_error("destructive_tracker_command", f"read-only command {command_text!r} contains {forbidden}")
            continue
        argv = shlex.split(command_text)
        if argv[:2] == ["br", "show"] or argv[:2] == ["br", "dep"]:
            if "--no-db" not in argv or "--json" not in argv:
                add_error("destructive_tracker_command", f"br command must use --no-db --json: {command_text!r}")
        elif argv == ["bv", "--robot-insights"]:
            pass
        else:
            add_error("destructive_tracker_command", f"unsupported read-only command {command_text!r}")
    if errors:
        fail_report("read_only_policy", source_artifact_refs)
    events.append(
        event(
            "read_only_policy_validated",
            "pass",
            "read-only-tracker-policy",
            "no destructive tracker commands",
            "ok",
            [rel(contract_path), *source_artifact_refs],
        )
    )


def validate_missing_item_bindings(contract: dict[str, Any], source_artifact_refs: list[str]) -> list[dict[str, Any]]:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        add_error("malformed_contract", "completion_debt_evidence must be an object")
        fail_report("completion_debt_evidence", source_artifact_refs)
    bindings = require_array(evidence, "missing_item_bindings", "completion_debt_evidence")
    binding_ids = {binding.get("spec_item") for binding in bindings if isinstance(binding, dict)}
    require(
        binding_ids == REQUIRED_MISSING_ITEMS,
        "missing_completion_binding",
        f"missing item bindings must be {sorted(REQUIRED_MISSING_ITEMS)}, got {sorted(str(item) for item in binding_ids)}",
    )
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            add_error("malformed_contract", f"missing_item_bindings[{index}] must be an object")
            continue
        spec_item = require_string(binding, "spec_item", f"missing_item_bindings[{index}]")
        for field in ["implementation_refs", "test_refs"]:
            for ref_text in require_array(binding, field, f"missing_item_bindings[{spec_item}]"):
                if not isinstance(ref_text, str) or not resolve(ref_text).exists():
                    add_error("missing_completion_binding", f"{spec_item}.{field} contains missing path {ref_text!r}")
        if spec_item == "tests.unit.primary":
            require_array(binding, "required_positive_tests", f"missing_item_bindings[{spec_item}]")
            require_array(binding, "required_negative_tests", f"missing_item_bindings[{spec_item}]")
        if spec_item == "tests.e2e.primary":
            commands = require_array(binding, "required_commands", f"missing_item_bindings[{spec_item}]")
            for command in commands:
                if isinstance(command, str) and "cargo " in command:
                    require(
                        command.startswith("rch exec --"),
                        "missing_completion_binding",
                        f"cargo command must run through rch: {command}",
                    )
            require(
                any(command == "br dep cycles --no-db --json" for command in commands if isinstance(command, str)),
                "missing_completion_binding",
                "tests.e2e.primary must name br dep cycles --no-db --json",
            )
            require(
                any(command == "bv --robot-insights" for command in commands if isinstance(command, str)),
                "missing_completion_binding",
                "tests.e2e.primary must name bv --robot-insights",
            )
    if errors:
        fail_report("missing_item_bindings", source_artifact_refs)
    events.append(
        event(
            "missing_item_bindings_validated",
            "pass",
            "completion-debt-bindings",
            sorted(REQUIRED_MISSING_ITEMS),
            sorted(binding_ids),
            [rel(contract_path), *source_artifact_refs],
        )
    )
    return [binding for binding in bindings if isinstance(binding, dict)]


def show_bead(bead_id: str) -> dict[str, Any] | None:
    rows = run_json_command(["br", "show", bead_id, "--no-db", "--json"], "tracker_command_failed")
    if not isinstance(rows, list) or not rows:
        add_error("missing_tracker_dependency", f"br show returned no row for {bead_id}")
        return None
    if not isinstance(rows[0], dict):
        add_error("missing_tracker_dependency", f"br show row for {bead_id} is not an object")
        return None
    return rows[0]


def validate_original_close_reason(source_artifact_refs: list[str]) -> dict[str, Any] | None:
    row = show_bead(ORIGINAL_BEAD)
    if row is None:
        return None
    require(row.get("status") == "closed", "missing_tracker_dependency", f"{ORIGINAL_BEAD} must be closed")
    close_reason = str(row.get("close_reason", ""))
    for phrase in [
        "bd-bp8fl.10.4 depends on bd-bp8fl.10.8",
        "bd-bp8fl.6.4 depends on bd-bp8fl.6.6",
        "bd-bp8fl.8.4 depends on bd-bp8fl.8.6",
        "br dep cycles --no-db --json returned count 0",
        "No cycles detected",
    ]:
        require(phrase in close_reason, "missing_tracker_dependency", f"{ORIGINAL_BEAD} close reason missing {phrase!r}")
    return row


def validate_dependency_edges(dependency_edges: dict[str, Any], source_artifact_refs: list[str]) -> list[dict[str, Any]]:
    required_type = dependency_edges.get("required_dependency_type")
    source_status = dependency_edges.get("required_source_status")
    target_status = dependency_edges.get("required_target_status")
    rows = require_array(dependency_edges, "edges", "dependency_edges")
    edge_reports: list[dict[str, Any]] = []
    for index, edge in enumerate(rows):
        if not isinstance(edge, dict):
            add_error("malformed_contract", f"dependency_edges.edges[{index}] must be an object")
            continue
        edge_id = require_string(edge, "edge_id", f"dependency_edges.edges[{index}]")
        source = require_string(edge, "source", f"dependency_edges.edges[{index}]")
        target = require_string(edge, "target", f"dependency_edges.edges[{index}]")
        scenario_id = require_string(edge, "scenario_id", f"dependency_edges.edges[{index}]")
        if not source or not target:
            continue
        source_row = show_bead(source)
        target_row = show_bead(target)
        if source_row is None or target_row is None:
            continue
        require(source_row.get("status") == source_status, "missing_tracker_dependency", f"{source} status mismatch")
        require(target_row.get("status") == target_status, "missing_tracker_dependency", f"{target} status mismatch")
        dependencies = source_row.get("dependencies") or []
        dependents = target_row.get("dependents") or []
        forward = any(
            isinstance(dep, dict) and dep.get("id") == target and dep.get("dependency_type") == required_type
            for dep in dependencies
        )
        reverse = any(
            isinstance(dep, dict) and dep.get("id") == source and dep.get("dependency_type") == required_type
            for dep in dependents
        )
        require(forward, "missing_tracker_dependency", f"{source} does not depend on {target} as {required_type}")
        require(reverse, "missing_tracker_dependency", f"{target} does not list {source} as {required_type} dependent")
        edge_reports.append(
            {
                "edge_id": edge_id,
                "scenario_id": scenario_id,
                "source": source,
                "target": target,
                "dependency_type": required_type,
                "source_status": source_row.get("status"),
                "target_status": target_row.get("status"),
                "forward_edge_present": forward,
                "reverse_edge_present": reverse,
            }
        )
        events.append(
            event(
                "dependency_edge_verified",
                "pass" if forward and reverse else "fail",
                scenario_id,
                {"source": source, "target": target, "dependency_type": required_type},
                {"forward_edge_present": forward, "reverse_edge_present": reverse},
                [rel(contract_path), ".beads/issues.jsonl"],
                "none" if forward and reverse else "missing_tracker_dependency",
            )
        )
    if errors:
        fail_report("dependency_edges", source_artifact_refs)
    events.append(
        event(
            "dependency_edges_verified",
            "pass",
            "dependency-edge-set",
            len(rows),
            len(edge_reports),
            [rel(contract_path), ".beads/issues.jsonl"],
        )
    )
    return edge_reports


def validate_cycles(source_artifact_refs: list[str]) -> dict[str, Any]:
    cycles = run_json_command(["br", "dep", "cycles", "--no-db", "--json"], "tracker_command_failed")
    cycle_count = None
    if isinstance(cycles, dict):
        cycle_count = cycles.get("count")
    require(cycle_count == 0, "tracker_cycle_detected", f"br dep cycles count must be 0, got {cycle_count}")
    if errors:
        fail_report("tracker_cycles", source_artifact_refs)
    proof = {"command": "br dep cycles --no-db --json", "count": cycle_count}
    events.append(
        event(
            "tracker_cycles_verified",
            "pass",
            "tracker-cycle-proof",
            0,
            cycle_count,
            [rel(contract_path), ".beads/issues.jsonl"],
        )
    )
    return proof


def validate_bv_cycle_break(contract: dict[str, Any], source_artifact_refs: list[str]) -> dict[str, Any]:
    evidence = contract.get("completion_debt_evidence") if isinstance(contract.get("completion_debt_evidence"), dict) else {}
    required = evidence.get("required_bv_cycle_break") if isinstance(evidence, dict) else {}
    if not isinstance(required, dict):
        add_error("malformed_contract", "completion_debt_evidence.required_bv_cycle_break must be an object")
        fail_report("bv_cycle_break", source_artifact_refs)
    insights = run_json_command(["bv", "--robot-insights"], "bv_cycle_break_failed", timeout=180)
    cycle_break = {}
    if isinstance(insights, dict):
        advanced = insights.get("advanced_insights")
        if isinstance(advanced, dict):
            maybe_cycle_break = advanced.get("cycle_break")
            if isinstance(maybe_cycle_break, dict):
                cycle_break = maybe_cycle_break
    state = None
    status = cycle_break.get("status")
    if isinstance(status, dict):
        state = status.get("state")
    cycle_count = cycle_break.get("cycle_count")
    advisory = str(cycle_break.get("advisory", ""))
    require(state == required.get("status_state"), "bv_cycle_break_failed", f"bv cycle_break state must be {required.get('status_state')}, got {state}")
    require(cycle_count == required.get("cycle_count"), "bv_cycle_break_failed", f"bv cycle_break cycle_count must be {required.get('cycle_count')}, got {cycle_count}")
    for term in required.get("advisory_terms", []):
        require(isinstance(term, str) and term in advisory, "bv_cycle_break_failed", f"bv advisory missing {term!r}")
    if errors:
        fail_report("bv_cycle_break", source_artifact_refs)
    proof = {
        "command": "bv --robot-insights",
        "status_state": state,
        "cycle_count": cycle_count,
        "advisory": advisory,
    }
    events.append(
        event(
            "bv_cycle_break_verified",
            "pass",
            "bv-cycle-break-proof",
            {"state": required.get("status_state"), "cycle_count": required.get("cycle_count")},
            {"state": state, "cycle_count": cycle_count},
            [rel(contract_path)],
        )
    )
    return proof


contract = load_json(contract_path, "contract")
if not isinstance(contract, dict):
    add_error("malformed_contract", "contract must be a JSON object")
    fail_report("contract_parse")

validate_manifest_shape(contract)
if errors:
    fail_report("manifest_shape")
source_artifact_refs = validate_source_artifacts(contract)
dependency_edges = contract.get("dependency_edges")
if not isinstance(dependency_edges, dict):
    add_error("malformed_contract", "dependency_edges must be an object")
    fail_report("dependency_edges_shape", source_artifact_refs)
validate_read_only_policy(dependency_edges, source_artifact_refs)
missing_item_bindings = validate_missing_item_bindings(contract, source_artifact_refs)
validate_original_close_reason(source_artifact_refs)
edge_reports = validate_dependency_edges(dependency_edges, source_artifact_refs)
cycle_proof = validate_cycles(source_artifact_refs)
bv_cycle_break = validate_bv_cycle_break(contract, source_artifact_refs)

artifact_refs = sorted(set([rel(contract_path), rel(report_path), rel(log_path), ".beads/issues.jsonl", *source_artifact_refs]))
summary = {
    "source_artifact_count": len(source_artifact_refs),
    "required_edge_count": len(dependency_edges.get("edges", [])),
    "verified_edge_count": len(edge_reports),
    "cycle_count": cycle_proof.get("count"),
    "bv_cycle_count": bv_cycle_break.get("cycle_count"),
    "missing_item_count": len(missing_item_bindings),
    "log_row_count": len(events) + 1,
    "tracker_mode": dependency_edges.get("tracker_mode"),
}
events.append(
    event(
        "bp8fl_dependency_edges_completion_contract_validated",
        "pass",
        "completion-contract-output",
        {"verified_edge_count": 3, "cycle_count": 0, "bv_cycle_count": 0},
        {
            "verified_edge_count": summary["verified_edge_count"],
            "cycle_count": summary["cycle_count"],
            "bv_cycle_count": summary["bv_cycle_count"],
        },
        artifact_refs,
    )
)

report = {
    "schema_version": f"{SCHEMA}.report",
    "bead_id": BEAD_ID,
    "original_bead": ORIGINAL_BEAD,
    "trace_id": TRACE_ID,
    "source_commit": source_commit,
    "status": "pass",
    "summary": summary,
    "dependency_edges": edge_reports,
    "cycle_proof": cycle_proof,
    "bv_cycle_break": bv_cycle_break,
    "missing_item_bindings": missing_item_bindings,
    "source_artifacts": source_artifact_refs,
    "artifact_refs": artifact_refs,
    "errors": [],
}

completion_output = contract.get("completion_output_contract")
if not isinstance(completion_output, dict):
    add_error("completion_output_contract_failed", "completion_output_contract must be an object")
else:
    for field in completion_output.get("required_report_fields", []):
        if field not in report:
            add_error("completion_output_contract_failed", f"report missing required field {field}")
    for row in events:
        for field in completion_output.get("required_log_fields", []):
            if field not in row:
                add_error("completion_output_contract_failed", f"log row {row.get('event')} missing field {field}")
    required_events = set(completion_output.get("required_events", []))
    present_events = {row.get("event") for row in events}
    missing_events = required_events - present_events
    if missing_events:
        add_error("completion_output_contract_failed", f"missing events {sorted(missing_events)}")
if errors:
    fail_report("completion_output_contract", artifact_refs)

write_json(report_path, report)
write_jsonl(log_path, events)
print(
    "PASS: bp8fl dependency-edge completion contract validated "
    f"edges={summary['verified_edge_count']} "
    f"cycle_count={summary['cycle_count']} "
    f"bv_cycle_count={summary['bv_cycle_count']} "
    f"log_rows={summary['log_row_count']}"
)
PY
