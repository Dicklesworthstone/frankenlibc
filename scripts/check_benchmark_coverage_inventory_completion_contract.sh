#!/usr/bin/env bash
# Validate bd-bp8fl.8.1.1 benchmark coverage inventory completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_BENCHMARK_COVERAGE_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/benchmark_coverage_inventory_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_BENCHMARK_COVERAGE_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/benchmark_coverage_inventory_completion}"
REPORT="${FRANKENLIBC_BENCHMARK_COVERAGE_COMPLETION_REPORT:-${OUT_DIR}/benchmark_coverage_inventory_completion_contract.report.json}"
LOG="${FRANKENLIBC_BENCHMARK_COVERAGE_COMPLETION_LOG:-${OUT_DIR}/benchmark_coverage_inventory_completion_contract.events.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT = pathlib.Path(sys.argv[2]).resolve()
REPORT = pathlib.Path(sys.argv[3]).resolve()
LOG = pathlib.Path(sys.argv[4]).resolve()

SCHEMA = "benchmark_coverage_inventory_completion_contract.v1"
REPORT_SCHEMA = "benchmark_coverage_inventory_completion_contract.report.v1"
LOG_SCHEMA = "benchmark_coverage_inventory_completion_contract.log.v1"
ORIGINAL_BEAD = "bd-bp8fl.8.1"
COMPLETION_BEAD = "bd-bp8fl.8.1.1"
EXPECTED_MISSING = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_SOURCE_IDS = {
    "benchmark_inventory_artifact",
    "benchmark_inventory_generator",
    "benchmark_inventory_gate",
    "benchmark_inventory_harness",
    "completion_contract",
    "completion_checker",
    "completion_harness",
}
REQUIRED_TESTS = {
    "committed_inventory_artifact_preserves_required_scope",
    "family_rows_name_benchmarks_baselines_workloads_and_next_actions",
    "inventory_rows_are_symbol_mode_owned_and_actionable",
    "generator_self_test_canonical_check_and_stale_artifact_rejection_pass",
    "gate_script_emits_valid_report_and_structured_jsonl",
    "check_benchmark_coverage_inventory.sh",
    "generate_benchmark_coverage_inventory.py --check",
    "benchmark_coverage_inventory.v1.json",
    "checker_accepts_contract_and_emits_telemetry",
}
REQUIRED_COMMANDS = {
    "bash scripts/check_benchmark_coverage_inventory.sh",
    "bash scripts/check_benchmark_coverage_inventory_completion_contract.sh",
    "python3 -m py_compile scripts/generate_benchmark_coverage_inventory.py",
    "python3 scripts/generate_benchmark_coverage_inventory.py --self-test",
    "python3 scripts/generate_benchmark_coverage_inventory.py --check --output tests/conformance/benchmark_coverage_inventory.v1.json --target-dir target/conformance",
    "rch exec -- cargo test -p frankenlibc-harness --test benchmark_coverage_inventory_test -- --nocapture",
    "rch exec -- cargo test -p frankenlibc-harness --test benchmark_coverage_inventory_completion_contract_test -- --nocapture",
    "rch exec -- cargo clippy -p frankenlibc-harness --test benchmark_coverage_inventory_completion_contract_test -- -D warnings",
}
REQUIRED_EVENTS = {
    "benchmark_coverage_inventory.source_artifacts_validated",
    "benchmark_coverage_inventory.inventory_expectations_validated",
    "benchmark_coverage_inventory.unit_binding_validated",
    "benchmark_coverage_inventory.e2e_binding_validated",
    "benchmark_coverage_inventory.conformance_binding_validated",
    "benchmark_coverage_inventory.telemetry_binding_validated",
    "benchmark_coverage_inventory.completion_contract_validated",
    "benchmark_coverage_inventory.completion_contract_failed",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
source_count = 0
implementation_ref_count = 0
test_binding_count = 0
binding_count = 0
family_count = 0
inventory_row_count = 0
missing_inventory_row_count = 0


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


SOURCE_COMMIT = source_commit()


def error(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        error(message)


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        error(f"{label} unreadable: {rel(path)}: {exc}")
        return {}


def string_array(value: Any, label: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        error(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            error(f"{label}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": LOG_SCHEMA,
            "timestamp": utc_now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}",
            "event": event,
            "level": "info" if status == "pass" else "error",
            "status": status,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "source_commit": SOURCE_COMMIT,
            "artifact_refs": [rel(CONTRACT), rel(REPORT)],
            "details": details,
        }
    )


def validate_file_line_ref(value: Any, label: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        error(f"{label} must be file:line")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        error(f"{label} must be file:line")
        return
    path = ROOT / path_text
    if not path.is_file():
        error(f"{label} references missing file: {value}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines):
        error(f"{label} references line past EOF: {value}")
    elif not lines[line_no - 1].strip():
        error(f"{label} references blank line: {value}")


def validate_sources(contract: dict[str, Any]) -> None:
    global source_count
    sources = contract.get("source_artifacts")
    if not isinstance(sources, list):
        error("source_artifacts must be an array")
        return
    ids: set[str] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            error(f"source_artifacts[{index}] must be an object")
            continue
        source_id = source.get("id")
        path_text = source.get("path")
        if not isinstance(source_id, str) or not source_id:
            error(f"source_artifacts[{index}].id must be a non-empty string")
            continue
        ids.add(source_id)
        if not isinstance(path_text, str) or not path_text:
            error(f"source artifact {source_id} path must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            error(f"source artifact {source_id} missing: {path_text}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for needle in string_array(source.get("required_needles"), f"{source_id}.required_needles"):
            if needle not in text:
                error(f"source artifact {source_id} missing required needle: {needle}")
        if source_id == "benchmark_inventory_gate" and not (path.stat().st_mode & stat.S_IXUSR):
            error("scripts/check_benchmark_coverage_inventory.sh must be executable")
        if source_id == "completion_checker" and not (path.stat().st_mode & stat.S_IXUSR):
            error("scripts/check_benchmark_coverage_inventory_completion_contract.sh must be executable")
    missing = REQUIRED_SOURCE_IDS - ids
    extra = ids - REQUIRED_SOURCE_IDS
    if missing:
        error(f"source_artifacts missing required ids: {sorted(missing)}")
    if extra:
        error(f"source_artifacts contains unexpected ids: {sorted(extra)}")
    source_count = len(ids)
    append_event(
        "benchmark_coverage_inventory.source_artifacts_validated",
        "pass" if not errors else "fail",
        {"source_count": source_count},
    )


def run_command(argv: list[str], description: str, env: dict[str, str] | None = None) -> str:
    child_env = None
    if env is not None:
        child_env = os.environ.copy()
        child_env.update(env)
    proc = subprocess.run(
        argv,
        cwd=ROOT,
        env=child_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        error(
            f"{description} failed: status={proc.returncode} "
            f"stdout={proc.stdout[-1000:]} stderr={proc.stderr[-1000:]}"
        )
    return proc.stdout


def validate_inventory_expectations(contract: dict[str, Any]) -> None:
    global family_count, inventory_row_count, missing_inventory_row_count
    expectations = contract.get("inventory_expectations", {})
    require(isinstance(expectations, dict), "inventory_expectations must be object")
    artifact = load_json(ROOT / "tests/conformance/benchmark_coverage_inventory.v1.json", "benchmark coverage inventory")
    if not isinstance(artifact, dict):
        return
    require(artifact.get("schema_version") == expectations.get("schema_version") == "v1", "inventory schema_version drifted")
    require(artifact.get("bead") == expectations.get("bead") == ORIGINAL_BEAD, "inventory bead drifted")
    require(isinstance(artifact.get("artifact_hash"), str) and bool(artifact.get("artifact_hash")), "inventory artifact_hash must be present")
    summary = artifact.get("summary", {})
    require(isinstance(summary, dict), "inventory summary must be object")
    families = artifact.get("families", [])
    bench_targets = artifact.get("bench_targets", [])
    rows = artifact.get("inventory_rows", [])
    family_count = len(families) if isinstance(families, list) else 0
    inventory_row_count = len(rows) if isinstance(rows, list) else 0
    missing_inventory_row_count = int(summary.get("missing_inventory_row_count", -1)) if isinstance(summary, dict) else -1
    require(family_count == expectations.get("family_count"), "inventory family_count expectation drifted")
    require(summary.get("family_count") == family_count, "inventory summary family_count mismatch")
    require(summary.get("required_family_count") == expectations.get("required_family_count"), "inventory required_family_count drifted")
    require(isinstance(bench_targets, list) and len(bench_targets) == expectations.get("actual_bench_target_count"), "inventory bench target count drifted")
    require(summary.get("actual_bench_target_count") == expectations.get("actual_bench_target_count"), "inventory summary actual_bench_target_count drifted")
    require(inventory_row_count == expectations.get("inventory_row_count"), "inventory row count drifted")
    require(summary.get("inventory_row_count") == inventory_row_count, "inventory summary inventory_row_count mismatch")
    require(summary.get("covered_inventory_row_count") == expectations.get("covered_inventory_row_count"), "covered inventory row count drifted")
    require(summary.get("missing_inventory_row_count") == expectations.get("missing_inventory_row_count"), "missing inventory row count drifted")
    require(summary.get("missing_owner_row_count") == expectations.get("missing_owner_row_count"), "missing owner row count drifted")
    require(len(artifact.get("required_log_fields", [])) == expectations.get("required_log_field_count"), "required log field count drifted")
    require(len(artifact.get("required_inventory_row_fields", [])) == expectations.get("required_inventory_row_field_count"), "required inventory row field count drifted")
    require(len(artifact.get("prioritized_hot_paths", [])) == expectations.get("prioritized_hot_path_count"), "prioritized hot path count drifted")
    require(
        set(summary.get("fully_baselined_families", [])) == set(expectations.get("fully_baselined_families", [])),
        "fully baselined families drifted",
    )
    require(
        set(summary.get("missing_required_baseline_families", [])) == set(expectations.get("missing_required_baseline_families", [])),
        "missing required baseline families drifted",
    )
    follow_ups = {
        row.get("bead")
        for row in artifact.get("follow_up_beads", [])
        if isinstance(row, dict)
    }
    require(follow_ups == set(expectations.get("follow_up_beads", [])), "follow-up bead set drifted")
    required_families = {"string", "malloc", "stdio", "pthread", "syscall", "membrane"}
    family_ids = {row.get("family") for row in families if isinstance(row, dict)}
    require(required_families.issubset(family_ids), f"missing required families: {sorted(required_families - family_ids)}")
    if isinstance(rows, list):
        ownerless = [
            row.get("row_id")
            for row in rows
            if not isinstance(row, dict)
            or not isinstance(row.get("owner_bead"), str)
            or not str(row.get("owner_bead")).startswith("bd-")
        ]
        require(not ownerless, f"inventory rows missing owner beads: {ownerless[:10]}")
    append_event(
        "benchmark_coverage_inventory.inventory_expectations_validated",
        "pass" if not errors else "fail",
        {
            "family_count": family_count,
            "inventory_row_count": inventory_row_count,
            "missing_inventory_row_count": missing_inventory_row_count,
        },
    )


def run_base_gates() -> None:
    base_gate_dir = REPORT.parent / "benchmark_coverage_inventory_base_gate"
    generator_check_dir = base_gate_dir / "generator_check"
    base_gate_dir.mkdir(parents=True, exist_ok=True)
    generator_check_dir.mkdir(parents=True, exist_ok=True)
    gate_report = base_gate_dir / "benchmark_coverage_inventory.report.json"
    gate_log = base_gate_dir / "benchmark_coverage_inventory.log.jsonl"

    run_command(["python3", "-m", "py_compile", "scripts/generate_benchmark_coverage_inventory.py"], "generator py_compile")
    run_command(["python3", "scripts/generate_benchmark_coverage_inventory.py", "--self-test"], "generator self-test")
    run_command(
        [
            "python3",
            "scripts/generate_benchmark_coverage_inventory.py",
            "--check",
            "--output",
            "tests/conformance/benchmark_coverage_inventory.v1.json",
            "--target-dir",
            str(generator_check_dir),
        ],
        "generator canonical check",
    )
    gate_stdout = run_command(
        ["bash", "scripts/check_benchmark_coverage_inventory.sh"],
        "benchmark coverage gate",
        {
            "FRANKENLIBC_BENCHMARK_COVERAGE_REPORT": str(gate_report),
            "FRANKENLIBC_BENCHMARK_COVERAGE_LOG": str(gate_log),
        },
    )
    if "check_benchmark_coverage_inventory: PASS" not in gate_stdout:
        error("benchmark coverage gate did not print PASS marker")


def validate_contract(contract: dict[str, Any]) -> None:
    global implementation_ref_count, test_binding_count, binding_count
    require(contract.get("schema_version") == SCHEMA, "schema_version drifted")
    require(contract.get("original_bead") == ORIGINAL_BEAD, "original_bead drifted")
    require(contract.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead drifted")
    audit = contract.get("audit_reference", {})
    require(isinstance(audit, dict), "audit_reference must be object")
    require(audit.get("score_before") == 470, "audit_reference.score_before drifted")
    require(audit.get("score_threshold") == 800, "audit_reference.score_threshold must be 800")
    evidence = contract.get("completion_debt_evidence", {})
    require(isinstance(evidence, dict), "completion_debt_evidence must be object")
    missing_items = set(string_array(evidence.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed"))
    if missing_items != EXPECTED_MISSING:
        error(f"missing_items_closed drifted: {sorted(missing_items)}")
    refs = string_array(contract.get("implementation_refs"), "implementation_refs")
    implementation_ref_count = len(refs)
    for index, reference in enumerate(refs):
        validate_file_line_ref(reference, f"implementation_refs[{index}]")
    bindings = contract.get("completion_bindings")
    if not isinstance(bindings, list):
        error("completion_bindings must be array")
        return
    binding_count = len(bindings)
    seen_missing: set[str] = set()
    tests: set[str] = set()
    commands: set[str] = set()
    events_required: set[str] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            error(f"completion_bindings[{index}] must be object")
            continue
        missing_item = binding.get("missing_item_id")
        if not isinstance(missing_item, str) or not missing_item:
            error(f"completion_bindings[{index}].missing_item_id must be non-empty string")
        else:
            seen_missing.add(missing_item)
        for row in binding.get("required_test_refs", []):
            if isinstance(row, dict) and isinstance(row.get("name"), str):
                tests.add(row["name"])
        commands.update(string_array(binding.get("required_commands"), f"completion_bindings[{index}].required_commands"))
        events_required.update(string_array(binding.get("required_completion_events"), f"completion_bindings[{index}].required_completion_events"))
        event_name = {
            "tests.unit.primary": "benchmark_coverage_inventory.unit_binding_validated",
            "tests.e2e.primary": "benchmark_coverage_inventory.e2e_binding_validated",
            "tests.conformance.primary": "benchmark_coverage_inventory.conformance_binding_validated",
            "telemetry.primary": "benchmark_coverage_inventory.telemetry_binding_validated",
        }.get(str(missing_item))
        if event_name:
            append_event(event_name, "pass" if not errors else "fail", {"missing_item_id": missing_item})
    test_binding_count = len(tests)
    if seen_missing != EXPECTED_MISSING:
        error(f"completion_bindings missing items drifted: {sorted(seen_missing)}")
    if not REQUIRED_TESTS.issubset(tests):
        error(f"completion_bindings required_test_refs missing {sorted(REQUIRED_TESTS - tests)}")
    if not REQUIRED_COMMANDS.issubset(commands):
        error(f"completion_bindings required_commands missing {sorted(REQUIRED_COMMANDS - commands)}")
    if not REQUIRED_EVENTS.issubset(events_required):
        error(f"completion_bindings required_completion_events missing {sorted(REQUIRED_EVENTS - events_required)}")


def write_outputs(contract: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    event = (
        "benchmark_coverage_inventory.completion_contract_failed"
        if errors
        else "benchmark_coverage_inventory.completion_contract_validated"
    )
    append_event(event, status, {"error_count": len(errors)})
    evidence = contract.get("completion_debt_evidence", {}) if isinstance(contract, dict) else {}
    report = {
        "schema_version": REPORT_SCHEMA,
        "timestamp": utc_now(),
        "event": event,
        "status": status,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": SOURCE_COMMIT,
        "missing_items_bound": sorted(evidence.get("missing_items_closed", []))
        if isinstance(evidence, dict)
        else [],
        "source_count": source_count,
        "implementation_ref_count": implementation_ref_count,
        "test_binding_count": test_binding_count,
        "binding_count": binding_count,
        "family_count": family_count,
        "inventory_row_count": inventory_row_count,
        "missing_inventory_row_count": missing_inventory_row_count,
        "artifact_refs": [rel(CONTRACT), rel(LOG)],
        "failure_signature": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("\n".join(json.dumps(row, sort_keys=True) for row in events) + "\n", encoding="utf-8")


contract_data = load_json(CONTRACT, "completion contract")
if not isinstance(contract_data, dict):
    contract_data = {}
validate_sources(contract_data)
validate_inventory_expectations(contract_data)
run_base_gates()
validate_contract(contract_data)
write_outputs(contract_data)

if errors:
    print("FAIL benchmark coverage inventory completion contract")
    for item in errors:
        print(f"- {item}")
    sys.exit(1)

print(
    "PASS benchmark coverage inventory completion contract "
    f"sources={source_count} bindings={binding_count} rows={inventory_row_count} events={len(events)}"
)
PY
