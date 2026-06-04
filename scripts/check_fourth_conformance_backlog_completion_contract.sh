#!/usr/bin/env bash
# check_fourth_conformance_backlog_completion_contract.sh -- bd-gmbqy.12 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_FOURTH_CONFORMANCE_BACKLOG_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/fourth_conformance_backlog_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_FOURTH_CONFORMANCE_BACKLOG_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/fourth_conformance_backlog_completion}"
REPORT="${FRANKENLIBC_FOURTH_CONFORMANCE_BACKLOG_COMPLETION_REPORT:-${OUT_DIR}/fourth_conformance_backlog_completion_contract.report.json}"
LOG="${FRANKENLIBC_FOURTH_CONFORMANCE_BACKLOG_COMPLETION_LOG:-${OUT_DIR}/fourth_conformance_backlog_completion_contract.events.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
LOG = pathlib.Path(sys.argv[4])
SOURCE_COMMIT = sys.argv[5]

SCHEMA = "fourth_conformance_backlog_completion_contract.v1"
REPORT_SCHEMA = "fourth_conformance_backlog_completion_contract.report.v1"
BEAD_ID = "bd-gmbqy.12"
PARENT_BEAD = "bd-gmbqy"
TRACE_ID = "bd-gmbqy.12::fourth-conformance-backlog::completion::v1"

REQUIRED_ARTIFACT_IDS = {
    "symbol_fixture_coverage",
    "per_symbol_fixture_tests",
    "fixture_coverage_prioritizer",
    "symbol_fixture_coverage_gate",
    "per_symbol_fixture_tests_gate",
    "fixture_coverage_prioritizer_gate",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_fourth_conformance_backlog_closeout",
    "checker_accepts_fourth_conformance_backlog_completion_contract",
    "checker_emits_completion_telemetry",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_child_commit_ref",
    "checker_rejects_stale_completed_wave_symbol",
    "checker_rejects_per_symbol_case_count_drift",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "child_closeout_drift",
    "coverage_artifact_drift",
    "completed_fixture_drift",
    "prioritizer_stale_wave",
    "base_gate_failed",
    "missing_test_binding",
    "missing_telemetry_binding",
]

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []
artifact_refs: set[str] = {str(CONTRACT)}


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else ROOT / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "fourth_conformance_backlog.completion_contract_failed"


def event(name: str, status: str, failure_signature: str = "none", **fields: Any) -> dict[str, Any]:
    return {
        "schema_version": "fourth_conformance_backlog_completion_contract.event.v1",
        "timestamp": now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "event": name,
        "status": status,
        "bead_id": BEAD_ID,
        "parent_bead": PARENT_BEAD,
        "source_commit": SOURCE_COMMIT,
        "artifact_refs": sorted(artifact_refs),
        "failure_signature": failure_signature,
        **fields,
    }


def load_json(path: pathlib.Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def as_object(value: Any, context: str, signature: str = "malformed_contract") -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def as_array(value: Any, context: str, signature: str = "malformed_contract") -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def string_array(value: Any, context: str, signature: str) -> list[str]:
    rows = as_array(value, context, signature)
    result = [row for row in rows if isinstance(row, str)]
    if len(result) != len(rows):
        add_error(signature, f"{context} must contain only strings")
    return result


def string_set(value: Any, context: str, signature: str) -> set[str]:
    return set(string_array(value, context, signature))


def number_equals(actual: Any, expected: Any, context: str, signature: str = "coverage_artifact_drift") -> None:
    if actual != expected:
        add_error(signature, f"{context}: expected {expected!r}, got {actual!r}")


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def run_gate(command: list[str], label: str) -> None:
    try:
        output = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90,
            check=False,
        )
    except Exception as exc:
        add_error("base_gate_failed", f"{label}: failed to run: {exc}")
        return
    if output.returncode != 0:
        add_error(
            "base_gate_failed",
            f"{label}: exit={output.returncode} stdout={output.stdout[-1200:]} stderr={output.stderr[-1200:]}",
        )
        return
    if label == "br_dep_cycles":
        try:
            payload = json.loads(output.stdout)
            cycle_count = payload.get("count")
            if cycle_count is None and isinstance(payload.get("cycles"), list):
                cycle_count = len(payload["cycles"])
            if cycle_count != 0:
                add_error("base_gate_failed", f"{label}: expected zero cycles, got {payload!r}")
        except Exception as exc:
            add_error("base_gate_failed", f"{label}: invalid JSON output: {exc}")


def validate_source_artifacts(contract: dict[str, Any]) -> None:
    artifacts: dict[str, dict[str, Any]] = {}
    for row in as_array(contract.get("source_artifacts"), "source_artifacts"):
        obj = as_object(row, "source_artifacts[]")
        artifact_id = obj.get("id")
        path = obj.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            add_error("malformed_contract", "source artifact id must be a non-empty string")
            continue
        if not isinstance(path, str) or not path:
            add_error("malformed_contract", f"source artifact {artifact_id} path must be non-empty")
            continue
        artifacts[artifact_id] = obj
        resolved = resolve(path)
        artifact_refs.add(rel(resolved))
        if not resolved.exists():
            add_error("missing_source_artifact", f"missing source artifact {artifact_id}: {path}")
    missing = sorted(REQUIRED_ARTIFACT_IDS - set(artifacts))
    if missing:
        add_error("missing_source_artifact", f"missing source artifact ids: {missing}")
    events.append(
        event(
            "fourth_conformance_backlog.source_artifacts_validated",
            "pass" if not missing else "fail",
            "none" if not missing else "missing_source_artifact",
            artifact_count=len(artifacts),
        )
    )


def validate_child_closeouts(contract: dict[str, Any]) -> dict[str, str]:
    snapshot = as_object(contract.get("tracker_snapshot"), "tracker_snapshot")
    required_ids = string_set(snapshot.get("required_child_ids"), "tracker_snapshot.required_child_ids", "child_closeout_drift")
    closeouts = as_array(snapshot.get("child_closeouts"), "tracker_snapshot.child_closeouts", "child_closeout_drift")
    expected_ids = {f"bd-gmbqy.{idx}" for idx in range(1, 12)}
    fixture_by_child: dict[str, str] = {}
    if snapshot.get("required_closed_child_count") != 11:
        add_error("child_closeout_drift", f"required_closed_child_count expected 11, got {snapshot.get('required_closed_child_count')!r}")
    if required_ids != expected_ids:
        add_error("child_closeout_drift", f"required_child_ids drift: expected {sorted(expected_ids)}, got {sorted(required_ids)}")
    seen: set[str] = set()
    for row in closeouts:
        obj = as_object(row, "tracker_snapshot.child_closeouts[]", "child_closeout_drift")
        child_id = obj.get("id")
        if isinstance(child_id, str):
            seen.add(child_id)
        if child_id not in expected_ids:
            add_error("child_closeout_drift", f"unexpected child closeout id {child_id!r}")
        if obj.get("status") != "closed":
            add_error("child_closeout_drift", f"{child_id} status must be closed, got {obj.get('status')!r}")
        commit_refs = string_array(obj.get("commit_refs"), f"child_closeout {child_id} commit_refs", "child_closeout_drift")
        if not commit_refs:
            add_error("child_closeout_drift", f"{child_id} must include at least one commit ref")
        fragments = string_array(obj.get("evidence_fragments"), f"child_closeout {child_id} evidence_fragments", "child_closeout_drift")
        if len(fragments) < 2:
            add_error("child_closeout_drift", f"{child_id} must bind at least two evidence fragments")
        fixture = obj.get("fixture")
        if not isinstance(fixture, str) or not fixture:
            add_error("child_closeout_drift", f"{child_id} must bind a fixture path")
        else:
            fixture_by_child[str(child_id)] = fixture
            if not resolve(fixture).exists():
                add_error("child_closeout_drift", f"{child_id} fixture does not exist: {fixture}")
    if seen != expected_ids:
        add_error("child_closeout_drift", f"child closeout set drift: missing {sorted(expected_ids - seen)} extra {sorted(seen - expected_ids)}")
    events.append(
        event(
            "fourth_conformance_backlog.child_closeouts_validated",
            "pass" if not any(e["failure_signature"] == "child_closeout_drift" for e in errors) else "fail",
            "none" if not any(e["failure_signature"] == "child_closeout_drift" for e in errors) else "child_closeout_drift",
            child_count=len(seen),
        )
    )
    return fixture_by_child


def validate_coverage(contract: dict[str, Any]) -> None:
    expected = as_object(contract.get("coverage_expectations"), "coverage_expectations")
    symbol = load_json(ROOT / "tests/conformance/symbol_fixture_coverage.v1.json", "symbol fixture coverage", "coverage_artifact_drift")
    per_symbol = load_json(ROOT / "tests/conformance/per_symbol_fixture_tests.v1.json", "per-symbol fixture tests", "coverage_artifact_drift")
    prioritizer = load_json(ROOT / "tests/conformance/fixture_coverage_prioritizer.v1.json", "fixture coverage prioritizer", "coverage_artifact_drift")

    symbol_summary = as_object(symbol.get("summary"), "symbol_fixture_coverage.summary", "coverage_artifact_drift")
    for key, value in as_object(expected.get("symbol_fixture_coverage"), "coverage_expectations.symbol_fixture_coverage").items():
        number_equals(symbol_summary.get(key), value, f"symbol_fixture_coverage.summary.{key}")

    per_symbol_summary = as_object(per_symbol.get("summary"), "per_symbol_fixture_tests.summary", "coverage_artifact_drift")
    for key, value in as_object(expected.get("per_symbol_fixture_tests"), "coverage_expectations.per_symbol_fixture_tests").items():
        number_equals(per_symbol_summary.get(key), value, f"per_symbol_fixture_tests.summary.{key}")

    prioritizer_summary = as_object(prioritizer.get("summary"), "fixture_coverage_prioritizer.summary", "coverage_artifact_drift")
    prioritizer_expected = as_object(expected.get("fixture_coverage_prioritizer"), "coverage_expectations.fixture_coverage_prioritizer")
    for key in [
        "campaign_count",
        "selected_target_uncovered_symbols",
        "all_uncovered_target_symbols",
        "total_first_wave_fixture_count",
    ]:
        number_equals(prioritizer_summary.get(key), prioritizer_expected.get(key), f"fixture_coverage_prioritizer.summary.{key}")
    required_modules = set(string_array(prioritizer_expected.get("required_covered_modules"), "required_covered_modules", "coverage_artifact_drift"))
    actual_modules = set(string_array(prioritizer_summary.get("covered_modules"), "summary.covered_modules", "coverage_artifact_drift"))
    if not required_modules.issubset(actual_modules):
        add_error("coverage_artifact_drift", f"missing covered modules: {sorted(required_modules - actual_modules)}")
    events.append(
        event(
            "fourth_conformance_backlog.coverage_artifacts_validated",
            "pass" if not any(e["failure_signature"] == "coverage_artifact_drift" for e in errors) else "fail",
            "none" if not any(e["failure_signature"] == "coverage_artifact_drift" for e in errors) else "coverage_artifact_drift",
            covered_symbols=symbol_summary.get("target_covered_symbols"),
            fixture_cases=per_symbol_summary.get("total_cases"),
        )
    )


def validate_completed_wave_fixtures(contract: dict[str, Any], fixture_by_child: dict[str, str]) -> set[str]:
    completed_symbols: set[str] = set()
    rows = as_array(contract.get("completed_wave_fixtures"), "completed_wave_fixtures", "completed_fixture_drift")
    expected_ids = {f"bd-gmbqy.{idx}" for idx in range(1, 12)}
    seen_ids: set[str] = set()
    for row in rows:
        obj = as_object(row, "completed_wave_fixtures[]", "completed_fixture_drift")
        bead = obj.get("bead")
        campaign_id = obj.get("campaign_id")
        path_text = obj.get("path")
        symbols = string_array(obj.get("completed_symbols"), f"completed_wave_fixtures {bead} completed_symbols", "completed_fixture_drift")
        if isinstance(bead, str):
            seen_ids.add(bead)
        if bead not in expected_ids:
            add_error("completed_fixture_drift", f"unexpected completed wave bead {bead!r}")
        if fixture_by_child.get(str(bead)) != path_text:
            add_error("completed_fixture_drift", f"{bead} fixture path does not match child closeout")
        if not isinstance(path_text, str):
            add_error("completed_fixture_drift", f"{bead} path must be a string")
            continue
        fixture = as_object(load_json(resolve(path_text), f"completed fixture {path_text}", "completed_fixture_drift"), f"completed fixture {path_text}", "completed_fixture_drift")
        campaign = as_object(fixture.get("campaign"), f"{path_text}.campaign", "completed_fixture_drift")
        if campaign.get("bead") != bead:
            add_error("completed_fixture_drift", f"{path_text} campaign.bead expected {bead!r}, got {campaign.get('bead')!r}")
        if campaign.get("campaign_id") != campaign_id:
            add_error("completed_fixture_drift", f"{path_text} campaign_id expected {campaign_id!r}, got {campaign.get('campaign_id')!r}")
        actual_symbols = string_array(campaign.get("first_wave_symbols"), f"{path_text}.campaign.first_wave_symbols", "completed_fixture_drift")
        if actual_symbols != symbols:
            add_error("completed_fixture_drift", f"{path_text} first_wave_symbols drift: expected {symbols}, got {actual_symbols}")
        for symbol in symbols:
            if symbol in completed_symbols:
                add_error("completed_fixture_drift", f"duplicate completed symbol {symbol}")
            completed_symbols.add(symbol)
    if seen_ids != expected_ids:
        add_error("completed_fixture_drift", f"completed fixture set drift: missing {sorted(expected_ids - seen_ids)} extra {sorted(seen_ids - expected_ids)}")
    events.append(
        event(
            "fourth_conformance_backlog.completed_wave_fixtures_validated",
            "pass" if not any(e["failure_signature"] == "completed_fixture_drift" for e in errors) else "fail",
            "none" if not any(e["failure_signature"] == "completed_fixture_drift" for e in errors) else "completed_fixture_drift",
            completed_symbol_count=len(completed_symbols),
        )
    )
    return completed_symbols


def validate_prioritizer_advancement(contract: dict[str, Any], completed_symbols: set[str]) -> None:
    advancement = as_object(contract.get("prioritizer_advancement"), "prioritizer_advancement")
    expected_completed_count = advancement.get("completed_wave_symbol_count")
    if expected_completed_count != len(completed_symbols):
        add_error("prioritizer_stale_wave", f"completed_wave_symbol_count expected {expected_completed_count!r}, derived {len(completed_symbols)}")
    prioritizer = load_json(ROOT / "tests/conformance/fixture_coverage_prioritizer.v1.json", "fixture coverage prioritizer", "prioritizer_stale_wave")
    campaigns = as_array(prioritizer.get("campaigns"), "fixture_coverage_prioritizer.campaigns", "prioritizer_stale_wave")
    by_id: dict[str, dict[str, Any]] = {}
    current_first_wave: set[str] = set()
    for row in campaigns:
        obj = as_object(row, "campaigns[]", "prioritizer_stale_wave")
        campaign_id = obj.get("campaign_id")
        if isinstance(campaign_id, str):
            by_id[campaign_id] = obj
        current_first_wave.update(string_array(obj.get("first_wave_symbols"), f"campaign {campaign_id} first_wave_symbols", "prioritizer_stale_wave"))
    stale = sorted(completed_symbols.intersection(current_first_wave))
    if stale:
        add_error("prioritizer_stale_wave", f"completed fourth-wave symbols still advertised as first-wave work: {stale}")
    for retired in string_array(advancement.get("retired_campaign_ids"), "prioritizer_advancement.retired_campaign_ids", "prioritizer_stale_wave"):
        if retired in by_id:
            add_error("prioritizer_stale_wave", f"retired campaign still present in prioritizer: {retired}")
    for row in as_array(advancement.get("current_campaign_first_wave"), "prioritizer_advancement.current_campaign_first_wave", "prioritizer_stale_wave"):
        expected = as_object(row, "current_campaign_first_wave[]", "prioritizer_stale_wave")
        campaign_id = expected.get("campaign_id")
        actual = by_id.get(campaign_id)
        if actual is None:
            add_error("prioritizer_stale_wave", f"missing current campaign {campaign_id!r}")
            continue
        expected_symbols = string_array(expected.get("first_wave_symbols"), f"{campaign_id}.first_wave_symbols", "prioritizer_stale_wave")
        actual_symbols = string_array(actual.get("first_wave_symbols"), f"actual {campaign_id}.first_wave_symbols", "prioritizer_stale_wave")
        if actual_symbols != expected_symbols:
            add_error("prioritizer_stale_wave", f"{campaign_id} first_wave_symbols drift: expected {expected_symbols}, got {actual_symbols}")
        for key in ["current_coverage_pct", "target_covered", "target_uncovered"]:
            if actual.get(key) != expected.get(key):
                add_error("prioritizer_stale_wave", f"{campaign_id}.{key} expected {expected.get(key)!r}, got {actual.get(key)!r}")
    events.append(
        event(
            "fourth_conformance_backlog.prioritizer_advancement_validated",
            "pass" if not any(e["failure_signature"] == "prioritizer_stale_wave" for e in errors) else "fail",
            "none" if not any(e["failure_signature"] == "prioritizer_stale_wave" for e in errors) else "prioritizer_stale_wave",
            completed_symbol_count=len(completed_symbols),
            current_campaign_count=len(by_id),
        )
    )


def validate_base_gates() -> None:
    run_gate(["bash", "scripts/check_symbol_fixture_coverage.sh"], "symbol_fixture_coverage")
    run_gate(["bash", "scripts/check_per_symbol_fixture_tests.sh", "--validate-only"], "per_symbol_fixture_tests")
    run_gate(["bash", "scripts/check_fixture_coverage_prioritizer.sh"], "fixture_coverage_prioritizer")
    run_gate(["br", "--no-db", "dep", "cycles", "--json"], "br_dep_cycles")
    events.append(
        event(
            "fourth_conformance_backlog.base_gates_validated",
            "pass" if not any(e["failure_signature"] == "base_gate_failed" for e in errors) else "fail",
            "none" if not any(e["failure_signature"] == "base_gate_failed" for e in errors) else "base_gate_failed",
        )
    )


def validate_test_surface(contract: dict[str, Any]) -> None:
    required = as_object(contract.get("required_test_functions"), "required_test_functions")
    required_tests = set(string_array(required.get("positive"), "required_test_functions.positive", "missing_test_binding"))
    required_tests.update(string_array(required.get("negative"), "required_test_functions.negative", "missing_test_binding"))
    if not REQUIRED_POSITIVE_TESTS.issubset(required_tests) or not REQUIRED_NEGATIVE_TESTS.issubset(required_tests):
        add_error("missing_test_binding", "required_test_functions must include the positive and negative contract test names")
    test_path = ROOT / "crates/frankenlibc-harness/tests/fourth_conformance_backlog_completion_contract_test.rs"
    try:
        artifact_refs.add(rel(test_path))
        text = test_path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error("missing_test_binding", f"cannot read completion test: {exc}")
        text = ""
    missing_tests = sorted(test for test in required_tests if test not in text)
    if missing_tests:
        add_error("missing_test_binding", f"missing test functions: {missing_tests}")
    events.append(
        event(
            "fourth_conformance_backlog.test_surface_validated",
            "pass" if not missing_tests else "fail",
            "none" if not missing_tests else "missing_test_binding",
            test_count=len(required_tests),
        )
    )


def validate_telemetry(contract: dict[str, Any]) -> None:
    telemetry = as_object(contract.get("telemetry_contract"), "telemetry_contract")
    required = set(string_array(telemetry.get("required_events"), "telemetry_contract.required_events", "missing_telemetry_binding"))
    emitted = {row["event"] for row in events}
    missing_events = sorted(required - emitted - {"fourth_conformance_backlog.completion_contract_validated"})
    required_fields = set(string_array(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields", "missing_telemetry_binding"))
    sample = event("fourth_conformance_backlog.completion_contract_validated", "pass")
    missing_fields = sorted(required_fields - set(sample))
    if missing_events:
        add_error("missing_telemetry_binding", f"missing telemetry events before final event: {missing_events}")
    if missing_fields:
        add_error("missing_telemetry_binding", f"missing telemetry fields: {missing_fields}")


contract = load_json(CONTRACT, "contract")
contract_obj = as_object(contract, "contract")
if contract_obj.get("schema_version") != SCHEMA:
    add_error("malformed_contract", f"schema_version must be {SCHEMA}")
if contract_obj.get("bead_id") != BEAD_ID:
    add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
if contract_obj.get("parent_bead") != PARENT_BEAD:
    add_error("malformed_contract", f"parent_bead must be {PARENT_BEAD}")
if contract_obj.get("trace_id") != TRACE_ID:
    add_error("malformed_contract", f"trace_id must be {TRACE_ID}")

validate_source_artifacts(contract_obj)
fixture_by_child = validate_child_closeouts(contract_obj)
validate_coverage(contract_obj)
completed_symbols = validate_completed_wave_fixtures(contract_obj, fixture_by_child)
validate_prioritizer_advancement(contract_obj, completed_symbols)
validate_base_gates()
validate_test_surface(contract_obj)
validate_telemetry(contract_obj)

summary_expectations = as_object(contract_obj.get("coverage_expectations"), "coverage_expectations")
symbol_expectations = as_object(
    summary_expectations.get("symbol_fixture_coverage"),
    "coverage_expectations.symbol_fixture_coverage",
)
per_symbol_expectations = as_object(
    summary_expectations.get("per_symbol_fixture_tests"),
    "coverage_expectations.per_symbol_fixture_tests",
)
prioritizer_expectations = as_object(
    summary_expectations.get("fixture_coverage_prioritizer"),
    "coverage_expectations.fixture_coverage_prioritizer",
)

status = "pass" if not errors else "fail"
failure_signature = "none" if not errors else primary_signature()
events.append(
    event(
        "fourth_conformance_backlog.completion_contract_validated" if status == "pass" else "fourth_conformance_backlog.completion_contract_failed",
        status,
        failure_signature,
        error_count=len(errors),
    )
)

report = {
    "schema_version": REPORT_SCHEMA,
    "trace_id": TRACE_ID,
    "bead_id": BEAD_ID,
    "parent_bead": PARENT_BEAD,
    "status": status,
    "failure_signature": failure_signature,
    "source_commit": SOURCE_COMMIT,
    "artifact_refs": sorted(artifact_refs),
    "errors": errors,
    "summary": {
        "closed_child_count": 11,
        "completed_wave_symbol_count": len(completed_symbols),
        "target_covered_symbols": symbol_expectations.get("target_covered_symbols"),
        "symbols_with_fixtures": per_symbol_expectations.get("symbols_with_fixtures"),
        "fixture_cases": per_symbol_expectations.get("total_cases"),
        "selected_target_uncovered_symbols": prioritizer_expectations.get(
            "selected_target_uncovered_symbols"
        ),
    },
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if status == "pass":
    print(f"PASS fourth conformance backlog completion contract ({REPORT})")
    sys.exit(0)

print(f"FAIL fourth conformance backlog completion contract: {failure_signature} ({REPORT})", file=sys.stderr)
for error in errors:
    print(f"{error['failure_signature']}: {error['message']}", file=sys.stderr)
sys.exit(1)
PY
