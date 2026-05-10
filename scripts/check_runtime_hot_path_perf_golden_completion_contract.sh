#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_HOT_PATH_PERF_GOLDEN_CONTRACT:-$ROOT/tests/conformance/runtime_hot_path_perf_golden_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_HOT_PATH_PERF_GOLDEN_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_RUNTIME_HOT_PATH_PERF_GOLDEN_REPORT:-$OUT_DIR/runtime_hot_path_perf_golden_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_HOT_PATH_PERF_GOLDEN_LOG:-$OUT_DIR/runtime_hot_path_perf_golden_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "runtime_hot_path_perf_golden_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "runtime_hot_path_perf_golden_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-73r"
COMPLETION_BEAD = "bd-73r.1"

errors: list[str] = []
events: list[dict[str, Any]] = []


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


def artifact_path(path_text: str, context: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must be a repo-relative path without parent traversal: {path_text}")
        return ROOT / "__invalid__"
    return ROOT / path


def source_text(path_text: str, context: str) -> str:
    path = artifact_path(path_text, context)
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {path_text}: {exc}")
        return ""


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


def append_event(event: str, status: str, outcome: str, artifact_refs: list[str], details: dict[str, Any] | None = None) -> None:
    events.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "source_commit": SOURCE_COMMIT,
            "status": status,
            "outcome": outcome,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "runtime_hot_path_perf_golden_completion_contract_failed",
            "details": details or {},
        }
    )


def write_outputs(manifest: dict[str, Any], status: str, summary: dict[str, Any]) -> None:
    telemetry = manifest.get("telemetry_contract", {}) if isinstance(manifest, dict) else {}
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id") if isinstance(manifest, dict) else None,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "golden": summary.get("golden", {}),
        "budget_targets": summary.get("budget_targets", {}),
        "gate_bindings": summary.get("gate_bindings", {}),
        "events": events,
        "errors": errors,
    }
    for field in as_string_list(telemetry.get("required_report_fields") if isinstance(telemetry, dict) else [], "telemetry_contract.required_report_fields", allow_empty=True):
        if field not in report:
            err(f"report missing telemetry field {field}")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")


def parse_sha256_manifest(path: pathlib.Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    try:
        body = path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"sha256 manifest unreadable: {rel(path)}: {exc}")
        return rows
    for line_no, raw in enumerate(body.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            err(f"sha256 manifest line {line_no} must contain hash and filename")
            continue
        digest, filename = parts
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            err(f"sha256 manifest line {line_no} has invalid lowercase sha256 digest")
            continue
        rows[filename] = digest
    return rows


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("source_artifacts", {})
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    out: dict[str, str] = {}
    for artifact_id, raw_path in artifacts.items():
        if not isinstance(raw_path, str) or not raw_path:
            err(f"source_artifacts.{artifact_id} must be a non-empty string")
            continue
        path = artifact_path(raw_path, f"source_artifacts.{artifact_id}")
        if not path.is_file():
            err(f"source artifact missing: {artifact_id}: {raw_path}")
        out[str(artifact_id)] = raw_path
    return out


def validate_test_refs(manifest: dict[str, Any], artifacts: dict[str, str]) -> None:
    evidence = manifest.get("completion_debt_evidence", {})
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        return
    require(evidence.get("missing_items_closed") == ["tests.golden.primary"], "missing_items_closed must be exactly tests.golden.primary")
    golden = evidence.get("golden_primary", {})
    if not isinstance(golden, dict):
        err("completion_debt_evidence.golden_primary must be an object")
        return
    require(golden.get("missing_item_id") == "tests.golden.primary", "golden_primary missing_item_id mismatch")
    for gate in as_string_list(golden.get("verification_gates"), "golden_primary.verification_gates"):
        require(gate in artifacts.values(), f"verification gate {gate} must be listed in source_artifacts")
    test_sources = {
        "runtime_math_determinism_test": artifacts.get("runtime_math_determinism_test", ""),
        "completion_harness_test": artifacts.get("completion_harness_test", ""),
    }
    texts = {
        key: source_text(path, key)
        for key, path in test_sources.items()
        if path
    }
    for index, ref_obj in enumerate(golden.get("required_test_refs", [])):
        if not isinstance(ref_obj, dict):
            err(f"golden_primary.required_test_refs[{index}] must be an object")
            continue
        source = str(ref_obj.get("source", ""))
        name = str(ref_obj.get("name", ""))
        if source not in texts:
            err(f"unknown test source {source}")
            continue
        require(f"fn {name}" in texts[source] or name in texts[source], f"{source} missing required test {name}")
    for command in as_string_list(golden.get("required_commands"), "golden_primary.required_commands"):
        if "cargo " in command:
            require("rch exec" in command, f"cargo command must be offloaded through rch: {command}")
    require(any("check_runtime_hot_path_perf_golden_completion_contract.sh" in command for command in golden.get("required_commands", [])), "golden command list must include completion checker")


def validate_golden(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    evidence = manifest.get("completion_debt_evidence", {})
    golden = evidence.get("golden_primary", {}) if isinstance(evidence, dict) else {}
    required = manifest.get("required_golden_contract", {})
    if not isinstance(golden, dict) or not isinstance(required, dict):
        err("golden evidence and required_golden_contract must be objects")
        return {}

    snapshot_rel = str(golden.get("golden_source", ""))
    sha_rel = str(golden.get("sha256_manifest", ""))
    snapshot_path = artifact_path(snapshot_rel, "golden_primary.golden_source")
    sha_path = artifact_path(sha_rel, "golden_primary.sha256_manifest")
    expected_name = str(golden.get("expected_filename", ""))
    expected_hash = str(golden.get("expected_sha256", ""))
    require(snapshot_rel == artifacts.get("golden_snapshot"), "golden source must match source_artifacts.golden_snapshot")
    require(sha_rel == artifacts.get("golden_sha256s"), "sha manifest must match source_artifacts.golden_sha256s")
    require(len(expected_hash) == 64, "expected_sha256 must be 64 lowercase hex characters")

    sha_rows = parse_sha256_manifest(sha_path)
    require(expected_name in sha_rows, f"sha256 manifest missing {expected_name}")
    require(sha_rows.get(expected_name) == expected_hash, "sha256 manifest digest does not match contract expected_sha256")
    actual_hash = hashlib.sha256(snapshot_path.read_bytes()).hexdigest() if snapshot_path.is_file() else ""
    require(actual_hash == expected_hash, "golden snapshot hash drift")

    snapshot = load_json(snapshot_path, "golden snapshot")
    require(snapshot.get("version") == "v1", "golden snapshot version must be v1")
    scenario = snapshot.get("scenario", {})
    required_scenario = required.get("scenario", {})
    if not isinstance(scenario, dict) or not isinstance(required_scenario, dict):
        err("snapshot scenario and required scenario must be objects")
        scenario = {}
        required_scenario = {}
    for field in ["id", "seed", "steps"]:
        require(scenario.get(field) == required_scenario.get(field), f"snapshot scenario {field} drift")
    families = set(as_string_list(scenario.get("families"), "snapshot.scenario.families"))
    for family in as_string_list(required_scenario.get("required_families"), "required_golden_contract.scenario.required_families"):
        require(family in families, f"snapshot scenario missing family {family}")

    modes = as_string_list(required.get("modes"), "required_golden_contract.modes")
    required_fields = as_string_list(required.get("required_snapshot_fields"), "required_golden_contract.required_snapshot_fields")
    for mode in modes:
        mode_doc = snapshot.get(mode)
        if not isinstance(mode_doc, dict):
            err(f"snapshot missing mode object {mode}")
            continue
        require(mode_doc.get("mode") == mode, f"snapshot {mode}.mode mismatch")
        snap = mode_doc.get("snapshot")
        if not isinstance(snap, dict):
            err(f"snapshot {mode}.snapshot must be an object")
            continue
        require(snap.get("schema_version") == required.get("snapshot_schema_version"), f"{mode} snapshot schema version drift")
        for field in required_fields:
            require(field in snap, f"{mode} snapshot missing field {field}")

    append_event(
        "runtime_hot_path_perf_golden_hash_verified",
        "pass",
        "golden_hash_verified",
        [snapshot_rel, sha_rel],
        {"sha256": actual_hash, "scenario": scenario},
    )
    return {"snapshot": snapshot_rel, "sha256": actual_hash, "modes": modes, "families": sorted(families)}


def validate_budgets(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    required = manifest.get("required_golden_contract", {})
    targets = required.get("perf_targets_ns", {}) if isinstance(required, dict) else {}
    if not isinstance(targets, dict):
        err("required_golden_contract.perf_targets_ns must be an object")
        targets = {}
    policy = load_json(artifact_path(artifacts.get("perf_budget_policy", ""), "perf_budget_policy"), "perf budget policy")
    baseline = load_json(artifact_path(artifacts.get("perf_baseline", ""), "perf_baseline"), "perf baseline")
    spec = load_json(artifact_path(artifacts.get("perf_baseline_spec", ""), "perf_baseline_spec"), "perf baseline spec")

    strict_budget = policy.get("budgets", {}).get("strict_hotpath", {}) if isinstance(policy.get("budgets"), dict) else {}
    hardened_budget = policy.get("budgets", {}).get("hardened_hotpath", {}) if isinstance(policy.get("budgets"), dict) else {}
    if not isinstance(strict_budget, dict):
        strict_budget = {}
    if not isinstance(hardened_budget, dict):
        hardened_budget = {}
    require(strict_budget.get("strict_mode_ns") == targets.get("strict_hot_path_max"), "strict_hotpath.strict_mode_ns drift")
    require(strict_budget.get("hardened_mode_ns") == targets.get("hardened_hot_path_max"), "strict_hotpath.hardened_mode_ns drift")
    require(hardened_budget.get("hardened_mode_ns") == targets.get("hardened_hot_path_max"), "hardened_hotpath.hardened_mode_ns drift")

    baseline_targets = baseline.get("targets_ns_op", {})
    if not isinstance(baseline_targets, dict):
        err("perf_baseline.targets_ns_op must be an object")
        baseline_targets = {}
    for key in ["decide", "observe_fast", "decide_observe", "validate_null", "validate_foreign", "validate_known", "errno_location_fastpath", "errno_set_then_read_roundtrip"]:
        require(baseline_targets.get("strict", {}).get(key) == targets.get("strict_hot_path_max"), f"strict baseline target {key} drift")
        require(baseline_targets.get("hardened", {}).get(key) == targets.get("hardened_hot_path_max"), f"hardened baseline target {key} drift")
    for key in ["stage_null_check", "stage_tls_cache_hit", "stage_bloom_hit", "stage_arena_lookup", "stage_fingerprint_verify", "stage_canary_verify", "stage_bounds_check"]:
        require(baseline_targets.get("strict", {}).get(key) == targets.get(key), f"strict stage target {key} drift")
        require(baseline_targets.get("hardened", {}).get(key) == targets.get(key), f"hardened stage target {key} drift")

    suites = spec.get("benchmark_suites", {}).get("suites", []) if isinstance(spec.get("benchmark_suites"), dict) else []
    if not isinstance(suites, list):
        err("perf_baseline_spec.benchmark_suites.suites must be an array")
        suites = []
    suite_map = {suite.get("id"): suite for suite in suites if isinstance(suite, dict)}
    for suite_id in as_string_list(required.get("required_baseline_suites"), "required_golden_contract.required_baseline_suites"):
        suite = suite_map.get(suite_id)
        require(isinstance(suite, dict), f"perf baseline spec missing suite {suite_id}")
        if isinstance(suite, dict):
            require(suite.get("enforced_in_gate") is True, f"perf baseline suite {suite_id} must be enforced_in_gate")
            require(suite.get("modes") == ["strict", "hardened"], f"perf baseline suite {suite_id} modes drift")

    baseline_p50 = baseline.get("baseline_p50_ns_op", {})
    if not isinstance(baseline_p50, dict):
        err("perf_baseline.baseline_p50_ns_op must be an object")
        baseline_p50 = {}
    for benchmark_id in as_string_list(required.get("required_enforced_benchmarks"), "required_golden_contract.required_enforced_benchmarks"):
        suite_id, _, bench = benchmark_id.partition("/")
        require(bool(suite_id and bench), f"invalid benchmark id {benchmark_id}")
        for mode in ["strict", "hardened"]:
            value = baseline_p50.get(suite_id, {}).get(mode, {}).get(bench)
            require(isinstance(value, (int, float)), f"perf baseline missing {mode} {benchmark_id}")

    append_event(
        "runtime_hot_path_perf_budget_targets_verified",
        "pass",
        "budget_targets_verified",
        [artifacts.get("perf_budget_policy", ""), artifacts.get("perf_baseline", ""), artifacts.get("perf_baseline_spec", "")],
        {"strict_hot_path_max": targets.get("strict_hot_path_max"), "hardened_hot_path_max": targets.get("hardened_hot_path_max")},
    )
    return {"strict_hot_path_max": targets.get("strict_hot_path_max"), "hardened_hot_path_max": targets.get("hardened_hot_path_max")}


def validate_gate_bindings(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, bool]:
    required = manifest.get("required_golden_contract", {})
    text_req = required.get("required_gate_text", {}) if isinstance(required, dict) else {}
    if not isinstance(text_req, dict):
        err("required_golden_contract.required_gate_text must be an object")
        text_req = {}
    result: dict[str, bool] = {}
    for artifact_id in ["snapshot_gate", "perf_gate", "benchmark_gate_wrapper", "ci_script"]:
        path_text = artifacts.get(artifact_id, "")
        text = source_text(path_text, artifact_id)
        snippets = as_string_list(text_req.get(artifact_id), f"required_gate_text.{artifact_id}")
        ok = True
        for snippet in snippets:
            if snippet not in text:
                ok = False
                err(f"{artifact_id} missing required text {snippet}")
        result[artifact_id] = ok
    append_event(
        "runtime_hot_path_perf_gate_bindings_verified",
        "pass",
        "gate_bindings_verified",
        [artifacts.get("snapshot_gate", ""), artifacts.get("perf_gate", ""), artifacts.get("benchmark_gate_wrapper", ""), artifacts.get("ci_script", "")],
        result,
    )
    return result


manifest = load_json(CONTRACT, "runtime hot path perf golden contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

artifacts = validate_source_artifacts(manifest)
validate_test_refs(manifest, artifacts)
golden_summary = validate_golden(manifest, artifacts)
budget_summary = validate_budgets(manifest, artifacts)
gate_summary = validate_gate_bindings(manifest, artifacts)

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
else:
    required_log_fields = set(as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
    present_events = {event["event"] for event in events}
    for event_name in sorted(required_events - {"runtime_hot_path_perf_golden_completion_contract_pass"}):
        require(event_name in present_events, f"telemetry event missing before pass: {event_name}")
    for event in events:
        missing = required_log_fields - set(event)
        require(not missing, f"telemetry event {event.get('event')} missing fields {sorted(missing)}")

if errors:
    append_event(
        "runtime_hot_path_perf_golden_completion_contract_fail",
        "fail",
        "contract_failed",
        [rel(CONTRACT)],
        {"error_count": len(errors), "errors": errors[:20]},
    )
    write_outputs(
        manifest,
        "fail",
        {"golden": golden_summary, "budget_targets": budget_summary, "gate_bindings": gate_summary},
    )
    print("runtime_hot_path_perf_golden_completion_contract: FAIL", file=os.sys.stderr)
    for message in errors:
        print(f" - {message}", file=os.sys.stderr)
    raise SystemExit(1)

append_event(
    "runtime_hot_path_perf_golden_completion_contract_pass",
    "pass",
    "contract_passed",
    [rel(CONTRACT)],
    {"event_count": len(events) + 1},
)
write_outputs(
    manifest,
    "pass",
    {"golden": golden_summary, "budget_targets": budget_summary, "gate_bindings": gate_summary},
)
print(
    "runtime_hot_path_perf_golden_completion_contract: PASS "
    f"sha256={golden_summary.get('sha256')} "
    f"strict={budget_summary.get('strict_hot_path_max')}ns "
    f"hardened={budget_summary.get('hardened_hot_path_max')}ns "
    f"events={len(events)}"
)
PY
