#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_ABI_DRIFT_AUTO_BISECT_CONTRACT:-${ROOT}/tests/conformance/abi_drift_auto_bisect_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_ABI_DRIFT_AUTO_BISECT_REPORT:-${ROOT}/target/conformance/abi_drift_auto_bisect_completion_contract.report.json}"
LOG="${FRANKENLIBC_ABI_DRIFT_AUTO_BISECT_LOG:-${ROOT}/target/conformance/abi_drift_auto_bisect_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" <<'PY'
import json
import pathlib
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
start_ns = time.time_ns()

EXPECTED_SCHEMA = "abi_drift_auto_bisect_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "abi_drift_auto_bisect_completion_contract.report.v1"
EXPECTED_ORIGINAL_BEAD = "bd-26xb.7"
EXPECTED_COMPLETION_BEAD = "bd-26xb.7.1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary": "unit",
    "tests.e2e.primary": "e2e",
    "telemetry.primary": "telemetry",
}
EXPECTED_SOURCE_KEYS = {
    "parent_tracker",
    "workspace_manifest",
    "harness_manifest",
    "asupersync_orchestrator",
    "snapshot_diff",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
EXPECTED_REQUIRED_EVENTS = [
    "abi_drift_auto_bisect_completion.unit_binding",
    "abi_drift_auto_bisect_completion.e2e_transcript",
    "abi_drift_auto_bisect_completion.telemetry_contract",
    "abi_drift_auto_bisect_completion.validated",
]
FAIL_EVENT = "abi_drift_auto_bisect_completion.failed"
REQUIRED_CANDIDATE_FIELDS = {
    "scenario_id",
    "first_bad_commit",
    "previous_good_commit",
    "changed_symbols",
    "drift_class",
    "witnesses",
    "artifact_refs",
}


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_log(records: list[dict]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def fail(signature: str, message: str, **details) -> None:
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
        "source_commit": git_head(),
        "status": "fail",
        "failure_signature": signature,
        "message": message,
        "contract": rel(contract_path),
        "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
        "details": details,
    }
    write_json(report_path, report)
    write_log(
        [
            {
                "timestamp": now_utc(),
                "event": FAIL_EVENT,
                "status": "fail",
                "failure_signature": signature,
                "message": message,
                "details": details,
            }
        ]
    )
    raise SystemExit(f"FAIL[{signature}]: {message}")


def require(condition: bool, signature: str, message: str, **details) -> None:
    if not condition:
        fail(signature, message, **details)


def load_json(path: pathlib.Path):
    require(path.is_file(), "json_missing", f"missing json artifact: {rel(path)}", path=rel(path))
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        fail("json_invalid", f"invalid json artifact: {rel(path)}", path=rel(path), error=str(err))


def validate_line_ref(ref: str) -> str:
    require(isinstance(ref, str) and ref, "line_ref_empty", "line ref must be a non-empty string")
    path_text, sep, line_text = ref.rpartition(":")
    require(sep == ":" and line_text.isdigit(), "line_ref_shape", "line ref must be path:line", ref=ref)
    line_no = int(line_text)
    require(line_no > 0, "line_ref_line", "line number must be positive", ref=ref)
    path = root / path_text
    require(path.is_file(), "line_ref_path_missing", "line ref path is missing", ref=ref)
    lines = path.read_text(encoding="utf-8").splitlines()
    require(line_no <= len(lines), "line_ref_out_of_range", "line ref is beyond end of file", ref=ref)
    require(lines[line_no - 1].strip() != "", "line_ref_blank", "line ref points at a blank line", ref=ref)
    return ref


def validate_source_artifacts(contract: dict) -> dict:
    artifacts = contract.get("source_artifacts")
    require(isinstance(artifacts, dict), "source_artifacts_shape", "source_artifacts must be an object")
    require(
        set(artifacts) == EXPECTED_SOURCE_KEYS,
        "source_artifact_key_drift",
        "source_artifacts keys drifted",
        declared=sorted(artifacts),
        expected=sorted(EXPECTED_SOURCE_KEYS),
    )
    for key, path_text in artifacts.items():
        require(isinstance(path_text, str) and path_text, "source_artifact_value", f"{key} must point at a path")
        require((root / path_text).is_file(), "source_path_missing", f"source artifact missing: {path_text}", key=key)
    return artifacts


def validate_source_anchors(contract: dict, artifacts: dict) -> int:
    anchors = contract.get("source_anchors")
    require(isinstance(anchors, dict), "source_anchors_shape", "source_anchors must be an object")
    require(set(anchors) <= set(artifacts), "source_anchor_unknown_key", "source anchors contain unknown keys")
    total = 0
    for key, needles in anchors.items():
        require(isinstance(needles, list) and needles, "source_anchor_list", f"{key} anchors must be non-empty")
        text = (root / artifacts[key]).read_text(encoding="utf-8")
        for needle in needles:
            require(isinstance(needle, str) and needle, "source_anchor_empty", f"{key} anchor must be non-empty")
            require(
                needle in text,
                "source_anchor_missing",
                f"{key} is missing a required source anchor",
                key=key,
                path=artifacts[key],
                needle=needle,
            )
            total += 1
    return total


def validate_missing_items(contract: dict) -> list[dict]:
    bindings = contract.get("missing_item_bindings")
    require(isinstance(bindings, list), "missing_item_bindings_shape", "missing_item_bindings must be an array")
    actual = {}
    for binding in bindings:
        require(isinstance(binding, dict), "missing_item_shape", "missing item binding must be an object")
        item_id = binding.get("id")
        kind = binding.get("kind")
        require(isinstance(item_id, str) and item_id, "missing_item_id", "missing item id must be non-empty")
        require(isinstance(kind, str) and kind, "missing_item_kind", "missing item kind must be non-empty")
        actual[item_id] = kind
        require(binding.get("next_audit_threshold") == 900, "next_audit_threshold", "each item must pin threshold 900", item_id=item_id)
        for key in ("implementation_refs", "test_refs"):
            refs = binding.get(key)
            require(isinstance(refs, list) and refs, f"{key}_missing", f"{item_id} must cite {key}", item_id=item_id)
            for ref in refs:
                validate_line_ref(ref)
        commands = binding.get("required_commands")
        require(isinstance(commands, list) and commands, "required_commands_missing", f"{item_id} commands must be non-empty")
        for command in commands:
            require(isinstance(command, str) and command, "command_empty", "required command must be non-empty")
            require("rm -rf" not in command and "git reset --hard" not in command and "git clean -fd" not in command, "destructive_command", "required command contains forbidden destructive operation", command=command)
        if item_id == "telemetry.primary":
            refs = binding.get("telemetry_refs")
            require(isinstance(refs, list) and refs, "telemetry_refs_missing", "telemetry.primary must cite telemetry refs")
            for ref in refs:
                validate_line_ref(ref)
            require(binding.get("required_events") == EXPECTED_REQUIRED_EVENTS, "required_events_drift", "telemetry required events drifted")
    require(actual == EXPECTED_MISSING_ITEMS, "missing_item_set_drift", "missing item set drifted", actual=actual, expected=EXPECTED_MISSING_ITEMS)
    return bindings


def validate_tooling_contract(contract: dict) -> dict:
    tooling = contract.get("tooling_contract")
    require(isinstance(tooling, dict), "tooling_contract_shape", "tooling_contract must be an object")
    orchestration = tooling.get("deterministic_orchestration")
    diff_snapshot = tooling.get("deterministic_diff_snapshot")
    require(isinstance(orchestration, dict), "orchestration_shape", "deterministic_orchestration must be an object")
    require(isinstance(diff_snapshot, dict), "diff_snapshot_shape", "deterministic_diff_snapshot must be an object")
    require(orchestration.get("dependency") == "asupersync-conformance", "asupersync_dependency_drift", "asupersync dependency drifted")
    require(orchestration.get("feature") == "asupersync-tooling", "asupersync_feature_drift", "asupersync feature drifted")
    require(diff_snapshot.get("dependency") == "ftui-harness", "frankentui_dependency_drift", "frankentui dependency drifted")
    require(diff_snapshot.get("feature") == "frankentui-ui", "frankentui_feature_drift", "frankentui feature drifted")
    for section_name, section in (("deterministic_orchestration", orchestration), ("deterministic_diff_snapshot", diff_snapshot)):
        refs = section.get("evidence_refs")
        require(isinstance(refs, list) and refs, f"{section_name}_refs_missing", f"{section_name} must cite evidence refs")
        for ref in refs:
            validate_line_ref(ref)
    return tooling


def commit_status(commit: dict) -> str:
    status = commit.get("status")
    require(status in {"pass", "fail"}, "commit_status", "commit status must be pass or fail", commit=commit)
    return status


def ceil_log2_plus_one(n: int) -> int:
    require(n > 0, "commit_count", "commit_count must be positive", commit_count=n)
    return (n - 1).bit_length() + 1


def compute_bisect(commits: list[dict]) -> tuple[list[str], int]:
    lo = 0
    hi = len(commits) - 1
    probes = []
    while lo < hi:
        mid = (lo + hi) // 2
        probes.append(commits[mid]["id"])
        if commit_status(commits[mid]) == "fail":
            hi = mid
        else:
            lo = mid + 1
    return probes, lo


def validate_monotonic_history(commits: list[dict], scenario_id: str) -> None:
    seen_fail = False
    pass_count = 0
    fail_count = 0
    ids = set()
    for commit in commits:
        commit_id = commit.get("id")
        require(isinstance(commit_id, str) and commit_id, "commit_id", "commit id must be non-empty", scenario_id=scenario_id)
        require(commit_id not in ids, "duplicate_commit_id", "commit ids must be unique", scenario_id=scenario_id, commit_id=commit_id)
        ids.add(commit_id)
        status = commit_status(commit)
        if status == "pass":
            pass_count += 1
            require(not seen_fail, "non_monotonic_history", "pass commit appears after fail commit", scenario_id=scenario_id, commit_id=commit_id)
        else:
            fail_count += 1
            seen_fail = True
        witnesses = commit.get("witnesses")
        require(isinstance(witnesses, list) and witnesses, "commit_witnesses", "commit witnesses must be non-empty", scenario_id=scenario_id, commit_id=commit_id)
        for witness in witnesses:
            require(isinstance(witness, str) and witness, "commit_witness_string", "commit witness must be non-empty", scenario_id=scenario_id)
    require(pass_count > 0, "history_without_good_commit", "scenario must include at least one passing commit", scenario_id=scenario_id)
    require(fail_count > 0, "history_without_bad_commit", "scenario must include at least one failing commit", scenario_id=scenario_id)


def validate_candidate(candidate: dict, scenario: dict, first_bad_index: int) -> None:
    scenario_id = scenario["scenario_id"]
    require(isinstance(candidate, dict), "candidate_shape", "candidate_root_cause must be an object", scenario_id=scenario_id)
    require(set(candidate) == REQUIRED_CANDIDATE_FIELDS, "candidate_field_drift", "candidate fields drifted", scenario_id=scenario_id, fields=sorted(candidate))
    require(candidate["scenario_id"] == scenario_id, "candidate_scenario_drift", "candidate scenario drifted", scenario_id=scenario_id)
    require(candidate["first_bad_commit"] == scenario["expected_first_bad_commit"], "candidate_first_bad_drift", "candidate first bad commit drifted", scenario_id=scenario_id)
    require(candidate["previous_good_commit"] == scenario["expected_previous_good_commit"], "candidate_previous_good_drift", "candidate previous good commit drifted", scenario_id=scenario_id)
    require(candidate["drift_class"] == scenario["drift_class"], "candidate_drift_class", "candidate drift_class must match scenario", scenario_id=scenario_id)
    for key in ("changed_symbols", "witnesses", "artifact_refs"):
        value = candidate.get(key)
        require(isinstance(value, list) and value, f"candidate_{key}", f"candidate {key} must be non-empty", scenario_id=scenario_id)
        for item in value:
            require(isinstance(item, str) and item, f"candidate_{key}_string", f"candidate {key} values must be strings", scenario_id=scenario_id)
    require(scenario["symbol"] in candidate["changed_symbols"], "candidate_symbol_missing", "candidate changed_symbols must include scenario symbol", scenario_id=scenario_id, symbol=scenario["symbol"])
    first_bad_witnesses = set(scenario["commits"][first_bad_index]["witnesses"])
    require(first_bad_witnesses <= set(candidate["witnesses"]), "candidate_witness_missing", "candidate witnesses must include first bad witnesses", scenario_id=scenario_id)


def validate_scenarios(contract: dict) -> list[dict]:
    engine = contract.get("bisect_engine_contract")
    require(isinstance(engine, dict), "engine_contract_shape", "bisect_engine_contract must be an object")
    require(engine.get("strategy") == "leftmost_first_bad_binary_search", "strategy_drift", "bisect strategy drifted")
    require(engine.get("max_probe_rule") == "ceil(log2(commit_count)) + 1", "max_probe_rule_drift", "max probe rule drifted")
    required_fields = engine.get("required_candidate_fields")
    require(set(required_fields or []) == REQUIRED_CANDIDATE_FIELDS, "candidate_required_fields_drift", "required candidate fields drifted")
    scenarios = engine.get("scenarios")
    require(isinstance(scenarios, list) and len(scenarios) >= engine.get("minimum_scenarios", 3), "scenario_count", "not enough bisect scenarios")
    transcripts = []
    seen_scenarios = set()
    for scenario in scenarios:
        require(isinstance(scenario, dict), "scenario_shape", "scenario must be an object")
        scenario_id = scenario.get("scenario_id")
        require(isinstance(scenario_id, str) and scenario_id, "scenario_id", "scenario id must be non-empty")
        require(scenario_id not in seen_scenarios, "duplicate_scenario_id", "scenario ids must be unique", scenario_id=scenario_id)
        seen_scenarios.add(scenario_id)
        for key in ("api_family", "symbol", "drift_class"):
            require(isinstance(scenario.get(key), str) and scenario[key], "scenario_field", f"{key} must be non-empty", scenario_id=scenario_id)
        commits = scenario.get("commits")
        require(isinstance(commits, list) and len(commits) >= 3, "commit_count", "each scenario needs at least three commits", scenario_id=scenario_id)
        validate_monotonic_history(commits, scenario_id)
        probes, first_bad_index = compute_bisect(commits)
        first_bad_commit = commits[first_bad_index]["id"]
        previous_good = commits[first_bad_index - 1]["id"] if first_bad_index > 0 else None
        require(probes == scenario.get("expected_probe_sequence"), "probe_sequence_drift", "probe sequence drifted", scenario_id=scenario_id, computed=probes, expected=scenario.get("expected_probe_sequence"))
        require(first_bad_commit == scenario.get("expected_first_bad_commit"), "first_bad_drift", "first bad commit drifted", scenario_id=scenario_id, computed=first_bad_commit, expected=scenario.get("expected_first_bad_commit"))
        require(previous_good == scenario.get("expected_previous_good_commit"), "previous_good_drift", "previous good commit drifted", scenario_id=scenario_id, computed=previous_good, expected=scenario.get("expected_previous_good_commit"))
        require(len(probes) <= ceil_log2_plus_one(len(commits)), "probe_budget_exceeded", "probe sequence exceeds budget", scenario_id=scenario_id, probes=len(probes), commit_count=len(commits))
        validate_candidate(scenario.get("candidate_root_cause"), scenario, first_bad_index)
        transcripts.append(
            {
                "scenario_id": scenario_id,
                "api_family": scenario["api_family"],
                "symbol": scenario["symbol"],
                "drift_class": scenario["drift_class"],
                "commit_count": len(commits),
                "probe_sequence": probes,
                "probe_count": len(probes),
                "max_probe_count": ceil_log2_plus_one(len(commits)),
                "first_bad_commit": first_bad_commit,
                "previous_good_commit": previous_good,
                "candidate_root_cause": scenario["candidate_root_cause"],
            }
        )
    return transcripts


contract = load_json(contract_path)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "schema version drifted")
require(contract.get("original_bead") == EXPECTED_ORIGINAL_BEAD, "original_bead", "original bead drifted")
require(contract.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_bead", "completion debt bead drifted")

source_artifacts = validate_source_artifacts(contract)
anchor_count = validate_source_anchors(contract, source_artifacts)
bindings = validate_missing_items(contract)
tooling = validate_tooling_contract(contract)
transcripts = validate_scenarios(contract)

rows = [
    {
        "timestamp": now_utc(),
        "event": "abi_drift_auto_bisect_completion.unit_binding",
        "status": "pass",
        "missing_item_count": len(bindings),
        "source_anchor_count": anchor_count,
        "line_ref_policy": "path:line nonblank",
    },
    {
        "timestamp": now_utc(),
        "event": "abi_drift_auto_bisect_completion.e2e_transcript",
        "status": "pass",
        "scenario_count": len(transcripts),
        "transcripts": transcripts,
    },
    {
        "timestamp": now_utc(),
        "event": "abi_drift_auto_bisect_completion.telemetry_contract",
        "status": "pass",
        "required_events": EXPECTED_REQUIRED_EVENTS,
        "report_path": rel(report_path),
        "log_path": rel(log_path),
    },
    {
        "timestamp": now_utc(),
        "event": "abi_drift_auto_bisect_completion.validated",
        "status": "pass",
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
        "source_commit": git_head(),
    },
]

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
    "source_commit": git_head(),
    "status": "pass",
    "failure_signature": "none",
    "contract": rel(contract_path),
    "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
    "summary": {
        "missing_item_count": len(bindings),
        "source_artifact_count": len(source_artifacts),
        "source_anchor_count": anchor_count,
        "scenario_count": len(transcripts),
        "total_probe_count": sum(transcript["probe_count"] for transcript in transcripts),
        "max_probe_budget": max(transcript["max_probe_count"] for transcript in transcripts),
        "tooling_dependencies": [
            tooling["deterministic_orchestration"]["dependency"],
            tooling["deterministic_diff_snapshot"]["dependency"],
        ],
        "events": EXPECTED_REQUIRED_EVENTS,
    },
    "transcripts": transcripts,
}
write_json(report_path, report)
write_log(rows)
print(
    "abi_drift_auto_bisect_completion_contract: PASS "
    f"items={len(bindings)} scenarios={len(transcripts)} probes={report['summary']['total_probe_count']} "
    f"anchors={anchor_count}"
)
PY
