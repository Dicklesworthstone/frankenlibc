#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_REVERSE_ROUND_LOGGING_CONTRACT:-${ROOT}/tests/conformance/reverse_round_logging_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_REVERSE_ROUND_LOGGING_REPORT:-${ROOT}/target/conformance/reverse_round_logging_completion_contract.report.json}"
LOG="${FRANKENLIBC_REVERSE_ROUND_LOGGING_LOG:-${ROOT}/target/conformance/reverse_round_logging_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "reverse_round_logging_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "reverse_round_logging_completion_contract.report.v1"
EXPECTED_ORIGINAL_BEAD = "bd-2a2.6"
EXPECTED_COMPLETION_BEAD = "bd-2a2.6.1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary": "unit",
    "tests.e2e.primary": "e2e",
    "telemetry.primary": "telemetry",
}
EXPECTED_SOURCE_KEYS = {
    "parent_tracker",
    "reverse_round_report",
    "reverse_round_generator",
    "reverse_round_gate",
    "reverse_round_tests",
    "runtime_math_logging_contract",
    "runtime_math_logging_gate",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
EXPECTED_REQUIRED_EVENTS = [
    "reverse_round_logging_completion.unit_binding",
    "reverse_round_logging_completion.e2e_round_execution",
    "reverse_round_logging_completion.math_family_selection",
    "reverse_round_logging_completion.coverage_metrics",
    "reverse_round_logging_completion.telemetry_contract",
    "reverse_round_logging_completion.validated",
]
FAIL_EVENT = "reverse_round_logging_completion.failed"


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


def lookup_path(value, dotted: str):
    cursor = value
    for segment in dotted.split("."):
        if isinstance(cursor, dict) and segment in cursor:
            cursor = cursor[segment]
        else:
            return None
    return cursor


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


def validate_summary(summary: dict, expected: dict) -> None:
    for key, expected_value in expected.items():
        actual = summary.get(key)
        require(actual == expected_value, "coverage_metric_drift", "reverse-round summary metric drifted", key=key, expected=expected_value, actual=actual)
    pct = summary.get("module_coverage_pct")
    require(isinstance(pct, (int, float)) and pct == 100.0, "coverage_pct_drift", "module coverage percent must remain 100.0", actual=pct)


def validate_required_rounds(reverse_report: dict, logging_contract: dict) -> list[dict]:
    round_results = reverse_report.get("round_results")
    require(isinstance(round_results, dict), "round_results_shape", "round_results must be an object")
    required_rounds = logging_contract.get("required_rounds")
    require(isinstance(required_rounds, list) and required_rounds, "required_rounds_shape", "required_rounds must be non-empty")
    required_round_fields = logging_contract.get("required_round_fields")
    required_family_fields = logging_contract.get("required_math_family_fields")
    thresholds = logging_contract.get("coverage_thresholds")
    require(isinstance(required_round_fields, list) and required_round_fields, "required_round_fields_shape", "required round fields must be non-empty")
    require(isinstance(required_family_fields, list) and required_family_fields, "required_family_fields_shape", "required family fields must be non-empty")
    require(isinstance(thresholds, dict), "coverage_thresholds_shape", "coverage_thresholds must be an object")
    rows = []
    for round_id in required_rounds:
        round_data = round_results.get(round_id)
        require(isinstance(round_data, dict), "required_round_missing", "required reverse round missing", round_id=round_id)
        for field in required_round_fields:
            value = round_data.get(field)
            require(value not in (None, "", [], {}), "required_round_field_missing", "required round field missing", round_id=round_id, field=field)
        families = round_data.get("math_families")
        require(isinstance(families, dict), "math_families_shape", "math_families must be an object", round_id=round_id)
        require(len(families) >= thresholds["minimum_math_families_per_required_round"], "math_family_count_low", "round has too few math families", round_id=round_id, count=len(families))
        for family_id, family in families.items():
            require(isinstance(family, dict), "math_family_shape", "math family must be an object", round_id=round_id, family_id=family_id)
            for field in required_family_fields:
                value = family.get(field)
                require(value not in (None, "", [], {}), "math_family_field_missing", "math family field missing", round_id=round_id, family_id=family_id, field=field)
            require(family.get("module_exists") is True, "math_family_module_missing", "math family module must exist", round_id=round_id, family_id=family_id)
            require(family.get("invariant_specified") is True, "math_family_invariant_missing", "math family invariant must be specified", round_id=round_id, family_id=family_id)
        diversity = round_data.get("branch_diversity")
        require(isinstance(diversity, dict), "branch_diversity_shape", "branch_diversity must be an object", round_id=round_id)
        class_count = diversity.get("class_count")
        require(class_count >= thresholds["minimum_math_classes_per_required_round"], "math_class_count_low", "round has too few math classes", round_id=round_id, class_count=class_count)
        require(diversity.get("passes_diversity") is True, "round_diversity_failed", "round diversity must pass", round_id=round_id)
        require(round_data.get("verification_hooks_found", 0) >= thresholds["minimum_verification_hooks_per_required_round"], "verification_hooks_low", "round has too few verification hooks", round_id=round_id)
        require(round_data.get("supporting_files_found", 0) >= thresholds["minimum_supporting_files_per_required_round"], "supporting_files_low", "round has too few supporting files", round_id=round_id)
        rows.append(
            {
                "round_id": round_id,
                "name": round_data["name"],
                "math_family_count": len(families),
                "math_class_count": class_count,
                "verification_hooks_found": round_data.get("verification_hooks_found", 0),
                "supporting_files_found": round_data.get("supporting_files_found", 0),
                "legacy_surfaces": round_data["legacy_surfaces"],
            }
        )
    return rows


def validate_logging_scenarios(reverse_report: dict, logging_contract: dict) -> list[dict]:
    scenarios = logging_contract.get("logging_scenarios")
    require(isinstance(scenarios, list) and scenarios, "logging_scenarios_shape", "logging_scenarios must be non-empty")
    rows = []
    for scenario in scenarios:
        require(isinstance(scenario, dict), "scenario_shape", "scenario must be an object")
        scenario_id = scenario.get("scenario_id")
        event = scenario.get("event")
        require(isinstance(scenario_id, str) and scenario_id, "scenario_id", "scenario id must be non-empty")
        require(event in EXPECTED_REQUIRED_EVENTS, "scenario_event_drift", "scenario event must be a required pass event", scenario_id=scenario_id, event=event)
        for path in scenario.get("required_report_paths", []):
            require(lookup_path(reverse_report, path) is not None, "required_report_path_missing", "required report path missing", scenario_id=scenario_id, path=path)
        if "expected_round_count" in scenario:
            require(reverse_report["summary"]["rounds_verified"] == scenario["expected_round_count"], "round_count_drift", "round execution count drifted", scenario_id=scenario_id)
        if "expected_total_math_families" in scenario:
            require(reverse_report["summary"]["total_math_families"] == scenario["expected_total_math_families"], "math_family_total_drift", "math family total drifted", scenario_id=scenario_id)
        if "expected_module_coverage_pct" in scenario:
            require(reverse_report["summary"]["module_coverage_pct"] == scenario["expected_module_coverage_pct"], "module_coverage_pct_drift", "module coverage pct drifted", scenario_id=scenario_id)
        rows.append(
            {
                "scenario_id": scenario_id,
                "event": event,
                "required_report_path_count": len(scenario.get("required_report_paths", [])),
            }
        )
    return rows


contract = load_json(contract_path)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "schema version drifted")
require(contract.get("original_bead") == EXPECTED_ORIGINAL_BEAD, "original_bead", "original bead drifted")
require(contract.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_bead", "completion debt bead drifted")

source_artifacts = validate_source_artifacts(contract)
anchor_count = validate_source_anchors(contract, source_artifacts)
bindings = validate_missing_items(contract)

logging_contract = contract.get("reverse_round_logging_contract")
require(isinstance(logging_contract, dict), "logging_contract_shape", "reverse_round_logging_contract must be an object")
reverse_report = load_json(root / source_artifacts["reverse_round_report"])
require(reverse_report.get("schema_version") == "v1", "reverse_report_schema", "reverse-round report schema drifted")
summary = reverse_report.get("summary")
require(isinstance(summary, dict), "reverse_summary_shape", "reverse-round summary must be an object")
validate_summary(summary, logging_contract.get("expected_summary", {}))
round_rows = validate_required_rounds(reverse_report, logging_contract)
scenario_rows = validate_logging_scenarios(reverse_report, logging_contract)

rows = [
    {
        "timestamp": now_utc(),
        "event": "reverse_round_logging_completion.unit_binding",
        "status": "pass",
        "missing_item_count": len(bindings),
        "source_anchor_count": anchor_count,
        "required_round_count": len(round_rows),
    },
    {
        "timestamp": now_utc(),
        "event": "reverse_round_logging_completion.e2e_round_execution",
        "status": "pass",
        "rounds_verified": summary["rounds_verified"],
        "round_rows": round_rows,
        "cross_round_checks_passing": summary["cross_round_checks_passing"],
        "milestones_diverse": summary["milestones_diverse"],
    },
    {
        "timestamp": now_utc(),
        "event": "reverse_round_logging_completion.math_family_selection",
        "status": "pass",
        "total_math_families": summary["total_math_families"],
        "math_class_count": summary["math_class_count"],
        "required_rounds": [row["round_id"] for row in round_rows],
    },
    {
        "timestamp": now_utc(),
        "event": "reverse_round_logging_completion.coverage_metrics",
        "status": "pass",
        "modules_found": summary["modules_found"],
        "modules_missing": summary["modules_missing"],
        "module_coverage_pct": summary["module_coverage_pct"],
        "invariants_specified": summary["invariants_specified"],
        "invariants_total": summary["invariants_total"],
    },
    {
        "timestamp": now_utc(),
        "event": "reverse_round_logging_completion.telemetry_contract",
        "status": "pass",
        "scenario_rows": scenario_rows,
        "required_events": EXPECTED_REQUIRED_EVENTS,
        "report_path": rel(report_path),
        "log_path": rel(log_path),
    },
    {
        "timestamp": now_utc(),
        "event": "reverse_round_logging_completion.validated",
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
        "required_round_count": len(round_rows),
        "scenario_count": len(scenario_rows),
        "rounds_verified": summary["rounds_verified"],
        "total_math_families": summary["total_math_families"],
        "module_coverage_pct": summary["module_coverage_pct"],
        "cross_round_checks_passing": summary["cross_round_checks_passing"],
        "milestones_diverse": summary["milestones_diverse"],
        "events": EXPECTED_REQUIRED_EVENTS,
    },
    "round_rows": round_rows,
    "scenario_rows": scenario_rows,
}
write_json(report_path, report)
write_log(rows)
print(
    "reverse_round_logging_completion_contract: PASS "
    f"items={len(bindings)} rounds={len(round_rows)} scenarios={len(scenario_rows)} "
    f"families={summary['total_math_families']} coverage={summary['module_coverage_pct']}"
)
PY
