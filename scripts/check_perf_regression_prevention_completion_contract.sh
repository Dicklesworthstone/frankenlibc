#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACT="${FRANKENLIBC_PERF_REGRESSION_COMPLETION_CONTRACT:-$ROOT/tests/conformance/perf_regression_prevention_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_PERF_REGRESSION_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_PERF_REGRESSION_COMPLETION_REPORT:-$OUT_DIR/perf_regression_prevention_completion_contract.report.json}"
LOG="${FRANKENLIBC_PERF_REGRESSION_COMPLETION_LOG:-$OUT_DIR/perf_regression_prevention_completion_contract.log.jsonl}"
SOURCE_REPORT="${FRANKENLIBC_PERF_REGRESSION_COMPLETION_SOURCE_REPORT:-$OUT_DIR/perf_regression_prevention_completion_contract.source_report.json}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$SOURCE_REPORT")"

python3 - "$ROOT" "$CONTRACT" "$SOURCE_REPORT" "$REPORT" "$LOG" <<'PY'
import json
import subprocess
import sys
from pathlib import Path


root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
source_report_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])

errors = []


def load_json(path, label):
    try:
        with Path(path).open() as f:
            return json.load(f)
    except Exception as exc:
        errors.append(f"{label}: failed to load JSON from {path}: {exc}")
        return {}


def rel_path(path):
    return root / str(path)


def read_text(path, label):
    try:
        return rel_path(path).read_text()
    except Exception as exc:
        errors.append(f"{label}: failed to read {path}: {exc}")
        return ""


def dotted(value, dotted_key):
    cur = value
    for part in dotted_key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def require(condition, message):
    if not condition:
        errors.append(message)


contract = load_json(contract_path, "contract")
source_artifacts = contract.get("source_artifacts", {})

require(
    contract.get("schema_version") == "perf_regression_prevention_completion_contract.v1",
    "schema_version must be perf_regression_prevention_completion_contract.v1",
)
require(contract.get("original_bead") == "bd-1qfc", "original_bead must be bd-1qfc")
require(
    contract.get("completion_debt_bead") == "bd-1qfc.1",
    "completion_debt_bead must be bd-1qfc.1",
)

for artifact_id, artifact_path in source_artifacts.items():
    require(rel_path(artifact_path).exists(), f"source artifact {artifact_id} missing: {artifact_path}")

texts = {
    key: read_text(path, key)
    for key, path in source_artifacts.items()
    if str(path).endswith((".py", ".sh", ".rs", ".json"))
}

for ref in contract.get("completion_debt_evidence", {}).get("implementation_refs", []):
    path = ref.get("path")
    text = texts.get(next((k for k, v in source_artifacts.items() if v == path), ""), "")
    if not text:
        text = read_text(path, ref.get("id", "implementation_ref"))
    for needle in ref.get("required_text", []):
        require(
            needle in text,
            f"implementation ref {ref.get('id')} missing required text {needle!r} in {path}",
        )

test_sources = contract.get("completion_debt_evidence", {}).get("test_sources", {})
for source_id, source in test_sources.items():
    path = source.get("path")
    text = read_text(path, source_id)
    for test_ref in source.get("required_test_refs", []):
        require(
            f"fn {test_ref}" in text or test_ref in text,
            f"test source {source_id} missing required test ref {test_ref}",
        )

generator = rel_path(source_artifacts.get("source_generator", ""))
if generator.exists():
    completed = subprocess.run(
        ["python3", str(generator), "-o", str(source_report_path)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    require(
        completed.returncode == 0,
        "source generator failed with "
        f"exit={completed.returncode} stdout={completed.stdout!r} stderr={completed.stderr!r}",
    )
else:
    errors.append(f"source generator missing: {generator}")

source_report = load_json(source_report_path, "generated_source_report")
required_source = contract.get("required_source_report", {})
require(
    source_report.get("schema_version") == required_source.get("schema_version"),
    "generated source report schema_version mismatch",
)
require(source_report.get("bead") == required_source.get("bead"), "generated source report bead mismatch")

summary = source_report.get("summary", {})
for field, expected in required_source.get("summary_exact", {}).items():
    require(summary.get(field) == expected, f"summary.{field} expected {expected!r}, got {summary.get(field)!r}")

for field, minimum in required_source.get("summary_min", {}).items():
    value = summary.get(field)
    require(
        isinstance(value, (int, float)) and value >= minimum,
        f"summary.{field} expected >= {minimum!r}, got {value!r}",
    )

for section in required_source.get("required_sections", []):
    require(section in source_report, f"generated source report missing section {section}")

gate = source_report.get("gate_wiring", {})
require(gate.get("exists") is True, "gate_wiring.exists must be true")
gate_features = gate.get("features", {})
for feature in required_source.get("required_gate_features", []):
    require(gate_features.get(feature) is True, f"required gate feature {feature} missing or false")

enforced_suites = set(gate.get("enforced_suites", []))
for suite in required_source.get("required_enforced_suites", []):
    require(suite in enforced_suites, f"required enforced suite {suite} missing from gate_wiring.enforced_suites")

config = source_report.get("config_consistency", {})
for field in required_source.get("required_config_fields", []):
    require(field in config, f"config_consistency missing field {field}")
require(config.get("expired_waivers") == 0, "config_consistency.expired_waivers must be 0")
require(config.get("issues") == [], "config_consistency.issues must be empty")

dashboard = load_json(rel_path(source_artifacts.get("dashboard_report", "")), "dashboard_report")
dashboard_rows = {
    row.get("row_id")
    for row in dashboard.get("rows", [])
    if isinstance(row, dict) and row.get("row_id")
}
for row_id in required_source.get("required_dashboard_rows", []):
    require(row_id in dashboard_rows, f"dashboard missing required perf prevention row {row_id}")

all_test_text = "\n".join(texts.values())
for item in contract.get("missing_item_bindings", []):
    for test_ref in item.get("required_test_refs", []):
        require(test_ref in all_test_text, f"missing item {item.get('id')} lacks test ref {test_ref}")
    for command in item.get("required_commands", []):
        require("cargo " not in command or "rch exec -- cargo " in command, f"required command must use rch: {command}")

summary_event = {
    "event": "perf_regression_prevention_completion_summary",
    "bead_id": contract.get("manifest_id"),
    "source_bead": contract.get("original_bead"),
    "completion_debt_bead": contract.get("completion_debt_bead"),
    "source_report": str(source_report_path.relative_to(root)) if source_report_path.is_relative_to(root) else str(source_report_path),
    "outcome": "summary",
    "total_suites_in_spec": summary.get("total_suites_in_spec"),
    "suites_with_bench_files": summary.get("suites_with_bench_files"),
    "suites_enforced_in_gate": summary.get("suites_enforced_in_gate"),
    "baseline_slot_fill_pct": summary.get("baseline_slot_fill_pct"),
    "hotpath_symbol_coverage_pct": summary.get("hotpath_symbol_coverage_pct"),
    "total_issues": summary.get("total_issues"),
    "total_warnings": summary.get("total_warnings"),
}
gate_event = {
    "event": "perf_regression_prevention_gate_wiring_preserved",
    "bead_id": contract.get("manifest_id"),
    "source_bead": contract.get("original_bead"),
    "completion_debt_bead": contract.get("completion_debt_bead"),
    "source_report": str(source_report_path.relative_to(root)) if source_report_path.is_relative_to(root) else str(source_report_path),
    "outcome": "gate_wiring",
    "enforced_suites": sorted(enforced_suites),
    "features": gate_features,
    "dashboard_row_count": len(required_source.get("required_dashboard_rows", [])),
}
pass_event = {
    "event": "perf_regression_prevention_completion_contract_pass",
    "bead_id": contract.get("manifest_id"),
    "source_bead": contract.get("original_bead"),
    "completion_debt_bead": contract.get("completion_debt_bead"),
    "source_report": str(source_report_path.relative_to(root)) if source_report_path.is_relative_to(root) else str(source_report_path),
    "outcome": "pass" if not errors else "fail",
}
events = [summary_event, gate_event, pass_event]
status = "pass" if not errors else "fail"
for event in events:
    event["status"] = status

telemetry = contract.get("telemetry_contract", {})
event_names = {event.get("event") for event in events}
for event_name in telemetry.get("required_events", []):
    require(event_name in event_names, f"required telemetry event {event_name} was not emitted")

for event in events:
    for field in telemetry.get("required_log_fields", []):
        require(field in event, f"telemetry event {event.get('event')} missing field {field}")

report = {
    "schema_version": "perf_regression_prevention_completion_contract.report.v1",
    "manifest_id": contract.get("manifest_id"),
    "source_bead": contract.get("original_bead"),
    "completion_debt_bead": contract.get("completion_debt_bead"),
    "status": status,
    "source_report": str(source_report_path.relative_to(root)) if source_report_path.is_relative_to(root) else str(source_report_path),
    "summary": summary,
    "gate_wiring": gate,
    "dashboard_row_count": len(required_source.get("required_dashboard_rows", [])),
    "events": [event["event"] for event in events],
    "errors": errors,
}

for field in telemetry.get("required_report_fields", []):
    if field not in report:
        errors.append(f"completion report missing required field {field}")

if errors:
    status = "fail"
    report["status"] = status
    report["errors"] = errors
    for event in events:
        event["status"] = status

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
log_path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events))

if errors:
    print(f"FAIL: perf regression prevention completion contract ({len(errors)} errors, report={report_path})")
    for error in errors:
        print(f"  - {error}")
    sys.exit(1)

print(
    "PASS: perf regression prevention completion contract "
    f"(suites={summary.get('total_suites_in_spec')}, "
    f"baseline_fill={summary.get('baseline_slot_fill_pct')}, "
    f"hotpath_coverage={summary.get('hotpath_symbol_coverage_pct')}, "
    f"report={report_path})"
)
PY
