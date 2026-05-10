#!/usr/bin/env bash
# check_explainability_workbench_completion_contract.sh - bd-26xb.4.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_EXPLAINABILITY_WORKBENCH_CONTRACT:-${ROOT}/tests/conformance/explainability_workbench_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_EXPLAINABILITY_WORKBENCH_REPORT:-${OUT_DIR}/explainability_workbench_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_EXPLAINABILITY_WORKBENCH_LOG:-${OUT_DIR}/explainability_workbench_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}"

export FLC_ROOT="${ROOT}"
export FLC_CONTRACT_PATH="${CONTRACT_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"
export FLC_LOG_PATH="${LOG_PATH}"

python3 - <<'PY'
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

root = Path(os.environ["FLC_ROOT"])
contract_path = Path(os.environ["FLC_CONTRACT_PATH"])
report_path = Path(os.environ["FLC_REPORT_PATH"])
log_path = Path(os.environ["FLC_LOG_PATH"])
ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

errors: list[str] = []
events: list[dict[str, Any]] = []

REQUIRED_EVENTS = {
    "explainability_workbench_units_validated",
    "explainability_workbench_integration_validated",
    "explainability_workbench_e2e_validated",
    "explainability_workbench_golden_validated",
    "explainability_workbench_telemetry_validated",
}

REQUIRED_FIELDS = {
    "timestamp",
    "trace_id",
    "completion_debt_bead",
    "original_bead",
    "event",
    "status",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "scenario_count",
    "trace_count",
    "artifact_link_count",
    "divergence_count",
    "render_format_count",
    "artifact_refs",
    "failure_signature",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def rel_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay under workspace root: {value}")
    return root / path


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


SOURCE_COMMIT = source_commit()


def check_file_line_ref(ref: str) -> None:
    if ":" not in ref:
        errors.append(f"implementation ref missing line separator: {ref}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        errors.append(f"implementation ref has invalid line: {ref}")
        return
    path = rel_path(path_text)
    if not path.is_file():
        errors.append(f"implementation ref path missing: {ref}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no < 1 or line_no > len(lines) or not lines[line_no - 1].strip():
        errors.append(f"implementation ref does not point to non-empty line: {ref}")


def require_contains(label: str, text: str, needle: str) -> None:
    if needle not in text:
        errors.append(f"{label} missing required text: {needle}")


def require_test_fn(path: Path, name: str) -> None:
    text = path.read_text(encoding="utf-8")
    if f"fn {name}" not in text:
        errors.append(f"{path.relative_to(root)} missing test function {name}")


def emit_event(event: str, status: str, *, summary: dict[str, Any], details: dict[str, Any] | None = None) -> None:
    events.append(
        {
            "timestamp": ts,
            "trace_id": f"bd-26xb.4.1:{event}",
            "completion_debt_bead": "bd-26xb.4.1",
            "original_bead": "bd-26xb.4",
            "source_commit": SOURCE_COMMIT,
            "event": event,
            "status": status,
            "mode": "completion-contract",
            "api_family": "harness",
            "symbol": "explainability_workbench",
            "decision_path": "contract+workbench_module+cli+golden_shape+telemetry",
            "healing_action": "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "scenario_count": summary.get("scenario_count", 0),
            "trace_count": summary.get("trace_count", 0),
            "artifact_link_count": summary.get("artifact_link_count", 0),
            "divergence_count": summary.get("divergence_count", 0),
            "render_format_count": summary.get("render_format_count", 0),
            "artifact_refs": [
                "tests/conformance/explainability_workbench_completion_contract.v1.json",
                "scripts/check_explainability_workbench_completion_contract.sh",
                "crates/frankenlibc-harness/src/explainability_workbench.rs",
                "crates/frankenlibc-harness/tests/explainability_workbench_test.rs",
            ],
            "failure_signature": "none" if status == "pass" else "explainability_workbench_completion_contract_failed",
            "details": details or {},
        }
    )


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})
policy = evidence.get("workbench_policy", {})

if contract.get("schema") != "explainability_workbench_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != "bd-26xb.4":
    errors.append("bead must be bd-26xb.4")
if contract.get("completion_debt_bead") != "bd-26xb.4.1":
    errors.append("completion_debt_bead must be bd-26xb.4.1")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != {
    "tests.unit.primary",
    "tests.integration.primary",
    "tests.e2e.primary",
    "tests.golden.primary",
    "telemetry.primary",
}:
    errors.append(f"missing_items mismatch: {sorted(missing_items)}")

artifact_paths: dict[str, Path] = {}
for name, value in artifacts.items():
    try:
        path = rel_path(str(value))
    except ValueError as exc:
        errors.append(str(exc))
        continue
    artifact_paths[name] = path
    if not path.is_file():
        errors.append(f"artifact {name} missing: {value}")

for ref in evidence.get("implementation_refs", []):
    check_file_line_ref(str(ref))

workbench_text = artifact_paths["workbench_source"].read_text(encoding="utf-8")
cli_text = artifact_paths["harness_cli"].read_text(encoding="utf-8")
cargo_text = artifact_paths["harness_cargo"].read_text(encoding="utf-8")
integration_test_text = artifact_paths["existing_integration_test"].read_text(encoding="utf-8")

for required in [
    "pub struct ExplainabilityWorkbenchReport",
    "pub struct ToolingContract",
    "pub fn tooling_contract()",
    "pub fn build_report(",
    "pub fn render_plain(",
    "pub fn render_ftui(",
    "mode_divergence",
    "artifact_links",
    "root_cause",
    "timeline",
]:
    require_contains("workbench source", workbench_text, required)

for required in [
    "ExplainabilityWorkbench",
    "Build a trace-to-decision explainability workbench from structured logs",
    "build_report(",
    "render_plain(&report)",
    "render_ftui(",
    "Unsupported format",
]:
    require_contains("harness CLI", cli_text, required)

for required in [
    "default = [\"asupersync-tooling\"]",
    "asupersync-tooling = [\"dep:asupersync-conformance\"]",
    "frankentui-ui = [",
    "ftui-harness = { workspace = true, optional = true }",
    "name = \"harness\"",
]:
    require_contains("harness Cargo.toml", cargo_text, required)

for flag in policy.get("required_cli_flags", []):
    require_contains("existing integration test", integration_test_text, str(flag))

for required in [
    "report[\"bead\"]",
    "report[\"scenarios\"][0][\"mode_divergence\"]",
    "reports/root-cause.json",
    "tooling_contract",
    "default_enables_asupersync_tooling",
    "frankentui_feature_present",
]:
    require_contains("existing integration test", integration_test_text, required)

for field in policy.get("required_tooling_contract_fields", []):
    require_contains("workbench source", workbench_text, str(field))

if policy.get("required_schema_version") != "v1":
    errors.append("required_schema_version must be v1")
if policy.get("required_bead") != "bd-26xb.4":
    errors.append("required_bead must be bd-26xb.4")
if int(policy.get("minimum_scenarios", 0)) < 1:
    errors.append("minimum_scenarios must be >= 1")
if int(policy.get("minimum_traces", 0)) < 2:
    errors.append("minimum_traces must be >= 2")
if int(policy.get("minimum_artifact_links", 0)) < 1:
    errors.append("minimum_artifact_links must be >= 1")
if int(policy.get("minimum_mode_divergences", 0)) < 1:
    errors.append("minimum_mode_divergences must be >= 1")

required_modes = set(policy.get("required_modes", []))
if required_modes != {"strict", "hardened"}:
    errors.append(f"required_modes mismatch: {sorted(required_modes)}")
required_formats = set(policy.get("required_render_formats", []))
if required_formats != {"json", "plain", "ftui"}:
    errors.append(f"required_render_formats mismatch: {sorted(required_formats)}")

sources = evidence.get("test_sources", {})
source_paths = {name: rel_path(str(path)) for name, path in sources.items()}
for section_name in ("unit_primary", "integration_primary", "e2e_primary"):
    for test_ref in evidence.get(section_name, {}).get("required_test_refs", []):
        source = str(test_ref.get("source", ""))
        name = str(test_ref.get("name", ""))
        path = source_paths.get(source)
        if path is None:
            errors.append(f"unknown test source: {source}")
            continue
        require_test_fn(path, name)

for script in evidence.get("e2e_primary", {}).get("required_scripts", []):
    if not rel_path(str(script).split()[0]).is_file():
        errors.append(f"required script missing: {script}")

for section in ("unit_primary", "integration_primary", "e2e_primary"):
    for command in evidence.get(section, {}).get("required_commands", []):
        if "cargo test" in command and "rch exec" not in command:
            errors.append(f"{section} cargo command must be rch-backed: {command}")

golden = evidence.get("golden_primary", {})
required_report_fields = set(golden.get("required_report_fields", []))
if not {"schema", "status", "summary", "required_events", "required_fields", "errors"}.issubset(required_report_fields):
    errors.append("golden required_report_fields missing completion report fields")
required_golden_fields = set(policy.get("required_golden_fields", []))
if not {"schema_version", "bead", "tooling_contract", "scenarios", "mode_divergence", "artifact_links"}.issubset(required_golden_fields):
    errors.append("workbench required_golden_fields missing report shape fields")

telemetry = evidence.get("telemetry_primary", {})
if set(telemetry.get("required_events", [])) != REQUIRED_EVENTS:
    errors.append("telemetry required_events mismatch")
if set(telemetry.get("required_fields", [])) != REQUIRED_FIELDS:
    errors.append("telemetry required_fields mismatch")

summary = {
    "scenario_count": int(policy.get("minimum_scenarios", 0)),
    "trace_count": int(policy.get("minimum_traces", 0)),
    "artifact_link_count": int(policy.get("minimum_artifact_links", 0)),
    "divergence_count": int(policy.get("minimum_mode_divergences", 0)),
    "render_format_count": len(required_formats),
    "required_modes": sorted(required_modes),
    "required_formats": sorted(required_formats),
    "tooling_contract_field_count": len(policy.get("required_tooling_contract_fields", [])),
    "golden_field_count": len(policy.get("required_golden_fields", [])),
}

status = "pass" if not errors else "fail"
emit_event("explainability_workbench_units_validated", status, summary=summary, details={"tests": evidence.get("unit_primary", {}).get("required_test_refs", [])})
emit_event("explainability_workbench_integration_validated", status, summary=summary, details={"tests": evidence.get("integration_primary", {}).get("required_test_refs", [])})
emit_event("explainability_workbench_e2e_validated", status, summary=summary, details={"cli_flags": policy.get("required_cli_flags", [])})
emit_event("explainability_workbench_golden_validated", status, summary=summary, details={"golden_fields": sorted(required_golden_fields)})
emit_event("explainability_workbench_telemetry_validated", status, summary=summary, details={"required_events": sorted(REQUIRED_EVENTS), "required_fields": sorted(REQUIRED_FIELDS)})

for event in events:
    missing = REQUIRED_FIELDS - set(event)
    if missing:
        errors.append(f"event {event['event']} missing fields: {sorted(missing)}")

if errors:
    for event in events:
        event["status"] = "fail"
        event["errno"] = 1
        event["failure_signature"] = "explainability_workbench_completion_contract_failed"

report = {
    "schema": "explainability_workbench_completion_contract.report.v1",
    "status": "pass" if not errors else "fail",
    "completion_debt_bead": "bd-26xb.4.1",
    "original_bead": "bd-26xb.4",
    "source_commit": SOURCE_COMMIT,
    "generated_at": ts,
    "summary": summary,
    "required_events": sorted(REQUIRED_EVENTS),
    "required_fields": sorted(REQUIRED_FIELDS),
    "errors": errors,
}

report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.parent.mkdir(parents=True, exist_ok=True)
log_path.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)

if errors:
    print("FAIL: explainability workbench completion contract", file=os.sys.stderr)
    for err in errors:
        print(f" - {err}", file=os.sys.stderr)
    os.sys.exit(1)

print(
    "PASS: explainability workbench completion contract "
    f"(scenarios={summary['scenario_count']}, traces={summary['trace_count']}, "
    f"formats={summary['render_format_count']}, report={report_path.relative_to(root)})"
)
PY
