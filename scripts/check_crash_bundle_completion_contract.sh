#!/usr/bin/env bash
# Gate for bd-6yd.1 crash bundle completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_CRASH_BUNDLE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/crash_bundle_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_CRASH_BUNDLE_COMPLETION_REPORT:-$ROOT/target/conformance/crash_bundle_completion_contract.report.json}"
LOG="${FRANKENLIBC_CRASH_BUNDLE_COMPLETION_LOG:-$ROOT/target/conformance/crash_bundle_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "crash_bundle_completion_contract.v1"
EXPECTED_MANIFEST = "bd-6yd.1-crash-bundle-completion-contract"
COMPLETION_BEAD = "bd-6yd.1"
ORIGINAL_BEAD = "bd-6yd"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}
EXPECTED_UNIT_TESTS = {
    "spec_exists_and_valid",
    "required_artifacts_have_bounds",
    "required_artifact_filenames_complete",
    "determinism_rules_well_formed",
    "reproduction_checklist_covers_essentials",
    "evidence_snapshot_bounded_by_k_max",
    "runner_integration_scripts_exist",
    "summary_consistent",
    "gate_script_exists_and_executable",
}
EXPECTED_ARTIFACTS = {
    "bundle.meta",
    "env.txt",
    "proc_self_maps.txt",
    "backtrace.txt",
    "evidence_snapshot.jsonl",
    "allocator_stats.json",
    "command.shline",
    "stdout.txt",
    "stderr.txt",
}
EXPECTED_ARTIFACT_KINDS = {"backtrace", "snapshot", "log"}

errors: list[str] = []


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{rel(path)} is not valid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{rel(path)} must be a JSON object")
        return {}
    return value


def as_string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        err(f"{context} must be a non-empty array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def source_texts(test_sources: Any) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return texts
    for key, path_text in test_sources.items():
        if not isinstance(path_text, str) or not path_text:
            err(f"test_sources.{key} must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            err(f"test_sources.{key} references missing file: {path_text}")
            continue
        texts[key] = path.read_text(encoding="utf-8")
    return texts


def validate_file_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        err(f"{context} must be a file:line string")
        return
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines):
        err(f"{context} references line past EOF: {value}")
    elif not lines[line_no - 1].strip():
        err(f"{context} references a blank line: {value}")


def validate_crash_spec(spec: dict[str, Any], evidence: dict[str, Any]) -> None:
    if spec.get("bead") != ORIGINAL_BEAD:
        err("crash_bundle_spec bead must remain bd-6yd")
    bundle = spec.get("bundle_format", {})
    if not isinstance(bundle, dict):
        err("crash_bundle_spec.bundle_format must be an object")
        return
    required = bundle.get("required_artifacts", [])
    if not isinstance(required, list):
        err("crash_bundle_spec required_artifacts must be an array")
        return
    actual_artifacts = {
        item.get("filename")
        for item in required
        if isinstance(item, dict) and isinstance(item.get("filename"), str)
    }
    if not EXPECTED_ARTIFACTS.issubset(actual_artifacts):
        err("crash bundle required artifacts missing: " + ", ".join(sorted(EXPECTED_ARTIFACTS - actual_artifacts)))
    for item in required:
        if not isinstance(item, dict):
            err("required_artifacts entries must be objects")
            continue
        name = item.get("filename", "?")
        if not isinstance(item.get("max_size_bytes"), int) or item.get("max_size_bytes", 0) <= 0:
            err(f"{name}: missing positive max_size_bytes")
        if not isinstance(item.get("description"), str) or not item.get("description"):
            err(f"{name}: missing description")
        if not isinstance(item.get("format"), str) or not item.get("format"):
            err(f"{name}: missing format")
    evidence_artifact = next(
        (item for item in required if isinstance(item, dict) and item.get("filename") == "evidence_snapshot.jsonl"),
        {},
    )
    if evidence_artifact.get("max_records") != 256:
        err("evidence_snapshot.jsonl must remain bounded to max_records=256")

    telemetry = evidence.get("telemetry_primary", {})
    if not isinstance(telemetry, dict):
        err("telemetry_primary must be an object")
        return
    integration = spec.get("integration", {})
    if not isinstance(integration, dict):
        err("crash_bundle_spec.integration must be an object")
        return
    if telemetry.get("required_artifact") != "evidence_snapshot.jsonl":
        err("telemetry required_artifact must be evidence_snapshot.jsonl")
    if integration.get("log_schema_ref") != telemetry.get("required_log_schema_ref"):
        err("telemetry log_schema_ref is not bound to crash bundle spec")
    if integration.get("evidence_system_ref") != telemetry.get("required_evidence_system_ref"):
        err("telemetry evidence_system_ref is not bound to crash bundle spec")
    artifact_kinds = set(integration.get("artifact_kinds_used", []))
    if artifact_kinds != EXPECTED_ARTIFACT_KINDS:
        err("crash bundle artifact_kinds_used must be backtrace/snapshot/log")


def validate_unit_binding(unit: dict[str, Any], texts: dict[str, str]) -> list[str]:
    declared = set(as_string_list(unit.get("required_test_refs"), "unit_primary.required_test_refs"))
    if declared != EXPECTED_UNIT_TESTS:
        err("unit_primary.required_test_refs do not match crash_bundle_test coverage")
    unit_text = texts.get("unit", "")
    if not unit_text:
        err("unit source must be declared")
        return sorted(declared)
    for name in sorted(EXPECTED_UNIT_TESTS):
        if f"fn {name}" not in unit_text:
            err(f"crash_bundle_test missing test {name}")
    declared_artifacts = set(as_string_list(unit.get("required_spec_artifacts"), "unit_primary.required_spec_artifacts"))
    if declared_artifacts != EXPECTED_ARTIFACTS:
        err("unit_primary.required_spec_artifacts do not match expected artifact set")
    return sorted(declared)


def validate_e2e_binding(e2e: dict[str, Any]) -> str:
    script = e2e.get("gate_script")
    if script != "scripts/check_crash_bundle.sh":
        err("e2e_primary.gate_script must be scripts/check_crash_bundle.sh")
        return ""
    script_path = ROOT / script
    if not script_path.is_file():
        err("check_crash_bundle.sh is missing")
        return str(script)
    output = subprocess.run(
        ["bash", str(script_path)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stdout = output.stdout
    if output.returncode != 0:
        err("check_crash_bundle.sh failed during completion contract replay")
    required_stdout = e2e.get("required_stdout")
    if isinstance(required_stdout, str) and required_stdout not in stdout:
        err(f"check_crash_bundle.sh stdout missing {required_stdout!r}")
    for phrase in as_string_list(e2e.get("required_gate_checks"), "e2e_primary.required_gate_checks"):
        if phrase not in stdout:
            err(f"check_crash_bundle.sh stdout missing gate check {phrase!r}")
    return stdout


manifest = load_json(CONTRACT)
if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if manifest.get("bead") != COMPLETION_BEAD:
    err(f"bead must be {COMPLETION_BEAD}")
if manifest.get("original_bead") != ORIGINAL_BEAD:
    err(f"original_bead must be {ORIGINAL_BEAD}")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
if evidence.get("bead") != COMPLETION_BEAD:
    err("completion_debt_evidence.bead mismatch")
if evidence.get("original_bead") != ORIGINAL_BEAD:
    err("completion_debt_evidence.original_bead mismatch")
missing_items = set(as_string_list(evidence.get("missing_items"), "missing_items"))
if missing_items != EXPECTED_MISSING_ITEMS:
    err(f"missing_items should be {sorted(EXPECTED_MISSING_ITEMS)}")

texts = source_texts(evidence.get("test_sources"))
spec = load_json(ROOT / "tests/conformance/crash_bundle_spec.json")
validate_crash_spec(spec, evidence)
unit_refs = validate_unit_binding(evidence.get("unit_primary", {}), texts)
e2e_stdout = validate_e2e_binding(evidence.get("e2e_primary", {}))

telemetry = evidence.get("telemetry_primary", {})
if not isinstance(telemetry, dict):
    telemetry = {}
completion_artifacts = telemetry.get("completion_artifacts", {})
if not isinstance(completion_artifacts, dict):
    err("telemetry_primary.completion_artifacts must be an object")
    completion_artifacts = {}

implementation_refs = as_string_list(evidence.get("implementation_refs"), "implementation_refs")
if len(implementation_refs) < 20:
    err("implementation_refs should cite spec, gate, and unit coverage")
for index, ref in enumerate(implementation_refs):
    validate_file_line_ref(ref, f"implementation_refs[{index}]")

commands = set(as_string_list(evidence.get("validation_commands", {}).get("required"), "validation_commands.required"))
for expected in [
    "bash scripts/check_crash_bundle_completion_contract.sh",
    "bash scripts/check_crash_bundle.sh",
    "cargo test -p frankenlibc-harness --test crash_bundle_test -- --nocapture",
    "cargo test -p frankenlibc-harness --test crash_bundle_completion_contract_test -- --nocapture",
    "cargo clippy -p frankenlibc-harness --test crash_bundle_completion_contract_test -- -D warnings",
]:
    if expected not in commands:
        err(f"validation_commands.required missing {expected}")

if evidence.get("failure_signature") != "crash_bundle_completion_missing_unit_e2e_or_telemetry_evidence":
    err("failure_signature mismatch")

status = "fail" if errors else "pass"
report = {
    "schema_version": "crash_bundle_completion_contract.report.v1",
    "schema": EXPECTED_SCHEMA,
    "bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "source_commit": git_head(),
    "missing_items_bound": sorted(missing_items),
    "required_artifacts": sorted(EXPECTED_ARTIFACTS),
    "unit_refs": unit_refs,
    "e2e_gate_script": "scripts/check_crash_bundle.sh",
    "telemetry_artifact": "evidence_snapshot.jsonl",
    "telemetry_artifact_kinds": sorted(EXPECTED_ARTIFACT_KINDS),
    "implementation_refs": implementation_refs,
    "artifact_refs": evidence.get("artifact_refs", {}),
    "failure_signature": evidence.get("failure_signature"),
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

event = {
    "schema_version": "crash_bundle_completion_contract.log.v1",
    "event": "crash_bundle_completion_contract_failed" if errors else "crash_bundle_completion_contract_validated",
    "status": status,
    "trace_id": f"{COMPLETION_BEAD}:crash_bundle_completion",
    "bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": report["source_commit"],
    "timestamp": timestamp(),
    "artifact_refs": {
        "contract": rel(CONTRACT),
        "report": rel(REPORT),
        "log": rel(LOG),
    },
    "errors": errors,
}
with LOG.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(event, sort_keys=True) + "\n")

if errors:
    for message in errors:
        print(f"ERROR: {message}", file=sys.stderr)
    if e2e_stdout:
        print("--- check_crash_bundle.sh stdout ---", file=sys.stderr)
        print(e2e_stdout, file=sys.stderr)
    sys.exit(1)

print(
    "crash bundle completion contract validated: "
    f"missing_items={len(missing_items)} "
    f"artifacts={len(EXPECTED_ARTIFACTS)} "
    f"unit_refs={len(unit_refs)} "
    f"telemetry_kinds={len(EXPECTED_ARTIFACT_KINDS)}"
)
PY
