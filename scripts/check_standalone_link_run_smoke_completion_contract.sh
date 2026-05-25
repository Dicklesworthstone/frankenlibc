#!/usr/bin/env bash
# check_standalone_link_run_smoke_completion_contract.sh - bd-bp8fl.6.2.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_STANDALONE_SMOKE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/standalone_link_run_smoke_completion_contract.v1.json}"
SMOKE_MANIFEST="${FRANKENLIBC_STANDALONE_SMOKE_MANIFEST:-$ROOT/tests/conformance/standalone_link_run_smoke.v1.json}"
REPORT="${FRANKENLIBC_STANDALONE_SMOKE_COMPLETION_REPORT:-$ROOT/target/conformance/standalone_link_run_smoke_completion_contract.report.json}"
LOG="${FRANKENLIBC_STANDALONE_SMOKE_COMPLETION_LOG:-$ROOT/target/conformance/standalone_link_run_smoke_completion_contract.log.jsonl}"
SMOKE_REPORT="${FRANKENLIBC_STANDALONE_SMOKE_COMPLETION_SMOKE_REPORT:-$ROOT/target/conformance/standalone_link_run_smoke_completion_contract.smoke.report.json}"
SMOKE_LOG="${FRANKENLIBC_STANDALONE_SMOKE_COMPLETION_SMOKE_LOG:-$ROOT/target/conformance/standalone_link_run_smoke_completion_contract.smoke.log.jsonl}"
SMOKE_TARGET_DIR="${FRANKENLIBC_STANDALONE_SMOKE_COMPLETION_TARGET_DIR:-$ROOT/target/standalone_link_run_smoke_completion_contract}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$SMOKE_REPORT")" "$(dirname "$SMOKE_LOG")" "$SMOKE_TARGET_DIR"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
SMOKE_MANIFEST="$SMOKE_MANIFEST" \
REPORT="$REPORT" \
LOG="$LOG" \
SMOKE_REPORT="$SMOKE_REPORT" \
SMOKE_LOG="$SMOKE_LOG" \
SMOKE_TARGET_DIR="$SMOKE_TARGET_DIR" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
SMOKE_MANIFEST = pathlib.Path(os.environ["SMOKE_MANIFEST"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
SMOKE_REPORT = pathlib.Path(os.environ["SMOKE_REPORT"])
SMOKE_LOG = pathlib.Path(os.environ["SMOKE_LOG"])
SMOKE_TARGET_DIR = pathlib.Path(os.environ["SMOKE_TARGET_DIR"])

COMPLETION_BEAD = "bd-bp8fl.6.2.1"
ORIGINAL_BEAD = "bd-bp8fl.6.2"
EXPECTED_SCHEMA = "standalone_link_run_smoke_completion_contract.v1"
EXPECTED_MANIFEST = "bd-bp8fl.6.2.1-standalone-link-run-smoke-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "metamorphic_primary": "tests.metamorphic.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_RELATIONS = {
    "strict_hardened_claim_block_invariance",
    "ld_preload_forbidden_direct_link_invariance",
    "source_only_dry_run_claim_block_invariance",
    "host_baseline_artifact_shape_invariance",
}
EXPECTED_TELEMETRY_EVENTS = {
    "standalone_link_run_smoke_completion_contract_validated",
    "standalone_link_run_smoke_completion_contract_failed",
    "standalone_link_run_smoke_summary",
    "standalone_link_run_smoke_metamorphic_relations_preserved",
    "standalone_link_run_smoke_claim_block_preserved",
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "status",
    "source_commit",
    "missing_items_bound",
    "test_refs",
    "smoke_summary",
    "smoke_report",
    "metamorphic_results",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


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


def load_jsonl(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"{label} is not readable: {rel(path)}: {exc}")
        return rows
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            err(f"{label} line {index} is not valid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            err(f"{label} line {index} must be an object")
            continue
        rows.append(row)
    return rows


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
    line_number = int(line_text)
    if line_number > len(lines):
        err(f"{context} references line past EOF: {value}")
    elif not lines[line_number - 1].strip():
        err(f"{context} references a blank line: {value}")


def source_texts(test_sources: Any) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return texts
    for key, path_text in test_sources.items():
        if not isinstance(key, str) or not key:
            err("test_sources keys must be non-empty strings")
            continue
        if not isinstance(path_text, str) or not path_text:
            err(f"test_sources.{key} must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            err(f"test_sources.{key} references missing file: {path_text}")
            continue
        texts[key] = path.read_text(encoding="utf-8")
    return texts


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not source:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].source must be non-empty")
            continue
        if not isinstance(name, str) or not name:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].name must be non-empty")
            continue
        key = (source, name)
        if key in seen:
            err(f"completion_debt_evidence.{section_name} duplicates test ref {source}::{name}")
        seen.add(key)
        text = texts.get(source, "")
        if not text:
            err(f"completion_debt_evidence.{section_name} references unknown source {source}")
        elif not function_exists(text, name):
            err(f"completion_debt_evidence.{section_name} references missing test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


def validate_required_commands(section: dict[str, Any], section_name: str) -> None:
    commands = as_string_list(section.get("required_commands"), f"completion_debt_evidence.{section_name}.required_commands")
    for command in commands:
        if "cargo " in command and "rch exec --" not in command:
            err(f"completion_debt_evidence.{section_name}.required_commands must route cargo through rch: {command}")


def run_smoke_gate() -> None:
    env = os.environ.copy()
    env.update(
        {
            "STANDALONE_SMOKE_MANIFEST": str(SMOKE_MANIFEST),
            "STANDALONE_SMOKE_REPORT": str(SMOKE_REPORT),
            "STANDALONE_SMOKE_LOG": str(SMOKE_LOG),
            "STANDALONE_SMOKE_TARGET_DIR": str(SMOKE_TARGET_DIR),
            "STANDALONE_SMOKE_RUN_ID": "completion-contract-dry-run",
        }
    )
    env.pop("FRANKENLIBC_STANDALONE_LIB", None)
    env.pop("LD_PRELOAD", None)
    result = subprocess.run(
        ["bash", "scripts/check_standalone_link_run_smoke.sh", "--dry-run"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        err(
            "standalone smoke dry-run gate failed: "
            f"exit={result.returncode} stdout={result.stdout[-1200:]} stderr={result.stderr[-1200:]}"
        )


def candidate_results_by_mode(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for result in row.get("candidate_results", []):
        if isinstance(result, dict) and isinstance(result.get("runtime_mode"), str):
            results[result["runtime_mode"]] = result
    return results


def validate_metamorphic_relations(
    manifest: dict[str, Any],
    smoke_report: dict[str, Any],
    smoke_log_rows: list[dict[str, Any]],
    expected_candidate_rows: int,
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}

    invariant_ok = True
    checked_rows = 0
    for row in smoke_report.get("rows", []):
        if not isinstance(row, dict):
            invariant_ok = False
            continue
        by_mode = candidate_results_by_mode(row)
        strict = by_mode.get("strict")
        hardened = by_mode.get("hardened")
        if not strict or not hardened:
            invariant_ok = False
            continue
        checked_rows += 1
        if strict.get("actual_status") != "claim_blocked" or hardened.get("actual_status") != "claim_blocked":
            invariant_ok = False
        if strict.get("failure_signature") != hardened.get("failure_signature"):
            invariant_ok = False
    results["strict_hardened_claim_block_invariance"] = {
        "status": "pass" if invariant_ok and checked_rows else "fail",
        "checked_rows": checked_rows,
    }

    ld_preload_ok = True
    for row in manifest.get("smoke_rows", []):
        if not isinstance(row, dict):
            ld_preload_ok = False
            continue
        forbidden = row.get("runtime_env", {}).get("forbidden", [])
        if "LD_PRELOAD" not in forbidden:
            ld_preload_ok = False
        for key in ["baseline_template", "candidate_template"]:
            for token in row.get("link_command", {}).get(key, []):
                if "LD_PRELOAD" in str(token):
                    ld_preload_ok = False
    for row in smoke_log_rows:
        for arg in row.get("link_args", []):
            if "LD_PRELOAD" in str(arg):
                ld_preload_ok = False
    results["ld_preload_forbidden_direct_link_invariance"] = {
        "status": "pass" if ld_preload_ok else "fail",
        "checked_log_rows": len(smoke_log_rows),
    }

    summary = smoke_report.get("summary") if isinstance(smoke_report.get("summary"), dict) else {}
    allowed_levels = set(
        completion.get("minimum_smoke_expectations", {}).get(
            "current_levels_allowed_without_standalone_claim", ["L0"]
        )
    )
    source_only_ok = (
        smoke_report.get("status") == "pass"
        and smoke_report.get("claim_status") == "claim_blocked"
        and smoke_report.get("current_level") in allowed_levels
        and smoke_report.get("ld_preload_evidence_accepted") is False
        and summary.get("candidate_blocked", 0) >= expected_candidate_rows
        and smoke_report.get("artifact_state", {}).get("status") != "current"
    )
    results["source_only_dry_run_claim_block_invariance"] = {
        "status": "pass" if source_only_ok else "fail",
        "candidate_blocked": summary.get("candidate_blocked", 0),
    }

    artifact_shape_ok = True
    for row in smoke_report.get("rows", []):
        if not isinstance(row, dict):
            artifact_shape_ok = False
            continue
        refs = [str(value) for value in row.get("artifact_refs", [])]
        if not any(ref.endswith(".c") for ref in refs):
            artifact_shape_ok = False
        if not any(ref.endswith("baseline.link.txt") for ref in refs):
            artifact_shape_ok = False
        if not any(ref.endswith("candidate.link.txt") for ref in refs):
            artifact_shape_ok = False
        if row.get("baseline_status") != "dry_run":
            artifact_shape_ok = False
    results["host_baseline_artifact_shape_invariance"] = {
        "status": "pass" if artifact_shape_ok and smoke_report.get("rows") else "fail",
        "checked_rows": len(smoke_report.get("rows", [])),
    }

    for relation_id, result in results.items():
        if result["status"] != "pass":
            err(f"metamorphic relation failed: {relation_id}")
    return results


manifest = load_json(CONTRACT, "completion contract")
smoke_manifest = load_json(SMOKE_MANIFEST, "standalone smoke manifest")
source_commit = git_head()

run_smoke_gate()
smoke_report = load_json(SMOKE_REPORT, "standalone smoke dry-run report")
smoke_log_rows = load_jsonl(SMOKE_LOG, "standalone smoke dry-run log")

if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if manifest.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")

source_artifacts = manifest.get("source_artifacts")
if not isinstance(source_artifacts, dict):
    err("source_artifacts must be an object")
    source_artifacts = {}
for key in ["smoke_manifest", "smoke_gate", "smoke_harness", "completion_gate", "completion_harness"]:
    path_text = source_artifacts.get(key)
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{key} must be a non-empty string")
    elif not (ROOT / path_text).is_file():
        err(f"source_artifacts.{key} references missing file: {path_text}")

completion = manifest.get("completion_debt_evidence")
if not isinstance(completion, dict):
    err("completion_debt_evidence must be an object")
    completion = {}
if completion.get("bead") != COMPLETION_BEAD:
    err(f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
if completion.get("original_bead") != ORIGINAL_BEAD:
    err(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
threshold = completion.get("next_audit_score_threshold")
if not isinstance(threshold, int) or threshold < 800 or threshold > 1000:
    err("completion_debt_evidence.next_audit_score_threshold must be 800..1000")

implementation_refs = completion.get("implementation_refs")
if not isinstance(implementation_refs, list) or len(implementation_refs) < 20:
    err("completion_debt_evidence.implementation_refs must contain at least 20 file:line refs")
else:
    for index, ref in enumerate(implementation_refs):
        validate_file_line_ref(ref, f"completion_debt_evidence.implementation_refs[{index}]")

required_categories = set(as_string_list(completion.get("required_smoke_categories"), "required_smoke_categories"))
manifest_categories = set(as_string_list(smoke_manifest.get("summary", {}).get("required_categories"), "smoke_manifest.summary.required_categories"))
if required_categories != manifest_categories:
    err("required_smoke_categories must match standalone smoke manifest summary.required_categories")

required_log_fields = set(as_string_list(completion.get("required_log_fields"), "required_log_fields"))
manifest_log_fields = set(as_string_list(smoke_manifest.get("required_log_fields"), "smoke_manifest.required_log_fields"))
missing_log_fields = sorted(manifest_log_fields - required_log_fields)
if missing_log_fields:
    err(f"required_log_fields missing {missing_log_fields}")

expected_signatures = {
    row.get("failure_signature")
    for row in smoke_manifest.get("expected_failure_classifications", [])
    if isinstance(row, dict)
}
completion_signatures = set(as_string_list(completion.get("required_failure_signatures"), "required_failure_signatures"))
if completion_signatures != expected_signatures:
    err("required_failure_signatures must match standalone smoke manifest classifications")

relations = completion.get("required_metamorphic_relations")
if not isinstance(relations, list) or not relations:
    err("required_metamorphic_relations must be non-empty")
    relation_ids: set[str] = set()
else:
    relation_ids = {row.get("id") for row in relations if isinstance(row, dict)}
    if relation_ids != EXPECTED_RELATIONS:
        err(f"required_metamorphic_relations must be {sorted(EXPECTED_RELATIONS)}")

texts = source_texts(completion.get("test_sources"))
missing_items_bound: list[str] = []
test_refs_by_section: dict[str, list[dict[str, str]]] = {}
for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
    section = completion.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    section_threshold = section.get("next_audit_score_threshold", threshold)
    if not isinstance(section_threshold, int) or section_threshold < 800:
        err(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be >= 800")
    missing_items_bound.append(str(section.get("missing_item_id", "")))
    test_refs_by_section[section_name] = validate_test_refs(section, section_name, texts)
    if section_name != "telemetry_primary":
        validate_required_commands(section, section_name)

telemetry = completion.get("telemetry_primary") if isinstance(completion.get("telemetry_primary"), dict) else {}
required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
missing_events = sorted(EXPECTED_TELEMETRY_EVENTS - required_events)
if missing_events:
    err(f"telemetry_primary.required_events missing {missing_events}")
required_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
missing_fields = sorted(EXPECTED_TELEMETRY_FIELDS - required_fields)
if missing_fields:
    err(f"telemetry_primary.required_fields missing {missing_fields}")

minimums = completion.get("minimum_smoke_expectations")
if not isinstance(minimums, dict):
    err("minimum_smoke_expectations must be an object")
    minimums = {}

summary = smoke_report.get("summary") if isinstance(smoke_report.get("summary"), dict) else {}
artifact_state = smoke_report.get("artifact_state") if isinstance(smoke_report.get("artifact_state"), dict) else {}
smoke_row_count = int(smoke_manifest.get("summary", {}).get("row_count", 0))
runtime_mode_count = len(minimums.get("runtime_modes", ["strict", "hardened"]))
expected_candidate_rows = smoke_row_count * runtime_mode_count

if smoke_report.get("status") != "pass":
    err("standalone smoke dry-run report must pass")
if smoke_report.get("bead") != ORIGINAL_BEAD:
    err(f"standalone smoke dry-run report bead must be {ORIGINAL_BEAD}")
allowed_levels = set(minimums.get("current_levels_allowed_without_standalone_claim", ["L0"]))
if smoke_report.get("current_level") not in allowed_levels:
    err("standalone smoke dry-run report must keep current_level below L2")
if smoke_report.get("claim_status") != minimums.get("claim_status", "claim_blocked"):
    err("standalone smoke dry-run report must preserve claim_status=claim_blocked")
if smoke_report.get("ld_preload_evidence_accepted") is not minimums.get("ld_preload_evidence_accepted", False):
    err("standalone smoke dry-run report must reject LD_PRELOAD evidence")
if summary.get("rows") != minimums.get("smoke_row_count", smoke_row_count):
    err("standalone smoke dry-run row count drifted")
if summary.get("positive_rows") != minimums.get("positive_row_count", 8):
    err("standalone smoke dry-run positive row count drifted")
if summary.get("negative_rows") != minimums.get("negative_row_count", 2):
    err("standalone smoke dry-run negative row count drifted")
if summary.get("candidate_blocked", 0) < minimums.get("candidate_blocked_min", expected_candidate_rows):
    err("standalone smoke dry-run did not block every strict+hardened candidate row")
allowed_artifact_states = set(minimums.get("source_only_artifact_states_allowed", []))
if artifact_state.get("status") not in allowed_artifact_states:
    err(f"source-only artifact_state.status must be one of {sorted(allowed_artifact_states)}")

if not smoke_log_rows:
    err("standalone smoke dry-run log must contain JSONL rows")
for index, row in enumerate(smoke_log_rows):
    missing = sorted(manifest_log_fields - set(row))
    if missing:
        err(f"standalone smoke dry-run log row {index + 1} missing fields {missing}")

metamorphic_results = validate_metamorphic_relations(
    smoke_manifest,
    smoke_report,
    smoke_log_rows,
    expected_candidate_rows,
)

status = "pass" if not errors else "fail"


def event_payload(event: str, level: str, failure_signature: str = "none") -> dict[str, Any]:
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trace_id": f"{COMPLETION_BEAD}::{event}",
        "event": event,
        "level": level,
        "bead_id": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "status": status,
        "source_commit": source_commit,
        "missing_items_bound": missing_items_bound,
        "test_refs": test_refs_by_section,
        "smoke_summary": summary,
        "smoke_report": rel(SMOKE_REPORT),
        "metamorphic_results": metamorphic_results,
        "artifact_refs": [
            rel(CONTRACT),
            rel(SMOKE_MANIFEST),
            rel(SMOKE_REPORT),
            rel(SMOKE_LOG),
            rel(REPORT),
            rel(LOG),
        ],
        "failure_signature": failure_signature,
    }


events: list[dict[str, Any]] = [
    event_payload("standalone_link_run_smoke_summary", "info"),
    event_payload("standalone_link_run_smoke_metamorphic_relations_preserved", "info"),
]
if summary.get("candidate_blocked", 0) >= expected_candidate_rows:
    events.append(event_payload("standalone_link_run_smoke_claim_block_preserved", "warning"))
if errors:
    events.append(event_payload("standalone_link_run_smoke_completion_contract_failed", "error", ",".join(errors[:8])))
else:
    events.append(event_payload("standalone_link_run_smoke_completion_contract_validated", "info"))

for index, event in enumerate(events):
    missing = sorted(EXPECTED_TELEMETRY_FIELDS - set(event))
    if missing:
        err(f"generated telemetry event {index} missing fields {missing}")
if not errors:
    emitted = {event["event"] for event in events}
    required_for_pass = EXPECTED_TELEMETRY_EVENTS - {"standalone_link_run_smoke_completion_contract_failed"}
    missing = sorted(required_for_pass - emitted)
    if missing:
        err(f"pass telemetry missing events {missing}")
        status = "fail"

LOG.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)

report = {
    "schema_version": "standalone_link_run_smoke_completion_contract.report.v1",
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": {
        "smoke_rows": summary.get("rows", 0),
        "positive_rows": summary.get("positive_rows", 0),
        "negative_rows": summary.get("negative_rows", 0),
        "candidate_blocked": summary.get("candidate_blocked", 0),
        "candidate_failed": summary.get("candidate_failed", 0),
        "baseline_dry_run": summary.get("baseline_dry_run", 0),
        "claim_status": smoke_report.get("claim_status"),
        "current_level": smoke_report.get("current_level"),
        "ld_preload_evidence_accepted": smoke_report.get("ld_preload_evidence_accepted"),
        "artifact_state": artifact_state,
    },
    "missing_items_bound": missing_items_bound,
    "test_refs": test_refs_by_section,
    "metamorphic_results": metamorphic_results,
    "required_telemetry_events": sorted(required_events),
    "required_telemetry_fields": sorted(required_fields),
    "smoke_report": rel(SMOKE_REPORT),
    "smoke_log": rel(SMOKE_LOG),
    "errors": errors,
    "log": rel(LOG),
    "artifact_refs": [
        rel(CONTRACT),
        rel(SMOKE_MANIFEST),
        rel(SMOKE_REPORT),
        rel(SMOKE_LOG),
        rel(REPORT),
        rel(LOG),
    ],
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: standalone link-run smoke completion contract ({len(errors)} errors)")
    for message in errors[:20]:
        print(f"  - {message}")
    raise SystemExit(1)

print(
    "PASS: standalone link-run smoke completion contract "
    f"(rows={summary.get('rows', 0)}, "
    f"candidate_blocked={summary.get('candidate_blocked', 0)}, "
    f"report={rel(REPORT)})"
)
PY
