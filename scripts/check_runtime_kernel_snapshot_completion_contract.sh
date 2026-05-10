#!/usr/bin/env bash
# check_runtime_kernel_snapshot_completion_contract.sh - bd-oai.2.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_KERNEL_SNAPSHOT_CONTRACT:-$ROOT/tests/conformance/runtime_kernel_snapshot_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_KERNEL_SNAPSHOT_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_RUNTIME_KERNEL_SNAPSHOT_REPORT:-$OUT_DIR/runtime_kernel_snapshot_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_KERNEL_SNAPSHOT_LOG:-$OUT_DIR/runtime_kernel_snapshot_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "runtime_kernel_snapshot_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "runtime_kernel_snapshot_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-oai.2.1-runtime-kernel-snapshot-completion-contract"
ORIGINAL_BEAD = "bd-oai.2"
COMPLETION_BEAD = "bd-oai.2.1"
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
PASS_EVENTS = {
    "runtime_kernel_snapshot_unit_bindings_verified",
    "runtime_kernel_snapshot_golden_verified",
    "runtime_kernel_snapshot_e2e_bindings_verified",
    "runtime_kernel_snapshot_completion_contract_pass",
}
FAIL_EVENT = "runtime_kernel_snapshot_completion_contract_fail"
REQUIRED_UNIT_TEST_NAMES = {
    "runtime_kernel_snapshot_schema_and_literal_cover_all_fields",
    "snapshot_literal_never_relocks_summary_mutexes",
    "snapshot_contract_ranges_are_sane_for_fresh_kernel",
    "snapshot_decision_and_evidence_counters_are_monotone",
    "fixture_is_stable_for_same_seed_steps",
    "fixture_serializes_structured_snapshot_payload",
    "snapshot_field_map_preserves_scalar_and_array_values",
    "diff_kernel_snapshots_uses_structured_snapshot_payloads",
}
REQUIRED_E2E_TEST_NAMES = {
    "runtime_math_kernel_snapshot_golden_checksum_matches_manifest",
    "manifest_binds_runtime_kernel_snapshot_unit_and_e2e_items",
    "checker_validates_snapshot_contract_and_emits_report_log",
    "checker_rejects_snapshot_field_floor_drift",
    "checker_rejects_missing_unit_test_binding",
    "checker_rejects_golden_hash_drift",
}

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


def git_head() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


SOURCE_COMMIT = git_head()


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


def artifact_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must be repo-relative without parent traversal: {path_text}")
        return None
    full = ROOT / path
    if not full.is_file():
        err(f"{context} references missing file: {path_text}")
        return None
    return full


def source_text(path_text: Any, context: str) -> str:
    path = artifact_path(path_text, context)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {path_text}: {exc}")
        return ""


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}(" in text or f"fn {name}<" in text


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_sha_manifest(path: pathlib.Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"sha256 manifest unreadable: {rel(path)}: {exc}")
        return rows
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            err(f"sha256 manifest line {line_no} must contain digest and filename")
            continue
        digest, filename = parts
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            err(f"sha256 manifest line {line_no} has invalid lowercase sha256 digest")
            continue
        rows[filename] = digest
    return rows


def snapshot_struct_fields(source: str) -> list[str]:
    marker = "pub struct RuntimeKernelSnapshot {"
    start = source.find(marker)
    if start < 0:
        err("RuntimeKernelSnapshot struct definition missing")
        return []
    tail = source[start + len(marker):]
    end = tail.find("\n}\n\n/// Online control kernel")
    if end < 0:
        err("RuntimeKernelSnapshot struct end marker missing")
        return []
    fields: list[str] = []
    for line in tail[:end].splitlines():
        trimmed = line.strip()
        if not trimmed.startswith("pub "):
            continue
        name = trimmed[4:].split(":", 1)[0].strip()
        if name:
            fields.append(name)
    return fields


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
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
            "outcome": "pass" if status == "pass" else "fail",
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "runtime_kernel_snapshot_completion_contract_failed",
            "details": details,
        }
    )


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("source_artifacts", {})
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    out: dict[str, str] = {}
    for artifact_id, path_text in artifacts.items():
        artifact_path(path_text, f"source_artifacts.{artifact_id}")
        if isinstance(path_text, str):
            out[str(artifact_id)] = path_text
    return out


def validate_test_refs(
    section: dict[str, Any],
    section_name: str,
    sources: dict[str, str],
    required_names: set[str],
) -> list[str]:
    found: list[str] = []
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"{section_name}.required_test_refs must be a non-empty array")
        return found
    source_cache = {source_id: source_text(path, f"test_source.{source_id}") for source_id, path in sources.items()}
    for index, ref_obj in enumerate(refs):
        if not isinstance(ref_obj, dict):
            err(f"{section_name}.required_test_refs[{index}] must be an object")
            continue
        source_id = ref_obj.get("source")
        name = ref_obj.get("name")
        if not isinstance(source_id, str) or source_id not in source_cache:
            err(f"{section_name}.required_test_refs[{index}] references unknown source {source_id!r}")
            continue
        if not isinstance(name, str) or not function_exists(source_cache[source_id], name):
            err(f"{section_name}.required_test_refs[{index}] missing test {source_id}::{name}")
            continue
        found.append(f"{source_id}::{name}")
    found_names = {item.split("::", 1)[1] for item in found if "::" in item}
    missing_required = sorted(required_names - found_names)
    if missing_required:
        err(f"{section_name}.required_test_refs missing required bindings {missing_required}")
    for command in section.get("required_commands", []):
        if not isinstance(command, str):
            err(f"{section_name}.required_commands entries must be strings")
            continue
        if "cargo " in command and "rch exec" not in command and not command.startswith("rch cargo "):
            err(f"{section_name} cargo command must be rch-backed: {command}")
    return found


def validate_snapshot_contract(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest.get("required_snapshot_contract", {})
    if not isinstance(contract, dict):
        err("required_snapshot_contract must be an object")
        contract = {}

    golden_path = artifact_path(artifacts.get("golden_snapshot"), "source_artifacts.golden_snapshot")
    sha_path = artifact_path(artifacts.get("golden_sha256s"), "source_artifacts.golden_sha256s")
    mod_text = source_text(artifacts.get("runtime_math_mod"), "source_artifacts.runtime_math_mod")

    struct_fields = snapshot_struct_fields(mod_text)
    minimum = int(contract.get("minimum_snapshot_fields", -1))
    expected_current = int(contract.get("current_snapshot_fields", -1))
    require(minimum >= 154, "minimum_snapshot_fields must preserve the 154-field baseline")
    require(len(struct_fields) >= minimum, "RuntimeKernelSnapshot field count is below contract minimum")
    require(len(struct_fields) == expected_current, "current_snapshot_fields must match RuntimeKernelSnapshot field count")

    snapshot_summary: dict[str, Any] = {
        "struct_field_count": len(struct_fields),
        "strict_field_count": None,
        "hardened_field_count": None,
        "sha256": None,
    }
    if golden_path is not None:
        golden = load_json(golden_path, "golden snapshot")
        scenario = golden.get("scenario", {}) if isinstance(golden, dict) else {}
        expected_scenario = contract.get("scenario", {})
        if not isinstance(expected_scenario, dict):
            expected_scenario = {}
            err("required_snapshot_contract.scenario must be an object")
        require(golden.get("version") == "v1", "golden snapshot version must be v1")
        require(scenario.get("id") == expected_scenario.get("id"), "golden scenario id mismatch")
        require(scenario.get("seed") == expected_scenario.get("seed"), "golden scenario seed mismatch")
        require(scenario.get("steps") == expected_scenario.get("steps"), "golden scenario steps mismatch")
        require(
            scenario.get("families") == expected_scenario.get("required_families"),
            "golden scenario families mismatch",
        )
        for mode in as_string_list(contract.get("modes"), "required_snapshot_contract.modes"):
            mode_obj = golden.get(mode)
            if not isinstance(mode_obj, dict):
                err(f"golden snapshot missing mode {mode}")
                continue
            require(mode_obj.get("mode") == mode, f"golden {mode}.mode mismatch")
            snapshot = mode_obj.get("snapshot")
            if not isinstance(snapshot, dict):
                err(f"golden {mode}.snapshot must be an object")
                continue
            field_count = len(snapshot)
            snapshot_summary[f"{mode}_field_count"] = field_count
            require(field_count >= minimum, f"golden {mode} snapshot field count below minimum")
            require(field_count == expected_current, f"golden {mode} snapshot field count mismatch")
            require(
                snapshot.get("schema_version") == contract.get("snapshot_schema_version"),
                f"golden {mode} schema_version mismatch",
            )
            for field in as_string_list(contract.get("required_snapshot_fields"), "required_snapshot_contract.required_snapshot_fields"):
                require(field in snapshot, f"golden {mode} snapshot missing required field {field}")
        actual_sha = sha256_file(golden_path)
        snapshot_summary["sha256"] = actual_sha
        expected_sha = contract.get("expected_sha256")
        require(actual_sha == expected_sha, "golden snapshot sha256 drift")
        if sha_path is not None:
            rows = parse_sha_manifest(sha_path)
            expected_filename = contract.get("expected_filename")
            require(rows.get(str(expected_filename)) == expected_sha, "sha256 manifest does not pin expected golden digest")

    required_gate_text = contract.get("required_gate_text", {})
    if not isinstance(required_gate_text, dict):
        err("required_snapshot_contract.required_gate_text must be an object")
        required_gate_text = {}
    for artifact_id, needles in required_gate_text.items():
        path_text = artifacts.get(str(artifact_id))
        text = source_text(path_text, f"required_gate_text.{artifact_id}")
        for needle in as_string_list(needles, f"required_gate_text.{artifact_id}"):
            require(needle in text, f"{artifact_id} missing required text {needle!r}")

    return snapshot_summary


def write_outputs(manifest: dict[str, Any], status: str, snapshot_summary: dict[str, Any], unit_refs: list[str], e2e_refs: list[str]) -> None:
    telemetry = manifest.get("telemetry_contract", {}) if isinstance(manifest, dict) else {}
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id") if isinstance(manifest, dict) else None,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "snapshot_contract": snapshot_summary,
        "unit_bindings": unit_refs,
        "e2e_bindings": e2e_refs,
        "events": events,
        "errors": errors,
    }
    for field in as_string_list(telemetry.get("required_report_fields") if isinstance(telemetry, dict) else [], "telemetry.required_report_fields", allow_empty=True):
        if field not in report:
            err(f"report missing required telemetry field {field}")
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")


started = time.time_ns()
manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("manifest_id") == EXPECTED_MANIFEST, f"manifest_id must be {EXPECTED_MANIFEST}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
artifacts = validate_source_artifacts(manifest)

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
missing_items = evidence.get("missing_items_closed")
require(set(as_string_list(missing_items, "completion_debt_evidence.missing_items_closed")) == REQUIRED_MISSING_ITEMS, "missing_items_closed must be exactly unit and e2e primary")

unit_section = evidence.get("unit_primary", {})
if not isinstance(unit_section, dict):
    err("unit_primary must be an object")
    unit_section = {}
e2e_section = evidence.get("e2e_primary", {})
if not isinstance(e2e_section, dict):
    err("e2e_primary must be an object")
    e2e_section = {}
require(unit_section.get("missing_item_id") == "tests.unit.primary", "unit_primary missing_item_id mismatch")
require(e2e_section.get("missing_item_id") == "tests.e2e.primary", "e2e_primary missing_item_id mismatch")

unit_sources = {
    "runtime_math_mod": artifacts.get("runtime_math_mod", ""),
    "kernel_snapshot_source": artifacts.get("kernel_snapshot_source", ""),
    "snapshot_diff_source": artifacts.get("snapshot_diff_source", ""),
}
e2e_sources = {
    "determinism_harness_test": artifacts.get("determinism_harness_test", ""),
    "completion_harness_test": artifacts.get("completion_harness_test", ""),
}
unit_refs = validate_test_refs(unit_section, "unit_primary", unit_sources, REQUIRED_UNIT_TEST_NAMES)
e2e_refs = validate_test_refs(e2e_section, "e2e_primary", e2e_sources, REQUIRED_E2E_TEST_NAMES)
for script in as_string_list(e2e_section.get("required_scripts"), "e2e_primary.required_scripts"):
    require(script in artifacts.values(), f"e2e required script {script} must be listed in source_artifacts")

snapshot_summary = validate_snapshot_contract(manifest, artifacts)
elapsed_ns = time.time_ns() - started

if not errors:
    append_event(
        "runtime_kernel_snapshot_unit_bindings_verified",
        "pass",
        [artifacts.get("runtime_math_mod", ""), artifacts.get("kernel_snapshot_source", ""), artifacts.get("snapshot_diff_source", "")],
        {"unit_test_refs": unit_refs, "unit_test_ref_count": len(unit_refs)},
    )
    append_event(
        "runtime_kernel_snapshot_golden_verified",
        "pass",
        [artifacts.get("golden_snapshot", ""), artifacts.get("golden_sha256s", "")],
        snapshot_summary,
    )
    append_event(
        "runtime_kernel_snapshot_e2e_bindings_verified",
        "pass",
        [artifacts.get("snapshot_gate", ""), artifacts.get("harness_cli", ""), artifacts.get("determinism_harness_test", "")],
        {"e2e_test_refs": e2e_refs, "e2e_test_ref_count": len(e2e_refs)},
    )
    append_event(
        "runtime_kernel_snapshot_completion_contract_pass",
        "pass",
        [rel(CONTRACT), rel(REPORT), rel(LOG)],
        {"elapsed_ns": elapsed_ns},
    )
    status = "pass"
else:
    append_event(
        FAIL_EVENT,
        "fail",
        [rel(CONTRACT), rel(REPORT), rel(LOG)],
        {"errors": errors[:16], "elapsed_ns": elapsed_ns},
    )
    status = "fail"

write_outputs(manifest, status, snapshot_summary, unit_refs, e2e_refs)

if status == "pass":
    print(
        "PASS: runtime kernel snapshot completion contract "
        f"fields={snapshot_summary.get('struct_field_count')} "
        f"sha256={snapshot_summary.get('sha256')}"
    )
else:
    print("FAIL: runtime kernel snapshot completion contract", file=os.sys.stderr)
    for message in errors:
        print(f" - {message}", file=os.sys.stderr)
    raise SystemExit(1)
PY
