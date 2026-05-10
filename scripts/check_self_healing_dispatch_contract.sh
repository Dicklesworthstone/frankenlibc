#!/usr/bin/env bash
# Gate for bd-32e.4.1 self-healing dispatch completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SELF_HEALING_CONTRACT:-$ROOT/tests/conformance/self_healing_dispatch_contract.v1.json}"
REPORT="${FRANKENLIBC_SELF_HEALING_REPORT:-$ROOT/target/conformance/self_healing_dispatch_contract.report.json}"
LOG="${FRANKENLIBC_SELF_HEALING_LOG:-$ROOT/target/conformance/self_healing_dispatch_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

COMPLETION_BEAD = "bd-32e.4.1"
ORIGINAL_BEAD = "bd-32e.4"
EXPECTED_SCHEMA = "self_healing_dispatch_contract.v1"
EXPECTED_MANIFEST = "bd-32e.4.1-self-healing-dispatch-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_HEALING_ACTIONS = {
    "ClampSize",
    "TruncateWithNull",
    "IgnoreDoubleFree",
    "IgnoreForeignFree",
    "ReallocAsMalloc",
    "ReturnSafeDefault",
    "UpgradeToSafeVariant",
}
EXPECTED_ENUM_VARIANTS = EXPECTED_HEALING_ACTIONS | {"None"}
EXPECTED_COUNTER_FIELDS = {
    "total_heals",
    "size_clamps",
    "null_truncations",
    "double_frees",
    "foreign_frees",
    "realloc_as_mallocs",
    "safe_defaults",
    "variant_upgrades",
}
EXPECTED_HEALING_LOG_FIELDS = {
    "trace_id",
    "decision_id",
    "schema_version",
    "bead_id",
    "runtime_mode",
    "level",
    "api_family",
    "decision_path",
    "outcome",
    "healing_action",
    "escalated",
    "details",
}
EXPECTED_LEVELS = {"info", "warn"}
EXPECTED_TELEMETRY_EVENTS = {
    "self_healing_dispatch_contract_validated",
    "self_healing_dispatch_contract_failed",
    "healing_dispatch",
    "healing_evidence",
    "hardened_repair_matrix",
    "runtime_evidence_verifier",
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "completion_debt_bead",
    "original_bead",
    "status",
    "source_commit",
    "missing_items_bound",
    "required_healing_actions",
    "required_enum_variants",
    "required_counter_fields",
    "required_healing_log_fields",
    "required_events",
    "required_fields",
    "test_refs",
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


def validate_test_refs(
    section: dict[str, Any], section_name: str, texts: dict[str, str]
) -> list[dict[str, str]]:
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
            err(
                f"completion_debt_evidence.{section_name}.required_test_refs[{index}].source must be non-empty"
            )
            continue
        if not isinstance(name, str) or not name:
            err(
                f"completion_debt_evidence.{section_name}.required_test_refs[{index}].name must be non-empty"
            )
            continue
        key = (source, name)
        if key in seen:
            err(f"completion_debt_evidence.{section_name} duplicates test ref {source}::{name}")
        seen.add(key)
        text = texts.get(source, "")
        if not text:
            err(f"completion_debt_evidence.{section_name} references unknown source {source}")
        elif f"fn {name}" not in text:
            err(f"completion_debt_evidence.{section_name} references missing test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


def extract_enum_variants(source: str) -> list[str]:
    marker = "pub enum HealingAction"
    start = source.find(marker)
    if start == -1:
        err("heal.rs does not declare pub enum HealingAction")
        return []
    brace_start = source.find("{", start)
    if brace_start == -1:
        err("HealingAction enum is missing opening brace")
        return []
    depth = 0
    brace_end = None
    for index in range(brace_start, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                brace_end = index
                break
    if brace_end is None:
        err("HealingAction enum is missing closing brace")
        return []
    body = source[brace_start + 1 : brace_end]
    variants: list[str] = []
    seen: set[str] = set()
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("///"):
            continue
        name = stripped.split("{", 1)[0].split("(", 1)[0].split(",", 1)[0].strip()
        if re.match(r"^[A-Z][A-Za-z0-9_]*$", name) and name not in seen:
            variants.append(name)
            seen.add(name)
    if not variants:
        err("HealingAction enum variants could not be parsed")
    return variants


manifest = load_json(CONTRACT)
if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if manifest.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")

for source in as_string_list(manifest.get("source_modules"), "source_modules"):
    if not (ROOT / source).is_file():
        err(f"source module missing: {source}")

completion = manifest.get("completion_debt_evidence")
if not isinstance(completion, dict):
    completion = {}
    err("completion_debt_evidence must be an object")

if completion.get("bead") != COMPLETION_BEAD:
    err(f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
if completion.get("original_bead") != ORIGINAL_BEAD:
    err(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
threshold = completion.get("next_audit_score_threshold")
if not isinstance(threshold, int) or threshold < 800 or threshold > 1000:
    err("completion_debt_evidence.next_audit_score_threshold must be 800..1000")

implementation_refs = completion.get("implementation_refs")
if not isinstance(implementation_refs, list) or len(implementation_refs) < 10:
    err("completion_debt_evidence.implementation_refs must contain at least 10 file:line refs")
else:
    for index, ref in enumerate(implementation_refs):
        validate_file_line_ref(ref, f"completion_debt_evidence.implementation_refs[{index}]")

texts = source_texts(completion.get("test_sources"))
heal_text = texts.get("heal_unit", "")
enum_variants = set(extract_enum_variants(heal_text))

missing_items_bound: list[str] = []
test_refs_by_section: dict[str, list[dict[str, str]]] = {}
for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
    section = completion.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    missing_items_bound.append(str(section.get("missing_item_id", "")))
    section_threshold = section.get("next_audit_score_threshold", threshold)
    if not isinstance(section_threshold, int) or section_threshold < 800 or section_threshold > 1000:
        err(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be 800..1000")
    test_refs_by_section[section_name] = validate_test_refs(section, section_name, texts)
    if section_name != "telemetry_primary":
        as_string_list(section.get("required_commands"), f"completion_debt_evidence.{section_name}.required_commands")

unit_sources = {ref["source"] for ref in test_refs_by_section.get("unit_primary", [])}
if "heal_unit" not in unit_sources:
    err("unit_primary must include heal_unit source")
e2e_sources = {ref["source"] for ref in test_refs_by_section.get("e2e_primary", [])}
if not {"hardened_matrix", "strict_hardened_e2e", "cve_hardened_assertions", "runtime_evidence_verifier"}.issubset(e2e_sources):
    err("e2e_primary must include hardened matrix, strict/hardened e2e, CVE assertions, and runtime verifier sources")

dispatch = completion.get("dispatch_contract")
required_actions: set[str] = set()
required_variants: set[str] = set()
required_counters: set[str] = set()
required_healing_log_fields: set[str] = set()
required_levels: set[str] = set()
if isinstance(dispatch, dict):
    required_actions = set(as_string_list(dispatch.get("required_healing_actions"), "dispatch_contract.required_healing_actions"))
    required_variants = set(as_string_list(dispatch.get("required_enum_variants"), "dispatch_contract.required_enum_variants"))
    required_counters = set(as_string_list(dispatch.get("required_counter_fields"), "dispatch_contract.required_counter_fields"))
    required_healing_log_fields = set(
        as_string_list(dispatch.get("required_healing_log_fields"), "dispatch_contract.required_healing_log_fields")
    )
    required_levels = set(as_string_list(dispatch.get("required_levels"), "dispatch_contract.required_levels"))
else:
    err("completion_debt_evidence.dispatch_contract must be an object")

missing_actions = sorted(EXPECTED_HEALING_ACTIONS - required_actions)
if missing_actions:
    err(f"dispatch_contract.required_healing_actions missing {missing_actions}")
missing_variants = sorted(EXPECTED_ENUM_VARIANTS - required_variants)
if missing_variants:
    err(f"dispatch_contract.required_enum_variants missing {missing_variants}")
missing_enum = sorted(EXPECTED_ENUM_VARIANTS - enum_variants)
if missing_enum:
    err(f"heal.rs HealingAction enum missing {missing_enum}")
extra_required = sorted(required_variants - enum_variants)
if extra_required:
    err(f"dispatch_contract.required_enum_variants includes variants absent from heal.rs {extra_required}")
missing_counters = sorted(EXPECTED_COUNTER_FIELDS - required_counters)
if missing_counters:
    err(f"dispatch_contract.required_counter_fields missing {missing_counters}")
missing_healing_fields = sorted(EXPECTED_HEALING_LOG_FIELDS - required_healing_log_fields)
if missing_healing_fields:
    err(f"dispatch_contract.required_healing_log_fields missing {missing_healing_fields}")
missing_levels = sorted(EXPECTED_LEVELS - required_levels)
if missing_levels:
    err(f"dispatch_contract.required_levels missing {missing_levels}")

for action in EXPECTED_HEALING_ACTIONS:
    if action not in heal_text:
        err(f"heal.rs no longer contains healing action token {action}")
for counter in EXPECTED_COUNTER_FIELDS:
    if counter not in heal_text:
        err(f"heal.rs no longer contains counter token {counter}")
for field in EXPECTED_HEALING_LOG_FIELDS:
    if field not in heal_text:
        err(f"heal.rs no longer contains healing log field token {field}")
if "global_evidence_ledger().record_healing" not in heal_text:
    err("heal.rs must continue recording healing rows into the unified evidence ledger")

telemetry = completion.get("telemetry_primary")
required_events: set[str] = set()
required_fields: set[str] = set()
if isinstance(telemetry, dict):
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
    required_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
    if telemetry.get("default_report_path") != "target/conformance/self_healing_dispatch_contract.report.json":
        err("telemetry_primary.default_report_path drifted")
    if telemetry.get("default_log_path") != "target/conformance/self_healing_dispatch_contract.log.jsonl":
        err("telemetry_primary.default_log_path drifted")
else:
    err("completion_debt_evidence.telemetry_primary must be an object")

missing_events = sorted(EXPECTED_TELEMETRY_EVENTS - required_events)
if missing_events:
    err(f"telemetry_primary.required_events missing {missing_events}")
missing_fields = sorted(EXPECTED_TELEMETRY_FIELDS - required_fields)
if missing_fields:
    err(f"telemetry_primary.required_fields missing {missing_fields}")

artifact_refs = [
    rel(CONTRACT),
    rel(REPORT),
    rel(LOG),
    "crates/frankenlibc-membrane/src/heal.rs",
    "crates/frankenlibc-harness/tests/hardened_repair_deny_matrix_test.rs",
    "crates/frankenlibc-harness/tests/strict_hardened_evidence_e2e_test.rs",
    "crates/frankenlibc-harness/tests/cve_hardened_assertions_test.rs",
    "crates/frankenlibc-harness/tests/runtime_evidence_verifier_test.rs",
]
status = "fail" if errors else "pass"
now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
report = {
    "schema_version": "self_healing_dispatch_contract.report.v1",
    "timestamp": now,
    "status": status,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": git_head(),
    "missing_items": missing_items_bound,
    "required_healing_actions": sorted(required_actions),
    "required_enum_variants": sorted(required_variants),
    "live_enum_variants": sorted(enum_variants),
    "required_counter_fields": sorted(required_counters),
    "required_healing_log_fields": sorted(required_healing_log_fields),
    "required_events": sorted(required_events),
    "required_fields": sorted(required_fields),
    "test_refs": test_refs_by_section,
    "artifact_refs": artifact_refs,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log_row = {
    "timestamp": now,
    "trace_id": f"tsm::self_healing_dispatch_contract::{COMPLETION_BEAD}",
    "event": "self_healing_dispatch_contract_failed" if errors else "self_healing_dispatch_contract_validated",
    "level": "error" if errors else "info",
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "source_commit": report["source_commit"],
    "missing_items_bound": missing_items_bound,
    "required_healing_actions": sorted(required_actions),
    "required_enum_variants": sorted(required_variants),
    "required_counter_fields": sorted(required_counters),
    "required_healing_log_fields": sorted(required_healing_log_fields),
    "required_events": sorted(required_events),
    "required_fields": sorted(required_fields),
    "test_refs": test_refs_by_section,
    "artifact_refs": artifact_refs,
    "failure_signature": "; ".join(errors) if errors else "none",
}
LOG.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    for message in errors:
        print(f"error: {message}", file=sys.stderr)
    sys.exit(1)

print(
    f"self-healing dispatch contract validated: missing_items={len(missing_items_bound)} "
    f"actions={len(required_actions)} refs={sum(len(v) for v in test_refs_by_section.values())}"
)
PY
