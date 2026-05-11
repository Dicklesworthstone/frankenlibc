#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FUZZ_GAP_COMPLETION_CONTRACT:-$ROOT/tests/conformance/fuzz_gap_abi_modules_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_FUZZ_GAP_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_FUZZ_GAP_COMPLETION_REPORT:-$OUT_DIR/fuzz_gap_abi_modules_completion_contract.report.json}"
LOG="${FRANKENLIBC_FUZZ_GAP_COMPLETION_LOG:-$OUT_DIR/fuzz_gap_abi_modules_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "fuzz_gap_abi_modules_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "fuzz_gap_abi_modules_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-dvr22"
COMPLETION_BEAD = "bd-dvr22.1"

SUPPORTED_EVENTS = {
    "fuzz_gap_abi_modules_target_inventory",
    "fuzz_gap_abi_modules_source_anchors",
    "fuzz_gap_abi_modules_corpus_dictionary",
    "fuzz_gap_abi_modules_telemetry_summary",
    "fuzz_gap_abi_modules_completion_contract_pass",
    "fuzz_gap_abi_modules_completion_contract_fail",
}
REQUIRED_SOURCE_ARTIFACTS = {
    "fuzz_cargo_manifest",
    "fuzz_architecture_report",
    "fuzz_architecture_checker",
    "fuzz_architecture_test",
    "completion_checker",
    "completion_harness_test",
}
REQUIRED_MODULES = {
    "signal",
    "socket",
    "fortify",
    "setjmp",
    "mmap",
    "dlfcn",
    "pthread",
    "c11threads",
}
GENERIC_FUZZ_ANCHORS = ["#![no_main]", "fuzz_target!", "Arbitrary"]
REQUIRED_BINDINGS = {"tests.fuzz.primary", "telemetry.primary"}

ROW_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "bead_id",
    "original_bead",
    "completion_debt_bead",
    "status",
    "outcome",
    "source_commit",
    "schema_version",
    "module_count",
    "target_count",
    "artifact_refs",
    "target_refs",
    "telemetry_refs",
    "failure_signature",
    "details",
}
REPORT_FIELDS = {
    "schema_version",
    "manifest_id",
    "original_bead",
    "completion_debt_bead",
    "status",
    "source_commit",
    "summary",
    "modules",
    "target_refs",
    "source_artifacts",
    "events",
    "errors",
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


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


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


def read_text(path_text: str, label: str) -> str:
    path = ROOT / path_text
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} is unreadable: {path_text}: {exc}")
        return ""


def strings(value: Any, context: str, allow_empty: bool = False) -> list[str]:
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


def parse_fuzz_bins(cargo_text: str) -> dict[str, str]:
    bins: dict[str, str] = {}
    current_name: str | None = None
    for raw_line in cargo_text.splitlines():
        line = raw_line.strip()
        name_match = re.fullmatch(r'name\s*=\s*"(fuzz_[^"]+)"', line)
        if name_match:
            current_name = name_match.group(1)
            continue
        path_match = re.fullmatch(r'path\s*=\s*"([^"]+)"', line)
        if path_match and current_name:
            bins[current_name] = path_match.group(1)
            current_name = None
    return bins


def function_exists(source: str, name: str) -> bool:
    return f"fn {name}" in source


manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}
missing_artifacts = sorted(REQUIRED_SOURCE_ARTIFACTS - set(source_artifacts))
if missing_artifacts:
    err(f"source_artifacts missing {','.join(missing_artifacts)}")
for source_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{source_id} must be a non-empty string")
        continue
    require((ROOT / path_text).exists(), f"source artifact {source_id} missing: {path_text}")

modules_value = manifest.get("required_module_fuzz_coverage", [])
if not isinstance(modules_value, list) or not modules_value:
    err("required_module_fuzz_coverage must be a non-empty array")
    modules_value = []

module_ids: set[str] = set()
target_specs: dict[str, dict[str, Any]] = {}
module_to_targets: dict[str, list[str]] = {}
for module_index, module in enumerate(modules_value):
    if not isinstance(module, dict):
        err(f"required_module_fuzz_coverage[{module_index}] must be an object")
        continue
    module_id = module.get("module_id")
    if not isinstance(module_id, str) or not module_id:
        err(f"required_module_fuzz_coverage[{module_index}].module_id must be a non-empty string")
        continue
    module_ids.add(module_id)
    module_symbols = strings(module.get("required_symbols"), f"{module_id}.required_symbols")
    targets = module.get("targets", [])
    if not isinstance(targets, list) or not targets:
        err(f"{module_id}.targets must be a non-empty array")
        continue
    combined_source = ""
    module_to_targets[module_id] = []
    for target_index, target in enumerate(targets):
        if not isinstance(target, dict):
            err(f"{module_id}.targets[{target_index}] must be an object")
            continue
        name = target.get("name")
        path_text = target.get("path")
        if not isinstance(name, str) or not name.startswith("fuzz_"):
            err(f"{module_id}.targets[{target_index}].name must be a fuzz target name")
            continue
        if name in target_specs:
            err(f"duplicate target binding {name}")
            continue
        if not isinstance(path_text, str) or not path_text:
            err(f"{name}.path must be a non-empty string")
            continue
        target_path = ROOT / path_text
        require(target_path.is_file(), f"{name} source missing: {path_text}")
        source = read_text(path_text, name)
        combined_source += "\n" + source
        for needle in GENERIC_FUZZ_ANCHORS:
            require(needle in source, f"{name} missing generic fuzz anchor {needle!r}")
        for needle in strings(target.get("required_text"), f"{name}.required_text"):
            require(needle in source, f"{name} missing required source anchor {needle!r}")
        target_specs[name] = {
            "module_id": module_id,
            "path": path_text,
            "required_text": target.get("required_text", []),
        }
        module_to_targets[module_id].append(name)
    for symbol in module_symbols:
        require(symbol in combined_source, f"{module_id} required symbol {symbol!r} not covered by target source")

missing_modules = sorted(REQUIRED_MODULES - module_ids)
if missing_modules:
    err(f"required_module_fuzz_coverage missing modules {','.join(missing_modules)}")

required_targets = set(target_specs)
cargo_path = source_artifacts.get("fuzz_cargo_manifest")
cargo_text = read_text(str(cargo_path), "fuzz_cargo_manifest") if isinstance(cargo_path, str) else ""
fuzz_bins = parse_fuzz_bins(cargo_text)
for target_name, spec in sorted(target_specs.items()):
    cargo_rel = fuzz_bins.get(target_name)
    require(cargo_rel is not None, f"Cargo.toml missing fuzz bin {target_name}")
    expected_rel = pathlib.Path(spec["path"]).relative_to("crates/frankenlibc-fuzz").as_posix()
    if cargo_rel is not None:
        require(cargo_rel == expected_rel, f"Cargo.toml path mismatch for {target_name}: {cargo_rel} != {expected_rel}")

arch_path = source_artifacts.get("fuzz_architecture_report")
arch = load_json(ROOT / str(arch_path), "fuzz_architecture_report") if isinstance(arch_path, str) else {}
target_analyses = arch.get("target_analyses", [])
if not isinstance(target_analyses, list):
    err("fuzz_architecture_report.target_analyses must be an array")
    target_analyses = []
analysis_by_target = {
    item.get("target"): item
    for item in target_analyses
    if isinstance(item, dict) and isinstance(item.get("target"), str)
}
for target_name, spec in sorted(target_specs.items()):
    analysis = analysis_by_target.get(target_name)
    if not isinstance(analysis, dict):
        err(f"fuzz architecture report missing target {target_name}")
        continue
    require(analysis.get("source") == spec["path"], f"{target_name} architecture source mismatch")
    require(analysis.get("implementation_status") == "functional", f"{target_name} implementation_status must be functional")
    require(int(analysis.get("checks_passed", -1)) == int(analysis.get("checks_total", -2)), f"{target_name} convention checks must all pass")

corpus = arch.get("corpus_strategy", {})
if not isinstance(corpus, dict):
    err("fuzz_architecture_report.corpus_strategy must be an object")
    corpus = {}
corpus_rows = corpus.get("manifests", [])
if not isinstance(corpus_rows, list):
    err("corpus_strategy.manifests must be an array")
    corpus_rows = []
corpus_by_target = {
    row.get("target"): row
    for row in corpus_rows
    if isinstance(row, dict) and isinstance(row.get("target"), str)
}
corpus_count = 0
for target_name in sorted(required_targets):
    row = corpus_by_target.get(target_name)
    if not isinstance(row, dict):
        err(f"corpus_strategy missing target {target_name}")
        continue
    count = int(row.get("count", -1))
    corpus_count += max(count, 0)
    require(count > 0, f"{target_name} corpus count must be positive")
    require(row.get("reproducible") is True, f"{target_name} corpus must be reproducible")

dictionaries = arch.get("dictionary_strategy", {})
if not isinstance(dictionaries, dict):
    err("fuzz_architecture_report.dictionary_strategy must be an object")
    dictionaries = {}
dictionary_rows = dictionaries.get("manifests", [])
if not isinstance(dictionary_rows, list):
    err("dictionary_strategy.manifests must be an array")
    dictionary_rows = []
dictionary_by_target = {
    row.get("target"): row
    for row in dictionary_rows
    if isinstance(row, dict) and isinstance(row.get("target"), str)
}
dictionary_count = 0
for target_name in sorted(required_targets):
    row = dictionary_by_target.get(target_name)
    if not isinstance(row, dict):
        err(f"dictionary_strategy missing target {target_name}")
        continue
    count = int(row.get("count", -1))
    dictionary_count += max(count, 0)
    require(count > 0, f"{target_name} dictionary count must be positive")

test_refs: list[str] = []
completion_tests = manifest.get("completion_tests", {})
if not isinstance(completion_tests, dict) or not completion_tests:
    err("completion_tests must be a non-empty object")
    completion_tests = {}
for test_id, spec in completion_tests.items():
    if not isinstance(spec, dict):
        err(f"completion_tests.{test_id} must be an object")
        continue
    path_text = spec.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"completion_tests.{test_id}.path must be a non-empty string")
        continue
    source = read_text(path_text, test_id)
    for test_ref in strings(spec.get("required_test_refs"), f"completion_tests.{test_id}.required_test_refs"):
        require(function_exists(source, test_ref), f"completion test {path_text} missing {test_ref}")
        test_refs.append(f"{test_id}::{test_ref}")

bindings = manifest.get("missing_item_bindings", [])
if not isinstance(bindings, list) or not bindings:
    err("missing_item_bindings must be a non-empty array")
    bindings = []
binding_by_id = {item.get("id"): item for item in bindings if isinstance(item, dict)}
for binding_id in sorted(REQUIRED_BINDINGS):
    binding = binding_by_id.get(binding_id)
    if not isinstance(binding, dict):
        err(f"missing_item_bindings missing {binding_id}")
        continue
    for artifact in strings(binding.get("required_artifacts"), f"{binding_id}.required_artifacts"):
        require((ROOT / artifact).exists(), f"{binding_id} artifact missing: {artifact}")
    if binding_id == "tests.fuzz.primary":
        bound_targets = set(strings(binding.get("required_targets"), f"{binding_id}.required_targets"))
        missing_bound_targets = sorted(required_targets - bound_targets)
        extra_bound_targets = sorted(bound_targets - required_targets)
        if missing_bound_targets:
            err(f"{binding_id} missing targets {','.join(missing_bound_targets)}")
        if extra_bound_targets:
            err(f"{binding_id} references unknown targets {','.join(extra_bound_targets)}")
    if binding_id == "telemetry.primary":
        bound_events = set(strings(binding.get("required_events"), f"{binding_id}.required_events"))
        missing_bound_events = sorted(SUPPORTED_EVENTS - bound_events)
        extra_bound_events = sorted(bound_events - SUPPORTED_EVENTS)
        if missing_bound_events:
            err(f"{binding_id} missing events {','.join(missing_bound_events)}")
        if extra_bound_events:
            err(f"{binding_id} references unsupported events {','.join(extra_bound_events)}")

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}
required_log_fields = strings(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields")
required_report_fields = strings(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields")
declared_events = set(strings(telemetry.get("required_events"), "telemetry_contract.required_events"))
missing_events = sorted(SUPPORTED_EVENTS - declared_events)
extra_events = sorted(declared_events - SUPPORTED_EVENTS)
if missing_events:
    err(f"telemetry_contract.required_events missing {','.join(missing_events)}")
if extra_events:
    err(f"telemetry_contract.required_events declares unimplemented event {','.join(extra_events)}")
for field in required_log_fields:
    require(field in ROW_FIELDS, f"checker telemetry row missing required log field {field}")
for field in required_report_fields:
    require(field in REPORT_FIELDS, f"checker report missing required report field {field}")

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
source_commit = git_head()
status = "pass" if not errors else "fail"
outcome = status
failure_signature = "none" if not errors else ";".join(errors[:8])
artifact_refs = [rel(CONTRACT), rel(REPORT), rel(LOG)]
target_refs = [f"{name}:{target_specs[name]['path']}" for name in sorted(target_specs)]
telemetry_refs = sorted(declared_events)

event_specs = [
    {
        "event": "fuzz_gap_abi_modules_target_inventory",
        "details": {
            "module_to_targets": {module: sorted(targets) for module, targets in sorted(module_to_targets.items())},
            "cargo_bins": sorted(name for name in required_targets if name in fuzz_bins),
        },
    },
    {
        "event": "fuzz_gap_abi_modules_source_anchors",
        "details": {
            "generic_anchors": GENERIC_FUZZ_ANCHORS,
            "source_targets": sorted(target_specs),
            "test_refs": sorted(set(test_refs)),
        },
    },
    {
        "event": "fuzz_gap_abi_modules_corpus_dictionary",
        "details": {
            "corpus_targets": sorted(name for name in required_targets if name in corpus_by_target),
            "dictionary_targets": sorted(name for name in required_targets if name in dictionary_by_target),
            "corpus_entries": corpus_count,
            "dictionary_entries": dictionary_count,
        },
    },
    {
        "event": "fuzz_gap_abi_modules_telemetry_summary",
        "details": {
            "declared_events": sorted(declared_events),
            "required_report_fields": required_report_fields,
            "required_log_fields": required_log_fields,
        },
    },
    {
        "event": "fuzz_gap_abi_modules_completion_contract_pass"
        if not errors
        else "fuzz_gap_abi_modules_completion_contract_fail",
        "details": {
            "bindings": sorted(binding_by_id),
            "errors": errors,
        },
    },
]

rows: list[dict[str, Any]] = []
for seq, event_spec in enumerate(event_specs, start=1):
    rows.append(
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_BEAD}::fuzz-gap-abi-modules::{seq:03d}",
            "event": event_spec["event"],
            "bead_id": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "outcome": outcome,
            "source_commit": source_commit,
            "schema_version": EXPECTED_SCHEMA,
            "module_count": len(module_ids),
            "target_count": len(required_targets),
            "artifact_refs": artifact_refs,
            "target_refs": target_refs,
            "telemetry_refs": telemetry_refs,
            "failure_signature": failure_signature,
            "details": event_spec["details"],
        }
    )

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": {
        "module_count": len(module_ids),
        "target_count": len(required_targets),
        "cargo_bound_targets": len(required_targets & set(fuzz_bins)),
        "architecture_bound_targets": len(required_targets & set(analysis_by_target)),
        "corpus_bound_targets": len(required_targets & set(corpus_by_target)),
        "dictionary_bound_targets": len(required_targets & set(dictionary_by_target)),
        "corpus_entries": corpus_count,
        "dictionary_entries": dictionary_count,
        "test_refs": len(set(test_refs)),
        "telemetry_events": len(declared_events),
    },
    "modules": [
        {
            "module_id": module_id,
            "targets": sorted(targets),
        }
        for module_id, targets in sorted(module_to_targets.items())
    ],
    "target_refs": target_refs,
    "source_artifacts": source_artifacts,
    "events": [row["event"] for row in rows],
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"MODULES={len(module_ids)}")
print(f"TARGETS={len(required_targets)}")
print(f"REPORT={rel(REPORT)}")
print(f"LOG={rel(LOG)}")
for error in errors:
    print(f"ERROR: {error}")

if errors:
    raise SystemExit(1)
PY
