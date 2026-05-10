#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FUZZ_HARNESS_COMPLETION_CONTRACT:-$ROOT/tests/conformance/fuzz_harness_architecture_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_FUZZ_HARNESS_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_FUZZ_HARNESS_COMPLETION_REPORT:-$OUT_DIR/fuzz_harness_architecture_completion_contract.report.json}"
LOG="${FRANKENLIBC_FUZZ_HARNESS_COMPLETION_LOG:-$OUT_DIR/fuzz_harness_architecture_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "fuzz_harness_architecture_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "fuzz_harness_architecture_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-1oz.5"
COMPLETION_BEAD = "bd-1oz.5.1"
SOURCE_SCHEMA = "v1"
PASS_EVENT = "fuzz_harness_architecture_completion_contract_pass"
FAIL_EVENT = "fuzz_harness_architecture_completion_contract_fail"
REQUIRED_SOURCE_ARTIFACTS = {
    "fuzz_harness_architecture_report",
    "fuzz_harness_architecture_generator",
    "fuzz_harness_architecture_gate",
    "fuzz_harness_architecture_harness_test",
    "fuzz_cargo_manifest",
    "fuzz_ci_gate",
    "completion_checker",
    "completion_harness_test",
}
REQUIRED_TELEMETRY_EVENTS = {
    "fuzz_harness_architecture_completion_summary",
    "fuzz_harness_architecture_source_bindings",
    "fuzz_harness_architecture_test_bindings",
    PASS_EVENT,
    FAIL_EVENT,
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
    try:
        return (ROOT / path_text).read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} is unreadable: {path_text}: {exc}")
        return ""


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


def require_set(value: Any, required: set[str], context: str) -> set[str]:
    actual = set(as_string_list(value, context))
    missing = sorted(required - actual)
    if missing:
        err(f"{context} missing {','.join(missing)}")
    return actual


def function_exists(source: str, name: str) -> bool:
    return f"fn {name}" in source


def positive_int(value: Any, context: str) -> int:
    try:
        parsed = int(value)
    except Exception:
        err(f"{context} must be an integer")
        return -1
    if parsed <= 0:
        err(f"{context} must be positive")
    return parsed


def parse_fuzz_bins(cargo_toml: str) -> dict[str, str]:
    bins: dict[str, str] = {}
    current_name: str | None = None
    for raw_line in cargo_toml.splitlines():
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


manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}
missing_sources = sorted(REQUIRED_SOURCE_ARTIFACTS - set(source_artifacts))
if missing_sources:
    err(f"source_artifacts missing {','.join(missing_sources)}")
for source_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{source_id} must be a non-empty string")
        continue
    require((ROOT / path_text).exists(), f"source artifact {source_id} missing: {path_text}")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}

architecture_contract = evidence.get("required_architecture_contract", {})
if not isinstance(architecture_contract, dict):
    err("completion_debt_evidence.required_architecture_contract must be an object")
    architecture_contract = {}
require(architecture_contract.get("schema_version") == SOURCE_SCHEMA, f"required architecture schema must be {SOURCE_SCHEMA}")
require(architecture_contract.get("generated_by_bead") == ORIGINAL_BEAD, f"required architecture bead must be {ORIGINAL_BEAD}")
required_summary_domains = require_set(
    architecture_contract.get("required_summary_domains"),
    {
        "abi-entrypoint",
        "allocator",
        "loader",
        "locale",
        "membrane",
        "runtime-kernel",
    },
    "required_architecture_contract.required_summary_domains",
)
required_checks = require_set(
    architecture_contract.get("required_convention_checks"),
    {"no_main_attr", "fuzz_target_macro", "input_size_guard", "no_unwrap", "no_panic"},
    "required_architecture_contract.required_convention_checks",
)
required_attributes = set(as_string_list(architecture_contract.get("required_attributes"), "required_architecture_contract.required_attributes"))
required_macros = set(as_string_list(architecture_contract.get("required_macros"), "required_architecture_contract.required_macros"))
required_layout_keys = set(as_string_list(architecture_contract.get("required_artifact_layout_keys"), "required_architecture_contract.required_artifact_layout_keys"))
required_targets = set(as_string_list(architecture_contract.get("required_targets"), "required_architecture_contract.required_targets"))
required_ci_steps = set(as_string_list(architecture_contract.get("required_ci_steps"), "required_architecture_contract.required_ci_steps"))

source_report_path = source_artifacts.get("fuzz_harness_architecture_report")
source_report = load_json(ROOT / str(source_report_path), "fuzz_harness_architecture_report") if isinstance(source_report_path, str) else {}
require(source_report.get("schema_version") == SOURCE_SCHEMA, "fuzz architecture report schema mismatch")
require(source_report.get("bead") == ORIGINAL_BEAD, "fuzz architecture report bead mismatch")
summary = source_report.get("summary", {})
if not isinstance(summary, dict):
    err("fuzz architecture report summary must be an object")
    summary = {}
total_targets = positive_int(summary.get("total_targets"), "summary.total_targets")
functional_targets = positive_int(summary.get("functional_targets"), "summary.functional_targets")
checks_passed = positive_int(summary.get("checks_passed"), "summary.checks_passed")
checks_total = positive_int(summary.get("checks_total"), "summary.checks_total")
total_seed_corpus = positive_int(summary.get("total_seed_corpus"), "summary.total_seed_corpus")
total_dict_entries = positive_int(summary.get("total_dict_entries"), "summary.total_dict_entries")
unique_cwes = positive_int(summary.get("unique_cwes"), "summary.unique_cwes")
require(total_targets >= int(architecture_contract.get("minimum_total_targets", 0)), "summary.total_targets below required minimum")
require(functional_targets == int(architecture_contract.get("required_functional_targets", -1)), "summary.functional_targets mismatch")
require(int(summary.get("stub_targets", -1)) == int(architecture_contract.get("required_stub_targets", -1)), "summary.stub_targets mismatch")
require(float(summary.get("quality_score_pct", -1.0)) >= float(architecture_contract.get("required_quality_score_pct", 100.0)), "summary.quality_score_pct below requirement")
require(total_seed_corpus >= int(architecture_contract.get("minimum_seed_corpus", 1)), "summary.total_seed_corpus below minimum")
require(total_dict_entries >= int(architecture_contract.get("minimum_dictionary_entries", 1)), "summary.total_dict_entries below minimum")
require(unique_cwes >= int(architecture_contract.get("minimum_unique_cwes", 5)), "summary.unique_cwes below minimum")
source_domains = set(as_string_list(summary.get("domains_covered"), "summary.domains_covered"))
missing_summary_domains = sorted(required_summary_domains - source_domains)
if missing_summary_domains:
    err(f"summary.domains_covered missing {','.join(missing_summary_domains)}")

conventions = source_report.get("harness_conventions", {})
if not isinstance(conventions, dict):
    err("harness_conventions must be an object")
    conventions = {}
require(required_attributes <= set(as_string_list(conventions.get("required_attributes"), "harness_conventions.required_attributes")), "harness_conventions.required_attributes missing required values")
require(required_macros <= set(as_string_list(conventions.get("required_macros"), "harness_conventions.required_macros")), "harness_conventions.required_macros missing required values")
layout = conventions.get("artifact_layout", {})
if not isinstance(layout, dict):
    err("harness_conventions.artifact_layout must be an object")
    layout = {}
missing_layout = sorted(required_layout_keys - set(layout))
if missing_layout:
    err(f"harness_conventions.artifact_layout missing {','.join(missing_layout)}")

target_analyses = source_report.get("target_analyses", [])
if not isinstance(target_analyses, list) or not target_analyses:
    err("target_analyses must be a non-empty array")
    target_analyses = []
require(len(target_analyses) == total_targets, "target_analyses length must match summary.total_targets")
report_targets: set[str] = set()
for target in target_analyses:
    if not isinstance(target, dict):
        err("target_analyses entries must be objects")
        continue
    name = target.get("target")
    if not isinstance(name, str) or not name:
        err("target_analyses entry missing target")
        continue
    report_targets.add(name)
    require(target.get("implementation_status") == "functional", f"{name} implementation_status must be functional")
    require(int(target.get("checks_passed", -1)) == int(target.get("checks_total", -2)), f"{name} must pass all convention checks")
    source = target.get("source")
    if isinstance(source, str):
        require((ROOT / source).is_file(), f"{name} source missing: {source}")
    else:
        err(f"{name} source must be a string")
    checks = target.get("checks", [])
    if not isinstance(checks, list):
        err(f"{name}.checks must be an array")
        checks = []
    checks_by_name = {str(check.get("check")): check for check in checks if isinstance(check, dict)}
    missing_checks = sorted(required_checks - set(checks_by_name))
    if missing_checks:
        err(f"{name} missing checks {','.join(missing_checks)}")
    for check_name in sorted(required_checks):
        check = checks_by_name.get(check_name)
        if isinstance(check, dict):
            require(check.get("passed") is True, f"{name} check {check_name} did not pass")

missing_required_targets = sorted(required_targets - report_targets)
if missing_required_targets:
    err(f"fuzz architecture report missing required targets {','.join(missing_required_targets)}")

corpus = source_report.get("corpus_strategy", {})
if not isinstance(corpus, dict):
    err("corpus_strategy must be an object")
    corpus = {}
corpus_manifests = corpus.get("manifests", [])
if not isinstance(corpus_manifests, list) or not corpus_manifests:
    err("corpus_strategy.manifests must be a non-empty array")
    corpus_manifests = []
require(len(corpus_manifests) == total_targets, "corpus_strategy.manifests length must match summary.total_targets")
corpus_targets: set[str] = set()
seed_count = 0
for manifest_row in corpus_manifests:
    if not isinstance(manifest_row, dict):
        err("corpus manifest entries must be objects")
        continue
    target = str(manifest_row.get("target"))
    corpus_targets.add(target)
    count = int(manifest_row.get("count", -1))
    seed_count += max(count, 0)
    require(count > 0, f"{target} corpus count must be positive")
    require(manifest_row.get("reproducible") is True, f"{target} corpus must be reproducible")
    seeds = manifest_row.get("seeds", [])
    if not isinstance(seeds, list) or not seeds:
        err(f"{target} corpus seeds must be a non-empty array")
        seeds = []
    require(len(seeds) == count, f"{target} corpus seed count must match count")
    for seed in seeds:
        if not isinstance(seed, dict):
            err(f"{target} seed entries must be objects")
            continue
        require(isinstance(seed.get("seed_id"), str) and seed.get("seed_id", "").startswith("seed-"), f"{target} seed missing seed_id")
        require(isinstance(seed.get("sha256_prefix"), str) and len(seed.get("sha256_prefix", "")) == 12, f"{target} seed missing sha256_prefix")
require(seed_count == total_seed_corpus, "corpus seed count must match summary.total_seed_corpus")
missing_corpus_targets = sorted(report_targets - corpus_targets)
if missing_corpus_targets:
    err(f"corpus_strategy missing targets {','.join(missing_corpus_targets)}")

dictionaries = source_report.get("dictionary_strategy", {})
if not isinstance(dictionaries, dict):
    err("dictionary_strategy must be an object")
    dictionaries = {}
dict_manifests = dictionaries.get("manifests", [])
if not isinstance(dict_manifests, list) or not dict_manifests:
    err("dictionary_strategy.manifests must be a non-empty array")
    dict_manifests = []
require(len(dict_manifests) == total_targets, "dictionary_strategy.manifests length must match summary.total_targets")
dict_targets: set[str] = set()
dict_count = 0
for manifest_row in dict_manifests:
    if not isinstance(manifest_row, dict):
        err("dictionary manifest entries must be objects")
        continue
    target = str(manifest_row.get("target"))
    dict_targets.add(target)
    count = int(manifest_row.get("count", -1))
    dict_count += max(count, 0)
    require(count > 0, f"{target} dictionary count must be positive")
    entries = manifest_row.get("entries", [])
    require(isinstance(entries, list) and len(entries) == count, f"{target} dictionary entries must match count")
require(dict_count == total_dict_entries, "dictionary entry count must match summary.total_dict_entries")
missing_dict_targets = sorted(report_targets - dict_targets)
if missing_dict_targets:
    err(f"dictionary_strategy missing targets {','.join(missing_dict_targets)}")

cargo_manifest_path = source_artifacts.get("fuzz_cargo_manifest")
cargo_text = read_text(str(cargo_manifest_path), "fuzz_cargo_manifest") if isinstance(cargo_manifest_path, str) else ""
fuzz_bins = parse_fuzz_bins(cargo_text)
missing_cargo_targets = sorted(required_targets - set(fuzz_bins))
if missing_cargo_targets:
    err(f"fuzz Cargo.toml missing required bins {','.join(missing_cargo_targets)}")
for target, path_text in sorted(fuzz_bins.items()):
    require((ROOT / "crates/frankenlibc-fuzz" / path_text).is_file(), f"fuzz bin source missing for {target}: {path_text}")

ci_path = source_artifacts.get("fuzz_ci_gate")
ci_text = read_text(str(ci_path), "fuzz_ci_gate") if isinstance(ci_path, str) else ""
for step in sorted(required_ci_steps):
    require(step in ci_text, f"fuzz CI gate missing step {step!r}")
for target in sorted(required_targets):
    require(target in ci_text or target in fuzz_bins, f"required target {target} missing from CI/Cargo bindings")

for ref in evidence.get("implementation_refs", []):
    if not isinstance(ref, dict):
        err("implementation_refs entries must be objects")
        continue
    path_text = ref.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"implementation ref {ref.get('id')} missing path")
        continue
    text = read_text(path_text, str(ref.get("id", "implementation_ref")))
    for needle in as_string_list(ref.get("required_text"), f"implementation_refs.{ref.get('id')}.required_text"):
        require(needle in text, f"implementation ref {ref.get('id')} missing {needle!r} in {path_text}")

test_refs: list[str] = []
test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict) or not test_sources:
    err("completion_debt_evidence.test_sources must be a non-empty object")
    test_sources = {}
for source_id, spec in test_sources.items():
    if not isinstance(spec, dict):
        err(f"test source {source_id} must be an object")
        continue
    path_text = spec.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"test source {source_id} missing path")
        continue
    text = read_text(path_text, source_id)
    for test_ref in as_string_list(spec.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
        require(function_exists(text, test_ref), f"test source {source_id} missing required test ref {test_ref}")
        test_refs.append(f"{source_id}::{test_ref}")

bindings = manifest.get("missing_item_bindings", [])
if not isinstance(bindings, list) or not bindings:
    err("missing_item_bindings must be a non-empty array")
    bindings = []
required_binding_ids = {"tests.unit.primary", "tests.e2e.primary", "tests.fuzz.primary"}
binding_by_id = {str(item.get("id")): item for item in bindings if isinstance(item, dict)}
for binding_id in sorted(required_binding_ids):
    binding = binding_by_id.get(binding_id)
    if not isinstance(binding, dict):
        err(f"missing_item_bindings missing {binding_id}")
        continue
    for artifact in as_string_list(binding.get("required_artifacts"), f"{binding_id}.required_artifacts"):
        require((ROOT / artifact).exists(), f"{binding_id} artifact missing: {artifact}")
    for ref in as_string_list(binding.get("required_test_refs"), f"{binding_id}.required_test_refs"):
        require(any(ref in recorded for recorded in test_refs), f"{binding_id} references missing test ref {ref}")

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}
required_log_fields = as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields")
required_report_fields = as_string_list(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields")
declared_events = require_set(telemetry.get("required_events"), REQUIRED_TELEMETRY_EVENTS, "telemetry_contract.required_events")
for event in sorted(declared_events - REQUIRED_TELEMETRY_EVENTS):
    err(f"telemetry_contract.required_events declares unimplemented event {event}")

row_field_names = {
    "timestamp",
    "trace_id",
    "event",
    "bead_id",
    "source_bead",
    "completion_debt_bead",
    "status",
    "outcome",
    "source_commit",
    "schema_version",
    "artifact_refs",
    "test_refs",
    "failure_signature",
    "stream",
    "gate",
    "details",
}
report_field_names = {
    "schema_version",
    "manifest_id",
    "source_bead",
    "completion_debt_bead",
    "status",
    "source_commit",
    "summary",
    "source_artifacts",
    "required_architecture_contract",
    "test_refs",
    "events",
    "errors",
}
for field in required_log_fields:
    require(field in row_field_names, f"checker telemetry row missing required log field {field}")
for field in required_report_fields:
    require(field in report_field_names, f"checker report missing required report field {field}")

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
source_commit = git_head()
status = "pass" if not errors else "fail"
outcome = "pass" if not errors else "fail"
failure_signature = "none" if not errors else ";".join(errors[:8])
artifact_refs = [rel(CONTRACT), rel(REPORT), rel(LOG)]

events = [
    {
        "event": "fuzz_harness_architecture_completion_summary",
        "stream": "fuzz",
        "gate": "fuzz_harness_architecture_completion_contract",
        "details": {
            "total_targets": total_targets,
            "functional_targets": functional_targets,
            "checks": f"{checks_passed}/{checks_total}",
            "seed_corpus": total_seed_corpus,
            "dictionary_entries": total_dict_entries,
        },
    },
    {
        "event": "fuzz_harness_architecture_source_bindings",
        "stream": "fuzz",
        "gate": "fuzz_harness_architecture_completion_contract",
        "details": {
            "required_targets": sorted(required_targets),
            "summary_domains": sorted(source_domains),
            "required_checks": sorted(required_checks),
        },
    },
    {
        "event": "fuzz_harness_architecture_test_bindings",
        "stream": "conformance",
        "gate": "fuzz_harness_architecture_completion_contract",
        "details": {
            "missing_item_bindings": sorted(required_binding_ids),
            "test_refs": sorted(set(test_refs)),
        },
    },
    {
        "event": PASS_EVENT if not errors else FAIL_EVENT,
        "stream": "release",
        "gate": "fuzz_harness_architecture_completion_contract",
        "details": {
            "declared_events": sorted(declared_events),
            "required_report_fields": required_report_fields,
            "required_log_fields": required_log_fields,
        },
    },
]

rows: list[dict[str, Any]] = []
for seq, event in enumerate(events, start=1):
    rows.append(
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_BEAD}::fuzz-harness-architecture-completion::{seq:03d}",
            "event": event["event"],
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "outcome": outcome,
            "source_commit": source_commit,
            "schema_version": EXPECTED_SCHEMA,
            "artifact_refs": artifact_refs,
            "test_refs": sorted(set(test_refs)),
            "failure_signature": failure_signature,
            "stream": event["stream"],
            "gate": event["gate"],
            "details": event["details"],
        }
    )

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": {
        "source_artifacts": len(source_artifacts),
        "total_targets": total_targets,
        "functional_targets": functional_targets,
        "checks_total": checks_total,
        "checks_passed": checks_passed,
        "seed_corpus": total_seed_corpus,
        "dictionary_entries": total_dict_entries,
        "unique_cwes": unique_cwes,
        "test_refs": len(set(test_refs)),
        "telemetry_events": len(declared_events),
    },
    "source_artifacts": source_artifacts,
    "required_architecture_contract": architecture_contract,
    "test_refs": sorted(set(test_refs)),
    "events": [row["event"] for row in rows],
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"REPORT={rel(REPORT)}")
print(f"LOG={rel(LOG)}")
for error in errors:
    print(f"ERROR: {error}")

if errors:
    raise SystemExit(1)
PY
