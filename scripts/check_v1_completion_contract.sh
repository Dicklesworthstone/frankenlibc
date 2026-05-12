#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_V1_COMPLETION_CONTRACT:-$ROOT/tests/conformance/v1_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_V1_COMPLETION_OUT_DIR:-$ROOT/target/conformance/v1_completion_contract}"
REPORT="${FRANKENLIBC_V1_COMPLETION_REPORT:-$OUT_DIR/v1_completion_contract.report.json}"
LOG="${FRANKENLIBC_V1_COMPLETION_LOG:-$OUT_DIR/v1_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import shlex
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "v1_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "v1_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-2uro.1-v1-completion-contract"
SOURCE_BEAD = "bd-2uro"
COMPLETION_BEAD = "bd-2uro.1"
REQUIRED_SOURCE_IDS = {
    "support_matrix",
    "conformance_coverage",
    "closure_sweep",
    "ld_preload_smoke_summary",
    "cve_corpus_index",
    "fuzz_phase1_targets",
    "posix_obligation_matrix",
    "proof_binder_validation",
    "strict_differential_parity_contract",
    "release_dossier_report",
    "closure_contract",
    "ld_preload_smoke_test",
    "fuzz_phase1_test",
    "strict_differential_test",
    "proof_binder_test",
    "release_dossier_test",
    "completion_checker",
    "completion_harness_test",
}
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "v1_completion_sources_bound",
    "v1_completion_missing_items_bound",
    "v1_completion_claims_validated",
    "v1_completion_telemetry_validated",
    "v1_completion_contract_pass",
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


def repo_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative without parent traversal: {path_text}")
        return None
    full = ROOT / path
    if not full.exists():
        err(f"{context} references missing path: {path_text}")
        return None
    return full


def as_string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        err(f"{context} must be a non-empty array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def append_event(
    event: str, status: str, artifact_refs: list[str], details: dict[str, Any] | None = None
) -> None:
    events.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "source_bead": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "v1_completion_contract_failed",
            "details": details or {},
        }
    )


def validate_line_ref(file_line_ref: Any, context: str) -> None:
    if not isinstance(file_line_ref, str) or ":" not in file_line_ref:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = file_line_ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        err(f"{context} has invalid line number: {file_line_ref}")
        return
    path = repo_path(path_text, context)
    if path is None or not path.is_file():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        err(f"{context} references non-UTF8 text: {file_line_ref}")
        return
    if line_no < 1 or line_no > len(lines):
        err(f"{context} points past EOF: {file_line_ref}")
    elif not lines[line_no - 1].strip():
        err(f"{context} points to a blank line: {file_line_ref}")


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}(" in text or f"fn {name}<" in text or f"def {name}(" in text


def has_unrouted_cargo(command: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for index, token in enumerate(tokens):
        if token != "cargo":
            continue
        if "rch" not in tokens[:index]:
            return True
    return False


def validate_sources(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    found: dict[str, str] = {}
    for artifact_id, path_text in artifacts.items():
        path = repo_path(path_text, f"source_artifacts.{artifact_id}")
        if path is not None and isinstance(path_text, str):
            found[str(artifact_id)] = path_text
    missing = REQUIRED_SOURCE_IDS - set(found)
    if missing:
        err(f"source_artifacts missing required ids: {sorted(missing)}")
    for ref in as_string_list(manifest.get("implementation_refs"), "implementation_refs"):
        validate_line_ref(ref, f"implementation_refs.{ref}")
    append_event(
        "v1_completion_sources_bound",
        "pass" if not errors else "fail",
        [found[key] for key in sorted(found) if key in REQUIRED_SOURCE_IDS],
        {"source_count": len(found)},
    )
    return found


def validate_bindings(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    bindings = manifest.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        err("missing_item_bindings must be a non-empty array")
        return {"binding_count": 0, "test_ref_count": 0, "command_count": 0}

    source_cache: dict[str, str] = {}
    found_ids: set[str] = set()
    test_ref_count = 0
    command_count = 0
    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing_item_bindings entries must be objects")
            continue
        item_id = binding.get("id")
        if not isinstance(item_id, str) or not item_id:
            err("missing_item_bindings entry missing id")
            continue
        found_ids.add(item_id)
        for ref in as_string_list(binding.get("implementation_refs"), f"missing_item_bindings.{item_id}.implementation_refs"):
            validate_line_ref(ref, f"missing_item_bindings.{item_id}.implementation_refs.{ref}")
        refs = binding.get("required_test_refs")
        if not isinstance(refs, list) or not refs:
            err(f"missing_item_bindings.{item_id}.required_test_refs must be non-empty")
            refs = []
        for index, ref_obj in enumerate(refs):
            if not isinstance(ref_obj, dict):
                err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] must be an object")
                continue
            source_id = ref_obj.get("source")
            name = ref_obj.get("name")
            if not isinstance(source_id, str) or source_id not in artifacts:
                err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] references unknown source {source_id!r}")
                continue
            if source_id not in source_cache:
                source_path = repo_path(artifacts[source_id], f"test_source.{source_id}")
                source_cache[source_id] = source_path.read_text(encoding="utf-8") if source_path and source_path.is_file() else ""
            if not isinstance(name, str) or not function_exists(source_cache[source_id], name):
                err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] missing test {source_id}::{name}")
            else:
                test_ref_count += 1
        commands = as_string_list(binding.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands")
        for command in commands:
            command_count += 1
            if has_unrouted_cargo(command):
                err(f"missing_item_bindings.{item_id}.required_commands contains bare cargo command: {command}")

    missing = REQUIRED_MISSING_ITEMS - found_ids
    extra = found_ids - REQUIRED_MISSING_ITEMS
    if missing or extra:
        err(f"missing_item_bindings ids mismatch: missing={sorted(missing)} extra={sorted(extra)}")

    append_event(
        "v1_completion_missing_items_bound",
        "pass" if not errors else "fail",
        [artifacts.get("completion_checker", ""), artifacts.get("completion_harness_test", "")],
        {"binding_count": len(bindings), "test_ref_count": test_ref_count, "command_count": command_count},
    )
    return {"binding_count": len(bindings), "test_ref_count": test_ref_count, "command_count": command_count}


def expect_int(actual: Any, expected: Any, context: str) -> None:
    require(isinstance(actual, int) and actual == expected, f"{context} drift: expected={expected!r} actual={actual!r}")


def validate_claims(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest.get("claimed_closure_contract")
    if not isinstance(contract, dict):
        err("claimed_closure_contract must be an object")
        return {}

    support = load_json(ROOT / artifacts.get("support_matrix", ""), "support_matrix")
    support_expected = contract.get("support_matrix", {})
    summary = support.get("summary", {}) if isinstance(support.get("summary"), dict) else {}
    expect_int(summary.get("total"), support_expected.get("expected_total_exported"), "support_matrix.summary.total")
    expect_int(support.get("total_exported"), support_expected.get("expected_total_exported"), "support_matrix.total_exported")
    native_total = summary.get("implemented", 0) + summary.get("raw_syscall", 0)
    expect_int(native_total, support_expected.get("expected_native_total"), "support_matrix.native_total")
    expect_int(summary.get("glibc_call_through"), support_expected.get("expected_glibc_callthrough"), "support_matrix.glibc_call_through")
    expect_int(summary.get("stub"), support_expected.get("expected_stub"), "support_matrix.stub")

    coverage = load_json(ROOT / artifacts.get("conformance_coverage", ""), "conformance_coverage")
    coverage_expected = contract.get("conformance_coverage", {})
    coverage_summary = coverage.get("summary", {}) if isinstance(coverage.get("summary"), dict) else {}
    expect_int(coverage_summary.get("total_symbols"), coverage_expected.get("expected_classified_symbols"), "conformance_coverage.summary.total_symbols")
    require(
        coverage_summary.get("total_fixture_cases", 0) >= coverage_expected.get("minimum_fixture_cases", 0),
        "conformance_coverage total_fixture_cases below floor",
    )
    require(
        coverage_summary.get("total_fixture_files", 0) >= coverage_expected.get("minimum_fixture_files", 0),
        "conformance_coverage total_fixture_files below floor",
    )

    closure = load_json(ROOT / artifacts.get("closure_sweep", ""), "closure_sweep")
    closure_expected = contract.get("closure_sweep", {})
    closure_summary = closure.get("summary", {}) if isinstance(closure.get("summary"), dict) else {}
    expect_int(closure_summary.get("callthrough_remaining"), closure_expected.get("expected_callthrough_remaining"), "closure_sweep.summary.callthrough_remaining")
    expect_int(closure_summary.get("open_gap_beads"), closure_expected.get("expected_open_gap_beads"), "closure_sweep.summary.open_gap_beads")
    expect_int(closure_summary.get("errors"), closure_expected.get("expected_errors"), "closure_sweep.summary.errors")

    smoke = load_json(ROOT / artifacts.get("ld_preload_smoke_summary", ""), "ld_preload_smoke_summary")
    smoke_expected = contract.get("ld_preload_smoke", {})
    smoke_summary = smoke.get("summary", {}) if isinstance(smoke.get("summary"), dict) else {}
    for key, expected_key in [
        ("total_cases", "expected_total_cases"),
        ("passes", "expected_passes"),
        ("fails", "expected_fails"),
        ("skips", "expected_skips"),
    ]:
        expect_int(smoke_summary.get(key), smoke_expected.get(expected_key), f"ld_preload_smoke.summary.{key}")
    require(
        smoke_summary.get("overall_failed") is smoke_expected.get("expected_overall_failed"),
        f"ld_preload_smoke.summary.overall_failed drift: expected={smoke_expected.get('expected_overall_failed')!r} actual={smoke_summary.get('overall_failed')!r}",
    )

    cve = load_json(ROOT / artifacts.get("cve_corpus_index", ""), "cve_corpus_index")
    cve_expected = contract.get("cve_arena", {})
    cve_summary = cve.get("corpus_summary", {}) if isinstance(cve.get("corpus_summary"), dict) else {}
    require(
        cve_summary.get("total_scenarios", 0) >= cve_expected.get("minimum_total_scenarios", 0),
        "cve_arena total_scenarios below floor",
    )
    require(
        cve_summary.get("all_replay_deterministic") is cve_expected.get("require_all_replay_deterministic"),
        "cve_arena replay determinism drift",
    )
    feature_counts = cve_summary.get("tsm_features_coverage", {})
    for feature in cve_expected.get("required_tsm_features", []):
        require(isinstance(feature_counts, dict) and feature_counts.get(feature, 0) > 0, f"cve_arena missing TSM feature coverage: {feature}")

    fuzz = load_json(ROOT / artifacts.get("fuzz_phase1_targets", ""), "fuzz_phase1_targets")
    fuzz_expected = contract.get("fuzz_phase1", {})
    fuzz_summary = fuzz.get("summary", {}) if isinstance(fuzz.get("summary"), dict) else {}
    for key, expected_key in [
        ("phase", "expected_phase"),
        ("total_targets", "expected_total_targets"),
        ("functional_targets", "expected_functional_targets"),
        ("stub_targets", "expected_stub_targets"),
    ]:
        expect_int(fuzz_summary.get(key), fuzz_expected.get(expected_key), f"fuzz_phase1.summary.{key}")
    require(
        fuzz_summary.get("total_cwes_targeted", 0) >= fuzz_expected.get("minimum_cwes_targeted", 0),
        "fuzz_phase1 total_cwes_targeted below floor",
    )

    posix = load_json(ROOT / artifacts.get("posix_obligation_matrix", ""), "posix_obligation_matrix")
    posix_expected = contract.get("posix_obligations", {})
    posix_summary = posix.get("summary", {}) if isinstance(posix.get("summary"), dict) else {}
    expect_int(posix_summary.get("total_obligations"), posix_expected.get("expected_total_obligations"), "posix_obligations.summary.total_obligations")
    expect_int(posix_summary.get("covered_obligations"), posix_expected.get("expected_covered_obligations"), "posix_obligations.summary.covered_obligations")
    expect_int(posix_summary.get("obligations_with_execution_failures"), posix_expected.get("expected_execution_failures"), "posix_obligations.summary.obligations_with_execution_failures")

    proof = load_json(ROOT / artifacts.get("proof_binder_validation", ""), "proof_binder_validation")
    proof_expected = contract.get("proof_binder", {})
    require(proof.get("binder_valid") is proof_expected.get("expected_binder_valid"), "proof_binder binder_valid drift")
    expect_int(proof.get("total_violations"), proof_expected.get("expected_total_violations"), "proof_binder.total_violations")
    require(proof.get("valid_obligations", 0) >= proof_expected.get("minimum_valid_obligations", 0), "proof_binder valid_obligations below floor")
    categories = set(proof.get("categories_covered", [])) if isinstance(proof.get("categories_covered"), list) else set()
    for category in proof_expected.get("required_categories", []):
        require(category in categories, f"proof_binder missing required category {category}")

    differential = load_json(ROOT / artifacts.get("strict_differential_parity_contract", ""), "strict_differential_parity_contract")
    differential_expected = contract.get("strict_differential", {})
    claimed = differential.get("claimed_surface", {}) if isinstance(differential.get("claimed_surface"), dict) else {}
    required_cases = claimed.get("strict_required_cases", [])
    require(isinstance(required_cases, list) and len(required_cases) >= differential_expected.get("minimum_required_cases", 0), "strict_differential strict_required_cases below floor")
    expect_int(
        claimed.get("strict_claimed_surface_mismatch_count_max"),
        differential_expected.get("expected_claimed_surface_mismatch_max"),
        "strict_differential.claimed_surface.strict_claimed_surface_mismatch_count_max",
    )

    dossier = load_json(ROOT / artifacts.get("release_dossier_report", ""), "release_dossier_report")
    dossier_expected = contract.get("release_dossier", {})
    require(dossier.get("status") == dossier_expected.get("expected_status"), "release_dossier status drift")
    require(dossier.get("verdict") == dossier_expected.get("expected_verdict"), "release_dossier verdict drift")
    dossier_summary = dossier.get("summary", {}) if isinstance(dossier.get("summary"), dict) else {}
    expect_int(dossier_summary.get("critical_missing"), dossier_expected.get("expected_critical_missing"), "release_dossier.summary.critical_missing")
    expect_int(dossier_summary.get("errors"), dossier_expected.get("expected_errors"), "release_dossier.summary.errors")
    require(dossier_summary.get("valid", 0) >= dossier_expected.get("minimum_valid_artifacts", 0), "release_dossier valid artifact count below floor")

    summary_result = {
        "support_total": summary.get("total"),
        "native_total": native_total,
        "classified_symbols": coverage_summary.get("total_symbols"),
        "smoke_passes": smoke_summary.get("passes"),
        "fuzz_targets": fuzz_summary.get("total_targets"),
        "posix_obligations": posix_summary.get("total_obligations"),
        "proof_valid_obligations": proof.get("valid_obligations"),
        "release_status": dossier.get("status"),
    }
    append_event(
        "v1_completion_claims_validated",
        "pass" if not errors else "fail",
        [
            artifacts.get("support_matrix", ""),
            artifacts.get("conformance_coverage", ""),
            artifacts.get("ld_preload_smoke_summary", ""),
            artifacts.get("fuzz_phase1_targets", ""),
            artifacts.get("proof_binder_validation", ""),
            artifacts.get("release_dossier_report", ""),
        ],
        summary_result,
    )
    return summary_result


def validate_telemetry(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    telemetry = manifest.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return {"required_events": []}
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
    if required_events != REQUIRED_EVENTS:
        err(f"telemetry_contract.required_events mismatch: missing={sorted(REQUIRED_EVENTS - required_events)} extra={sorted(required_events - REQUIRED_EVENTS)}")
    required_fields = set(as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    missing_fields = {"timestamp", "event", "source_bead", "completion_debt_bead", "status", "artifact_refs", "failure_signature", "details"} - required_fields
    if missing_fields:
        err(f"telemetry_contract.required_log_fields missing {sorted(missing_fields)}")
    append_event(
        "v1_completion_telemetry_validated",
        "pass" if not errors else "fail",
        [artifacts.get("completion_checker", ""), artifacts.get("completion_harness_test", "")],
        {"required_event_count": len(required_events), "required_field_count": len(required_fields)},
    )
    return {"required_events": sorted(required_events), "required_fields": sorted(required_fields)}


manifest = load_json(CONTRACT, "v1 completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version drift")
require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id drift")
require(manifest.get("original_bead") == SOURCE_BEAD, "original_bead drift")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead drift")
require(manifest.get("next_audit_score_threshold", 0) >= 800, "next audit score threshold must be >=800")

artifacts = validate_sources(manifest)
binding_summary = validate_bindings(manifest, artifacts)
claim_summary = validate_claims(manifest, artifacts) if artifacts else {}
telemetry_summary = validate_telemetry(manifest, artifacts)

status = "pass" if not errors else "fail"
append_event(
    "v1_completion_contract_pass",
    status,
    [rel(CONTRACT), rel(REPORT), rel(LOG)],
    {"error_count": len(errors)},
)

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": status,
    "source_bead": SOURCE_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "manifest": rel(CONTRACT),
    "report": rel(REPORT),
    "log": rel(LOG),
    "summaries": {
        "bindings": binding_summary,
        "claims": claim_summary,
        "telemetry": telemetry_summary,
        "source_count": len(artifacts),
    },
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

if errors:
    print("FAIL: v1 completion contract failed", flush=True)
    for message in errors:
        print(f"- {message}", flush=True)
    raise SystemExit(1)

print(
    f"PASS: v1 completion contract validated sources={len(artifacts)} "
    f"bindings={binding_summary.get('binding_count')} "
    f"native={claim_summary.get('native_total')} "
    f"smoke_passes={claim_summary.get('smoke_passes')}",
    flush=True,
)
PY
