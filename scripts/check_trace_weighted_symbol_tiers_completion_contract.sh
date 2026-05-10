#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_PATH="${TRACE_WEIGHTED_SYMBOL_TIERS_CONTRACT:-${ROOT_DIR}/tests/conformance/trace_weighted_symbol_tiers_completion_contract.v1.json}"
GENERATED_PATH="${TRACE_WEIGHTED_SYMBOL_TIERS_GENERATED:-${ROOT_DIR}/target/conformance/trace_weighted_symbol_tiers.generated.v1.json}"
REPORT_PATH="${TRACE_WEIGHTED_SYMBOL_TIERS_REPORT:-${ROOT_DIR}/target/conformance/trace_weighted_symbol_tiers_completion_contract.report.json}"
LOG_PATH="${TRACE_WEIGHTED_SYMBOL_TIERS_LOG:-${ROOT_DIR}/target/conformance/trace_weighted_symbol_tiers_completion_contract.jsonl}"

mkdir -p "$(dirname -- "${GENERATED_PATH}")" "$(dirname -- "${REPORT_PATH}")" "$(dirname -- "${LOG_PATH}")"

python3 - "${ROOT_DIR}" "${CONTRACT_PATH}" "${GENERATED_PATH}" "${REPORT_PATH}" "${LOG_PATH}" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(sys.argv[1])
CONTRACT = Path(sys.argv[2])
GENERATED = Path(sys.argv[3])
REPORT = Path(sys.argv[4])
LOG = Path(sys.argv[5])
START_NS = time.monotonic_ns()

EXPECTED_COVERAGE = {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}
REQUIRED_TELEMETRY_FIELDS = {
    "trace_id",
    "symbol",
    "tier",
    "family",
    "planned_wave",
    "rationale",
    "artifact_refs",
    "failure_signature",
    "latency_ns",
    "source_commit",
}
REQUIRED_TELEMETRY_EVENTS = {
    "trace_weighted_symbol_tier_validated",
    "trace_weighted_symbol_tiers_completion_contract_failed",
}


def source_commit():
    try:
        return subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "--short=12", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return "unknown"


def load_json(path):
    with Path(path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def rel(path):
    try:
        return Path(path).relative_to(ROOT).as_posix()
    except ValueError:
        return Path(path).as_posix()


def require(condition, message, errors):
    if not condition:
        errors.append(message)


def read_text(path, errors):
    full = ROOT / path
    if not full.exists():
        errors.append(f"missing path: {path}")
        return ""
    return full.read_text(encoding="utf-8")


def list_values(value):
    return value if isinstance(value, list) else []


def string_set(value):
    return {item for item in list_values(value) if isinstance(item, str)}


def validate_ref(ref, errors):
    path = ref.get("path")
    line = ref.get("line")
    anchor = ref.get("anchor")
    if not isinstance(path, str):
        errors.append(f"ref missing path: {ref!r}")
        return
    text = read_text(path, errors)
    if not text:
        return
    lines = text.splitlines()
    require(isinstance(line, int), f"{path} line is not an integer", errors)
    if isinstance(line, int):
        require(1 <= line <= len(lines), f"{path}:{line} outside 1..{len(lines)}", errors)
    if isinstance(anchor, str):
        require(anchor in text, f"{path} missing anchor {anchor!r}", errors)


def validate_source_anchors(manifest, errors):
    source_paths = manifest.get("source_paths") or {}
    for source, anchors in (manifest.get("source_anchors") or {}).items():
        path = source_paths.get(source)
        require(isinstance(path, str), f"missing source path for {source}", errors)
        if not isinstance(path, str):
            continue
        text = read_text(path, errors)
        for anchor in list_values(anchors):
            require(isinstance(anchor, str), f"non-string anchor for {source}", errors)
            if isinstance(anchor, str):
                require(anchor in text, f"{path} missing anchor {anchor!r}", errors)


def validate_test_refs(manifest, coverage, errors):
    source_paths = manifest.get("source_paths") or {}
    texts = {}
    count = 0
    for section in coverage:
        for ref in list_values(section.get("test_refs")):
            name = ref.get("name") if isinstance(ref, dict) else None
            source = ref.get("source") if isinstance(ref, dict) else None
            require(isinstance(name, str), f"test ref missing name: {ref!r}", errors)
            require(isinstance(source, str), f"test ref missing source: {ref!r}", errors)
            if not isinstance(name, str) or not isinstance(source, str):
                continue
            path = source_paths.get(source)
            require(isinstance(path, str), f"unknown test source {source}", errors)
            if not isinstance(path, str):
                continue
            text = texts.setdefault(path, read_text(path, errors))
            require(f"fn {name}(" in text, f"{path} missing test function fn {name}(", errors)
            count += 1
    return count


def run_generator(errors):
    generator = ROOT / "scripts/generate_symbol_tiers_roadmap.py"
    result = subprocess.run(
        ["python3", str(generator), "-o", str(GENERATED)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        errors.append(f"generator failed: {result.stderr.strip() or result.stdout.strip()}")
        return {}
    return load_json(GENERATED)


def validate_roadmap_report(name, report, contract, errors):
    road = contract.get("roadmap_contract") or {}
    required_symbol_fields = string_set(road.get("required_symbol_fields"))
    summary = report.get("summary") or {}
    tier_counts = summary.get("tier_counts") or {}
    symbols = report.get("tiered_symbols") or []
    waves = report.get("wave_roadmap") or {}
    checklist = report.get("wave_acceptance_checklist") or []
    mandatory = [item for item in checklist if item.get("mandatory")]

    require(report.get("schema_version") == "v1", f"{name} schema_version must be v1", errors)
    require(report.get("bead") == "bd-2vv.10", f"{name} bead must be bd-2vv.10", errors)
    require(isinstance(report.get("roadmap_hash"), str), f"{name} missing roadmap_hash", errors)
    require(
        summary.get("total_symbols", 0) >= road.get("minimum_symbols", 100),
        f"{name} has too few symbols",
        errors,
    )
    require(
        tier_counts.get("top50") == road.get("required_top50_count", 50),
        f"{name} top50 count mismatch",
        errors,
    )
    require(
        string_set(road.get("required_tiers")) <= set(tier_counts.keys()),
        f"{name} missing required tier counts",
        errors,
    )
    require(
        summary.get("wave_count", 0) >= road.get("minimum_waves", 3),
        f"{name} has too few waves",
        errors,
    )
    require(
        len(mandatory) >= road.get("minimum_mandatory_checklist_items", 3),
        f"{name} has too few mandatory checklist items",
        errors,
    )
    require(isinstance(symbols, list) and symbols, f"{name} missing tiered_symbols", errors)
    for index, symbol in enumerate(symbols[:25]):
        missing = required_symbol_fields - set(symbol.keys())
        require(not missing, f"{name} symbol {index} missing fields {sorted(missing)}", errors)
    wave_total = sum((wave.get("total_symbols") or 0) for wave in waves.values())
    require(
        wave_total == summary.get("total_symbols"),
        f"{name} wave total {wave_total} != total {summary.get('total_symbols')}",
        errors,
    )


def validate_contract(manifest, errors):
    require(
        manifest.get("schema_version") == "trace_weighted_symbol_tiers_completion_contract.v1",
        "unexpected schema_version",
        errors,
    )
    require(manifest.get("bead") == "bd-2vv.10", "unexpected bead id", errors)
    require(
        manifest.get("completion_debt_bead") == "bd-2vv.10.1",
        "unexpected completion debt bead id",
        errors,
    )
    for ref in list_values(manifest.get("implementation_refs")):
        if isinstance(ref, dict):
            validate_ref(ref, errors)
        else:
            errors.append(f"implementation ref is not an object: {ref!r}")
    validate_source_anchors(manifest, errors)

    coverage = list_values(manifest.get("completion_coverage"))
    coverage_by_id = {
        item.get("missing_item_id"): item
        for item in coverage
        if isinstance(item, dict) and isinstance(item.get("missing_item_id"), str)
    }
    require(
        EXPECTED_COVERAGE <= set(coverage_by_id.keys()),
        f"coverage missing ids {sorted(EXPECTED_COVERAGE - set(coverage_by_id.keys()))}",
        errors,
    )
    for item_id in EXPECTED_COVERAGE:
        section = coverage_by_id.get(item_id) or {}
        require(section.get("status") == "covered", f"{item_id} status must be covered", errors)
    test_ref_count = validate_test_refs(manifest, coverage, errors)

    telemetry = manifest.get("telemetry_contract") or {}
    telemetry_fields = string_set(telemetry.get("required_fields"))
    telemetry_events = string_set(telemetry.get("events"))
    require(
        REQUIRED_TELEMETRY_FIELDS <= telemetry_fields,
        f"telemetry contract missing fields {sorted(REQUIRED_TELEMETRY_FIELDS - telemetry_fields)}",
        errors,
    )
    require(
        REQUIRED_TELEMETRY_EVENTS <= telemetry_events,
        f"telemetry contract missing events {sorted(REQUIRED_TELEMETRY_EVENTS - telemetry_events)}",
        errors,
    )

    report_path = manifest.get("source_paths", {}).get("roadmap_report")
    require(isinstance(report_path, str), "roadmap_report source path missing", errors)
    checked_in = load_json(ROOT / report_path) if isinstance(report_path, str) else {}
    generated = run_generator(errors)
    if checked_in:
        validate_roadmap_report("checked-in roadmap", checked_in, manifest, errors)
    if generated:
        validate_roadmap_report("generated roadmap", generated, manifest, errors)
    if checked_in and generated:
        require(
            checked_in.get("roadmap_hash") == generated.get("roadmap_hash"),
            "generated roadmap hash differs from checked-in roadmap hash",
            errors,
        )

    artifact_refs = list_values(telemetry.get("artifact_refs"))
    return {
        "missing_items_covered": len(EXPECTED_COVERAGE & set(coverage_by_id.keys())),
        "test_ref_count": test_ref_count,
        "telemetry_field_count": len(telemetry_fields),
        "roadmap_hash": generated.get("roadmap_hash") or checked_in.get("roadmap_hash"),
        "symbol_count": (generated.get("summary") or checked_in.get("summary") or {}).get("total_symbols", 0),
        "artifact_refs": [item for item in artifact_refs if isinstance(item, str)],
        "generated": generated,
        "telemetry_fields": sorted(telemetry_fields),
    }


def write_outputs(manifest, errors, metrics):
    elapsed_ns = max(1, time.monotonic_ns() - START_NS)
    ok = not errors
    commit = source_commit()
    bead = manifest.get("bead") if isinstance(manifest, dict) else "bd-2vv.10"
    completion = (
        manifest.get("completion_debt_bead")
        if isinstance(manifest, dict)
        else "bd-2vv.10.1"
    )
    report = {
        "schema_version": "trace_weighted_symbol_tiers_completion_contract.report.v1",
        "status": "pass" if ok else "fail",
        "bead": bead,
        "completion_debt_bead": completion,
        "source_commit": commit,
        "roadmap_hash": metrics.get("roadmap_hash"),
        "symbol_count": metrics.get("symbol_count", 0),
        "latency_ns": elapsed_ns,
        "failure_signature": "none" if ok else "trace_weighted_symbol_tiers_contract_invalid",
        "errors": errors,
        "summary": {
            "missing_items_covered": metrics.get("missing_items_covered", 0),
            "test_ref_count": metrics.get("test_ref_count", 0),
            "telemetry_field_count": metrics.get("telemetry_field_count", 0),
            "artifact_refs": metrics.get("artifact_refs", []),
        },
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    generated = metrics.get("generated") or {}
    symbols = list_values(generated.get("tiered_symbols"))[:3]
    waves = generated.get("wave_roadmap") or {}
    rows = []
    if ok and symbols:
        for index, symbol in enumerate(symbols, start=1):
            wave_key = str(symbol.get("wave"))
            rationale = (waves.get(wave_key) or {}).get("rationale", "roadmap wave assignment")
            rows.append(
                {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                    "trace_id": f"{completion}::symbol-tier::{index:03}",
                    "level": "info",
                    "event": "trace_weighted_symbol_tier_validated",
                    "bead_id": bead,
                    "stream": "conformance",
                    "gate": "trace_weighted_symbol_tiers_completion_contract",
                    "mode": "strict",
                    "runtime_mode": "strict",
                    "api_family": "symbol_roadmap",
                    "symbol": symbol.get("symbol"),
                    "tier": symbol.get("tier"),
                    "family": symbol.get("family"),
                    "planned_wave": symbol.get("wave"),
                    "rationale": rationale,
                    "decision_path": "trace_frequency->priority_score->tier->wave",
                    "healing_action": "None",
                    "outcome": "pass",
                    "errno": 0,
                    "latency_ns": elapsed_ns,
                    "source_commit": commit,
                    "target_dir": os.environ.get("CARGO_TARGET_DIR", "target"),
                    "failure_signature": "none",
                    "artifact_refs": metrics.get("artifact_refs", []),
                }
            )
    else:
        rows.append(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                "trace_id": f"{completion}::symbol-tier::failed",
                "level": "error",
                "event": "trace_weighted_symbol_tiers_completion_contract_failed",
                "bead_id": bead,
                "stream": "conformance",
                "gate": "trace_weighted_symbol_tiers_completion_contract",
                "mode": "strict",
                "runtime_mode": "strict",
                "api_family": "symbol_roadmap",
                "symbol": "symbol_tiers_roadmap",
                "tier": "unknown",
                "family": "roadmap",
                "planned_wave": 0,
                "rationale": "completion contract failed closed",
                "decision_path": "contract->fail-closed",
                "healing_action": "None",
                "outcome": "fail",
                "errno": 1,
                "latency_ns": elapsed_ns,
                "source_commit": commit,
                "target_dir": os.environ.get("CARGO_TARGET_DIR", "target"),
                "failure_signature": "trace_weighted_symbol_tiers_contract_invalid",
                "artifact_refs": metrics.get("artifact_refs", []),
                "details": {"errors": errors},
            }
        )
    LOG.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


errors = []
metrics = {}
manifest = None
try:
    manifest = load_json(CONTRACT)
    metrics = validate_contract(manifest, errors)
except Exception as exc:
    errors.append(f"checker exception: {type(exc).__name__}: {exc}")

write_outputs(manifest, errors, metrics)
if errors:
    for error in errors:
        print(f"trace-weighted symbol tiers contract error: {error}", file=sys.stderr)
    sys.exit(1)
print(f"trace-weighted symbol tiers completion contract passed: {REPORT}")
PY
