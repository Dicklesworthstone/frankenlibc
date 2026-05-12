#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SYNTHETIC_WORKLOAD_COMPOSER:-$ROOT/tests/conformance/synthetic_workload_composer.v1.json}"
OUT_DIR="${FRANKENLIBC_SYNTHETIC_WORKLOAD_COMPOSER_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_SYNTHETIC_WORKLOAD_COMPOSER_REPORT:-$OUT_DIR/synthetic_workload_composer.report.json}"
LOG="${FRANKENLIBC_SYNTHETIC_WORKLOAD_COMPOSER_LOG:-$OUT_DIR/synthetic_workload_composer.log.jsonl}"
SOURCE_COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" SOURCE_COMMIT="$SOURCE_COMMIT" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import sys
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
SOURCE_COMMIT = os.environ["SOURCE_COMMIT"]

BEAD = "bd-26xb.11"
COMPLETION_BEAD = "bd-26xb.11.1"
REQUIRED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}
FAILURE_SIGNATURE = "synthetic_workload_composer_contract_invalid"

errors: list[str] = []
rows: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def repo_path(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else ROOT / path


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label} must be a JSON object")
        return {}
    return value


def string_list(value: Any, label: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        errors.append(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if isinstance(item, str) and item:
            result.append(item)
        else:
            errors.append(f"{label}[{index}] must be a non-empty string")
    return result


def numeric(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def row(event: str, status: str = "pass", **fields: Any) -> dict[str, Any]:
    failure = "none" if status == "pass" else FAILURE_SIGNATURE
    output = {
        "timestamp": utc_now(),
        "trace_id": f"{COMPLETION_BEAD}::synthetic_workload_composer::001",
        "bead_id": COMPLETION_BEAD,
        "original_bead": BEAD,
        "event": event,
        "status": status,
        "outcome": "pass" if status == "pass" else "fail",
        "mode": fields.pop("mode", "strict+hardened"),
        "api_family": fields.pop("api_family", "workload_composer"),
        "symbol": fields.pop("symbol", "synthetic_workload"),
        "decision_path": fields.pop("decision_path", "motif->compose->validate"),
        "healing_action": "None",
        "errno": 0 if status == "pass" else 1,
        "latency_ns": fields.pop("latency_ns", 1),
        "artifact_refs": fields.pop("artifact_refs", []),
        "source_commit": SOURCE_COMMIT,
        "failure_signature": failure,
        "composition_id": fields.pop("composition_id", "none"),
        "motif_id": fields.pop("motif_id", "none"),
        "edge_emphasis_score": fields.pop("edge_emphasis_score", 0),
    }
    output.update(fields)
    return output


def validate_source_artifacts(contract: dict[str, Any]) -> dict[str, pathlib.Path]:
    artifacts = contract.get("source_artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        errors.append("source_artifacts must be a non-empty object")
        return {}
    resolved: dict[str, pathlib.Path] = {}
    for artifact_id, path_value in artifacts.items():
        if not isinstance(path_value, str) or not path_value:
            errors.append(f"source_artifacts.{artifact_id} must be a non-empty string")
            continue
        path = repo_path(path_value)
        resolved[artifact_id] = path
        require(path.is_file(), f"source artifact {artifact_id} missing file: {path_value}")
    return resolved


def validate_completion_debt(contract: dict[str, Any], harness_text: str) -> dict[str, Any]:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return {"sections": 0}
    require(evidence.get("bead") == COMPLETION_BEAD, f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
    require(evidence.get("original_bead") == BEAD, f"completion_debt_evidence.original_bead must be {BEAD}")
    for section, missing_item in REQUIRED_MISSING_ITEMS.items():
        section_data = evidence.get(section)
        if not isinstance(section_data, dict):
            errors.append(f"completion_debt_evidence.{section} must be an object")
            continue
        require(section_data.get("missing_item_id") == missing_item, f"{section} must bind {missing_item}")
        for test_name in string_list(section_data.get("required_test_names"), f"{section}.required_test_names"):
            require(f"fn {test_name}" in harness_text, f"{section} references missing test {test_name}")
    return {"sections": len(REQUIRED_MISSING_ITEMS)}


def validate_tooling(contract: dict[str, Any], cargo_text: str) -> dict[str, Any]:
    tooling = contract.get("tooling_contract")
    if not isinstance(tooling, dict):
        errors.append("tooling_contract must be an object")
        return {"asupersync": False, "frankentui": False}
    asuper = tooling.get("asupersync_traceability")
    ftui = tooling.get("frankentui_snapshot")
    if not isinstance(asuper, dict):
        errors.append("tooling_contract.asupersync_traceability must be an object")
        asuper = {}
    if not isinstance(ftui, dict):
        errors.append("tooling_contract.frankentui_snapshot must be an object")
        ftui = {}
    require(asuper.get("enabled") is True, "asupersync traceability must be enabled")
    require(asuper.get("cargo_feature") in cargo_text, "asupersync cargo feature missing")
    require(asuper.get("required_dependency") in cargo_text, "asupersync dependency missing")
    require("default = [\"asupersync-tooling\"]" in cargo_text, "asupersync tooling must be enabled by default")
    require(ftui.get("enabled") is True, "frankentui snapshot must be enabled")
    require(ftui.get("cargo_feature") in cargo_text, "frankentui cargo feature missing")
    require(ftui.get("required_dependency") in cargo_text, "frankentui dependency missing")
    rows.append(
        row(
            "synthetic_workload_composer.tooling_bound",
            artifact_refs=["crates/frankenlibc-harness/Cargo.toml"],
            edge_emphasis_score=2,
        )
    )
    return {"asupersync": asuper.get("enabled") is True, "frankentui": ftui.get("enabled") is True}


def validate_motifs(contract: dict[str, Any], workload_ids: set[str]) -> dict[str, Any]:
    motifs = contract.get("trace_motifs")
    if not isinstance(motifs, list) or not motifs:
        errors.append("trace_motifs must be a non-empty array")
        return {}
    motif_by_id: dict[str, dict[str, Any]] = {}
    seeds: set[int] = set()
    for motif in motifs:
        if not isinstance(motif, dict):
            errors.append("trace_motifs entries must be objects")
            continue
        motif_id = motif.get("motif_id")
        if not isinstance(motif_id, str) or not motif_id:
            errors.append("motif missing motif_id")
            continue
        if motif_id in motif_by_id:
            errors.append(f"duplicate motif_id {motif_id}")
        motif_by_id[motif_id] = motif
        sources = string_list(motif.get("source_workload_ids"), f"{motif_id}.source_workload_ids")
        for source in sources:
            require(source in workload_ids, f"{motif_id} references unknown workload {source}")
        require(numeric(motif.get("intensity")) > 0, f"{motif_id} intensity must be positive")
        modules = string_list(motif.get("required_modules"), f"{motif_id}.required_modules")
        symbols = string_list(motif.get("critical_symbols"), f"{motif_id}.critical_symbols")
        require(bool(modules), f"{motif_id} must bind modules")
        require(bool(symbols), f"{motif_id} must bind symbols")
        seed = motif.get("deterministic_seed")
        require(isinstance(seed, int), f"{motif_id} deterministic_seed must be integer")
        if isinstance(seed, int):
            require(seed not in seeds, f"duplicate deterministic seed {seed}")
            seeds.add(seed)
        require(isinstance(motif.get("rough_path_signature"), str), f"{motif_id} missing rough_path_signature")
        rows.append(
            row(
                "synthetic_workload_composer.motif_bound",
                motif_id=motif_id,
                api_family=motif.get("api_family", "unknown"),
                mode=motif.get("mode", "strict+hardened"),
                edge_emphasis_score=len(motif.get("edge_emphasis", [])),
                artifact_refs=["tests/conformance/workload_matrix.json"],
            )
        )
    return motif_by_id


def validate_compositions(contract: dict[str, Any], motif_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    compositions = contract.get("composed_workloads")
    if not isinstance(compositions, list) or not compositions:
        errors.append("composed_workloads must be a non-empty array")
        return {"count": 0}
    composition_ids: set[str] = set()
    for composition in compositions:
        if not isinstance(composition, dict):
            errors.append("composed_workloads entries must be objects")
            continue
        composition_id = composition.get("composition_id")
        if not isinstance(composition_id, str) or not composition_id:
            errors.append("composition missing composition_id")
            continue
        require(composition_id not in composition_ids, f"duplicate composition_id {composition_id}")
        composition_ids.add(composition_id)
        motif_ids = string_list(composition.get("motifs"), f"{composition_id}.motifs")
        modules: set[str] = set()
        symbols: set[str] = set()
        for motif_id in motif_ids:
            motif = motif_by_id.get(motif_id)
            if motif is None:
                errors.append(f"{composition_id} references unknown motif {motif_id}")
                continue
            modules.update(string_list(motif.get("required_modules"), f"{motif_id}.required_modules"))
            symbols.update(string_list(motif.get("critical_symbols"), f"{motif_id}.critical_symbols"))
        actual_modules = set(string_list(composition.get("required_modules"), f"{composition_id}.required_modules"))
        actual_symbols = set(string_list(composition.get("critical_symbols"), f"{composition_id}.critical_symbols"))
        require(modules <= actual_modules, f"{composition_id} does not preserve motif module union")
        require(symbols <= actual_symbols, f"{composition_id} does not preserve motif symbol union")
        require(numeric(composition.get("expected_rare_edge_uplift_pct")) > 0, f"{composition_id} uplift must be positive")
        require(bool(string_list(composition.get("target_edge_cases"), f"{composition_id}.target_edge_cases")), f"{composition_id} target edge cases missing")
        require(bool(string_list(composition.get("deterministic_replay_command"), f"{composition_id}.deterministic_replay_command")), f"{composition_id} deterministic replay command missing")
        checks = composition.get("preservation_checks")
        if not isinstance(checks, dict):
            errors.append(f"{composition_id} preservation_checks must be object")
            checks = {}
        for field in ["required_modules_superset", "critical_symbols_superset", "deterministic_seed_replay"]:
            require(checks.get(field) is True, f"{composition_id} preservation_checks.{field} must be true")
        rows.append(
            row(
                "synthetic_workload_composer.composition_bound",
                composition_id=composition_id,
                motif_id=",".join(motif_ids),
                mode=composition.get("mode", "strict+hardened"),
                edge_emphasis_score=len(composition.get("target_edge_cases", [])),
                artifact_refs=composition.get("artifact_refs", []),
            )
        )
    return {"count": len(compositions)}


def validate_telemetry(contract: dict[str, Any]) -> None:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be an object")
        return
    rows.append(
        row(
            "synthetic_workload_composer.validated",
            artifact_refs=[rel(CONTRACT), rel(REPORT), rel(LOG)],
            edge_emphasis_score=1,
        )
    )
    required_events = set(string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
    emitted_events = {entry["event"] for entry in rows}
    missing_events = sorted(required_events - emitted_events)
    require(not missing_events, "telemetry missing events: " + ", ".join(missing_events))
    for entry in rows:
        for field in string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"):
            if field not in entry:
                errors.append(f"telemetry row {entry.get('event')} missing field {field}")


contract = load_json(CONTRACT, "synthetic workload composer")
require(contract.get("schema_version") == "v1", "schema_version must be v1")
require(contract.get("bead") == BEAD, f"bead must be {BEAD}")
require(contract.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

artifacts = validate_source_artifacts(contract)
workload_matrix = load_json(artifacts.get("workload_matrix", ROOT / "__missing__"), "workload matrix")
harness_cargo = artifacts.get("harness_cargo", ROOT / "__missing__").read_text(encoding="utf-8") if artifacts.get("harness_cargo", ROOT / "__missing__").is_file() else ""
harness_test = artifacts.get("composer_harness_test", ROOT / "__missing__").read_text(encoding="utf-8") if artifacts.get("composer_harness_test", ROOT / "__missing__").is_file() else ""

workload_ids = {
    row.get("id")
    for row in workload_matrix.get("workloads", [])
    if isinstance(row, dict) and isinstance(row.get("id"), str)
}
motifs = validate_motifs(contract, workload_ids)
composition_summary = validate_compositions(contract, motifs)
tooling_summary = validate_tooling(contract, harness_cargo)
completion_summary = validate_completion_debt(contract, harness_test)
validate_telemetry(contract)

status = "fail" if errors else "pass"
report = {
    "schema_version": "synthetic_workload_composer.report.v1",
    "status": status,
    "bead": BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "source_commit": SOURCE_COMMIT,
    "errors": errors,
    "summary": {
        "motif_count": len(motifs),
        "composition_count": composition_summary.get("count", 0),
        "workload_source_count": len(workload_ids),
        "tooling": tooling_summary,
        "completion_debt": completion_summary,
        "telemetry_rows": len(rows),
    },
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("\n".join(json.dumps(entry, sort_keys=True) for entry in rows) + "\n", encoding="utf-8")

if errors:
    print("FAIL: synthetic workload composer contract failed", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: synthetic workload composer "
    f"motifs={len(motifs)} compositions={composition_summary.get('count', 0)} "
    f"workloads={len(workload_ids)} telemetry_rows={len(rows)}"
)
PY
