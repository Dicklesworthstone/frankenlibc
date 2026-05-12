#!/usr/bin/env bash
# check_trace_weighted_stub_ranking_completion_contract.sh - bd-1x3.2.1 evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_TRACE_WEIGHTED_STUB_RANKING_CONTRACT:-${ROOT}/tests/conformance/trace_weighted_stub_ranking_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_TRACE_WEIGHTED_STUB_RANKING_REPORT:-${ROOT}/target/conformance/trace_weighted_stub_ranking_completion_contract.report.json}"
LOG="${FRANKENLIBC_TRACE_WEIGHTED_STUB_RANKING_LOG:-${ROOT}/target/conformance/trace_weighted_stub_ranking_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import copy
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

ORIGINAL_BEAD = "bd-1x3.2"
COMPLETION_DEBT_BEAD = "bd-1x3.2.1"
SCHEMA_VERSION = "trace_weighted_stub_ranking_completion_contract.v1"
FAILURE_SIGNATURE = "trace_weighted_stub_ranking_completion_contract_invalid"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "trace_weighted_stub_ranking_completion.source_ref",
    "trace_weighted_stub_ranking_completion.missing_item_bound",
    "trace_weighted_stub_ranking_completion.deterministic_fuzz_seed_replayed",
    "trace_weighted_stub_ranking_completion.conformance_artifact_bound",
    "trace_weighted_stub_ranking_completion.telemetry_bound",
    "trace_weighted_stub_ranking_completion.validated",
}
REQUIRED_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "scenario_id",
    "api_family",
    "symbol",
    "outcome",
    "latency_ns",
    "failure_signature",
    "artifact_refs",
}
REQUIRED_HOOKS = {"setjmp", "tls", "threading", "hard_parts"}
MINIMUM_SEED_COUNT = 10


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def workspace_path(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def row(event: str, status: str = "pass", **fields: Any) -> dict[str, Any]:
    failure = "none" if status == "pass" else FAILURE_SIGNATURE
    return {
        "timestamp": utc_now(),
        "trace_id": f"{COMPLETION_DEBT_BEAD}::trace_weighted_stub_ranking::001",
        "level": "info" if status == "pass" else "error",
        "event": event,
        "bead_id": COMPLETION_DEBT_BEAD,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "status": status,
        "scenario_id": fields.pop("scenario_id", event),
        "stream": "conformance",
        "gate": "trace_weighted_stub_ranking_completion_contract",
        "mode": "strict",
        "runtime_mode": "strict",
        "replacement_level": "L0",
        "api_family": fields.pop("api_family", "stub_ranking"),
        "symbol": fields.pop("symbol", "trace_weighted_stub_ranking"),
        "oracle_kind": fields.pop("oracle_kind", "completion_contract"),
        "expected": fields.pop("expected", {"status": "pass"}),
        "actual": fields.pop("actual", {"status": status}),
        "errno": 0 if status == "pass" else 1,
        "decision_path": fields.pop("decision_path", "contract->artifact->telemetry"),
        "healing_action": "None",
        "outcome": "pass" if status == "pass" else "fail",
        "latency_ns": fields.pop("latency_ns", 1),
        "target_dir": "target/conformance",
        "failure_signature": failure,
        "artifact_refs": fields.pop("artifact_refs", []),
        **fields,
    }


def require_dict(value: Any, label: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return {}
    return value


def require_list(value: Any, label: str, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{label} must be an array")
        return []
    return value


def require_string_list(value: Any, label: str, errors: list[str]) -> list[str]:
    result: list[str] = []
    for index, item in enumerate(require_list(value, label, errors)):
        if isinstance(item, str) and item:
            result.append(item)
        else:
            errors.append(f"{label}[{index}] must be a non-empty string")
    return result


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load_json(path: Path, label: str, errors: list[str]) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(data, dict):
        errors.append(f"{label} must be a JSON object")
        return {}
    return data


def validate_line_ref(ref: Any, label: str, errors: list[str]) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"{label} must be file:line")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{label} has invalid line number: {ref}")
        return
    path = workspace_path(path_text)
    if not path.is_file():
        errors.append(f"{label} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        errors.append(f"{label} references line past EOF: {ref}")
    elif not lines[line_number - 1].strip():
        errors.append(f"{label} references blank line: {ref}")


def run_gate(command: list[str], errors: list[str]) -> None:
    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    if result.returncode != 0:
        errors.append(
            "gate failed: "
            + " ".join(command)
            + "\nstdout="
            + result.stdout[-2000:]
            + "\nstderr="
            + result.stderr[-2000:]
        )


def validate_artifacts(
    evidence: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> tuple[dict[str, str], dict[str, Path]]:
    artifacts = require_dict(evidence.get("artifacts"), "completion_debt_evidence.artifacts", errors)
    directory_artifacts = set(
        require_string_list(evidence.get("directory_artifacts"), "directory_artifacts", errors)
    )
    texts: dict[str, str] = {}
    paths: dict[str, Path] = {}
    for artifact_id, path_value in artifacts.items():
        if not isinstance(path_value, str) or not path_value:
            errors.append(f"artifact {artifact_id} path must be a non-empty string")
            continue
        path = workspace_path(path_value)
        paths[artifact_id] = path
        if artifact_id in directory_artifacts:
            if not path.is_dir():
                errors.append(f"artifact {artifact_id} missing directory: {path_value}")
                continue
        else:
            if not path.is_file():
                errors.append(f"artifact {artifact_id} missing file: {path_value}")
                continue
            try:
                texts[artifact_id] = path.read_text(encoding="utf-8")
            except Exception as exc:
                errors.append(f"artifact {artifact_id} unreadable: {path_value}: {exc}")
                continue
        rows.append(
            row(
                "trace_weighted_stub_ranking_completion.source_ref",
                artifact_id=artifact_id,
                artifact_refs=[path_value],
            )
        )
    for ref in require_list(evidence.get("implementation_refs"), "implementation_refs", errors):
        validate_line_ref(ref, "implementation_refs", errors)
    return texts, paths


def validate_missing_bindings(
    evidence: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> list[str]:
    actual: set[str] = set()
    sections: set[str] = set()
    for index, binding in enumerate(
        require_list(evidence.get("missing_item_bindings"), "missing_item_bindings", errors)
    ):
        if not isinstance(binding, dict):
            errors.append(f"missing_item_bindings[{index}] must be an object")
            continue
        item_id = binding.get("missing_item_id")
        section = binding.get("evidence_section")
        if isinstance(item_id, str):
            actual.add(item_id)
        else:
            errors.append(f"missing_item_bindings[{index}].missing_item_id missing")
        if isinstance(section, str):
            sections.add(section)
        else:
            errors.append(f"missing_item_bindings[{index}].evidence_section missing")
        if isinstance(item_id, str) and isinstance(section, str):
            rows.append(
                row(
                    "trace_weighted_stub_ranking_completion.missing_item_bound",
                    item_id=item_id,
                    evidence_section=section,
                )
            )
    if actual != REQUIRED_MISSING_ITEMS:
        errors.append(f"missing items must be {sorted(REQUIRED_MISSING_ITEMS)}, got {sorted(actual)}")
    for required_section in [
        "unit_primary",
        "e2e_primary",
        "fuzz_primary",
        "conformance_primary",
        "telemetry_primary",
    ]:
        if required_section not in sections or not isinstance(evidence.get(required_section), dict):
            errors.append(f"{required_section} must be bound and present")
    return sorted(actual)


def validate_test_refs(section: dict[str, Any], texts: dict[str, str], label: str, errors: list[str]) -> int:
    count = 0
    for index, ref in enumerate(require_list(section.get("required_test_refs"), f"{label}.required_test_refs", errors)):
        if not isinstance(ref, dict):
            errors.append(f"{label}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not isinstance(name, str):
            errors.append(f"{label}.required_test_refs[{index}] source/name missing")
            continue
        text = texts.get(source)
        if text is None:
            errors.append(f"{label}.required_test_refs[{index}] references unknown source {source}")
            continue
        if f"fn {name}(" not in text:
            errors.append(f"{source} missing test function fn {name}(")
            continue
        count += 1
    return count


def validate_required_artifacts(
    section: dict[str, Any], paths: dict[str, Path], label: str, errors: list[str]
) -> int:
    count = 0
    for artifact_id in require_string_list(section.get("required_artifacts"), f"{label}.required_artifacts", errors):
        path = paths.get(artifact_id)
        if path is None:
            errors.append(f"{label}.required_artifacts references unknown artifact {artifact_id}")
            continue
        if not path.exists():
            errors.append(f"{label}.required_artifacts missing {artifact_id}")
            continue
        count += 1
    return count


def validate_ranking_artifact(ranking: dict[str, Any], errors: list[str]) -> None:
    if as_int(ranking.get("schema_version"), 0) < 1:
        errors.append("ranking schema_version must be >= 1")
    if ranking.get("bead") != "bd-4ia":
        errors.append("ranking bead must be bd-4ia")
    symbol_ranking = require_dict(ranking.get("symbol_ranking"), "ranking.symbol_ranking", errors)
    tiers = require_list(symbol_ranking.get("tiers"), "ranking.symbol_ranking.tiers", errors)
    if not tiers:
        errors.append("ranking tiers must be non-empty")
    tier_symbol_total = 0
    for tier in tiers:
        if not isinstance(tier, dict):
            errors.append("ranking tier must be an object")
            continue
        symbols = require_list(tier.get("symbols"), "ranking tier symbols", errors)
        count = as_int(tier.get("count"), -1)
        if count != len(symbols):
            errors.append("ranking tier count mismatch")
        tier_symbol_total += len(symbols)
    burn = require_dict(ranking.get("burn_down"), "ranking.burn_down", errors)
    burn_total = as_int(burn.get("total_non_implemented"), -1)
    if burn_total != tier_symbol_total:
        errors.append("ranking burn_down total does not match tier symbols")
    summary = require_dict(ranking.get("summary"), "ranking.summary", errors)
    if as_int(summary.get("total_non_implemented"), -1) != tier_symbol_total:
        errors.append("ranking summary total does not match tier symbols")
    if as_int(summary.get("stubs"), 0) + as_int(summary.get("callthroughs"), 0) != tier_symbol_total:
        errors.append("ranking summary stubs+callthroughs mismatch")
    waves = require_list(burn.get("wave_plan"), "ranking.burn_down.wave_plan", errors)
    wave_total = 0
    for wave in waves:
        if isinstance(wave, dict):
            wave_total += as_int(wave.get("symbols"), 0)
    if wave_total != burn_total:
        errors.append("ranking wave symbols total mismatch")


def validate_wave_plan_artifact(plan: dict[str, Any], errors: list[str]) -> None:
    if plan.get("schema_version") != "v1":
        errors.append("wave plan schema_version must be v1")
    if plan.get("bead") != "bd-3mam":
        errors.append("wave plan bead must be bd-3mam")
    if plan.get("uplift_bead") != ORIGINAL_BEAD:
        errors.append("wave plan uplift_bead must be bd-1x3.2")
    inputs = require_dict(plan.get("inputs"), "wave_plan.inputs", errors)
    fixtures = require_dict(inputs.get("trace_fixtures_dir"), "wave_plan.inputs.trace_fixtures_dir", errors)
    if as_int(fixtures.get("fixture_count"), 0) < 1:
        errors.append("wave plan fixture_count must be positive")
    hooks = require_dict(plan.get("integration_hooks"), "wave_plan.integration_hooks", errors)
    for key in REQUIRED_HOOKS:
        values = hooks.get(key)
        if not isinstance(values, list) or not values:
            errors.append(f"wave plan integration_hooks.{key} must be non-empty")
    downgrade = require_dict(plan.get("downgrade_policy"), "wave_plan.downgrade_policy", errors)
    if downgrade.get("default_decision") != "deny":
        errors.append("wave plan downgrade default_decision must be deny")
    summary = require_dict(plan.get("summary"), "wave_plan.summary", errors)
    modules = require_list(plan.get("module_ranking"), "wave_plan.module_ranking", errors)
    symbols = require_list(plan.get("symbol_ranking_top_n"), "wave_plan.symbol_ranking_top_n", errors)
    waves = require_list(plan.get("wave_plan"), "wave_plan.wave_plan", errors)
    candidate_count = as_int(summary.get("candidate_symbols"), -1)
    if candidate_count > 0 and (not modules or not symbols or not waves):
        errors.append("wave plan candidate rows missing")
    if candidate_count == 0 and (modules or symbols or waves):
        errors.append("wave plan rows must be empty when no candidates remain")
    if as_int(summary.get("top_n"), -1) != len(symbols):
        errors.append("wave plan summary top_n mismatch")
    if as_int(summary.get("module_count"), -1) != len(modules):
        errors.append("wave plan summary module_count mismatch")
    if as_int(summary.get("wave_count"), -1) != len(waves):
        errors.append("wave plan summary wave_count mismatch")


def mutate_payload(payload: dict[str, Any], mutation: str) -> dict[str, Any]:
    mutated = copy.deepcopy(payload)
    if mutation == "schema_version_zero":
        mutated["schema_version"] = 0
    elif mutation == "remove_symbol_tiers":
        mutated.setdefault("symbol_ranking", {})["tiers"] = []
    elif mutation == "increment_burn_down_total":
        mutated.setdefault("burn_down", {})["total_non_implemented"] = (
            as_int(mutated.get("burn_down", {}).get("total_non_implemented"), 0) + 1
        )
    elif mutation == "increment_summary_total":
        mutated.setdefault("summary", {})["total_non_implemented"] = (
            as_int(mutated.get("summary", {}).get("total_non_implemented"), 0) + 1
        )
    elif mutation == "wrong_uplift_bead":
        mutated["uplift_bead"] = "bd-wrong"
    elif mutation == "candidate_count_without_rows":
        mutated.setdefault("summary", {})["candidate_symbols"] = 1
        mutated["module_ranking"] = []
        mutated["symbol_ranking_top_n"] = []
        mutated["wave_plan"] = []
    elif mutation == "clear_threading_hook":
        mutated.setdefault("integration_hooks", {})["threading"] = []
    elif mutation == "allow_downgrade_default":
        mutated.setdefault("downgrade_policy", {})["default_decision"] = "allow"
    elif mutation == "zero_trace_fixture_count":
        mutated.setdefault("inputs", {}).setdefault("trace_fixtures_dir", {})["fixture_count"] = 0
    elif mutation == "increment_top_n":
        mutated.setdefault("summary", {})["top_n"] = as_int(mutated.get("summary", {}).get("top_n"), 0) + 1
    else:
        mutated["schema_version"] = "unknown-mutation"
    return mutated


def replay_fuzz_seeds(
    section: dict[str, Any],
    ranking: dict[str, Any],
    wave_plan: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> int:
    seeds = require_list(section.get("deterministic_seed_replay"), "fuzz_primary.deterministic_seed_replay", errors)
    minimum = as_int(section.get("minimum_seed_count"), MINIMUM_SEED_COUNT)
    if len(seeds) < minimum:
        errors.append(f"fuzz seed count {len(seeds)} below minimum {minimum}")
    replayed = 0
    for index, seed in enumerate(seeds):
        if not isinstance(seed, dict):
            errors.append(f"fuzz seed {index} must be an object")
            continue
        seed_id = seed.get("seed_id")
        artifact = seed.get("artifact")
        mutation = seed.get("mutation")
        expected_signature = seed.get("expected_failure_signature")
        if not all(isinstance(value, str) and value for value in [seed_id, artifact, mutation, expected_signature]):
            errors.append(f"fuzz seed {index} missing id/artifact/mutation/signature")
            continue
        target = ranking if artifact == "stub_priority_ranking" else wave_plan
        mutated = mutate_payload(target, mutation)
        seed_errors: list[str] = []
        if artifact == "stub_priority_ranking":
            validate_ranking_artifact(mutated, seed_errors)
        elif artifact == "workload_wave_plan":
            validate_wave_plan_artifact(mutated, seed_errors)
        else:
            seed_errors.append(f"unknown artifact {artifact}")
        if not seed_errors:
            errors.append(f"fuzz seed {seed_id} did not fail closed")
            continue
        replayed += 1
        rows.append(
            row(
                "trace_weighted_stub_ranking_completion.deterministic_fuzz_seed_replayed",
                scenario_id=seed_id,
                artifact=artifact,
                mutation=mutation,
                expected_failure_signature=expected_signature,
                observed_error_count=len(seed_errors),
            )
        )
    return replayed


def validate_telemetry(
    section: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> tuple[int, list[str]]:
    events = set(require_string_list(section.get("required_events"), "telemetry_primary.required_events", errors))
    fields = set(require_string_list(section.get("required_fields"), "telemetry_primary.required_fields", errors))
    consumed = require_string_list(section.get("consumed_gate_events"), "telemetry_primary.consumed_gate_events", errors)
    if not REQUIRED_EVENTS <= events:
        errors.append(f"telemetry events missing {sorted(REQUIRED_EVENTS - events)}")
    if not REQUIRED_LOG_FIELDS <= fields:
        errors.append(f"telemetry fields missing {sorted(REQUIRED_LOG_FIELDS - fields)}")
    for event in sorted(events):
        rows.append(row("trace_weighted_stub_ranking_completion.telemetry_bound", telemetry_event=event))
    return len(events), consumed


def validate_consumed_gate_log(consumed_events: list[str], errors: list[str]) -> None:
    log_path = root / "target/conformance/workload_api_wave_plan.log.jsonl"
    if not log_path.is_file():
        errors.append("workload API wave plan log missing after gate run")
        return
    seen: set[str] = set()
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except Exception as exc:
            errors.append(f"workload API wave plan log has invalid JSONL: {exc}")
            continue
        event = payload.get("event")
        if isinstance(event, str):
            seen.add(event)
    missing = set(consumed_events) - seen
    if missing:
        errors.append(f"consumed gate events missing from workload log: {sorted(missing)}")


def validate_contract(manifest: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> dict[str, Any]:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append("unexpected schema_version")
    if manifest.get("bead") != ORIGINAL_BEAD:
        errors.append("unexpected original bead")
    if manifest.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
        errors.append("unexpected completion debt bead")
    evidence = require_dict(manifest.get("completion_debt_evidence"), "completion_debt_evidence", errors)
    if evidence.get("next_audit_score_threshold") != 900:
        errors.append("next audit score threshold must be 900")

    texts, paths = validate_artifacts(evidence, errors, rows)
    missing_items = validate_missing_bindings(evidence, errors, rows)

    unit = require_dict(evidence.get("unit_primary"), "unit_primary", errors)
    e2e = require_dict(evidence.get("e2e_primary"), "e2e_primary", errors)
    fuzz = require_dict(evidence.get("fuzz_primary"), "fuzz_primary", errors)
    conformance = require_dict(evidence.get("conformance_primary"), "conformance_primary", errors)
    telemetry = require_dict(evidence.get("telemetry_primary"), "telemetry_primary", errors)

    unit_test_ref_count = validate_test_refs(unit, texts, "unit_primary", errors)
    e2e_test_ref_count = validate_test_refs(e2e, texts, "e2e_primary", errors)
    conformance_test_ref_count = validate_test_refs(conformance, texts, "conformance_primary", errors)
    e2e_artifact_count = validate_required_artifacts(e2e, paths, "e2e_primary", errors)
    conformance_artifact_count = validate_required_artifacts(conformance, paths, "conformance_primary", errors)

    ranking = load_json(paths.get("stub_priority_ranking", root / "__missing__"), "stub priority ranking", errors)
    wave_plan = load_json(paths.get("workload_wave_plan", root / "__missing__"), "workload wave plan", errors)
    if ranking:
        validate_ranking_artifact(ranking, errors)
    if wave_plan:
        validate_wave_plan_artifact(wave_plan, errors)

    fixtures_path = paths.get("conformance_fixtures")
    fixture_count = len(list(fixtures_path.glob("*.json"))) if fixtures_path and fixtures_path.is_dir() else 0
    minimum_fixture_count = as_int(conformance.get("minimum_fixture_count"), 0)
    if fixture_count < minimum_fixture_count:
        errors.append(f"fixture count {fixture_count} below minimum {minimum_fixture_count}")
    if wave_plan:
        plan_fixture_count = as_int(
            wave_plan.get("inputs", {}).get("trace_fixtures_dir", {}).get("fixture_count"), 0
        )
        if plan_fixture_count != fixture_count:
            errors.append(f"wave plan fixture_count {plan_fixture_count} != actual {fixture_count}")

    for artifact_id in require_string_list(conformance.get("required_artifacts"), "conformance_primary.required_artifacts", errors):
        rows.append(
            row(
                "trace_weighted_stub_ranking_completion.conformance_artifact_bound",
                artifact_id=artifact_id,
                artifact_refs=[rel(paths[artifact_id])] if artifact_id in paths else [],
            )
        )

    run_gate(["bash", "scripts/check_stub_priority.sh"], errors)
    run_gate(["bash", "scripts/check_workload_api_wave_plan.sh"], errors)
    telemetry_event_count, consumed_events = validate_telemetry(telemetry, errors, rows)
    validate_consumed_gate_log(consumed_events, errors)
    fuzz_seed_count = replay_fuzz_seeds(fuzz, ranking, wave_plan, errors, rows)

    return {
        "missing_items": missing_items,
        "unit_test_ref_count": unit_test_ref_count,
        "e2e_test_ref_count": e2e_test_ref_count,
        "conformance_test_ref_count": conformance_test_ref_count,
        "e2e_artifact_count": e2e_artifact_count,
        "conformance_artifact_count": conformance_artifact_count,
        "fuzz_seed_count": fuzz_seed_count,
        "fixture_count": fixture_count,
        "telemetry_event_count": telemetry_event_count,
        "artifact_refs": sorted(rel(path) for path in paths.values()),
    }


def write_outputs(manifest: dict[str, Any] | None, errors: list[str], metrics: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    ok = not errors
    status = "pass" if ok else "fail"
    event = (
        "trace_weighted_stub_ranking_completion.validated"
        if ok
        else "trace_weighted_stub_ranking_completion.failed"
    )
    summary_row = row(
        event,
        status=status,
        artifact_refs=metrics.get("artifact_refs", []),
        missing_items=metrics.get("missing_items", []),
        unit_test_ref_count=metrics.get("unit_test_ref_count", 0),
        e2e_test_ref_count=metrics.get("e2e_test_ref_count", 0),
        e2e_artifact_count=metrics.get("e2e_artifact_count", 0),
        deterministic_fuzz_seed_count=metrics.get("fuzz_seed_count", 0),
        conformance_test_ref_count=metrics.get("conformance_test_ref_count", 0),
        conformance_artifact_count=metrics.get("conformance_artifact_count", 0),
        fixture_count=metrics.get("fixture_count", 0),
        telemetry_event_count=metrics.get("telemetry_event_count", 0),
        errors=errors,
    )
    rows.append(summary_row)
    report = {
        "schema_version": "trace_weighted_stub_ranking_completion_contract.report.v1",
        "timestamp": utc_now(),
        "trace_id": f"{COMPLETION_DEBT_BEAD}:trace-weighted-stub-ranking",
        "event": event,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "status": status,
        "missing_items": metrics.get("missing_items", []),
        "artifact_refs": metrics.get("artifact_refs", []),
        "unit_test_ref_count": metrics.get("unit_test_ref_count", 0),
        "e2e_test_ref_count": metrics.get("e2e_test_ref_count", 0),
        "e2e_artifact_count": metrics.get("e2e_artifact_count", 0),
        "deterministic_fuzz_seed_count": metrics.get("fuzz_seed_count", 0),
        "conformance_test_ref_count": metrics.get("conformance_test_ref_count", 0),
        "conformance_artifact_count": metrics.get("conformance_artifact_count", 0),
        "fixture_count": metrics.get("fixture_count", 0),
        "telemetry_event_count": metrics.get("telemetry_event_count", 0),
        "failure_signature": "none" if ok else FAILURE_SIGNATURE,
        "errors": errors,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text(
        "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in rows),
        encoding="utf-8",
    )


errors: list[str] = []
rows: list[dict[str, Any]] = []
metrics: dict[str, Any] = {}
manifest: dict[str, Any] | None = None
try:
    manifest = load_json(contract_path, "completion contract", errors)
    if manifest:
        metrics = validate_contract(manifest, errors, rows)
except Exception as exc:
    errors.append(f"checker exception: {type(exc).__name__}: {exc}")

write_outputs(manifest, errors, metrics, rows)
if errors:
    for error in errors:
        print(f"trace-weighted stub ranking completion error: {error}", file=sys.stderr)
    sys.exit(1)
print(
    "PASS: trace-weighted stub ranking completion contract "
    f"unit_refs={metrics.get('unit_test_ref_count', 0)} "
    f"e2e_artifacts={metrics.get('e2e_artifact_count', 0)} "
    f"fuzz_seeds={metrics.get('fuzz_seed_count', 0)} "
    f"conformance_refs={metrics.get('conformance_test_ref_count', 0)} "
    f"fixtures={metrics.get('fixture_count', 0)}"
)
PY
