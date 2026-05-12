#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_MATH_RETIREMENT_COMPLETION_CONTRACT:-$ROOT/tests/conformance/math_retirement_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_MATH_RETIREMENT_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_MATH_RETIREMENT_COMPLETION_REPORT:-$OUT_DIR/math_retirement_completion_contract.report.json}"
LOG="${FRANKENLIBC_MATH_RETIREMENT_COMPLETION_LOG:-$OUT_DIR/math_retirement_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

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

EXPECTED_SCHEMA = "math_retirement_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "math_retirement_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-545"
COMPLETION_BEAD = "bd-545.1"
REQUIRED_BINDINGS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "migrations.primary",
    "telemetry.primary",
}
CANONICAL_RULE_IDS = ["RC-1", "RC-2", "RC-3"]
CANONICAL_STAGE_ORDER = ["active", "deprecated", "research_only", "removed"]

errors: list[str] = []


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


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


def string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        out.append(item)
    return out


def source_text(path_text: str, label: str) -> str:
    path = ROOT / path_text
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} is unreadable at {path_text}: {exc}")
        return ""


def module_set(rows: Any, context: str) -> set[str]:
    if not isinstance(rows, list):
        err(f"{context} must be an array")
        return set()
    result: set[str] = set()
    for index, row in enumerate(rows):
        name = row.get("module") if isinstance(row, dict) else row
        if not isinstance(name, str) or not name:
            err(f"{context}[{index}] must name a module")
            continue
        result.add(name)
    return result


def rust_test_exists(source: str, name: str) -> bool:
    return f"fn {name}" in source


def load_sources(manifest: dict[str, Any]) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}, {}

    texts: dict[str, str] = {}
    loaded: dict[str, dict[str, Any]] = {}
    for source_id, path_value in artifacts.items():
        if not isinstance(path_value, str) or not path_value:
            err(f"source_artifacts.{source_id} must be a non-empty string")
            continue
        path = ROOT / path_value
        require(path.is_file(), f"source artifact missing: {source_id}: {path_value}")
        if not path.is_file():
            continue
        if path.suffix == ".json":
            loaded[source_id] = load_json(path, source_id)
        texts[source_id] = source_text(path_value, source_id)
    return texts, loaded


def validate_policy(
    manifest: dict[str, Any],
    loaded: dict[str, dict[str, Any]],
    texts: dict[str, str],
) -> dict[str, Any]:
    policy = loaded.get("retirement_policy", {})
    governance = loaded.get("governance", {})
    production_manifest = loaded.get("production_manifest", {})
    linkage = loaded.get("linkage", {})

    expected_summary = manifest.get("expected_policy_summary", {})
    if not isinstance(expected_summary, dict):
        err("expected_policy_summary must be an object")
        expected_summary = {}
    summary = policy.get("summary", {}) if isinstance(policy.get("summary"), dict) else {}
    require(summary == expected_summary, "math retirement summary drifted")

    gate_contract = manifest.get("retirement_gate_contract", {})
    if not isinstance(gate_contract, dict):
        err("retirement_gate_contract must be an object")
        gate_contract = {}

    required_rule_ids = string_list(gate_contract.get("required_rule_ids"), "required_rule_ids")
    require(required_rule_ids == CANONICAL_RULE_IDS, "required_rule_ids must match canonical RC-1/RC-2/RC-3")
    rules = policy.get("retirement_criteria", {}).get("rules", [])
    if not isinstance(rules, list):
        err("retirement_criteria.rules must be an array")
        rules = []
    actual_rule_ids = [row.get("id") for row in rules if isinstance(row, dict)]
    require(actual_rule_ids == required_rule_ids, "retirement rule order or ids drifted")
    for row in rules:
        if isinstance(row, dict):
            rid = row.get("id", "?")
            for field in ["name", "description", "severity", "enforcement"]:
                require(isinstance(row.get(field), str) and row.get(field), f"rule {rid} missing {field}")

    required_stage_order = string_list(gate_contract.get("required_stage_order"), "required_stage_order")
    require(required_stage_order == CANONICAL_STAGE_ORDER, "required_stage_order must match canonical lifecycle")
    stages = policy.get("deprecation_stages", {}).get("stages", [])
    if not isinstance(stages, list):
        err("deprecation_stages.stages must be an array")
        stages = []
    actual_stage_order = [row.get("stage") for row in stages if isinstance(row, dict)]
    require(actual_stage_order == required_stage_order, "deprecation stage order drifted")

    for marker in string_list(gate_contract.get("required_gate_markers"), "required_gate_markers"):
        require(marker in texts.get("retirement_gate", ""), f"retirement gate missing marker: {marker}")
    for marker in string_list(gate_contract.get("required_ci_markers"), "required_ci_markers"):
        require(marker in texts.get("ci_script", ""), f"CI script missing marker: {marker}")
    for needle in string_list(gate_contract.get("required_verification_matrix_needles"), "required_verification_matrix_needles"):
        require(needle in texts.get("verification_matrix", ""), f"verification matrix missing needle: {needle}")

    classifications = governance.get("classifications", {}) if isinstance(governance.get("classifications"), dict) else {}
    prod_core = module_set(classifications.get("production_core"), "governance.production_core")
    prod_monitor = module_set(classifications.get("production_monitor"), "governance.production_monitor")
    research = module_set(classifications.get("research"), "governance.research")
    production_modules = set(string_list(production_manifest.get("production_modules"), "production_manifest.production_modules"))
    research_only_modules = set(string_list(production_manifest.get("research_only_modules"), "production_manifest.research_only_modules"))

    assessment = policy.get("current_assessment", {}) if isinstance(policy.get("current_assessment"), dict) else {}
    rc1 = assessment.get("rc1_candidates", {}) if isinstance(assessment.get("rc1_candidates"), dict) else {}
    rc2 = assessment.get("rc2_candidates", {}) if isinstance(assessment.get("rc2_candidates"), dict) else {}
    compliant = assessment.get("production_compliant", {}) if isinstance(assessment.get("production_compliant"), dict) else {}

    actual_rc1 = research & production_modules
    claimed_rc1 = set(string_list(rc1.get("modules"), "policy.rc1_candidates.modules", allow_empty=True))
    require(claimed_rc1 == actual_rc1, "RC-1 candidates drifted from governance/manifest")
    require(rc1.get("count") == len(actual_rc1), "RC-1 count drifted")

    expected_production = prod_core | prod_monitor
    require(production_modules == expected_production, "production manifest must equal governance production tiers")
    claimed_core = set(string_list(compliant.get("production_core"), "policy.production_compliant.production_core"))
    claimed_monitor = set(string_list(compliant.get("production_monitor"), "policy.production_compliant.production_monitor"))
    require(claimed_core == prod_core, "production_core compliance list drifted")
    require(claimed_monitor == prod_monitor, "production_monitor compliance list drifted")
    require(compliant.get("count") == len(expected_production), "production compliant count drifted")

    linkage_modules = linkage.get("modules", {}) if isinstance(linkage.get("modules"), dict) else {}
    actual_rc2 = {
        name
        for name, row in linkage_modules.items()
        if name in production_modules and isinstance(row, dict) and row.get("linkage_status") != "Production"
    }
    require(rc2.get("count") == len(actual_rc2), "RC-2 count drifted from linkage ledger")
    require(not actual_rc2, f"production modules have non-Production linkage: {sorted(actual_rc2)}")

    active_waivers = policy.get("active_waivers", [])
    if not isinstance(active_waivers, list):
        err("active_waivers must be an array")
        active_waivers = []
    required_waiver_fields = string_list(policy.get("waiver_policy", {}).get("required_fields"), "waiver_policy.required_fields")
    covered: set[str] = set()
    for index, waiver in enumerate(active_waivers):
        if not isinstance(waiver, dict):
            err(f"active_waivers[{index}] must be an object")
            continue
        for field in required_waiver_fields:
            require(field in waiver, f"active_waivers[{index}] missing {field}")
        module = waiver.get("module")
        if module == "ALL_RESEARCH":
            covered = set(claimed_rc1)
        elif isinstance(module, str):
            covered.add(module)
    require(claimed_rc1 <= covered, "active waivers do not cover every RC-1 candidate")
    require(summary.get("active_waivers") == len(active_waivers), "active waiver summary count drifted")

    migration = policy.get("migration_notes", {}) if isinstance(policy.get("migration_notes"), dict) else {}
    waves = migration.get("waves", [])
    if not isinstance(waves, list):
        err("migration_notes.waves must be an array")
        waves = []
    wave_modules: set[str] = set()
    for index, wave in enumerate(waves):
        if not isinstance(wave, dict):
            err(f"migration wave {index} must be an object")
            continue
        modules = set(string_list(wave.get("modules"), f"migration wave {index}.modules", allow_empty=True))
        require(wave.get("count") == len(modules), f"migration wave {index} count drifted")
        duplicate = wave_modules & modules
        require(not duplicate, f"duplicate migration wave modules: {sorted(duplicate)}")
        wave_modules |= modules
    require(wave_modules == claimed_rc1, "migration waves must cover exactly the RC-1 candidates")
    require(migration.get("total_modules_to_migrate") == len(wave_modules), "migration total_modules_to_migrate drifted")
    require(migration.get("total_waves") == len(waves), "migration total_waves drifted")

    migration_contract = manifest.get("migration_contract", {})
    if not isinstance(migration_contract, dict):
        err("migration_contract must be an object")
        migration_contract = {}
    require(
        len(research_only_modules) == migration_contract.get("expected_research_only_modules"),
        "research_only_modules count drifted",
    )
    require(len(production_modules) == migration_contract.get("expected_production_modules"), "production_modules count drifted")
    require(
        migration.get("total_modules_to_migrate") == migration_contract.get("expected_total_modules_to_migrate"),
        "migration contract expected_total_modules_to_migrate drifted",
    )
    require(research_only_modules == research, "research_only manifest must equal governance research tier")
    require(not (production_modules & research_only_modules), "production and research_only manifests overlap")
    for marker in string_list(migration_contract.get("required_manifest_feature_text"), "required_manifest_feature_text"):
        require(marker in texts.get("membrane_cargo", ""), f"membrane Cargo.toml missing feature marker: {marker}")

    return {
        "rules": len(actual_rule_ids),
        "stages": len(actual_stage_order),
        "production_modules": len(production_modules),
        "research_only_modules": len(research_only_modules),
        "rc1_candidates": len(claimed_rc1),
        "rc2_candidates": rc2.get("count", 0),
        "migration_waves": len(waves),
        "total_modules_to_migrate": migration.get("total_modules_to_migrate", 0),
        "policy_status": summary.get("policy_status", "unknown"),
    }


def validate_bindings(manifest: dict[str, Any], texts: dict[str, str]) -> dict[str, Any]:
    bindings = manifest.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        err("missing_item_bindings must be a non-empty array")
        bindings = []

    ids = {binding.get("id") for binding in bindings if isinstance(binding, dict)}
    require(ids == REQUIRED_BINDINGS, "missing_item_bindings must close unit/e2e/migrations/telemetry exactly")

    test_sources = manifest.get("test_sources", {})
    if not isinstance(test_sources, dict) or not test_sources:
        err("test_sources must be a non-empty object")
        test_sources = {}

    test_source_text: dict[str, str] = {}
    for source_id, path_text in test_sources.items():
        if not isinstance(path_text, str) or not path_text:
            err(f"test_sources.{source_id} must be a non-empty string")
            continue
        test_source_text[source_id] = source_text(path_text, f"test source {source_id}")

    refs: list[str] = []
    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing_item_bindings entries must be objects")
            continue
        binding_id = str(binding.get("id", "?"))
        commands = string_list(binding.get("required_commands"), f"{binding_id}.required_commands")
        for command in commands:
            if "cargo " in command:
                require(command.startswith("rch exec -- "), f"cargo validation command must use rch: {command}")

        test_refs = binding.get("required_test_refs")
        if not isinstance(test_refs, list) or not test_refs:
            err(f"{binding_id}.required_test_refs must be a non-empty array")
            test_refs = []
        for index, test_ref in enumerate(test_refs):
            if not isinstance(test_ref, dict):
                err(f"{binding_id}.required_test_refs[{index}] must be an object")
                continue
            source_id = test_ref.get("source")
            name = test_ref.get("name")
            if not isinstance(source_id, str) or not isinstance(name, str):
                err(f"{binding_id}.required_test_refs[{index}] must include source and name")
                continue
            source = test_source_text.get(source_id)
            if source is None:
                err(f"{binding_id} references unknown test source {source_id}")
            else:
                require(rust_test_exists(source, name), f"{binding_id} references missing test {source_id}::{name}")
            refs.append(f"{source_id}::{name}")

        if binding_id == "tests.unit.primary":
            require(any("math_retirement_test" in command for command in commands), "unit binding must run math_retirement_test")
            require(any("math_retirement_completion_contract_test" in command for command in commands), "unit binding must run completion contract test")
        if binding_id == "tests.e2e.primary":
            require(any("check_math_retirement.sh" in command for command in commands), "e2e binding must run check_math_retirement.sh")
            require(
                any("check_math_retirement_completion_contract.sh" in command for command in commands),
                "e2e binding must run completion checker",
            )
        if binding_id == "migrations.primary":
            require(any("migration_waves_cover_all_rc1" in ref for ref in refs), "migration binding must cite migration wave test")
            require(
                any("checker_rejects_migration_summary_drift" in ref for ref in refs),
                "migration binding must cite completion mutation test",
            )
        if binding_id == "telemetry.primary":
            require(
                any("checker_emits_jsonl_rows_with_required_fields" in ref for ref in refs),
                "telemetry binding must cite JSONL field test",
            )
            require(
                any("checker_rejects_bare_cargo_required_command" in ref for ref in refs),
                "telemetry binding must cite rch command guard",
            )

    return {
        "binding_count": len(bindings),
        "binding_ids": sorted(str(item) for item in ids),
        "test_refs": sorted(refs),
    }


def make_event(
    name: str,
    status: str,
    outcome: str,
    source_commit: str,
    artifact_refs: list[str],
    test_refs: list[str],
    **extra: Any,
) -> dict[str, Any]:
    row = {
        "timestamp": now_utc(),
        "event": name,
        "bead_id": COMPLETION_BEAD,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": outcome,
        "source_commit": source_commit,
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "artifact_refs": artifact_refs,
        "test_refs": test_refs,
        "failure_signature": "none" if status == "pass" else "math_retirement_completion_contract_failed",
    }
    row.update(extra)
    return row


def validate_telemetry(manifest: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    telemetry = manifest.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        telemetry = {}
    required_events = string_list(telemetry.get("required_pass_events"), "telemetry.required_pass_events")
    emitted = {str(row.get("event")) for row in events}
    for event_name in required_events:
        require(event_name in emitted, f"required pass event missing: {event_name}")
    required_fields = string_list(telemetry.get("required_log_fields"), "telemetry.required_log_fields")
    for row in events:
        for field in required_fields:
            require(field in row, f"telemetry row {row.get('event')} missing {field}")
    report_fields = string_list(telemetry.get("required_report_fields"), "telemetry.required_report_fields")
    return {
        "required_pass_events": len(required_events),
        "required_log_fields": len(required_fields),
        "required_report_fields": len(report_fields),
        "failure_event": telemetry.get("failure_event"),
    }


manifest = load_json(CONTRACT, "completion contract")
source_commit = git_head()

require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

texts, loaded = load_sources(manifest)
artifact_refs = sorted(str(value) for value in manifest.get("source_artifacts", {}).values()) if isinstance(manifest.get("source_artifacts"), dict) else []
policy_summary = validate_policy(manifest, loaded, texts)
binding_summary = validate_bindings(manifest, texts)
test_refs = binding_summary.get("test_refs", []) if isinstance(binding_summary.get("test_refs"), list) else []

events = [
    make_event(
        "math_retirement_completion_summary",
        "pass",
        "policy_gate_migration_checked",
        source_commit,
        artifact_refs,
        test_refs,
        policy=policy_summary,
    ),
    make_event(
        "math_retirement_unit_binding",
        "pass",
        "unit_evidence_bound",
        source_commit,
        artifact_refs,
        test_refs,
        binding="tests.unit.primary",
    ),
    make_event(
        "math_retirement_e2e_binding",
        "pass",
        "e2e_gate_bound",
        source_commit,
        artifact_refs,
        test_refs,
        binding="tests.e2e.primary",
    ),
    make_event(
        "math_retirement_migration_binding",
        "pass",
        "research_only_migration_bound",
        source_commit,
        artifact_refs,
        test_refs,
        binding="migrations.primary",
        migration={
            "research_only_modules": policy_summary["research_only_modules"],
            "total_modules_to_migrate": policy_summary["total_modules_to_migrate"],
        },
    ),
    make_event(
        "math_retirement_telemetry_binding",
        "pass",
        "jsonl_telemetry_bound",
        source_commit,
        artifact_refs,
        test_refs,
        binding="telemetry.primary",
    ),
    make_event(
        "math_retirement_completion_contract_pass",
        "pass",
        "ready_for_closeout",
        source_commit,
        artifact_refs,
        test_refs,
    ),
]
telemetry_summary = validate_telemetry(manifest, events)

status = "fail" if errors else "pass"
if status == "fail":
    events_to_write = [
        make_event(
            "math_retirement_completion_contract_fail",
            "fail",
            "contract_rejected",
            source_commit,
            artifact_refs,
            test_refs,
            error_count=len(errors),
        )
    ]
else:
    events_to_write = events

summary = {
    "policy": policy_summary,
    "bindings": binding_summary,
    "telemetry": telemetry_summary,
}
report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": summary,
    "source_artifacts": manifest.get("source_artifacts", {}),
    "missing_item_bindings": manifest.get("missing_item_bindings", []),
    "events": events_to_write,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events_to_write), encoding="utf-8")

if errors:
    print(f"math_retirement_completion_contract: FAIL errors={len(errors)}")
    for message in errors:
        print(f"ERROR: {message}")
    raise SystemExit(1)

print(
    "math_retirement_completion_contract: PASS "
    f"production={policy_summary['production_modules']} "
    f"research_only={policy_summary['research_only_modules']} "
    f"rc1={policy_summary['rc1_candidates']} "
    f"migrate={policy_summary['total_modules_to_migrate']} "
    f"bindings={binding_summary['binding_count']}"
)
PY
