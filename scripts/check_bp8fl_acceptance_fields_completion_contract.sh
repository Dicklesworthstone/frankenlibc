#!/usr/bin/env bash
# Validate bd-bp8fl.2.5.1 acceptance-field completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${1:-${ROOT}/tests/conformance/bp8fl_acceptance_fields_completion_contract.v1.json}"
OUT_DIR="${2:-${ROOT}/target/conformance}"
REPORT_PATH="${OUT_DIR}/bp8fl_acceptance_fields_completion_contract.report.json"
LOG_PATH="${OUT_DIR}/bp8fl_acceptance_fields_completion_contract.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT_PATH}" "${REPORT_PATH}" "${LOG_PATH}" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT_PATH = pathlib.Path(sys.argv[2]).resolve()
REPORT_PATH = pathlib.Path(sys.argv[3]).resolve()
LOG_PATH = pathlib.Path(sys.argv[4]).resolve()

EXPECTED_SCHEMA = "bp8fl_acceptance_fields_completion_contract.v1"
EXPECTED_BEAD = "bd-bp8fl.2.5"
EXPECTED_COMPLETION_BEAD = "bd-bp8fl.2.5.1"
EXPECTED_MISSING_ITEMS = ["tests.unit.primary", "tests.e2e.primary"]
EXPECTED_SOURCE_KEYS = {
    "issues_jsonl",
    "parent_acceptance_replay_contract",
    "parent_acceptance_replay_checker",
    "parent_acceptance_replay_test",
    "reality_bridge_import_contract",
    "reality_bridge_import_generator",
    "reality_bridge_import_checker",
    "reality_bridge_import_test",
    "ambition_graph_lint_contract",
    "ambition_graph_lint_checker",
    "ambition_graph_lint_test",
    "completion_checker",
    "completion_test",
}
EXPECTED_HISTORICAL_PREFIX = "bd-bp8fl"
EXPECTED_HISTORICAL_CREATED_BEFORE = "2026-05-04T00:00:00"
EXPECTED_HISTORICAL_ROWS = 89
EXPECTED_UNIT_REFS = {
    ("parent_acceptance_replay_test", "artifact_defines_aixvz_completion_debt_contract"),
    ("parent_acceptance_replay_test", "fixture_replay_proves_missing_duplicate_and_weak_rows_fail_closed"),
    ("parent_acceptance_replay_test", "valid_parent_fixture_rows_pass_acceptance_replay"),
    ("parent_acceptance_replay_test", "checker_script_is_read_only_and_names_tool_probe_contract"),
    ("reality_bridge_import_test", "artifact_defines_import_mapping_contract"),
    ("reality_bridge_import_test", "backlog_and_feature_gap_rows_are_preserved_without_rejections"),
    ("reality_bridge_import_test", "fixture_replay_emits_report_logs_and_negative_cases"),
    ("ambition_graph_lint_test", "artifact_defines_graph_readiness_contract"),
    ("ambition_graph_lint_test", "fixture_replay_emits_actionable_findings"),
}
EXPECTED_E2E_COMMANDS = {
    "bash scripts/check_bp8fl_acceptance_fields_completion_contract.sh",
    "bash scripts/check_bp8fl_parent_acceptance_replay.sh --validate-current",
    "bash scripts/check_reality_bridge_import_reconciliation.sh --validate-only",
    "bash scripts/check_ambition_graph_readiness_lint.sh --fixture-replay",
    "br dep cycles --no-db --json",
    "bv --robot-triage",
    "rch exec -- env CARGO_TARGET_DIR=<target> cargo check -p frankenlibc-harness --test bp8fl_acceptance_fields_completion_contract_test",
    "rch exec -- env CARGO_TARGET_DIR=<target> cargo clippy -p frankenlibc-harness --test bp8fl_acceptance_fields_completion_contract_test -- -D warnings",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


SOURCE_COMMIT = source_commit()


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        err(f"{label} JSON load failed: {exc}")
        return {}


def read_text(path: pathlib.Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} read failed: {exc}")
        return ""


def load_jsonl(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if isinstance(row, dict):
                row["_line_number"] = line_number
                rows.append(row)
            else:
                err(f"{label} line {line_number} is not an object")
    except Exception as exc:
        err(f"{label} JSONL load failed: {exc}")
    return rows


def sha256_file(path: pathlib.Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_event(event: str, outcome: str, expected: Any, actual: Any, failure_signature: str = "ok") -> None:
    events.append(
        {
            "schema_version": "bp8fl_acceptance_fields_completion_contract.log.v1",
            "trace_id": f"{EXPECTED_COMPLETION_BEAD}::{event}",
            "bead_id": EXPECTED_COMPLETION_BEAD,
            "source_bead": EXPECTED_BEAD,
            "event": event,
            "outcome": outcome,
            "expected": expected,
            "actual": actual,
            "artifact_refs": [rel(CONTRACT_PATH), rel(REPORT_PATH)],
            "source_commit": SOURCE_COMMIT,
            "failure_signature": failure_signature,
        }
    )


def artifact_path(value: Any, context: str) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty string path")
        return None
    candidate = pathlib.Path(value)
    path = candidate if candidate.is_absolute() else ROOT / candidate
    path = path.resolve()
    if ROOT not in path.parents and path != ROOT:
        err(f"{context} escapes workspace: {value}")
        return None
    if not path.is_file():
        err(f"{context} missing file: {value}")
        return None
    return path


def string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        err(f"{context} must be a list of strings")
        return []
    return list(value)


def phrase_group_matches(text: str, group: list[str]) -> bool:
    lower = text.lower()
    return all(str(phrase).lower() in lower for phrase in group)


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, pathlib.Path]:
    source_artifacts = manifest.get("source_artifacts")
    if not isinstance(source_artifacts, dict):
        err("source_artifacts must be an object")
        return {}
    missing = EXPECTED_SOURCE_KEYS - set(source_artifacts)
    extra = set(source_artifacts) - EXPECTED_SOURCE_KEYS
    require(not missing, f"source_artifacts missing keys: {sorted(missing)}")
    require(not extra, f"source_artifacts unexpected keys: {sorted(extra)}")

    paths: dict[str, pathlib.Path] = {}
    for key in sorted(EXPECTED_SOURCE_KEYS):
        path = artifact_path(source_artifacts.get(key), f"source_artifacts.{key}")
        if path is not None:
            paths[key] = path
    append_event(
        "source_artifacts",
        "fail" if missing or extra or len(paths) != len(EXPECTED_SOURCE_KEYS) else "pass",
        sorted(EXPECTED_SOURCE_KEYS),
        sorted(paths),
        "source_artifacts_invalid" if missing or extra else "ok",
    )
    return paths


def validate_manifest_shape(manifest: dict[str, Any]) -> None:
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
    require(manifest.get("bead") == EXPECTED_BEAD, "bead mismatch")
    require(manifest.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_debt_bead mismatch")

    completion_debt = manifest.get("completion_debt", {})
    if not isinstance(completion_debt, dict):
        err("completion_debt must be an object")
        completion_debt = {}
    require(completion_debt.get("original_bead") == EXPECTED_BEAD, "completion_debt.original_bead mismatch")
    require(
        string_list(completion_debt.get("missing_items_closed"), "completion_debt.missing_items_closed")
        == EXPECTED_MISSING_ITEMS,
        "completion_debt.missing_items_closed must close tests.unit.primary and tests.e2e.primary",
    )
    require(
        isinstance(completion_debt.get("original_close_reason"), str)
        and "verified all 89 bd-bp8fl rows now have acceptance criteria" in completion_debt["original_close_reason"],
        "completion_debt.original_close_reason must preserve the 89-row acceptance proof",
    )

    historical = manifest.get("historical_scope", {})
    if not isinstance(historical, dict):
        err("historical_scope must be an object")
        historical = {}
    require(historical.get("id_prefix") == EXPECTED_HISTORICAL_PREFIX, "historical_scope.id_prefix mismatch")
    require(
        historical.get("created_before") == EXPECTED_HISTORICAL_CREATED_BEFORE,
        "historical_scope.created_before mismatch",
    )
    require(historical.get("expected_rows") == EXPECTED_HISTORICAL_ROWS, "historical_scope.expected_rows mismatch")
    require(historical.get("expected_missing_acceptance") == 0, "historical_scope.expected_missing_acceptance mismatch")


def validate_rch_commands(commands: list[str], section_name: str) -> None:
    for command in commands:
        if "cargo " in command:
            require(command.startswith("rch exec --"), f"non-rch cargo validation command in {section_name}: {command}")


def validate_evidence_sections(manifest: dict[str, Any], paths: dict[str, pathlib.Path]) -> tuple[list[dict[str, Any]], list[str]]:
    evidence = manifest.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        return [], []

    unit = evidence.get("unit_primary", {})
    e2e = evidence.get("e2e_primary", {})
    if not isinstance(unit, dict):
        err("completion_debt_evidence.unit_primary must be an object")
        unit = {}
    if not isinstance(e2e, dict):
        err("completion_debt_evidence.e2e_primary must be an object")
        e2e = {}

    refs = unit.get("required_test_refs")
    if not isinstance(refs, list):
        err("unit_primary.required_test_refs must be a list")
        refs = []
    got_refs = {
        (ref.get("artifact"), ref.get("name"))
        for ref in refs
        if isinstance(ref, dict) and isinstance(ref.get("artifact"), str) and isinstance(ref.get("name"), str)
    }
    require(got_refs == EXPECTED_UNIT_REFS, f"unit_primary test refs mismatch: got {sorted(got_refs)}")
    for artifact, test_name in sorted(got_refs):
        path = paths.get(artifact)
        if path is None:
            continue
        text = read_text(path, artifact)
        require(test_name in text, f"{artifact} missing test ref {test_name}")

    unit_commands = string_list(unit.get("required_commands"), "unit_primary.required_commands")
    e2e_commands = string_list(e2e.get("required_commands"), "e2e_primary.required_commands")
    validate_rch_commands(unit_commands, "unit_primary")
    validate_rch_commands(e2e_commands, "e2e_primary")
    require(set(e2e_commands) == EXPECTED_E2E_COMMANDS, f"e2e_primary required_commands mismatch: got {sorted(e2e_commands)}")

    append_event(
        "unit_and_e2e_bindings",
        "pass" if got_refs == EXPECTED_UNIT_REFS and set(e2e_commands) == EXPECTED_E2E_COMMANDS else "fail",
        {"unit_refs": len(EXPECTED_UNIT_REFS), "e2e_commands": len(EXPECTED_E2E_COMMANDS)},
        {"unit_refs": len(got_refs), "e2e_commands": len(e2e_commands)},
        "evidence_binding_mismatch" if got_refs != EXPECTED_UNIT_REFS else "ok",
    )
    return list(refs), e2e_commands


def validate_historical_scope(manifest: dict[str, Any], issues_path: pathlib.Path) -> dict[str, Any]:
    historical = manifest.get("historical_scope", {})
    prefix = historical.get("id_prefix", EXPECTED_HISTORICAL_PREFIX)
    cutoff = historical.get("created_before", EXPECTED_HISTORICAL_CREATED_BEFORE)
    expected_rows = historical.get("expected_rows", EXPECTED_HISTORICAL_ROWS)
    expected_missing = historical.get("expected_missing_acceptance", 0)

    rows = load_jsonl(issues_path, "issues_jsonl")
    current_rows = [row for row in rows if str(row.get("id", "")).startswith(prefix)]
    historical_rows = [
        row
        for row in current_rows
        if isinstance(row.get("created_at"), str) and row["created_at"] < cutoff
    ]
    historical_missing = sorted(
        str(row.get("id"))
        for row in historical_rows
        if not str(row.get("acceptance_criteria", "")).strip()
    )
    current_missing = sorted(
        str(row.get("id"))
        for row in current_rows
        if not str(row.get("acceptance_criteria", "")).strip()
    )

    if len(historical_rows) != expected_rows:
        err(f"historical row count mismatch: expected {expected_rows}, got {len(historical_rows)}")
    if len(historical_missing) != expected_missing:
        err(f"historical missing acceptance mismatch: expected {expected_missing}, got {historical_missing}")

    aggregate_text = "\n".join(str(row.get("acceptance_criteria", "")) for row in historical_rows)
    terms = manifest.get("acceptance_field_contract", {}).get("required_aggregate_terms", [])
    missing_terms: list[str] = []
    if not isinstance(terms, list):
        err("acceptance_field_contract.required_aggregate_terms must be a list")
        terms = []
    for term in terms:
        if not isinstance(term, dict):
            err("acceptance_field_contract.required_aggregate_terms entries must be objects")
            continue
        term_id = term.get("term_id", "<unknown>")
        any_of = term.get("any_of", [])
        if not isinstance(any_of, list) or not any(
            isinstance(group, list) and phrase_group_matches(aggregate_text, group) for group in any_of
        ):
            missing_terms.append(str(term_id))
    if missing_terms:
        err(f"historical acceptance aggregate missing terms: {missing_terms}")

    append_event(
        "historical_acceptance_scope",
        "pass" if len(historical_rows) == expected_rows and not historical_missing and not missing_terms else "fail",
        {"rows": expected_rows, "missing_acceptance": expected_missing, "aggregate_terms_present": True},
        {
            "rows": len(historical_rows),
            "missing_acceptance_ids": historical_missing,
            "missing_terms": missing_terms,
            "current_missing_acceptance_ids": current_missing,
        },
        "historical_acceptance_scope_failed" if historical_missing or missing_terms else "ok",
    )
    return {
        "historical_row_count": len(historical_rows),
        "historical_missing_acceptance_ids": historical_missing,
        "current_row_count": len(current_rows),
        "current_missing_acceptance_ids": current_missing,
        "aggregate_missing_terms": missing_terms,
    }


def validate_source_contracts(paths: dict[str, pathlib.Path]) -> None:
    parent_contract = load_json(paths["parent_acceptance_replay_contract"], "parent_acceptance_replay_contract")
    require(parent_contract.get("bead") == "bd-aixvz.1", "parent acceptance replay bead mismatch")
    require(
        len(parent_contract.get("target_parent_ids", [])) == 11,
        "parent acceptance replay target_parent_ids must contain 11 parents",
    )
    parent_terms = {term.get("term_id") for term in parent_contract.get("required_acceptance_terms", []) if isinstance(term, dict)}
    for term_id in {
        "parent_specific_header",
        "required_unit_tests",
        "deterministic_e2e",
        "structured_telemetry",
        "source_of_truth_freshness",
        "claim_gate_cases",
        "closure_commands",
        "no_feature_loss",
    }:
        require(term_id in parent_terms, f"parent acceptance replay missing term {term_id}")

    parent_checker = read_text(paths["parent_acceptance_replay_checker"], "parent_acceptance_replay_checker")
    for needle in ["br show", "br dep cycles", "FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_PROBE_TOOLS"]:
        require(needle in parent_checker, f"parent acceptance replay checker missing {needle}")

    reality_contract = load_json(paths["reality_bridge_import_contract"], "reality_bridge_import_contract")
    require(
        reality_contract.get("summary", {}).get("missing_acceptance_target_count") == 0,
        "reality bridge import summary missing_acceptance_target_count must be 0",
    )
    require(
        "missing_acceptance" in reality_contract.get("negative_fixture_cases", []),
        "reality bridge import negative_fixture_cases must include missing_acceptance",
    )
    reality_checker = read_text(paths["reality_bridge_import_checker"], "reality_bridge_import_checker")
    for needle in ["missing_acceptance", "has_acceptance", "negative_case_results"]:
        require(needle in reality_checker, f"reality bridge import checker missing {needle}")

    ambition_checker = read_text(paths["ambition_graph_lint_checker"], "ambition_graph_lint_checker")
    for needle in ["acceptance_contract", "missing_structured_log_obligation", "missing_artifact_obligation"]:
        require(needle in ambition_checker, f"ambition graph lint checker missing {needle}")
    ambition_contract = load_json(paths["ambition_graph_lint_contract"], "ambition_graph_lint_contract")
    rules = {rule.get("rule_id") for rule in ambition_contract.get("rule_catalog", []) if isinstance(rule, dict)}
    require("acceptance_contract" in rules, "ambition graph lint contract missing acceptance_contract rule")

    append_event(
        "source_contracts",
        "pass" if not errors else "fail",
        "parent replay, reality bridge, and ambition lint artifacts expose acceptance fail-closed coverage",
        {
            "parent_terms": sorted(parent_terms),
            "reality_missing_acceptance_count": reality_contract.get("summary", {}).get("missing_acceptance_target_count"),
            "ambition_rules": sorted(rules),
        },
        "source_contracts_failed" if errors else "ok",
    )


manifest = load_json(CONTRACT_PATH, "completion_contract")
if not isinstance(manifest, dict):
    err("completion contract root must be an object")
    manifest = {}

validate_manifest_shape(manifest)
paths = validate_source_artifacts(manifest)
unit_bindings, e2e_commands = validate_evidence_sections(manifest, paths)
scope_report = (
    validate_historical_scope(manifest, paths["issues_jsonl"])
    if "issues_jsonl" in paths
    else {
        "historical_row_count": 0,
        "historical_missing_acceptance_ids": [],
        "current_row_count": 0,
        "current_missing_acceptance_ids": [],
        "aggregate_missing_terms": [],
    }
)
if EXPECTED_SOURCE_KEYS <= set(paths):
    validate_source_contracts(paths)

source_artifacts_report = {
    key: {
        "path": rel(path),
        "sha256": sha256_file(path),
    }
    for key, path in sorted(paths.items())
}

status = "fail" if errors else "pass"
report = {
    "schema_version": "bp8fl_acceptance_fields_completion_contract.report.v1",
    "status": status,
    "bead": EXPECTED_COMPLETION_BEAD,
    "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
    "source_bead": EXPECTED_BEAD,
    "source_commit": SOURCE_COMMIT,
    "historical_row_count": scope_report["historical_row_count"],
    "historical_missing_acceptance_ids": scope_report["historical_missing_acceptance_ids"],
    "current_row_count": scope_report["current_row_count"],
    "current_missing_acceptance_ids": scope_report["current_missing_acceptance_ids"],
    "aggregate_missing_terms": scope_report["aggregate_missing_terms"],
    "unit_bindings": unit_bindings,
    "e2e_commands": e2e_commands,
    "source_artifacts": source_artifacts_report,
    "errors": errors,
}

REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG_PATH.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

if status != "pass":
    print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
    sys.exit(1)

print(json.dumps(report, indent=2, sort_keys=True))
PY
