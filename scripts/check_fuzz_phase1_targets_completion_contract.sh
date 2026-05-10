#!/usr/bin/env bash
# check_fuzz_phase1_targets_completion_contract.sh -- fail-closed gate for bd-1oz.6.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_FUZZ_PHASE1_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/fuzz_phase1_targets_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_FUZZ_PHASE1_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_FUZZ_PHASE1_COMPLETION_REPORT:-${OUT_DIR}/fuzz_phase1_targets_completion_contract.report.json}"
LOG="${FRANKENLIBC_FUZZ_PHASE1_COMPLETION_LOG:-${OUT_DIR}/fuzz_phase1_targets_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${OUT_DIR}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])

BEAD_ID = "bd-1oz.6"
COMPLETION_BEAD_ID = "bd-1oz.6.1"
MANIFEST_ID = "fuzz-phase1-targets-completion-contract"
REQUIRED_TARGETS = {"fuzz_string", "fuzz_malloc", "fuzz_membrane", "fuzz_printf"}
REQUIRED_EVENTS = {
    "fuzz_phase1_component",
    "fuzz_phase1_target",
    "fuzz_phase1_e2e",
    "fuzz_phase1_summary",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str], context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{context} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{context} must be a JSON object")
        return {}
    return value


def read_text(path_text: str, errors: list[str], context: str) -> str:
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} missing file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{context} unreadable: {path_text}: {exc}")
        return ""


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def validate_line_ref(ref: Any, errors: list[str], context: str) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"{context} must be a file:line string")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{context} has invalid line number: {ref}")
        return
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        errors.append(f"{context} references line past EOF: {ref}")
    elif not lines[line_number - 1].strip():
        errors.append(f"{context} references blank line: {ref}")


def require_strings(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    strings = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{index}] must be a non-empty string")
        else:
            strings.append(item)
    return strings


def ensure_subset(required: list[str], actual: Any, errors: list[str], context: str) -> None:
    if not isinstance(actual, list):
        errors.append(f"{context} must compare against an array")
        return
    actual_set = {item for item in actual if isinstance(item, str)}
    missing = [item for item in required if item not in actual_set]
    if missing:
        errors.append(f"{context} missing {missing}")


def dotted_get(value: dict[str, Any], dotted_key: str) -> Any:
    current: Any = value
    for part in dotted_key.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def validate_command_policy(contract: dict[str, Any], errors: list[str]) -> None:
    runtime = contract.get("runtime_target")
    if not isinstance(runtime, dict):
        errors.append("runtime_target must be an object")
        return
    allowed = require_strings(
        runtime.get("allowed_command_prefixes"),
        errors,
        "runtime_target.allowed_command_prefixes",
    )
    forbidden = require_strings(
        runtime.get("forbidden_command_substrings"),
        errors,
        "runtime_target.forbidden_command_substrings",
    )
    command_fields: list[tuple[str, str]] = []
    e2e = contract.get("e2e_primary")
    if isinstance(e2e, dict):
        for scenario in e2e.get("scenarios", []):
            if isinstance(scenario, dict) and isinstance(scenario.get("command"), str):
                command_fields.append((str(scenario.get("scenario_id", "unknown")), scenario["command"]))
    for context, command in command_fields:
        if not any(command.startswith(prefix) for prefix in allowed):
            errors.append(f"{context} command is not allowlisted: {command}")
        for needle in forbidden:
            if needle in command:
                errors.append(f"{context} command contains forbidden substring {needle!r}")


def validate_source_artifacts(
    contract: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    artifacts = contract.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("source_artifacts must be a non-empty array")
        return
    seen = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("source_artifacts entries must be objects")
            continue
        artifact_id = artifact.get("artifact_id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            errors.append("source artifact missing artifact_id")
            continue
        if artifact_id in seen:
            errors.append(f"duplicate source artifact {artifact_id}")
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{artifact_id}.path missing")
            continue
        text = read_text(path_text, errors, artifact_id)
        for needle in require_strings(
            artifact.get("required_needles"),
            errors,
            f"{artifact_id}.required_needles",
        ):
            if needle not in text:
                errors.append(f"{artifact_id} missing needle {needle!r}")
        for ref in artifact.get("required_line_refs", []):
            validate_line_ref(ref, errors, f"{artifact_id}.required_line_refs")
        rows.append({
            "event": "fuzz_phase1_component",
            "status": "pass" if text else "fail",
            "component_id": artifact_id,
            "path": path_text,
            "timestamp": utc_now(),
        })
    required_ids = {
        "phase1_generator",
        "phase1_shell_gate",
        "persisted_phase1_report",
        "source_harness_tests",
    }
    if seen != required_ids:
        errors.append(f"source_artifacts must be exactly {sorted(required_ids)}, got {sorted(seen)}")


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    events = evidence.get("required_events")
    if not isinstance(events, list) or set(events) != REQUIRED_EVENTS:
        errors.append("completion_debt_evidence.required_events drifted")


def validate_unit_e2e_and_fuzz_sections(contract: dict[str, Any], errors: list[str]) -> None:
    unit = contract.get("unit_primary")
    if not isinstance(unit, dict) or unit.get("missing_item_id") != "tests.unit.primary":
        errors.append("unit_primary must bind tests.unit.primary")
        test_source = ""
    else:
        test_source_path = unit.get("test_source")
        test_source = read_text(test_source_path, errors, "unit_primary.test_source") if isinstance(test_source_path, str) else ""
        for test_name in require_strings(unit.get("required_test_names"), errors, "unit_primary.required_test_names"):
            if f"fn {test_name}(" not in test_source:
                errors.append(f"unit_primary references missing Rust test {test_name}")
        existing_source = read_text(
            "crates/frankenlibc-harness/tests/fuzz_phase1_targets_test.rs",
            errors,
            "existing phase1 source test",
        )
        for existing in unit.get("existing_unit_tests", []):
            if not isinstance(existing, dict):
                errors.append("unit_primary.existing_unit_tests entries must be objects")
                continue
            name = existing.get("name")
            if not isinstance(name, str):
                errors.append("unit_primary.existing_unit_tests.name missing")
                continue
            if name not in existing_source:
                errors.append(f"unit_primary existing test missing {name}")
            if "line_ref" in existing:
                validate_line_ref(existing["line_ref"], errors, f"unit_primary.{name}.line_ref")

    e2e = contract.get("e2e_primary")
    if not isinstance(e2e, dict) or e2e.get("missing_item_id") != "tests.e2e.primary":
        errors.append("e2e_primary must bind tests.e2e.primary")
    else:
        scenarios = e2e.get("scenarios")
        if not isinstance(scenarios, list) or len(scenarios) < 3:
            errors.append("e2e_primary.scenarios must include at least three scenarios")
        else:
            scenario_ids = {item.get("scenario_id") for item in scenarios if isinstance(item, dict)}
            required = {
                "generate_isolated_phase1_report",
                "validate_crash_triage_contract",
                "completion_checker_runs_fail_closed",
            }
            if scenario_ids != required:
                errors.append(
                    f"e2e_primary.scenarios must be exactly {sorted(required)}, "
                    f"got {sorted(str(item) for item in scenario_ids)}"
                )

    fuzz = contract.get("fuzz_primary")
    if not isinstance(fuzz, dict) or fuzz.get("missing_item_id") != "tests.fuzz.primary":
        errors.append("fuzz_primary must bind tests.fuzz.primary")
        return
    required_targets = set(require_strings(fuzz.get("required_targets"), errors, "fuzz_primary.required_targets"))
    if required_targets != REQUIRED_TARGETS:
        errors.append(f"fuzz_primary.required_targets must be exactly {sorted(REQUIRED_TARGETS)}")
    smoke_targets = set(
        require_strings(
            fuzz.get("required_smoke_config_targets"),
            errors,
            "fuzz_primary.required_smoke_config_targets",
        )
    )
    if smoke_targets != REQUIRED_TARGETS:
        errors.append("fuzz_primary.required_smoke_config_targets drifted")
    for source in require_strings(
        fuzz.get("required_target_sources"),
        errors,
        "fuzz_primary.required_target_sources",
    ):
        if not (root / source).is_file():
            errors.append(f"fuzz_primary.required_target_sources missing file: {source}")
    if "fn checker_rejects_stale_fuzz_target_contract(" not in test_source:
        errors.append("fuzz_primary references missing stale fuzz target contract test")


def run_generator(
    contract: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    report_contract = contract.get("report_contract")
    if not isinstance(report_contract, dict):
        errors.append("report_contract must be an object")
        return {}
    generator = report_contract.get("generator")
    if not isinstance(generator, str) or not generator:
        errors.append("report_contract.generator missing")
        return {}
    generated_report = out_dir / "generated_fuzz_phase1_targets.v1.json"
    result = subprocess.run(
        ["python3", str(root / generator), "-o", str(generated_report)],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=int(contract.get("runtime_target", {}).get("max_seconds", 45)),
    )
    rows.append({
        "event": "fuzz_phase1_e2e",
        "scenario_id": "generate_isolated_phase1_report",
        "status": "pass" if result.returncode == 0 else "fail",
        "exit_code": result.returncode,
        "artifact": rel(generated_report),
        "timestamp": utc_now(),
    })
    if result.returncode != 0:
        errors.append(f"generator failed: stdout={result.stdout} stderr={result.stderr}")
        return {}
    generated = load_json(generated_report, errors, "generated fuzz phase1 report")
    persisted_path = root / str(report_contract.get("report_path", ""))
    persisted = load_json(persisted_path, errors, "persisted fuzz phase1 report")
    for context, report in [("generated", generated), ("persisted", persisted)]:
        if report.get("schema_version") != "v1":
            errors.append(f"{context} report schema_version must be v1")
        if report.get("bead") != BEAD_ID:
            errors.append(f"{context} report bead must be {BEAD_ID}")
        validate_report_summary(report_contract, report, errors, context)
        validate_target_contracts(contract, report, errors, rows, context)
        validate_crash_triage(contract, report, errors, rows, context)
    return generated


def validate_report_summary(
    report_contract: dict[str, Any],
    report: dict[str, Any],
    errors: list[str],
    context: str,
) -> None:
    summary = report.get("summary")
    if not isinstance(summary, dict):
        errors.append(f"{context} report.summary must be an object")
        return
    expected = report_contract.get("expected_summary")
    if not isinstance(expected, dict):
        errors.append("report_contract.expected_summary must be an object")
        expected = {}
    for key, expected_value in expected.items():
        actual_value = summary.get(key)
        if key == "average_readiness_score" and isinstance(actual_value, (int, float)):
            if actual_value < expected_value:
                errors.append(f"{context} summary.{key} expected >= {expected_value!r}, got {actual_value!r}")
        elif actual_value != expected_value:
            errors.append(f"{context} summary.{key} expected {expected_value!r}, got {summary.get(key)!r}")

    target_names = {
        item.get("target")
        for item in report.get("target_assessments", [])
        if isinstance(item, dict)
    }
    required_targets = set(require_strings(report_contract.get("required_targets"), errors, "report_contract.required_targets"))
    if target_names != required_targets:
        errors.append(f"{context} target_assessments must be exactly {sorted(required_targets)}, got {sorted(str(item) for item in target_names)}")

    families = set(report.get("coverage_summary", {}).get("symbols_by_family", {}).keys())
    required_families = set(require_strings(report_contract.get("required_families"), errors, "report_contract.required_families"))
    if families != required_families:
        errors.append(f"{context} coverage families drifted")

    ensure_subset(
        require_strings(report_contract.get("required_cwe_targets"), errors, "report_contract.required_cwe_targets"),
        report.get("coverage_summary", {}).get("all_cwes"),
        errors,
        f"{context} coverage_summary.all_cwes",
    )


def validate_target_contracts(
    contract: dict[str, Any],
    report: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
    context: str,
) -> None:
    target_contracts = contract.get("target_contracts")
    if not isinstance(target_contracts, list):
        errors.append("target_contracts must be an array")
        return
    contract_targets = {
        item.get("target")
        for item in target_contracts
        if isinstance(item, dict) and isinstance(item.get("target"), str)
    }
    if contract_targets != REQUIRED_TARGETS:
        errors.append(f"target_contracts must bind exactly {sorted(REQUIRED_TARGETS)}, got {sorted(contract_targets)}")

    assessments = {
        item.get("target"): item
        for item in report.get("target_assessments", [])
        if isinstance(item, dict) and isinstance(item.get("target"), str)
    }
    smoke_configs = report.get("smoke_test_configs", {})
    if not isinstance(smoke_configs, dict):
        errors.append(f"{context} smoke_test_configs must be an object")
        smoke_configs = {}
    for target_contract in target_contracts:
        if not isinstance(target_contract, dict):
            errors.append("target_contracts entries must be objects")
            continue
        target = target_contract.get("target")
        if not isinstance(target, str) or not target:
            errors.append("target_contract missing target")
            continue
        assessment = assessments.get(target)
        if not isinstance(assessment, dict):
            errors.append(f"{context} missing target assessment {target}")
            continue
        source = target_contract.get("target_source")
        if not isinstance(source, str) or not (root / source).is_file():
            errors.append(f"{target}.target_source missing file")
        if assessment.get("family") != target_contract.get("family"):
            errors.append(f"{context} {target} family drifted")
        if assessment.get("implementation_status") != target_contract.get("required_status"):
            errors.append(f"{context} {target} implementation_status drifted")
        if assessment.get("smoke_viable") is not target_contract.get("required_smoke_viable"):
            errors.append(f"{context} {target} smoke_viable drifted")
        min_score = target_contract.get("min_readiness_score")
        if isinstance(min_score, int) and assessment.get("readiness_score", 0) < min_score:
            errors.append(f"{context} {target} readiness_score below {min_score}")
        ensure_subset(
            require_strings(target_contract.get("required_cwe_targets"), errors, f"{target}.required_cwe_targets"),
            assessment.get("cwe_targets"),
            errors,
            f"{context} {target} cwe_targets",
        )
        ensure_subset(
            require_strings(target_contract.get("required_symbols"), errors, f"{target}.required_symbols"),
            assessment.get("symbol_coverage", {}).get("target_symbols"),
            errors,
            f"{context} {target} target_symbols",
        )
        smoke = smoke_configs.get(target)
        if not isinstance(smoke, dict):
            errors.append(f"{context} {target} missing smoke_test_config")
        elif smoke.get("expected_outcome") != "no_crash":
            errors.append(f"{context} {target} smoke expected_outcome drifted")
        rows.append({
            "event": "fuzz_phase1_target",
            "status": "pass",
            "context": context,
            "target": target,
            "family": assessment.get("family"),
            "readiness_score": assessment.get("readiness_score"),
            "smoke_viable": assessment.get("smoke_viable"),
            "timestamp": utc_now(),
        })


def validate_crash_triage(
    contract: dict[str, Any],
    report: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
    context: str,
) -> None:
    triage_contract = contract.get("crash_triage_contract")
    triage = report.get("crash_triage_policy")
    if not isinstance(triage_contract, dict) or not isinstance(triage, dict):
        errors.append(f"{context} crash_triage_contract/report missing")
        return
    severity = dotted_get(triage, "classification.severity_levels")
    if not isinstance(severity, dict):
        errors.append(f"{context} crash triage severity_levels missing")
        return
    min_classes = triage_contract.get("min_severity_classes")
    if isinstance(min_classes, int) and len(severity) < min_classes:
        errors.append(f"{context} crash severity classes below {min_classes}")
    for key in require_strings(
        triage_contract.get("required_severity_keys"),
        errors,
        "crash_triage_contract.required_severity_keys",
    ):
        if key not in severity:
            errors.append(f"{context} crash severity missing {key}")
    dedup = triage.get("dedup")
    if not isinstance(dedup, dict):
        errors.append(f"{context} crash dedup missing")
        return
    if dedup.get("method") != triage_contract.get("dedup_method"):
        errors.append(f"{context} crash dedup method drifted")
    frame_depth_min = triage_contract.get("frame_depth_min")
    if isinstance(frame_depth_min, int) and dedup.get("frame_depth", 0) < frame_depth_min:
        errors.append(f"{context} crash dedup frame_depth below {frame_depth_min}")
    flow = triage.get("triage_flow")
    if not isinstance(flow, list):
        errors.append(f"{context} crash triage_flow missing")
        return
    actions = [item.get("action") for item in flow if isinstance(item, dict)]
    if actions != require_strings(
        triage_contract.get("required_flow_actions"),
        errors,
        "crash_triage_contract.required_flow_actions",
    ):
        errors.append(f"{context} crash triage actions drifted")
    rows.append({
        "event": "fuzz_phase1_e2e",
        "scenario_id": "validate_crash_triage_contract",
        "status": "pass",
        "context": context,
        "severity_classes": len(severity),
        "dedup_method": dedup.get("method"),
        "timestamp": utc_now(),
    })


def validate_contract(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> dict[str, Any]:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")
    validate_command_policy(contract, errors)
    validate_source_artifacts(contract, errors, rows)
    validate_completion_evidence(contract, errors)
    validate_unit_e2e_and_fuzz_sections(contract, errors)
    generated = run_generator(contract, errors, rows)
    rows.append({
        "event": "fuzz_phase1_e2e",
        "scenario_id": "completion_checker_runs_fail_closed",
        "status": "pass",
        "exit_code": 0,
        "artifact": rel(contract_path),
        "timestamp": utc_now(),
    })
    return generated


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, errors, "completion contract")
generated = validate_contract(contract, errors, rows) if contract else {}
summary = generated.get("summary", {}) if isinstance(generated, dict) else {}

status = "pass" if not errors else "fail"
rows.append({
    "event": "fuzz_phase1_summary",
    "status": status,
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "total_targets": summary.get("total_targets"),
    "functional_targets": summary.get("functional_targets"),
    "smoke_viable_targets": summary.get("smoke_viable_targets"),
    "triage_steps": summary.get("triage_steps"),
    "error_count": len(errors),
    "timestamp": utc_now(),
})
report = {
    "schema_version": "v1",
    "status": status,
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "contract": rel(contract_path),
    "generated_report": rel(out_dir / "generated_fuzz_phase1_targets.v1.json"),
    "log": rel(log_path),
    "target_count": len(contract.get("target_contracts", [])) if isinstance(contract, dict) else 0,
    "e2e_scenario_count": len(contract.get("e2e_primary", {}).get("scenarios", [])) if isinstance(contract, dict) else 0,
    "summary": summary,
    "errors": errors,
}
write_json(report_path, report)
write_jsonl(log_path, rows)

if errors:
    print("fuzz_phase1_targets_completion_contract: FAIL", file=sys.stderr)
    for error in errors:
        print(f" - {error}", file=sys.stderr)
    sys.exit(1)

print(
    "fuzz_phase1_targets_completion_contract: PASS "
    f"targets={report['target_count']} e2e={report['e2e_scenario_count']} "
    f"functional={summary.get('functional_targets')} smoke={summary.get('smoke_viable_targets')} "
    f"triage={summary.get('triage_steps')} crash_triage_contract=pass"
)
PY
