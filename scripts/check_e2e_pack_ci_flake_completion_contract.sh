#!/usr/bin/env bash
# e2e_pack_ci_flake_completion_contract - bd-b5a.3.1 static completion gate.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_PATH="${E2E_PACK_CI_FLAKE_COMPLETION_CONTRACT:-${ROOT_DIR}/tests/conformance/e2e_pack_ci_flake_completion_contract.v1.json}"
REPORT_PATH="${E2E_PACK_CI_FLAKE_COMPLETION_REPORT:-${ROOT_DIR}/target/conformance/e2e_pack_ci_flake_completion_contract.report.json}"
LOG_PATH="${E2E_PACK_CI_FLAKE_COMPLETION_LOG:-${ROOT_DIR}/target/conformance/e2e_pack_ci_flake_completion_contract.log.jsonl}"

mkdir -p "$(dirname -- "${REPORT_PATH}")" "$(dirname -- "${LOG_PATH}")"

python3 - "${ROOT_DIR}" "${CONTRACT_PATH}" "${REPORT_PATH}" "${LOG_PATH}" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(sys.argv[1])
CONTRACT = Path(sys.argv[2])
REPORT = Path(sys.argv[3])
LOG = Path(sys.argv[4])
START_NS = time.monotonic_ns()

EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_PACKS = {"smoke", "stress", "fault", "stability"}
EXPECTED_ARTIFACTS = {
    "trace.jsonl",
    "artifact_index.json",
    "mode_pair_report.json",
    "scenario_pack_report.json",
    "flake_quarantine_report.json",
}
EXPECTED_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "mode",
    "scenario_id",
    "scenario_pack",
    "retry_count",
    "flake_score",
    "artifact_refs",
    "verdict",
    "replay_key",
    "env_fingerprint",
    "latency_ns",
}
EXPECTED_REPORT_FIELDS = {
    "timestamp",
    "trace_id",
    "span_id",
    "level",
    "event",
    "bead_id",
    "completion_debt_bead",
    "mode",
    "runtime_mode",
    "scenario_pack",
    "retry_count",
    "flake_score",
    "artifact_refs",
    "verdict",
    "latency_ns",
    "source_commit",
    "failure_signature",
}
EXPECTED_REPORT_EVENTS = {
    "e2e_pack_ci_flake_completion_contract_validated",
    "e2e_pack_ci_flake_completion_contract_failed",
}
EXPECTED_UNIT_TESTS = {
    "test_all_pass_not_flaky",
    "test_fail_then_pass_is_flaky",
    "test_quarantined_flake_when_threshold_breached",
    "test_consistent_failure_is_not_flaky",
    "test_retry_on_nonzero_enabled",
    "test_retry_on_nonzero_disabled_respects_allowlist",
    "test_retry_stops_at_max",
    "test_classify_json_output",
    "test_should_retry_cli",
}
EXPECTED_E2E_TESTS = {
    "e2e_suite_runs_and_produces_jsonl",
    "e2e_suite_supports_manifest_dry_run",
    "e2e_artifact_index_valid",
    "e2e_mode_pair_report_valid",
    "e2e_quarantine_and_pack_reports_valid",
    "check_e2e_suite_emits_completion_debt_report_and_log",
    "completion_debt_checker_rejects_stale_test_binding",
}


def source_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "--short=12", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def rel_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def list_values(value) -> list:
    return value if isinstance(value, list) else []


def string_set(value) -> set[str]:
    return {item for item in list_values(value) if isinstance(item, str)}


def read_text(rel: str, errors: list[str]) -> str:
    path = ROOT / rel
    if not path.exists():
        errors.append(f"missing path: {rel}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        errors.append(f"{rel} is not UTF-8: {exc}")
        return ""


def validate_file_ref(ref, errors: list[str]) -> None:
    if not isinstance(ref, dict):
        errors.append(f"implementation ref is not an object: {ref!r}")
        return
    path = ref.get("path")
    line = ref.get("line")
    anchor = ref.get("anchor")
    if not isinstance(path, str):
        errors.append(f"implementation ref missing path: {ref!r}")
        return
    text = read_text(path, errors)
    if not text:
        return
    lines = text.splitlines()
    require(isinstance(line, int), f"{path} ref line is not an integer", errors)
    if isinstance(line, int):
        require(1 <= line <= len(lines), f"{path}:{line} outside 1..{len(lines)}", errors)
    require(isinstance(anchor, str) and bool(anchor), f"{path} ref missing anchor", errors)
    if isinstance(anchor, str) and anchor:
        require(anchor in text, f"{path} missing anchor {anchor!r}", errors)


def validate_source_anchors(manifest: dict, errors: list[str]) -> dict[str, str]:
    source_paths = manifest.get("source_paths", {})
    anchors_by_source = manifest.get("source_anchors", {})
    require(isinstance(source_paths, dict), "source_paths must be an object", errors)
    require(isinstance(anchors_by_source, dict), "source_anchors must be an object", errors)
    texts: dict[str, str] = {}
    if not isinstance(source_paths, dict) or not isinstance(anchors_by_source, dict):
        return texts
    for source, anchors in anchors_by_source.items():
        rel = source_paths.get(source)
        require(isinstance(rel, str), f"source path missing for {source}", errors)
        if not isinstance(rel, str):
            continue
        text = texts.setdefault(rel, read_text(rel, errors))
        for anchor in list_values(anchors):
            require(isinstance(anchor, str), f"non-string anchor in {source}", errors)
            if isinstance(anchor, str):
                require(anchor in text, f"{rel} missing source anchor {anchor!r}", errors)
    return texts


def test_name_exists(source_text: str, name: str) -> bool:
    return f"fn {name}(" in source_text or f"def {name}(" in source_text


def validate_test_refs(manifest: dict, coverage: list[dict], errors: list[str]) -> tuple[int, set[str], set[str]]:
    source_paths = manifest.get("source_paths", {})
    texts: dict[str, str] = {}
    count = 0
    unit_tests: set[str] = set()
    e2e_tests: set[str] = set()
    for section in coverage:
        item_id = section.get("missing_item_id")
        for ref in list_values(section.get("test_refs")):
            name = ref.get("name") if isinstance(ref, dict) else None
            source = ref.get("source") if isinstance(ref, dict) else None
            require(isinstance(name, str), f"test ref missing name: {ref!r}", errors)
            require(isinstance(source, str), f"test ref missing source: {ref!r}", errors)
            if not isinstance(name, str) or not isinstance(source, str):
                continue
            rel = source_paths.get(source) if isinstance(source_paths, dict) else None
            require(isinstance(rel, str), f"test ref {name} has unknown source {source}", errors)
            if not isinstance(rel, str):
                continue
            text = texts.setdefault(rel, read_text(rel, errors))
            require(test_name_exists(text, name), f"{rel} missing test function {name}", errors)
            if item_id == "tests.unit.primary":
                unit_tests.add(name)
            if item_id == "tests.e2e.primary":
                e2e_tests.add(name)
            count += 1
    require(
        EXPECTED_UNIT_TESTS <= unit_tests,
        f"unit coverage missing flake-policy tests {sorted(EXPECTED_UNIT_TESTS - unit_tests)}",
        errors,
    )
    require(
        EXPECTED_E2E_TESTS <= e2e_tests,
        f"e2e coverage missing suite tests {sorted(EXPECTED_E2E_TESTS - e2e_tests)}",
        errors,
    )
    return count, unit_tests, e2e_tests


def validate_file_line_strings(refs, errors: list[str], label: str) -> int:
    count = 0
    for ref in list_values(refs):
        if not isinstance(ref, str) or ":" not in ref:
            errors.append(f"{label} ref is not file:line: {ref!r}")
            continue
        rel, line_text = ref.rsplit(":", 1)
        text = read_text(rel, errors)
        if not text:
            continue
        try:
            line_no = int(line_text)
        except ValueError:
            errors.append(f"{label} ref line is not numeric: {ref}")
            continue
        require(1 <= line_no <= len(text.splitlines()), f"{label} ref outside file: {ref}", errors)
        count += 1
    return count


def validate_commands(commands, errors: list[str], section: str) -> int:
    count = 0
    for command in list_values(commands):
        require(isinstance(command, str), f"{section} validation command is not a string", errors)
        if not isinstance(command, str):
            continue
        stripped = command.strip()
        require(stripped, f"{section} validation command is empty", errors)
        if "cargo " in stripped:
            require(
                stripped.startswith("rch ") or " rch " in stripped or "rch exec" in stripped or "rch cargo" in stripped,
                f"{section} cargo validation command must use rch: {stripped}",
                errors,
            )
        count += 1
    return count


def validate_manifest_catalog(errors: list[str]) -> int:
    manifest_path = ROOT / "tests/conformance/e2e_scenario_manifest.v1.json"
    manifest = load_json(manifest_path)
    scenarios = manifest.get("scenarios", [])
    require(isinstance(scenarios, list) and bool(scenarios), "scenario manifest must have scenarios", errors)
    packs = {scenario.get("class") for scenario in scenarios if isinstance(scenario, dict)}
    require(EXPECTED_PACKS <= packs, f"scenario manifest missing packs {sorted(EXPECTED_PACKS - packs)}", errors)
    return len(scenarios) if isinstance(scenarios, list) else 0


def run_flake_policy_unit_tests(errors: list[str]) -> dict:
    cmd = ["python3", "-m", "unittest", "tests/conformance/test_e2e_flake_policy.py", "-q"]
    proc = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        errors.append(
            "flake policy unit tests failed: "
            + (proc.stdout + proc.stderr).strip().replace("\n", " | ")[:800]
        )
    return {
        "command": " ".join(cmd),
        "exit_code": proc.returncode,
        "stdout": proc.stdout[-1000:],
        "stderr": proc.stderr[-1000:],
    }


def validate_contract(manifest: dict, errors: list[str]) -> dict:
    require(
        manifest.get("schema_version") == "e2e_pack_ci_flake_completion_contract.v1",
        "unexpected schema_version",
        errors,
    )
    require(manifest.get("bead") == "bd-b5a.3", "unexpected bead id", errors)
    require(manifest.get("completion_debt_bead") == "bd-b5a.3.1", "unexpected completion debt bead id", errors)
    threshold = manifest.get("next_audit_score_threshold")
    require(isinstance(threshold, int) and threshold >= 800, "next audit threshold must be >= 800", errors)

    for ref in list_values(manifest.get("implementation_refs")):
        validate_file_ref(ref, errors)
    validate_source_anchors(manifest, errors)

    gate = manifest.get("gate_contract", {})
    require(isinstance(gate, dict), "gate_contract must be an object", errors)
    packs = string_set(gate.get("required_scenario_packs")) if isinstance(gate, dict) else set()
    artifacts = string_set(gate.get("required_artifacts")) if isinstance(gate, dict) else set()
    fields = string_set(gate.get("required_log_fields")) if isinstance(gate, dict) else set()
    events = string_set(gate.get("required_events")) if isinstance(gate, dict) else set()
    require(EXPECTED_PACKS <= packs, f"gate contract missing packs {sorted(EXPECTED_PACKS - packs)}", errors)
    require(EXPECTED_ARTIFACTS <= artifacts, f"gate contract missing artifacts {sorted(EXPECTED_ARTIFACTS - artifacts)}", errors)
    require(EXPECTED_LOG_FIELDS <= fields, f"gate contract missing log fields {sorted(EXPECTED_LOG_FIELDS - fields)}", errors)
    require("case_retry" in events, "gate contract must require case_retry event", errors)
    require("scenario_pack_gate_fail" in events, "gate contract must require scenario_pack_gate_fail event", errors)

    ci_gate = gate.get("ci_gate", {}) if isinstance(gate, dict) else {}
    ci_scripts = string_set(ci_gate.get("required_scripts")) if isinstance(ci_gate, dict) else set()
    require("scripts/check_e2e_suite.sh" in ci_scripts, "ci gate must require scripts/check_e2e_suite.sh", errors)
    require(ci_gate.get("gating_mode") == "extended", "ci gate should be documented as extended", errors)

    quarantine = gate.get("quarantine_policy", {}) if isinstance(gate, dict) else {}
    require(
        quarantine.get("threshold_env") == "FRANKENLIBC_E2E_FLAKE_QUARANTINE_THRESHOLD",
        "quarantine threshold env drifted",
        errors,
    )
    remediation = list_values(quarantine.get("remediation_required")) if isinstance(quarantine, dict) else []
    require(len(remediation) >= 4, "quarantine remediation workflow must be non-trivial", errors)

    coverage = list_values(manifest.get("completion_coverage"))
    coverage_by_id = {
        item.get("missing_item_id"): item
        for item in coverage
        if isinstance(item, dict) and isinstance(item.get("missing_item_id"), str)
    }
    missing_ids = EXPECTED_MISSING_ITEMS - set(coverage_by_id.keys())
    extra_ids = set(coverage_by_id.keys()) - EXPECTED_MISSING_ITEMS
    require(not missing_ids, f"completion coverage missing ids {sorted(missing_ids)}", errors)
    require(not extra_ids, f"completion coverage has unexpected ids {sorted(extra_ids)}", errors)

    impl_ref_count = 0
    command_count = 0
    required_artifact_count = 0
    for item_id, section in coverage_by_id.items():
        require(section.get("status") == "covered", f"{item_id} status is not covered", errors)
        impl_ref_count += validate_file_line_strings(section.get("implementation_refs"), errors, item_id)
        command_count += validate_commands(section.get("validation_commands"), errors, item_id)
        required_artifact_count += len(list_values(section.get("required_artifacts")))

    test_ref_count, unit_tests, e2e_tests = validate_test_refs(manifest, coverage, errors)
    scenario_count = validate_manifest_catalog(errors)
    unit_result = run_flake_policy_unit_tests(errors)

    reporting = manifest.get("reporting", {})
    reporting_fields = string_set(reporting.get("required_fields")) if isinstance(reporting, dict) else set()
    reporting_events = string_set(reporting.get("events")) if isinstance(reporting, dict) else set()
    require(
        EXPECTED_REPORT_FIELDS <= reporting_fields,
        f"reporting required fields missing {sorted(EXPECTED_REPORT_FIELDS - reporting_fields)}",
        errors,
    )
    require(
        EXPECTED_REPORT_EVENTS <= reporting_events,
        f"reporting events missing {sorted(EXPECTED_REPORT_EVENTS - reporting_events)}",
        errors,
    )

    return {
        "missing_items_covered": len(set(coverage_by_id.keys()) & EXPECTED_MISSING_ITEMS),
        "implementation_ref_count": impl_ref_count,
        "test_ref_count": test_ref_count,
        "validation_command_count": command_count,
        "required_artifact_count": required_artifact_count,
        "scenario_count": scenario_count,
        "scenario_packs": sorted(packs),
        "unit_tests": sorted(unit_tests),
        "e2e_tests": sorted(e2e_tests),
        "required_artifacts": sorted(artifacts),
        "required_log_fields": sorted(fields),
        "flake_policy_unit_result": unit_result,
    }


def write_outputs(manifest: dict | None, errors: list[str], metrics: dict) -> None:
    elapsed_ns = max(1, time.monotonic_ns() - START_NS)
    ok = not errors
    commit = source_commit()
    bead = manifest.get("bead") if isinstance(manifest, dict) else "bd-b5a.3"
    completion_bead = manifest.get("completion_debt_bead") if isinstance(manifest, dict) else "bd-b5a.3.1"
    failure_signature = "none" if ok else "e2e_pack_ci_flake_contract_invalid"
    artifact_refs = [
        rel_path(CONTRACT),
        rel_path(REPORT),
        rel_path(LOG),
        "scripts/e2e_suite.sh",
        "scripts/check_e2e_suite.sh",
        "scripts/e2e_flake_policy.py",
        "tests/conformance/test_e2e_flake_policy.py",
        "crates/frankenlibc-harness/tests/e2e_suite_test.rs",
    ]
    report = {
        "schema_version": "e2e_pack_ci_flake_completion_contract.report.v1",
        "status": "pass" if ok else "fail",
        "bead": bead,
        "completion_debt_bead": completion_bead,
        "source_commit": commit,
        "contract_path": rel_path(CONTRACT),
        "report_path": rel_path(REPORT),
        "log_path": rel_path(LOG),
        "latency_ns": elapsed_ns,
        "failure_signature": failure_signature,
        "errors": errors,
        "summary": metrics,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    log_row = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "trace_id": f"{completion_bead}::e2e-pack-ci-flake-contract::001",
        "span_id": "e2e_pack_ci_flake::completion_contract",
        "level": "info" if ok else "error",
        "event": (
            "e2e_pack_ci_flake_completion_contract_validated"
            if ok
            else "e2e_pack_ci_flake_completion_contract_failed"
        ),
        "bead_id": bead,
        "completion_debt_bead": completion_bead,
        "stream": "conformance",
        "gate": "e2e_pack_ci_flake_completion_contract",
        "mode": "strict",
        "runtime_mode": "strict",
        "api_family": "harness",
        "symbol": "e2e_pack_ci_flake",
        "decision_path": "contract->scenario_manifest->flake_policy_unit_tests->ci_gate->e2e_artifacts",
        "healing_action": "None",
        "controller_id": "e2e_pack_ci_flake_completion_contract.v1",
        "decision_id": 5050031,
        "policy_id": 50503,
        "evidence_seqno": 1,
        "scenario_pack": "all",
        "retry_count": 0,
        "flake_score": 0.0,
        "verdict": "pass" if ok else "fail",
        "outcome": "pass" if ok else "fail",
        "errno": 0 if ok else 1,
        "latency_ns": elapsed_ns,
        "source_commit": commit,
        "target_dir": os.environ.get("CARGO_TARGET_DIR", "target"),
        "failure_signature": failure_signature,
        "artifact_refs": artifact_refs,
        "details": {
            "completion_debt_bead": completion_bead,
            "missing_items_covered": metrics.get("missing_items_covered", 0),
            "scenario_packs": metrics.get("scenario_packs", []),
            "test_ref_count": metrics.get("test_ref_count", 0),
            "required_artifacts": metrics.get("required_artifacts", []),
            "errors": errors,
        },
    }
    LOG.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")


errors: list[str] = []
metrics: dict = {}
manifest = None
try:
    manifest = load_json(CONTRACT)
    metrics = validate_contract(manifest, errors)
except Exception as exc:
    errors.append(f"checker exception: {type(exc).__name__}: {exc}")

write_outputs(manifest, errors, metrics)
if errors:
    for error in errors:
        print(f"e2e pack CI flake contract error: {error}", file=sys.stderr)
    sys.exit(1)

print(f"e2e pack CI flake completion contract passed: {REPORT}")
PY
