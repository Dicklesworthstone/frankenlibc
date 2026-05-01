#!/usr/bin/env bash
# check_user_workload_acceptance_matrix.sh -- CI gate for bd-bp8fl.10.1
#
# Validates that the user/persona workload acceptance matrix covers the required
# domains, failure taxonomy, runtime modes, replacement levels, diagnostics, and
# negative claim-block tests. Emits deterministic report/log artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${ROOT}/tests/conformance/user_workload_acceptance_matrix.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/user_workload_acceptance_matrix.report.json"
LOG="${OUT_DIR}/user_workload_acceptance_matrix.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

errors = []
checks = {}

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_WORKLOAD_FIELDS = [
    "id",
    "persona_id",
    "title",
    "primary_domain",
    "coverage_domains",
    "representative_commands",
    "replacement_levels",
    "runtime_modes",
    "oracle_kind",
    "subsystems",
    "required_unit_tests",
    "deterministic_e2e_scripts",
    "artifact_paths",
    "failure_scenarios",
    "structured_log_fields",
    "user_facing_diagnostics",
    "negative_claim_tests",
]
REQUIRED_LEVELS = {"L0", "L1", "L2", "L3"}
REQUIRED_MODES = {"strict", "hardened"}

def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return None

artifact = load_json(artifact_path)
checks["json_parse"] = "pass" if isinstance(artifact, dict) else "fail"

if not isinstance(artifact, dict):
    artifact = {}

if artifact.get("schema_version") == "v1" and artifact.get("bead") == "bd-bp8fl.10.1":
    checks["top_level_shape"] = "pass"
else:
    checks["top_level_shape"] = "fail"
    errors.append("artifact must declare schema_version=v1 and bead=bd-bp8fl.10.1")

required_log_fields = artifact.get("required_log_fields", [])
if required_log_fields == REQUIRED_LOG_FIELDS:
    checks["required_log_fields"] = "pass"
else:
    checks["required_log_fields"] = "fail"
    errors.append("required_log_fields must match the standard structured log contract")

personas = artifact.get("personas", [])
persona_ids = [p.get("id") for p in personas]
if personas and len(persona_ids) == len(set(persona_ids)) and all(p.get("success_condition") for p in personas):
    checks["personas"] = "pass"
else:
    checks["personas"] = "fail"
    errors.append("personas must be non-empty, unique, and include success_condition")
persona_set = set(persona_ids)

taxonomy = artifact.get("failure_taxonomy", [])
taxonomy_ids = [t.get("id") for t in taxonomy]
taxonomy_set = set(taxonomy_ids)
taxonomy_ok = bool(taxonomy) and len(taxonomy_ids) == len(taxonomy_set)
for item in taxonomy:
    if not item.get("oracle_kind") or not item.get("representative_signatures") or not item.get("diagnostic_expectations"):
        taxonomy_ok = False
        errors.append(f"{item.get('id', '<missing taxonomy id>')}: taxonomy entry lacks oracle/signature/diagnostic detail")
checks["failure_taxonomy"] = "pass" if taxonomy_ok else "fail"
if not taxonomy_ok:
    errors.append("failure taxonomy must be non-empty, unique, and diagnostic-rich")

required_domains = artifact.get("required_domains", [])
required_domain_set = set(required_domains)
workloads = artifact.get("workloads", [])
workload_ids = [w.get("id") for w in workloads]
coverage = Counter()
negative_claim_count = 0
rows_with_modes = 0
rows_with_levels = 0
workload_ok = bool(workloads) and len(workload_ids) == len(set(workload_ids))

for workload in workloads:
    wid = workload.get("id", "<missing workload id>")
    for field in REQUIRED_WORKLOAD_FIELDS:
        if field not in workload:
            workload_ok = False
            errors.append(f"{wid}: missing field {field}")

    if workload.get("persona_id") not in persona_set:
        workload_ok = False
        errors.append(f"{wid}: persona_id does not reference a persona")

    domains = workload.get("coverage_domains", [])
    if not domains or workload.get("primary_domain") not in domains:
        workload_ok = False
        errors.append(f"{wid}: coverage_domains must include primary_domain")
    for domain in domains:
        coverage[domain] += 1
        if domain not in required_domain_set:
            workload_ok = False
            errors.append(f"{wid}: unknown coverage domain {domain}")

    modes = set(workload.get("runtime_modes", []))
    if REQUIRED_MODES.issubset(modes):
        rows_with_modes += 1
    else:
        workload_ok = False
        errors.append(f"{wid}: runtime_modes must include strict and hardened")

    levels = set(workload.get("replacement_levels", []))
    if REQUIRED_LEVELS.issubset(levels):
        rows_with_levels += 1
    else:
        workload_ok = False
        errors.append(f"{wid}: replacement_levels must include L0, L1, L2, and L3")

    if workload.get("structured_log_fields") != "required_log_fields":
        workload_ok = False
        errors.append(f"{wid}: structured_log_fields must reference required_log_fields")

    for script in workload.get("deterministic_e2e_scripts", []):
        if not (root / script).exists():
            workload_ok = False
            errors.append(f"{wid}: deterministic script does not exist: {script}")

    if not workload.get("representative_commands"):
        workload_ok = False
        errors.append(f"{wid}: representative_commands must not be empty")
    if not workload.get("required_unit_tests"):
        workload_ok = False
        errors.append(f"{wid}: required_unit_tests must not be empty")
    if not workload.get("user_facing_diagnostics"):
        workload_ok = False
        errors.append(f"{wid}: user_facing_diagnostics must not be empty")

    failure_scenarios = workload.get("failure_scenarios", [])
    if not failure_scenarios:
        workload_ok = False
        errors.append(f"{wid}: failure_scenarios must not be empty")
    for scenario in failure_scenarios:
        tid = scenario.get("taxonomy_id")
        if tid not in taxonomy_set:
            workload_ok = False
            errors.append(f"{wid}: unknown taxonomy_id {tid}")
        if not scenario.get("expected_failure_signature") or not scenario.get("diagnostic_expectation"):
            workload_ok = False
            errors.append(f"{wid}: failure scenario lacks signature or diagnostic expectation")
        if not scenario.get("blocks_claim_levels"):
            workload_ok = False
            errors.append(f"{wid}: failure scenario must block at least one claim level")

    negative_claim_tests = workload.get("negative_claim_tests", [])
    if not negative_claim_tests:
        workload_ok = False
        errors.append(f"{wid}: negative_claim_tests must not be empty")
    for test in negative_claim_tests:
        negative_claim_count += 1
        if test.get("expected_result") != "claim_blocked":
            workload_ok = False
            errors.append(f"{wid}: negative claim test must expect claim_blocked")
        for field in ["unsupported_condition", "advertised_claim_blocked", "evidence_probe"]:
            if not test.get(field):
                workload_ok = False
                errors.append(f"{wid}: negative claim test missing {field}")

checks["workload_rows"] = "pass" if workload_ok else "fail"

missing_domains = sorted(required_domain_set - set(coverage))
if not missing_domains:
    checks["domain_coverage"] = "pass"
else:
    checks["domain_coverage"] = "fail"
    errors.append("missing required workload domains: " + ", ".join(missing_domains))

summary = artifact.get("summary", {})
summary_ok = (
    summary.get("persona_count") == len(personas)
    and summary.get("failure_taxonomy_count") == len(taxonomy)
    and summary.get("workload_count") == len(workloads)
    and summary.get("negative_claim_test_count") == negative_claim_count
    and summary.get("rows_with_strict_and_hardened") == rows_with_modes
    and summary.get("rows_with_l0_l1_l2_l3") == rows_with_levels
    and summary.get("required_domain_coverage") == dict(coverage)
)
checks["summary_counts"] = "pass" if summary_ok else "fail"
if not summary_ok:
    errors.append("summary counts do not match personas, taxonomy, workloads, modes, levels, negatives, and domain coverage")

claim_policy = artifact.get("replacement_level_policy", {})
claim_policy_ok = (
    claim_policy.get("must_not_overclaim") is True
    and claim_policy.get("missing_evidence_result") == "claim_blocked"
    and negative_claim_count >= len(workloads)
)
checks["negative_claim_policy"] = "pass" if claim_policy_ok else "fail"
if not claim_policy_ok:
    errors.append("claim policy must block missing evidence and every row must include a negative claim test")

try:
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except Exception:
    source_commit = "unknown"

status = "pass" if not errors else "fail"
artifact_refs = [
    "tests/conformance/user_workload_acceptance_matrix.v1.json",
    "target/conformance/user_workload_acceptance_matrix.report.json",
    "target/conformance/user_workload_acceptance_matrix.log.jsonl",
]
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.10.1",
    "status": status,
    "checks": checks,
    "persona_count": len(personas),
    "failure_taxonomy_count": len(taxonomy),
    "workload_count": len(workloads),
    "negative_claim_test_count": negative_claim_count,
    "rows_with_strict_and_hardened": rows_with_modes,
    "rows_with_l0_l1_l2_l3": rows_with_levels,
    "required_domain_coverage": dict(coverage),
    "missing_required_domains": missing_domains,
    "errors": errors,
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

event = {
    "trace_id": "bd-bp8fl.10.1-user-workload-acceptance",
    "bead_id": "bd-bp8fl.10.1",
    "scenario_id": "user-workload-matrix-gate",
    "runtime_mode": "strict+hardened_required",
    "replacement_level": "L0,L1,L2,L3",
    "api_family": "user_workload_acceptance",
    "symbol": "*",
    "oracle_kind": "persona_workload_claim_gate",
    "expected": "all required domains covered and unsupported claims blocked",
    "actual": status,
    "errno": None,
    "decision_path": list(checks.keys()),
    "healing_action": "none",
    "latency_ns": 0,
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
    "target_dir": str(root / "target/conformance"),
    "failure_signature": "; ".join(errors),
    "workload_count": len(workloads),
    "negative_claim_test_count": negative_claim_count,
}
log_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
