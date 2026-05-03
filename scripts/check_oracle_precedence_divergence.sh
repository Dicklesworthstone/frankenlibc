#!/usr/bin/env bash
# check_oracle_precedence_divergence.sh -- CI gate for bd-bp8fl.1.6
#
# Validates the oracle-precedence/divergence-classification artifact and emits
# deterministic JSON/JSONL evidence under target/conformance.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FLC_ORACLE_PRECEDENCE_ARTIFACT:-${ROOT}/tests/conformance/oracle_precedence_divergence.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/oracle_precedence_divergence.report.json"
LOG="${OUT_DIR}/oracle_precedence_divergence.log.jsonl"

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

required_log_fields = [
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
    "status",
    "oracle_precedence_path",
    "decision_path",
    "healing_action",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
required_oracles = {
    "environment_probe",
    "frankenlibc_contract",
    "hardened_safety_policy",
    "host_glibc",
    "linux_syscall",
    "posix_text",
}
required_classes = {
    "allowed_divergence",
    "flaky_environment",
    "parity_match",
    "proof_gap",
    "safety_repair",
    "unsupported_contract",
}
required_observable_fields = {"errno", "status", "stdout", "stderr"}
required_replay_kinds = {
    "allowed_divergence",
    "blocked_divergence",
    "stale_oracle",
    "hardened_vs_strict_mode",
}

errors = []
checks = {}

def rel(path):
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)

def load_json(path, label):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        errors.append(f"{label}: failed to parse {path}: {exc}")
        return None

artifact = load_json(artifact_path, "artifact")
if artifact is not None:
    checks["json_parse"] = "pass"
else:
    checks["json_parse"] = "fail"
    artifact = {}

if artifact.get("schema_version") == "v1" and artifact.get("bead") == "bd-bp8fl.1.6":
    checks["artifact_shape"] = "pass"
else:
    checks["artifact_shape"] = "fail"
    errors.append("artifact must declare schema_version=v1 and bead=bd-bp8fl.1.6")

if artifact.get("required_log_fields") == required_log_fields:
    checks["required_log_fields"] = "pass"
else:
    checks["required_log_fields"] = "fail"
    errors.append("required_log_fields must match the universal structured log contract")

observable_fields = set(artifact.get("observable_fields", []))
if observable_fields == required_observable_fields:
    checks["observable_field_coverage"] = "pass"
else:
    checks["observable_field_coverage"] = "fail"
    errors.append(
        f"observable_fields must cover {sorted(required_observable_fields)}, got {sorted(observable_fields)}"
    )

inputs = artifact.get("inputs", {})
loaded_inputs = {}
if isinstance(inputs, dict) and inputs:
    for key, rel_path in inputs.items():
        path = root / str(rel_path)
        if path.exists():
            loaded_inputs[key] = load_json(path, key)
        else:
            errors.append(f"input artifact missing: {rel_path}")
    checks["input_artifacts_exist"] = "pass" if len(loaded_inputs) == len(inputs) else "fail"
else:
    checks["input_artifacts_exist"] = "fail"
    errors.append("inputs must be a non-empty object of artifact references")

oracles = artifact.get("oracle_kinds", [])
oracle_ids = [row.get("id") for row in oracles if isinstance(row, dict)]
oracle_ranks = [row.get("precedence_rank") for row in oracles if isinstance(row, dict)]
oracle_rank_by_id = {
    row.get("id"): row.get("precedence_rank")
    for row in oracles
    if isinstance(row, dict)
}
if set(oracle_ids) == required_oracles and len(oracle_ids) == len(set(oracle_ids)):
    checks["oracle_kind_coverage"] = "pass"
else:
    checks["oracle_kind_coverage"] = "fail"
    errors.append(
        f"oracle_kinds must cover exactly {sorted(required_oracles)}, got {sorted(set(oracle_ids))}"
    )
if len(oracle_ranks) == len(set(oracle_ranks)) and all(isinstance(rank, int) for rank in oracle_ranks):
    checks["oracle_precedence_unique"] = "pass"
else:
    checks["oracle_precedence_unique"] = "fail"
    errors.append("oracle precedence ranks must be unique integers")

classes = artifact.get("divergence_classifications", [])
class_ids = [row.get("id") for row in classes if isinstance(row, dict)]
if set(class_ids) == required_classes and len(class_ids) == len(set(class_ids)):
    checks["divergence_class_coverage"] = "pass"
else:
    checks["divergence_class_coverage"] = "fail"
    errors.append(
        f"divergence_classifications must cover exactly {sorted(required_classes)}, got {sorted(set(class_ids))}"
    )
for row in classes:
    class_id = row.get("id", "<missing>")
    if not row.get("claim_effect"):
        errors.append(f"{class_id}: claim_effect is required")
    if not row.get("required_evidence"):
        errors.append(f"{class_id}: required_evidence is required")

rules = artifact.get("decision_rules", [])
if rules and all(row.get("primary_oracle") in required_oracles for row in rules):
    checks["decision_rules_use_known_oracles"] = "pass"
else:
    checks["decision_rules_use_known_oracles"] = "fail"
    errors.append("decision_rules must be non-empty and use known primary_oracle values")
for row in rules:
    rule_id = row.get("id", "<missing>")
    for klass in row.get("allowed_divergence_classes", []):
        if klass not in required_classes:
            errors.append(f"{rule_id}: unknown allowed_divergence_class {klass}")
    for oracle in row.get("fallback_oracles", []):
        if oracle not in required_oracles:
            errors.append(f"{rule_id}: unknown fallback_oracle {oracle}")

semantic_join = loaded_inputs.get("semantic_contract_symbol_join") or {}
semantic_classes = {
    row.get("semantic_class")
    for row in semantic_join.get("entries", [])
    if isinstance(row, dict) and row.get("semantic_class")
}
mappings = artifact.get("semantic_class_mappings", [])
mapped_classes = {row.get("semantic_class") for row in mappings if isinstance(row, dict)}
if semantic_classes and mapped_classes == semantic_classes:
    checks["semantic_class_mapping_coverage"] = "pass"
else:
    checks["semantic_class_mapping_coverage"] = "fail"
    errors.append(
        f"semantic_class_mappings must cover semantic join classes {sorted(semantic_classes)}, got {sorted(mapped_classes)}"
    )
for row in mappings:
    row_id = row.get("semantic_class", "<missing>")
    if row.get("divergence_class") not in required_classes:
        errors.append(f"{row_id}: unknown mapped divergence_class")
    if row.get("primary_oracle") not in required_oracles:
        errors.append(f"{row_id}: unknown mapped primary_oracle")
    claim_effect = str(row.get("claim_effect", ""))
    if "block" not in claim_effect:
        errors.append(f"{row_id}: semantic mapping must block overbroad claims")

scenarios = artifact.get("scenarios", [])
scenario_ids = {
    scenario.get("scenario_id")
    for scenario in scenarios
    if isinstance(scenario, dict) and scenario.get("scenario_id")
}
by_divergence = Counter()
by_primary = Counter()
negative_claim_tests = 0
scenario_errors_before = len(errors)
for scenario in scenarios:
    scenario_id = scenario.get("scenario_id", "<missing>")
    primary = scenario.get("primary_oracle")
    divergence = scenario.get("divergence_class")
    by_primary[primary] += 1
    by_divergence[divergence] += 1

    if primary not in required_oracles:
        errors.append(f"{scenario_id}: unknown primary_oracle {primary}")
    for oracle in scenario.get("fallback_oracles", []):
        if oracle not in required_oracles:
            errors.append(f"{scenario_id}: unknown fallback_oracle {oracle}")
    expected_path = [primary] + list(scenario.get("fallback_oracles", []))
    if scenario.get("oracle_precedence_path") != expected_path:
        errors.append(
            f"{scenario_id}: oracle_precedence_path must equal primary_oracle followed by fallback_oracles"
        )
    if divergence not in required_classes:
        errors.append(f"{scenario_id}: unknown divergence_class {divergence}")

    modes = set(scenario.get("runtime_modes", []))
    if not {"strict", "hardened"}.issubset(modes):
        errors.append(f"{scenario_id}: runtime_modes must include strict and hardened")
    levels = set(scenario.get("replacement_levels", []))
    if not {"L0", "L1"}.issubset(levels):
        errors.append(f"{scenario_id}: replacement_levels must include L0 and L1")
    if not scenario.get("symbols"):
        errors.append(f"{scenario_id}: symbols must not be empty")
    if not scenario.get("expected_claim_effect"):
        errors.append(f"{scenario_id}: expected_claim_effect must not be empty")

    for rel_path in scenario.get("artifact_refs", []):
        path = root / str(rel_path)
        if not path.exists():
            errors.append(f"{scenario_id}: missing artifact_ref {rel_path}")
    for negative in scenario.get("negative_claim_tests", []):
        if negative.get("expected_result") != "claim_blocked":
            errors.append(f"{scenario_id}: negative claim tests must expect claim_blocked")
        if not negative.get("failure_signature"):
            errors.append(f"{scenario_id}: negative claim test missing failure_signature")
        negative_claim_tests += 1

if set(by_divergence) == required_classes and all(by_divergence[klass] >= 1 for klass in required_classes):
    checks["scenario_divergence_coverage"] = "pass"
else:
    checks["scenario_divergence_coverage"] = "fail"
    errors.append(f"scenarios must cover divergence classes {sorted(required_classes)}")
if set(by_primary) == required_oracles and all(by_primary[oracle] >= 1 for oracle in required_oracles):
    checks["scenario_oracle_coverage"] = "pass"
else:
    checks["scenario_oracle_coverage"] = "fail"
    errors.append(f"scenarios must cover primary oracle kinds {sorted(required_oracles)}")
if len(errors) == scenario_errors_before:
    checks["scenario_schema_and_artifacts"] = "pass"
else:
    checks["scenario_schema_and_artifacts"] = "fail"

replay_cases = artifact.get("replay_cases", [])
replay_kinds = {
    row.get("replay_kind")
    for row in replay_cases
    if isinstance(row, dict) and row.get("replay_kind")
}
if replay_kinds == required_replay_kinds:
    checks["replay_case_coverage"] = "pass"
else:
    checks["replay_case_coverage"] = "fail"
    errors.append(
        f"replay_cases must cover {sorted(required_replay_kinds)}, got {sorted(replay_kinds)}"
    )
for replay in replay_cases:
    replay_id = replay.get("id", "<missing>")
    scenario_id = replay.get("scenario_id")
    if scenario_id not in scenario_ids:
        errors.append(f"{replay_id}: unknown replay scenario_id {scenario_id}")
    if replay.get("command") != "scripts/check_oracle_precedence_divergence.sh":
        errors.append(f"{replay_id}: replay command must be the deterministic gate script")
    if replay.get("expected_divergence_class") not in required_classes:
        errors.append(f"{replay_id}: unknown expected_divergence_class")
    if not replay.get("expected_result"):
        errors.append(f"{replay_id}: expected_result is required")

negative_precedence_tests = artifact.get("negative_precedence_tests", [])
negative_precedence_errors_before = len(errors)
for row in negative_precedence_tests:
    row_id = row.get("id", "<missing>")
    higher = row.get("higher_priority_oracle")
    lower = row.get("lower_priority_oracle")
    higher_rank = oracle_rank_by_id.get(higher)
    lower_rank = oracle_rank_by_id.get(lower)
    if higher not in required_oracles or lower not in required_oracles:
        errors.append(f"{row_id}: unknown precedence test oracle")
    elif not (isinstance(higher_rank, int) and isinstance(lower_rank, int) and higher_rank < lower_rank):
        errors.append(
            f"{row_id}: higher_priority_oracle must have a smaller precedence_rank than lower_priority_oracle"
        )
    if row.get("expected_result") != "claim_blocked":
        errors.append(f"{row_id}: negative precedence test must expect claim_blocked")
    if not row.get("failure_signature"):
        errors.append(f"{row_id}: negative precedence test missing failure_signature")
    if not row.get("conflict"):
        errors.append(f"{row_id}: negative precedence test missing conflict description")
if negative_precedence_tests and len(errors) == negative_precedence_errors_before:
    checks["negative_precedence_tests"] = "pass"
else:
    checks["negative_precedence_tests"] = "fail"
    if not negative_precedence_tests:
        errors.append("negative_precedence_tests must not be empty")

summary_actual = {
    "oracle_kind_count": len(oracles),
    "divergence_class_count": len(classes),
    "decision_rule_count": len(rules),
    "semantic_class_mapping_count": len(mappings),
    "scenario_count": len(scenarios),
    "replay_case_count": len(replay_cases),
    "negative_claim_test_count": negative_claim_tests,
    "negative_precedence_test_count": len(negative_precedence_tests),
    "by_divergence_class": dict(sorted(by_divergence.items())),
    "by_primary_oracle": dict(sorted(by_primary.items())),
    "semantic_classes_mapped": sorted(mapped_classes),
}
if artifact.get("summary") == summary_actual:
    checks["summary_matches_artifact"] = "pass"
else:
    checks["summary_matches_artifact"] = "fail"
    errors.append("summary does not match oracle/divergence/mapping/scenario contents")

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
artifact_refs = [rel(artifact_path)] + [str(path) for path in inputs.values()]
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.1.6",
    "status": status,
    "checks": checks,
    "summary": summary_actual,
    "errors": errors,
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
    "target_dir": rel(report_path.parent),
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log_event = {
    "trace_id": "bd-bp8fl.1.6-oracle-precedence-divergence",
    "bead_id": "bd-bp8fl.1.6",
    "scenario_id": "oracle-precedence-divergence-gate",
    "runtime_mode": "strict+hardened",
    "replacement_level": "L0_L1_claim_control",
    "api_family": "conformance_oracle_governance",
    "symbol": "*",
    "oracle_kind": "oracle_precedence_contract",
    "expected": "all oracle kinds, divergence classes, semantic mappings, scenarios, negative claim tests, and artifact refs are current",
    "actual": status,
    "errno": None,
    "status": status,
    "oracle_precedence_path": [
        "frankenlibc_contract",
        "hardened_safety_policy",
        "posix_text",
        "linux_syscall",
        "host_glibc",
        "environment_probe",
    ],
    "decision_path": list(checks.keys()),
    "healing_action": "none",
    "latency_ns": 0,
    "artifact_refs": artifact_refs + [rel(report_path), rel(log_path)],
    "source_commit": source_commit,
    "target_dir": rel(report_path.parent),
    "failure_signature": "; ".join(errors),
    "summary": summary_actual,
}
log_path.write_text(json.dumps(log_event, sort_keys=True) + "\n", encoding="utf-8")

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
