#!/usr/bin/env bash
# check_perf_regression_gate.sh — CI gate for bd-30o.3
#
# Validates that:
#   1. Perf regression attribution policy exists and is valid.
#   2. Threshold policy and benchmark attribution mapping are complete.
#   3. Logging contract and triage playbooks are complete.
#   4. Intentional regression E2E scenario fails perf_gate and emits attribution logs.
#   5. Summary counts are internally consistent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT}/tests/conformance/perf_regression_attribution.v1.json"
BASELINE="${ROOT}/scripts/perf_baseline.json"

failures=0

echo "=== Perf Regression Attribution Gate (bd-30o.3) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Policy exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Policy exists and is valid ---"

if [[ ! -f "${POLICY}" ]]; then
    echo "FAIL: tests/conformance/perf_regression_attribution.v1.json not found"
    echo ""
    echo "check_perf_regression_gate: FAILED"
    exit 1
fi

valid_check="$(python3 - "${POLICY}" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    v = doc.get("schema_version", 0)
    warning = doc.get("warning_policy", {})
    threshold = doc.get("threshold_policy", {})
    attribution = doc.get("attribution", {})
    logging = doc.get("logging_contract", {})
    if v < 1:
        print("INVALID: schema_version < 1")
    elif not warning:
        print("INVALID: missing warning_policy")
    elif not threshold:
        print("INVALID: missing threshold_policy")
    elif not attribution:
        print("INVALID: missing attribution")
    elif not logging:
        print("INVALID: missing logging_contract")
    else:
        print(f"VALID version={v} mapped={len(attribution.get('suspect_component_map', {}))}")
except Exception as exc:
    print(f"INVALID: {exc}")
PY
)"

if [[ "${valid_check}" == INVALID* ]]; then
    echo "FAIL: ${valid_check}"
    failures=$((failures + 1))
else
    echo "PASS: ${valid_check}"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: Threshold policy + benchmark mapping completeness
# ---------------------------------------------------------------------------
echo "--- Check 2: Threshold policy + benchmark mapping ---"

mapping_check="$(python3 - "${POLICY}" "${BASELINE}" <<'PY'
import json
import sys

policy_path, baseline_path = sys.argv[1:3]
with open(policy_path, encoding="utf-8") as f:
    policy = json.load(f)
with open(baseline_path, encoding="utf-8") as f:
    baseline = json.load(f)

errors = []
threshold = policy.get("threshold_policy", {})
warning = policy.get("warning_policy", {})
default_pct = threshold.get("default_max_regression_pct")
if not isinstance(default_pct, (int, float)) or default_pct <= 0:
    errors.append("default_max_regression_pct must be positive")

mode_thresholds = threshold.get("per_mode_max_regression_pct", {})
for mode in ("strict", "hardened"):
    pct = mode_thresholds.get(mode)
    if not isinstance(pct, (int, float)) or pct <= 0:
        errors.append(f"per_mode_max_regression_pct.{mode} must be positive")

default_warning = warning.get("default_warning_pct")
if not isinstance(default_warning, (int, float)) or default_warning <= 0:
    errors.append("default_warning_pct must be positive")

mode_warnings = warning.get("per_mode_warning_pct", {})
for mode in ("strict", "hardened"):
    pct = mode_warnings.get(mode)
    if not isinstance(pct, (int, float)) or pct <= 0:
        errors.append(f"per_mode_warning_pct.{mode} must be positive")
    max_pct = mode_thresholds.get(mode)
    if isinstance(max_pct, (int, float)) and isinstance(pct, (int, float)) and pct > max_pct:
        errors.append(
            f"per_mode_warning_pct.{mode} must be <= per_mode_max_regression_pct.{mode}"
        )

required_benchmark_ids = []
for suite, modes in baseline.get("baseline_p50_ns_op", {}).items():
    for mode, benches in modes.items():
        if not isinstance(benches, dict):
            continue
        for bench in benches:
            required_benchmark_ids.append(f"{suite}/{bench}")

suspects = policy.get("attribution", {}).get("suspect_component_map", {})
for benchmark_id in sorted(set(required_benchmark_ids)):
    if benchmark_id not in suspects:
        errors.append(f"suspect_component_map missing benchmark_id: {benchmark_id}")

overrides = threshold.get("per_benchmark_overrides", {})
for benchmark_id, by_mode in overrides.items():
    if benchmark_id not in required_benchmark_ids:
        errors.append(f"per_benchmark_overrides references unknown benchmark_id: {benchmark_id}")
    if not isinstance(by_mode, dict):
        errors.append(f"per_benchmark_overrides.{benchmark_id} must be object")
        continue
    for mode, pct in by_mode.items():
        if mode not in ("strict", "hardened"):
            errors.append(f"per_benchmark_overrides.{benchmark_id} has invalid mode: {mode}")
        if not isinstance(pct, (int, float)) or pct <= 0:
            errors.append(f"per_benchmark_overrides.{benchmark_id}.{mode} must be positive")

warning_overrides = warning.get("per_benchmark_overrides", {})
for benchmark_id, by_mode in warning_overrides.items():
    if benchmark_id not in required_benchmark_ids:
        errors.append(f"warning per_benchmark_overrides references unknown benchmark_id: {benchmark_id}")
    if not isinstance(by_mode, dict):
        errors.append(f"warning per_benchmark_overrides.{benchmark_id} must be object")
        continue
    for mode, pct in by_mode.items():
        if mode not in ("strict", "hardened"):
            errors.append(f"warning per_benchmark_overrides.{benchmark_id} has invalid mode: {mode}")
        if not isinstance(pct, (int, float)) or pct <= 0:
            errors.append(f"warning per_benchmark_overrides.{benchmark_id}.{mode} must be positive")
        max_pct = (
            threshold.get("per_benchmark_overrides", {})
            .get(benchmark_id, {})
            .get(mode, mode_thresholds.get(mode))
        )
        if isinstance(max_pct, (int, float)) and isinstance(pct, (int, float)) and pct > max_pct:
            errors.append(
                f"warning per_benchmark_overrides.{benchmark_id}.{mode} must be <= max threshold"
            )

print(f"MAPPING_ERRORS={len(errors)}")
print(f"REQUIRED_BENCHMARKS={len(set(required_benchmark_ids))}")
for err in errors:
    print(f"  {err}")
PY
)"

mapping_errs="$(echo "${mapping_check}" | grep '^MAPPING_ERRORS=' | cut -d= -f2)"
if [[ "${mapping_errs}" -gt 0 ]]; then
    echo "FAIL: ${mapping_errs} mapping error(s):"
    echo "${mapping_check}" | grep '^  '
    failures=$((failures + 1))
else
    mapped="$(echo "${mapping_check}" | grep '^REQUIRED_BENCHMARKS=' | cut -d= -f2)"
    echo "PASS: Threshold + suspect mapping covers ${mapped} benchmark IDs"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Logging + triage contracts
# ---------------------------------------------------------------------------
echo "--- Check 3: Logging and triage contracts ---"

contract_check="$(python3 - "${POLICY}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    policy = json.load(f)

errors = []
logging = policy.get("logging_contract", {})
required_fields = set(logging.get("required_fields", []))
for field in (
    "timestamp",
    "trace_id",
    "mode",
    "benchmark_id",
    "threshold",
    "observed",
    "regression_class",
    "suspect_component",
):
    if field not in required_fields:
        errors.append(f"logging_contract.required_fields missing: {field}")

classes = set(policy.get("attribution", {}).get("regression_classes", []))
for cls in ("ok", "baseline_warning", "baseline_regression", "target_budget_violation", "baseline_and_budget_violation"):
    if cls not in classes:
        errors.append(f"attribution.regression_classes missing: {cls}")

triage = policy.get("triage_guide", {})
for cls in ("baseline_warning", "baseline_regression", "target_budget_violation", "baseline_and_budget_violation"):
    guide = triage.get(cls)
    if not isinstance(guide, dict):
        errors.append(f"triage_guide missing class: {cls}")
        continue
    if not guide.get("actions"):
        errors.append(f"triage_guide.{cls} missing actions")
    if not guide.get("commands"):
        errors.append(f"triage_guide.{cls} missing commands")

scenario = policy.get("intentional_regression_scenario", {})
if scenario.get("script") != "scripts/e2e_perf_regression_scenario.sh":
    errors.append("intentional_regression_scenario.script must reference scripts/e2e_perf_regression_scenario.sh")

print(f"CONTRACT_ERRORS={len(errors)}")
for err in errors:
    print(f"  {err}")
PY
)"

contract_errs="$(echo "${contract_check}" | grep '^CONTRACT_ERRORS=' | cut -d= -f2)"
if [[ "${contract_errs}" -gt 0 ]]; then
    echo "FAIL: ${contract_errs} contract error(s):"
    echo "${contract_check}" | grep '^  '
    failures=$((failures + 1))
else
    echo "PASS: Logging + triage contracts are complete"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Intentional regression E2E scenario
# ---------------------------------------------------------------------------
echo "--- Check 4: Intentional regression E2E scenario ---"

if bash "${ROOT}/scripts/e2e_perf_regression_scenario.sh"; then
    echo "PASS: Intentional regression scenario validated attribution path"
else
    echo "FAIL: Intentional regression scenario failed"
    failures=$((failures + 1))
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 5: Summary consistency ---"

summary_check="$(python3 - "${POLICY}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    policy = json.load(f)

errors = []
summary = policy.get("summary", {})
mapped = len(policy.get("attribution", {}).get("suspect_component_map", {}))
classes = len(policy.get("attribution", {}).get("regression_classes", []))
required_log_fields = len(policy.get("logging_contract", {}).get("required_fields", []))
triage_playbooks = len(policy.get("triage_guide", {}))

if summary.get("mapped_benchmarks") != mapped:
    errors.append(f"mapped_benchmarks mismatch: claimed={summary.get('mapped_benchmarks')} actual={mapped}")
if summary.get("regression_classes") != classes:
    errors.append(f"regression_classes mismatch: claimed={summary.get('regression_classes')} actual={classes}")
if summary.get("required_log_fields") != required_log_fields:
    errors.append(
        f"required_log_fields mismatch: claimed={summary.get('required_log_fields')} actual={required_log_fields}"
    )
if summary.get("triage_playbooks") != triage_playbooks:
    errors.append(f"triage_playbooks mismatch: claimed={summary.get('triage_playbooks')} actual={triage_playbooks}")

print(f"SUMMARY_ERRORS={len(errors)}")
for err in errors:
    print(f"  {err}")
PY
)"

summary_errs="$(echo "${summary_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)"
if [[ "${summary_errs}" -gt 0 ]]; then
    echo "FAIL: ${summary_errs} summary inconsistency(ies):"
    echo "${summary_check}" | grep '^  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics are consistent"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_perf_regression_gate: FAILED"
    exit 1
fi

echo ""
echo "check_perf_regression_gate: PASS"
