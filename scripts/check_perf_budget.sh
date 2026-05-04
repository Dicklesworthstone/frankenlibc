#!/usr/bin/env bash
# check_perf_budget.sh — CI gate for bd-2r0
#
# Validates that:
#   1. Perf budget policy JSON exists and is valid.
#   2. Hotpath symbol list matches support_matrix.json perf_class assignments.
#   3. Budget thresholds are consistent with replacement_levels.json.
#   4. Active waivers reference valid beads.
#   5. Assessment counts match support_matrix.json.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT}/tests/conformance/perf_budget_policy.json"
MATRIX="${ROOT}/support_matrix.json"
LEVELS="${ROOT}/tests/conformance/replacement_levels.json"
BEADS="${ROOT}/.beads/issues.jsonl"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/perf_budget_policy.report.json"
LOG="${OUT_DIR}/perf_budget_policy.log.jsonl"

failures=0

mkdir -p "${OUT_DIR}"

echo "=== Perf Budget Gate (bd-2r0) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Policy file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Policy file exists and is valid ---"

if [[ ! -f "${POLICY}" ]]; then
    echo "FAIL: tests/conformance/perf_budget_policy.json not found"
    echo ""
    echo "check_perf_budget: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${POLICY}') as f:
        pol = json.load(f)
    v = pol.get('schema_version', 0)
    budgets = pol.get('budgets', {})
    hotpath = pol.get('hotpath_symbols', {})
    assessment = pol.get('current_assessment', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not budgets:
        print('INVALID: empty budgets')
    elif not hotpath:
        print('INVALID: empty hotpath_symbols')
    elif not assessment:
        print('INVALID: empty current_assessment')
    else:
        strict_count = len(hotpath.get('strict_hotpath', []))
        print(f'VALID version={v} budgets={len(budgets)} hotpath_symbols={strict_count}')
except Exception as e:
    print(f'INVALID: {e}')
")

if [[ "${valid_check}" == INVALID* ]]; then
    echo "FAIL: ${valid_check}"
    failures=$((failures + 1))
else
    echo "PASS: ${valid_check}"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: Hotpath symbols match support_matrix.json
# ---------------------------------------------------------------------------
echo "--- Check 2: Hotpath symbols match support_matrix ---"

hotpath_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    pol = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

errors = []

# Build set of strict_hotpath symbols from matrix
matrix_strict = set()
for sym in matrix.get('symbols', []):
    if sym.get('perf_class') == 'strict_hotpath':
        matrix_strict.add(sym['symbol'])

# Build set from policy
policy_strict = set()
for entry in pol.get('hotpath_symbols', {}).get('strict_hotpath', []):
    policy_strict.add(entry['symbol'])

missing = matrix_strict - policy_strict
extra = policy_strict - matrix_strict

if missing:
    for s in sorted(missing):
        errors.append(f'MISSING from policy: {s} (in matrix as strict_hotpath)')
if extra:
    for s in sorted(extra):
        errors.append(f'EXTRA in policy: {s} (not strict_hotpath in matrix)')

# Verify module/status match for shared symbols
for entry in pol.get('hotpath_symbols', {}).get('strict_hotpath', []):
    sym_name = entry['symbol']
    if sym_name not in matrix_strict:
        continue
    matrix_sym = next((s for s in matrix['symbols'] if s['symbol'] == sym_name), None)
    if matrix_sym:
        if entry.get('module') != matrix_sym.get('module'):
            errors.append(f'{sym_name}: module mismatch policy={entry.get(\"module\")} matrix={matrix_sym.get(\"module\")}')
        if entry.get('status') != matrix_sym.get('status'):
            errors.append(f'{sym_name}: status mismatch policy={entry.get(\"status\")} matrix={matrix_sym.get(\"status\")}')

print(f'HOTPATH_ERRORS={len(errors)}')
print(f'MATRIX_STRICT={len(matrix_strict)}')
print(f'POLICY_STRICT={len(policy_strict)}')
for e in errors:
    print(f'  {e}')
")

hotpath_errs=$(echo "${hotpath_check}" | grep '^HOTPATH_ERRORS=' | cut -d= -f2)

if [[ "${hotpath_errs}" -gt 0 ]]; then
    echo "FAIL: ${hotpath_errs} hotpath symbol mismatch(es):"
    echo "${hotpath_check}" | grep '  '
    failures=$((failures + 1))
else
    matrix_ct=$(echo "${hotpath_check}" | grep '^MATRIX_STRICT=' | cut -d= -f2)
    policy_ct=$(echo "${hotpath_check}" | grep '^POLICY_STRICT=' | cut -d= -f2)
    echo "PASS: ${policy_ct} policy symbols match ${matrix_ct} matrix strict_hotpath symbols"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Budget thresholds consistent with replacement_levels.json
# ---------------------------------------------------------------------------
echo "--- Check 3: Budget thresholds vs replacement levels ---"

budget_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    pol = json.load(f)

errors = []
budgets = pol.get('budgets', {})

# Check replacement levels if available
try:
    with open('${LEVELS}') as f:
        lvl = json.load(f)

    for entry in lvl.get('levels', []):
        gc = entry.get('gate_criteria', {})
        lid = entry.get('level', '?')
        strict_ns = gc.get('perf_budget_strict_ns')
        hardened_ns = gc.get('perf_budget_hardened_ns')

        pol_strict = budgets.get('strict_hotpath', {}).get('strict_mode_ns')
        pol_hardened = budgets.get('strict_hotpath', {}).get('hardened_mode_ns')

        if strict_ns is not None and pol_strict is not None:
            if pol_strict != strict_ns:
                errors.append(f'{lid}: strict budget policy={pol_strict}ns levels={strict_ns}ns')
        if hardened_ns is not None and pol_hardened is not None:
            if pol_hardened != hardened_ns:
                errors.append(f'{lid}: hardened budget policy={pol_hardened}ns levels={hardened_ns}ns')
except FileNotFoundError:
    errors.append('replacement_levels.json not found (skipping cross-check)')

print(f'BUDGET_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

budget_errs=$(echo "${budget_check}" | grep '^BUDGET_ERRORS=' | cut -d= -f2)

if [[ "${budget_errs}" -gt 0 ]]; then
    echo "FAIL: ${budget_errs} budget threshold inconsistency(ies):"
    echo "${budget_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Budget thresholds consistent with replacement levels"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Active waivers reference tracked beads
# ---------------------------------------------------------------------------
echo "--- Check 4: Waiver bead references ---"

waiver_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    pol = json.load(f)

errors = []
waivers = pol.get('active_waivers', [])

# Load beads
bead_ids = set()
try:
    with open('${BEADS}') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            bead_ids.add(obj.get('id', ''))
except FileNotFoundError:
    pass

for w in waivers:
    bid = w.get('bead_id', '')
    if not bid:
        errors.append('Waiver missing bead_id')
        continue
    if bid not in bead_ids:
        errors.append(f'Waiver bead {bid} not found in issues.jsonl')

    for req in ['symbols', 'justification', 'expires_at']:
        if not w.get(req):
            errors.append(f'Waiver {bid}: missing required field \"{req}\"')

print(f'WAIVER_ERRORS={len(errors)}')
print(f'ACTIVE_WAIVERS={len(waivers)}')
for e in errors:
    print(f'  {e}')
")

waiver_errs=$(echo "${waiver_check}" | grep '^WAIVER_ERRORS=' | cut -d= -f2)
waiver_count=$(echo "${waiver_check}" | grep '^ACTIVE_WAIVERS=' | cut -d= -f2)

if [[ "${waiver_errs}" -gt 0 ]]; then
    echo "FAIL: ${waiver_errs} waiver error(s):"
    echo "${waiver_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: ${waiver_count} active waiver(s), all reference tracked beads"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Assessment counts match support_matrix.json
# ---------------------------------------------------------------------------
echo "--- Check 5: Assessment counts ---"

assess_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    pol = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

errors = []
assessment = pol.get('current_assessment', {})
symbols = matrix.get('symbols', [])

# Count perf_class from matrix
class_counts = {}
for sym in symbols:
    pc = sym.get('perf_class', 'coldpath')
    class_counts[pc] = class_counts.get(pc, 0) + 1

# Total
if assessment.get('total_symbols', 0) != len(symbols):
    errors.append(f'total_symbols: policy={assessment.get(\"total_symbols\")} matrix={len(symbols)}')

for pc, json_key in [('strict_hotpath', 'strict_hotpath_count'),
                      ('hardened_hotpath', 'hardened_hotpath_count'),
                      ('coldpath', 'coldpath_count')]:
    actual = class_counts.get(pc, 0)
    claimed = assessment.get(json_key, 0)
    if claimed != actual:
        errors.append(f'{json_key}: policy={claimed} matrix={actual}')

# Check by_module breakdown
by_mod = assessment.get('strict_hotpath_by_module', {})
mod_counts = {}
for sym in symbols:
    if sym.get('perf_class') == 'strict_hotpath':
        m = sym.get('module', 'unknown')
        mod_counts[m] = mod_counts.get(m, 0) + 1

for m, claimed in by_mod.items():
    actual = mod_counts.get(m, 0)
    if claimed != actual:
        errors.append(f'strict_hotpath_by_module.{m}: policy={claimed} matrix={actual}')

for m, actual in mod_counts.items():
    if m not in by_mod:
        errors.append(f'strict_hotpath_by_module missing {m} ({actual} symbols)')

# Check by_status breakdown
by_status = assessment.get('strict_hotpath_by_status', {})
status_counts = {}
for sym in symbols:
    if sym.get('perf_class') == 'strict_hotpath':
        s = sym.get('status', 'Unknown')
        status_counts[s] = status_counts.get(s, 0) + 1

for s, claimed in by_status.items():
    actual = status_counts.get(s, 0)
    if claimed != actual:
        errors.append(f'strict_hotpath_by_status.{s}: policy={claimed} matrix={actual}')

print(f'ASSESS_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')

# Distribution
total = len(symbols)
for pc in ['strict_hotpath', 'hardened_hotpath', 'coldpath']:
    c = class_counts.get(pc, 0)
    pct = round(c * 100 / total) if total > 0 else 0
    print(f'{pc}: {c} ({pct}%)')
")

assess_errs=$(echo "${assess_check}" | grep '^ASSESS_ERRORS=' | cut -d= -f2)

if [[ "${assess_errs}" -gt 0 ]]; then
    echo "FAIL: ${assess_errs} assessment mismatch(es):"
    echo "${assess_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Assessment counts match support_matrix.json"
fi
echo "${assess_check}" | grep -E '^(strict_hotpath|hardened_hotpath|coldpath):' || true
echo ""

# ---------------------------------------------------------------------------
# Check 6: Workload-linked performance budgets and claim blockers
# ---------------------------------------------------------------------------
echo "--- Check 6: Workload-linked performance budgets ---"

workload_check=$(python3 - "${ROOT}" "${POLICY}" "${REPORT}" "${LOG}" <<'PY'
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
policy_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

errors = []
checks = {}

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "benchmark_id",
    "workload_id",
    "api_family",
    "symbol",
    "runtime_mode",
    "replacement_level",
    "environment_id",
    "baseline_value",
    "actual_value",
    "variance",
    "threshold",
    "decision",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]

REQUIRED_BUDGET_FIELDS = [
    "budget_id",
    "benchmark_id",
    "benchmark_kind",
    "workload_id",
    "api_family",
    "symbol",
    "runtime_mode",
    "replacement_level",
    "environment_id",
    "host_baseline",
    "current_result",
    "variance_policy",
    "sample_count",
    "warmup_policy",
    "latency_threshold_ns",
    "throughput_threshold_ops_per_sec",
    "regression_severity",
    "benchmark_script",
    "artifact_refs",
    "parity_evidence_refs",
    "required_evidence",
    "present_evidence",
    "missing_evidence",
    "blocking_decision",
    "decision",
    "failure_signature",
]

REQUIRED_BLOCKER_SIGNATURES = {
    "perf_claim_stale_baseline",
    "perf_claim_missing_parity_proof",
    "perf_claim_microbench_only",
    "perf_claim_parity_failing",
}

def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return {}

def repo_ref_exists(ref, context):
    if not isinstance(ref, str) or not ref:
        errors.append(f"{context}: artifact ref must be a non-empty string")
        return False
    rel = Path(ref)
    if rel.is_absolute() or ".." in rel.parts:
        errors.append(f"{context}: artifact ref must stay repo-relative: {ref}")
        return False
    if ref.startswith("target/"):
        return True
    if not (root / rel).exists():
        errors.append(f"{context}: artifact ref does not exist: {ref}")
        return False
    return True

policy = load_json(policy_path)
extension = policy.get("workload_budget_extension", {})
budgets = policy.get("workload_performance_budgets", [])
blockers = policy.get("performance_claim_blocking_tests", [])

extension_ok = (
    extension.get("bead") == "bd-bp8fl.8.6"
    and extension.get("parity_first") is True
    and extension.get("baseline_first") is True
    and extension.get("performance_claims_require_current_behavior_proof") is True
    and extension.get("microbench_only_cannot_support_user_claims") is True
    and extension.get("required_log_fields") == REQUIRED_LOG_FIELDS
)
checks["workload_budget_extension"] = "pass" if extension_ok else "fail"
if not extension_ok:
    errors.append("workload_budget_extension must preserve parity-first/baseline-first rules and required log fields")

budget_ids = [budget.get("budget_id") for budget in budgets]
budget_kind_counts = Counter()
decision_counts = Counter()
budget_rows_ok = bool(budgets) and len(budget_ids) == len(set(budget_ids))

for budget in budgets:
    budget_id = budget.get("budget_id", "<missing budget_id>")
    for field in REQUIRED_BUDGET_FIELDS:
        if field not in budget:
            budget_rows_ok = False
            errors.append(f"{budget_id}: missing budget field {field}")

    kind = budget.get("benchmark_kind")
    budget_kind_counts[kind] += 1
    decision = budget.get("decision")
    decision_counts[decision] += 1

    if budget.get("runtime_mode") not in {"strict", "hardened"}:
        budget_rows_ok = False
        errors.append(f"{budget_id}: runtime_mode must be strict or hardened")
    if budget.get("replacement_level") not in {"L0", "L1", "L2", "L3"}:
        budget_rows_ok = False
        errors.append(f"{budget_id}: replacement_level must be L0-L3")
    if budget.get("sample_count", 0) < 3:
        budget_rows_ok = False
        errors.append(f"{budget_id}: sample_count must be at least 3")
    if budget.get("latency_threshold_ns") is None and budget.get("throughput_threshold_ops_per_sec") is None:
        budget_rows_ok = False
        errors.append(f"{budget_id}: latency or throughput threshold must be present")
    if budget.get("regression_severity") not in {"blocking", "warning"}:
        budget_rows_ok = False
        errors.append(f"{budget_id}: regression_severity must be blocking or warning")
    if budget.get("blocking_decision") != "claim_blocked":
        budget_rows_ok = False
        errors.append(f"{budget_id}: blocking_decision must be claim_blocked")

    if decision == "claim_blocked":
        if not budget.get("missing_evidence"):
            budget_rows_ok = False
            errors.append(f"{budget_id}: claim_blocked rows must name missing_evidence")
        if not budget.get("failure_signature"):
            budget_rows_ok = False
            errors.append(f"{budget_id}: claim_blocked rows must name failure_signature")
    elif decision == "pass":
        baseline = budget.get("host_baseline", {}).get("baseline_value_ns")
        actual = budget.get("current_result", {}).get("actual_value_ns")
        threshold = budget.get("latency_threshold_ns")
        if baseline is None or actual is None or threshold is None or actual > threshold:
            budget_rows_ok = False
            errors.append(f"{budget_id}: pass rows require baseline, actual, and actual <= latency threshold")
    else:
        budget_rows_ok = False
        errors.append(f"{budget_id}: decision must be pass or claim_blocked")

    for ref in budget.get("artifact_refs", []):
        if not repo_ref_exists(ref, budget_id):
            budget_rows_ok = False
    for ref in budget.get("parity_evidence_refs", []):
        if not repo_ref_exists(ref, budget_id):
            budget_rows_ok = False
    for nested in ["host_baseline", "current_result"]:
        for ref in budget.get(nested, {}).get("artifact_refs", []):
            if not repo_ref_exists(ref, budget_id):
                budget_rows_ok = False
    if not repo_ref_exists(budget.get("benchmark_script"), budget_id):
        budget_rows_ok = False

if budget_kind_counts.get("user_workload_e2e", 0) < 1:
    budget_rows_ok = False
    errors.append("at least one user_workload_e2e budget row is required")
if budget_kind_counts.get("membrane_hot_path_microbenchmark", 0) < 1:
    budget_rows_ok = False
    errors.append("at least one membrane_hot_path_microbenchmark budget row is required")
checks["workload_budget_rows"] = "pass" if budget_rows_ok else "fail"

blocker_signatures = {blocker.get("failure_signature") for blocker in blockers}
blockers_ok = REQUIRED_BLOCKER_SIGNATURES.issubset(blocker_signatures)
for blocker in blockers:
    if blocker.get("expected_decision") != "claim_blocked":
        blockers_ok = False
        errors.append(f"{blocker.get('id', '<missing blocker id>')}: expected_decision must be claim_blocked")
    for field in ["condition", "claim_surface", "failure_signature"]:
        if not blocker.get(field):
            blockers_ok = False
            errors.append(f"{blocker.get('id', '<missing blocker id>')}: missing {field}")
checks["performance_claim_blockers"] = "pass" if blockers_ok else "fail"

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
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.8.6",
    "status": status,
    "checks": checks,
    "workload_budget_count": len(budgets),
    "user_workload_budget_count": budget_kind_counts.get("user_workload_e2e", 0),
    "membrane_hotpath_budget_count": budget_kind_counts.get("membrane_hot_path_microbenchmark", 0),
    "claim_blocking_test_count": len(blockers),
    "decision_counts": dict(decision_counts),
    "artifact_refs": [
        "tests/conformance/perf_budget_policy.json",
        "target/conformance/perf_budget_policy.report.json",
        "target/conformance/perf_budget_policy.log.jsonl",
    ],
    "errors": errors,
    "source_commit": source_commit,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

events = []
for budget in budgets:
    events.append({
        "trace_id": f"bd-bp8fl.8.6::{budget.get('benchmark_id')}",
        "bead_id": "bd-bp8fl.8.6",
        "benchmark_id": budget.get("benchmark_id"),
        "workload_id": budget.get("workload_id"),
        "api_family": budget.get("api_family"),
        "symbol": budget.get("symbol"),
        "runtime_mode": budget.get("runtime_mode"),
        "replacement_level": budget.get("replacement_level"),
        "environment_id": budget.get("environment_id"),
        "baseline_value": budget.get("host_baseline", {}).get("baseline_value_ns"),
        "actual_value": budget.get("current_result", {}).get("actual_value_ns"),
        "variance": budget.get("variance_policy", {}).get("max_coefficient_of_variation_pct"),
        "threshold": budget.get("latency_threshold_ns"),
        "decision": budget.get("decision"),
        "latency_ns": budget.get("current_result", {}).get("actual_value_ns"),
        "artifact_refs": budget.get("artifact_refs", []),
        "source_commit": source_commit,
        "target_dir": str(root / "target/conformance"),
        "failure_signature": budget.get("failure_signature"),
    })
log_path.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)

print(f"WORKLOAD_ERRORS={len(errors)}")
print(f"WORKLOAD_BUDGETS={len(budgets)}")
print(f"USER_WORKLOAD_BUDGETS={budget_kind_counts.get('user_workload_e2e', 0)}")
print(f"MEMBRANE_HOTPATH_BUDGETS={budget_kind_counts.get('membrane_hot_path_microbenchmark', 0)}")
print(f"CLAIM_BLOCKING_TESTS={len(blockers)}")
for error in errors:
    print(f"  {error}")
PY
)

workload_errs=$(echo "${workload_check}" | grep '^WORKLOAD_ERRORS=' | cut -d= -f2)

if [[ "${workload_errs}" -gt 0 ]]; then
    echo "FAIL: ${workload_errs} workload budget error(s):"
    echo "${workload_check}" | grep '  '
    failures=$((failures + 1))
else
    workload_ct=$(echo "${workload_check}" | grep '^WORKLOAD_BUDGETS=' | cut -d= -f2)
    user_ct=$(echo "${workload_check}" | grep '^USER_WORKLOAD_BUDGETS=' | cut -d= -f2)
    membrane_ct=$(echo "${workload_check}" | grep '^MEMBRANE_HOTPATH_BUDGETS=' | cut -d= -f2)
    claim_ct=$(echo "${workload_check}" | grep '^CLAIM_BLOCKING_TESTS=' | cut -d= -f2)
    echo "PASS: ${workload_ct} workload budget row(s), ${user_ct} user workload row(s), ${membrane_ct} membrane hot-path row(s), ${claim_ct} claim blocker(s)"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_perf_budget: FAILED"
    exit 1
fi

echo ""
echo "check_perf_budget: PASS"
