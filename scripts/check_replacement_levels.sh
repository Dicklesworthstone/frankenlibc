#!/usr/bin/env bash
# check_replacement_levels.sh — CI gate for bd-2bu
#
# Validates that:
#   1. Replacement levels JSON exists and is valid.
#   2. All four levels are defined with required fields.
#   3. Current assessment matches support_matrix.json counts.
#   4. Level status progression is consistent (achieved < in_progress < planned < roadmap).
#   5. Gate criteria thresholds are monotonically tightening.
#   6. README claim and release-tag policy do not drift above current_level.
#   7. README smoke-readiness prose does not overclaim beyond replacement-level blockers.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEVELS="${ROOT}/tests/conformance/replacement_levels.json"
MATRIX="${ROOT}/support_matrix.json"
README="${ROOT}/README.md"
L1_CRT_MATRIX="${ROOT}/tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json"
DEFAULT_REPORT_PATH="${ROOT}/target/conformance/replacement_levels_l1_gate.report.json"
DEFAULT_LOG_PATH="${ROOT}/target/conformance/replacement_levels_l1_gate.log.jsonl"

failures=0

echo "=== Replacement Levels Gate (bd-2bu) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Levels file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Levels file exists and is valid ---"

if [[ ! -f "${LEVELS}" ]]; then
    echo "FAIL: tests/conformance/replacement_levels.json not found"
    echo ""
    echo "check_replacement_levels: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${LEVELS}') as f:
        lvl = json.load(f)
    v = lvl.get('schema_version', 0)
    levels = lvl.get('levels', [])
    assessment = lvl.get('current_assessment', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not levels:
        print('INVALID: empty levels')
    elif not assessment:
        print('INVALID: empty current_assessment')
    else:
        print(f'VALID version={v} levels={len(levels)} symbols={assessment.get(\"total_symbols\", 0)}')
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
# Check 2: All four levels defined with required fields
# ---------------------------------------------------------------------------
echo "--- Check 2: Level definitions ---"

level_check=$(python3 -c "
import json

with open('${LEVELS}') as f:
    lvl = json.load(f)

levels = lvl.get('levels', [])
errors = []
required_fields = ['level', 'name', 'description', 'deployment', 'host_glibc_required', 'gate_criteria', 'status']
expected_ids = ['L0', 'L1', 'L2', 'L3']
found_ids = []

for entry in levels:
    lid = entry.get('level', '?')
    found_ids.append(lid)
    for field in required_fields:
        if field not in entry:
            errors.append(f'{lid}: missing field \"{field}\"')

    # Gate criteria required fields
    gc = entry.get('gate_criteria', {})
    for gf in ['max_callthrough_pct', 'max_stub_pct', 'min_implemented_pct', 'e2e_smoke_required']:
        if gf not in gc:
            errors.append(f'{lid}: gate_criteria missing \"{gf}\"')

missing = [x for x in expected_ids if x not in found_ids]
extra = [x for x in found_ids if x not in expected_ids]

if missing:
    errors.append(f'Missing levels: {missing}')
if extra:
    errors.append(f'Unexpected levels: {extra}')

print(f'LEVEL_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
print(f'FOUND_LEVELS={len(found_ids)}')
")

level_errs=$(echo "${level_check}" | grep '^LEVEL_ERRORS=' | cut -d= -f2)

if [[ "${level_errs}" -gt 0 ]]; then
    echo "FAIL: ${level_errs} level definition error(s):"
    echo "${level_check}" | grep '  '
    failures=$((failures + 1))
else
    found=$(echo "${level_check}" | grep '^FOUND_LEVELS=' | cut -d= -f2)
    echo "PASS: All ${found} levels defined with required fields"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Current assessment matches support_matrix.json
# ---------------------------------------------------------------------------
echo "--- Check 3: Assessment vs support matrix ---"

assessment_check=$(python3 -c "
import json

with open('${LEVELS}') as f:
    lvl = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

assessment = lvl.get('current_assessment', {})
symbols = matrix.get('symbols', [])
errors = []

# Count statuses from matrix
counts = {}
module_counts = {}
for sym in symbols:
    status = sym.get('status', 'Unknown')
    module = sym.get('module', 'unknown')
    counts[status] = counts.get(status, 0) + 1
    key = (status, module)
    module_counts[key] = module_counts.get(key, 0) + 1

matrix_total = len(symbols)
claimed_total = assessment.get('total_symbols', 0)
if claimed_total != matrix_total:
    errors.append(f'total_symbols: claimed={claimed_total} matrix={matrix_total}')

for status_key, json_key in [('Implemented', 'implemented'), ('RawSyscall', 'raw_syscall'),
                               ('GlibcCallThrough', 'callthrough'), ('Stub', 'stub')]:
    actual = counts.get(status_key, 0)
    claimed = assessment.get(json_key, 0)
    if claimed != actual:
        errors.append(f'{json_key}: claimed={claimed} matrix={actual}')

# Check callthrough breakdown
ct_breakdown = assessment.get('callthrough_breakdown', {})
for module, claimed_count in ct_breakdown.items():
    actual_count = module_counts.get(('GlibcCallThrough', module), 0)
    if claimed_count != actual_count:
        errors.append(f'callthrough_breakdown.{module}: claimed={claimed_count} matrix={actual_count}')

# Check stub breakdown
stub_breakdown = assessment.get('stub_breakdown', {})
for module, claimed_count in stub_breakdown.items():
    actual_count = module_counts.get(('Stub', module), 0)
    if claimed_count != actual_count:
        errors.append(f'stub_breakdown.{module}: claimed={claimed_count} matrix={actual_count}')

print(f'ASSESSMENT_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')

# Distribution report
print()
for status in ['Implemented', 'RawSyscall', 'GlibcCallThrough', 'Stub']:
    c = counts.get(status, 0)
    pct = round(c * 100 / matrix_total) if matrix_total > 0 else 0
    print(f'{status}: {c} ({pct}%)')
")

assessment_errs=$(echo "${assessment_check}" | grep '^ASSESSMENT_ERRORS=' | cut -d= -f2)

if [[ "${assessment_errs}" -gt 0 ]]; then
    echo "FAIL: ${assessment_errs} assessment mismatch(es):"
    echo "${assessment_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Current assessment matches support_matrix.json"
fi
echo "${assessment_check}" | grep -E '^(Implemented|RawSyscall|GlibcCallThrough|Stub):' || true
echo ""

# ---------------------------------------------------------------------------
# Check 4: Status progression consistency
# ---------------------------------------------------------------------------
echo "--- Check 4: Status progression ---"

status_check=$(python3 -c "
import json

with open('${LEVELS}') as f:
    lvl = json.load(f)

levels = lvl.get('levels', [])
errors = []

valid_statuses = ['achieved', 'in_progress', 'planned', 'roadmap']
status_order = {s: i for i, s in enumerate(valid_statuses)}

prev_order = -1
prev_level = None
for entry in levels:
    lid = entry.get('level', '?')
    status = entry.get('status', 'unknown')
    if status not in valid_statuses:
        errors.append(f'{lid}: invalid status \"{status}\" (expected one of {valid_statuses})')
        continue
    order = status_order[status]
    if order < prev_order:
        errors.append(f'{lid} ({status}) is less mature than {prev_level} — status should be monotonically non-decreasing')
    prev_order = order
    prev_level = lid

# Check current_level is consistent
current = lvl.get('current_level', '')
achieved = [e.get('level') for e in levels if e.get('status') == 'achieved']
if current and current not in achieved:
    errors.append(f'current_level={current} but its status is not \"achieved\"')

print(f'STATUS_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

status_errs=$(echo "${status_check}" | grep '^STATUS_ERRORS=' | cut -d= -f2)

if [[ "${status_errs}" -gt 0 ]]; then
    echo "FAIL: ${status_errs} status progression error(s):"
    echo "${status_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Status progression is consistent"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Gate criteria monotonically tightening
# ---------------------------------------------------------------------------
echo "--- Check 5: Gate criteria monotonicity ---"

mono_check=$(python3 -c "
import json

with open('${LEVELS}') as f:
    lvl = json.load(f)

levels = lvl.get('levels', [])
errors = []

# max_callthrough_pct should decrease (or stay same) as levels increase
# max_stub_pct should decrease (or stay same)
# min_implemented_pct should increase (or stay same)
prev = {}
for entry in levels:
    lid = entry.get('level', '?')
    gc = entry.get('gate_criteria', {})

    for field, direction in [('max_callthrough_pct', 'decreasing'),
                              ('max_stub_pct', 'decreasing'),
                              ('min_implemented_pct', 'increasing')]:
        val = gc.get(field)
        if val is None:
            continue
        if field in prev:
            if direction == 'decreasing' and val > prev[field][1]:
                errors.append(f'{field}: {lid}={val} > {prev[field][0]}={prev[field][1]} (should be non-increasing)')
            elif direction == 'increasing' and val < prev[field][1]:
                errors.append(f'{field}: {lid}={val} < {prev[field][0]}={prev[field][1]} (should be non-decreasing)')
        prev[field] = (lid, val)

print(f'MONO_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

mono_errs=$(echo "${mono_check}" | grep '^MONO_ERRORS=' | cut -d= -f2)

if [[ "${mono_errs}" -gt 0 ]]; then
    echo "FAIL: ${mono_errs} monotonicity violation(s):"
    echo "${mono_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Gate criteria monotonically tighten across levels"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 6: README + release tag claim drift
# ---------------------------------------------------------------------------
echo "--- Check 6: Claim drift (README + release tags + smoke readiness) ---"

claim_check=$(python3 -c "
import json
import re

with open('${LEVELS}') as f:
    lvl = json.load(f)
with open('${README}', encoding='utf-8') as f:
    readme = f.read()

errors = []
levels = lvl.get('levels', [])
level_map = {entry.get('level'): entry for entry in levels}
current = lvl.get('current_level', '')
if not current:
    errors.append('current_level is missing')
entry = level_map.get(current, {})
name = entry.get('name', '')
if not name:
    errors.append(f'current_level={current} not found in levels[]')

expected_claim = f'Declared replacement level claim: **{current} — {name}**.'
if expected_claim not in readme:
    errors.append('README replacement-level claim line is missing or stale')
claim_matches = re.findall(r'Declared replacement level claim: \\*\\*(L[0-3]) — ([^*]+)\\*\\*\\.', readme)
if len(claim_matches) != 1:
    errors.append(f'Expected exactly one replacement-level claim line in README, found {len(claim_matches)}')

policy = lvl.get('release_tag_policy')
if not isinstance(policy, dict):
    errors.append('release_tag_policy missing or invalid')
else:
    tag_format = policy.get('tag_format', '')
    if not tag_format:
        errors.append('release_tag_policy.tag_format missing')
    suffixes = policy.get('level_tag_suffix')
    if not isinstance(suffixes, dict):
        errors.append('release_tag_policy.level_tag_suffix missing or invalid')
    else:
        for lid in ['L0', 'L1', 'L2', 'L3']:
            expected_suffix = f'-{lid}'
            actual_suffix = suffixes.get(lid)
            if actual_suffix != expected_suffix:
                errors.append(
                    f'release_tag_policy.level_tag_suffix.{lid}={actual_suffix!r} expected {expected_suffix!r}'
                )

    claimed_release_level = policy.get('current_release_level', '')
    if claimed_release_level != current:
        errors.append(
            f'release_tag_policy.current_release_level={claimed_release_level!r} must match current_level={current!r}'
        )

    example = policy.get('current_release_tag_example', '')
    required_suffix = f'-{current}'
    if not example:
        errors.append('release_tag_policy.current_release_tag_example missing')
    elif not example.endswith(required_suffix):
        errors.append(
            f'current_release_tag_example={example!r} must end with {required_suffix!r}'
        )

l1_entry = level_map.get('L1', {})
l1_blockers = ' '.join(
    blocker
    for blocker in l1_entry.get('blockers', [])
    if isinstance(blocker, str)
).lower()
hardened_smoke_incomplete = (
    'hardened-mode e2e smoke' in l1_blockers and 'incomplete' in l1_blockers
)
if hardened_smoke_incomplete:
    overclaim_patterns = [
        (
            r'latest broad preload smoke run is \\*\\*fully green\\*\\*',
            'README must not claim broad preload smoke is fully green while L1 hardened smoke remains blocked'
        ),
        (
            r'both strict and hardened modes pass all workloads',
            'README must not claim paired strict+hardened smoke closure while L1 hardened smoke remains blocked'
        ),
    ]
    for pattern, message in overclaim_patterns:
        if re.search(pattern, readme, re.IGNORECASE):
            errors.append(message)

print(f'CLAIM_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

claim_errs=$(echo "${claim_check}" | grep '^CLAIM_ERRORS=' | cut -d= -f2)

if [[ "${claim_errs}" -gt 0 ]]; then
    echo "FAIL: ${claim_errs} claim drift error(s):"
    echo "${claim_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: README and release-tag policy are aligned to current_level"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 7: L1 CRT/startup/TLS proof matrix
# ---------------------------------------------------------------------------
echo "--- Check 7: L1 CRT/startup/TLS proof matrix ---"

l1_crt_check=$(
L1_CRT_MATRIX="${L1_CRT_MATRIX}" \
python3 <<'PY'
import json
from pathlib import Path

matrix_path = Path(__import__("os").environ["L1_CRT_MATRIX"])
required_log_fields = [
    "trace_id",
    "bead_id",
    "proof_row_id",
    "runtime_mode",
    "replacement_level",
    "expected_order",
    "actual_order",
    "expected_status",
    "actual_status",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
required_rows = [
    "process_startup",
    "argc_argv_envp_handoff",
    "tls_initialization",
    "pthread_tls_keys",
    "constructors",
    "destructors",
    "atexit_on_exit",
    "init_fini_arrays",
    "errno_tls_isolation",
    "secure_mode",
    "failure_diagnostics",
]

def ordinal(ts):
    try:
        date = ts.split("T", 1)[0]
        year_s, month_s, day_s = date.split("-")
        year = int(year_s)
        month = int(month_s)
        day = int(day_s)
    except Exception as exc:
        raise ValueError(f"invalid timestamp {ts!r}: {exc}") from exc
    if month < 1 or month > 12:
        raise ValueError(f"invalid timestamp month in {ts!r}")
    offsets = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    leap_days = year // 4 - year // 100 + year // 400
    return year * 365 + leap_days + offsets[month - 1] + day

errors = []
try:
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
except Exception as exc:
    print("L1_CRT_ERRORS=1")
    print(f"  failed to load {matrix_path}: {exc}")
    raise SystemExit(0)

if matrix.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if matrix.get("bead") != "bd-bp8fl.6.3":
    errors.append("bead must be bd-bp8fl.6.3")
claim_policy = matrix.get("claim_policy", {})
if claim_policy.get("replacement_level") != "L1":
    errors.append("claim_policy.replacement_level must be L1")
if matrix.get("required_log_fields") != required_log_fields:
    errors.append("required_log_fields mismatch")
if matrix.get("required_proof_row_ids") != required_rows:
    errors.append("required_proof_row_ids mismatch")

try:
    generated_at = ordinal(matrix.get("generated_at_utc", ""))
except Exception as exc:
    errors.append(str(exc))
    generated_at = 0
max_age_days = int(claim_policy.get("max_evidence_age_days", 0) or 0)
if max_age_days <= 0:
    errors.append("claim_policy.max_evidence_age_days must be positive")

seen = set()
for row in matrix.get("proof_rows", []):
    row_id = row.get("id", "<missing>")
    if row_id in seen:
        errors.append(f"duplicate proof row id {row_id}")
    seen.add(row_id)
    if row.get("replacement_level") != "L1":
        errors.append(f"{row_id}: replacement_level must be L1")
    modes = set(row.get("runtime_modes", []))
    if not {"strict", "hardened"}.issubset(modes):
        errors.append(f"{row_id}: runtime_modes must include strict and hardened")
    for field in ["expected_order", "actual_order", "artifact_refs", "check_commands", "symbols"]:
        if not isinstance(row.get(field), list):
            errors.append(f"{row_id}: {field} must be an array")
    if not row.get("artifact_refs"):
        errors.append(f"{row_id}: artifact_refs must not be empty")
    if not row.get("check_commands"):
        errors.append(f"{row_id}: check_commands must not be empty")
    if not row.get("failure_signature"):
        errors.append(f"{row_id}: failure_signature must be non-empty")
    actual_status = row.get("actual_status")
    decision = row.get("promotion_decision")
    if actual_status not in {"pass", "blocked", "required"}:
        errors.append(f"{row_id}: invalid actual_status {actual_status!r}")
    if decision not in {"satisfied", "claim_blocked"}:
        errors.append(f"{row_id}: invalid promotion_decision {decision!r}")
    if (actual_status == "pass") != (decision == "satisfied"):
        errors.append(f"{row_id}: actual_status contradicts promotion_decision")
    if decision == "satisfied":
        evidence_at = row.get("evidence_generated_at_utc")
        if not evidence_at:
            errors.append(f"{row_id}: satisfied row missing evidence_generated_at_utc")
        else:
            try:
                age_days = generated_at - ordinal(evidence_at)
            except Exception as exc:
                errors.append(f"{row_id}: {exc}")
            else:
                if age_days > max_age_days:
                    errors.append(f"{row_id}: evidence is stale by {age_days} days")

for row_id in required_rows:
    if row_id not in seen:
        errors.append(f"missing required proof row {row_id}")

negative_tests = matrix.get("negative_claim_tests", [])
if len(negative_tests) < 3:
    errors.append("negative_claim_tests must include at least three cases")
for test in negative_tests:
    test_id = test.get("id", "<missing>")
    if test.get("expected_result") != "claim_blocked":
        errors.append(f"{test_id}: expected_result must be claim_blocked")
    if not test.get("failure_signature"):
        errors.append(f"{test_id}: failure_signature must be non-empty")

print(f"L1_CRT_ERRORS={len(errors)}")
for error in errors:
    print(f"  {error}")
print(f"L1_CRT_ROWS={len(seen)}")
PY
)

l1_crt_errs=$(echo "${l1_crt_check}" | grep '^L1_CRT_ERRORS=' | cut -d= -f2)

if [[ "${l1_crt_errs}" -gt 0 ]]; then
    echo "FAIL: ${l1_crt_errs} L1 CRT/startup/TLS proof matrix error(s):"
    echo "${l1_crt_check}" | grep '  '
    failures=$((failures + 1))
else
    rows=$(echo "${l1_crt_check}" | grep '^L1_CRT_ROWS=' | cut -d= -f2)
    echo "PASS: L1 CRT/startup/TLS proof matrix is valid (${rows} rows)"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 8: Structured L1 objective gate artifacts
# ---------------------------------------------------------------------------
echo "--- Check 8: Structured L1 objective gate artifacts ---"

artifact_output=$(
ROOT="${ROOT}" \
LEVELS="${LEVELS}" \
MATRIX="${MATRIX}" \
README="${README}" \
L1_CRT_MATRIX="${L1_CRT_MATRIX}" \
DEFAULT_REPORT_PATH="${DEFAULT_REPORT_PATH}" \
DEFAULT_LOG_PATH="${DEFAULT_LOG_PATH}" \
python3 <<'PY'
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

root = Path(os.environ["ROOT"])
levels_path = Path(os.environ["LEVELS"])
matrix_path = Path(os.environ["MATRIX"])
readme_path = Path(os.environ["README"])
l1_crt_matrix_path = Path(os.environ["L1_CRT_MATRIX"])
default_report_path = Path(os.environ["DEFAULT_REPORT_PATH"])
default_log_path = Path(os.environ["DEFAULT_LOG_PATH"])

generated_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

L1_CRT_REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "proof_row_id",
    "runtime_mode",
    "replacement_level",
    "expected_order",
    "actual_order",
    "expected_status",
    "actual_status",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]

L1_CRT_REQUIRED_ROWS = [
    "process_startup",
    "argc_argv_envp_handoff",
    "tls_initialization",
    "pthread_tls_keys",
    "constructors",
    "destructors",
    "atexit_on_exit",
    "init_fini_arrays",
    "errno_tls_isolation",
    "secure_mode",
    "failure_diagnostics",
]


def ordinal(timestamp: str) -> int:
    date = timestamp.split("T", 1)[0]
    year_s, month_s, day_s = date.split("-")
    year = int(year_s)
    month = int(month_s)
    day = int(day_s)
    if month < 1 or month > 12:
        raise ValueError(f"invalid timestamp month in {timestamp!r}")
    offsets = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    leap_days = year // 4 - year // 100 + year // 400
    return year * 365 + leap_days + offsets[month - 1] + day


def validate_l1_crt_matrix(matrix: dict) -> list[str]:
    failures = []
    if matrix.get("schema_version") != "v1":
        failures.append("schema_version must be v1")
    if matrix.get("bead") != "bd-bp8fl.6.3":
        failures.append("bead must be bd-bp8fl.6.3")
    claim_policy = matrix.get("claim_policy", {})
    if claim_policy.get("replacement_level") != "L1":
        failures.append("claim_policy.replacement_level must be L1")
    if matrix.get("required_log_fields") != L1_CRT_REQUIRED_LOG_FIELDS:
        failures.append("required_log_fields mismatch")
    if matrix.get("required_proof_row_ids") != L1_CRT_REQUIRED_ROWS:
        failures.append("required_proof_row_ids mismatch")
    try:
        generated_ordinal = ordinal(matrix.get("generated_at_utc", ""))
    except Exception as exc:
        failures.append(f"generated_at_utc invalid: {exc}")
        generated_ordinal = 0
    max_age_days = int(claim_policy.get("max_evidence_age_days", 0) or 0)
    if max_age_days <= 0:
        failures.append("claim_policy.max_evidence_age_days must be positive")

    seen = set()
    for row in matrix.get("proof_rows", []):
        row_id = row.get("id", "<missing>")
        if row_id in seen:
            failures.append(f"duplicate proof row id {row_id}")
        seen.add(row_id)
        if row.get("replacement_level") != "L1":
            failures.append(f"{row_id}: replacement_level must be L1")
        modes = set(row.get("runtime_modes", []))
        if not {"strict", "hardened"}.issubset(modes):
            failures.append(f"{row_id}: runtime_modes must include strict and hardened")
        for field in ["expected_order", "actual_order", "artifact_refs", "check_commands", "symbols"]:
            if not isinstance(row.get(field), list):
                failures.append(f"{row_id}: {field} must be an array")
        if not row.get("artifact_refs"):
            failures.append(f"{row_id}: artifact_refs must not be empty")
        if not row.get("check_commands"):
            failures.append(f"{row_id}: check_commands must not be empty")
        if not row.get("failure_signature"):
            failures.append(f"{row_id}: failure_signature must be non-empty")
        actual_status = row.get("actual_status")
        decision = row.get("promotion_decision")
        if actual_status not in {"pass", "blocked", "required"}:
            failures.append(f"{row_id}: invalid actual_status {actual_status!r}")
        if decision not in {"satisfied", "claim_blocked"}:
            failures.append(f"{row_id}: invalid promotion_decision {decision!r}")
        if (actual_status == "pass") != (decision == "satisfied"):
            failures.append(f"{row_id}: actual_status contradicts promotion_decision")
        if decision == "satisfied":
            evidence_at = row.get("evidence_generated_at_utc")
            if not evidence_at:
                failures.append(f"{row_id}: satisfied row missing evidence_generated_at_utc")
            else:
                try:
                    age_days = generated_ordinal - ordinal(evidence_at)
                except Exception as exc:
                    failures.append(f"{row_id}: evidence timestamp invalid: {exc}")
                else:
                    if age_days > max_age_days:
                        failures.append(f"{row_id}: evidence is stale by {age_days} days")
    for row_id in L1_CRT_REQUIRED_ROWS:
        if row_id not in seen:
            failures.append(f"missing required proof row {row_id}")
    negative_tests = matrix.get("negative_claim_tests", [])
    if len(negative_tests) < 3:
        failures.append("negative_claim_tests must include at least three cases")
    for test in negative_tests:
        test_id = test.get("id", "<missing>")
        if test.get("expected_result") != "claim_blocked":
            failures.append(f"{test_id}: expected_result must be claim_blocked")
        if not test.get("failure_signature"):
            failures.append(f"{test_id}: failure_signature must be non-empty")
    return failures


def rel(path: Path) -> str:
    return os.path.relpath(path, root)


def level_for_outcome(outcome: str) -> str:
    return {
        "pass": "info",
        "blocked": "warning",
        "warn": "warning",
        "warning": "warning",
        "fail": "error",
        "error": "error",
        "satisfied": "info",
        "claim_blocked": "warning",
    }.get(outcome, "info")


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


report_path = default_report_path
log_path = default_log_path
levels = None
l1_entry = {}
objective_gate = {}
l1_crt_matrix = {}

script_checks = []


def add_check(check_id: str, name: str, artifact_ref: str, failures: list[str]) -> None:
    script_checks.append(
        {
            "id": check_id,
            "name": name,
            "artifact_ref": artifact_ref,
            "outcome": "pass" if not failures else "fail",
            "failure_count": len(failures),
            "details": failures,
        }
    )


try:
    if not levels_path.exists():
        raise FileNotFoundError(f"{rel(levels_path)} not found")

    levels = load_json(levels_path)
    schema_version = levels.get("schema_version", 0)
    level_entries = levels.get("levels", [])
    assessment = levels.get("current_assessment", {})
    initial_failures = []
    if schema_version < 1:
        initial_failures.append("schema_version < 1")
    if not level_entries:
        initial_failures.append("levels array is empty")
    if not assessment:
        initial_failures.append("current_assessment is empty")
    add_check(
        "levels_file_valid",
        "Levels file exists and is valid",
        rel(levels_path),
        initial_failures,
    )

    level_map = {
        entry.get("level"): entry
        for entry in level_entries
        if isinstance(entry, dict) and entry.get("level")
    }
    l1_entry = level_map.get("L1", {})
    objective_gate = l1_entry.get("objective_gate", {}) if isinstance(l1_entry, dict) else {}
    generated_report = objective_gate.get("generated_report", {})

    report_env = os.environ.get("FLC_REPLACEMENT_LEVELS_REPORT_PATH")
    log_env = os.environ.get("FLC_REPLACEMENT_LEVELS_LOG_PATH")
    report_path = Path(report_env) if report_env else root / generated_report.get(
        "report_path", rel(default_report_path)
    )
    log_path = Path(log_env) if log_env else root / generated_report.get(
        "log_path", rel(default_log_path)
    )
    if not report_path.is_absolute():
        report_path = root / report_path
    if not log_path.is_absolute():
        log_path = root / log_path

    required_fields = [
        "level",
        "name",
        "description",
        "deployment",
        "host_glibc_required",
        "gate_criteria",
        "status",
    ]
    expected_ids = ["L0", "L1", "L2", "L3"]
    found_ids = []
    definition_failures = []
    for entry in level_entries:
        lid = entry.get("level", "?")
        found_ids.append(lid)
        for field in required_fields:
            if field not in entry:
                definition_failures.append(f'{lid}: missing field "{field}"')
        gc = entry.get("gate_criteria", {})
        for field in [
            "max_callthrough_pct",
            "max_stub_pct",
            "min_implemented_pct",
            "e2e_smoke_required",
        ]:
            if field not in gc:
                definition_failures.append(f'{lid}: gate_criteria missing "{field}"')
    missing = [lid for lid in expected_ids if lid not in found_ids]
    extra = [lid for lid in found_ids if lid not in expected_ids]
    if missing:
        definition_failures.append(f"Missing levels: {missing}")
    if extra:
        definition_failures.append(f"Unexpected levels: {extra}")
    add_check(
        "level_definitions",
        "All four levels are defined with required fields",
        rel(levels_path),
        definition_failures,
    )

    assessment_failures = []
    matrix = load_json(matrix_path)
    symbols = matrix.get("symbols", [])
    counts = Counter()
    module_counts = Counter()
    for sym in symbols:
        status = sym.get("status", "Unknown")
        module = sym.get("module", "unknown")
        counts[status] += 1
        module_counts[(status, module)] += 1

    matrix_total = len(symbols)
    claimed_total = assessment.get("total_symbols", 0)
    if claimed_total != matrix_total:
        assessment_failures.append(
            f"total_symbols: claimed={claimed_total} matrix={matrix_total}"
        )
    for status_key, json_key in [
        ("Implemented", "implemented"),
        ("RawSyscall", "raw_syscall"),
        ("GlibcCallThrough", "callthrough"),
        ("Stub", "stub"),
    ]:
        actual = counts.get(status_key, 0)
        claimed = assessment.get(json_key, 0)
        if claimed != actual:
            assessment_failures.append(f"{json_key}: claimed={claimed} matrix={actual}")
    for module, claimed_count in assessment.get("callthrough_breakdown", {}).items():
        actual = module_counts.get(("GlibcCallThrough", module), 0)
        if claimed_count != actual:
            assessment_failures.append(
                f"callthrough_breakdown.{module}: claimed={claimed_count} matrix={actual}"
            )
    for module, claimed_count in assessment.get("stub_breakdown", {}).items():
        actual = module_counts.get(("Stub", module), 0)
        if claimed_count != actual:
            assessment_failures.append(
                f"stub_breakdown.{module}: claimed={claimed_count} matrix={actual}"
            )
    add_check(
        "assessment_matches_support_matrix",
        "Current assessment matches support_matrix.json",
        rel(matrix_path),
        assessment_failures,
    )

    status_failures = []
    valid_statuses = ["achieved", "in_progress", "planned", "roadmap"]
    status_order = {status: idx for idx, status in enumerate(valid_statuses)}
    prev_order = -1
    prev_level = None
    for entry in level_entries:
        lid = entry.get("level", "?")
        status = entry.get("status", "unknown")
        if status not in status_order:
            status_failures.append(
                f'{lid}: invalid status "{status}" (expected one of {valid_statuses})'
            )
            continue
        order = status_order[status]
        if order < prev_order:
            status_failures.append(
                f"{lid} ({status}) is less mature than {prev_level}"
            )
        prev_order = order
        prev_level = lid
    current = levels.get("current_level", "")
    if current and level_map.get(current, {}).get("status") != "achieved":
        status_failures.append(f'current_level={current} but its status is not "achieved"')
    add_check(
        "status_progression",
        "Status progression is monotonically non-decreasing",
        rel(levels_path),
        status_failures,
    )

    monotonicity_failures = []
    previous = {}
    for entry in level_entries:
        lid = entry.get("level", "?")
        gate_criteria = entry.get("gate_criteria", {})
        for field, direction in [
            ("max_callthrough_pct", "decreasing"),
            ("max_stub_pct", "decreasing"),
            ("min_implemented_pct", "increasing"),
        ]:
            value = gate_criteria.get(field)
            if value is None:
                continue
            if field in previous:
                prev_lid, prev_value = previous[field]
                if direction == "decreasing" and value > prev_value:
                    monotonicity_failures.append(
                        f"{field}: {lid}={value} > {prev_lid}={prev_value}"
                    )
                if direction == "increasing" and value < prev_value:
                    monotonicity_failures.append(
                        f"{field}: {lid}={value} < {prev_lid}={prev_value}"
                    )
            previous[field] = (lid, value)
    add_check(
        "gate_criteria_monotonicity",
        "Gate criteria tighten across levels",
        rel(levels_path),
        monotonicity_failures,
    )

    claim_failures = []
    readme = readme_path.read_text(encoding="utf-8")
    current_entry = level_map.get(current, {})
    current_name = current_entry.get("name", "")
    expected_claim = f"Declared replacement level claim: **{current} — {current_name}**."
    if expected_claim not in readme:
        claim_failures.append("README replacement-level claim line is missing or stale")
    claim_matches = re.findall(
        r"Declared replacement level claim: \*\*(L[0-3]) — ([^*]+)\*\*\.", readme
    )
    if len(claim_matches) != 1:
        claim_failures.append(
            f"Expected exactly one replacement-level claim line in README, found {len(claim_matches)}"
        )

    policy = levels.get("release_tag_policy")
    if not isinstance(policy, dict):
        claim_failures.append("release_tag_policy missing or invalid")
    else:
        if not policy.get("tag_format"):
            claim_failures.append("release_tag_policy.tag_format missing")
        suffixes = policy.get("level_tag_suffix")
        if not isinstance(suffixes, dict):
            claim_failures.append("release_tag_policy.level_tag_suffix missing or invalid")
        else:
            for lid in ["L0", "L1", "L2", "L3"]:
                expected_suffix = f"-{lid}"
                actual_suffix = suffixes.get(lid)
                if actual_suffix != expected_suffix:
                    claim_failures.append(
                        f"release_tag_policy.level_tag_suffix.{lid}={actual_suffix!r} expected {expected_suffix!r}"
                    )
        claimed_release_level = policy.get("current_release_level", "")
        if claimed_release_level != current:
            claim_failures.append(
                f"release_tag_policy.current_release_level={claimed_release_level!r} must match current_level={current!r}"
            )
        example = policy.get("current_release_tag_example", "")
        required_suffix = f"-{current}"
        if not example:
            claim_failures.append("release_tag_policy.current_release_tag_example missing")
        elif not example.endswith(required_suffix):
            claim_failures.append(
                f"current_release_tag_example={example!r} must end with {required_suffix!r}"
            )

    blockers = " ".join(
        blocker for blocker in l1_entry.get("blockers", []) if isinstance(blocker, str)
    ).lower()
    if "hardened-mode e2e smoke" in blockers and "incomplete" in blockers:
        if re.search(r"latest broad preload smoke run is \*\*fully green\*\*", readme, re.IGNORECASE):
            claim_failures.append(
                "README must not claim broad preload smoke is fully green while L1 hardened smoke remains blocked"
            )
        if re.search(r"both strict and hardened modes pass all workloads", readme, re.IGNORECASE):
            claim_failures.append(
                "README must not claim paired strict+hardened smoke closure while L1 hardened smoke remains blocked"
            )
    add_check(
        "claim_drift",
        "README and release-tag policy are aligned to current_level",
        rel(readme_path),
        claim_failures,
    )

    l1_crt_matrix = load_json(l1_crt_matrix_path)
    add_check(
        "l1_crt_startup_tls_proof_matrix",
        "L1 CRT/startup/TLS proof matrix is complete and fail-closed",
        rel(l1_crt_matrix_path),
        validate_l1_crt_matrix(l1_crt_matrix),
    )
except Exception as exc:
    if not script_checks:
        add_check(
            "levels_file_valid",
            "Levels file exists and is valid",
            rel(levels_path),
            [str(exc)],
        )

objective_obligations = objective_gate.get("obligations", []) if isinstance(objective_gate, dict) else []
required_log_fields = (
    objective_gate.get("required_log_fields", [])
    if isinstance(objective_gate, dict)
    else []
)
evidence_bundle = (
    objective_gate.get("evidence_bundle", {})
    if isinstance(objective_gate, dict)
    else {}
)

report_path.parent.mkdir(parents=True, exist_ok=True)
log_path.parent.mkdir(parents=True, exist_ok=True)

objective_outcomes = Counter(
    obligation.get("outcome", "unknown") for obligation in objective_obligations
)
l1_crt_rows = l1_crt_matrix.get("proof_rows", []) if isinstance(l1_crt_matrix, dict) else []
l1_crt_outcomes = Counter(row.get("promotion_decision", "unknown") for row in l1_crt_rows)
script_failure_count = sum(1 for check in script_checks if check["outcome"] != "pass")

artifact_refs = [
    rel(levels_path),
    rel(matrix_path),
    rel(readme_path),
    rel(l1_crt_matrix_path),
    rel(root / "scripts/check_replacement_levels.sh"),
]
for artifact in evidence_bundle.get("artifact_refs", []):
    if artifact not in artifact_refs:
        artifact_refs.append(artifact)

report = {
    "schema_version": 1,
    "bead_id": "bd-gtf.4",
    "gate_id": "replacement_levels_l1_gate",
    "generated_at": generated_at,
    "status": "pass" if script_failure_count == 0 else "fail",
    "current_level": (levels or {}).get("current_level"),
    "objective_gate_status": objective_gate.get("status"),
    "objective_gate_status_reason": objective_gate.get("status_reason"),
    "required_log_fields": required_log_fields,
    "report_artifact_path": rel(report_path),
    "log_artifact_path": rel(log_path),
    "script_checks": script_checks,
    "objective_gate": objective_gate,
    "l1_crt_startup_tls_proof_matrix": {
        "artifact_ref": rel(l1_crt_matrix_path),
        "bead_id": l1_crt_matrix.get("bead"),
        "current_gate_status": l1_crt_matrix.get("summary", {}).get("current_gate_status"),
        "blocker_reason": l1_crt_matrix.get("summary", {}).get("blocker_reason"),
        "required_log_fields": l1_crt_matrix.get("required_log_fields", []),
        "required_proof_row_ids": l1_crt_matrix.get("required_proof_row_ids", []),
        "summary": l1_crt_matrix.get("summary", {}),
    },
    "summary": {
        "script_check_count": len(script_checks),
        "script_failure_count": script_failure_count,
        "objective_obligation_count": len(objective_obligations),
        "objective_outcomes": dict(objective_outcomes),
        "l1_crt_proof_row_count": len(l1_crt_rows),
        "l1_crt_promotion_decisions": dict(l1_crt_outcomes),
    },
    "artifact_refs": artifact_refs,
}

source_commit = os.environ.get("SOURCE_COMMIT", "unknown")
target_dir = os.environ.get("CARGO_TARGET_DIR", "target")

log_rows = []
for check in script_checks:
    log_rows.append(
        {
            "timestamp": generated_at,
            "trace_id": f"bd-gtf.4::replacement_levels::{check['id']}",
            "level": level_for_outcome(check["outcome"]),
            "obligation_id": check["id"],
            "outcome": check["outcome"],
            "artifact_ref": check["artifact_ref"],
            "source": "script_check",
            "bead_id": "bd-gtf.4",
            "description": check["name"],
            "details": check["details"],
        }
    )

for obligation in objective_obligations:
    outcome = obligation.get("outcome", "unknown")
    log_rows.append(
        {
            "timestamp": generated_at,
            "trace_id": f"bd-gtf.4::replacement_levels::{obligation.get('id', 'unknown')}",
            "level": level_for_outcome(outcome),
            "obligation_id": obligation.get("id"),
            "outcome": outcome,
            "artifact_ref": obligation.get("artifact_ref"),
            "source": "objective_gate",
            "bead_id": "bd-gtf.4",
            "description": obligation.get("description"),
            "expected": obligation.get("expected"),
            "actual": obligation.get("actual"),
        }
    )

for proof_row in l1_crt_rows:
    outcome = proof_row.get("promotion_decision", "unknown")
    runtime_modes = proof_row.get("runtime_modes", []) or ["unknown"]
    for runtime_mode in runtime_modes:
        log_rows.append(
            {
                "timestamp": generated_at,
                "trace_id": f"bd-bp8fl.6.3::l1_crt_startup_tls::{proof_row.get('id', 'unknown')}::{runtime_mode}",
                "level": level_for_outcome(outcome),
                "outcome": outcome,
                "artifact_ref": rel(l1_crt_matrix_path),
                "source": "l1_crt_startup_tls_proof_matrix",
                "bead_id": "bd-bp8fl.6.3",
                "proof_row_id": proof_row.get("id"),
                "runtime_mode": runtime_mode,
                "replacement_level": proof_row.get("replacement_level"),
                "expected_order": proof_row.get("expected_order", []),
                "actual_order": proof_row.get("actual_order", []),
                "expected_status": proof_row.get("expected_status"),
                "actual_status": proof_row.get("actual_status"),
                "artifact_refs": proof_row.get("artifact_refs", []),
                "source_commit": source_commit,
                "target_dir": target_dir,
                "failure_signature": proof_row.get("failure_signature"),
                "description": proof_row.get("title"),
            }
        )

report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as handle:
    for row in log_rows:
        handle.write(json.dumps(row, sort_keys=True) + "\n")

print(f"REPORT_PATH={rel(report_path)}")
print(f"LOG_PATH={rel(log_path)}")
PY
)

echo "${artifact_output}"
echo "PASS: Structured L1 objective gate artifacts refreshed"
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_replacement_levels: FAILED"
    exit 1
fi

echo ""
echo "check_replacement_levels: PASS"
