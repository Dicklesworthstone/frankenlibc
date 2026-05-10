#!/usr/bin/env bash
# check_math_governance.sh — CI gate for bd-2yx
#
# Validates that:
#   1. Math governance classification exists and is valid.
#   2. Every classified module exists in the manifest union
#      (production_modules U research_only_modules).
#   3. No manifest-union module is unclassified (coverage).
#   4. No module appears in multiple tiers.
#   5. Summary statistics are consistent.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOVERNANCE="${FRANKENLIBC_MATH_GOVERNANCE:-${ROOT}/tests/conformance/math_governance.json}"
MANIFEST="${FRANKENLIBC_MATH_GOVERNANCE_MANIFEST:-${ROOT}/tests/runtime_math/production_kernel_manifest.v1.json}"
REPORT="${FRANKENLIBC_MATH_GOVERNANCE_REPORT:-${ROOT}/target/conformance/math_governance.report.json}"
LOG="${FRANKENLIBC_MATH_GOVERNANCE_LOG:-${ROOT}/target/conformance/math_governance.log.jsonl}"

failures=0

echo "=== Math Governance Gate (bd-2yx) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Governance file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Governance file exists ---"

if [[ ! -f "${GOVERNANCE}" ]]; then
    echo "FAIL: tests/conformance/math_governance.json not found"
    echo ""
    echo "check_math_governance: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${GOVERNANCE}') as f:
        gov = json.load(f)
    v = gov.get('schema_version', 0)
    tiers = gov.get('tiers', {})
    cls = gov.get('classifications', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not tiers:
        print('INVALID: empty tiers')
    elif not cls:
        print('INVALID: empty classifications')
    else:
        total = sum(len(cls.get(t, [])) for t in cls)
        print(f'VALID version={v} tiers={len(tiers)} classified={total}')
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
# Check 2: All classified modules exist in manifest union
# ---------------------------------------------------------------------------
echo "--- Check 2: Classified modules exist in manifest union ---"

manifest_check=$(python3 -c "
import json

with open('${GOVERNANCE}') as f:
    gov = json.load(f)
with open('${MANIFEST}') as f:
    manifest = json.load(f)

manifest_modules = set(manifest.get('production_modules', [])) | set(manifest.get('research_only_modules', []))
classifications = gov.get('classifications', {})
errors = []

for tier, entries in classifications.items():
    for entry in entries:
        module = entry.get('module', '')
        if module not in manifest_modules:
            errors.append(f'{module} (tier={tier}): not in manifest union')

print(f'MANIFEST_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

manifest_errs=$(echo "${manifest_check}" | grep '^MANIFEST_ERRORS=' | cut -d= -f2)

if [[ "${manifest_errs}" -gt 0 ]]; then
    echo "FAIL: ${manifest_errs} classified module(s) not in manifest union:"
    echo "${manifest_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All classified modules exist in manifest union"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Manifest coverage (no unclassified modules)
# ---------------------------------------------------------------------------
echo "--- Check 3: Manifest coverage ---"

coverage_check=$(python3 -c "
import json

with open('${GOVERNANCE}') as f:
    gov = json.load(f)
with open('${MANIFEST}') as f:
    manifest = json.load(f)

manifest_modules = set(manifest.get('production_modules', [])) | set(manifest.get('research_only_modules', []))
classifications = gov.get('classifications', {})

classified = set()
for tier, entries in classifications.items():
    for entry in entries:
        classified.add(entry.get('module', ''))

unclassified = manifest_modules - classified
extra = classified - manifest_modules

print(f'MANIFEST_MODULES={len(manifest_modules)}')
print(f'CLASSIFIED={len(classified)}')
print(f'UNCLASSIFIED={len(unclassified)}')
print(f'EXTRA={len(extra)}')

for m in sorted(unclassified):
    print(f'  UNCLASSIFIED: {m}')
for m in sorted(extra):
    print(f'  EXTRA: {m}')
")

unclassified=$(echo "${coverage_check}" | grep '^UNCLASSIFIED=' | cut -d= -f2)
extra=$(echo "${coverage_check}" | grep '^EXTRA=' | cut -d= -f2)

if [[ "${unclassified}" -gt 0 ]]; then
    echo "FAIL: ${unclassified} manifest module(s) not classified:"
    echo "${coverage_check}" | grep '  UNCLASSIFIED:'
    failures=$((failures + 1))
else
    echo "PASS: All manifest modules are classified"
fi

if [[ "${extra}" -gt 0 ]]; then
    echo "WARNING: ${extra} classified module(s) not in manifest:"
    echo "${coverage_check}" | grep '  EXTRA:'
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: No duplicate classifications
# ---------------------------------------------------------------------------
echo "--- Check 4: No duplicate classifications ---"

dup_check=$(python3 -c "
import json

with open('${GOVERNANCE}') as f:
    gov = json.load(f)

classifications = gov.get('classifications', {})
seen = {}
dups = []

for tier, entries in classifications.items():
    for entry in entries:
        module = entry.get('module', '')
        if module in seen:
            dups.append(f'{module}: in both {seen[module]} and {tier}')
        seen[module] = tier

print(f'DUPLICATES={len(dups)}')
for d in dups:
    print(f'  {d}')
")

dup_count=$(echo "${dup_check}" | grep '^DUPLICATES=' | cut -d= -f2)

if [[ "${dup_count}" -gt 0 ]]; then
    echo "FAIL: ${dup_count} module(s) in multiple tiers:"
    echo "${dup_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: No duplicate classifications"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 5: Summary consistency ---"

summary_check=$(python3 -c "
import json

with open('${GOVERNANCE}') as f:
    gov = json.load(f)

classifications = gov.get('classifications', {})
summary = gov.get('summary', {})
errors = []

actual_counts = {}
total = 0
for tier, entries in classifications.items():
    actual_counts[tier] = len(entries)
    total += len(entries)

claimed_total = summary.get('total_modules', 0)
if claimed_total != total:
    errors.append(f'total_modules: claimed={claimed_total} actual={total}')

for tier in ['production_core', 'production_monitor', 'research']:
    claimed = summary.get(tier, 0)
    actual = actual_counts.get(tier, 0)
    if claimed != actual:
        errors.append(f'{tier}: claimed={claimed} actual={actual}')

print(f'SUMMARY_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')

# Distribution report
print()
for tier in ['production_core', 'production_monitor', 'research']:
    count = actual_counts.get(tier, 0)
    pct = round(count * 100 / total) if total > 0 else 0
    print(f'{tier}: {count} modules ({pct}%)')
")

summary_errs=$(echo "${summary_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)

if [[ "${summary_errs}" -gt 0 ]]; then
    echo "FAIL: ${summary_errs} summary inconsistency(ies):"
    echo "${summary_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics consistent"
fi
echo "${summary_check}" | grep -E '^(production_|research:)'
echo ""

# ---------------------------------------------------------------------------
# Check 6: Completion-debt evidence and telemetry
# ---------------------------------------------------------------------------
echo "--- Check 6: Completion-debt evidence and telemetry ---"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

completion_check=$(python3 - "${ROOT}" "${GOVERNANCE}" "${MANIFEST}" "${REPORT}" "${LOG}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
governance_path = Path(sys.argv[2])
manifest_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])

BEAD_ID = "bd-2yx"
COMPLETION_DEBT_BEAD_ID = "bd-2yx.1"
SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "migrations_primary": "migrations.primary",
    "telemetry_primary": "telemetry.primary",
}
REQUIRED_EVENTS = {"math_governance_tier", "math_governance_summary"}


def rel(path):
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load(path, label, errors):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}


def ensure_file(path_text, errors, context):
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} missing file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{context} unreadable: {path_text}: {exc}")
        return ""


errors = []
governance = load(governance_path, "governance", errors)
manifest = load(manifest_path, "manifest", errors)

evidence = governance.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}
if evidence.get("bead") != COMPLETION_DEBT_BEAD_ID:
    errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD_ID}")
if evidence.get("original_bead") != BEAD_ID:
    errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
if evidence.get("next_audit_score_threshold", 0) < 800:
    errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")

test_source_path = evidence.get("test_source")
test_source = ensure_file(test_source_path, errors, "completion_debt_evidence.test_source") if isinstance(test_source_path, str) else ""
if not isinstance(test_source_path, str):
    errors.append("completion_debt_evidence.test_source missing")

for section, missing_item in SECTIONS.items():
    block = evidence.get(section)
    if not isinstance(block, dict):
        errors.append(f"completion_debt_evidence.{section} missing")
        continue
    if block.get("missing_item_id") != missing_item:
        errors.append(f"completion_debt_evidence.{section}.missing_item_id must be {missing_item}")
    names = block.get("required_test_names")
    if not isinstance(names, list) or not names:
        errors.append(f"completion_debt_evidence.{section}.required_test_names missing")
        continue
    for name in names:
        if not isinstance(name, str) or f"fn {name}(" not in test_source:
            errors.append(f"completion_debt_evidence.{section} references missing Rust test {name}")

telemetry = governance.get("telemetry_contract")
if not isinstance(telemetry, dict):
    errors.append("telemetry_contract must be an object")
    telemetry = {}
events = telemetry.get("required_log_events")
if set(events or []) != REQUIRED_EVENTS:
    errors.append("telemetry_contract.required_log_events drifted")
fields = telemetry.get("required_log_fields")
if not isinstance(fields, list) or not {"trace_id", "event", "bead_id", "completion_debt_bead", "artifact_refs"} <= set(fields):
    errors.append("telemetry_contract.required_log_fields missing required keys")

classifications = governance.get("classifications", {})
production_modules = set(manifest.get("production_modules", []))
research_only_modules = set(manifest.get("research_only_modules", []))
research_classified = {
    entry.get("module")
    for entry in classifications.get("research", [])
    if isinstance(entry, dict) and entry.get("module")
}
research_in_production = sorted(research_classified & production_modules)
research_missing_from_research_manifest = sorted(research_classified - research_only_modules)
if research_in_production:
    errors.append(f"research modules leaked into production manifest: {research_in_production}")
if research_missing_from_research_manifest:
    errors.append(f"research modules missing from research_only_modules: {research_missing_from_research_manifest}")

cargo_toml = ensure_file("crates/frankenlibc-membrane/Cargo.toml", errors, "completion_debt_evidence.migrations_primary")
if "runtime-math-research" not in cargo_toml:
    errors.append("crates/frankenlibc-membrane/Cargo.toml must expose runtime-math-research feature")

summary = governance.get("summary", {})
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
tier_rows = []
for tier in ["production_core", "production_monitor", "research"]:
    tier_rows.append({
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:{tier}",
        "event": "math_governance_tier",
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "tier": tier,
        "module_count": len(classifications.get(tier, [])),
        "status": "pass" if not errors else "fail",
        "artifact_refs": [rel(governance_path), rel(manifest_path)],
        "failure_signature": "none" if not errors else "completion_debt_validation_error",
    })

log_rows = tier_rows + [{
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:summary",
    "event": "math_governance_summary",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "tier": None,
    "module_count": summary.get("total_modules", 0),
    "status": "pass" if not errors else "fail",
    "artifact_refs": [rel(governance_path), rel(manifest_path), rel(report_path), rel(log_path)],
    "failure_signature": "none" if not errors else "completion_debt_validation_error",
}]

report = {
    "schema_version": "math_governance.report.v1",
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "governance": rel(governance_path),
    "manifest": rel(manifest_path),
    "tier_counts": {
        "production_core": len(classifications.get("production_core", [])),
        "production_monitor": len(classifications.get("production_monitor", [])),
        "research": len(classifications.get("research", [])),
    },
    "total_modules": summary.get("total_modules", 0),
    "research_in_production_manifest": research_in_production,
    "research_missing_from_research_manifest": research_missing_from_research_manifest,
    "errors": errors,
    "status": "pass" if not errors else "fail",
    "report_path": rel(report_path),
    "log_path": rel(log_path),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")

print(f"COMPLETION_ERRORS={len(errors)}")
print(f"REPORT={rel(report_path)}")
print(f"LOG={rel(log_path)}")
print(f"LOG_ROWS={len(log_rows)}")
for error in errors:
    print(f"ERROR: {error}")
PY
)

completion_errs=$(echo "${completion_check}" | grep '^COMPLETION_ERRORS=' | cut -d= -f2)

if [[ "${completion_errs}" -gt 0 ]]; then
    echo "FAIL: ${completion_errs} completion-debt evidence issue(s):"
    echo "${completion_check}" | grep '^ERROR:'
    failures=$((failures + 1))
else
    echo "PASS: Completion-debt evidence and telemetry contract valid"
fi
echo "${completion_check}" | grep -E '^(REPORT|LOG|LOG_ROWS)='
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_math_governance: FAILED"
    exit 1
fi

echo ""
echo "check_math_governance: PASS"
