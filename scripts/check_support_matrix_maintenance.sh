#!/usr/bin/env bash
# check_support_matrix_maintenance.sh — CI gate for bd-3g4p
# Runs the automated support matrix maintenance validator, checks the
# generated report against the checked-in canonical stable sections, and
# reports status/conformance drift without rewriting the canonical artifact.
#
# Default mode: fails for policy violations (new stubs, unsupported
# reclassification) and malformed reports, while requiring status
# validation >= 80%.
#
# --strict: requires >= 95% status validation to pass.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$REPO_ROOT/target/conformance"
CANONICAL_REPORT="${FRANKENLIBC_MAINTENANCE_CANONICAL_REPORT:-$REPO_ROOT/tests/conformance/support_matrix_maintenance_report.v1.json}"
GENERATED_REPORT="$LOG_DIR/support_matrix_maintenance.generated.json"
LOG_FILE="$LOG_DIR/support_matrix_maintenance.log.jsonl"
TRACE_ID="bd-ldj.8-$(date -u +%Y%m%dT%H%M%SZ)-$$"
TRACE_SYMBOL_EVENTS="${FRANKENLIBC_SYMBOL_GATE_TRACE:-0}"

STRICT=false
if [[ "${1:-}" == "--strict" ]]; then
    STRICT=true
fi

echo "=== Support Matrix Maintenance Gate (bd-3g4p) ==="
mkdir -p "$LOG_DIR"

# 1. Run the maintenance validator
echo "--- Generating maintenance report ---"
python3 "$SCRIPT_DIR/generate_support_matrix_maintenance.py" -o "$GENERATED_REPORT"

if [ ! -f "$GENERATED_REPORT" ]; then
    echo "FAIL: maintenance report not generated"
    exit 1
fi

if [ ! -f "$CANONICAL_REPORT" ]; then
    echo "FAIL: canonical maintenance report missing at $CANONICAL_REPORT"
    exit 1
fi

# 2. Validate report structure, compare stable sections against the canonical
# artifact, emit logging, and check thresholds.
python3 - "$GENERATED_REPORT" "$CANONICAL_REPORT" "$STRICT" "$TRACE_ID" "$LOG_FILE" "$TRACE_SYMBOL_EVENTS" <<'PY'
import json, sys
from datetime import datetime, timezone

report_path = sys.argv[1]
canonical_path = sys.argv[2]
strict = sys.argv[3].strip().lower() == "true"
trace_id = sys.argv[4]
log_path = sys.argv[5]
trace_symbol_events = sys.argv[6].strip().lower() in ("1", "true", "yes", "on")
errors = 0
events = []
# These are the current-state sections that should match the checked-in
# canonical artifact. The generator's trend/reclassification fields are
# baseline-relative and intentionally excluded from strict equality.
stable_keys = [
    "schema_version",
    "bead",
    "summary",
    "coverage_dashboard",
    "status_distribution",
    "module_coverage",
    "symbol_status_map",
    "status_validation_issues",
    "unlinked_symbols",
]

def emit(level, event, symbol, outcome, errno_code, details):
    events.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "trace_id": trace_id,
            "level": level,
            "event": event,
            "mode": "classification_gate",
            "api_family": "symbols",
            "symbol": symbol,
            "outcome": outcome,
            "errno": int(errno_code),
            "artifact_refs": [report_path, canonical_path, log_path],
            "details": details,
        }
    )

with open(report_path) as f:
    report = json.load(f)
with open(canonical_path) as f:
    canonical = json.load(f)

generated_stable = {key: report.get(key) for key in stable_keys}
canonical_stable = {key: canonical.get(key) for key in stable_keys}
stable_diff_keys = [
    key for key in stable_keys if generated_stable.get(key) != canonical_stable.get(key)
]

emit(
    "info" if not stable_diff_keys else "error",
    "canonical_stable_sections",
    "all",
    "pass" if not stable_diff_keys else "fail",
    0 if not stable_diff_keys else 1,
    {
        "stable_keys": stable_keys,
        "excluded_baseline_relative_keys": [
            "generated_at",
            "trend",
            "reclassified_symbols",
            "policy_checks",
        ],
        "mismatched_keys": stable_diff_keys,
    },
)

if stable_diff_keys:
    print("FAIL: canonical maintenance report drift detected in stable sections")
    for key in stable_diff_keys[:10]:
        print(f"  - {key}")
    errors += 1

# Check required fields
summary = report.get("summary", {})
required = [
    "total_symbols", "status_validated", "status_invalid",
    "fixture_linked", "fixture_unlinked", "fixture_coverage_pct",
    "status_valid_pct",
]
for key in required:
    if key not in summary:
        print(f"FAIL: missing summary field '{key}'")
        errors += 1

coverage_dashboard = report.get("coverage_dashboard", {})
policy_checks = report.get("policy_checks", {})
trend = report.get("trend", {})

total = summary.get("total_symbols", 0)
valid = summary.get("status_validated", 0)
invalid = summary.get("status_invalid", 0)
linked = summary.get("fixture_linked", 0)
unlinked = summary.get("fixture_unlinked", 0)
valid_pct = summary.get("status_valid_pct", 0)
cov_pct = summary.get("fixture_coverage_pct", 0)

print(f"Total symbols: {total}")
print(f"Status validated: {valid}/{total} ({valid_pct}%)")
print(f"  Invalid: {invalid}")
print(f"Fixture linked: {linked}/{total} ({cov_pct}%)")
print(f"  Unlinked: {unlinked}")
emit(
    "info",
    "coverage_summary",
    "all",
    "pass",
    0,
    {
        "total_symbols": total,
        "status_validated": valid,
        "status_invalid": invalid,
        "fixture_linked": linked,
        "fixture_unlinked": unlinked,
        "status_valid_pct": valid_pct,
        "fixture_coverage_pct": cov_pct,
    },
)

if coverage_dashboard:
    status_counts = coverage_dashboard.get("status_counts", {})
    native_pct = coverage_dashboard.get("native_coverage_pct")
    print("\nCoverage dashboard:")
    print(
        f"  Implemented={status_counts.get('Implemented', 0)} "
        f"RawSyscall={status_counts.get('RawSyscall', 0)} "
        f"GlibcCallThrough={status_counts.get('GlibcCallThrough', 0)} "
        f"Stub={status_counts.get('Stub', 0)}"
    )
    print(f"  Native coverage (Implemented+RawSyscall): {native_pct}%")
    emit(
        "info",
        "status_counts",
        "all",
        "pass",
        0,
        {
            "implemented": status_counts.get("Implemented", 0),
            "raw_syscall": status_counts.get("RawSyscall", 0),
            "glibc_call_through": status_counts.get("GlibcCallThrough", 0),
            "stub": status_counts.get("Stub", 0),
            "native_coverage_pct": native_pct,
        },
    )

if trend:
    print("\nCoverage trend:")
    print(
        f"  Baseline loaded: {trend.get('baseline_loaded')} "
        f"({trend.get('baseline_report_path', 'n/a')})"
    )
    print(
        f"  Reclassified symbols: {trend.get('reclassified_symbol_count', 0)} "
        f"New symbols: {trend.get('new_symbol_count', 0)} "
        f"Removed symbols: {trend.get('removed_symbol_count', 0)}"
    )
    deltas = trend.get("status_count_delta", {})
    if isinstance(deltas, dict) and deltas:
        ordered = ", ".join(f"{k}={v:+d}" for k, v in sorted(deltas.items()))
        print(f"  Status deltas: {ordered}")

# Status distribution
dist = report.get("status_distribution", {})
if dist:
    print("\nStatus distribution:")
    for st, info in sorted(dist.items()):
        count = info.get("count", 0)
        fix = info.get("fixture_linked", 0)
        print(f"  {st:25s} {count:3d} symbols ({fix} with fixtures)")

# Module coverage
mod_cov = report.get("module_coverage", {})
if mod_cov:
    print(f"\nModule coverage ({len(mod_cov)} modules):")
    for mod_name, info in sorted(mod_cov.items()):
        t = info.get("total", 0)
        l = info.get("linked", 0)
        pct = info.get("coverage_pct", 0)
        bar = "█" * int(pct / 10) + "░" * (10 - int(pct / 10))
        print(f"  {mod_name:20s} {l:3d}/{t:3d} {bar} {pct}%")

# Show findings
issues = report.get("status_validation_issues", [])
if issues:
    print(f"\nStatus validation findings ({len(issues)}):")
    for iss in issues[:15]:
        findings_str = "; ".join(iss.get("findings", []))
        print(f"  {iss['symbol']:30s} ({iss['status']}) {findings_str}")
    for iss in issues:
        level = "warn" if iss.get("status") == "GlibcCallThrough" else "debug"
        emit(
            level,
            "status_validation_issue",
            iss.get("symbol", "<unknown>"),
            "warn",
            0,
            {
                "status": iss.get("status"),
                "module": iss.get("module"),
                "findings": iss.get("findings", []),
            },
        )

# Policy checks for bd-ldj.7
stub_policy = policy_checks.get("no_new_stub_symbols", {})
if stub_policy:
    status = stub_policy.get("status")
    prev_stub = stub_policy.get("previous_stub_count")
    curr_stub = stub_policy.get("current_stub_count")
    delta = stub_policy.get("delta")
    print(
        f"\nPolicy no_new_stub_symbols: {status} "
        f"(previous={prev_stub}, current={curr_stub}, delta={delta:+d})"
    )
    emit(
        "info" if status == "pass" else "error",
        "policy_no_new_stub_symbols",
        "all",
        status,
        0 if status == "pass" else 1,
        {
            "previous_stub_count": prev_stub,
            "current_stub_count": curr_stub,
            "delta": delta,
        },
    )
    if status != "pass":
        errors += 1
        print("FAIL: no_new_stub_symbols policy violation")

reclass_policy = policy_checks.get("reclassification_requires_conformance", {})
if reclass_policy:
    status = reclass_policy.get("status")
    total_reclassified = reclass_policy.get("total_reclassified", 0)
    violations = reclass_policy.get("violations", [])
    print(
        f"Policy reclassification_requires_conformance: {status} "
        f"(reclassified={total_reclassified}, violations={len(violations)})"
    )
    emit(
        "info" if status == "pass" else "error",
        "policy_reclassification_requires_conformance",
        "all",
        status,
        0 if status == "pass" else 1,
        {
            "reclassified": total_reclassified,
            "violations": len(violations),
            "baseline_symbol_map_loaded": reclass_policy.get("baseline_symbol_map_loaded"),
        },
    )
    if status != "pass":
        errors += 1
        print("FAIL: reclassification_requires_conformance policy violation")
        for row in violations[:10]:
            symbol = row.get("symbol", "<unknown>")
            prev_status = row.get("previous_status", "<unknown>")
            current_status = row.get("current_status", "<unknown>")
            missing = ", ".join(row.get("missing_evidence", []))
            print(
                f"  - {symbol}: {prev_status} -> {current_status} "
                f"(missing: {missing})"
            )
            emit(
                "error",
                "reclassification_violation",
                symbol,
                "fail",
                1,
                {
                    "previous_status": prev_status,
                    "current_status": current_status,
                    "missing_evidence": row.get("missing_evidence", []),
                },
            )

if trace_symbol_events:
    symbol_map = report.get("symbol_status_map", {})
    if isinstance(symbol_map, dict):
        for symbol, status_name in sorted(symbol_map.items()):
            emit(
                "trace",
                "symbol_status_snapshot",
                symbol,
                "pass",
                0,
                {"status": status_name},
            )

# Threshold checks
threshold = 95.0 if strict else 80.0
if valid_pct < threshold:
    print(f"\nFAIL: status validation {valid_pct}% below {threshold}% threshold")
    errors += 1

if total == 0:
    print("\nFAIL: no symbols in matrix")
    errors += 1

emit(
    "error" if errors > 0 else "info",
    "gate_result",
    "all",
    "fail" if errors > 0 else "pass",
    1 if errors > 0 else 0,
    {"errors": errors, "strict_mode": strict},
)

with open(log_path, "w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")

print(f"\nStructured log: {log_path}")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

mode = "strict" if strict else "default"
print(f"\ncheck_support_matrix_maintenance ({mode}): PASS")
PY
