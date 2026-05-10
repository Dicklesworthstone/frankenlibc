#!/usr/bin/env bash
# check_cve_paired_mode_runner.sh — CI gate for bd-1m5.7
# Validates strict detection assertions + paired-mode CVE evidence runner.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="${FRANKENLIBC_CVE_PAIRED_MODE_REPORT:-$REPO_ROOT/tests/cve_arena/results/paired_mode_evidence.v1.json}"
LOG="${FRANKENLIBC_CVE_PAIRED_MODE_LOG:-$REPO_ROOT/tests/cve_arena/results/paired_mode_evidence.log.jsonl}"
TIMESTAMP="${FRANKENLIBC_CVE_PAIRED_MODE_TIMESTAMP:-2026-05-10T00:00:00Z}"

echo "=== CVE Paired-Mode Evidence Runner Gate (bd-1m5.7) ==="

echo "--- Generating paired-mode evidence report ---"
python3 "$SCRIPT_DIR/generate_cve_paired_mode_runner.py" \
    -o "$REPORT" \
    --log "$LOG" \
    --timestamp "$TIMESTAMP" 2>&1

if [ ! -f "$REPORT" ]; then
    echo "FAIL: paired-mode evidence report not generated"
    exit 1
fi
if [ ! -f "$LOG" ]; then
    echo "FAIL: paired-mode structured log not generated"
    exit 1
fi

python3 - "$REPORT" "$LOG" "$REPO_ROOT" <<'PY'
import json, pathlib, sys

report_path = sys.argv[1]
log_path = sys.argv[2]
repo_root = pathlib.Path(sys.argv[3])
errors = 0

with open(report_path) as f:
    report = json.load(f)
with open(log_path, encoding="utf-8") as f:
    log_entries = [json.loads(line) for line in f if line.strip()]

summary = report.get("summary", {})
evidence = report.get("paired_evidence", [])
val_issues = report.get("validation_issues", [])

total = summary.get("total_paired_scenarios", 0)
strict_detected = summary.get("strict_detected", 0)
hardened_prevented = summary.get("hardened_prevented", 0)
with_flags = summary.get("with_detection_flags", 0)
detection_flags = summary.get("unique_detection_flags", [])
dossier_count = summary.get("unique_dossier_ids", 0)
val_errors = summary.get("validation_errors", 0)
val_warnings = summary.get("validation_warnings", 0)
completion = report.get("completion_debt_evidence", {})

print(f"Paired scenarios:        {total}")
print(f"  Strict detected:       {strict_detected}/{total}")
print(f"  Hardened prevented:    {hardened_prevented}/{total}")
print(f"  With detection flags:  {with_flags}/{total}")
print(f"  Detection flags:       {len(detection_flags)} unique")
print(f"  Dossier IDs:           {dossier_count} unique")
print(f"  Validation errors:     {val_errors}")
print(f"  Validation warnings:   {val_warnings}")
print(f"  Structured log:        {log_path} ({len(log_entries)} entries)")

print("\nPaired evidence matrix:")
for e in evidence:
    s_verdict = e["strict_mode"]["verdict"]
    h_verdict = e["hardened_mode"]["verdict"]
    n_flags = len(e["strict_mode"]["detection_flags"])
    healing = ", ".join(e["hardened_mode"]["healing_actions"])
    print(f"  {e['cve_id']:35s} CVSS={e.get('cvss_score', '?'):>4}  strict={s_verdict:10s}  hardened={h_verdict:10s}  flags={n_flags}  healing=[{healing}]")

if val_issues:
    print(f"\nValidation issues:")
    for issue in val_issues:
        print(f"  [{issue['severity']}] {issue['cve_id']}: {issue['issue']}")

print("")

# All strict must be "detected"
if strict_detected < total:
    undetected = [e["cve_id"] for e in evidence if e["strict_mode"]["verdict"] != "detected"]
    print(f"FAIL: {total - strict_detected} CVE(s) not detected in strict mode: {', '.join(undetected)}")
    errors += 1
else:
    print(f"PASS: All {total} CVEs detected in strict mode")

# All hardened must be "prevented"
if hardened_prevented < total:
    vulnerable = [e["cve_id"] for e in evidence if e["hardened_mode"]["verdict"] != "prevented"]
    print(f"FAIL: {total - hardened_prevented} CVE(s) not prevented in hardened mode: {', '.join(vulnerable)}")
    errors += 1
else:
    print(f"PASS: All {total} CVEs prevented in hardened mode")

# All must have detection flags
if with_flags < total:
    missing = [e["cve_id"] for e in evidence if not e["strict_mode"]["detection_flags"]]
    print(f"FAIL: {total - with_flags} CVE(s) missing detection flags: {', '.join(missing)}")
    errors += 1
else:
    print(f"PASS: All {total} CVEs have strict detection flags")

# All must have unique dossier IDs
if dossier_count < total:
    print(f"FAIL: Only {dossier_count} unique dossier IDs for {total} scenarios")
    errors += 1
else:
    print(f"PASS: All {total} scenarios have unique dossier IDs")

# Evidence bundles must be joinable
joinable = all(
    set(["dossier_id", "cve_id", "test_name"]).issubset(set(e["evidence_bundle"]["joinable_on"]))
    for e in evidence
)
if not joinable:
    print("FAIL: Evidence bundles not joinable on required fields")
    errors += 1
else:
    print(f"PASS: All evidence bundles joinable on dossier_id/cve_id/test_name")

# No validation errors
if val_errors > 0:
    print(f"FAIL: {val_errors} validation error(s)")
    errors += 1
else:
    print(f"PASS: No validation errors")

if total == 0:
    print("FAIL: No paired scenarios found")
    errors += 1

if completion.get("bead") != "bd-1m5.7.1":
    print("FAIL: completion_debt_evidence.bead drifted")
    errors += 1
if completion.get("original_bead") != "bd-1m5.7":
    print("FAIL: completion_debt_evidence.original_bead drifted")
    errors += 1

test_source = completion.get("test_source")
test_source_text = ""
if not isinstance(test_source, str) or not test_source:
    print("FAIL: completion_debt_evidence.test_source missing")
    errors += 1
else:
    test_source_path = repo_root / test_source
    if not test_source_path.is_file():
        print(f"FAIL: completion_debt_evidence.test_source not found: {test_source}")
        errors += 1
    else:
        test_source_text = test_source_path.read_text(encoding="utf-8")

for section, missing_item in [
    ("unit_primary", "tests.unit.primary"),
    ("e2e_primary", "tests.e2e.primary"),
    ("fuzz_primary", "tests.fuzz.primary"),
    ("conformance_primary", "tests.conformance.primary"),
    ("telemetry_primary", "telemetry.primary"),
]:
    section_data = completion.get(section, {})
    if section_data.get("missing_item_id") != missing_item:
        print(f"FAIL: completion_debt_evidence.{section}.missing_item_id drifted")
        errors += 1
        continue
    test_names = section_data.get("required_test_names", [])
    if not isinstance(test_names, list) or not test_names:
        print(f"FAIL: completion_debt_evidence.{section}.required_test_names missing")
        errors += 1
        continue
    for test_name in test_names:
        if f"fn {test_name}(" not in test_source_text:
            print(f"FAIL: completion_debt_evidence.{section} references missing test {test_name}")
            errors += 1
            break

seed_fields = set(completion.get("fuzz_primary", {}).get("required_seed_fields", []))
for entry in evidence:
    seed = entry.get("paired_fuzz_seed", {})
    missing_seed_fields = sorted(field for field in seed_fields if field not in seed)
    if missing_seed_fields:
        print(f"FAIL: {entry['cve_id']} paired_fuzz_seed missing fields {missing_seed_fields}")
        errors += 1
        break
    if seed.get("seed_payload_schema") != "cve-paired-mode-fuzz-seed/v1":
        print(f"FAIL: {entry['cve_id']} paired_fuzz_seed schema drifted")
        errors += 1
        break

required_log_fields = set(completion.get("telemetry_primary", {}).get("required_fields", []))
expected_log_entries = total + 1
if len(log_entries) != expected_log_entries:
    print(f"FAIL: structured log entry count mismatch (expected {expected_log_entries}, got {len(log_entries)})")
    errors += 1
else:
    print(f"PASS: structured log has {expected_log_entries} deterministic entries")

scenario_entries = [entry for entry in log_entries if entry.get("event") == "paired_mode_scenario"]
summary_entries = [entry for entry in log_entries if entry.get("event") == "paired_mode_summary"]
for entry in scenario_entries:
    missing = sorted(field for field in required_log_fields if field not in entry)
    if missing:
        print(f"FAIL: structured scenario log missing fields {missing}: {entry}")
        errors += 1
        break
    if entry.get("bead_id") != "bd-1m5.7" or entry.get("completion_debt_bead") != "bd-1m5.7.1":
        print(f"FAIL: structured scenario log bead IDs drifted: {entry}")
        errors += 1
        break
    if entry.get("outcome") != "expected" or entry.get("failure_signature") != "none":
        print(f"FAIL: structured scenario log outcome/failure drifted: {entry}")
        errors += 1
        break
else:
    print("PASS: scenario log entries include required structured fields")

if len(summary_entries) != 1:
    print(f"FAIL: expected exactly one paired_mode_summary telemetry row, got {len(summary_entries)}")
    errors += 1
elif summary_entries[0].get("completion_debt_bead") != "bd-1m5.7.1" or summary_entries[0].get("outcome") != "pass":
    print("FAIL: paired_mode_summary telemetry row drifted")
    errors += 1
else:
    print("PASS: paired_mode_summary telemetry row is present")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_cve_paired_mode_runner: PASS")
PY
