#!/usr/bin/env bash
# check_cve_corpus_normalization.sh — CI gate for bd-1m5.5
# Validates CVE corpus normalization and deterministic scenario metadata.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="${FRANKENLIBC_CVE_CORPUS_NORMALIZATION_REPORT:-$REPO_ROOT/tests/cve_arena/results/corpus_normalization.v1.json}"
LOG="${FRANKENLIBC_CVE_CORPUS_NORMALIZATION_LOG:-$REPO_ROOT/tests/cve_arena/results/corpus_normalization.log.jsonl}"
TIMESTAMP="${FRANKENLIBC_CVE_CORPUS_NORMALIZATION_TIMESTAMP:-2026-05-10T00:00:00Z}"

echo "=== CVE Corpus Normalization Gate (bd-1m5.5) ==="

echo "--- Generating corpus normalization report ---"
python3 "$SCRIPT_DIR/generate_cve_corpus_normalization.py" \
    -o "$REPORT" \
    --log "$LOG" \
    --timestamp "$TIMESTAMP" 2>&1

if [ ! -f "$REPORT" ]; then
    echo "FAIL: normalization report not generated"
    exit 1
fi
if [ ! -f "$LOG" ]; then
    echo "FAIL: normalization structured log not generated"
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
corpus = report.get("corpus_index", [])
norm_changes = report.get("normalization_changes", [])

total = summary.get("total_cve_tests", 0)
valid = summary.get("manifests_valid", 0)
with_triggers = summary.get("with_trigger_files", 0)
issues = summary.get("total_issues", 0)
needing_norm = summary.get("manifests_needing_normalization", 0)
vuln_classes = summary.get("vulnerability_classes", [])
healing = summary.get("unique_healing_actions", [])
cwes = summary.get("unique_cwe_ids", [])
categories = summary.get("categories", {})

print(f"CVE corpus:             {total} tests")
print(f"  Manifests valid:      {valid}/{total}")
print(f"  With triggers:        {with_triggers}/{total}")
print(f"  Issues:               {issues}")
print(f"  Need normalization:   {needing_norm}/{total}")
print(f"  Vulnerability classes: {', '.join(vuln_classes)}")
print(f"  Healing actions:      {', '.join(healing)}")
print(f"  CWE coverage:         {len(cwes)} unique CWEs")
print(f"  Categories:           {categories}")
print(f"  Structured log:       {log_path} ({len(log_entries)} entries)")

print("\nCorpus entries:")
for entry in corpus:
    status = "VALID" if entry["manifest_valid"] else "INVALID"
    classes = ", ".join(entry["vulnerability_classes"])
    replay = entry.get("replay", {}).get("replay_key", "?")
    norm = len(entry.get("normalization_changes", []))
    print(f"  {entry['cve_id']:35s} CVSS={entry.get('cvss_score', '?'):>4}  {status}  classes=[{classes}]  replay={replay}  norm_changes={norm}")

if norm_changes:
    print(f"\nNormalization changes needed: {len(norm_changes)} manifests")
    for nc in norm_changes:
        changes = "; ".join(nc["changes"])
        print(f"  {nc['cve_id']:35s} {changes}")

print("")

# Validation checks
if valid < total:
    print(f"FAIL: {total - valid} invalid manifest(s)")
    errors += 1
else:
    print(f"PASS: All {total} manifests valid")

if with_triggers < total:
    print(f"FAIL: {total - with_triggers} test(s) missing triggers")
    errors += 1
else:
    print(f"PASS: All {total} tests have trigger files")

# Each entry must have a replay key
missing_replay = [e for e in corpus if not e.get("replay", {}).get("replay_key")]
if missing_replay:
    print(f"FAIL: {len(missing_replay)} entries missing replay_key")
    errors += 1
else:
    print(f"PASS: All {total} entries have replay keys")

# Each entry must have vulnerability_classes
missing_classes = [e for e in corpus if not e.get("vulnerability_classes") or e["vulnerability_classes"] == ["unknown"]]
if missing_classes:
    ids = [e["cve_id"] for e in missing_classes]
    print(f"FAIL: {len(missing_classes)} entries with unknown vulnerability class: {', '.join(ids)}")
    errors += 1
else:
    print(f"PASS: All {total} entries have vulnerability classification")

# Each entry must have expected outcomes for both modes
missing_outcomes = []
for e in corpus:
    replay = e.get("replay", {})
    strict = replay.get("expected_strict", {})
    hardened = replay.get("expected_hardened", {})
    if "crashes" not in strict or "crashes" not in hardened:
        missing_outcomes.append(e["cve_id"])
if missing_outcomes:
    print(f"FAIL: {len(missing_outcomes)} entries missing mode outcome expectations")
    errors += 1
else:
    print(f"PASS: All {total} entries have strict+hardened expected outcomes")

# Must have at least 3 vulnerability classes
if len(vuln_classes) < 3:
    print(f"FAIL: Only {len(vuln_classes)} vulnerability classes (need >= 3)")
    errors += 1
else:
    print(f"PASS: {len(vuln_classes)} vulnerability classes covered")

# Must have at least 3 healing actions
if len(healing) < 3:
    print(f"FAIL: Only {len(healing)} healing actions (need >= 3)")
    errors += 1
else:
    print(f"PASS: {len(healing)} healing actions exercised")

if total == 0:
    print("FAIL: No CVE tests found")
    errors += 1

expected_log_entries = total * 2 + 1
if len(log_entries) != expected_log_entries:
    print(
        f"FAIL: structured log entry count mismatch "
        f"(expected {expected_log_entries}, got {len(log_entries)})"
    )
    errors += 1
else:
    print(f"PASS: structured log has {expected_log_entries} deterministic entries")

required_log_fields = {
    "api_family",
    "artifact_refs",
    "bead_id",
    "completion_debt_bead",
    "cve_id",
    "event",
    "expected_outcome",
    "failure_signature",
    "fuzz_seed_id",
    "manifest_path",
    "manifest_sha256",
    "mode",
    "outcome",
    "parent_bead",
    "replay_key",
    "scenario_id",
    "timestamp",
    "trace_id",
}
scenario_entries = [e for e in log_entries if e.get("event") == "scenario_expectation"]
for entry in scenario_entries:
    missing = sorted(field for field in required_log_fields if field not in entry)
    if missing:
        print(f"FAIL: structured log entry missing fields {missing}: {entry}")
        errors += 1
        break
    if entry.get("bead_id") != "bd-1m5.5":
        print(f"FAIL: scenario log bead_id drifted: {entry}")
        errors += 1
        break
    if entry.get("completion_debt_bead") != "bd-1m5.5.1":
        print(f"FAIL: scenario log completion_debt_bead drifted: {entry}")
        errors += 1
        break
    if entry.get("parent_bead") != "bd-1m5.5":
        print(f"FAIL: scenario log parent_bead drifted: {entry}")
        errors += 1
        break
    if not isinstance(entry.get("artifact_refs"), list) or not entry["artifact_refs"]:
        print(f"FAIL: scenario log artifact_refs must be non-empty: {entry}")
        errors += 1
        break
    if entry.get("outcome") != "expected":
        print(f"FAIL: scenario log outcome must be expected: {entry}")
        errors += 1
        break
    if entry.get("failure_signature") != "none":
        print(f"FAIL: scenario log failure_signature must be none: {entry}")
        errors += 1
        break
else:
    print("PASS: scenario log entries include required structured fields")

summary_entries = [e for e in log_entries if e.get("event") == "corpus_summary"]
if len(summary_entries) != 1:
    print(f"FAIL: expected exactly one corpus_summary telemetry row, got {len(summary_entries)}")
    errors += 1
else:
    summary_entry = summary_entries[0]
    if summary_entry.get("completion_debt_bead") != "bd-1m5.5.1":
        print("FAIL: corpus_summary completion_debt_bead drifted")
        errors += 1
    elif summary_entry.get("outcome") != "pass":
        print("FAIL: corpus_summary outcome must be pass")
        errors += 1
    elif summary_entry.get("failure_signature") != "none":
        print("FAIL: corpus_summary failure_signature must be none")
        errors += 1
    else:
        print("PASS: corpus_summary telemetry row binds completion-debt outcome")

fuzz_required_fields = {
    "seed_payload_schema",
    "seed_id",
    "seed_sha256",
    "mutation_axes",
    "replay_modes",
    "source_manifest_fields",
}
for entry in corpus:
    fuzz_seed = entry.get("fuzz_replay_seed")
    replay_key = entry.get("replay", {}).get("replay_key")
    cve_id = entry.get("cve_id", "unknown")
    if not isinstance(fuzz_seed, dict):
        print(f"FAIL: {cve_id} missing fuzz_replay_seed object")
        errors += 1
        continue
    missing = sorted(field for field in fuzz_required_fields if field not in fuzz_seed)
    if missing:
        print(f"FAIL: {cve_id} fuzz_replay_seed missing fields {missing}")
        errors += 1
    if fuzz_seed.get("seed_payload_schema") != "cve-arena-fuzz-seed/v1":
        print(f"FAIL: {cve_id} fuzz seed schema drifted")
        errors += 1
    if fuzz_seed.get("seed_id") != f"cve_arena:{replay_key}":
        print(f"FAIL: {cve_id} fuzz seed_id does not bind replay_key")
        errors += 1
    seed_hash = fuzz_seed.get("seed_sha256", "")
    if len(seed_hash) != 64 or not all(ch in "0123456789abcdef" for ch in seed_hash):
        print(f"FAIL: {cve_id} fuzz seed_sha256 must be 64 lowercase hex chars")
        errors += 1
    if fuzz_seed.get("replay_modes") != ["strict", "hardened"]:
        print(f"FAIL: {cve_id} fuzz replay_modes drifted")
        errors += 1
    axes = set(fuzz_seed.get("mutation_axes", []))
    for axis in ["mode", "category", "cwe_ids", "trigger_files", "healing_actions"]:
        if axis not in axes:
            print(f"FAIL: {cve_id} fuzz mutation_axes missing {axis}")
            errors += 1
else:
    if errors == 0:
        print("PASS: all corpus entries define deterministic fuzz replay seeds")

completion = report.get("completion_debt_evidence")
if not isinstance(completion, dict):
    print("FAIL: completion_debt_evidence must be an object")
    errors += 1
else:
    if completion.get("bead") != "bd-1m5.5.1":
        print("FAIL: completion_debt_evidence.bead must be bd-1m5.5.1")
        errors += 1
    if completion.get("original_bead") != "bd-1m5.5":
        print("FAIL: completion_debt_evidence.original_bead must be bd-1m5.5")
        errors += 1

    test_source = completion.get("test_source")
    test_source_text = ""
    if not isinstance(test_source, str) or not test_source:
        print("FAIL: completion_debt_evidence.test_source must be non-empty")
        errors += 1
    else:
        test_source_path = repo_root / test_source
        if not test_source_path.is_file():
            print(f"FAIL: test source missing: {test_source}")
            errors += 1
        else:
            test_source_text = test_source_path.read_text(encoding="utf-8")

    expected_sections = {
        "unit_primary": "tests.unit.primary",
        "e2e_primary": "tests.e2e.primary",
        "fuzz_primary": "tests.fuzz.primary",
        "conformance_primary": "tests.conformance.primary",
        "telemetry_primary": "telemetry.primary",
    }
    for section_name, missing_item_id in expected_sections.items():
        section = completion.get(section_name)
        if not isinstance(section, dict):
            print(f"FAIL: completion_debt_evidence.{section_name} must be an object")
            errors += 1
            continue
        if section.get("missing_item_id") != missing_item_id:
            print(f"FAIL: {section_name}.missing_item_id must be {missing_item_id}")
            errors += 1
        required_tests = section.get("required_test_names", [])
        if not isinstance(required_tests, list) or not required_tests:
            print(f"FAIL: {section_name}.required_test_names must be non-empty")
            errors += 1
            continue
        for test_name in required_tests:
            if not isinstance(test_name, str) or not test_name:
                print(f"FAIL: {section_name} contains invalid test name")
                errors += 1
            elif f"fn {test_name}(" not in test_source_text:
                print(f"FAIL: {section_name} references missing test {test_name}")
                errors += 1

    fuzz_primary = completion.get("fuzz_primary", {})
    if fuzz_primary.get("required_entry_field") != "fuzz_replay_seed":
        print("FAIL: fuzz_primary.required_entry_field must be fuzz_replay_seed")
        errors += 1
    seed_fields = fuzz_primary.get("required_seed_fields", [])
    missing_seed_fields = sorted(fuzz_required_fields - set(seed_fields))
    if missing_seed_fields:
        print(f"FAIL: fuzz_primary.required_seed_fields missing {missing_seed_fields}")
        errors += 1

    telemetry = completion.get("telemetry_primary", {})
    if telemetry.get("default_report_path") != "tests/cve_arena/results/corpus_normalization.v1.json":
        print("FAIL: telemetry_primary.default_report_path drifted")
        errors += 1
    if telemetry.get("default_log_path") != "tests/cve_arena/results/corpus_normalization.log.jsonl":
        print("FAIL: telemetry_primary.default_log_path drifted")
        errors += 1
    expected_events = {"scenario_expectation", "corpus_summary"}
    if set(telemetry.get("required_events", [])) != expected_events:
        print("FAIL: telemetry_primary.required_events drifted")
        errors += 1
    required_fields = set(telemetry.get("required_fields", []))
    missing_telemetry_fields = sorted(required_log_fields - required_fields)
    if missing_telemetry_fields:
        print(f"FAIL: telemetry_primary.required_fields missing {missing_telemetry_fields}")
        errors += 1

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_cve_corpus_normalization: PASS")
PY
