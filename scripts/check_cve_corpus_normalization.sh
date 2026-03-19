#!/usr/bin/env bash
# check_cve_corpus_normalization.sh — CI gate for bd-1m5.5
# Validates CVE corpus normalization and deterministic scenario metadata.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/cve_arena/results/corpus_normalization.v1.json"
LOG="$REPO_ROOT/tests/cve_arena/results/corpus_normalization.log.jsonl"

echo "=== CVE Corpus Normalization Gate (bd-1m5.5) ==="

echo "--- Generating corpus normalization report ---"
python3 "$SCRIPT_DIR/generate_cve_corpus_normalization.py" \
    -o "$REPORT" \
    --log "$LOG" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: normalization report not generated"
    exit 1
fi
if [ ! -f "$LOG" ]; then
    echo "FAIL: normalization structured log not generated"
    exit 1
fi

python3 - "$REPORT" "$LOG" <<'PY'
import json, sys

report_path = sys.argv[1]
log_path = sys.argv[2]
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
    "bead_id",
    "cve_id",
    "event",
    "expected_outcome",
    "manifest_path",
    "manifest_sha256",
    "mode",
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
else:
    print("PASS: scenario log entries include required structured fields")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_cve_corpus_normalization: PASS")
PY
