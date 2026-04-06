#!/usr/bin/env bash
# check_cve_corpus.sh — validate CVE arena corpus integrity (bd-1m5.5)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="${ROOT}/tests/cve_arena/corpus_index.v1.json"
ARENA="${ROOT}/tests/cve_arena"
OUT_DIR="${ROOT}/target/conformance/cve_corpus"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="${OUT_DIR}/${RUN_ID}_report.json"
TRACE="${OUT_DIR}/${RUN_ID}_trace.jsonl"
mkdir -p "${OUT_DIR}"

echo "=== CVE corpus validation (bd-1m5.5) ==="
echo "corpus_index: ${CORPUS}"
echo "run_id: ${RUN_ID}"

python3 << PYEOF
import json, os, sys, hashlib, time

root = "${ROOT}"
corpus_path = "${CORPUS}"
arena_path = "${ARENA}"
report_path = "${REPORT}"
trace_path = "${TRACE}"
run_id = "${RUN_ID}"

with open(corpus_path) as f:
    corpus = json.load(f)

scenarios = corpus.get("scenarios", [])
schema = corpus.get("metadata_schema", {})
required = set(schema.get("required_fields", []))
feature_vocab = set(schema.get("tsm_feature_vocabulary", []))

errors = []
warnings = []
traces = []

for sc in scenarios:
    cve = sc.get("cve_id", "?")
    directory = sc.get("directory", "")
    sc_path = os.path.join(arena_path, directory)

    trace_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trace_id": f"bd-1m5.5::{run_id}::{cve}",
        "cve_id": cve,
        "mode": "validation",
        "api_family": "cve_arena",
        "symbol": sc.get("affected_component", "?"),
        "checks": {}
    }

    # Check required fields
    missing = required - set(sc.keys())
    if missing:
        errors.append(f"{cve}: missing required fields: {missing}")
        trace_entry["checks"]["required_fields"] = "FAIL"
    else:
        trace_entry["checks"]["required_fields"] = "PASS"

    # Check directory exists
    if not os.path.isdir(sc_path):
        errors.append(f"{cve}: directory not found: {sc_path}")
        trace_entry["checks"]["directory"] = "FAIL"
    else:
        trace_entry["checks"]["directory"] = "PASS"

    # Check trigger file exists
    trigger = sc.get("trigger_file", "trigger.c")
    trigger_path = os.path.join(sc_path, trigger)
    if os.path.isdir(sc_path) and not os.path.isfile(trigger_path):
        errors.append(f"{cve}: trigger file not found: {trigger_path}")
        trace_entry["checks"]["trigger_file"] = "FAIL"
    elif os.path.isfile(trigger_path):
        trace_entry["checks"]["trigger_file"] = "PASS"

    # Check manifest.json matches corpus index
    manifest_path = os.path.join(sc_path, "manifest.json")
    if os.path.isfile(manifest_path):
        with open(manifest_path) as mf:
            manifest = json.load(mf)
        if manifest.get("cve_id") != cve:
            errors.append(f"{cve}: manifest cve_id mismatch: {manifest.get('cve_id')}")
            trace_entry["checks"]["manifest_match"] = "FAIL"
        else:
            trace_entry["checks"]["manifest_match"] = "PASS"

    # Check TSM features are from vocabulary
    features = set(sc.get("tsm_features_tested", []))
    unknown = features - feature_vocab
    if unknown:
        warnings.append(f"{cve}: unknown TSM features: {unknown}")
        trace_entry["checks"]["feature_vocab"] = "WARN"
    else:
        trace_entry["checks"]["feature_vocab"] = "PASS"

    # Check CVSS score is valid
    cvss = sc.get("cvss_score", 0)
    if not (0 <= cvss <= 10):
        errors.append(f"{cve}: invalid CVSS score: {cvss}")
        trace_entry["checks"]["cvss_valid"] = "FAIL"
    else:
        trace_entry["checks"]["cvss_valid"] = "PASS"

    traces.append(trace_entry)

# Write trace
with open(trace_path, "w") as tf:
    for t in traces:
        tf.write(json.dumps(t) + "\n")

# Summary
total = len(scenarios)
pass_count = total - len(errors)
status = "PASS" if not errors else "FAIL"

report = {
    "schema_version": "v1",
    "run_id": run_id,
    "corpus_file": corpus_path,
    "total_scenarios": total,
    "pass_count": pass_count,
    "error_count": len(errors),
    "warning_count": len(warnings),
    "errors": errors,
    "warnings": warnings,
    "status": status
}
with open(report_path, "w") as rf:
    json.dump(report, indent=2, fp=rf)

print(f"Scenarios: {total}")
print(f"Pass: {pass_count}, Errors: {len(errors)}, Warnings: {len(warnings)}")
for e in errors:
    print(f"  ERROR: {e}")
for w in warnings:
    print(f"  WARN: {w}")
print(f"Trace: {trace_path}")
print(f"Report: {report_path}")
print(f"check_cve_corpus: {status}")

if errors:
    sys.exit(1)
PYEOF

echo "=== done ==="
