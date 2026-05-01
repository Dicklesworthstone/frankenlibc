#!/usr/bin/env bash
# check_feature_parity_gap_groups.sh -- CI gate for bd-bp8fl.3.1
#
# Validates that feature_parity_gap_groups.v1.json covers every unresolved
# feature-parity ledger gap exactly once and emits deterministic report/log
# artifacts under target/conformance.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${ROOT}/tests/conformance/feature_parity_gap_groups.v1.json"
LEDGER="${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/feature_parity_gap_groups.report.json"
LOG="${OUT_DIR}/feature_parity_gap_groups.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${ARTIFACT}" "${LEDGER}" "${REPORT}" "${LOG}" <<'PY'
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
ledger_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])

errors = []
checks = {}

def load_json(path):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return None

artifact = load_json(artifact_path)
ledger = load_json(ledger_path)
checks["json_parse"] = "pass" if artifact is not None and ledger is not None else "fail"

batches = artifact.get("batches", []) if isinstance(artifact, dict) else []
ledger_gaps = ledger.get("gaps", []) if isinstance(ledger, dict) else []
ledger_ids = [gap.get("gap_id") for gap in ledger_gaps if gap.get("gap_id")]

if artifact and artifact.get("schema_version") == "v1" and artifact.get("bead") == "bd-bp8fl.3.1":
    checks["top_level_shape"] = "pass"
else:
    checks["top_level_shape"] = "fail"
    errors.append("artifact must declare schema_version=v1 and bead=bd-bp8fl.3.1")

required_batch_fields = [
    "batch_id",
    "title",
    "feature_parity_sections",
    "symbol_family",
    "evidence_artifacts",
    "source_owner",
    "priority",
    "gap_count",
    "gap_ids",
    "actionable_next_step",
]
for batch in batches:
    batch_id = batch.get("batch_id", "<missing batch_id>")
    for field in required_batch_fields:
        if field not in batch:
            errors.append(f"{batch_id}: missing field {field}")
    if len(batch.get("gap_ids", [])) != batch.get("gap_count"):
        errors.append(f"{batch_id}: gap_count does not match gap_ids length")
    if not batch.get("feature_parity_sections"):
        errors.append(f"{batch_id}: feature_parity_sections must not be empty")
    if not batch.get("evidence_artifacts"):
        errors.append(f"{batch_id}: evidence_artifacts must not be empty")
checks["batch_schema"] = "fail" if any(": missing field" in e or "must not be empty" in e or "gap_count" in e for e in errors) else "pass"

batch_ids = [batch.get("batch_id") for batch in batches]
checks["unique_batch_ids"] = "pass" if len(batch_ids) == len(set(batch_ids)) else "fail"
if checks["unique_batch_ids"] == "fail":
    errors.append("batch ids must be unique")

batched_ids = [gap_id for batch in batches for gap_id in batch.get("gap_ids", [])]
batched_counter = Counter(batched_ids)
ledger_set = set(ledger_ids)
batched_set = set(batched_ids)
duplicates = sorted([gap_id for gap_id, count in batched_counter.items() if count > 1])
missing = sorted(ledger_set - batched_set)
extra = sorted(batched_set - ledger_set)

if not duplicates and not missing and not extra:
    checks["exact_gap_coverage"] = "pass"
else:
    checks["exact_gap_coverage"] = "fail"
    if duplicates:
        errors.append("duplicate batched gap ids: " + ", ".join(duplicates))
    if missing:
        errors.append("missing ledger gap ids: " + ", ".join(missing))
    if extra:
        errors.append("unknown batched gap ids: " + ", ".join(extra))

section_counts = Counter()
for gap in ledger_gaps:
    section = gap.get("section") or "machine_delta"
    section_counts[section] += 1

summary = artifact.get("summary", {}) if isinstance(artifact, dict) else {}
summary_ok = (
    summary.get("ledger_gap_count") == len(ledger_ids)
    and summary.get("batched_gap_count") == len(batched_ids)
    and summary.get("batch_count") == len(batches)
    and summary.get("duplicate_gap_count") == len(duplicates)
    and summary.get("unbatched_gap_count") == len(missing)
    and summary.get("by_feature_parity_section") == dict(section_counts)
)
checks["summary_counts"] = "pass" if summary_ok else "fail"
if not summary_ok:
    errors.append("summary counts do not match ledger and batch coverage")

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
    "bead": "bd-bp8fl.3.1",
    "status": status,
    "checks": checks,
    "ledger_gap_count": len(ledger_ids),
    "batch_count": len(batches),
    "batched_gap_count": len(batched_ids),
    "duplicate_gap_count": len(duplicates),
    "unbatched_gap_count": len(missing),
    "extra_gap_count": len(extra),
    "section_counts": dict(section_counts),
    "errors": errors,
    "artifact_refs": [
        "tests/conformance/feature_parity_gap_groups.v1.json",
        "tests/conformance/feature_parity_gap_ledger.v1.json",
    ],
    "source_commit": source_commit,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

event = {
    "trace_id": "bd-bp8fl.3.1-feature-parity-gap-groups",
    "bead_id": "bd-bp8fl.3.1",
    "scenario_id": "feature-parity-gap-grouping-gate",
    "runtime_mode": "not_applicable",
    "replacement_level": "L0_interpose_and_L1_planning",
    "api_family": "feature_parity_gap_ledger",
    "symbol": "*",
    "oracle_kind": "ledger_exact_cover_grouping",
    "expected": "111 ledger gaps covered exactly once",
    "actual": status,
    "errno": None,
    "decision_path": list(checks.keys()),
    "healing_action": "none",
    "latency_ns": 0,
    "artifact_refs": report["artifact_refs"] + [
        "target/conformance/feature_parity_gap_groups.report.json",
        "target/conformance/feature_parity_gap_groups.log.jsonl",
    ],
    "source_commit": source_commit,
    "target_dir": str(root / "target/conformance"),
    "failure_signature": "; ".join(errors),
    "ledger_gap_count": len(ledger_ids),
    "batch_count": len(batches),
    "batched_gap_count": len(batched_ids),
}
log_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
