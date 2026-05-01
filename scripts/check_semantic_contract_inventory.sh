#!/usr/bin/env bash
# check_semantic_contract_inventory.sh -- CI gate for bd-bp8fl.1.1
#
# Validates the semantic-contract inventory artifact and emits deterministic
# report/log artifacts under target/conformance.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${ROOT}/tests/conformance/semantic_contract_inventory.v1.json"
SEED="${ROOT}/tests/conformance/support_semantic_overlay.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/semantic_contract_inventory.report.json"
LOG="${OUT_DIR}/semantic_contract_inventory.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${ARTIFACT}" "${SEED}" "${REPORT}" "${LOG}" <<'PY'
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
seed_path = Path(sys.argv[3])
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
seed = load_json(seed_path)

if artifact is None or seed is None:
    checks["json_parse"] = "fail"
else:
    checks["json_parse"] = "pass"

entries = artifact.get("entries", []) if isinstance(artifact, dict) else []
summary = artifact.get("summary", {}) if isinstance(artifact, dict) else {}

if artifact and artifact.get("schema_version") == "v1" and artifact.get("bead") == "bd-bp8fl.1.1":
    checks["top_level_shape"] = "pass"
else:
    checks["top_level_shape"] = "fail"
    errors.append("artifact must declare schema_version=v1 and bead=bd-bp8fl.1.1")

if entries and all(isinstance(row, dict) for row in entries):
    checks["entries_present"] = "pass"
else:
    checks["entries_present"] = "fail"
    errors.append("entries must be a non-empty array of objects")

required_fields = [
    "id",
    "surface",
    "symbols",
    "module",
    "source_path",
    "source_line",
    "line_marker",
    "support_matrix_status",
    "semantic_class",
    "contract_kind",
    "current_behavior",
    "user_risk",
    "required_followup",
    "evidence_artifacts",
]
for row in entries:
    row_id = row.get("id", "<missing id>")
    for field in required_fields:
        if field not in row:
            errors.append(f"{row_id}: missing field {field}")
if not any("missing field" in err for err in errors):
    checks["entry_schema"] = "pass"
else:
    checks["entry_schema"] = "fail"

ids = [row.get("id") for row in entries]
if len(ids) == len(set(ids)):
    checks["unique_ids"] = "pass"
else:
    checks["unique_ids"] = "fail"
    errors.append("entry ids must be unique")

seed_ids = {
    row.get("id")
    for row in seed.get("audited_entries", [])
    if isinstance(row, dict) and row.get("id")
} if isinstance(seed, dict) else set()
inventory_seed_ids = {
    row.get("seed_overlay_id")
    for row in entries
    if row.get("seed_overlay_id")
}
missing_seed_ids = sorted(seed_ids - inventory_seed_ids)
if not missing_seed_ids:
    checks["seed_overlay_coverage"] = "pass"
else:
    checks["seed_overlay_coverage"] = "fail"
    errors.append("missing seed overlay ids: " + ", ".join(missing_seed_ids))

class_counts = Counter(row.get("semantic_class") for row in entries)
source_counts = Counter(row.get("source_path") for row in entries)
if summary.get("entry_count") == len(entries) and summary.get("by_semantic_class") == dict(class_counts):
    checks["summary_counts"] = "pass"
else:
    checks["summary_counts"] = "fail"
    errors.append("summary entry_count or by_semantic_class does not match entries")

if summary.get("by_source_path") == dict(source_counts):
    checks["source_summary_counts"] = "pass"
else:
    checks["source_summary_counts"] = "fail"
    errors.append("summary by_source_path does not match entries")

source_errors = []
for row in entries:
    source = root / row.get("source_path", "")
    marker = row.get("line_marker", "")
    if not source.exists():
        source_errors.append(f"{row.get('id')}: missing source {source}")
        continue
    text = source.read_text(encoding="utf-8")
    if marker not in text:
        source_errors.append(f"{row.get('id')}: marker not found: {marker}")
if source_errors:
    checks["source_markers"] = "fail"
    errors.extend(source_errors)
else:
    checks["source_markers"] = "pass"

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
    "bead": "bd-bp8fl.1.1",
    "status": status,
    "checks": checks,
    "entry_count": len(entries),
    "seed_overlay_entries": len(seed_ids),
    "seed_overlay_covered": len(inventory_seed_ids & seed_ids),
    "semantic_class_counts": dict(class_counts),
    "source_path_counts": dict(source_counts),
    "errors": errors,
    "artifact_refs": [
        "tests/conformance/semantic_contract_inventory.v1.json",
        "tests/conformance/support_semantic_overlay.v1.json",
    ],
    "source_commit": source_commit,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log_event = {
    "trace_id": "bd-bp8fl.1.1-semantic-contract-inventory",
    "bead_id": "bd-bp8fl.1.1",
    "scenario_id": "semantic-contract-inventory-gate",
    "runtime_mode": "not_applicable",
    "replacement_level": "L0_interpose_and_L1_planning",
    "api_family": "semantic_contract_inventory",
    "symbol": "*",
    "oracle_kind": "artifact_shape_seed_source_cross_reference",
    "expected": "all checks pass",
    "actual": status,
    "errno": None,
    "decision_path": list(checks.keys()),
    "healing_action": "none",
    "latency_ns": 0,
    "artifact_refs": report["artifact_refs"] + [
        "target/conformance/semantic_contract_inventory.report.json",
        "target/conformance/semantic_contract_inventory.log.jsonl",
    ],
    "source_commit": source_commit,
    "target_dir": str(root / "target/conformance"),
    "failure_signature": "; ".join(errors),
    "entry_count": len(entries),
    "semantic_class_counts": dict(class_counts),
}
log_path.write_text(json.dumps(log_event, sort_keys=True) + "\n", encoding="utf-8")

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
