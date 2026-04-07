#!/usr/bin/env bash
# check_docs_env_mismatch.sh — CI gate for bd-29b.2 + bd-3rw.3
#
# Validates that:
#   1) docs env inventory/report are reproducible.
#   2) each mismatch has explicit remediation_action.
#   3) unresolved_ambiguous mismatch list is empty.
#   4) docs/code mismatch counts are fully reconciled (all zero).
#   5) major documentation surfaces have explicit owners, sources, and triggers.
#   6) deterministic docs-generation dry run succeeds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_docs_env_mismatch_report.py"
REPORT="${ROOT}/tests/conformance/env_docs_code_mismatch_report.v1.json"
SOURCE_MAP="${ROOT}/tests/conformance/docs_source_of_truth_map.v1.json"
TRACE="${ROOT}/tests/conformance/docs_source_of_truth_trace.v1.jsonl"
DRY_RUN_DIR="${ROOT}/target/conformance/docs_governance_dry_run"

if [[ ! -f "${GEN}" ]]; then
  echo "FAIL: missing generator script ${GEN}"
  exit 1
fi

python3 "${GEN}" --root "${ROOT}" --check

mkdir -p "${DRY_RUN_DIR}"
python3 "${GEN}" \
  --root "${ROOT}" \
  --docs-output "${DRY_RUN_DIR}/docs_env_inventory.v1.json" \
  --report-output "${DRY_RUN_DIR}/env_docs_code_mismatch_report.v1.json" \
  --source-map-output "${DRY_RUN_DIR}/docs_source_of_truth_map.v1.json" \
  --trace-output "${DRY_RUN_DIR}/docs_source_of_truth_trace.v1.jsonl" \
  >/dev/null

python3 - "${REPORT}" "${SOURCE_MAP}" "${TRACE}" "${DRY_RUN_DIR}" <<'PY'
import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
source_map_path = Path(sys.argv[2])
trace_path = Path(sys.argv[3])
dry_run_dir = Path(sys.argv[4])

with report_path.open("r", encoding="utf-8") as f:
    payload = json.load(f)

failures = []
for row in payload.get("classifications", []):
    if not row.get("remediation_action"):
        failures.append(f"{row.get('env_key')}: missing remediation_action")
    if not row.get("mismatch_class"):
        failures.append(f"{row.get('env_key')}: missing mismatch_class")

unresolved = payload.get("unresolved_ambiguous", [])
if unresolved:
    failures.append(f"unresolved_ambiguous_count={len(unresolved)}")

summary = payload.get("summary", {})
for key in ("missing_in_docs_count", "missing_in_code_count", "semantic_drift_count"):
    count = int(summary.get(key, 0))
    if count != 0:
        failures.append(f"{key}={count}")

if failures:
    print("FAIL: docs/code mismatch report unresolved")
    for row in failures:
        print(f"  - {row}")
    raise SystemExit(1)

print(
    "PASS: docs/code mismatch report reconciled "
    f"(total={summary.get('total_classifications', 0)}, "
    f"missing_in_docs={summary.get('missing_in_docs_count', 0)}, "
    f"missing_in_code={summary.get('missing_in_code_count', 0)}, "
    f"semantic_drift={summary.get('semantic_drift_count', 0)})"
)

with source_map_path.open("r", encoding="utf-8") as f:
    source_map = json.load(f)

required_surfaces = {
    "README",
    "ARCHITECTURE",
    "DEPLOYMENT",
    "SECURITY",
    "API",
    "TROUBLESHOOTING",
}
surfaces = source_map.get("surfaces", [])
surface_ids = {row.get("surface_id") for row in surfaces}
missing_surfaces = sorted(required_surfaces - surface_ids)
if missing_surfaces:
    failures.append(f"missing governance surfaces: {missing_surfaces}")

for surface in surfaces:
    sid = surface.get("surface_id", "<unknown>")
    if not surface.get("target_path"):
        failures.append(f"{sid}: missing target_path")
    if not surface.get("future_target_path"):
        failures.append(f"{sid}: missing future_target_path")
    sections = surface.get("sections", [])
    if not sections:
        failures.append(f"{sid}: missing sections")
        continue
    for section in sections:
        section_id = f"{sid}/{section.get('section_id', '<unknown>')}"
        for key in ("owner", "review_policy", "freshness_status"):
            if not section.get(key):
                failures.append(f"{section_id}: missing {key}")
        if not section.get("backing_paths"):
            failures.append(f"{section_id}: missing backing_paths")
        if not section.get("source_artifacts"):
            failures.append(f"{section_id}: missing source_artifacts")
        if not section.get("update_triggers"):
            failures.append(f"{section_id}: missing update_triggers")
        if section.get("freshness_status") != "fresh":
            failures.append(
                f"{section_id}: freshness_status={section.get('freshness_status')}"
            )

summary = source_map.get("summary", {})
if summary.get("surface_count") != len(surfaces):
    failures.append("source-of-truth summary.surface_count mismatch")
if summary.get("missing_section_count") != 0:
    failures.append(
        f"source-of-truth missing_section_count={summary.get('missing_section_count')}"
    )

trace_lines = [
    line for line in trace_path.read_text(encoding="utf-8").splitlines() if line.strip()
]
expected_trace_count = sum(len(surface.get("sections", [])) for surface in surfaces)
if len(trace_lines) != expected_trace_count:
    failures.append(
        f"trace row count mismatch: expected {expected_trace_count}, got {len(trace_lines)}"
    )

for idx, line in enumerate(trace_lines, start=1):
    row = json.loads(line)
    for key in (
        "trace_id",
        "bead_id",
        "doc_surface",
        "doc_section",
        "source_artifact",
        "freshness_status",
        "owner",
        "review_policy",
        "update_trigger",
        "artifact_refs",
    ):
        if key not in row or row[key] in ("", [], None):
            failures.append(f"trace row {idx}: missing {key}")

for rel in (
    "docs_env_inventory.v1.json",
    "env_docs_code_mismatch_report.v1.json",
    "docs_source_of_truth_map.v1.json",
    "docs_source_of_truth_trace.v1.jsonl",
):
    if not (dry_run_dir / rel).exists():
        failures.append(f"dry-run artifact missing: {rel}")

if failures:
    print("FAIL: docs governance report unresolved")
    for row in failures:
        print(f"  - {row}")
    raise SystemExit(1)

print(
    "PASS: docs source-of-truth map validated "
    f"(surfaces={len(surfaces)}, trace_rows={len(trace_lines)})"
)
PY
