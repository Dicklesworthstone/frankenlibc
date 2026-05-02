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
from collections import Counter, defaultdict
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
required_log_fields = artifact.get("required_log_fields", []) if isinstance(artifact, dict) else []
required_grouping_axes = artifact.get("required_grouping_axes", []) if isinstance(artifact, dict) else []
expected_log_fields = [
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
expected_grouping_axes = [
    "feature_parity_sections",
    "symbol_family",
    "evidence_artifacts",
    "source_owner",
    "priority",
]
if required_log_fields != expected_log_fields:
    errors.append("required_log_fields must match closure evidence schema")
if required_grouping_axes != expected_grouping_axes:
    errors.append("required_grouping_axes must preserve section/family/artifact/owner/priority dimensions")

gap_by_id = {gap.get("gap_id"): gap for gap in ledger_gaps if gap.get("gap_id")}
batch_summaries = []
owner_counts = Counter()
priority_counts = Counter()
evidence_counts = Counter()
symbol_family_counts = Counter()
batch_errors = defaultdict(list)

for batch in batches:
    batch_id = batch.get("batch_id", "<missing batch_id>")
    for field in required_batch_fields:
        if field not in batch:
            errors.append(f"{batch_id}: missing field {field}")
            batch_errors[batch_id].append(f"missing field {field}")
    if len(batch.get("gap_ids", [])) != batch.get("gap_count"):
        errors.append(f"{batch_id}: gap_count does not match gap_ids length")
        batch_errors[batch_id].append("gap_count does not match gap_ids length")
    if not batch.get("feature_parity_sections"):
        errors.append(f"{batch_id}: feature_parity_sections must not be empty")
        batch_errors[batch_id].append("feature_parity_sections must not be empty")
    if not batch.get("evidence_artifacts"):
        errors.append(f"{batch_id}: evidence_artifacts must not be empty")
        batch_errors[batch_id].append("evidence_artifacts must not be empty")
    if not str(batch.get("symbol_family", "")).strip():
        errors.append(f"{batch_id}: symbol_family must not be empty")
        batch_errors[batch_id].append("symbol_family must not be empty")
    if not str(batch.get("source_owner", "")).strip():
        errors.append(f"{batch_id}: source_owner must not be empty")
        batch_errors[batch_id].append("source_owner must not be empty")
    if not isinstance(batch.get("priority"), int):
        errors.append(f"{batch_id}: priority must be an integer")
        batch_errors[batch_id].append("priority must be an integer")
checks["batch_schema"] = "fail" if any(": missing field" in e or "must not be empty" in e or "gap_count" in e or "priority must" in e for e in errors) else "pass"
checks["artifact_contract"] = "pass" if required_log_fields == expected_log_fields and required_grouping_axes == expected_grouping_axes else "fail"

missing_evidence_refs = []
for batch in batches:
    batch_id = batch.get("batch_id", "<missing batch_id>")
    for artifact_ref in batch.get("evidence_artifacts", []):
        artifact_path = root / artifact_ref.rstrip("/")
        if not artifact_path.exists():
            missing_evidence_refs.append(f"{batch_id}:{artifact_ref}")
            batch_errors[batch_id].append(f"missing evidence artifact {artifact_ref}")
        evidence_counts[artifact_ref] += len(batch.get("gap_ids", []))
    owner_counts[batch.get("source_owner", "<missing owner>")] += len(batch.get("gap_ids", []))
    priority_counts[str(batch.get("priority", "<missing priority>"))] += len(batch.get("gap_ids", []))
    symbol_family_counts[batch.get("symbol_family", "<missing symbol_family>")] += len(batch.get("gap_ids", []))

if missing_evidence_refs:
    errors.append("missing evidence artifact refs: " + ", ".join(missing_evidence_refs))
checks["evidence_artifacts_exist"] = "pass" if not missing_evidence_refs else "fail"

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

for batch in batches:
    batch_id = batch.get("batch_id", "<missing batch_id>")
    gap_ids = batch.get("gap_ids", [])
    status_counts = Counter()
    kind_counts = Counter()
    provenance_paths = Counter()
    representative_primary_keys = []
    for gap_id in gap_ids:
        gap = gap_by_id.get(gap_id, {})
        if gap:
            status_counts[gap.get("status", "<missing status>")] += 1
            kind_counts[gap.get("kind", "<missing kind>")] += 1
            provenance = gap.get("provenance", {})
            if isinstance(provenance, list):
                paths = [item.get("path", "<missing path>") for item in provenance if isinstance(item, dict)]
                if not paths:
                    paths = ["<missing path>"]
            elif isinstance(provenance, dict):
                paths = [provenance.get("path", "<missing path>")]
            else:
                paths = ["<missing path>"]
            for provenance_path in paths:
                provenance_paths[provenance_path] += 1
            if len(representative_primary_keys) < 3 and gap.get("primary_key"):
                representative_primary_keys.append(gap["primary_key"])
    batch_summaries.append(
        {
            "batch_id": batch_id,
            "title": batch.get("title"),
            "feature_parity_sections": batch.get("feature_parity_sections", []),
            "symbol_family": batch.get("symbol_family"),
            "evidence_artifacts": batch.get("evidence_artifacts", []),
            "source_owner": batch.get("source_owner"),
            "priority": batch.get("priority"),
            "gap_count": len(gap_ids),
            "status_counts": dict(sorted(status_counts.items())),
            "kind_counts": dict(sorted(kind_counts.items())),
            "provenance_paths": dict(sorted(provenance_paths.items())),
            "representative_primary_keys": representative_primary_keys,
            "failure_signature": "; ".join(batch_errors.get(batch_id, [])),
        }
    )

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
    "owner_counts": dict(sorted(owner_counts.items())),
    "priority_counts": dict(sorted(priority_counts.items())),
    "evidence_artifact_counts": dict(sorted(evidence_counts.items())),
    "symbol_family_counts": dict(sorted(symbol_family_counts.items())),
    "batch_summaries": batch_summaries,
    "errors": errors,
    "artifact_refs": [
        "tests/conformance/feature_parity_gap_groups.v1.json",
        "tests/conformance/feature_parity_gap_ledger.v1.json",
    ],
    "source_commit": source_commit,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

common_refs = report["artifact_refs"] + [
    "target/conformance/feature_parity_gap_groups.report.json",
    "target/conformance/feature_parity_gap_groups.log.jsonl",
]
events = [
    {
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
        "artifact_refs": common_refs,
        "source_commit": source_commit,
        "target_dir": str(root / "target/conformance"),
        "failure_signature": "; ".join(errors),
        "ledger_gap_count": len(ledger_ids),
        "batch_count": len(batches),
        "batched_gap_count": len(batched_ids),
    }
]
for batch_summary in batch_summaries:
    events.append(
        {
            "trace_id": f"bd-bp8fl.3.1-{batch_summary['batch_id']}",
            "bead_id": "bd-bp8fl.3.1",
            "scenario_id": f"feature-parity-gap-batch:{batch_summary['batch_id']}",
            "runtime_mode": "not_applicable",
            "replacement_level": "L0_interpose_and_L1_planning",
            "api_family": ",".join(batch_summary["feature_parity_sections"]),
            "symbol": batch_summary["symbol_family"],
            "oracle_kind": "ledger_batch_owner_evidence_grouping",
            "expected": "batch has owner, evidence artifacts, section, family, priority, and ledger gap coverage",
            "actual": "pass" if not batch_summary["failure_signature"] else "fail",
            "errno": None,
            "decision_path": ["artifact_contract", "batch_schema", "exact_gap_coverage", "evidence_artifacts_exist"],
            "healing_action": "none",
            "latency_ns": 0,
            "artifact_refs": common_refs + batch_summary["evidence_artifacts"],
            "source_commit": source_commit,
            "target_dir": str(root / "target/conformance"),
            "failure_signature": batch_summary["failure_signature"],
            "gap_count": batch_summary["gap_count"],
            "source_owner": batch_summary["source_owner"],
            "priority": batch_summary["priority"],
            "status_counts": batch_summary["status_counts"],
            "kind_counts": batch_summary["kind_counts"],
            "provenance_paths": batch_summary["provenance_paths"],
        }
    )
log_path.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
