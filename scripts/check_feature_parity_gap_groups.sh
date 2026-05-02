#!/usr/bin/env bash
# check_feature_parity_gap_groups.sh -- CI gate for bd-bp8fl.3.1
#
# Validates that feature_parity_gap_groups.v1.json covers every unresolved
# feature-parity ledger gap exactly once and emits deterministic report/log
# artifacts under target/conformance.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_groups.v1.json}"
LEDGER="${FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER:-${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json}"
COVERAGE="${FRANKENLIBC_FEATURE_PARITY_GAP_COVERAGE:-${ROOT}/tests/conformance/feature_parity_gap_bead_coverage.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUP_REPORT:-${OUT_DIR}/feature_parity_gap_groups.report.json}"
LOG="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUP_LOG:-${OUT_DIR}/feature_parity_gap_groups.log.jsonl}"
REGENERATED="${FRANKENLIBC_FEATURE_PARITY_GAP_REGENERATED:-${OUT_DIR}/feature_parity_gap_groups.regenerated.v1.json}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${ARTIFACT}" "${LEDGER}" "${COVERAGE}" "${REPORT}" "${LOG}" "${REGENERATED}" <<'PY'
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
ledger_path = Path(sys.argv[3])
coverage_path = Path(sys.argv[4])
report_path = Path(sys.argv[5])
log_path = Path(sys.argv[6])
regenerated_path = Path(sys.argv[7])

errors = []
checks = {}
allowed_sections = {
    "macro_targets",
    "machine_delta",
    "reverse_core",
    "proof_math",
    "gap_summary",
}

def load_json(path):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return None

artifact = load_json(artifact_path)
ledger = load_json(ledger_path)
coverage = load_json(coverage_path)
checks["json_parse"] = "pass" if artifact is not None and ledger is not None and coverage is not None else "fail"

batches = artifact.get("batches", []) if isinstance(artifact, dict) else []
ledger_gaps = ledger.get("gaps", []) if isinstance(ledger, dict) else []
ledger_ids = [gap.get("gap_id") for gap in ledger_gaps if gap.get("gap_id")]
coverage_rows = coverage.get("rows", []) if isinstance(coverage, dict) else []
coverage_by_gap = {
    row.get("gap_id"): row
    for row in coverage_rows
    if isinstance(row, dict) and row.get("gap_id")
}

if artifact and artifact.get("schema_version") == "v1" and artifact.get("bead") == "bd-bp8fl.3.1":
    checks["top_level_shape"] = "pass"
else:
    checks["top_level_shape"] = "fail"
    errors.append("artifact must declare schema_version=v1 and bead=bd-bp8fl.3.1")

ledger_generated_at = ledger.get("generated_at") if isinstance(ledger, dict) else None
artifact_generated_at = artifact.get("generated_at_utc") if isinstance(artifact, dict) else None
if ledger_generated_at and artifact_generated_at:
    try:
        ledger_ts = datetime.fromisoformat(ledger_generated_at.replace("Z", "+00:00"))
        artifact_ts = datetime.fromisoformat(artifact_generated_at.replace("Z", "+00:00"))
        freshness_ok = artifact_ts >= ledger_ts
    except Exception:
        freshness_ok = False
else:
    freshness_ok = False
checks["artifact_freshness"] = "pass" if freshness_ok else "fail"
if not freshness_ok:
    errors.append("group artifact generated_at_utc must be present and at least as fresh as ledger generated_at")

required_batch_fields = [
    "batch_id",
    "title",
    "feature_parity_sections",
    "symbol_family",
    "abi_modules",
    "support_statuses",
    "semantic_statuses",
    "evidence_artifacts",
    "source_owner",
    "owner_beads",
    "priority",
    "oracle_kind",
    "replacement_levels",
    "closure_blockers",
    "gap_count",
    "gap_ids",
    "actionable_next_step",
]
required_log_fields = artifact.get("required_log_fields", []) if isinstance(artifact, dict) else []
required_grouping_axes = artifact.get("required_grouping_axes", []) if isinstance(artifact, dict) else []
expected_log_fields = [
    "trace_id",
    "bead_id",
    "ledger_row_id",
    "section",
    "symbol_family",
    "owner_bead",
    "expected",
    "actual",
    "artifact_refs",
    "failure_signature",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "oracle_kind",
    "source_commit",
    "target_dir",
]
expected_grouping_axes = [
    "feature_parity_sections",
    "symbol_family",
    "abi_modules",
    "support_statuses",
    "semantic_statuses",
    "owner_beads",
    "oracle_kind",
    "replacement_levels",
    "evidence_artifacts",
    "closure_blockers",
    "source_owner",
    "priority",
]
missing_log_fields = [field for field in expected_log_fields if field not in required_log_fields]
missing_grouping_axes = [axis for axis in expected_grouping_axes if axis not in required_grouping_axes]
if missing_log_fields:
    errors.append("required_log_fields missing: " + ", ".join(missing_log_fields))
if missing_grouping_axes:
    errors.append("required_grouping_axes missing: " + ", ".join(missing_grouping_axes))

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
    for field in [
        "abi_modules",
        "support_statuses",
        "semantic_statuses",
        "owner_beads",
        "replacement_levels",
        "closure_blockers",
    ]:
        if not batch.get(field):
            errors.append(f"{batch_id}: {field} must not be empty")
            batch_errors[batch_id].append(f"{field} must not be empty")
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
    if not str(batch.get("oracle_kind", "")).strip():
        errors.append(f"{batch_id}: oracle_kind must not be empty")
        batch_errors[batch_id].append("oracle_kind must not be empty")
    if not isinstance(batch.get("priority"), int):
        errors.append(f"{batch_id}: priority must be an integer")
        batch_errors[batch_id].append("priority must be an integer")
checks["batch_schema"] = "fail" if any(": missing field" in e or "must not be empty" in e or "gap_count" in e or "priority must" in e for e in errors) else "pass"
checks["artifact_contract"] = "pass" if not missing_log_fields and not missing_grouping_axes else "fail"

missing_evidence_refs = []
missing_abi_modules = []
for batch in batches:
    batch_id = batch.get("batch_id", "<missing batch_id>")
    for module_ref in batch.get("abi_modules", []):
        module_path = root / module_ref.rstrip("/")
        if not module_path.exists():
            missing_abi_modules.append(f"{batch_id}:{module_ref}")
            batch_errors[batch_id].append(f"missing ABI module {module_ref}")
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
if missing_abi_modules:
    errors.append("missing ABI module refs: " + ", ".join(missing_abi_modules))
checks["evidence_artifacts_exist"] = "pass" if not missing_evidence_refs else "fail"
checks["abi_modules_exist"] = "pass" if not missing_abi_modules else "fail"

batch_ids = [batch.get("batch_id") for batch in batches]
checks["unique_batch_ids"] = "pass" if len(batch_ids) == len(set(batch_ids)) else "fail"
if checks["unique_batch_ids"] == "fail":
    errors.append("batch ids must be unique")

ledger_counter = Counter(ledger_ids)
duplicate_ledger_ids = sorted([gap_id for gap_id, count in ledger_counter.items() if count > 1])
if duplicate_ledger_ids:
    errors.append("duplicate ledger gap ids: " + ", ".join(duplicate_ledger_ids))
checks["unique_ledger_gap_ids"] = "pass" if not duplicate_ledger_ids else "fail"

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
unknown_sections = []
for gap in ledger_gaps:
    section = gap.get("section") or "machine_delta"
    if section not in allowed_sections:
        unknown_sections.append(f"{gap.get('gap_id', '<missing gap_id>')}:{section}")
    section_counts[section] += 1
if unknown_sections:
    errors.append("unknown ledger sections: " + ", ".join(unknown_sections))
checks["known_ledger_sections"] = "pass" if not unknown_sections else "fail"

missing_owner_refs = []
semantic_status_mismatches = []

for batch in batches:
    batch_id = batch.get("batch_id", "<missing batch_id>")
    gap_ids = batch.get("gap_ids", [])
    status_counts = Counter()
    kind_counts = Counter()
    provenance_paths = Counter()
    representative_primary_keys = []
    owner_beads = set(batch.get("owner_beads", []))
    semantic_statuses = set(batch.get("semantic_statuses", []))
    for gap_id in gap_ids:
        gap = gap_by_id.get(gap_id, {})
        if gap:
            gap_status = gap.get("status", "<missing status>")
            status_counts[gap_status] += 1
            if gap_status not in semantic_statuses:
                semantic_status_mismatches.append(f"{batch_id}:{gap_id}:{gap_status}")
                batch_errors[batch_id].append(f"semantic_statuses missing {gap_status} for {gap_id}")
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
        coverage_row = coverage_by_gap.get(gap_id)
        owner_bead = coverage_row.get("owner_bead") if isinstance(coverage_row, dict) else None
        if not owner_bead or owner_bead not in owner_beads:
            missing_owner_refs.append(f"{batch_id}:{gap_id}:{owner_bead or '<missing owner>'}")
            batch_errors[batch_id].append(f"owner_beads missing {owner_bead or '<missing owner>'} for {gap_id}")
    batch_summaries.append(
        {
            "batch_id": batch_id,
            "title": batch.get("title"),
            "feature_parity_sections": batch.get("feature_parity_sections", []),
            "symbol_family": batch.get("symbol_family"),
            "abi_modules": batch.get("abi_modules", []),
            "support_statuses": batch.get("support_statuses", []),
            "semantic_statuses": batch.get("semantic_statuses", []),
            "evidence_artifacts": batch.get("evidence_artifacts", []),
            "source_owner": batch.get("source_owner"),
            "owner_beads": batch.get("owner_beads", []),
            "priority": batch.get("priority"),
            "oracle_kind": batch.get("oracle_kind"),
            "replacement_levels": batch.get("replacement_levels", []),
            "closure_blockers": batch.get("closure_blockers", []),
            "gap_count": len(gap_ids),
            "status_counts": dict(sorted(status_counts.items())),
            "kind_counts": dict(sorted(kind_counts.items())),
            "provenance_paths": dict(sorted(provenance_paths.items())),
            "representative_primary_keys": representative_primary_keys,
            "failure_signature": "; ".join(batch_errors.get(batch_id, [])),
        }
    )
if missing_owner_refs:
    errors.append("missing owner bead refs: " + ", ".join(missing_owner_refs))
if semantic_status_mismatches:
    errors.append("semantic status mismatches: " + ", ".join(semantic_status_mismatches))
checks["owner_bead_coverage"] = "pass" if not missing_owner_refs else "fail"
checks["semantic_status_coverage"] = "pass" if not semantic_status_mismatches else "fail"

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
regenerated = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.3.1",
    "generated_from": [
        str(artifact_path.relative_to(root) if artifact_path.is_relative_to(root) else artifact_path),
        str(ledger_path.relative_to(root) if ledger_path.is_relative_to(root) else ledger_path),
        str(coverage_path.relative_to(root) if coverage_path.is_relative_to(root) else coverage_path),
    ],
    "source_commit": source_commit,
    "summary": {
        "ledger_gap_count": len(ledger_ids),
        "batch_count": len(batches),
        "batched_gap_count": len(batched_ids),
        "duplicate_gap_count": len(duplicates),
        "unbatched_gap_count": len(missing),
        "extra_gap_count": len(extra),
        "by_feature_parity_section": dict(section_counts),
    },
    "batches": sorted(batch_summaries, key=lambda batch: batch["batch_id"]),
}
regenerated_path.write_text(json.dumps(regenerated, indent=2, sort_keys=True) + "\n", encoding="utf-8")

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
    "owner_bead_counts": dict(sorted(Counter(
        coverage_by_gap.get(gap_id, {}).get("owner_bead", "<missing owner>")
        for gap_id in batched_ids
    ).items())),
    "support_status_counts": dict(sorted(Counter(
        status
        for batch in batches
        for status in batch.get("support_statuses", [])
    ).items())),
    "semantic_status_counts": dict(sorted(Counter(
        status
        for batch in batches
        for status in batch.get("semantic_statuses", [])
    ).items())),
    "batch_summaries": batch_summaries,
    "errors": errors,
    "artifact_refs": [
        "tests/conformance/feature_parity_gap_groups.v1.json",
        "tests/conformance/feature_parity_gap_ledger.v1.json",
        "tests/conformance/feature_parity_gap_bead_coverage.v1.json",
    ],
    "regenerated_group_artifact": str(regenerated_path),
    "source_commit": source_commit,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

common_refs = report["artifact_refs"] + [
        "target/conformance/feature_parity_gap_groups.report.json",
        "target/conformance/feature_parity_gap_groups.log.jsonl",
        "target/conformance/feature_parity_gap_groups.regenerated.v1.json",
]
events = [
    {
        "trace_id": "bd-bp8fl.3.1-feature-parity-gap-groups",
        "bead_id": "bd-bp8fl.3.1",
        "ledger_row_id": "*",
        "section": "*",
        "symbol_family": "*",
        "owner_bead": "*",
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
            "ledger_row_id": "*",
            "section": ",".join(batch_summary["feature_parity_sections"]),
            "symbol_family": batch_summary["symbol_family"],
            "owner_bead": ",".join(batch_summary["owner_beads"]),
            "scenario_id": f"feature-parity-gap-batch:{batch_summary['batch_id']}",
            "runtime_mode": "not_applicable",
            "replacement_level": ",".join(batch_summary["replacement_levels"]),
            "api_family": ",".join(batch_summary["feature_parity_sections"]),
            "symbol": batch_summary["symbol_family"],
            "oracle_kind": batch_summary["oracle_kind"],
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
for batch in batches:
    batch_id = batch.get("batch_id", "<missing batch_id>")
    batch_failure = "; ".join(batch_errors.get(batch_id, []))
    for gap_id in batch.get("gap_ids", []):
        gap = gap_by_id.get(gap_id, {})
        coverage_row = coverage_by_gap.get(gap_id, {})
        events.append(
            {
                "trace_id": f"bd-bp8fl.3.1-{gap_id}",
                "bead_id": "bd-bp8fl.3.1",
                "ledger_row_id": gap_id,
                "section": gap.get("section") or "machine_delta",
                "symbol_family": batch.get("symbol_family"),
                "owner_bead": coverage_row.get("owner_bead", "<missing owner>") if isinstance(coverage_row, dict) else "<missing owner>",
                "scenario_id": f"feature-parity-gap-row:{gap_id}",
                "runtime_mode": "not_applicable",
                "replacement_level": ",".join(batch.get("replacement_levels", [])),
                "api_family": gap.get("section") or "machine_delta",
                "symbol": gap.get("primary_key") or gap_id,
                "oracle_kind": batch.get("oracle_kind"),
                "expected": "ledger row is covered by exactly one batch with owner/evidence/replacement metadata",
                "actual": "pass" if not batch_failure else "fail",
                "errno": None,
                "decision_path": ["exact_gap_coverage", "owner_bead_coverage", "semantic_status_coverage"],
                "healing_action": "none",
                "latency_ns": 0,
                "artifact_refs": common_refs + batch.get("evidence_artifacts", []),
                "source_commit": source_commit,
                "target_dir": str(root / "target/conformance"),
                "failure_signature": batch_failure,
                "status": gap.get("status"),
                "kind": gap.get("kind"),
                "batch_id": batch_id,
            }
        )
log_path.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
