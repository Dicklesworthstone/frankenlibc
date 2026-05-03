#!/usr/bin/env bash
# check_reality_bridge_import_reconciliation.sh -- gate for bd-bp8fl.2.2
#
# Validates the import mapping from the reality-check bridge backlog and feature
# parity gap ledger into live bd-bp8fl beads, then replays the mapping into a
# deterministic fixture tracker snapshot.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_reality_bridge_import_reconciliation.py"
ARTIFACT="${FRANKENLIBC_REALITY_BRIDGE_IMPORT_ARTIFACT:-${ROOT}/tests/conformance/reality_bridge_import_reconciliation.v1.json}"
OUT_DIR="${FRANKENLIBC_REALITY_BRIDGE_IMPORT_TARGET_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_REALITY_BRIDGE_IMPORT_REPORT:-${OUT_DIR}/reality_bridge_import_reconciliation.report.json}"
LOG="${FRANKENLIBC_REALITY_BRIDGE_IMPORT_LOG:-${OUT_DIR}/reality_bridge_import_reconciliation.log.jsonl}"
FIXTURE_TRACKER="${FRANKENLIBC_REALITY_BRIDGE_IMPORT_FIXTURE_TRACKER:-${OUT_DIR}/reality_bridge_import_reconciliation.fixture_tracker.jsonl}"
MODE="${1:---fixture-replay}"
VERIFY_GENERATOR="${FRANKENLIBC_REALITY_BRIDGE_IMPORT_VERIFY_GENERATOR:-1}"

case "${MODE}" in
  --fixture-replay|--validate-only)
    ;;
  *)
    echo "usage: $0 [--fixture-replay|--validate-only]" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")" "$(dirname "${FIXTURE_TRACKER}")"

if [[ "${VERIFY_GENERATOR}" == "1" ]]; then
  (
    cd "${ROOT}"
    python3 "${GEN}" --check
  )
fi

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" "${FIXTURE_TRACKER}" "${MODE}" <<'PY'
import json
import subprocess
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
fixture_tracker_path = Path(sys.argv[5])
mode = sys.argv[6]

BEAD_ID = "bd-bp8fl.2.2"
TRACE_ID = "bd-bp8fl-2-2-reality-bridge-import-v1"
REQUIRED_NEGATIVE_CASES = {
    "duplicate_source_row",
    "missing_required_field",
    "stale_source_snapshot",
    "missing_dependency",
    "missing_acceptance",
    "no_feature_loss",
}


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def source_commit():
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"FAIL: cannot load {path}: {exc}")


def validate_payload(payload):
    errors = []
    if payload.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if payload.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if payload.get("trace_id") != TRACE_ID:
        errors.append(f"trace_id must be {TRACE_ID}")
    summary = payload.get("summary", {})
    expected_counts = {
        "backlog_source_rows": 10,
        "backlog_import_rows": 10,
        "feature_ledger_rows": 170,
        "feature_ledger_unresolved_gaps": 111,
        "feature_gap_import_rows": 111,
        "feature_gap_batches": 10,
        "rejected_row_count": 0,
        "missing_target_issue_count": 0,
        "missing_acceptance_target_count": 0,
        "missing_dependency_count": 0,
        "stale_source_snapshot_count": 0,
        "lost_feature_gap_count": 0,
    }
    for key, expected in expected_counts.items():
        if summary.get(key) != expected:
            errors.append(f"summary.{key} expected {expected}, got {summary.get(key)}")
    if payload.get("rejected_rows") != []:
        errors.append("rejected_rows must be empty")
    negative_cases = set(payload.get("negative_fixture_cases", []))
    missing_cases = sorted(REQUIRED_NEGATIVE_CASES - negative_cases)
    if missing_cases:
        errors.append(f"negative fixture cases missing: {missing_cases}")

    source_ids = []
    for row in payload.get("backlog_import_rows", []):
        source_ids.append(("backlog", row.get("source_row_id")))
        if row.get("failure_signature") != "ok":
            errors.append(f"{row.get('source_row_id')}: expected ok failure_signature")
        if row.get("source_freshness", {}).get("state") != "fresh":
            errors.append(f"{row.get('source_row_id')}: source freshness is not fresh")
        for target, summary_row in row.get("target_issue_summaries", {}).items():
            if not summary_row.get("exists"):
                errors.append(f"{row.get('source_row_id')}: missing target {target}")
            if not summary_row.get("has_acceptance"):
                errors.append(f"{row.get('source_row_id')}: missing acceptance {target}")
        if not row.get("artifact_refs"):
            errors.append(f"{row.get('source_row_id')}: artifact refs are empty")

    for row in payload.get("feature_gap_import_rows", []):
        source_ids.append(("feature", row.get("source_row_id")))
        if row.get("failure_signature") != "ok":
            errors.append(f"{row.get('source_row_id')}: expected ok failure_signature")
        summary_row = row.get("target_issue_summary", {})
        if not summary_row.get("exists"):
            errors.append(f"{row.get('source_row_id')}: missing target issue")
        if not summary_row.get("has_acceptance"):
            errors.append(f"{row.get('source_row_id')}: missing target acceptance")
        if row.get("missing_dependencies"):
            errors.append(f"{row.get('source_row_id')}: missing dependencies")
        if row.get("source_freshness", {}).get("state") != "fresh":
            errors.append(f"{row.get('source_row_id')}: source freshness is not fresh")
        if not row.get("artifact_refs"):
            errors.append(f"{row.get('source_row_id')}: artifact refs are empty")

    seen = set()
    for source in source_ids:
        if source in seen:
            errors.append(f"duplicate source row {source}")
        seen.add(source)
    return errors


def build_fixture_tracker(payload):
    tracker = {}
    for row in payload.get("backlog_import_rows", []):
        for target, summary_row in row.get("target_issue_summaries", {}).items():
            tracker[target] = {
                "id": target,
                "status": summary_row.get("status"),
                "priority": summary_row.get("priority"),
                "labels": summary_row.get("labels", []),
                "dependencies": summary_row.get("dependencies", []),
                "acceptance_criteria": "fixture acceptance" if summary_row.get("has_acceptance") else "",
            }
    for row in payload.get("feature_gap_import_rows", []):
        target = row.get("target_issue_id")
        summary_row = row.get("target_issue_summary", {})
        tracker[target] = {
            "id": target,
            "status": summary_row.get("status"),
            "priority": summary_row.get("priority"),
            "labels": summary_row.get("labels", []),
            "dependencies": summary_row.get("dependencies", []),
            "acceptance_criteria": "fixture acceptance" if summary_row.get("has_acceptance") else "",
        }
    return tracker


def validate_fixture_import(payload, tracker):
    errors = []
    if len(payload.get("backlog_import_rows", [])) != payload.get("summary", {}).get("backlog_source_rows"):
        errors.append("no_feature_loss: backlog row count mismatch")
    if len(payload.get("feature_gap_import_rows", [])) != payload.get("summary", {}).get("feature_ledger_unresolved_gaps"):
        errors.append("no_feature_loss: feature gap count mismatch")

    source_ids = []
    for row in payload.get("backlog_import_rows", []):
        source_id = row.get("source_row_id")
        if not source_id or not row.get("primary_target_issue_id"):
            errors.append("missing_required_field")
        source_ids.append(("backlog", source_id))
        if row.get("source_freshness", {}).get("state") != "fresh":
            errors.append("stale_source_snapshot")
        for target in row.get("target_issue_ids", []):
            issue = tracker.get(target)
            if issue is None:
                errors.append("missing_target_issue")
                continue
            if not issue.get("acceptance_criteria"):
                errors.append("missing_acceptance")

    for row in payload.get("feature_gap_import_rows", []):
        source_id = row.get("source_row_id")
        target = row.get("target_issue_id")
        if not source_id or not target:
            errors.append("missing_required_field")
        source_ids.append(("feature", source_id))
        if row.get("source_freshness", {}).get("state") != "fresh":
            errors.append("stale_source_snapshot")
        issue = tracker.get(target)
        if issue is None:
            errors.append("missing_target_issue")
            continue
        for dep in row.get("expected_dependencies", []):
            if dep not in issue.get("dependencies", []):
                errors.append("missing_dependency")
        if not issue.get("acceptance_criteria"):
            errors.append("missing_acceptance")

    seen = set()
    for source in source_ids:
        if source in seen:
            errors.append("duplicate_source_row")
        seen.add(source)
    return sorted(set(errors))


def run_negative_cases(payload, tracker):
    cases = []

    duplicate = deepcopy(payload)
    duplicate["backlog_import_rows"].append(deepcopy(duplicate["backlog_import_rows"][0]))
    cases.append(("duplicate_source_row", duplicate, deepcopy(tracker)))

    missing = deepcopy(payload)
    missing["backlog_import_rows"][0].pop("source_row_id", None)
    cases.append(("missing_required_field", missing, deepcopy(tracker)))

    stale = deepcopy(payload)
    stale["backlog_import_rows"][0]["source_freshness"]["state"] = "stale"
    cases.append(("stale_source_snapshot", stale, deepcopy(tracker)))

    missing_dep = deepcopy(payload)
    dep_tracker = deepcopy(tracker)
    target = missing_dep["feature_gap_import_rows"][0]["target_issue_id"]
    dep_tracker[target]["dependencies"] = [
        dep for dep in dep_tracker[target]["dependencies"] if dep != "bd-bp8fl.3.1"
    ]
    cases.append(("missing_dependency", missing_dep, dep_tracker))

    missing_acceptance = deepcopy(payload)
    acceptance_tracker = deepcopy(tracker)
    target = missing_acceptance["feature_gap_import_rows"][0]["target_issue_id"]
    acceptance_tracker[target]["acceptance_criteria"] = ""
    cases.append(("missing_acceptance", missing_acceptance, acceptance_tracker))

    lost = deepcopy(payload)
    lost["feature_gap_import_rows"] = lost["feature_gap_import_rows"][:-1]
    cases.append(("no_feature_loss", lost, deepcopy(tracker)))

    results = []
    for case_id, mutated_payload, mutated_tracker in cases:
        failures = validate_fixture_import(mutated_payload, mutated_tracker)
        expected_failure = "no_feature_loss: feature gap count mismatch" if case_id == "no_feature_loss" else case_id
        status = "pass" if expected_failure in failures else "fail"
        results.append(
            {
                "case_id": case_id,
                "expected_failure_signature": expected_failure,
                "actual_failure_signatures": failures,
                "status": status,
            }
        )
    return results


payload = load_json(artifact_path)
errors = validate_payload(payload)
tracker = build_fixture_tracker(payload)
fixture_errors = [] if mode == "--validate-only" else validate_fixture_import(payload, tracker)
negative_results = [] if mode == "--validate-only" else run_negative_cases(payload, tracker)
for row in negative_results:
    if row["status"] != "pass":
        errors.append(f"negative case failed: {row['case_id']}")
if fixture_errors:
    errors.extend(f"fixture import: {error}" for error in fixture_errors)

commit = source_commit()
fixture_tracker_rows = [tracker[key] for key in sorted(tracker)]
fixture_tracker_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in fixture_tracker_rows),
    encoding="utf-8",
)

log_rows = []
for row in payload.get("backlog_import_rows", []):
    for target in row.get("target_issue_ids", []):
        log_rows.append(
            {
                "trace_id": TRACE_ID,
                "bead_id": BEAD_ID,
                "import_source": row.get("import_source"),
                "source_row_id": row.get("source_row_id"),
                "target_issue_id": target,
                "action": row.get("status_translation", {}).get("action", "reconciled"),
                "expected": row.get("expected"),
                "actual": row.get("actual"),
                "artifact_refs": row.get("artifact_refs", []),
                "source_commit": commit,
                "failure_signature": row.get("failure_signature"),
            }
        )
for row in payload.get("feature_gap_import_rows", []):
    log_rows.append(
        {
            "trace_id": TRACE_ID,
            "bead_id": BEAD_ID,
            "import_source": row.get("import_source"),
            "source_row_id": row.get("source_row_id"),
            "target_issue_id": row.get("target_issue_id"),
            "action": "reconciled_existing_followup_bead",
            "expected": row.get("expected"),
            "actual": row.get("actual"),
            "artifact_refs": row.get("artifact_refs", []),
            "source_commit": commit,
            "failure_signature": row.get("failure_signature"),
        }
    )
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows),
    encoding="utf-8",
)

report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "trace_id": TRACE_ID,
    "generated_at_utc": utc_now(),
    "mode": mode,
    "status": "pass" if not errors else "fail",
    "summary": payload.get("summary", {}),
    "fixture_tracker": {
        "path": rel(fixture_tracker_path),
        "issue_count": len(fixture_tracker_rows),
    },
    "log": {
        "path": rel(log_path),
        "row_count": len(log_rows),
    },
    "negative_case_results": negative_results,
    "artifact_refs": [
        rel(artifact_path),
        "tests/conformance/reality_check_bridge_backlog.v1.json",
        "tests/conformance/feature_parity_gap_ledger.v1.json",
        "tests/conformance/feature_parity_gap_groups.v1.json",
        ".beads/issues.jsonl",
    ],
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print("FAIL: reality bridge import reconciliation failed", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: reality bridge import reconciliation valid "
    f"(backlog_rows={payload['summary']['backlog_import_rows']}, "
    f"feature_gaps={payload['summary']['feature_gap_import_rows']}, "
    f"targets={payload['summary']['unique_target_issue_count']})"
)
PY
