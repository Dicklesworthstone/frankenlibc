#!/usr/bin/env bash
# check_feature_parity_drift.sh — fail-fast parity-truth drift gate for bd-w2c3.1.2
#
# Validates:
# 1) FEATURE_PARITY gap ledger is up-to-date.
# 2) docs/env mismatch report is up-to-date.
# 3) Drift diagnostics include ownership for all unresolved gaps.
# 4) Ownership loss fails with actionable diagnostics:
#    gap_id, owner_bead, source_file, expected_vs_actual.
#
# Exit codes:
#   0 => all unresolved drift items are owned by active beads
#   1 => at least one unresolved drift item has missing/closed ownership
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GAP_LEDGER="${FLC_FP_GAP_LEDGER:-${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json}"
ENV_REPORT="${FLC_FP_ENV_REPORT:-${ROOT}/tests/conformance/env_docs_code_mismatch_report.v1.json}"
ISSUES_JSONL="${FLC_FP_ISSUES_JSONL:-${ROOT}/.beads/issues.jsonl}"
OUT="${FLC_FP_DRIFT_DIAGNOSTICS:-${ROOT}/tests/conformance/feature_parity_drift_diagnostics.v1.json}"

TRACE_ID="bd-w2c3.1.2-$(date -u +%Y%m%dT%H%M%SZ)-$$"
START_NS="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"

for path in "${GAP_LEDGER}" "${ENV_REPORT}" "${ISSUES_JSONL}"; do
    if [[ ! -f "${path}" ]]; then
        echo "FAIL: required input missing: ${path}" >&2
        exit 1
    fi
done

# Upstream reproducibility gates must be clean first.
"${ROOT}/scripts/check_feature_parity_gap_ledger.sh" >/dev/null
python3 "${ROOT}/scripts/generate_docs_env_mismatch_report.py" --root "${ROOT}" --check >/dev/null

python3 - "${GAP_LEDGER}" "${ENV_REPORT}" "${ISSUES_JSONL}" "${OUT}" "${TRACE_ID}" "${START_NS}" <<'PY'
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import sys

gap_ledger_path = Path(sys.argv[1])
env_report_path = Path(sys.argv[2])
issues_path = Path(sys.argv[3])
out_path = Path(sys.argv[4])
trace_id = sys.argv[5]
start_ns = int(sys.argv[6])

ACTIVE_OWNER_STATUSES = {"open", "in_progress", "blocked", "deferred"}


def first_source_path(provenance: Any) -> str:
    if isinstance(provenance, dict):
        return str(provenance.get("path", "unknown"))
    if isinstance(provenance, list) and provenance:
        first = provenance[0]
        if isinstance(first, dict):
            return str(first.get("path", "unknown"))
    return "unknown"


def load_issues(path: Path) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        obj = json.loads(line)
        issue_id = obj.get("id")
        if isinstance(issue_id, str) and issue_id:
            statuses[issue_id] = str(obj.get("status", "unknown"))
    return statuses


def owner_for_gap(gap: dict[str, Any]) -> str:
    kind = str(gap.get("kind", ""))
    if kind == "machine_delta_drift":
        delta_id = str(gap.get("delta_id", ""))
        if delta_id == "machine.support_vs_reality":
            return "bd-w2c3.10.1"
        if delta_id == "machine.replacement_vs_reality":
            return "bd-w2c3.2.3"
        return "bd-w2c3.1.2"
    if kind == "parse_error":
        return "bd-w2c3.1.1"
    section = str(gap.get("section", ""))
    section_owner = {
        "macro_targets": "bd-w2c3.1",
        "runtime_math": "bd-w2c3.5",
        "reverse_core": "bd-w2c3.4",
        "proof_math": "bd-w2c3.6",
        "gap_summary": "bd-w2c3.10",
    }
    return section_owner.get(section, "bd-w2c3.1.2")


def build_diag(
    *,
    gap_id: str,
    kind: str,
    owner_bead: str,
    source_file: str,
    expected_vs_actual: dict[str, Any],
    message: str,
    issues_status: dict[str, str],
) -> dict[str, Any]:
    owner_status = issues_status.get(owner_bead, "missing")
    owned = owner_status in ACTIVE_OWNER_STATUSES
    return {
        "gap_id": gap_id,
        "kind": kind,
        "owner_bead": owner_bead,
        "owner_status": owner_status,
        "ownership_ok": owned,
        "status": "tracked" if owned else "fail",
        "source_file": source_file,
        "expected_vs_actual": expected_vs_actual,
        "message": message,
    }


gap_ledger = json.loads(gap_ledger_path.read_text(encoding="utf-8"))
env_report = json.loads(env_report_path.read_text(encoding="utf-8"))
issues_status = load_issues(issues_path)

deltas_by_id = {
    str(delta.get("delta_id")): delta for delta in gap_ledger.get("deltas", []) if isinstance(delta, dict)
}

diagnostics: list[dict[str, Any]] = []
for gap in gap_ledger.get("gaps", []):
    if not isinstance(gap, dict):
        continue
    kind = str(gap.get("kind", ""))
    gap_id = str(gap.get("gap_id", ""))
    if not gap_id:
        continue

    owner = owner_for_gap(gap)
    source = first_source_path(gap.get("provenance"))
    message = str(gap.get("message", "feature parity unresolved drift"))
    drift_kind = kind
    expected_vs_actual: dict[str, Any]

    if kind == "feature_parity_row_status":
        drift_kind = "status_drift"
        expected_vs_actual = {
            "expected": {"status": "DONE"},
            "actual": {"status": str(gap.get("status", "UNKNOWN"))},
        }
    elif kind == "machine_delta_drift":
        delta_id = str(gap.get("delta_id", ""))
        delta = deltas_by_id.get(delta_id, {})
        if delta_id == "machine.support_vs_reality":
            drift_kind = "stale_count_drift"
        elif delta_id == "machine.replacement_vs_reality":
            drift_kind = "replacement_claim_contradiction"
        else:
            drift_kind = "machine_delta_drift"
        expected_vs_actual = {
            "expected": delta.get("expected", {}),
            "actual": delta.get("actual", {}),
        }
    elif kind == "parse_error":
        drift_kind = "parse_error"
        expected_vs_actual = {"expected": {"parse_errors": 0}, "actual": {"message": message}}
    else:
        expected_vs_actual = {
            "expected": {"status": "resolved"},
            "actual": {"status": str(gap.get("status", "UNKNOWN"))},
        }

    diagnostics.append(
        build_diag(
            gap_id=gap_id,
            kind=drift_kind,
            owner_bead=owner,
            source_file=source,
            expected_vs_actual=expected_vs_actual,
            message=message,
            issues_status=issues_status,
        )
    )

env_summary = env_report.get("summary", {})
env_counts = [
    ("missing_in_docs_count", "env-doc.missing-in-docs", "documentation coverage drift"),
    ("missing_in_code_count", "env-doc.missing-in-code", "stale docs key not present in runtime usage"),
    ("semantic_drift_count", "env-doc.semantic-drift", "semantic mismatch between docs and runtime behavior"),
]
for key, gap_id, message in env_counts:
    count = int(env_summary.get(key, 0))
    if count <= 0:
        continue
    diagnostics.append(
        build_diag(
            gap_id=gap_id,
            kind="env_doc_mismatch",
            owner_bead="bd-29b.3",
            source_file=env_report_path.as_posix(),
            expected_vs_actual={"expected": {"count": 0}, "actual": {"count": count}},
            message=message,
            issues_status=issues_status,
        )
    )

unresolved_ambiguous = env_report.get("unresolved_ambiguous", [])
if isinstance(unresolved_ambiguous, list) and unresolved_ambiguous:
    diagnostics.append(
        build_diag(
            gap_id="env-doc.unresolved-ambiguous",
            kind="env_doc_mismatch",
            owner_bead="bd-29b.3",
            source_file=env_report_path.as_posix(),
            expected_vs_actual={"expected": {"count": 0}, "actual": {"count": len(unresolved_ambiguous)}},
            message="unresolved ambiguous env docs mismatches",
            issues_status=issues_status,
        )
    )

diagnostics.sort(key=lambda row: (row["status"], row["kind"], row["gap_id"]))
kind_counts = Counter(row["kind"] for row in diagnostics)
fail_count = sum(1 for row in diagnostics if row["status"] == "fail")
tracked_count = sum(1 for row in diagnostics if row["status"] == "tracked")

generated_at = str(gap_ledger.get("generated_at", "")).strip() or datetime.now(timezone.utc).replace(
    microsecond=0
).isoformat().replace("+00:00", "Z")

payload = {
    "schema_version": "v1",
    "bead": "bd-w2c3.1.2",
    "generated_at": generated_at,
    "sources": {
        "feature_parity_gap_ledger": gap_ledger_path.as_posix(),
        "env_docs_code_mismatch_report": env_report_path.as_posix(),
        "issues": issues_path.as_posix(),
    },
    "summary": {
        "diagnostic_count": len(diagnostics),
        "tracked_count": tracked_count,
        "fail_count": fail_count,
        "kind_counts": dict(sorted(kind_counts.items())),
    },
    "diagnostics": diagnostics,
}

out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

elapsed_ns = time.time_ns() - start_ns
event = {
    "trace_id": trace_id,
    "mode": "strict",
    "api_family": "feature_parity",
    "symbol": "all",
    "decision_path": "deny" if fail_count > 0 else "allow",
    "healing_action": "none",
    "errno": 1 if fail_count > 0 else 0,
    "latency_ns": int(elapsed_ns),
    "artifact_refs": [
        out_path.as_posix(),
        gap_ledger_path.as_posix(),
        env_report_path.as_posix(),
    ],
}
print(json.dumps(event, separators=(",", ":")))

if fail_count > 0:
    print("FAIL: feature parity drift ownership loss detected")
    for row in diagnostics:
        if row["status"] != "fail":
            continue
        print(
            "  - "
            f"gap_id={row['gap_id']} owner_bead={row['owner_bead']} "
            f"owner_status={row['owner_status']} source_file={row['source_file']}"
        )
    raise SystemExit(1)

print(
    "PASS: feature parity drift diagnostics generated "
    f"(diagnostics={len(diagnostics)}, tracked={tracked_count}, fail={fail_count})"
)
PY
