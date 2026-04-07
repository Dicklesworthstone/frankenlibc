#!/usr/bin/env bash
# check_reverse_round_contracts.sh — CI gate for bd-2a2.4 / bd-2a2.5
# Regenerates the reverse-round contract artifact and emits E2E verification
# evidence for cross-round composition and milestone branch diversity.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/reverse_round_contracts.v1.json"
OUT_DIR="$REPO_ROOT/target/conformance"
LOG_PATH="$OUT_DIR/reverse_round_contracts.log.jsonl"
GATE_REPORT_PATH="$OUT_DIR/reverse_round_contracts.report.json"

mkdir -p "$OUT_DIR"

echo "=== Reverse-Round Contract Verification Gate (bd-2a2.5) ==="
echo "--- Generating reverse-round contract report ---"
python3 "$SCRIPT_DIR/generate_reverse_round_contracts.py" -o "$REPORT"

if [ ! -f "$REPORT" ]; then
    echo "FAIL: reverse-round contract report not generated"
    exit 1
fi

python3 - "$REPORT" "$LOG_PATH" "$GATE_REPORT_PATH" <<'PY'
import json
import sys
from datetime import datetime, timezone

report_path, log_path, gate_report_path = sys.argv[1:4]
contract_ref = "tests/conformance/reverse_round_contracts.v1.json"
log_ref = "target/conformance/reverse_round_contracts.log.jsonl"
gate_report_ref = "target/conformance/reverse_round_contracts.report.json"


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_check(checks, logs, check_id, gate_name, ok, summary_line, artifact_refs, details):
    status = "pass" if ok else "fail"
    level = "info" if ok else "error"
    checks.append(
        {
            "gate": check_id,
            "name": gate_name,
            "status": status,
            "summary_line": summary_line,
            "artifact_refs": artifact_refs,
            "details": details,
        }
    )
    logs.append(
        {
            "timestamp": now_utc(),
            "trace_id": f"bd-2a2.5::reverse-round-contracts::{check_id}",
            "level": level,
            "event": "reverse_round.contracts.check",
            "bead_id": "bd-2a2.5",
            "gate": gate_name,
            "mode": "strict",
            "api_family": "runtime_math",
            "symbol": check_id,
            "decision_path": "reverse_round_contracts",
            "healing_action": "none",
            "errno": 0,
            "latency_ns": 0,
            "artifact_refs": artifact_refs,
            "details": {
                "status": status,
                "summary_line": summary_line,
                "evaluated_modes": ["strict", "hardened"],
                **details,
            },
        }
    )


with open(report_path, encoding="utf-8") as handle:
    report = json.load(handle)

summary = report.get("summary", {})
rounds = report.get("round_results", {})
cross_round = report.get("cross_round_integrations", {})
milestones = report.get("milestone_branch_diversity", {})

checks = []
logs = []

total_families = summary.get("total_math_families", 0)
modules_found = summary.get("modules_found", 0)
invariants_specified = summary.get("invariants_specified", 0)
invariants_total = summary.get("invariants_total", 0)
classes = summary.get("math_class_count", 0)
all_rounds_diverse = summary.get("all_rounds_diverse", False)
all_milestones_diverse = summary.get("all_milestones_diverse", False)

append_check(
    checks,
    logs,
    "round-count",
    "R7-R11 round coverage",
    len(rounds) >= 5,
    f"{len(rounds)} rounds verified",
    [contract_ref],
    {"round_count": len(rounds)},
)
append_check(
    checks,
    logs,
    "module-coverage",
    "Runtime math module coverage",
    modules_found == total_families and total_families > 0,
    f"{modules_found}/{total_families} runtime-math modules found",
    [contract_ref],
    {"modules_found": modules_found, "total_math_families": total_families},
)
append_check(
    checks,
    logs,
    "invariant-coverage",
    "Reverse-round invariant coverage",
    invariants_specified == invariants_total and invariants_total > 0,
    f"{invariants_specified}/{invariants_total} invariants specified",
    [contract_ref],
    {
        "invariants_specified": invariants_specified,
        "invariants_total": invariants_total,
    },
)
append_check(
    checks,
    logs,
    "per-round-diversity",
    "Per-round branch diversity",
    all_rounds_diverse,
    f"all_rounds_diverse={all_rounds_diverse}",
    [contract_ref],
    {
        "all_rounds_diverse": all_rounds_diverse,
        "math_class_count": classes,
    },
)
append_check(
    checks,
    logs,
    "overall-class-diversity",
    "Overall math-class diversity",
    classes >= 5,
    f"{classes} distinct math classes across rounds",
    [contract_ref],
    {"math_class_count": classes},
)
append_check(
    checks,
    logs,
    "legacy-anchors",
    "Legacy surface anchors present",
    all(bool(round_data.get("legacy_surfaces")) for round_data in rounds.values()),
    "all rounds include legacy surface anchors",
    [contract_ref],
    {"rounds_with_anchors": sorted(rounds)},
)

for integration_id, integration in sorted(cross_round.items()):
    supporting_refs = [
        item["path"] for item in integration.get("supporting_files", []) if item.get("exists")
    ]
    append_check(
        checks,
        logs,
        f"integration:{integration_id}",
        f"Cross-round integration: {integration['name']}",
        integration.get("passes_integration", False),
        (
            f"{integration_id} spans {'+'.join(integration['rounds'])} with "
            f"{integration['branch_diversity']['class_count']} math classes"
        ),
        [contract_ref, *supporting_refs],
        {
            "rounds": integration["rounds"],
            "class_count": integration["branch_diversity"]["class_count"],
            "max_single_class_pct": integration["branch_diversity"]["max_single_class_pct"],
            "supporting_files_found": integration.get("supporting_files_found", 0),
            "verification_hooks_found": integration.get("verification_hooks_found", 0),
        },
    )

for milestone_id, milestone in sorted(milestones.items()):
    supporting_refs = [
        item["path"] for item in milestone.get("supporting_files", []) if item.get("exists")
    ]
    append_check(
        checks,
        logs,
        f"milestone:{milestone_id}",
        f"Milestone branch diversity: {milestone['name']}",
        milestone.get("passes_milestone", False),
        (
            f"{milestone_id} spans {'+'.join(milestone['rounds'])} with "
            f"{milestone['branch_diversity']['class_count']} classes and "
            f"max share {milestone['branch_diversity']['max_single_class_pct']}%"
        ),
        [contract_ref, *supporting_refs],
        {
            "rounds": milestone["rounds"],
            "class_count": milestone["branch_diversity"]["class_count"],
            "max_single_class_pct": milestone["branch_diversity"]["max_single_class_pct"],
            "supporting_files_found": milestone.get("supporting_files_found", 0),
            "verification_hooks_found": milestone.get("verification_hooks_found", 0),
        },
    )

failed_checks = sum(1 for check in checks if check["status"] == "fail")
status = "pass" if failed_checks == 0 else "fail"

logs.append(
    {
        "timestamp": now_utc(),
        "trace_id": "bd-2a2.5::reverse-round-contracts::summary",
        "level": "info" if failed_checks == 0 else "error",
        "event": "reverse_round.contracts.summary",
        "bead_id": "bd-2a2.5",
        "gate": "Reverse-round contracts summary",
        "mode": "strict",
        "api_family": "runtime_math",
        "symbol": "bd-2a2.5",
        "decision_path": "reverse_round_contracts",
        "healing_action": "none",
        "errno": 0,
        "latency_ns": 0,
        "artifact_refs": [contract_ref, gate_report_ref, log_ref],
        "details": {
            "status": status,
            "total_checks": len(checks),
            "failed_checks": failed_checks,
            "evaluated_modes": ["strict", "hardened"],
            "cross_round_checks_passing": summary.get("cross_round_checks_passing", 0),
            "cross_round_checks_total": summary.get("cross_round_checks_total", 0),
            "milestones_diverse": summary.get("milestones_diverse", 0),
            "milestones_verified": summary.get("milestones_verified", 0),
            "all_milestones_diverse": all_milestones_diverse,
        },
    }
)

with open(log_path, "w", encoding="utf-8") as handle:
    for entry in logs:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")

gate_report = {
    "schema_version": "v1",
    "bead": "bd-2a2.5",
    "status": status,
    "contract_report": contract_ref,
    "contract_hash": report.get("report_hash"),
    "summary": {
        "total_checks": len(checks),
        "passed_checks": len(checks) - failed_checks,
        "failed_checks": failed_checks,
        "all_rounds_diverse": all_rounds_diverse,
        "cross_round_checks_total": summary.get("cross_round_checks_total", 0),
        "cross_round_checks_passing": summary.get("cross_round_checks_passing", 0),
        "milestones_verified": summary.get("milestones_verified", 0),
        "milestones_diverse": summary.get("milestones_diverse", 0),
        "all_milestones_diverse": all_milestones_diverse,
        "max_milestone_class_share_pct": summary.get("max_milestone_class_share_pct", 0.0),
    },
    "checks": checks,
    "artifacts": {
        "contract_report": contract_ref,
        "structured_log": log_ref,
        "gate_report": gate_report_ref,
    },
}

with open(gate_report_path, "w", encoding="utf-8") as handle:
    json.dump(gate_report, handle, indent=2)
    handle.write("\n")

print(f"Rounds:                  {len(rounds)}")
print(f"Cross-round integrations:{summary.get('cross_round_checks_passing', 0)}/{summary.get('cross_round_checks_total', 0)}")
print(f"Milestones diverse:      {summary.get('milestones_diverse', 0)}/{summary.get('milestones_verified', 0)}")
print(f"All milestones diverse:  {all_milestones_diverse}")

if failed_checks:
    print(f"FAIL: reverse-round contract gate found {failed_checks} failing check(s)")
    print(f"Contract report: {contract_ref}")
    print(f"Gate report:     {gate_report_ref}")
    print(f"Structured log:  {log_ref}")
    sys.exit(1)

print("PASS: reverse-round cross-round integration and milestone diversity verified")
print(f"Contract report: {contract_ref}")
print(f"Gate report:     {gate_report_ref}")
print(f"Structured log:  {log_ref}")
PY
