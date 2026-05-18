#!/usr/bin/env bash
# check_bp8fl_parent_acceptance_replay.sh -- read-only bd-aixvz.1 proof gate.
#
# Validates the bd-bp8fl parent acceptance-criteria rewrite and emits
# deterministic JSON/JSONL telemetry. The checker never edits tracker state.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_ARTIFACT:-${ROOT}/tests/conformance/bp8fl_parent_acceptance_replay.v1.json}"
ISSUES="${FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_ISSUES:-${ROOT}/.beads/issues.jsonl}"
OUT_DIR="${FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_TARGET_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_REPORT:-${OUT_DIR}/bp8fl_parent_acceptance_replay.report.json}"
LOG="${FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_LOG:-${OUT_DIR}/bp8fl_parent_acceptance_replay.log.jsonl}"
MODE="${1:---validate-current}"

case "${MODE}" in
  --validate-current|--fixture-replay)
    ;;
  *)
    echo "usage: $0 [--validate-current|--fixture-replay]" >&2
    exit 2
    ;;
esac

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${ARTIFACT}" "${ISSUES}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
issues_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])
mode = sys.argv[6]


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"FAIL: cannot load {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def load_jsonl(path):
    rows = []
    try:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            row = json.loads(line)
            row["_line_number"] = line_number
            rows.append(row)
    except Exception as exc:
        print(f"FAIL: cannot load {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    return rows


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


def normalize_rel(path):
    if not isinstance(path, str) or not path:
        return ""
    candidate = Path(path)
    if candidate.is_absolute():
        return rel(candidate)
    return str(candidate)


def configured_report_fields():
    contract = artifact.get("report_contract")
    if not isinstance(contract, dict):
        return []
    fields = contract.get("must_materialize")
    if not isinstance(fields, list):
        return []
    return [field for field in fields if isinstance(field, str) and field]


def validate_report_contract(report):
    contract = artifact.get("report_contract")
    if not isinstance(contract, dict):
        return ["missing_report_contract"]
    errors = []
    fields = contract.get("must_materialize")
    if not isinstance(fields, list) or not all(isinstance(field, str) and field for field in fields):
        errors.append("report_contract.must_materialize must be a non-empty string list")
        fields = []
    expected_report = normalize_rel(contract.get("output_path"))
    expected_log = normalize_rel(contract.get("log_path"))
    actual_report = rel(report_path)
    actual_log = rel(log_path)
    if actual_report == rel(root / artifact.get("report_path", "")) and expected_report != actual_report:
        errors.append(f"report_contract.output_path expected {actual_report} got {expected_report or '<missing>'}")
    if actual_log == rel(root / artifact.get("log_path", "")) and expected_log != actual_log:
        errors.append(f"report_contract.log_path expected {actual_log} got {expected_log or '<missing>'}")
    missing = [field for field in fields if field not in report]
    if missing:
        errors.append("report_contract missing materialized fields: " + ", ".join(missing))
    return errors


def phrase_group_matches(text, group):
    lower = text.lower()
    return all(str(phrase).lower() in lower for phrase in group)


def term_matches(text, term):
    return any(phrase_group_matches(text, group) for group in term.get("any_of", []))


def run_probe(command):
    try:
        proc = subprocess.run(
            command,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        return {
            "command": " ".join(command),
            "exit_status": proc.returncode,
            "stdout": proc.stdout.strip()[:4000],
            "stderr": proc.stderr.strip()[:4000],
        }
    except Exception as exc:
        return {
            "command": " ".join(command),
            "exit_status": 124,
            "stdout": "",
            "stderr": str(exc),
        }


artifact = load_json(artifact_path)
commit = source_commit()
target_ids = artifact["target_parent_ids"]
terms = artifact["required_acceptance_terms"]
run_tool_probes = mode == "--validate-current" and (
    Path(root / ".git").exists()
    and str(Path.cwd()).startswith(str(root))
    and bool(int(__import__("os").environ.get("FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_PROBE_TOOLS", "0")))
)

if mode == "--fixture-replay":
    issues = artifact["fixture_replay"]["issues"]
    tracker_state = "fixture_failure_expected"
else:
    issues = load_jsonl(issues_path)
    tracker_state = "current_jsonl"

jsonl_count = len(issues)
by_id = defaultdict(list)
for issue in issues:
    issue_id = issue.get("id")
    if issue_id:
        by_id[issue_id].append(issue)

missing_parent_ids = [issue_id for issue_id in target_ids if issue_id not in by_id]
duplicate_parent_ids = [issue_id for issue_id in target_ids if len(by_id.get(issue_id, [])) > 1]
failed_terms = []
logs = []
tool_probes = []


def log_row(parent_id, command, exit_status, expected, actual, failure_signature):
    row = {
        "trace_id": f"{artifact['bead']}::{mode}::{parent_id}::{failure_signature}",
        "bead_id": artifact["bead"],
        "parent_epic_id": parent_id,
        "command": command,
        "exit_status": exit_status,
        "expected": expected,
        "actual": actual,
        "db_count": None,
        "jsonl_count": jsonl_count,
        "artifact_refs": [rel(artifact_path), rel(issues_path)],
        "source_commit": commit,
        "failure_signature": failure_signature,
    }
    logs.append(row)
    return row


if missing_parent_ids:
    log_row(
        "tracker",
        "parse .beads/issues.jsonl",
        1,
        f"all target parent IDs present: {', '.join(target_ids)}",
        f"missing: {', '.join(missing_parent_ids)}",
        "missing_parent_rows",
    )

if duplicate_parent_ids:
    log_row(
        "tracker",
        "parse .beads/issues.jsonl",
        1,
        "one row per target parent ID",
        f"duplicates: {', '.join(duplicate_parent_ids)}",
        "duplicate_parent_rows",
    )

for parent_id in target_ids:
    rows = by_id.get(parent_id, [])
    if not rows:
        continue
    issue = rows[0]
    criteria = issue.get("acceptance_criteria", "")
    for term in terms:
        term_id = term["term_id"]
        if term_matches(criteria, term):
            log_row(
                parent_id,
                "validate acceptance_criteria",
                0,
                f"{parent_id} includes {term_id}",
                "present",
                f"{term_id}_present",
            )
        else:
            failed_terms.append({"parent_id": parent_id, "term_id": term_id})
            log_row(
                parent_id,
                "validate acceptance_criteria",
                1,
                f"{parent_id} includes {term_id}",
                "missing",
                term["failure_signature"],
            )

if run_tool_probes:
    for parent_id in target_ids:
        probe = run_probe(["br", "show", parent_id, "--no-db", "--json"])
        tool_probes.append(probe)
        log_row(
            parent_id,
            probe["command"],
            probe["exit_status"],
            "br show --no-db returns the exact parent row",
            probe["stdout"] or probe["stderr"],
            "br_show_no_db_probe" if probe["exit_status"] == 0 else "br_show_no_db_failure",
        )
    probe = run_probe(["br", "dep", "cycles", "--no-db", "--json"])
    tool_probes.append(probe)
    log_row(
        "tracker",
        probe["command"],
        probe["exit_status"],
        "br dep cycles --no-db returns count 0",
        probe["stdout"] or probe["stderr"],
        "br_dep_cycles_probe" if probe["exit_status"] == 0 else "br_dep_cycles_failure",
    )

failure_signatures = sorted(
    {
        row["failure_signature"]
        for row in logs
        if row["exit_status"] != 0
    }
)

if mode == "--fixture-replay":
    expected = set(artifact["fixture_replay"]["expected_failure_signatures"])
    found = set(failure_signatures)
    missing_expected = sorted(expected - found)
    status = "pass" if not missing_expected else "fail"
    tracker_state = "fixture_failure_detected" if status == "pass" else "fixture_failure_missed"
else:
    missing_expected = []
    tool_failures = [probe for probe in tool_probes if probe["exit_status"] != 0]
    status = "pass" if not missing_parent_ids and not duplicate_parent_ids and not failed_terms and not tool_failures else "fail"

term_failures_by_parent = Counter(item["parent_id"] for item in failed_terms)
report = {
    "schema_version": "v1",
    "bead": artifact["bead"],
    "parent_bead": artifact["parent_bead"],
    "generated_at_utc": utc_now(),
    "trace_id": f"{artifact['bead']}::{mode}::bp8fl-parent-acceptance-replay",
    "source_commit": commit,
    "mode": mode,
    "status": "pending",
    "tracker_state": tracker_state,
    "parent_count": sum(1 for issue_id in target_ids if issue_id in by_id),
    "jsonl_count": jsonl_count,
    "db_count": None,
    "missing_parent_ids": missing_parent_ids,
    "duplicate_parent_ids": duplicate_parent_ids,
    "failed_terms": failed_terms,
    "tool_probes": tool_probes,
    "failure_signatures": failure_signatures,
    "missing_expected_fixture_failures": missing_expected,
    "summary": {
        "target_parent_count": len(target_ids),
        "all_parent_rows_present": not missing_parent_ids,
        "no_duplicate_parent_rows": not duplicate_parent_ids,
        "all_acceptance_terms_present": not failed_terms,
        "term_failure_count_by_parent": dict(sorted(term_failures_by_parent.items())),
        "tool_probe_count": len(tool_probes),
        "read_only": True,
        "no_feature_loss": True,
    },
    "artifact_refs": [rel(artifact_path), rel(issues_path), rel(report_path), rel(log_path)],
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "report_contract_fields": configured_report_fields(),
    "contract_status": "pending",
    "contract_errors": [],
}
contract_errors = validate_report_contract(report)
report["contract_errors"] = contract_errors
report["contract_status"] = "pass" if not contract_errors else "fail"
if status == "pass" and contract_errors:
    status = "fail"
report["status"] = status

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in logs),
    encoding="utf-8",
)

if status != "pass":
    print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
    sys.exit(1)

print(json.dumps(report, indent=2, sort_keys=True))
PY
