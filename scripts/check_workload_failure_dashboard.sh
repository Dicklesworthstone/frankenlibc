#!/usr/bin/env bash
# check_workload_failure_dashboard.sh -- workload failure minimizer/dashboard for bd-b92jd.3.3
#
# Consumes user workload replay trace rows from bd-b92jd.3.2, groups failures
# into stable classes, and emits compact JSON, Markdown, and JSONL evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_WORKLOAD_FAILURE_DASHBOARD:-${ROOT}/tests/conformance/workload_failure_dashboard.v1.json}"
OUT_DIR="${FRANKENLIBC_WORKLOAD_FAILURE_OUT_DIR:-${ROOT}/target/conformance}"
TRACE_REPORT="${FRANKENLIBC_WORKLOAD_FAILURE_TRACE_REPORT:-${OUT_DIR}/user_workload_replay_traces.report.json}"
TRACE_LOG="${FRANKENLIBC_WORKLOAD_FAILURE_TRACE_LOG:-${OUT_DIR}/user_workload_replay_traces.log.jsonl}"
DASHBOARD_JSON="${FRANKENLIBC_WORKLOAD_FAILURE_REPORT:-${OUT_DIR}/workload_failure_dashboard.report.json}"
DASHBOARD_MD="${FRANKENLIBC_WORKLOAD_FAILURE_MARKDOWN:-${OUT_DIR}/workload_failure_dashboard.md}"
MINIMIZER_LOG="${FRANKENLIBC_WORKLOAD_FAILURE_LOG:-${OUT_DIR}/workload_failure_dashboard.log.jsonl}"
TRACE_TARGET_DIR="${FRANKENLIBC_WORKLOAD_FAILURE_TRACE_TARGET_DIR:-${OUT_DIR}/workload_failure_traces}"
AUTORUN_TRACE="${FRANKENLIBC_WORKLOAD_FAILURE_AUTORUN_TRACE:-1}"

mkdir -p "${OUT_DIR}" "$(dirname "${TRACE_REPORT}")" "$(dirname "${TRACE_LOG}")" \
  "$(dirname "${DASHBOARD_JSON}")" "$(dirname "${DASHBOARD_MD}")" "$(dirname "${MINIMIZER_LOG}")"

TRACE_RUNNER_EXIT=0
if [[ "${AUTORUN_TRACE}" != "0" && ( ! -f "${TRACE_REPORT}" || ! -f "${TRACE_LOG}" ) ]]; then
  set +e
  USER_WORKLOAD_REPLAY_TRACE_REPORT="${TRACE_REPORT}" \
    USER_WORKLOAD_REPLAY_TRACE_LOG="${TRACE_LOG}" \
    USER_WORKLOAD_REPLAY_TARGET_DIR="${TRACE_TARGET_DIR}" \
    "${ROOT}/scripts/run_user_workload_replay_traces.sh" --run >/dev/null
  TRACE_RUNNER_EXIT=$?
  set -e
fi

python3 - "${ROOT}" "${CONTRACT}" "${TRACE_REPORT}" "${TRACE_LOG}" \
  "${DASHBOARD_JSON}" "${DASHBOARD_MD}" "${MINIMIZER_LOG}" "${TRACE_RUNNER_EXIT}" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
trace_report_path = Path(sys.argv[3])
trace_log_path = Path(sys.argv[4])
dashboard_json_path = Path(sys.argv[5])
dashboard_md_path = Path(sys.argv[6])
minimizer_log_path = Path(sys.argv[7])
trace_runner_exit = int(sys.argv[8])

BEAD_ID = "bd-b92jd.3.3"
SOURCE_BEAD_ID = "bd-b92jd.3.2"
TRACE_ID = "bd-b92jd-3-3-workload-failure-dashboard-v1"
NONE_CLASS = "none"
UNKNOWN_CLASS = "unknown"


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, label: str, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label}: cannot read JSON {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label}: must be a JSON object")
        return {}
    return value


def load_jsonl(path: Path, errors: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        content = path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"trace_log: cannot read JSONL {rel(path)}: {exc}")
        return rows
    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"trace_log:{line_number}: malformed JSONL row: {exc}")
            continue
        if not isinstance(value, dict):
            errors.append(f"trace_log:{line_number}: row must be object")
            continue
        rows.append(value)
    return rows


def str_field(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return value if isinstance(value, str) else ""


def list_field(row: dict[str, Any], key: str) -> list[Any]:
    value = row.get(key)
    return value if isinstance(value, list) else []


def validate_contract(contract: dict[str, Any], errors: list[str]) -> None:
    if contract.get("schema_version") != "v1":
        errors.append("contract.schema_version must be v1")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"contract.bead must be {BEAD_ID}")
    if contract.get("source_bead") != SOURCE_BEAD_ID:
        errors.append(f"contract.source_bead must be {SOURCE_BEAD_ID}")
    if contract.get("trace_id") != TRACE_ID:
        errors.append(f"contract.trace_id must be {TRACE_ID}")

    required_classes = contract.get("required_failure_classes")
    expected = {
        "startup_timeout",
        "startup_segv",
        "symbol_lookup",
        "loader_missing_library",
        "parity_mismatch",
        "perf_regression",
        "optional_skip",
        "environment_error",
    }
    if not isinstance(required_classes, list) or set(required_classes) != expected:
        errors.append("contract.required_failure_classes mismatch")

    for section in ["required_row_fields", "required_dashboard_fields", "required_log_fields"]:
        value = contract.get(section)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            errors.append(f"contract.{section} must be an array of strings")

    classification = contract.get("signature_classification")
    if not isinstance(classification, dict):
        errors.append("contract.signature_classification must be an object")
        return
    if not isinstance(classification.get("exact"), dict):
        errors.append("contract.signature_classification.exact must be an object")
    if not isinstance(classification.get("prefixes"), dict):
        errors.append("contract.signature_classification.prefixes must be an object")


def classify_signature(signature: str, contract: dict[str, Any]) -> str:
    if not signature or signature in {"none", "ok"}:
        return NONE_CLASS
    classification = contract.get("signature_classification", {})
    exact = classification.get("exact", {}) if isinstance(classification, dict) else {}
    prefixes = classification.get("prefixes", {}) if isinstance(classification, dict) else {}
    if isinstance(exact, dict) and signature in exact:
        return str(exact[signature])
    if isinstance(prefixes, dict):
        for prefix, failure_class in sorted(prefixes.items(), key=lambda item: -len(str(item[0]))):
            if signature.startswith(str(prefix)):
                return str(failure_class)
    return UNKNOWN_CLASS


def representative(rows: list[dict[str, Any]]) -> dict[str, Any]:
    row = rows[0]
    return {
        "trace_id": str_field(row, "trace_id"),
        "workload_id": str_field(row, "workload_id"),
        "mode": str_field(row, "mode"),
        "status": str_field(row, "status"),
        "failure_signature": str_field(row, "failure_signature"),
        "artifact_refs": list_field(row, "artifact_refs"),
    }


def compact_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "trace_id": str_field(row, "trace_id"),
        "workload_id": str_field(row, "workload_id"),
        "mode": str_field(row, "mode"),
        "status": str_field(row, "status"),
        "failure_signature": str_field(row, "failure_signature"),
        "artifact_refs": list_field(row, "artifact_refs"),
    }


errors: list[str] = []
contract = load_json(contract_path, "contract", errors)
validate_contract(contract, errors)
trace_report = load_json(trace_report_path, "trace_report", errors)
trace_rows = load_jsonl(trace_log_path, errors)

if trace_report and trace_report.get("bead") != SOURCE_BEAD_ID:
    errors.append(f"trace_report.bead must be {SOURCE_BEAD_ID}")
if not trace_rows:
    errors.append("trace_log must contain at least one row")

required_row_fields = contract.get("required_row_fields", [])
if not isinstance(required_row_fields, list):
    required_row_fields = []

class_counts: Counter[str] = Counter()
status_counts: Counter[str] = Counter()
signature_counts: Counter[str] = Counter()
groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
hidden_skip_count = 0
unknown_signature_count = 0

known_statuses = {"pass", "fail", "claim_blocked", "skipped", "not_run", "timeout"}
for index, row in enumerate(trace_rows):
    context = f"trace_rows[{index}]"
    for key in required_row_fields:
        if key not in row:
            errors.append(f"{context}.{key} missing")

    status = str_field(row, "status")
    signature = str_field(row, "failure_signature")
    failure_class = classify_signature(signature, contract)
    row["_failure_class"] = failure_class

    status_counts[status or "<missing>"] += 1
    signature_counts[signature or "<missing>"] += 1
    class_counts[failure_class] += 1

    hidden_skip_row = False
    if status not in known_statuses:
        errors.append(f"{context}.status has unknown value {status!r}")
    if status == "pass" and failure_class != NONE_CLASS:
        errors.append(f"{context}: pass row carries failure signature {signature!r}")
    if status in {"skipped", "claim_blocked", "not_run", "timeout"} and failure_class == NONE_CLASS:
        hidden_skip_row = True
        errors.append(f"{context}: hidden non-pass row without failure signature")
    if status == "skipped" and failure_class != "optional_skip":
        hidden_skip_row = True
        errors.append(f"{context}: skipped row must use optional_skip signature")
    if hidden_skip_row:
        hidden_skip_count += 1
    if failure_class == "optional_skip" and status != "skipped":
        errors.append(f"{context}: optional_skip signature must have skipped status")
    if failure_class == UNKNOWN_CLASS and status != "pass":
        unknown_signature_count += 1
        errors.append(f"{context}: unknown failure signature {signature!r}")

    if failure_class not in {NONE_CLASS, UNKNOWN_CLASS}:
        groups[(failure_class, signature)].append(row)

failure_groups: list[dict[str, Any]] = []
for (failure_class, signature), rows in sorted(groups.items()):
    failure_groups.append(
        {
            "failure_class": failure_class,
            "failure_signature": signature,
            "count": len(rows),
            "statuses": sorted({str_field(row, "status") for row in rows}),
            "representative": representative(rows),
            "workload_modes": [compact_row(row) for row in rows[:5]],
        }
    )

real_regression_classes = {
    str(item)
    for item in contract.get("real_regression_classes", [])
    if isinstance(item, str)
}
next_beads = []
for group in failure_groups:
    if group["failure_class"] not in real_regression_classes:
        continue
    rep = group["representative"]
    workload = rep.get("workload_id") or "unknown_workload"
    mode = rep.get("mode") or "unknown_mode"
    next_beads.append(
        {
            "title": f"Investigate {group['failure_class']} in {workload} ({mode})",
            "failure_class": group["failure_class"],
            "failure_signature": group["failure_signature"],
            "representative_workload_id": workload,
            "representative_mode": mode,
            "artifact_refs": rep.get("artifact_refs", []),
        }
    )

current_commit = source_commit()
status = "pass" if not errors else "fail"
summary = {
    "trace_row_count": len(trace_rows),
    "failure_group_count": len(failure_groups),
    "hidden_skip_count": hidden_skip_count,
    "unknown_signature_count": unknown_signature_count,
    "real_regression_count": len(next_beads),
    "status_counts": dict(sorted(status_counts.items())),
    "class_counts": {key: class_counts.get(key, 0) for key in sorted(set(contract.get("required_failure_classes", [])) | {NONE_CLASS, UNKNOWN_CLASS})},
    "signature_counts": dict(sorted(signature_counts.items())),
}

dashboard = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "source_bead": SOURCE_BEAD_ID,
    "trace_id": TRACE_ID,
    "generated_at_utc": utc_now(),
    "source_commit": current_commit,
    "status": status,
    "trace_runner_exit_status": trace_runner_exit,
    "source_trace_report_status": trace_report.get("status"),
    "input_trace_report": rel(trace_report_path),
    "input_trace_log": rel(trace_log_path),
    "summary": summary,
    "failure_groups": failure_groups,
    "next_beads": next_beads,
    "errors": errors,
    "artifact_refs": [
        rel(contract_path),
        rel(trace_report_path),
        rel(trace_log_path),
        rel(dashboard_json_path),
        rel(dashboard_md_path),
        rel(minimizer_log_path),
    ],
}

dashboard_json_path.write_text(json.dumps(dashboard, indent=2, sort_keys=True) + "\n", encoding="utf-8")

markdown_lines = [
    "# Workload Failure Dashboard",
    "",
    f"- bead: `{BEAD_ID}`",
    f"- status: `{status}`",
    f"- trace rows: `{len(trace_rows)}`",
    f"- failure groups: `{len(failure_groups)}`",
    f"- hidden skips: `{hidden_skip_count}`",
    f"- unknown signatures: `{unknown_signature_count}`",
    "",
    "| class | signature | count | representative |",
    "| --- | --- | ---: | --- |",
]
for group in failure_groups:
    rep = group["representative"]
    representative_id = f"{rep.get('workload_id', '')}:{rep.get('mode', '')}:{rep.get('status', '')}"
    markdown_lines.append(
        f"| `{group['failure_class']}` | `{group['failure_signature']}` | {group['count']} | `{representative_id}` |"
    )
if not failure_groups:
    markdown_lines.append("| `none` | `none` | 0 | `all rows pass` |")

markdown_lines.extend(["", "## Next Beads", ""])
if next_beads:
    for item in next_beads:
        markdown_lines.append(
            f"- {item['title']} (`{item['failure_signature']}`)"
        )
else:
    markdown_lines.append("- No real regression follow-up rows were detected.")

if errors:
    markdown_lines.extend(["", "## Errors", ""])
    for error in errors:
        markdown_lines.append(f"- {error}")
dashboard_md_path.write_text("\n".join(markdown_lines) + "\n", encoding="utf-8")

with minimizer_log_path.open("w", encoding="utf-8") as log:
    for group in failure_groups:
        rep = group["representative"]
        row = {
            "trace_id": TRACE_ID,
            "bead_id": BEAD_ID,
            "event": "workload_failure_group",
            "status": status,
            "failure_class": group["failure_class"],
            "failure_signature": group["failure_signature"],
            "count": group["count"],
            "representative_workload_id": rep.get("workload_id"),
            "representative_mode": rep.get("mode"),
            "artifact_refs": rep.get("artifact_refs", []),
            "source_commit": current_commit,
            "target_dir": rel(dashboard_json_path.parent),
        }
        log.write(json.dumps(row, sort_keys=True) + "\n")
    for error in errors:
        row = {
            "trace_id": TRACE_ID,
            "bead_id": BEAD_ID,
            "event": "workload_failure_dashboard_error",
            "status": "fail",
            "failure_class": "environment_error",
            "failure_signature": "workload_failure_dashboard_invalid",
            "count": 1,
            "representative_workload_id": None,
            "representative_mode": None,
            "artifact_refs": [rel(dashboard_json_path), rel(dashboard_md_path)],
            "source_commit": current_commit,
            "target_dir": rel(dashboard_json_path.parent),
            "error": error,
        }
        log.write(json.dumps(row, sort_keys=True) + "\n")

if errors:
    print("FAIL: workload failure dashboard invalid")
    for error in errors:
        print(f"  - {error}")
    sys.exit(1)

print(f"PASS: workload failure dashboard valid ({len(failure_groups)} groups)")
print(f"json: {rel(dashboard_json_path)}")
print(f"markdown: {rel(dashboard_md_path)}")
print(f"log: {rel(minimizer_log_path)}")
PY
