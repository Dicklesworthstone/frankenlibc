#!/usr/bin/env bash
# Render and validate a reviewer-facing TSM overhead evidence report.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MANIFEST="${FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_MANIFEST:-${ROOT}/tests/conformance/tsm_overhead_evidence_report.v1.json}"
OVERHEAD_EVIDENCE="${FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_OVERHEAD:-}"
CONTENTION_EVIDENCE="${FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_CONTENTION:-}"
OUT_DIR="${FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_OUT_DIR:-${ROOT}/target/conformance/tsm_overhead_evidence_report}"
REPORT_JSON="${FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_JSON:-${OUT_DIR}/tsm_overhead_evidence_report.json}"
REPORT_MD="${FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_MD:-${OUT_DIR}/tsm_overhead_evidence_report.md}"
LOG="${FRANKENLIBC_TSM_OVERHEAD_EVIDENCE_REPORT_LOG:-${OUT_DIR}/tsm_overhead_evidence_report.log.jsonl}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${MANIFEST}" "${OVERHEAD_EVIDENCE}" "${CONTENTION_EVIDENCE}" "${REPORT_JSON}" "${REPORT_MD}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
MANIFEST = pathlib.Path(sys.argv[2])
OVERHEAD_OVERRIDE = sys.argv[3]
CONTENTION_OVERRIDE = sys.argv[4]
REPORT_JSON = pathlib.Path(sys.argv[5])
REPORT_MD = pathlib.Path(sys.argv[6])
LOG = pathlib.Path(sys.argv[7])

EXPECTED_SCHEMA = "tsm_overhead_evidence_report.v1"
OUTPUT_SCHEMA = "tsm_overhead_evidence_report.output.v1"
BEAD = "bd-hdflr"
LOCAL_FALLBACK_MARKERS = ["[RCH] local", "remote execution failed", "local fallback"]
DEFAULT_REQUIRED_MODES = ["strict", "hardened"]
DEFAULT_BUDGETS = {"strict": 20.0, "hardened": 200.0}

errors: list[dict[str, str]] = []
warnings: list[dict[str, str]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def repo_path(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def current_head() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def add_error(signature: str, path: str, message: str) -> None:
    errors.append({"failure_signature": signature, "path": path, "message": message})


def add_warning(signature: str, path: str, message: str) -> None:
    warnings.append({"warning_signature": signature, "path": path, "message": message})


def load_json(path: pathlib.Path, label: str) -> Any | None:
    if not path.exists():
        add_error("missing_evidence", label, f"missing evidence file {rel(path)}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("invalid_json", label, f"invalid JSON in {rel(path)}: {exc}")
        return None


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def string_list(value: Any, fallback: list[str]) -> list[str]:
    if isinstance(value, list) and all(isinstance(item, str) and item for item in value):
        return value
    return fallback


def text_contains_local_fallback(value: Any) -> bool:
    if isinstance(value, str):
        return any(marker in value for marker in LOCAL_FALLBACK_MARKERS)
    if isinstance(value, list):
        return any(text_contains_local_fallback(item) for item in value)
    if isinstance(value, dict):
        return any(text_contains_local_fallback(item) for item in value.values())
    return False


def field_status(ok: bool) -> str:
    return "pass" if ok else "fail"


CURRENT_HEAD = current_head()
manifest = load_json(MANIFEST, "manifest")
if not isinstance(manifest, dict):
    manifest = {}
    add_error("invalid_manifest", "manifest", "manifest root must be an object")
elif manifest.get("schema_version") != EXPECTED_SCHEMA or manifest.get("bead") != BEAD:
    add_error("invalid_manifest", "manifest", "unexpected tsm overhead evidence report manifest identity")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict):
    source_artifacts = {}
    add_error("invalid_manifest", "source_artifacts", "source_artifacts must be an object")

overhead_policy = source_artifacts.get("overhead_budget_evidence", {})
if not isinstance(overhead_policy, dict):
    overhead_policy = {}
contention_policy = source_artifacts.get("contention_lane_contract", {})
if not isinstance(contention_policy, dict):
    contention_policy = {}

overhead_path = repo_path(OVERHEAD_OVERRIDE or str(overhead_policy.get("path", "")))
contention_path = repo_path(CONTENTION_OVERRIDE or str(contention_policy.get("path", "")))
overhead = load_json(overhead_path, "overhead_budget_evidence")
contention = load_json(contention_path, "contention_lane_contract")

budget_rows: list[dict[str, Any]] = []
seen_pairs: set[tuple[str, str]] = set()
remote_ok = True
telemetry_ok = True
budget_ok = True
fresh_rows = 0
stale_rows = 0
schema_golden_rows = 0

budget_policy: dict[str, float] = dict(DEFAULT_BUDGETS)
required_modes = DEFAULT_REQUIRED_MODES
required_families: list[str] = []

if isinstance(overhead, dict):
    if overhead.get("schema_version") != overhead_policy.get("schema_version", "v1"):
        add_error("invalid_json", "overhead_budget_evidence.schema_version", "unexpected overhead evidence schema")
    raw_budget_policy = overhead.get("budget_policy", {})
    if isinstance(raw_budget_policy, dict):
        for mode, field in [("strict", "strict_p99_ns"), ("hardened", "hardened_p99_ns")]:
            if is_number(raw_budget_policy.get(field)) and float(raw_budget_policy[field]) > 0:
                budget_policy[mode] = float(raw_budget_policy[field])
    required_modes = string_list(overhead.get("required_modes"), DEFAULT_REQUIRED_MODES)
    required_families = string_list(overhead.get("required_families"), [])
    records = overhead.get("records")
    if not isinstance(records, list) or not records:
        add_error("missing_budget_row", "overhead_budget_evidence.records", "overhead evidence must contain records")
        records = []
    expected_source_commit = overhead_policy.get("expected_source_commit")
    schema_golden_allowed = overhead_policy.get("schema_golden_allowed") is True
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            add_error("invalid_json", f"overhead.records[{index}]", "record must be an object")
            continue
        mode = record.get("runtime_mode")
        family = record.get("api_family")
        symbol = record.get("symbol")
        p99 = record.get("p99_ns_op")
        budget = budget_policy.get(mode) if isinstance(mode, str) else None
        status = "pass"
        headroom_ns: float | None = None
        if not isinstance(mode, str) or not isinstance(family, str):
            add_error("missing_budget_row", f"overhead.records[{index}]", "record must include runtime_mode and api_family")
            status = "fail"
        else:
            seen_pairs.add((mode, family))
        if not is_number(p99) or float(p99) < 0:
            add_error("budget_regression", f"overhead.records[{index}].p99_ns_op", "p99_ns_op must be a non-negative number")
            status = "fail"
            budget_ok = False
        elif budget is None:
            add_error("missing_budget_row", f"overhead.records[{index}].runtime_mode", f"missing budget for mode {mode!r}")
            status = "fail"
            budget_ok = False
        else:
            headroom_ns = budget - float(p99)
            if float(p99) > budget:
                add_error("budget_regression", f"overhead.records[{index}].p99_ns_op", f"{family}/{mode} p99 {p99} exceeds budget {budget}")
                status = "fail"
                budget_ok = False
        command = record.get("command")
        if not isinstance(command, str) or "RCH_REQUIRE_REMOTE=1" not in command or "rch exec" not in command:
            add_error("missing_rch_remote", f"overhead.records[{index}].command", "record must carry RCH_REQUIRE_REMOTE=1 rch exec evidence")
            remote_ok = False
            status = "fail"
        if text_contains_local_fallback(record):
            add_error("local_fallback_seen", f"overhead.records[{index}]", "record contains a local fallback marker")
            remote_ok = False
            status = "fail"
        decision_count = record.get("decision_count")
        sample_count = record.get("sample_count")
        if record.get("missing_decision_telemetry") is not False or not isinstance(decision_count, int) or not isinstance(sample_count, int) or decision_count < sample_count:
            add_error("missing_runtime_math_telemetry", f"overhead.records[{index}]", "record must include runtime math decision telemetry for every sample")
            telemetry_ok = False
            status = "fail"
        source_commit = record.get("source_commit")
        source_status = "stale"
        if source_commit == CURRENT_HEAD:
            source_status = "current"
            fresh_rows += 1
        elif schema_golden_allowed and isinstance(expected_source_commit, str) and source_commit == expected_source_commit:
            source_status = "schema_golden_not_live"
            schema_golden_rows += 1
        else:
            add_error("stale_source_commit", f"overhead.records[{index}].source_commit", f"source_commit {source_commit!r} is not current HEAD")
            stale_rows += 1
            status = "fail"
        if source_status != "current":
            stale_rows += 1
        artifacts = record.get("artifact_refs")
        if not isinstance(artifacts, list) or not artifacts or not all(isinstance(item, str) and item for item in artifacts):
            add_error("missing_evidence", f"overhead.records[{index}].artifact_refs", "artifact_refs must be a non-empty string list")
            status = "fail"
        budget_rows.append(
            {
                "family": family,
                "mode": mode,
                "symbol": symbol,
                "p99_ns": float(p99) if is_number(p99) else None,
                "budget_ns": budget,
                "headroom_ns": headroom_ns,
                "budget_ratio": (float(p99) / budget) if is_number(p99) and budget else None,
                "status": status,
                "source_commit": source_commit,
                "source_status": source_status,
                "worker_id": record.get("worker_id"),
                "artifact_refs": artifacts if isinstance(artifacts, list) else [],
                "decision_count": decision_count,
            }
        )
    for mode in required_modes:
        for family in required_families:
            if (mode, family) not in seen_pairs:
                add_error("missing_budget_row", "overhead.records", f"missing required {mode}/{family} budget row")
                budget_ok = False

def family_sort_key(row: dict[str, Any]) -> tuple[int, int, str]:
    family = row.get("family")
    mode = row.get("mode")
    family_rank = required_families.index(family) if family in required_families else 999
    mode_rank = required_modes.index(mode) if mode in required_modes else 999
    return (family_rank, mode_rank, str(row.get("symbol") or ""))

budget_rows.sort(key=family_sort_key)
failing_budget_rows = [row for row in budget_rows if row.get("status") == "fail" or (is_number(row.get("headroom_ns")) and float(row["headroom_ns"]) < 0)]
worst_offenders = sorted(
    budget_rows,
    key=lambda row: (
        -float(row.get("budget_ratio") or -1.0),
        -float(row.get("p99_ns") or -1.0),
        str(row.get("family") or ""),
        str(row.get("mode") or ""),
    ),
)[:5]

contention_summary: dict[str, Any] = {
    "smoke_lane_present": False,
    "smoke_can_upgrade_public_readiness": None,
    "permissioned_lane_present": False,
    "permissioned_large_host_present": False,
    "required_release_lane": contention_policy.get("permissioned_release_lane", "permissioned_large_host"),
}
contention_rows: list[dict[str, Any]] = []
lanes_separated = False
permissioned_present = False

if isinstance(contention, dict):
    if contention.get("schema_version") != contention_policy.get("schema_version", "tsm_contention_e2e_lane.v1"):
        add_error("invalid_contention_lane", "contention.schema_version", "unexpected contention lane schema")
    lanes = contention.get("lanes")
    if not isinstance(lanes, list):
        lanes = []
        add_error("invalid_contention_lane", "contention.lanes", "contention lanes must be an array")
    by_id = {lane.get("id"): lane for lane in lanes if isinstance(lane, dict)}
    smoke_id = contention_policy.get("smoke_lane", "smoke_small_host")
    permissioned_id = contention_policy.get("permissioned_release_lane", "permissioned_large_host")
    smoke_lane = by_id.get(smoke_id)
    permissioned_lane = by_id.get(permissioned_id)
    contention_summary["smoke_lane_present"] = isinstance(smoke_lane, dict)
    contention_summary["permissioned_lane_present"] = isinstance(permissioned_lane, dict)
    if not isinstance(smoke_lane, dict) or not isinstance(permissioned_lane, dict):
        add_error("invalid_contention_lane", "contention.lanes", "smoke and permissioned lanes are both required")
    else:
        smoke_upgrade = smoke_lane.get("can_upgrade_public_readiness") is True
        permissioned_upgrade = permissioned_lane.get("can_upgrade_public_readiness") is True
        lanes_separated = not smoke_upgrade and permissioned_upgrade
        contention_summary["smoke_can_upgrade_public_readiness"] = smoke_lane.get("can_upgrade_public_readiness")
        if smoke_upgrade:
            add_error("smoke_claim_upgrade", "contention.lanes.smoke_small_host", "smoke lane must not upgrade public readiness")
    smoke_fixture = contention.get("smoke_fixture")
    if isinstance(smoke_fixture, dict):
        if smoke_fixture.get("can_upgrade_public_readiness") is True or smoke_fixture.get("readiness_claim") != "shape_only":
            add_error("smoke_claim_upgrade", "contention.smoke_fixture", "smoke evidence must remain shape_only")
        contention_rows.append(
            {
                "lane_id": smoke_fixture.get("lane_id"),
                "evidence_class": smoke_fixture.get("evidence_class"),
                "thread_count": smoke_fixture.get("thread_count"),
                "p99_latency_ns": smoke_fixture.get("p99_latency_ns"),
                "readiness_claim": smoke_fixture.get("readiness_claim"),
                "can_upgrade_public_readiness": smoke_fixture.get("can_upgrade_public_readiness"),
                "status": "smoke_shape_only",
            }
        )
    else:
        add_error("missing_evidence", "contention.smoke_fixture", "smoke_fixture is required for shape validation")
    permissioned_fixture = contention.get("permissioned_fixture")
    if isinstance(permissioned_fixture, dict):
        permissioned_present = True
        min_threads = 64
        min_cores = 64
        min_mem = 256
        if isinstance(permissioned_lane, dict):
            policy = permissioned_lane.get("execution_policy", {})
            if isinstance(policy, dict):
                if isinstance(policy.get("thread_count_min"), int):
                    min_threads = int(policy["thread_count_min"])
                host = policy.get("host_profile", {})
                if isinstance(host, dict):
                    if isinstance(host.get("cpu_cores_min"), int):
                        min_cores = int(host["cpu_cores_min"])
                    if isinstance(host.get("memory_gib_min"), int):
                        min_mem = int(host["memory_gib_min"])
        if permissioned_fixture.get("lane_id") != contention_policy.get("permissioned_release_lane", "permissioned_large_host"):
            add_error("invalid_contention_lane", "contention.permissioned_fixture.lane_id", "permissioned fixture must use permissioned lane id")
        if permissioned_fixture.get("can_upgrade_public_readiness") is not True:
            add_error("invalid_contention_lane", "contention.permissioned_fixture.can_upgrade_public_readiness", "permissioned fixture must be claim-upgrade capable")
        if not isinstance(permissioned_fixture.get("thread_count"), int) or permissioned_fixture["thread_count"] < min_threads:
            add_error("invalid_contention_lane", "contention.permissioned_fixture.thread_count", "permissioned fixture does not meet minimum thread count")
        if not isinstance(permissioned_fixture.get("cpu_logical_cores"), int) or permissioned_fixture["cpu_logical_cores"] < min_cores:
            add_error("invalid_contention_lane", "contention.permissioned_fixture.cpu_logical_cores", "permissioned fixture does not meet CPU topology")
        if not isinstance(permissioned_fixture.get("memory_gib"), int) or permissioned_fixture["memory_gib"] < min_mem:
            add_error("invalid_contention_lane", "contention.permissioned_fixture.memory_gib", "permissioned fixture does not meet memory topology")
        if str(permissioned_fixture.get("numa_topology", "")).lower() in {"", "none", "not_required_for_smoke"}:
            add_error("invalid_contention_lane", "contention.permissioned_fixture.numa_topology", "permissioned fixture must include NUMA topology")
        contention_rows.append(
            {
                "lane_id": permissioned_fixture.get("lane_id"),
                "evidence_class": permissioned_fixture.get("evidence_class"),
                "thread_count": permissioned_fixture.get("thread_count"),
                "p99_latency_ns": permissioned_fixture.get("p99_latency_ns"),
                "readiness_claim": permissioned_fixture.get("readiness_claim"),
                "can_upgrade_public_readiness": permissioned_fixture.get("can_upgrade_public_readiness"),
                "status": "permissioned_large_host",
            }
        )
    contention_summary["permissioned_large_host_present"] = permissioned_present

source_current_for_claims = stale_rows == 0 and schema_golden_rows == 0 and bool(budget_rows)
claim_blockers: list[str] = []
if not source_current_for_claims:
    claim_blockers.append("overhead evidence is schema-golden or not current-source live proof")
if not permissioned_present:
    claim_blockers.append("permissioned large-host contention evidence is absent")
if failing_budget_rows:
    claim_blockers.append("one or more budget rows fail")
if not remote_ok:
    claim_blockers.append("RCH remote-only proof is missing or includes local fallback")
if not telemetry_ok:
    claim_blockers.append("runtime-math decision telemetry is missing")

checklist = [
    {
        "id": "strict_hardened_matrix_complete",
        "status": field_status(not any(error["failure_signature"] == "missing_budget_row" for error in errors)),
        "evidence": f"{len(seen_pairs)} mode/family rows observed",
    },
    {
        "id": "no_budget_regressions",
        "status": field_status(budget_ok and not failing_budget_rows),
        "evidence": f"{len(failing_budget_rows)} failing budget rows",
    },
    {
        "id": "rch_remote_evidence_only",
        "status": field_status(remote_ok),
        "evidence": "all budget rows carry RCH_REQUIRE_REMOTE=1 rch exec and no local fallback markers",
    },
    {
        "id": "current_source_for_public_claims",
        "status": "pass" if source_current_for_claims else "block",
        "evidence": f"{fresh_rows} current rows, {schema_golden_rows} schema-golden rows, {max(stale_rows - schema_golden_rows, 0)} stale rows",
    },
    {
        "id": "runtime_math_telemetry_present",
        "status": field_status(telemetry_ok),
        "evidence": "decision_count is present and covers samples for every row",
    },
    {
        "id": "smoke_and_permissioned_lanes_separated",
        "status": field_status(lanes_separated),
        "evidence": "smoke lane cannot upgrade public readiness; permissioned lane is the release lane",
    },
    {
        "id": "permissioned_large_host_evidence_present",
        "status": "pass" if permissioned_present else "block",
        "evidence": "permissioned_large_host fixture present" if permissioned_present else "no permissioned large-host fixture included",
    },
]

status = "pass" if not errors else "fail"
public_claim_allowed = status == "pass" and not claim_blockers
report = {
    "schema_version": OUTPUT_SCHEMA,
    "bead": BEAD,
    "generated_at_utc": utc_now(),
    "current_head": CURRENT_HEAD,
    "manifest": rel(MANIFEST),
    "status": status,
    "public_claim_allowed": public_claim_allowed,
    "claim_blockers": claim_blockers,
    "source_artifacts": {
        "overhead_budget_evidence": rel(overhead_path),
        "contention_lane_contract": rel(contention_path),
    },
    "budget_summary": {
        "required_modes": required_modes,
        "required_families": required_families,
        "budget_policy": budget_policy,
        "row_count": len(budget_rows),
        "failing_budget_rows": failing_budget_rows,
        "worst_offenders": worst_offenders,
        "source_freshness": {
            "current_rows": fresh_rows,
            "schema_golden_rows": schema_golden_rows,
            "stale_rows": max(stale_rows - schema_golden_rows, 0),
        },
    },
    "family_rows": budget_rows,
    "runtime_math_telemetry": {
        "status": field_status(telemetry_ok),
        "records_with_decision_telemetry": len([row for row in budget_rows if isinstance(row.get("decision_count"), int)]),
    },
    "contention_summary": contention_summary,
    "contention_rows": contention_rows,
    "reviewer_checklist": checklist,
    "warnings": warnings,
    "errors": errors,
}


def fmt_float(value: Any) -> str:
    if is_number(value):
        return f"{float(value):.1f}"
    return "n/a"


md_lines = [
    "# TSM Overhead Evidence Report",
    "",
    f"Generated: {report['generated_at_utc']}",
    f"Status: {status.upper()}",
    f"Public performance claim: {'ALLOWED' if public_claim_allowed else 'BLOCKED'}",
    "",
    "## Source Evidence",
    "",
    f"- Overhead budget evidence: `{rel(overhead_path)}`",
    f"- Contention lane contract: `{rel(contention_path)}`",
    f"- Current HEAD: `{CURRENT_HEAD}`",
    f"- Claim blockers: {', '.join(claim_blockers) if claim_blockers else 'none'}",
    "",
    "## Budget Matrix",
    "",
    "| Family | Mode | Symbol | p99 ns | Budget ns | Headroom ns | Status | Source |",
    "|---|---|---|---:|---:|---:|---|---|",
]
for row in budget_rows:
    md_lines.append(
        "| {family} | {mode} | {symbol} | {p99} | {budget} | {headroom} | {status} | {source} |".format(
            family=row.get("family") or "n/a",
            mode=row.get("mode") or "n/a",
            symbol=row.get("symbol") or "n/a",
            p99=fmt_float(row.get("p99_ns")),
            budget=fmt_float(row.get("budget_ns")),
            headroom=fmt_float(row.get("headroom_ns")),
            status=str(row.get("status") or "n/a").upper(),
            source=row.get("source_status") or "n/a",
        )
    )
md_lines.extend(["", "## Worst Offenders", ""])
for row in worst_offenders:
    md_lines.append(
        f"- `{row.get('family')}/{row.get('mode')}` p99={fmt_float(row.get('p99_ns'))} ns, budget={fmt_float(row.get('budget_ns'))} ns, status={str(row.get('status')).upper()}"
    )
md_lines.extend(
    [
        "",
        "## Runtime Math Telemetry",
        "",
        f"- Status: {field_status(telemetry_ok).upper()}",
        f"- Rows with decision telemetry: {report['runtime_math_telemetry']['records_with_decision_telemetry']}",
        "",
        "## Contention Lane Evidence",
        "",
        "| Lane | Evidence Class | Threads | p99 ns | Readiness Claim | Upgrade Public Readiness |",
        "|---|---|---:|---:|---|---|",
    ]
)
for row in contention_rows:
    md_lines.append(
        "| {lane} | {klass} | {threads} | {p99} | {claim} | {upgrade} |".format(
            lane=row.get("lane_id") or "n/a",
            klass=row.get("evidence_class") or "n/a",
            threads=row.get("thread_count") if row.get("thread_count") is not None else "n/a",
            p99=fmt_float(row.get("p99_latency_ns")),
            claim=row.get("readiness_claim") or "n/a",
            upgrade=row.get("can_upgrade_public_readiness"),
        )
    )
md_lines.extend(["", "## Reviewer Checklist", "", "| Item | Status | Evidence |", "|---|---|---|"])
for item in checklist:
    md_lines.append(f"| {item['id']} | {item['status'].upper()} | {item['evidence']} |")
md_lines.extend(["", "## Failure Details", ""])
if errors:
    for error in errors:
        md_lines.append(f"- `{error['failure_signature']}` at `{error['path']}`: {error['message']}")
else:
    md_lines.append("- none")
md_lines.append("")

REPORT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
REPORT_MD.write_text("\n".join(md_lines), encoding="utf-8")

event_specs = [
    ("tsm_overhead_report_sources_loaded", {"status": status, "overhead": rel(overhead_path), "contention": rel(contention_path)}),
    ("tsm_overhead_budget_matrix_rendered", {"rows": len(budget_rows), "failing_rows": len(failing_budget_rows)}),
    ("tsm_overhead_worst_offenders_ranked", {"rows": len(worst_offenders)}),
    ("tsm_overhead_contention_lanes_rendered", {"permissioned_large_host_present": permissioned_present}),
    ("tsm_overhead_reviewer_checklist_rendered", {"items": len(checklist), "public_claim_allowed": public_claim_allowed}),
]
log_rows = []
for seq, (event, details) in enumerate(event_specs, start=1):
    log_rows.append(
        {
            "timestamp": utc_now(),
            "trace_id": f"{BEAD}::tsm_overhead_evidence_report::{seq:03d}",
            "level": "info" if status == "pass" else "error",
            "event": event,
            "bead_id": BEAD,
            "stream": "perf",
            "gate": "tsm_overhead_evidence_report",
            "outcome": "pass" if status == "pass" else "fail",
            "failure_signature": "none" if status == "pass" else errors[0]["failure_signature"],
            "source_commit": CURRENT_HEAD,
            "artifact_refs": [rel(REPORT_JSON), rel(REPORT_MD)],
            "details": details,
        }
    )
LOG.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in log_rows), encoding="utf-8")

print(json.dumps({"status": status, "public_claim_allowed": public_claim_allowed, "budget_rows": len(budget_rows)}, sort_keys=True))
if errors:
    raise SystemExit(1)
PY
