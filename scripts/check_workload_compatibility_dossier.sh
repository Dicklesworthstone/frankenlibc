#!/usr/bin/env bash
# check_workload_compatibility_dossier.sh -- workload compatibility dossier for bd-fp4tm.5
#
# Combines workload acceptance, freshness, reproducer, latency, smoke,
# release, replacement, and compatibility evidence into a machine-readable
# user-facing dossier. Ready recommendations fail closed if they rest only on
# prose or stale evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_WORKLOAD_DOSSIER_CONTRACT:-${ROOT}/tests/conformance/workload_compatibility_dossier.v1.json}"
ACCEPTANCE="${FRANKENLIBC_WORKLOAD_DOSSIER_ACCEPTANCE:-${ROOT}/tests/conformance/user_workload_acceptance_matrix.v1.json}"
FRESHNESS="${FRANKENLIBC_WORKLOAD_DOSSIER_FRESHNESS:-${ROOT}/target/conformance/workload_evidence_freshness.report.json}"
REPRODUCER="${FRANKENLIBC_WORKLOAD_DOSSIER_REPRODUCER:-${ROOT}/target/conformance/workload_reproducer_manifest.v1.json}"
LATENCY="${FRANKENLIBC_WORKLOAD_DOSSIER_LATENCY:-${ROOT}/target/conformance/workload_latency_budget_join.report.json}"
SMOKE="${FRANKENLIBC_WORKLOAD_DOSSIER_SMOKE:-${ROOT}/tests/conformance/ld_preload_smoke_summary.v1.json}"
RELEASE="${FRANKENLIBC_WORKLOAD_DOSSIER_RELEASE:-${ROOT}/tests/conformance/release_readme_example_workload_gate.v1.json}"
REPLACEMENT="${FRANKENLIBC_WORKLOAD_DOSSIER_REPLACEMENT:-${ROOT}/tests/conformance/replacement_levels.json}"
USER_COMPAT="${FRANKENLIBC_WORKLOAD_DOSSIER_USER_COMPAT:-${ROOT}/tests/conformance/user_compatibility_report.v1.json}"
OUT_DIR="${FRANKENLIBC_WORKLOAD_DOSSIER_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_WORKLOAD_DOSSIER_REPORT:-${OUT_DIR}/workload_compatibility_dossier.report.json}"
MARKDOWN="${FRANKENLIBC_WORKLOAD_DOSSIER_MARKDOWN:-${OUT_DIR}/workload_compatibility_dossier.md}"
LOG="${FRANKENLIBC_WORKLOAD_DOSSIER_LOG:-${OUT_DIR}/workload_compatibility_dossier.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${MARKDOWN}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${ACCEPTANCE}" "${FRESHNESS}" "${REPRODUCER}" \
  "${LATENCY}" "${SMOKE}" "${RELEASE}" "${REPLACEMENT}" "${USER_COMPAT}" \
  "${REPORT}" "${MARKDOWN}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
acceptance_path = Path(sys.argv[3])
freshness_path = Path(sys.argv[4])
reproducer_path = Path(sys.argv[5])
latency_path = Path(sys.argv[6])
smoke_path = Path(sys.argv[7])
release_path = Path(sys.argv[8])
replacement_path = Path(sys.argv[9])
user_compat_path = Path(sys.argv[10])
report_path = Path(sys.argv[11])
markdown_path = Path(sys.argv[12])
log_path = Path(sys.argv[13])

BEAD_ID = "bd-fp4tm.5"
PROSE_REFS = {"README.md", "CHANGELOG.md"}


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


SOURCE_COMMIT = source_commit()


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def normalize_rel(path: Any) -> str:
    if not isinstance(path, str) or not path:
        return ""
    candidate = Path(path)
    if candidate.is_absolute():
        return rel(candidate)
    return candidate.as_posix()


def configured_report_fields(contract: dict[str, Any]) -> list[str]:
    report_contract = contract.get("report_contract")
    if not isinstance(report_contract, dict):
        return []
    fields = report_contract.get("must_materialize")
    if not isinstance(fields, list):
        return []
    return [field for field in fields if isinstance(field, str) and field]


def validate_report_contract(contract: dict[str, Any], report: dict[str, Any]) -> list[str]:
    report_contract = contract.get("report_contract")
    if not isinstance(report_contract, dict):
        return ["missing_report_contract"]
    errors: list[str] = []
    fields = report_contract.get("must_materialize")
    if not isinstance(fields, list) or not all(isinstance(field, str) and field for field in fields):
        errors.append("report_contract.must_materialize must be a non-empty string list")
        fields = []
    outputs = contract.get("outputs", {})
    canonical_report = rel(root / str(outputs.get("dossier_json", ""))) if isinstance(outputs, dict) else ""
    canonical_markdown = rel(root / str(outputs.get("dossier_markdown", ""))) if isinstance(outputs, dict) else ""
    canonical_log = rel(root / str(outputs.get("jsonl_log", ""))) if isinstance(outputs, dict) else ""
    expected_report = normalize_rel(report_contract.get("output_path"))
    expected_markdown = normalize_rel(report_contract.get("markdown_path"))
    expected_log = normalize_rel(report_contract.get("log_path"))
    actual_report = rel(report_path)
    actual_markdown = rel(markdown_path)
    actual_log = rel(log_path)
    if actual_report == canonical_report and expected_report != actual_report:
        errors.append(f"report_contract.output_path expected {actual_report} got {expected_report or '<missing>'}")
    if actual_markdown == canonical_markdown and expected_markdown != actual_markdown:
        errors.append(f"report_contract.markdown_path expected {actual_markdown} got {expected_markdown or '<missing>'}")
    if actual_log == canonical_log and expected_log != actual_log:
        errors.append(f"report_contract.log_path expected {actual_log} got {expected_log or '<missing>'}")
    missing = [field for field in fields if field not in report]
    if missing:
        errors.append("report_contract missing materialized fields: " + ", ".join(missing))
    return errors


def load_json(path: Path, label: str, errors: list[str], required: bool = True) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        if required:
            errors.append(f"{label}: dossier_missing_input_artifact: cannot read {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label}: dossier_missing_input_artifact: must be object")
        return {}
    return value


def validate_contract(contract: dict[str, Any], errors: list[str]) -> None:
    if contract.get("schema_version") != "v1":
        errors.append("contract: dossier_missing_required_field: schema_version must be v1")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"contract: dossier_missing_required_field: bead must be {BEAD_ID}")
    for key in ["required_dossier_fields", "recommendation_classes", "ready_policy"]:
        if key not in contract:
            errors.append(f"contract: dossier_missing_required_field: {key} missing")


def string_field(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return value if isinstance(value, str) else ""


def list_field(row: dict[str, Any], key: str) -> list[str]:
    value = row.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def claim_rows(acceptance: dict[str, Any], release: dict[str, Any]) -> list[dict[str, Any]]:
    rows = acceptance.get("claim_rows")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]

    mappings = release.get("claim_mappings")
    if isinstance(mappings, list):
        result: list[dict[str, Any]] = []
        for item in mappings:
            if not isinstance(item, dict):
                continue
            result.append(
                {
                    "workload_id": item.get("workload_id"),
                    "claim_scope": item.get("claim_id"),
                    "replacement_level": item.get("replacement_level", "L0"),
                    "runtime_modes": item.get("runtime_modes", []),
                    "artifact_refs": item.get("evidence_refs", []),
                    "strict_status": "pass" if "strict" in item.get("runtime_modes", []) else "not_applicable",
                    "hardened_status": "pass" if "hardened" in item.get("runtime_modes", []) else "not_applicable",
                }
            )
        return result
    return []


def index_by_workload(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        workload_id = string_field(row, "workload_id")
        if workload_id and workload_id not in result:
            result[workload_id] = row
    return result


def freshness_rows(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = report.get("workload_rows")
    if isinstance(rows, list):
        return index_by_workload([row for row in rows if isinstance(row, dict)])
    return {}


def reproducer_rows(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest.get("reproducers")
    if isinstance(rows, list):
        return index_by_workload([row for row in rows if isinstance(row, dict)])
    return {}


def latency_rows(report: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    rows = report.get("workload_latency_rows")
    if not isinstance(rows, list):
        return result
    for row in rows:
        if not isinstance(row, dict):
            continue
        workload_id = string_field(row, "workload_id")
        mode = string_field(row, "mode")
        if workload_id and mode:
            result[(workload_id, mode)] = row
    return result


def current_level(replacement: dict[str, Any]) -> str:
    return string_field(replacement, "current_level") or "L0"


def mode_status(row: dict[str, Any], mode: str, latency_index: dict[tuple[str, str], dict[str, Any]]) -> str:
    explicit = string_field(row, f"{mode}_status")
    if explicit:
        return explicit
    latency = latency_index.get((string_field(row, "workload_id"), mode))
    if latency:
        decision = string_field(latency, "decision")
        if decision == "pass":
            return "pass"
        if decision == "skip":
            return "skipped"
        return "fail"
    modes = set(list_field(row, "runtime_modes"))
    if mode in modes:
        return "pass"
    return "not_applicable"


def freshness_state(row: dict[str, Any], freshness_index: dict[str, dict[str, Any]], freshness_report: dict[str, Any]) -> str:
    explicit = string_field(row, "freshness_state")
    if explicit:
        return explicit
    found = freshness_index.get(string_field(row, "workload_id"))
    if found:
        return string_field(found, "freshness_state") or "current"
    if freshness_report.get("status") == "pass":
        return "current"
    return "stale"


def perf_state(workload_id: str, latency_index: dict[tuple[str, str], dict[str, Any]]) -> str:
    states = [
        string_field(row, "perf_state")
        for (candidate, _mode), row in latency_index.items()
        if candidate == workload_id
    ]
    if any(state in {"over_budget", "missing_latency", "stale_evidence", "missing_budget"} for state in states):
        return "blocked"
    if any(state == "overloaded_skip" for state in states):
        return "overloaded_skip"
    if any(state == "within_budget" for state in states):
        return "within_budget"
    return "unknown"


def concrete_refs(refs: list[str]) -> list[str]:
    return [ref for ref in refs if ref not in PROSE_REFS and not ref.endswith(".md")]


def recommendation_and_failure(
    row: dict[str, Any],
    strict_status: str,
    hardened_status: str,
    fresh_state: str,
    perf: str,
    replacement_level: str,
    current_replacement: str,
    repro: dict[str, Any] | None,
) -> tuple[str, str, str]:
    if fresh_state != "current":
        return ("stale_evidence", "dossier_ready_from_stale_evidence", "Refresh workload evidence before making a compatibility recommendation.")
    if string_field(row, "unsupported") == "true" or string_field(row, "failure_signature") == "unsupported_workload":
        return ("unsupported_workload", "unsupported_workload", "Keep the workload unsupported until a concrete reproducer and support row exist.")
    if replacement_level != current_replacement:
        return ("replacement_blocked", "replacement_level_blocked", "Do not recommend a replacement level above the current claim-control level.")
    if perf == "blocked":
        return ("replacement_blocked", "workload_latency_over_budget", "Resolve latency-budget blockers before recommending this workload.")
    if (
        strict_status == "pass"
        and hardened_status in {"pass", "not_applicable"}
        and perf not in {"within_budget", "overloaded_skip"}
    ):
        return ("replacement_blocked", "workload_latency_missing_evidence", "Add latency-budget join evidence before recommending this workload.")
    if strict_status == "pass" and hardened_status == "pass":
        return ("ready_l0_interpose", "none", "Use L0 interpose with the cited strict and hardened evidence.")
    if strict_status == "pass" and hardened_status not in {"pass", "not_applicable"}:
        signature = string_field(repro or {}, "failure_signature") or "hardened_mode_degraded"
        return ("hardened_only_degraded", signature, "Use strict mode; hardened mode needs the cited reproducer before recommendation.")
    if strict_status == "pass":
        return ("ready_l0_interpose", "none", "Use L0 interpose for the cited strict-mode workload.")
    signature = string_field(repro or {}, "failure_signature") or "workload_not_ready"
    return ("replacement_blocked", signature, "Keep the workload blocked until strict-mode evidence passes.")


errors: list[str] = []
contract = load_json(contract_path, "contract", errors)
acceptance = load_json(acceptance_path, "acceptance", errors)
freshness = load_json(freshness_path, "freshness", errors)
reproducer = load_json(reproducer_path, "reproducer", errors)
latency = load_json(latency_path, "latency", errors)
smoke = load_json(smoke_path, "smoke", errors)
release = load_json(release_path, "release", errors)
replacement = load_json(replacement_path, "replacement", errors)
user_compat = load_json(user_compat_path, "user_compat", errors)
validate_contract(contract, errors)

claims = claim_rows(acceptance, release)
if not claims:
    errors.append("claims: dossier_missing_claim_rows: no workload claim rows available")

freshness_index = freshness_rows(freshness)
reproducer_index = reproducer_rows(reproducer)
latency_index = latency_rows(latency)
current_replacement = current_level(replacement)

dossier_rows: list[dict[str, Any]] = []
for index, claim in enumerate(claims):
    workload_id = string_field(claim, "workload_id") or f"workload-{index}"
    replacement_level = string_field(claim, "replacement_level") or current_replacement
    strict = mode_status(claim, "strict", latency_index)
    hardened = mode_status(claim, "hardened", latency_index)
    fresh_state = freshness_state(claim, freshness_index, freshness)
    perf = perf_state(workload_id, latency_index)
    repro = reproducer_index.get(workload_id)
    recommendation, failure_signature, next_safe_action = recommendation_and_failure(
        claim,
        strict,
        hardened,
        fresh_state,
        perf,
        replacement_level,
        current_replacement,
        repro,
    )
    if fresh_state != "current":
        errors.append(f"{workload_id}: dossier_ready_from_stale_evidence: stale evidence blocks compatibility dossier")
    refs = sorted(
        set(
            list_field(claim, "artifact_refs")
            + list_field(freshness_index.get(workload_id, {}), "artifact_refs")
            + list_field(repro or {}, "artifact_refs")
            + [
                rel(acceptance_path),
                rel(freshness_path),
                rel(reproducer_path),
                rel(latency_path),
                rel(smoke_path),
                rel(release_path),
                rel(replacement_path),
                rel(user_compat_path),
            ]
        )
    )
    if recommendation == "ready_l0_interpose" and len(concrete_refs(list_field(claim, "artifact_refs"))) < 2:
        errors.append(f"{workload_id}: dossier_ready_from_prose_only: ready recommendation lacks concrete evidence")
        failure_signature = "dossier_ready_from_prose_only"
        recommendation = "replacement_blocked"
        next_safe_action = "Add concrete workload evidence before recommending readiness."
    if recommendation == "ready_l0_interpose" and fresh_state != "current":
        errors.append(f"{workload_id}: dossier_ready_from_stale_evidence: ready recommendation uses stale evidence")
        failure_signature = "dossier_ready_from_stale_evidence"
        recommendation = "stale_evidence"
        next_safe_action = "Refresh workload evidence before recommending readiness."

    row = {
        "trace_id": f"{BEAD_ID}::{index}::{workload_id}",
        "bead_id": BEAD_ID,
        "workload_id": workload_id,
        "claim_scope": string_field(claim, "claim_scope") or workload_id,
        "replacement_level": replacement_level,
        "strict_status": strict,
        "hardened_status": hardened,
        "freshness_state": fresh_state,
        "perf_state": perf,
        "failure_signature": failure_signature,
        "user_recommendation": recommendation,
        "artifact_refs": refs,
        "exact_reproduction_command": string_field(repro or {}, "reproduction_command"),
        "source_commit": SOURCE_COMMIT,
        "next_safe_action": next_safe_action,
    }
    dossier_rows.append(row)

required_fields = contract.get("required_dossier_fields", [])
if isinstance(required_fields, list):
    for row in dossier_rows:
        for field in required_fields:
            if field not in row:
                errors.append(f"{row.get('workload_id', '<missing>')}: dossier_missing_required_field: {field}")

recommendation_counts = Counter(row["user_recommendation"] for row in dossier_rows)
failure_counts = Counter(row["failure_signature"] for row in dossier_rows)
report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "status": "pending",
    "generated_at_utc": utc_now(),
    "source_commit": SOURCE_COMMIT,
    "contract": rel(contract_path),
    "summary": {
        "workload_count": len(dossier_rows),
        "recommendation_counts": dict(sorted(recommendation_counts.items())),
        "failure_signature_counts": dict(sorted(failure_counts.items())),
    },
    "dossier_rows": dossier_rows,
    "failure_signatures": sorted(
        {
            part.split(": ", 2)[1]
            for part in errors
            if part.count(": ") >= 2 and part.split(": ", 2)[1].startswith("dossier_")
        }
    ),
    "errors": errors,
    "artifact_refs": [
        rel(contract_path),
        rel(log_path),
        rel(markdown_path),
    ],
    "report_path": rel(report_path),
    "markdown_path": rel(markdown_path),
    "log_path": rel(log_path),
    "report_contract_fields": configured_report_fields(contract),
    "contract_status": "pending",
    "contract_errors": [],
}
contract_errors = validate_report_contract(contract, report)
report["contract_errors"] = contract_errors
report["contract_status"] = "pass" if not contract_errors else "fail"
if contract_errors:
    errors.extend(f"report_contract: {error}" for error in contract_errors)
report["status"] = "pass" if not errors else "fail"
report["errors"] = errors

markdown_lines = [
    "# Workload Compatibility Dossier",
    "",
    f"Status: `{report['status']}`",
    "",
]
for row in dossier_rows:
    markdown_lines.extend(
        [
            f"## {row['workload_id']}",
            "",
            f"- recommendation: `{row['user_recommendation']}`",
            f"- strict: `{row['strict_status']}`",
            f"- hardened: `{row['hardened_status']}`",
            f"- freshness: `{row['freshness_state']}`",
            f"- perf: `{row['perf_state']}`",
            f"- failure: `{row['failure_signature']}`",
            "",
        ]
    )

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in dossier_rows), encoding="utf-8")
markdown_path.write_text("\n".join(markdown_lines) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if report["status"] == "pass" else 1)
PY
