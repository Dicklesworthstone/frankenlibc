#!/usr/bin/env bash
# check_workload_evidence_freshness.sh -- fail-closed workload evidence freshness gate for bd-fp4tm.2.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_WORKLOAD_EVIDENCE_CONTRACT:-${ROOT}/tests/conformance/workload_evidence_freshness_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_WORKLOAD_EVIDENCE_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_WORKLOAD_EVIDENCE_REPORT:-${OUT_DIR}/workload_evidence_freshness.report.json}"
LOG="${FRANKENLIBC_WORKLOAD_EVIDENCE_LOG:-${OUT_DIR}/workload_evidence_freshness.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import re
import shlex
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

BEAD_ID = "bd-fp4tm.2"
SOURCE_BEAD_ID = "bd-fp4tm.1"
HEX_COMMIT = re.compile(r"^[0-9a-f]{40}$")
TARGET_PREFIXES = ("target/",)
PLACEHOLDER_TOKENS = ("<run_id>",)
GENERATED_EVIDENCE_PREFIX = "target/conformance/"

errors: list[str] = []
failure_signatures: list[str] = []
logs: list[dict[str, Any]] = []
accepted_static_baselines: list[dict[str, str]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def add_failure(message: str, signature: str) -> None:
    errors.append(message)
    if signature not in failure_signatures:
        failure_signatures.append(signature)


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_failure(f"{label}: cannot parse {rel(path)}: {exc}", "artifact_unreadable")
        return {}
    if not isinstance(value, dict):
        add_failure(f"{label}: {rel(path)} must be a JSON object", "artifact_invalid_shape")
        return {}
    return value


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def repo_path(path_text: str) -> Path | None:
    path = Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        return None
    return root / path


def is_generated_ref(path_text: str) -> bool:
    return path_text.startswith(TARGET_PREFIXES) or any(token in path_text for token in PLACEHOLDER_TOKENS)


def parse_utc(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def check_timestamp_not_future(label: str, value: Any) -> None:
    if not isinstance(value, str):
        return
    parsed = parse_utc(value)
    if parsed is None:
        return
    now = datetime.now(timezone.utc)
    if parsed.timestamp() > now.timestamp() + 60:
        add_failure(
            f"{label}: generated timestamp is in the future: {value}",
            "future_generated_at",
        )


def check_source_commit(label: str, value: Any, *, static_ok: bool) -> str:
    if value in (None, ""):
        if static_ok:
            accepted_static_baselines.append(
                {
                    "artifact": label,
                    "reason": "source_commit_missing_but_row_policy_requires_generated_report_head",
                }
            )
            return "accepted_static_recipe"
        add_failure(f"{label}: source_commit missing", "missing_source_commit")
        return "fail"
    if not isinstance(value, str):
        add_failure(f"{label}: source_commit must be string when present", "invalid_source_commit")
        return "fail"
    if value in {"current", source_commit, "unknown"}:
        return "current"
    if HEX_COMMIT.match(value):
        add_failure(
            f"{label}: source_commit {value} does not match current HEAD {source_commit}",
            "stale_source_commit",
        )
        return "fail"
    add_failure(f"{label}: unrecognized source_commit policy {value!r}", "invalid_source_commit")
    return "fail"


def artifact_dates(data: dict[str, Any]) -> list[tuple[str, Any]]:
    fields = [
        "generated_at_utc",
        "generated_utc",
        "generated_at",
        "checked_at_utc",
        "run_id",
    ]
    return [(field, data.get(field)) for field in fields if field in data]


def check_artifact_metadata(path: Path, source_id: str) -> str:
    if path.suffix != ".json":
        return "not_json"
    data = load_json(path, f"{source_id}:{rel(path)}")
    state = "current"
    if not data:
        return "fail"
    for field, value in artifact_dates(data):
        check_timestamp_not_future(f"{source_id}:{rel(path)}.{field}", value)
    if "source_commit" in data:
        state = check_source_commit(
            f"{source_id}:{rel(path)}",
            data.get("source_commit"),
            static_ok=True,
        )
    elif data.get("source_commit_freshness_policy") or data.get("freshness"):
        state = "policy_declared"
    else:
        accepted_static_baselines.append(
            {
                "artifact": f"{source_id}:{rel(path)}",
                "reason": "no_source_commit_field_static_manifest",
            }
        )
        state = "accepted_static_recipe"
    return state


def required_fields_ok(source: dict[str, Any], required: list[str], source_id: str) -> bool:
    ok = True
    for field in required:
        if field not in source:
            add_failure(f"{source_id}: missing required field {field}", "missing_required_field")
            ok = False
    return ok


def list_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def shell_words(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def command_mentions_cargo(command: str) -> bool:
    return any(word == "cargo" or word.startswith("cargo ") for word in shell_words(command))


def validate_remote_cargo_command(source_id: str, command: str) -> None:
    if not command_mentions_cargo(command):
        return
    words = shell_words(command)
    if "[RCH] local" in command or "local fallback" in command.lower():
        add_failure(f"{source_id}: validation_command must not accept local rch fallback output", "local_fallback_validation_marker")
    has_force_remote = "RCH_FORCE_REMOTE=true" in words
    has_rch_cargo = any(words[index] == "rch" and index + 1 < len(words) and words[index + 1] == "cargo" for index in range(len(words)))
    has_rch_exec = any(words[index] == "rch" and index + 1 < len(words) and words[index + 1] == "exec" for index in range(len(words)))
    if not has_force_remote or not (has_rch_cargo or has_rch_exec):
        add_failure(
            f"{source_id}: cargo validation_command must use RCH_FORCE_REMOTE=true with rch cargo or rch exec",
            "non_remote_cargo_validation",
        )


def validate_generated_evidence_refs(source_id: str, source: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    generated_refs = list_strings(source.get("generated_evidence_refs"))
    if policy.get("generated_report_required") is True and not generated_refs:
        add_failure(f"{source_id}: generated_evidence_refs must name target/conformance report/log outputs", "missing_generated_evidence_ref")
    if not generated_refs:
        return []
    has_report = False
    has_log = False
    for ref in generated_refs:
        if not ref.startswith(GENERATED_EVIDENCE_PREFIX):
            add_failure(f"{source_id}: generated evidence ref must be under target/conformance: {ref}", "invalid_generated_evidence_ref")
        has_report = has_report or ref.endswith(".report.json")
        has_log = has_log or ref.endswith(".log.jsonl") or ref.endswith(".rows.jsonl")
    if not has_report:
        add_failure(f"{source_id}: generated_evidence_refs must include a report JSON", "missing_generated_report_ref")
    if not has_log:
        add_failure(f"{source_id}: generated_evidence_refs must include a JSONL log", "missing_generated_log_ref")
    return generated_refs


contract = load_json(contract_path, "contract")
if not contract:
    report = {
        "schema_version": "v1",
        "bead": BEAD_ID,
        "source_contract_bead": SOURCE_BEAD_ID,
        "status": "fail",
        "source_commit": source_commit,
        "generated_at_utc": utc_now(),
        "contract_path": rel(contract_path),
        "errors": errors,
        "failure_signatures": failure_signatures,
        "log_path": rel(log_path),
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text("", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    sys.exit(1)

if contract.get("schema_version") != "v1":
    add_failure("contract.schema_version must be v1", "invalid_contract_schema")
if contract.get("bead") != SOURCE_BEAD_ID:
    add_failure(f"contract.bead must be {SOURCE_BEAD_ID}", "invalid_contract_bead")

check_source_commit("contract", contract.get("source_commit"), static_ok=False)
check_timestamp_not_future("contract.generated_at_utc", contract.get("generated_at_utc"))

required_source_fields = list_strings(contract.get("required_evidence_source_fields"))
required_policy_fields = list_strings(contract.get("required_freshness_policy_fields"))
if not required_source_fields:
    add_failure("contract.required_evidence_source_fields must be a non-empty string array", "invalid_contract_schema")
if not required_policy_fields:
    add_failure("contract.required_freshness_policy_fields must be a non-empty string array", "invalid_contract_schema")

claim_ref_ids = set()
for claim in contract.get("claim_refs", []):
    if isinstance(claim, dict) and isinstance(claim.get("id"), str):
        claim_ref_ids.add(claim["id"])
if not claim_ref_ids:
    add_failure("contract.claim_refs must name at least one claim ref", "invalid_contract_schema")

evidence_sources = contract.get("evidence_sources", [])
if not isinstance(evidence_sources, list) or not evidence_sources:
    add_failure("contract.evidence_sources must be a non-empty array", "invalid_contract_schema")
    evidence_sources = []

seen_ids: set[str] = set()
report_rows: list[dict[str, Any]] = []

for source in evidence_sources:
    if not isinstance(source, dict):
        add_failure("evidence source row must be an object", "invalid_contract_schema")
        continue

    source_id = str(source.get("id", "<missing-source-id>"))
    row_errors_before = len(errors)
    row_signatures_before = set(failure_signatures)
    freshness_states: set[str] = set()

    if source_id in seen_ids:
        add_failure(f"{source_id}: duplicate evidence source id", "duplicate_source_id")
    seen_ids.add(source_id)

    required_fields_ok(source, required_source_fields, source_id)

    source_claim_refs = list_strings(source.get("claim_refs"))
    for claim_ref in source_claim_refs:
        if claim_ref not in claim_ref_ids:
            add_failure(f"{source_id}: unknown claim_ref {claim_ref}", "unknown_claim_ref")

    policy = source.get("freshness_policy")
    if not isinstance(policy, dict):
        add_failure(f"{source_id}: freshness_policy must be object", "missing_freshness_policy")
        policy = {}
    for field in required_policy_fields:
        if field not in policy or policy.get(field) in (None, "", []):
            add_failure(f"{source_id}: freshness_policy missing {field}", "missing_freshness_policy")

    source_artifact = source.get("source_artifact")
    if isinstance(source_artifact, str) and source_artifact:
        source_path = repo_path(source_artifact)
        if source_path is None or not source_path.exists():
            add_failure(f"{source_id}: missing source_artifact {source_artifact}", "missing_source_artifact")
            freshness_states.add("fail")
        else:
            freshness_states.add(check_artifact_metadata(source_path, source_id))
    else:
        add_failure(f"{source_id}: source_artifact must be a repo-relative path", "missing_source_artifact")

    artifact_refs = list_strings(source.get("artifact_refs"))
    if not artifact_refs:
        add_failure(f"{source_id}: artifact_refs must be a non-empty string array", "missing_artifact_ref")
    for artifact_ref in artifact_refs:
        if is_generated_ref(artifact_ref):
            continue
        artifact_path = repo_path(artifact_ref)
        if artifact_path is None or not artifact_path.exists():
            add_failure(f"{source_id}: artifact ref missing: {artifact_ref}", "missing_artifact_ref")
            freshness_states.add("fail")
        elif artifact_path.suffix == ".json":
            freshness_states.add(check_artifact_metadata(artifact_path, source_id))

    validation_command = source.get("validation_command")
    if not isinstance(validation_command, str) or not validation_command.strip():
        add_failure(f"{source_id}: validation_command must be non-empty", "missing_validation_command")
        validation_command = ""
    else:
        validate_remote_cargo_command(source_id, validation_command)
    generated_evidence_refs = validate_generated_evidence_refs(source_id, source, policy)

    if not isinstance(source.get("stale_failure_signature"), str) or not source.get("stale_failure_signature"):
        add_failure(f"{source_id}: stale_failure_signature must be non-empty", "missing_failure_signature")

    if not isinstance(source.get("next_safe_action"), str) or not source.get("next_safe_action"):
        add_failure(f"{source_id}: next_safe_action must be non-empty", "missing_next_safe_action")

    if source_id == "claim-field-contract" or source.get("owner_family") == "documentation_claim_control":
        refs_joined = "\n".join(artifact_refs)
        has_replay = (
            "user_workload_replay_manifest.v1.json" in refs_joined
            or "run_user_workload_replay_traces.sh" in refs_joined
        )
        has_smoke = "ld_preload_smoke_summary.v1.json" in refs_joined
        if not has_replay or not has_smoke:
            add_failure(
                f"{source_id}: compatibility claim-control source must cite replay and smoke evidence",
                "compatibility_claim_without_replay_evidence",
            )

    row_errors = errors[row_errors_before:]
    row_signatures = [
        signature for signature in failure_signatures if signature not in row_signatures_before
    ]
    if row_errors:
        row_status = "fail"
        freshness_state = "fail"
    elif "accepted_static_recipe" in freshness_states:
        row_status = "pass"
        freshness_state = "accepted_static_recipe"
    elif "bounded_snapshot" == source.get("freshness_state"):
        row_status = "pass"
        freshness_state = "bounded_snapshot"
    else:
        row_status = "pass"
        freshness_state = "current"

    workloads = list_strings(source.get("covered_workload_ids")) or [source_id]
    for workload_id in workloads:
        logs.append(
            {
                "trace_id": f"{BEAD_ID}::{source_id}::{workload_id}",
                "bead_id": BEAD_ID,
                "source_id": source_id,
                "workload_id": workload_id,
                "source_artifact": source.get("source_artifact", ""),
                "freshness_state": freshness_state,
                "source_commit": source_commit,
                "generated_at_utc": contract.get("generated_at_utc", ""),
                "max_age_policy": "refresh_on_declared_trigger",
                "validation_command": source.get("validation_command", ""),
                "artifact_refs": artifact_refs,
                "generated_evidence_refs": generated_evidence_refs,
                "failure_signature": row_signatures[0] if row_signatures else "none",
                "next_safe_action": source.get("next_safe_action", ""),
                "status": row_status,
            }
        )

    report_rows.append(
        {
            "id": source_id,
            "owner_family": source.get("owner_family", ""),
            "source_artifact": source.get("source_artifact", ""),
            "freshness_state": freshness_state,
            "status": row_status,
            "validation_command": source.get("validation_command", ""),
            "generated_evidence_refs": generated_evidence_refs,
            "stale_failure_signature": source.get("stale_failure_signature", ""),
            "covered_workload_count": len(workloads),
            "artifact_refs": artifact_refs,
            "errors": row_errors,
        }
    )

summary = {
    "evidence_source_count": len(report_rows),
    "passed_source_count": sum(1 for row in report_rows if row["status"] == "pass"),
    "failed_source_count": sum(1 for row in report_rows if row["status"] == "fail"),
    "log_row_count": len(logs),
    "accepted_static_baseline_count": len(accepted_static_baselines),
}

report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "source_contract_bead": SOURCE_BEAD_ID,
    "status": "pass" if not errors else "fail",
    "source_commit": source_commit,
    "generated_at_utc": utc_now(),
    "contract_path": rel(contract_path),
    "summary": summary,
    "accepted_static_baselines": accepted_static_baselines,
    "evidence_sources": report_rows,
    "errors": errors,
    "failure_signatures": failure_signatures,
    "log_path": rel(log_path),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as fh:
    for row in logs:
        fh.write(json.dumps(row, sort_keys=True) + "\n")

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if not errors else 1)
PY
