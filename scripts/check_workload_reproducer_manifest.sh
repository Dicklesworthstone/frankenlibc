#!/usr/bin/env bash
# check_workload_reproducer_manifest.sh -- fail-closed reproducer manifest gate for bd-fp4tm.3
#
# Consumes workload replay and LD_PRELOAD smoke JSONL failure rows and emits
# compact, replayable reproducer records. The checker never builds artifacts or
# reruns broad workload gates; callers provide the trace rows to minimize.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_WORKLOAD_REPRODUCER_CONTRACT:-${ROOT}/tests/conformance/workload_reproducer_manifest.v1.json}"
INPUTS="${FRANKENLIBC_WORKLOAD_REPRODUCER_INPUTS:-${ROOT}/target/conformance/user_workload_replay_traces.log.jsonl}"
OUT_DIR="${FRANKENLIBC_WORKLOAD_REPRODUCER_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_WORKLOAD_REPRODUCER_REPORT:-${OUT_DIR}/workload_reproducer_manifest.report.json}"
MANIFEST="${FRANKENLIBC_WORKLOAD_REPRODUCER_MANIFEST:-${OUT_DIR}/workload_reproducer_manifest.v1.json}"
LOG="${FRANKENLIBC_WORKLOAD_REPRODUCER_LOG:-${OUT_DIR}/workload_reproducer_manifest.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${MANIFEST}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${INPUTS}" "${REPORT}" "${MANIFEST}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
input_spec = sys.argv[3]
report_path = Path(sys.argv[4])
manifest_path = Path(sys.argv[5])
log_path = Path(sys.argv[6])

BEAD_ID = "bd-fp4tm.3"
DEFAULT_TIMEOUT_MS = 10000
DEFAULT_EXCERPT_BYTES = 512
PASS_SIGNATURES = {"", "none", "ok"}


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


def load_json(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"contract unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append("contract must be a JSON object")
        return {}
    return value


def split_inputs(raw: str) -> list[Path]:
    paths: list[Path] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        path = Path(item)
        paths.append(path if path.is_absolute() else root / path)
    return paths


def load_jsonl(path: Path, errors: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"input unreadable: {rel(path)}: {exc}")
        return rows
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{rel(path)}:{line_number}: malformed JSONL row: {exc}")
            continue
        if not isinstance(value, dict):
            errors.append(f"{rel(path)}:{line_number}: JSONL row must be object")
            continue
        value["_source_input"] = rel(path)
        rows.append(value)
    return rows


def validate_contract(contract: dict[str, Any], errors: list[str]) -> None:
    if contract.get("schema_version") != "v1":
        errors.append("contract.schema_version must be v1")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"contract.bead must be {BEAD_ID}")
    for key in [
        "required_input_fields",
        "required_reproducer_fields",
        "required_log_fields",
        "required_failure_signatures",
        "failure_signature_schema",
        "signature_aliases",
        "signature_prefix_aliases",
    ]:
        if key not in contract:
            errors.append(f"contract.{key} missing")
    required = contract.get("required_failure_signatures", [])
    schema = contract.get("failure_signature_schema", {})
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        errors.append("contract.required_failure_signatures must be strings")
        required = []
    if not isinstance(schema, dict):
        errors.append("contract.failure_signature_schema must be object")
        schema = {}
    for signature in required:
        entry = schema.get(signature)
        if not isinstance(entry, dict):
            errors.append(f"contract.failure_signature_schema.{signature} missing")
            continue
        for field in ["failure_class", "triage_owner_family", "next_safe_action"]:
            if not isinstance(entry.get(field), str) or not entry.get(field):
                errors.append(f"contract.failure_signature_schema.{signature}.{field} missing")


def is_failure_row(row: dict[str, Any]) -> bool:
    status = str(row.get("status", ""))
    signature = str(row.get("failure_signature", ""))
    if signature not in PASS_SIGNATURES:
        return True
    return status not in {"", "pass", "ok"}


def source_kind(row: dict[str, Any]) -> str:
    bead = str(row.get("bead_id", ""))
    event = str(row.get("event", ""))
    source_input = str(row.get("_source_input", ""))
    if "ld_preload_smoke" in source_input or bead == "bd-1ah8" or "ld_preload" in event:
        return "ld_preload_smoke"
    return "workload_replay"


def normalize_signature(signature: str, contract: dict[str, Any]) -> str:
    aliases = contract.get("signature_aliases", {})
    prefixes = contract.get("signature_prefix_aliases", {})
    if isinstance(aliases, dict) and signature in aliases:
        return str(aliases[signature])
    if isinstance(prefixes, dict):
        for prefix, normalized in sorted(prefixes.items(), key=lambda item: -len(str(item[0]))):
            if signature.startswith(str(prefix)):
                return str(normalized)
    return signature


def normalize_command(value: Any) -> list[str] | None:
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return list(value)
    return None


def normalize_env(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    env: dict[str, str] = {}
    for key, item in sorted(value.items()):
        if not isinstance(key, str) or not key or "=" in key:
            return None
        if not isinstance(item, str):
            return None
        env[key] = item
    return env


def normalize_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def row_workload_id(row: dict[str, Any]) -> str:
    for key in ["workload_id", "case", "symbol"]:
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return "<missing>"


def row_mode(row: dict[str, Any]) -> str | None:
    value = row.get("mode")
    return value if isinstance(value, str) and value else None


def timeout_ms(row: dict[str, Any]) -> int:
    value = row.get("timeout_ms")
    if isinstance(value, int) and value > 0:
        return value
    seconds = row.get("timeout_seconds")
    if isinstance(seconds, int) and seconds > 0:
        return seconds * 1000
    return DEFAULT_TIMEOUT_MS


def exit_status(row: dict[str, Any]) -> int | None:
    for key in ["preload_exit", "exit_status", "exit", "preload_rc", "baseline_rc"]:
        value = row.get(key)
        if isinstance(value, int):
            return value
    return None


def read_artifact_excerpt(refs: list[str], suffix: str, max_bytes: int) -> str:
    for ref in refs:
        if not ref.endswith(suffix):
            continue
        path = Path(ref)
        candidate = path if path.is_absolute() else root / path
        if not candidate.exists():
            continue
        try:
            return candidate.read_bytes()[:max_bytes].decode("utf-8", errors="replace")
        except Exception:
            return ""
    return ""


def excerpt(row: dict[str, Any], key: str, refs: list[str], suffix: str, max_bytes: int) -> str:
    value = row.get(key)
    if isinstance(value, str):
        return value[:max_bytes]
    return read_artifact_excerpt(refs, suffix, max_bytes)


def quote_env(env: dict[str, str]) -> list[str]:
    return [f"{key}={shlex.quote(value)}" for key, value in sorted(env.items())]


def build_reproduction_command(env: dict[str, str], command: list[str]) -> str:
    return " ".join(quote_env(env) + [shlex.quote(item) for item in command])


def safe_token(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)


def manifest_error(errors: list[str], row: dict[str, Any], signature: str, message: str) -> None:
    trace_id = row.get("trace_id", "<missing>")
    errors.append(f"{trace_id}: {signature}: {message}")


def materialize_reproducer(
    row: dict[str, Any],
    contract: dict[str, Any],
    errors: list[str],
) -> dict[str, Any] | None:
    raw_signature = row.get("failure_signature")
    if not isinstance(raw_signature, str) or raw_signature in PASS_SIGNATURES:
        manifest_error(errors, row, "reproducer_missing_failure_signature", "failure_signature must be non-pass string")
        return None

    normalized_signature = normalize_signature(raw_signature, contract)
    schema = contract.get("failure_signature_schema", {})
    schema_entry = schema.get(normalized_signature) if isinstance(schema, dict) else None
    if not isinstance(schema_entry, dict):
        manifest_error(errors, row, "reproducer_unknown_failure_signature", f"unknown signature {raw_signature}")
        return None

    workload_id = row_workload_id(row)
    mode = row_mode(row)
    if mode is None:
        manifest_error(errors, row, "reproducer_missing_mode", "failure rows must carry mode")
        return None

    command = normalize_command(row.get("command"))
    if command is None:
        manifest_error(errors, row, "reproducer_missing_command", "failure rows must carry command argv array")
        return None

    env = normalize_env(row.get("env"))
    if env is None:
        manifest_error(errors, row, "reproducer_missing_env", "failure rows must carry env object with string values")
        return None

    refs = normalize_string_list(row.get("artifact_refs"))
    if row.get("_source_input"):
        refs = sorted(set(refs + [str(row["_source_input"])]))

    max_excerpt = int(
        contract.get("excerpt_policy", {}).get("max_excerpt_bytes", DEFAULT_EXCERPT_BYTES)
        if isinstance(contract.get("excerpt_policy"), dict)
        else DEFAULT_EXCERPT_BYTES
    )
    input_files = normalize_string_list(row.get("input_files"))
    if not input_files:
        input_files = [
            ref
            for ref in refs
            if not ref.startswith("target/") and not ref.endswith(".jsonl") and not ref.endswith(".report.json")
        ]

    kind = source_kind(row)
    failure_class = str(schema_entry["failure_class"])
    reproducer_id = "::".join(
        [
            BEAD_ID,
            kind,
            safe_token(workload_id),
            safe_token(mode),
            safe_token(normalized_signature),
        ]
    )
    return {
        "reproducer_id": reproducer_id,
        "source_trace_id": row.get("trace_id", ""),
        "source_kind": kind,
        "workload_id": workload_id,
        "mode": mode,
        "command": command,
        "env": env,
        "input_files": input_files,
        "timeout_ms": timeout_ms(row),
        "exit_status": exit_status(row),
        "stdout_excerpt": excerpt(row, "stdout", refs, "stdout.txt", max_excerpt),
        "stderr_excerpt": excerpt(row, "stderr", refs, "stderr.txt", max_excerpt),
        "failure_signature": normalized_signature,
        "raw_failure_signature": raw_signature,
        "failure_class": failure_class,
        "artifact_refs": refs,
        "triage_owner_family": schema_entry["triage_owner_family"],
        "reproduction_command": build_reproduction_command(env, command),
        "next_safe_action": schema_entry["next_safe_action"],
        "minimization_state": "replayable_minimal",
        "source_commit": row.get("source_commit") if isinstance(row.get("source_commit"), str) else SOURCE_COMMIT,
    }


errors: list[str] = []
contract = load_json(contract_path, errors)
validate_contract(contract, errors)

input_paths = split_inputs(input_spec)
if not input_paths:
    errors.append("no reproducer input logs configured")

all_rows: list[dict[str, Any]] = []
for path in input_paths:
    all_rows.extend(load_jsonl(path, errors))

failure_rows = [row for row in all_rows if is_failure_row(row)]
reproducers: list[dict[str, Any]] = []
for row in failure_rows:
    item = materialize_reproducer(row, contract, errors)
    if item is not None:
        reproducers.append(item)

required_fields = contract.get("required_reproducer_fields", [])
if isinstance(required_fields, list):
    for item in reproducers:
        for field in required_fields:
            if field not in item:
                errors.append(f"{item.get('reproducer_id', '<missing>')}: reproducer missing {field}")

required_log_fields = contract.get("required_log_fields", [])
log_rows: list[dict[str, Any]] = []
for item in reproducers:
    log_row = {
        "trace_id": f"{item['reproducer_id']}::log",
        "bead_id": BEAD_ID,
        "event": "workload_reproducer_manifest_row",
        "status": "pass",
        "reproducer_id": item["reproducer_id"],
        "workload_id": item["workload_id"],
        "mode": item["mode"],
        "failure_signature": item["failure_signature"],
        "failure_class": item["failure_class"],
        "triage_owner_family": item["triage_owner_family"],
        "artifact_refs": item["artifact_refs"],
        "source_commit": item["source_commit"],
        "next_safe_action": item["next_safe_action"],
    }
    if isinstance(required_log_fields, list):
        for field in required_log_fields:
            if field not in log_row:
                errors.append(f"{item['reproducer_id']}: log row missing {field}")
    log_rows.append(log_row)

failure_signature_counts: dict[str, int] = {}
for item in reproducers:
    signature = item["failure_signature"]
    failure_signature_counts[signature] = failure_signature_counts.get(signature, 0) + 1

manifest = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "source_contract": rel(contract_path),
    "generated_at_utc": utc_now(),
    "source_commit": SOURCE_COMMIT,
    "status": "pass" if not errors else "fail",
    "reproducer_count": len(reproducers),
    "required_reproducer_fields": required_fields,
    "required_failure_signatures": contract.get("required_failure_signatures", []),
    "failure_signature_schema": contract.get("failure_signature_schema", {}),
    "reproducers": reproducers,
    "artifact_refs": [
        rel(contract_path),
        rel(report_path),
        rel(log_path),
    ] + [rel(path) for path in input_paths],
}

report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "status": manifest["status"],
    "generated_at_utc": manifest["generated_at_utc"],
    "source_commit": SOURCE_COMMIT,
    "source_contract": rel(contract_path),
    "input_logs": [rel(path) for path in input_paths],
    "summary": {
        "input_row_count": len(all_rows),
        "failure_row_count": len(failure_rows),
        "reproducer_count": len(reproducers),
        "failure_signature_counts": dict(sorted(failure_signature_counts.items())),
        "required_failure_signatures": contract.get("required_failure_signatures", []),
    },
    "failure_signatures": sorted(
        {
            part.split(": ", 2)[1]
            for part in errors
            if part.count(": ") >= 2 and part.split(": ", 2)[1].startswith("reproducer_")
        }
    ),
    "errors": errors,
    "artifact_refs": [
        rel(manifest_path),
        rel(log_path),
        rel(contract_path),
    ],
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if report["status"] == "pass" else 1)
PY
