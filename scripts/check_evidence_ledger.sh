#!/usr/bin/env bash
# check_evidence_ledger.sh -- WS-0 tamper-evident evidence ledger gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LEDGER="${FRANKENLIBC_EVIDENCE_LEDGER:-$ROOT/tests/conformance/evidence_ledger.jsonl}"
REPORT="${FRANKENLIBC_EVIDENCE_LEDGER_REPORT:-$ROOT/target/conformance/evidence_ledger.report.json}"

mkdir -p "$(dirname "$REPORT")"

python3 - "$ROOT" "$LEDGER" "$REPORT" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
LEDGER = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])

SCHEMA = "evidence_ledger_entry.v1"
REPORT_SCHEMA = "evidence_ledger_check_report.v1"
ZERO_HASH = "0" * 64
CHAIN_FIELDS = [
    "schema_version",
    "entry_index",
    "artifact_path",
    "artifact_hash",
    "source_commit",
    "generator_command",
    "tool_version",
    "prev_chain_hash",
]
FAILURE_PRIORITY = [
    "ledger_unreadable",
    "malformed_ledger_row",
    "ledger_index_gap",
    "ledger_prev_chain_mismatch",
    "missing_ledger_artifact",
    "artifact_hash_mismatch",
    "ledger_chain_hash_mismatch",
]

errors: list[dict[str, str]] = []


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {row["failure_signature"] for row in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "evidence_ledger_failed"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def is_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(ch in "0123456789abcdefABCDEF" for ch in value)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def chain_hash(row: dict[str, Any]) -> str:
    payload = {field: row.get(field) for field in CHAIN_FIELDS}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_rows() -> list[dict[str, Any]]:
    try:
        content = LEDGER.read_text(encoding="utf-8")
    except Exception as exc:
        add_error("ledger_unreadable", f"cannot read ledger {rel(LEDGER)}: {exc}")
        return []
    rows: list[dict[str, Any]] = []
    for line_number, raw in enumerate(content.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except Exception as exc:
            add_error("ledger_unreadable", f"line {line_number} is not JSON: {exc}")
            continue
        if not isinstance(row, dict):
            add_error("malformed_ledger_row", f"line {line_number} must be an object")
            continue
        rows.append(row)
    if not rows:
        add_error("ledger_unreadable", "ledger must contain at least one entry")
    return rows


def validate_row(row: dict[str, Any], index: int, expected_prev: str) -> str:
    context = f"entry[{index}]"
    if row.get("schema_version") != SCHEMA:
        add_error("malformed_ledger_row", f"{context}.schema_version must be {SCHEMA}")
    if row.get("entry_index") != index:
        add_error("ledger_index_gap", f"{context}.entry_index must be {index}")

    artifact_path = row.get("artifact_path")
    if not isinstance(artifact_path, str) or not artifact_path:
        add_error("malformed_ledger_row", f"{context}.artifact_path must be a non-empty string")
        artifact = None
    else:
        artifact = pathlib.Path(artifact_path)
        if not artifact.is_absolute():
            artifact = ROOT / artifact
        if not artifact.is_file():
            add_error("missing_ledger_artifact", f"{context}.artifact_path is missing: {artifact_path}")
            artifact = None

    if not is_hex(row.get("artifact_hash"), 64):
        add_error("malformed_ledger_row", f"{context}.artifact_hash must be hex64")
    elif artifact is not None:
        actual = sha256_file(artifact)
        if actual != row["artifact_hash"]:
            add_error(
                "artifact_hash_mismatch",
                f"{context}.artifact_hash for {rel(artifact)} expected {row['artifact_hash']}, got {actual}",
            )

    if not is_hex(row.get("source_commit"), 40):
        add_error("malformed_ledger_row", f"{context}.source_commit must be git hex40")
    for field in ["generator_command", "tool_version"]:
        value = row.get(field)
        if not isinstance(value, str) or not value.strip():
            add_error("malformed_ledger_row", f"{context}.{field} must be a non-empty string")

    if row.get("prev_chain_hash") != expected_prev:
        add_error(
            "ledger_prev_chain_mismatch",
            f"{context}.prev_chain_hash expected {expected_prev}, got {row.get('prev_chain_hash')}",
        )
    if not is_hex(row.get("chain_hash"), 64):
        add_error("malformed_ledger_row", f"{context}.chain_hash must be hex64")
        return expected_prev

    actual_chain = chain_hash(row)
    if actual_chain != row["chain_hash"]:
        add_error(
            "ledger_chain_hash_mismatch",
            f"{context}.chain_hash expected {actual_chain}, got {row['chain_hash']}",
        )
    return str(row.get("chain_hash", expected_prev))


rows = load_rows()
head_chain = ZERO_HASH
for index, row in enumerate(rows):
    head_chain = validate_row(row, index, ZERO_HASH if index == 0 else head_chain)

status = "fail" if errors else "pass"
failure_signature = primary_signature() if errors else "none"
report = {
    "schema_version": REPORT_SCHEMA,
    "generated_at_utc": now_utc(),
    "source_commit": git_head(),
    "ledger": rel(LEDGER),
    "status": status,
    "failure_signature": failure_signature,
    "checked_entry_count": len(rows),
    "head_chain_hash": head_chain,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if errors:
    print(f"FAIL evidence ledger {failure_signature}: {len(errors)} error(s)")
    sys.exit(1)
print(f"PASS evidence ledger entries={len(rows)} head={head_chain}")
PY
