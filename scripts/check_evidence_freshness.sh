#!/usr/bin/env bash
# check_evidence_freshness.sh -- WS-0 anytime-valid freshness gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LEDGER="${FRANKENLIBC_EVIDENCE_LEDGER:-$ROOT/tests/conformance/evidence_ledger.jsonl}"
REPORT="${FRANKENLIBC_EVIDENCE_FRESHNESS_REPORT:-$ROOT/target/conformance/evidence_freshness.report.json}"

mkdir -p "$(dirname "$REPORT")"

python3 - "$ROOT" "$LEDGER" "$REPORT" <<'PY'
from __future__ import annotations

import hashlib
import json
import math
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
LEDGER = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])

REPORT_SCHEMA = "evidence_freshness_report.v1"
P0 = 0.05
Q1 = 0.80
WARMUP = 1
WARNING_E = 4.0
ALARM_E = 10.0
FALSE_ALARM_ALPHA = 1.0 / ALARM_E
ADVERSE_DELTA = math.log(Q1 / P0)
CLEAN_DELTA = math.log((1.0 - Q1) / (1.0 - P0))

errors: list[dict[str, str]] = []
observations: list[dict[str, Any]] = []


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


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def load_rows() -> list[dict[str, Any]]:
    try:
        content = LEDGER.read_text(encoding="utf-8")
    except Exception as exc:
        add_error("evidence_freshness_ledger_unreadable", f"cannot read {rel(LEDGER)}: {exc}")
        return []
    rows: list[dict[str, Any]] = []
    for line_number, raw in enumerate(content.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except Exception as exc:
            add_error("evidence_freshness_ledger_unreadable", f"line {line_number} is not JSON: {exc}")
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            add_error("evidence_freshness_malformed_row", f"line {line_number} must be an object")
    if not rows:
        add_error("evidence_freshness_ledger_unreadable", "ledger must contain at least one row")
    return rows


def observe_row(row: dict[str, Any], index: int) -> bool:
    path_text = row.get("artifact_path")
    expected_hash = row.get("artifact_hash")
    if not isinstance(path_text, str) or not isinstance(expected_hash, str):
        add_error("evidence_freshness_malformed_row", f"entry[{index}] needs artifact_path and artifact_hash strings")
        return True
    artifact = pathlib.Path(path_text)
    if not artifact.is_absolute():
        artifact = ROOT / artifact
    if not artifact.is_file():
        add_error("evidence_freshness_missing_artifact", f"entry[{index}] missing artifact {path_text}")
        observations.append({
            "entry_index": index,
            "artifact_path": path_text,
            "diverged": True,
            "actual_hash": None,
            "expected_hash": expected_hash,
        })
        return True
    actual_hash = sha256_file(artifact)
    diverged = actual_hash != expected_hash
    observations.append({
        "entry_index": index,
        "artifact_path": path_text,
        "diverged": diverged,
        "actual_hash": actual_hash,
        "expected_hash": expected_hash,
    })
    return diverged


rows = load_rows()
log_e = 0.0
divergences = 0
for index, row in enumerate(rows):
    diverged = observe_row(row, index)
    if diverged:
        divergences += 1
        log_e += ADVERSE_DELTA
    else:
        log_e += CLEAN_DELTA

e_value = math.exp(log_e) if rows else 1.0
if len(rows) < WARMUP:
    state = "calibrating"
elif e_value >= ALARM_E:
    state = "alarm"
elif e_value >= WARNING_E:
    state = "warning"
else:
    state = "normal"

if state == "alarm":
    add_error(
        "evidence_freshness_alarm",
        f"artifact divergence e-value {e_value:.6g} crossed alarm threshold {ALARM_E}",
    )

status = "fail" if errors else "pass"
failure_signature = errors[0]["failure_signature"] if errors else "none"
report = {
    "schema_version": REPORT_SCHEMA,
    "generated_at_utc": now_utc(),
    "source_commit": git_head(),
    "ledger": rel(LEDGER),
    "status": status,
    "failure_signature": failure_signature,
    "observations": len(rows),
    "divergences": divergences,
    "e_value": e_value,
    "state": state,
    "false_alarm_alpha": FALSE_ALARM_ALPHA,
    "parameters": {
        "null_divergence_rate": P0,
        "alarm_divergence_rate": Q1,
        "warmup_observations": WARMUP,
        "warning_e_value": WARNING_E,
        "alarm_e_value": ALARM_E,
    },
    "ledger_observations": observations,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL evidence freshness {failure_signature}: e_value={e_value:.6g} divergences={divergences}")
    sys.exit(1)
print(f"PASS evidence freshness e_value={e_value:.6g} divergences={divergences} alpha={FALSE_ALARM_ALPHA}")
PY
