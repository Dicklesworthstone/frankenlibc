#!/usr/bin/env bash
# check_bead_closure_freshness.sh -- WS-0 gate for bd-3yr14.7.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
POLICY="${FRANKENLIBC_BEAD_CLOSURE_POLICY:-$ROOT/tests/conformance/bead_closure_freshness_policy.v1.json}"
BEADS="${FRANKENLIBC_BEADS_JSONL:-$ROOT/.beads/issues.jsonl}"
LEDGER="${FRANKENLIBC_EVIDENCE_LEDGER:-$ROOT/tests/conformance/evidence_ledger.jsonl}"
REPORT="${FRANKENLIBC_BEAD_CLOSURE_REPORT:-$ROOT/target/conformance/bead_closure_freshness.report.json}"
MODE="live"

case "${1:-}" in
    "")
        ;;
    --self-test)
        MODE="self-test"
        ;;
    -h|--help)
        cat <<'EOF'
Usage: scripts/check_bead_closure_freshness.sh [--self-test]

Validates that closed beads covered by the WS-0 closure-freshness policy cite a
completion-contract artifact whose freshness_state.generated_at_utc is inside
the bead in-progress-to-closed window and whose chain_hash has a valid shape.
EOF
        exit 0
        ;;
    *)
        echo "unknown argument: $1" >&2
        exit 2
        ;;
esac

mkdir -p "$(dirname "$REPORT")"

python3 - "$ROOT" "$POLICY" "$BEADS" "$LEDGER" "$REPORT" "$MODE" <<'PY'
from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
POLICY = pathlib.Path(sys.argv[2])
BEADS = pathlib.Path(sys.argv[3])
LEDGER = pathlib.Path(sys.argv[4])
REPORT = pathlib.Path(sys.argv[5])
MODE = sys.argv[6]

REPORT_SCHEMA = "bead_closure_freshness_report.v1"
CONTRACT_RE = re.compile(r"((?:tests|target|scripts)/[A-Za-z0-9._/-]*completion_contract\.v1\.json)")
UTC_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|\+00:00)$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


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


def parse_utc(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    match = UTC_RE.match(value)
    if match is None:
        return None
    fraction = match.group(2) or ""
    if len(fraction) > 7:
        fraction = fraction[:7]
    text = f"{match.group(1)}{fraction}+00:00"
    try:
        return dt.datetime.fromisoformat(text).astimezone(dt.timezone.utc)
    except ValueError:
        return None


def load_json(path: pathlib.Path, errors: list[dict[str, Any]], signature: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append({"failure_signature": signature, "message": f"cannot read {rel(path)}: {exc}"})
        return {}
    if not isinstance(value, dict):
        errors.append({"failure_signature": signature, "message": f"{rel(path)} must contain a JSON object"})
        return {}
    return value


def load_policy() -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    policy = load_json(POLICY, errors, "bead_closure_policy_unreadable")
    if errors:
        report = {
            "schema_version": REPORT_SCHEMA,
            "generated_at_utc": now_utc(),
            "source_commit": git_head(),
            "mode": MODE,
            "status": "fail",
            "failure_signature": errors[0]["failure_signature"],
            "errors": errors,
        }
        REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"FAIL bead closure freshness {errors[0]['failure_signature']}")
        raise SystemExit(1)
    return policy


def load_beads(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        lines = BEADS.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        errors.append({"failure_signature": "bead_closure_beads_unreadable", "message": f"cannot read {rel(BEADS)}: {exc}"})
        return []

    by_id: dict[str, dict[str, Any]] = {}
    for line_number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except Exception as exc:
            errors.append({
                "failure_signature": "bead_closure_beads_unreadable",
                "message": f"{rel(BEADS)} line {line_number} is not JSON: {exc}",
            })
            continue
        if isinstance(row, dict) and isinstance(row.get("id"), str):
            by_id[row["id"]] = row
        else:
            errors.append({
                "failure_signature": "bead_closure_beads_unreadable",
                "message": f"{rel(BEADS)} line {line_number} is not a bead object",
            })
    return list(by_id.values())


def load_ledger_chain_hashes(warnings: list[dict[str, Any]]) -> set[str]:
    if not LEDGER.exists():
        warnings.append({"warning": "bead_closure_ledger_missing", "message": f"{rel(LEDGER)} is absent"})
        return set()
    chain_hashes: set[str] = set()
    try:
        lines = LEDGER.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        warnings.append({"warning": "bead_closure_ledger_unreadable", "message": f"cannot read {rel(LEDGER)}: {exc}"})
        return set()
    for raw in lines:
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except Exception:
            continue
        if isinstance(row, dict) and isinstance(row.get("chain_hash"), str):
            chain_hashes.add(row["chain_hash"])
    return chain_hashes


def artifact_paths_from_bead(bead: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for key in ("completion_artifact", "completion_contract", "evidence_artifact"):
        value = bead.get(key)
        if isinstance(value, str):
            paths.append(value)
    refs = bead.get("artifact_refs")
    if isinstance(refs, list):
        paths.extend(item for item in refs if isinstance(item, str))
    for key in ("close_reason", "notes"):
        value = bead.get(key)
        if isinstance(value, str):
            paths.extend(CONTRACT_RE.findall(value))
    seen: set[str] = set()
    unique: list[str] = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def is_candidate(bead: dict[str, Any], policy: dict[str, Any]) -> bool:
    if bead.get("status") != "closed":
        return False
    bead_id = bead.get("id")
    if bead_id in set(policy.get("enforced_bead_ids", [])):
        return True
    closed_at = parse_utc(bead.get("closed_at"))
    effective_after = parse_utc(policy.get("effective_after_utc"))
    labels = set(bead.get("labels", [])) if isinstance(bead.get("labels"), list) else set()
    enforced_labels = set(policy.get("enforced_labels", []))
    if (
        policy.get("enforce_reality_check_after_effective", False)
        and closed_at is not None
        and effective_after is not None
        and closed_at >= effective_after
        and labels.intersection(enforced_labels)
    ):
        return True
    return False


def read_contract(path_text: str, errors: list[dict[str, Any]], overrides: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if path_text in overrides:
        return overrides[path_text]
    path = pathlib.Path(path_text)
    if not path.is_absolute():
        path = ROOT / path
    if not path.is_file():
        errors.append({
            "failure_signature": "bead_closure_missing_completion_artifact",
            "message": f"completion artifact is missing: {path_text}",
        })
        return None
    contract = load_json(path, errors, "bead_closure_unreadable_completion_artifact")
    return contract or None


def freshness_state(contract: dict[str, Any]) -> dict[str, Any]:
    value = contract.get("freshness_state")
    if isinstance(value, dict):
        return value
    if "generated_at_utc" in contract or "chain_hash" in contract:
        return {
            "generated_at_utc": contract.get("generated_at_utc"),
            "source_commit": contract.get("source_commit"),
            "generator_command": contract.get("generator_command"),
            "tool_version": contract.get("tool_version"),
            "chain_hash": contract.get("chain_hash"),
        }
    return {}


def window_start(bead: dict[str, Any], contract: dict[str, Any]) -> tuple[dt.datetime | None, str]:
    window = contract.get("bead_status_window")
    if isinstance(window, dict):
        for key in ("in_progress_at_utc", "in_progress_at", "claimed_at_utc", "claimed_at"):
            parsed = parse_utc(window.get(key))
            if parsed is not None:
                return parsed, f"artifact.bead_status_window.{key}"
    for key in ("in_progress_at", "started_at", "claimed_at", "updated_at", "created_at"):
        parsed = parse_utc(bead.get(key))
        if parsed is not None:
            return parsed, f"bead.{key}"
    return None, "missing"


def audit_contract(
    bead: dict[str, Any],
    path_text: str,
    contract: dict[str, Any],
    policy: dict[str, Any],
    ledger_chain_hashes: set[str],
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    bead_id = str(bead.get("id"))
    state = freshness_state(contract)
    row: dict[str, Any] = {
        "bead_id": bead_id,
        "completion_artifact": path_text,
        "status": "pass",
    }

    generated_at = parse_utc(state.get("generated_at_utc"))
    if generated_at is None:
        errors.append({
            "bead_id": bead_id,
            "failure_signature": "bead_closure_missing_generated_at_utc",
            "message": f"{path_text} lacks valid freshness_state.generated_at_utc",
        })
        row["status"] = "fail"

    chain_hash = state.get("chain_hash")
    if not isinstance(chain_hash, str) or HEX64_RE.match(chain_hash) is None:
        errors.append({
            "bead_id": bead_id,
            "failure_signature": "bead_closure_missing_chain_hash",
            "message": f"{path_text} lacks valid freshness_state.chain_hash",
        })
        row["status"] = "fail"
    elif policy.get("require_ledger_chain_hash", False) and chain_hash not in ledger_chain_hashes:
        errors.append({
            "bead_id": bead_id,
            "failure_signature": "bead_closure_chain_hash_missing",
            "message": f"{path_text} chain_hash is not present in {rel(LEDGER)}",
        })
        row["status"] = "fail"

    start_at, start_source = window_start(bead, contract)
    closed_at = parse_utc(bead.get("closed_at"))
    if closed_at is None:
        errors.append({
            "bead_id": bead_id,
            "failure_signature": "bead_closure_missing_closed_at",
            "message": f"{bead_id} is closed but lacks a valid closed_at timestamp",
        })
        row["status"] = "fail"
    if start_at is None:
        errors.append({
            "bead_id": bead_id,
            "failure_signature": "bead_closure_missing_in_progress_at",
            "message": f"{bead_id} has no in-progress lower-bound timestamp",
        })
        row["status"] = "fail"

    row["freshness_state"] = {
        "generated_at_utc": state.get("generated_at_utc"),
        "chain_hash": chain_hash,
        "window_start_source": start_source,
        "window_start_utc": start_at.strftime("%Y-%m-%dT%H:%M:%SZ") if start_at else None,
        "closed_at_utc": closed_at.strftime("%Y-%m-%dT%H:%M:%SZ") if closed_at else None,
    }

    if generated_at is not None and start_at is not None and generated_at < start_at:
        errors.append({
            "bead_id": bead_id,
            "failure_signature": "bead_closure_predated_artifact",
            "message": f"{path_text} generated_at_utc precedes {start_source}",
        })
        row["status"] = "fail"
    if generated_at is not None and closed_at is not None and generated_at > closed_at:
        errors.append({
            "bead_id": bead_id,
            "failure_signature": "bead_closure_postdated_artifact",
            "message": f"{path_text} generated_at_utc is after bead.closed_at",
        })
        row["status"] = "fail"

    return row


def audit(
    beads: list[dict[str, Any]],
    policy: dict[str, Any],
    contracts: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    contracts = contracts or {}
    ledger_chain_hashes = load_ledger_chain_hashes(warnings)
    checked: list[dict[str, Any]] = []

    for bead in sorted((b for b in beads if is_candidate(b, policy)), key=lambda b: str(b.get("id"))):
        paths = artifact_paths_from_bead(bead)
        if not paths:
            errors.append({
                "bead_id": bead.get("id"),
                "failure_signature": "bead_closure_missing_completion_artifact",
                "message": f"{bead.get('id')} closure has no completion-contract artifact reference",
            })
            checked.append({"bead_id": bead.get("id"), "status": "fail", "completion_artifact": None})
            continue
        for path_text in paths:
            contract = read_contract(path_text, errors, contracts)
            if contract is None:
                checked.append({"bead_id": bead.get("id"), "status": "fail", "completion_artifact": path_text})
                continue
            checked.append(audit_contract(bead, path_text, contract, policy, ledger_chain_hashes, errors))
    return checked, errors, warnings


def self_test(policy: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    valid_hash = "a" * 64
    base_policy = dict(policy)
    base_policy["enforced_bead_ids"] = [
        "bd-self-pass",
        "bd-self-predated",
        "bd-self-missing-chain",
        "bd-self-fractional",
        "bd-self-notes-ref",
    ]
    base_policy["require_ledger_chain_hash"] = False

    cases = [
        {
            "name": "fresh_contract_passes",
            "bead": {
                "id": "bd-self-pass",
                "status": "closed",
                "labels": ["reality-check"],
                "created_at": "2026-05-21T07:00:00Z",
                "closed_at": "2026-05-21T07:30:00Z",
                "close_reason": "evidence: tests/conformance/self_pass_completion_contract.v1.json",
            },
            "path": "tests/conformance/self_pass_completion_contract.v1.json",
            "contract": {
                "freshness_state": {
                    "generated_at_utc": "2026-05-21T07:10:00Z",
                    "source_commit": "1111111111111111111111111111111111111111",
                    "generator_command": "self-test pass",
                    "tool_version": "self-test",
                    "chain_hash": valid_hash,
                },
                "bead_status_window": {"in_progress_at_utc": "2026-05-21T07:05:00Z"},
            },
            "expected_signatures": [],
        },
        {
            "name": "predated_contract_rejected",
            "bead": {
                "id": "bd-self-predated",
                "status": "closed",
                "labels": ["reality-check"],
                "created_at": "2026-05-21T07:00:00Z",
                "closed_at": "2026-05-21T07:30:00Z",
                "close_reason": "evidence: tests/conformance/self_predated_completion_contract.v1.json",
            },
            "path": "tests/conformance/self_predated_completion_contract.v1.json",
            "contract": {
                "freshness_state": {
                    "generated_at_utc": "2026-05-21T07:04:59Z",
                    "source_commit": "1111111111111111111111111111111111111111",
                    "generator_command": "self-test predated",
                    "tool_version": "self-test",
                    "chain_hash": valid_hash,
                },
                "bead_status_window": {"in_progress_at_utc": "2026-05-21T07:05:00Z"},
            },
            "expected_signatures": ["bead_closure_predated_artifact"],
        },
        {
            "name": "missing_chain_hash_rejected",
            "bead": {
                "id": "bd-self-missing-chain",
                "status": "closed",
                "labels": ["reality-check"],
                "created_at": "2026-05-21T07:00:00Z",
                "closed_at": "2026-05-21T07:30:00Z",
                "close_reason": "evidence: tests/conformance/self_missing_chain_completion_contract.v1.json",
            },
            "path": "tests/conformance/self_missing_chain_completion_contract.v1.json",
            "contract": {
                "freshness_state": {
                    "generated_at_utc": "2026-05-21T07:10:00Z",
                    "source_commit": "1111111111111111111111111111111111111111",
                    "generator_command": "self-test missing chain",
                    "tool_version": "self-test",
                },
                "bead_status_window": {"in_progress_at_utc": "2026-05-21T07:05:00Z"},
            },
            "expected_signatures": ["bead_closure_missing_chain_hash"],
        },
        {
            "name": "fractional_bead_timestamps_pass",
            "bead": {
                "id": "bd-self-fractional",
                "status": "closed",
                "labels": ["reality-check"],
                "created_at": "2026-05-21T07:00:00.123456789Z",
                "closed_at": "2026-05-21T07:30:00.987654321Z",
                "close_reason": "evidence: tests/conformance/self_fractional_completion_contract.v1.json",
            },
            "path": "tests/conformance/self_fractional_completion_contract.v1.json",
            "contract": {
                "freshness_state": {
                    "generated_at_utc": "2026-05-21T07:10:00.456789123Z",
                    "source_commit": "1111111111111111111111111111111111111111",
                    "generator_command": "self-test fractional timestamps",
                    "tool_version": "self-test",
                    "chain_hash": valid_hash,
                },
                "bead_status_window": {"in_progress_at_utc": "2026-05-21T07:05:00.111222333Z"},
            },
            "expected_signatures": [],
        },
        {
            "name": "notes_completion_contract_reference_passes",
            "bead": {
                "id": "bd-self-notes-ref",
                "status": "closed",
                "labels": ["reality-check"],
                "created_at": "2026-05-21T07:00:00Z",
                "closed_at": "2026-05-21T07:30:00Z",
                "notes": "completion_artifact: tests/conformance/self_notes_completion_contract.v1.json",
            },
            "path": "tests/conformance/self_notes_completion_contract.v1.json",
            "contract": {
                "freshness_state": {
                    "generated_at_utc": "2026-05-21T07:10:00Z",
                    "source_commit": "1111111111111111111111111111111111111111",
                    "generator_command": "self-test notes reference",
                    "tool_version": "self-test",
                    "chain_hash": valid_hash,
                },
                "bead_status_window": {"in_progress_at_utc": "2026-05-21T07:05:00Z"},
            },
            "expected_signatures": [],
        },
    ]

    results: list[dict[str, Any]] = []
    harness_errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    for case in cases:
        checked, errors, case_warnings = audit([case["bead"]], base_policy, {case["path"]: case["contract"]})
        warnings.extend(case_warnings)
        signatures = sorted({error.get("failure_signature") for error in errors})
        expected = sorted(case["expected_signatures"])
        passed = signatures == expected
        results.append({
            "name": case["name"],
            "passed": passed,
            "expected_signatures": expected,
            "observed_signatures": signatures,
            "checked": checked,
        })
        if not passed:
            harness_errors.append({
                "failure_signature": "bead_closure_self_test_failed",
                "message": f"{case['name']} expected {expected} observed {signatures}",
            })
    return results, harness_errors, warnings


policy = load_policy()
top_errors: list[dict[str, Any]] = []
if MODE == "self-test":
    self_tests, errors, warnings = self_test(policy)
    checked: list[dict[str, Any]] = []
else:
    beads = load_beads(top_errors)
    checked, errors, warnings = audit(beads, policy)
    self_tests = []
    errors = top_errors + errors

status = "fail" if errors else "pass"
failure_signature = errors[0]["failure_signature"] if errors else "none"
report = {
    "schema_version": REPORT_SCHEMA,
    "generated_at_utc": now_utc(),
    "source_commit": git_head(),
    "mode": MODE,
    "policy": rel(POLICY),
    "beads_source": rel(BEADS),
    "ledger": rel(LEDGER),
    "status": status,
    "failure_signature": failure_signature,
    "checked_beads": checked,
    "checked_count": len(checked),
    "self_tests": self_tests,
    "errors": errors,
    "warnings": warnings,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL bead closure freshness {failure_signature}: checked={len(checked)} mode={MODE}")
    raise SystemExit(1)
if MODE == "self-test":
    print(f"PASS bead closure freshness self-test cases={len(self_tests)}")
else:
    print(f"PASS bead closure freshness checked={len(checked)}")
PY
