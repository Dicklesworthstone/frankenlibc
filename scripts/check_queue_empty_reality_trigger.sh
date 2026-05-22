#!/usr/bin/env bash
# check_queue_empty_reality_trigger.sh -- RC-WS9.2: Queue-empty triggers mandatory reality check.
#
# When the bead queue is empty, this script fires a mandatory reality check rather
# than allowing the swarm to treat "queue empty" as "done". An empty queue with
# undelivered vision goals is a Goodhart collapse signal, not a completion signal.
#
# Exit codes:
#   0 - Queue has work (normal operation, no intervention needed)
#   1 - Queue empty: reality check triggered and found issues
#   2 - Queue empty: reality check triggered, no major issues found
#   3 - Script error (could not determine queue state)
#
# Usage:
#   scripts/check_queue_empty_reality_trigger.sh [--json] [--trigger-only]
#
# Options:
#   --json          Output structured JSON report
#   --trigger-only  Only check if trigger condition is met, don't run full reality check
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPORT="${FRANKENLIBC_QUEUE_TRIGGER_REPORT:-$ROOT/target/conformance/queue_empty_reality_trigger.report.json}"
TRACE_ID="${FRANKENLIBC_QUEUE_TRIGGER_TRACE_ID:-queue-trigger-$(date -u +%Y%m%dT%H%M%SZ)-$$}"

JSON_OUTPUT=0
TRIGGER_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --json) JSON_OUTPUT=1 ;;
        --trigger-only) TRIGGER_ONLY=1 ;;
        -h|--help)
            head -25 "$0" | tail -n +2 | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
    esac
done

mkdir -p "$(dirname "$REPORT")"

python3 - "$ROOT" "$REPORT" "$TRACE_ID" "$JSON_OUTPUT" "$TRIGGER_ONLY" <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
REPORT_PATH = pathlib.Path(sys.argv[2])
TRACE_ID = sys.argv[3]
JSON_OUTPUT = sys.argv[4] == "1"
TRIGGER_ONLY = sys.argv[5] == "1"

REPORT_SCHEMA = "queue_empty_reality_trigger.v1"

REALITY_CHECK_GATES = [
    ("evidence_ledger", "scripts/check_evidence_ledger.sh"),
    ("evidence_freshness", "scripts/check_evidence_freshness.sh"),
    ("gate_drift", "scripts/check_gate_drift.sh"),
    ("regenerate_then_diff", "scripts/check_regenerate_then_diff_gate.sh"),
    ("bead_closure_freshness", "scripts/check_bead_closure_freshness.sh"),
    ("support_reality_drift", "scripts/check_support_reality_drift_triage.sh"),
]

findings: list[dict[str, Any]] = []
gate_results: list[dict[str, Any]] = []


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "unknown"


def check_queue_empty() -> tuple[bool, int, int, list[dict[str, Any]]]:
    """Check if the bead queue is empty. Returns (is_empty, ready_count, open_count, ready_items)."""
    ready_items: list[dict[str, Any]] = []
    ready_count = 0
    open_count = 0

    try:
        result = subprocess.run(
            ["br", "--no-db", "ready", "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                ready_items = json.loads(result.stdout)
                ready_count = len(ready_items)
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["br", "--no-db", "list", "--status", "open", "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                open_data = json.loads(result.stdout)
                if isinstance(open_data, list):
                    open_count = len(open_data)
                elif isinstance(open_data, dict) and "issues" in open_data:
                    open_count = len(open_data["issues"])
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    is_empty = ready_count == 0
    return is_empty, ready_count, open_count, ready_items


def run_reality_gate(name: str, script: str) -> dict[str, Any]:
    """Run a single reality check gate and return results."""
    script_path = ROOT / script
    result_entry = {
        "gate": name,
        "script": script,
        "outcome": "unknown",
        "exit_code": -1,
        "duration_seconds": 0.0,
    }

    if not script_path.exists():
        result_entry["outcome"] = "script_missing"
        return result_entry

    start = time.time()
    try:
        result = subprocess.run(
            ["bash", str(script_path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=300,
        )
        result_entry["exit_code"] = result.returncode
        result_entry["outcome"] = "pass" if result.returncode == 0 else "fail"
        if result.returncode != 0:
            stderr_tail = result.stderr.strip().split("\n")[-10:]
            result_entry["error_tail"] = stderr_tail
    except subprocess.TimeoutExpired:
        result_entry["outcome"] = "timeout"
    except Exception as exc:
        result_entry["outcome"] = "error"
        result_entry["error"] = str(exc)

    result_entry["duration_seconds"] = round(time.time() - start, 2)
    return result_entry


def run_full_reality_check() -> tuple[int, int]:
    """Run all reality check gates. Returns (passed_count, failed_count)."""
    passed = 0
    failed = 0

    for name, script in REALITY_CHECK_GATES:
        result = run_reality_gate(name, script)
        gate_results.append(result)
        if result["outcome"] == "pass":
            passed += 1
        else:
            failed += 1
            findings.append({
                "type": "reality_gate_failure",
                "gate": name,
                "outcome": result["outcome"],
                "exit_code": result.get("exit_code", -1),
            })

    return passed, failed


def main() -> int:
    timestamp = now_utc()
    commit = git_head()

    queue_empty, ready_count, open_count, ready_items = check_queue_empty()

    if not queue_empty:
        report = {
            "schema_version": REPORT_SCHEMA,
            "generated_at_utc": timestamp,
            "source_commit": commit,
            "trace_id": TRACE_ID,
            "trigger_condition": "queue_has_work",
            "ready_count": ready_count,
            "open_count": open_count,
            "reality_check_triggered": False,
            "outcome": "no_intervention_needed",
        }
        REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if JSON_OUTPUT:
            print(json.dumps(report, indent=2))
        else:
            print(f"Queue has {ready_count} ready items. No reality check triggered.")
        return 0

    findings.append({
        "type": "queue_empty_trigger",
        "message": "Empty bead queue detected. This is a Goodhart collapse signal, not a completion signal.",
        "ready_count": ready_count,
        "open_count": open_count,
    })

    if TRIGGER_ONLY:
        report = {
            "schema_version": REPORT_SCHEMA,
            "generated_at_utc": timestamp,
            "source_commit": commit,
            "trace_id": TRACE_ID,
            "trigger_condition": "queue_empty",
            "ready_count": ready_count,
            "open_count": open_count,
            "reality_check_triggered": False,
            "trigger_only_mode": True,
            "outcome": "trigger_condition_met",
            "findings": findings,
        }
        REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if JSON_OUTPUT:
            print(json.dumps(report, indent=2))
        else:
            print("TRIGGER: Queue is empty. Reality check would be triggered.")
            print(f"  Ready beads: {ready_count}")
            print(f"  Open beads: {open_count}")
        return 2

    print("=" * 60)
    print("QUEUE-EMPTY REALITY CHECK TRIGGERED")
    print("=" * 60)
    print()
    print("An empty bead queue does NOT mean the work is done.")
    print("Running mandatory reality check gates...")
    print()

    passed, failed = run_full_reality_check()

    print()
    print(f"Reality check complete: {passed} passed, {failed} failed")
    print()

    if failed > 0:
        print("REALITY CHECK FOUND ISSUES:")
        for finding in findings:
            if finding.get("type") == "reality_gate_failure":
                print(f"  - {finding['gate']}: {finding['outcome']}")
        outcome = "reality_check_failed"
        exit_code = 1
    else:
        print("Reality check gates passed, but queue empty state requires investigation.")
        print("Consider: Are all vision goals actually delivered? Run /reality-check-for-project.")
        outcome = "reality_check_passed_but_queue_empty"
        exit_code = 2

    report = {
        "schema_version": REPORT_SCHEMA,
        "generated_at_utc": timestamp,
        "source_commit": commit,
        "trace_id": TRACE_ID,
        "trigger_condition": "queue_empty",
        "ready_count": ready_count,
        "open_count": open_count,
        "reality_check_triggered": True,
        "gates_passed": passed,
        "gates_failed": failed,
        "gate_results": gate_results,
        "findings": findings,
        "outcome": outcome,
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if JSON_OUTPUT:
        print(json.dumps(report, indent=2))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
PY
