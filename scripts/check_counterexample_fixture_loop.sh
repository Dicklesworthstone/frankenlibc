#!/usr/bin/env bash
# check_counterexample_fixture_loop.sh -- CI gate for bd-bp8fl.9.1
#
# Validates the counterexample-to-fixture loop and materializes deterministic
# replay fixtures for minimized proof/parity/runtime counterexamples.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${ROOT}/tests/conformance/counterexample_fixture_loop.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/counterexample_fixture_loop.report.json"
LOG="${OUT_DIR}/counterexample_fixture_loop.log.jsonl"
FIXTURE_DIR="${OUT_DIR}/counterexample_fixture_loop/replay_fixtures"

mkdir -p "${OUT_DIR}" "${FIXTURE_DIR}"

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" "${FIXTURE_DIR}" "$@" <<'PY'
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
fixture_dir = Path(sys.argv[5])
args = sys.argv[6:]

REQUIRED_SOURCES = {
    "proof_failure",
    "differential_mismatch",
    "runtime_math_alarm",
    "conformance_failure",
}
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "counterexample_id",
    "symbol",
    "api_family",
    "minimization_state",
    "fixture_id",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
REQUIRED_COUNTEREXAMPLE_FIELDS = [
    "id",
    "source",
    "symbol",
    "api_family",
    "oracle_kind",
    "runtime_mode",
    "minimization_state",
    "minimized_input",
    "expected",
    "actual",
    "proof_link",
    "artifact_refs",
    "fixture_generation",
    "fixture_id",
    "fixture_path",
    "replay_command",
    "expected_replay_result",
    "source_commit",
    "failure_signature",
]


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"FAIL: {path}: {exc}")


def current_commit():
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout.strip()


def rel(path):
    return str(path.relative_to(root))


def counterexample_map(artifact):
    return {row.get("id"): row for row in artifact.get("counterexamples", [])}


def fixture_path_for(row):
    if not row.get("fixture_path"):
        return None
    return root / row["fixture_path"]


def materialize_fixture(row, commit):
    path = fixture_path_for(row)
    if path is None:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    fixture = {
        "schema_version": "v1",
        "bead": "bd-bp8fl.9.1",
        "fixture_id": row["fixture_id"],
        "counterexample_id": row["id"],
        "source": row["source"],
        "symbol": row["symbol"],
        "api_family": row["api_family"],
        "oracle_kind": row["oracle_kind"],
        "runtime_mode": row["runtime_mode"],
        "minimization_state": row["minimization_state"],
        "minimized_input": row["minimized_input"],
        "expected": row["expected"],
        "actual": row["actual"],
        "expected_replay_result": row["expected_replay_result"],
        "failure_signature": row["failure_signature"],
        "artifact_refs": row["artifact_refs"],
        "source_commit": commit,
    }
    path.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def replay(row, commit):
    generation = row.get("fixture_generation")
    if generation == "blocked":
        return "blocked", None
    path = fixture_path_for(row)
    if generation == "generate" and (path is None or not path.exists()):
        path = materialize_fixture(row, commit)
    if path is None or not path.exists():
        return "fail", None
    fixture = load_json(path)
    result = fixture.get("expected_replay_result")
    if result not in {"pass", "fail"}:
        result = "fail"
    return result, path


def emit_log(rows, commit):
    with log_path.open("w", encoding="utf-8") as handle:
        for index, row in enumerate(rows, start=1):
            event = {
                "trace_id": f"bd-bp8fl.9.1::counterexample_fixture_loop::{index:03d}",
                "bead_id": "bd-bp8fl.9.1",
                "counterexample_id": row["id"],
                "symbol": row["symbol"],
                "api_family": row["api_family"],
                "minimization_state": row["minimization_state"],
                "fixture_id": row.get("fixture_id"),
                "expected": row["expected"],
                "actual": row["actual"],
                "artifact_refs": row["artifact_refs"],
                "source_commit": commit,
                "failure_signature": row["failure_signature"],
            }
            handle.write(json.dumps(event, sort_keys=True) + "\n")


def validate(artifact, commit):
    errors = []
    checks = {}

    checks["json_parse"] = "pass" if isinstance(artifact, dict) else "fail"
    if not isinstance(artifact, dict):
        artifact = {}

    if artifact.get("schema_version") == "v1" and artifact.get("bead") == "bd-bp8fl.9.1":
        checks["top_level_shape"] = "pass"
    else:
        checks["top_level_shape"] = "fail"
        errors.append("artifact must declare schema_version=v1 and bead=bd-bp8fl.9.1")

    if set(artifact.get("required_sources", [])) == REQUIRED_SOURCES:
        checks["required_sources"] = "pass"
    else:
        checks["required_sources"] = "fail"
        errors.append("required_sources must cover proof, differential, runtime-math, and conformance failures")

    if artifact.get("required_log_fields") == REQUIRED_LOG_FIELDS:
        checks["required_log_fields"] = "pass"
    else:
        checks["required_log_fields"] = "fail"
        errors.append("required_log_fields must match the bd-bp8fl.9.1 log contract")

    rows = artifact.get("counterexamples", [])
    row_ids = [row.get("id") for row in rows]
    source_counts = Counter()
    replay_counts = Counter()
    generated_fixture_ids = []
    materialized = []
    rows_ok = bool(rows) and len(row_ids) == len(set(row_ids))
    if len(row_ids) != len(set(row_ids)):
        rows_ok = False
        errors.append("duplicate_counterexample_id")

    for row in rows:
        cid = row.get("id", "<missing counterexample id>")
        for field in REQUIRED_COUNTEREXAMPLE_FIELDS:
            if field not in row:
                rows_ok = False
                errors.append(f"{cid}: missing field {field}")
        source = row.get("source")
        if source not in REQUIRED_SOURCES:
            rows_ok = False
            errors.append(f"{cid}: invalid source {source}")
        else:
            source_counts[source] += 1
        replay_counts[row.get("expected_replay_result")] += 1

        proof_link = row.get("proof_link")
        if not proof_link or not (root / proof_link).exists():
            rows_ok = False
            errors.append(f"{cid}: missing_proof_link")
        for ref in row.get("artifact_refs", []):
            if not (root / ref).exists():
                rows_ok = False
                errors.append(f"{cid}: missing artifact ref {ref}")

        generation = row.get("fixture_generation")
        state = row.get("minimization_state")
        if state == "unsupported" and generation != "blocked":
            rows_ok = False
            errors.append(f"{cid}: unsupported_counterexample_generated")
        if generation in {"generate", "plan_only"}:
            if not row.get("fixture_id") or not row.get("fixture_path"):
                rows_ok = False
                errors.append(f"{cid}: fixture_id and fixture_path required")
            if not row.get("replay_command"):
                rows_ok = False
                errors.append(f"{cid}: missing_replay_command")
        if generation == "generate":
            generated_fixture_ids.append(row.get("fixture_id"))
            materialized_path = materialize_fixture(row, commit)
            if materialized_path is not None:
                materialized.append(rel(materialized_path))

        if row.get("source_commit") != "HEAD":
            rows_ok = False
            errors.append(f"{cid}: source_commit must be HEAD so the gate records the current commit")

    if len(generated_fixture_ids) != len(set(generated_fixture_ids)):
        rows_ok = False
        errors.append("duplicate_fixture_id")
    checks["counterexample_rows"] = "pass" if rows_ok else "fail"

    missing_sources = sorted(REQUIRED_SOURCES - set(source_counts))
    if not missing_sources:
        checks["source_coverage"] = "pass"
    else:
        checks["source_coverage"] = "fail"
        errors.append("missing counterexample sources: " + ", ".join(missing_sources))

    replay_ok = True
    replay_results = {}
    for row in rows:
        result, path = replay(row, commit)
        replay_results[row["id"]] = {
            "expected": row["expected_replay_result"],
            "actual": result,
            "fixture_path": None if path is None else rel(path),
        }
        if result != row["expected_replay_result"]:
            replay_ok = False
            errors.append(f"{row['id']}: replay expected {row['expected_replay_result']} got {result}")
    checks["replay"] = "pass" if replay_ok else "fail"

    negative_tests = artifact.get("negative_tests", [])
    negative_ok = bool(negative_tests)
    for test in negative_tests:
        if test.get("expected_result") != "gate_failed" or not test.get("expected_failure_signature"):
            negative_ok = False
            errors.append(f"{test.get('id', '<missing negative id>')}: malformed negative test")
    checks["negative_tests"] = "pass" if negative_ok else "fail"

    summary = artifact.get("summary", {})
    summary_ok = (
        summary.get("counterexample_count") == len(rows)
        and summary.get("generated_fixture_count") == sum(1 for row in rows if row.get("fixture_generation") == "generate")
        and summary.get("plan_only_fixture_count") == sum(1 for row in rows if row.get("fixture_generation") == "plan_only")
        and summary.get("unsupported_count") == sum(1 for row in rows if row.get("fixture_generation") == "blocked")
        and summary.get("negative_test_count") == len(negative_tests)
        and summary.get("source_counts") == dict(source_counts)
        and summary.get("replay_expectations") == dict(replay_counts)
    )
    checks["summary_counts"] = "pass" if summary_ok else "fail"
    if not summary_ok:
        errors.append("summary counts do not match counterexample rows")

    emit_log(rows, commit)
    log_lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    log_ok = len(log_lines) == len(rows)
    for event in log_lines:
        missing = [field for field in REQUIRED_LOG_FIELDS if field not in event]
        if missing:
            log_ok = False
            errors.append(f"{event.get('counterexample_id', '<missing log id>')}: log missing {missing}")
    checks["structured_log"] = "pass" if log_ok else "fail"

    report = {
        "schema_version": "v1",
        "bead": "bd-bp8fl.9.1",
        "status": "pass" if not errors else "fail",
        "checks": checks,
        "errors": errors,
        "source_commit": commit,
        "counterexample_count": len(rows),
        "generated_fixture_count": len(generated_fixture_ids),
        "materialized_fixtures": materialized,
        "source_counts": dict(source_counts),
        "replay_results": replay_results,
        "negative_test_count": len(negative_tests),
        "artifact_refs": [
            "tests/conformance/counterexample_fixture_loop.v1.json",
            rel(report_path),
            rel(log_path),
            rel(fixture_dir),
        ],
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main():
    artifact = load_json(artifact_path)
    commit = current_commit()

    if args:
        if len(args) != 4 or args[0] != "--replay" or args[2] != "--expect":
            raise SystemExit("usage: check_counterexample_fixture_loop.sh [--replay <counterexample-id> --expect <pass|fail|blocked>]")
        cid = args[1]
        expected = args[3]
        rows = counterexample_map(artifact)
        if cid not in rows:
            raise SystemExit(f"FAIL: unknown counterexample {cid}")
        actual, path = replay(rows[cid], commit)
        if actual != expected:
            fixture = "<none>" if path is None else rel(path)
            raise SystemExit(f"FAIL: replay {cid} expected {expected} got {actual} fixture={fixture}")
        print(json.dumps({"counterexample_id": cid, "expected": expected, "actual": actual, "fixture_path": None if path is None else rel(path)}, sort_keys=True))
        return

    report = validate(artifact, commit)
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["status"] != "pass":
        raise SystemExit(1)


main()
PY
