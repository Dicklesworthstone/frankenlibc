#!/usr/bin/env bash
# check_setjmp_fixture_pack.sh — CI/evidence gate for bd-ahjd
#
# Validates deterministic nested/edge setjmp fixture pack, executes fixture
# programs under strict+hardened mode env profiles, and emits structured logs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${ROOT}/tests/conformance/fixtures/setjmp_nested_edges.json"
OUT_DIR="${ROOT}/target/conformance"
BIN_DIR="${OUT_DIR}/setjmp_bins"
REPORT="${OUT_DIR}/setjmp_fixture_pack.report.json"
LOG="${OUT_DIR}/setjmp_fixture_pack.log.jsonl"
CVE_DIR="${ROOT}/tests/cve_arena/results/bd-ahjd"
CVE_TRACE="${CVE_DIR}/trace.jsonl"
CVE_INDEX="${CVE_DIR}/artifact_index.json"
RUN_ID="setjmp-fixture-pack-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}" "${BIN_DIR}" "${CVE_DIR}"

if [[ ! -f "${ARTIFACT}" ]]; then
  echo "FAIL: missing fixture artifact ${ARTIFACT}" >&2
  exit 1
fi

python3 - "${ROOT}" "${ARTIFACT}" "${BIN_DIR}" "${REPORT}" "${LOG}" "${CVE_TRACE}" "${CVE_INDEX}" "${RUN_ID}" <<'PY'
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import sys

(
    root_raw,
    artifact_raw,
    bin_dir_raw,
    report_raw,
    log_raw,
    cve_trace_raw,
    cve_index_raw,
    run_id,
) = sys.argv[1:9]

root = Path(root_raw)
artifact_path = Path(artifact_raw)
bin_dir = Path(bin_dir_raw)
report_path = Path(report_raw)
log_path = Path(log_raw)
cve_trace_path = Path(cve_trace_raw)
cve_index_path = Path(cve_index_raw)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover
        fail(f"unable to parse JSON {path}: {exc}")


artifact = load_json(artifact_path)

if artifact.get("schema_version") != "v1":
    fail("fixture artifact schema_version must be v1")
if artifact.get("bead") != "bd-ahjd":
    fail("fixture artifact bead must be bd-ahjd")

triage_rel = artifact.get("triage_doc")
if not isinstance(triage_rel, str) or not triage_rel.strip():
    fail("triage_doc must be non-empty string")
triage_path = root / triage_rel
if not triage_path.exists():
    fail(f"triage_doc missing: {triage_path}")

program_scenarios = artifact.get("program_scenarios", [])
unsupported_scenarios = artifact.get("unsupported_scenarios", [])
if not isinstance(program_scenarios, list) or not program_scenarios:
    fail("program_scenarios must be non-empty array")
if not isinstance(unsupported_scenarios, list) or not unsupported_scenarios:
    fail("unsupported_scenarios must be non-empty array")

summary = artifact.get("summary", {})
if int(summary.get("program_scenario_count", -1)) != len(program_scenarios):
    fail("summary.program_scenario_count mismatch")
if int(summary.get("unsupported_scenario_count", -1)) != len(unsupported_scenarios):
    fail("summary.unsupported_scenario_count mismatch")

required_modes = ["strict", "hardened"]
records = []

for scenario in program_scenarios:
    if not isinstance(scenario, dict):
        fail("program_scenarios entries must be objects")
    scenario_id = str(scenario.get("scenario_id", "")).strip()
    if not scenario_id:
        fail("program_scenario missing scenario_id")

    source_rel = str(scenario.get("source", "")).strip()
    if not source_rel:
        fail(f"scenario {scenario_id} missing source")
    source_path = root / source_rel
    if not source_path.exists():
        fail(f"scenario {scenario_id} missing source file: {source_path}")

    expected = scenario.get("expected", {})
    if not isinstance(expected, dict):
        fail(f"scenario {scenario_id} expected must be object")

    binary_path = bin_dir / f"{scenario_id}.bin"
    compile_cmd = ["cc", "-std=c11", "-O2", str(source_path), "-o", str(binary_path)]
    compile_proc = subprocess.run(compile_cmd, capture_output=True, text=True)
    if compile_proc.returncode != 0:
        fail(
            f"cc failed for scenario {scenario_id}: stderr={compile_proc.stderr.strip()}"
        )

    for mode in required_modes:
        mode_expected = expected.get(mode)
        if not isinstance(mode_expected, dict):
            fail(f"scenario {scenario_id} missing expected profile for mode {mode}")
        expected_exit = int(mode_expected.get("exit_code", -9999))
        expected_stdout = str(mode_expected.get("stdout_contains", "")).strip()
        if not expected_stdout:
            fail(f"scenario {scenario_id} mode {mode} missing stdout_contains")

        env = os.environ.copy()
        env["FRANKENLIBC_MODE"] = mode

        started = datetime.now(timezone.utc)
        proc = subprocess.run([str(binary_path)], capture_output=True, text=True, env=env)
        finished = datetime.now(timezone.utc)
        latency_ns = int((finished - started).total_seconds() * 1_000_000_000)

        if proc.returncode != expected_exit:
            fail(
                f"scenario {scenario_id} mode {mode} unexpected exit code {proc.returncode} expected {expected_exit}"
            )
        if expected_stdout not in proc.stdout:
            fail(
                f"scenario {scenario_id} mode {mode} stdout does not contain expected token '{expected_stdout}'"
            )

        records.append(
            {
                "timestamp": finished.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "trace_id": f"bd-ahjd::{run_id}::{scenario_id}::{mode}",
                "level": "info",
                "event": "fixture_result",
                "bead_id": "bd-ahjd",
                "stream": "conformance",
                "gate": "check_setjmp_fixture_pack",
                "scenario_id": scenario_id,
                "mode": mode,
                "api_family": "setjmp",
                "symbol": "non_local_jump",
                "jump_depth": int(scenario.get("jump_depth", 0)),
                "mask_state": str(scenario.get("mask_state", "unknown")),
                "outcome": "pass",
                "errno": 0,
                "latency_ns": latency_ns,
                "artifact_refs": [
                    "tests/conformance/fixtures/setjmp_nested_edges.json",
                    "target/conformance/setjmp_fixture_pack.report.json",
                    "target/conformance/setjmp_fixture_pack.log.jsonl",
                ],
            }
        )

for scenario in unsupported_scenarios:
    if not isinstance(scenario, dict):
        fail("unsupported_scenarios entries must be objects")
    scenario_id = str(scenario.get("scenario_id", "")).strip()
    if not scenario_id:
        fail("unsupported scenario missing scenario_id")
    documented_semantics = str(scenario.get("documented_semantics", "")).strip()
    expected_outcome = str(scenario.get("expected_outcome", "")).strip()
    expected_errno = str(scenario.get("expected_errno", "")).strip()
    modes = scenario.get("modes", [])
    if expected_outcome != "unsupported_deferred":
        fail(f"unsupported scenario {scenario_id} must set expected_outcome=unsupported_deferred")
    if not expected_errno:
        fail(f"unsupported scenario {scenario_id} missing expected_errno")
    if not documented_semantics:
        fail(f"unsupported scenario {scenario_id} missing documented_semantics")
    if not isinstance(modes, list) or not modes:
        fail(f"unsupported scenario {scenario_id} must define modes")
    for mode in modes:
        if mode not in required_modes:
            fail(f"unsupported scenario {scenario_id} has invalid mode {mode}")
        now = datetime.now(timezone.utc)
        records.append(
            {
                "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "trace_id": f"bd-ahjd::{run_id}::{scenario_id}::{mode}",
                "level": "info",
                "event": "unsupported_scenario",
                "bead_id": "bd-ahjd",
                "stream": "conformance",
                "gate": "check_setjmp_fixture_pack",
                "scenario_id": scenario_id,
                "mode": mode,
                "api_family": "setjmp",
                "symbol": "non_local_jump",
                "jump_depth": int(scenario.get("jump_depth", 0)),
                "mask_state": str(scenario.get("mask_state", "unknown")),
                "outcome": expected_outcome,
                "errno": expected_errno,
                "latency_ns": 0,
                "artifact_refs": [
                    "tests/conformance/fixtures/setjmp_nested_edges.json",
                    "docs/setjmp/non_local_jump_triage.md",
                    "target/conformance/setjmp_fixture_pack.log.jsonl",
                ],
            }
        )

strict_profiles = sum(1 for s in program_scenarios if isinstance(s.get("expected", {}).get("strict"), dict))
hardened_profiles = sum(1 for s in program_scenarios if isinstance(s.get("expected", {}).get("hardened"), dict))
if int(summary.get("strict_profiles", -1)) != strict_profiles:
    fail("summary.strict_profiles mismatch")
if int(summary.get("hardened_profiles", -1)) != hardened_profiles:
    fail("summary.hardened_profiles mismatch")

report = {
    "schema_version": "v1",
    "bead": "bd-ahjd",
    "checks": {
        "artifact_schema": "pass",
        "program_fixture_execution": "pass",
        "strict_hardened_profiles": "pass",
        "unsupported_semantics_documented": "pass",
        "triage_doc_present": "pass",
        "summary_consistent": "pass",
    },
    "summary": {
        "program_scenarios": len(program_scenarios),
        "unsupported_scenarios": len(unsupported_scenarios),
        "record_count": len(records),
        "strict_profiles": strict_profiles,
        "hardened_profiles": hardened_profiles,
    },
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

encoded_lines = [json.dumps(row, separators=(",", ":")) for row in records]
log_path.write_text("\n".join(encoded_lines) + "\n", encoding="utf-8")
cve_trace_path.write_text("\n".join(encoded_lines) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def rel_path(path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()

artifacts = [artifact_path, report_path, log_path, cve_trace_path, triage_path]
cve_index = {
    "index_version": 1,
    "bead_id": "bd-ahjd",
    "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
    "artifacts": [
        {
            "path": rel_path(path),
            "kind": "jsonl" if path.suffix == ".jsonl" else ("markdown" if path.suffix == ".md" else "json"),
            "sha256": sha256(path),
        }
        for path in artifacts
    ],
}
cve_index_path.write_text(json.dumps(cve_index, indent=2) + "\n", encoding="utf-8")

print(json.dumps(report, indent=2))
PY

echo "PASS: setjmp fixture pack gate"
