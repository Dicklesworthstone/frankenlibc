#!/usr/bin/env bash
# check_e2e_suite.sh — CI gate for deterministic E2E suite (bd-2ez, bd-b5a.3)
#
# Validates:
# 1. e2e_suite.sh exists and is executable.
# 2. Manifest + flake-policy tooling exists and compiles.
# 3. Flake classifier/retry-policy unit tests pass.
# 4. The suite can dry-run the scenario manifest catalog.
# 5. The suite can run at least the fault scenario (fastest).
# 6. Output JSONL conforms to structured logging contract, including:
#    trace_id, scenario_pack, retry_count, flake_score, artifact_refs, verdict.
# 7. Artifact index exists with retention policy metadata.
# 8. strict/hardened mode-pair report exists and validates.
# 9. Flake quarantine + scenario-pack reports exist and validate.
#
# Exit codes:
#   0 — infrastructure checks pass
#   1 — infrastructure failure
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE_SEED="${FRANKENLIBC_E2E_GATE_SEED:-91337}"
COMPLETION_MANIFEST="${FRANKENLIBC_E2E_COMPLETION_MANIFEST:-${ROOT}/tests/conformance/e2e_scenario_manifest.v1.json}"
COMPLETION_REPORT="${FRANKENLIBC_E2E_COMPLETION_REPORT:-${ROOT}/target/conformance/e2e_suite_completion_debt.report.json}"
COMPLETION_LOG="${FRANKENLIBC_E2E_COMPLETION_LOG:-${ROOT}/target/conformance/e2e_suite_completion_debt.log.jsonl}"
SCRATCH_DIR="${TMPDIR:-/tmp}"

failures=0

run_completion_debt_check() {
    local completion_output
    completion_output="$(
        ROOT="${ROOT}" \
        COMPLETION_MANIFEST="${COMPLETION_MANIFEST}" \
        COMPLETION_REPORT="${COMPLETION_REPORT}" \
        COMPLETION_LOG="${COMPLETION_LOG}" \
        FRANKENLIBC_E2E_LATEST_RUN="${latest_run:-}" \
        python3 - <<'PY'
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ["ROOT"])
MANIFEST = Path(os.environ["COMPLETION_MANIFEST"])
REPORT = Path(os.environ["COMPLETION_REPORT"])
LOG = Path(os.environ["COMPLETION_LOG"])
LATEST_RUN = os.environ.get("FRANKENLIBC_E2E_LATEST_RUN", "")
COMPLETION_BEAD = "bd-2ez.1"
ORIGINAL_BEAD = "bd-2ez"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_TELEMETRY_EVENTS = {
    "suite_start",
    "manifest_case",
    "case_start",
    "case_attempt",
    "mode_pair_result",
    "suite_end",
    "e2e_suite_completion_debt_validated",
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "mode",
    "scenario_id",
    "scenario_pack",
    "retry_count",
    "flake_score",
    "artifact_refs",
    "verdict",
    "replay_key",
    "env_fingerprint",
    "latency_ns",
}

errors: list[str] = []


def err(message: str) -> None:
    errors.append(message)


def rel_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{rel_path(path)} is not valid JSON: {exc}")
        return {}


def file_line_ref_exists(ref: str) -> bool:
    if ":" not in ref:
        err(f"implementation ref missing line separator: {ref}")
        return False
    path_text, line_text = ref.rsplit(":", 1)
    path = ROOT / path_text
    if not path.exists():
        err(f"implementation ref path missing: {ref}")
        return False
    try:
        line_no = int(line_text)
    except ValueError:
        err(f"implementation ref line is not numeric: {ref}")
        return False
    if line_no < 1:
        err(f"implementation ref line must be positive: {ref}")
        return False
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if line_no > line_count:
        err(f"implementation ref line outside file: {ref}")
        return False
    return True


manifest = read_json(MANIFEST)
completion = manifest.get("completion_debt_evidence")
if not isinstance(completion, dict):
    completion = {}
    err("completion_debt_evidence must be an object")

if completion.get("bead") != COMPLETION_BEAD:
    err("completion_debt_evidence.bead must be bd-2ez.1")
if completion.get("original_bead") != ORIGINAL_BEAD:
    err("completion_debt_evidence.original_bead must be bd-2ez")
threshold = completion.get("next_audit_score_threshold")
if not isinstance(threshold, int) or threshold < 700 or threshold > 1000:
    err("completion_debt_evidence.next_audit_score_threshold must be 700..1000")

test_source = completion.get("test_source")
test_source_path = ROOT / str(test_source)
test_source_text = ""
if not isinstance(test_source, str) or not test_source:
    err("completion_debt_evidence.test_source must be non-empty")
elif not test_source_path.exists():
    err(f"completion_debt_evidence.test_source missing: {test_source}")
else:
    test_source_text = test_source_path.read_text(encoding="utf-8")

implementation_refs = completion.get("implementation_refs")
if not isinstance(implementation_refs, list) or not implementation_refs:
    err("completion_debt_evidence.implementation_refs must be non-empty")
else:
    for ref in implementation_refs:
        if not isinstance(ref, str):
            err("completion_debt_evidence.implementation_refs entries must be strings")
            continue
        file_line_ref_exists(ref)

missing_items: list[str] = []
for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
    section = completion.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    missing_items.append(str(section.get("missing_item_id", "")))
    section_threshold = section.get("next_audit_score_threshold", threshold)
    if not isinstance(section_threshold, int) or section_threshold < 700 or section_threshold > 1000:
        err(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be 700..1000")
    required_tests = section.get("required_test_names")
    if not isinstance(required_tests, list) or not required_tests:
        err(f"completion_debt_evidence.{section_name}.required_test_names must be non-empty")
        continue
    for test_name in required_tests:
        if not isinstance(test_name, str) or not test_name:
            err(f"completion_debt_evidence.{section_name} contains invalid test name")
            continue
        if test_source_text and f"fn {test_name}" not in test_source_text:
            err(f"completion_debt_evidence.{section_name} references missing test {test_name}")

telemetry = completion.get("telemetry_primary", {})
events = set(telemetry.get("required_events", [])) if isinstance(telemetry, dict) else set()
fields = set(telemetry.get("required_fields", [])) if isinstance(telemetry, dict) else set()
if not EXPECTED_TELEMETRY_EVENTS.issubset(events):
    missing = sorted(EXPECTED_TELEMETRY_EVENTS - events)
    err(f"telemetry_primary.required_events missing {missing}")
if not EXPECTED_TELEMETRY_FIELDS.issubset(fields):
    missing = sorted(EXPECTED_TELEMETRY_FIELDS - fields)
    err(f"telemetry_primary.required_fields missing {missing}")
if telemetry.get("default_report_path") != "target/conformance/e2e_suite_completion_debt.report.json":
    err("telemetry_primary.default_report_path drifted")
if telemetry.get("default_log_path") != "target/conformance/e2e_suite_completion_debt.log.jsonl":
    err("telemetry_primary.default_log_path drifted")

latest_run_path = Path(LATEST_RUN) if LATEST_RUN else None
latest_artifacts: list[str] = []
if latest_run_path and latest_run_path.exists():
    for rel in [
        "trace.jsonl",
        "artifact_index.json",
        "mode_pair_report.json",
        "scenario_pack_report.json",
        "flake_quarantine_report.json",
    ]:
        candidate = latest_run_path / rel
        if not candidate.exists():
            err(f"latest e2e run missing {rel}")
        else:
            latest_artifacts.append(rel_path(candidate))
    trace_path = latest_run_path / "trace.jsonl"
    if trace_path.exists():
        actual_events: set[str] = set()
        for line_no, raw in enumerate(trace_path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                err(f"latest trace line {line_no} invalid JSON: {exc}")
                continue
            actual_events.add(str(row.get("event", "")))
            for field in ("timestamp", "trace_id", "level", "event", "bead_id"):
                if field not in row:
                    err(f"latest trace line {line_no} missing {field}")
        required_actual = {"suite_start", "case_start", "case_attempt", "mode_pair_result", "suite_end"}
        if not required_actual.issubset(actual_events):
            err(f"latest trace missing events {sorted(required_actual - actual_events)}")

try:
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except Exception:
    source_commit = "unknown"

status = "fail" if errors else "pass"
timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
REPORT.parent.mkdir(parents=True, exist_ok=True)
LOG.parent.mkdir(parents=True, exist_ok=True)
report = {
    "schema_version": "e2e_suite_completion_debt.report.v1",
    "status": status,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "missing_items": sorted(EXPECTED_MISSING_ITEMS.values()),
    "next_audit_score_threshold": threshold,
    "source_commit": source_commit,
    "test_source": test_source,
    "implementation_refs": implementation_refs if isinstance(implementation_refs, list) else [],
    "required_events": sorted(events),
    "required_fields": sorted(fields),
    "latest_e2e_run": rel_path(latest_run_path) if latest_run_path and latest_run_path.exists() else None,
    "artifact_refs": latest_artifacts,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
log_row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_BEAD}::e2e-suite-completion::{status}",
    "level": "info" if status == "pass" else "error",
    "event": "e2e_suite_completion_debt_validated" if status == "pass" else "e2e_suite_completion_debt_failed",
    "bead_id": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "missing_items_bound": sorted(missing_items),
    "report_path": rel_path(REPORT),
    "latest_e2e_run": rel_path(latest_run_path) if latest_run_path and latest_run_path.exists() else "",
    "artifact_refs": [rel_path(REPORT), *latest_artifacts],
    "failure_signature": "none" if status == "pass" else "completion_debt_contract_failed",
}
LOG.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")

for message in errors:
    print(f"COMPLETION_ERROR: {message}")
print(f"COMPLETION_ERRORS={len(errors)}")
print(f"COMPLETION_REPORT={REPORT}")
print(f"COMPLETION_LOG={LOG}")
PY
    )"
    echo "${completion_output}"
    local completion_errors
    completion_errors="$(echo "${completion_output}" | awk -F= '/^COMPLETION_ERRORS=/{print $2}')"
    [[ "${completion_errors:-1}" -eq 0 ]]
}

if [[ "${FRANKENLIBC_E2E_COMPLETION_ONLY:-0}" == "1" ]]; then
    echo "=== E2E Suite Completion Debt Gate (bd-2ez.1) ==="
    if run_completion_debt_check; then
        echo "check_e2e_suite completion debt: PASS"
        exit 0
    fi
    echo "check_e2e_suite completion debt: FAILED"
    exit 1
fi

echo "=== E2E Suite Gate (bd-2ez, bd-b5a.3) ==="
echo ""

echo "--- Check 1: E2E suite script exists ---"
if [[ ! -f "${ROOT}/scripts/e2e_suite.sh" ]]; then
    echo "FAIL: scripts/e2e_suite.sh not found"
    failures=$((failures + 1))
elif [[ ! -x "${ROOT}/scripts/e2e_suite.sh" ]]; then
    echo "FAIL: scripts/e2e_suite.sh is not executable"
    failures=$((failures + 1))
else
    echo "PASS: e2e_suite.sh exists and is executable"
fi
echo ""

echo "--- Check 2: Tooling presence + syntax ---"
tool_fail=0
for required in \
    "${ROOT}/scripts/validate_e2e_manifest.py" \
    "${ROOT}/scripts/e2e_flake_policy.py" \
    "${ROOT}/tests/conformance/e2e_scenario_manifest.v1.json" \
    "${ROOT}/tests/conformance/test_e2e_flake_policy.py"; do
    if [[ ! -f "${required}" ]]; then
        echo "  missing: ${required}"
        tool_fail=1
    fi
done
if ! python3 -c "import py_compile; py_compile.compile('${ROOT}/scripts/validate_e2e_manifest.py', doraise=True)" >/dev/null 2>&1; then
    echo "  syntax error: scripts/validate_e2e_manifest.py"
    tool_fail=1
fi
if ! python3 -c "import py_compile; py_compile.compile('${ROOT}/scripts/e2e_flake_policy.py', doraise=True)" >/dev/null 2>&1; then
    echo "  syntax error: scripts/e2e_flake_policy.py"
    tool_fail=1
fi
if ! python3 "${ROOT}/scripts/validate_e2e_manifest.py" validate --manifest "${ROOT}/tests/conformance/e2e_scenario_manifest.v1.json" >/dev/null 2>&1; then
    echo "  manifest validation failed"
    tool_fail=1
fi
if ! grep -Fq "rch exec -- cargo build -p frankenlibc-abi --release" "${ROOT}/scripts/e2e_suite.sh"; then
    echo "  missing rch offload build command in scripts/e2e_suite.sh"
    tool_fail=1
fi
if ! grep -Fq "rch is required for cargo build offload" "${ROOT}/scripts/e2e_suite.sh"; then
    echo "  missing rch-required guard in scripts/e2e_suite.sh"
    tool_fail=1
fi
if [[ "${tool_fail}" -ne 0 ]]; then
    echo "FAIL: tooling validation failed"
    failures=$((failures + 1))
else
    echo "PASS: tooling present and valid"
fi
echo ""

echo "--- Check 3: Flake policy unit tests ---"
mkdir -p "${SCRATCH_DIR}"
flake_policy_log="${SCRATCH_DIR%/}/e2e_flake_policy_test.log"
set +e
python3 -m unittest "${ROOT}/tests/conformance/test_e2e_flake_policy.py" -q >"${flake_policy_log}" 2>&1
ut_rc=$?
set -e
if [[ "${ut_rc}" -ne 0 ]]; then
    echo "FAIL: flake policy unit tests failed"
    tail -n 40 "${flake_policy_log}" || true
    failures=$((failures + 1))
else
    echo "PASS: flake policy unit tests"
fi
echo ""

echo "--- Check 4: Manifest dry-run ---"
set +e
bash "${ROOT}/scripts/e2e_suite.sh" --dry-run-manifest fault strict >/dev/null 2>&1
dry_run_rc=$?
set -e
if [[ "${dry_run_rc}" -ne 0 ]]; then
    echo "FAIL: manifest dry-run failed (exit=${dry_run_rc})"
    failures=$((failures + 1))
else
    echo "PASS: manifest dry-run succeeded"
fi
echo ""

echo "--- Check 5: Infrastructure smoke test ---"
export TIMEOUT_SECONDS=3
export FRANKENLIBC_E2E_SEED="${GATE_SEED}"
export FRANKENLIBC_E2E_RETRY_MAX=1
export FRANKENLIBC_E2E_RETRY_ON_NONZERO=1
export FRANKENLIBC_E2E_RETRYABLE_CODES=124,125
export FRANKENLIBC_E2E_FLAKE_QUARANTINE_THRESHOLD=0.34
export FRANKENLIBC_E2E_PACK_MAX_FAILS_FAULT=6
export FRANKENLIBC_E2E_PACK_MAX_QUARANTINED_FAULT=2
e2e_gate_run_log="${SCRATCH_DIR%/}/e2e_suite_gate_run.log"
set +e
bash "${ROOT}/scripts/e2e_suite.sh" fault >"${e2e_gate_run_log}" 2>&1
suite_rc=$?
set -e
latest_run="$(ls -td "${ROOT}"/target/e2e_suite/e2e-*"-s${GATE_SEED}" 2>/dev/null | head -1)"
if [[ -z "${latest_run}" ]]; then
    echo "FAIL: no E2E run directory generated for seed ${GATE_SEED}"
    failures=$((failures + 1))
else
    echo "PASS: suite generated output at ${latest_run} (exit=${suite_rc})"
fi
echo ""

echo "--- Check 6: Structured log validation ---"
if [[ -n "${latest_run}" && -f "${latest_run}/trace.jsonl" ]]; then
    log_check="$(python3 - <<PY
import json
errors = 0
lines = 0
with open("${latest_run}/trace.jsonl", "r", encoding="utf-8") as fh:
    for i, raw in enumerate(fh, 1):
        line = raw.strip()
        if not line:
            continue
        lines += 1
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"line {i}: invalid JSON: {exc}")
            errors += 1
            continue
        for field in ("timestamp", "trace_id", "level", "event", "bead_id"):
            if field not in obj:
                print(f"line {i}: missing {field}")
                errors += 1
        if "::" not in str(obj.get("trace_id", "")):
            print(f"line {i}: malformed trace_id")
            errors += 1
        event = obj.get("event", "")
        if event.startswith("case_") or event == "manifest_case":
            for field in ("mode", "scenario_id", "scenario_pack", "expected_outcome", "artifact_policy", "retry_count", "flake_score", "artifact_refs", "verdict"):
                if field not in obj:
                    print(f"line {i}: {event} missing {field}")
                    errors += 1
            if event.startswith("case_"):
                for field in ("replay_key", "env_fingerprint"):
                    if field not in obj:
                        print(f"line {i}: {event} missing {field}")
                        errors += 1
            if "artifact_refs" in obj and not isinstance(obj["artifact_refs"], list):
                print(f"line {i}: artifact_refs must be array")
                errors += 1
            if "retry_count" in obj and not isinstance(obj["retry_count"], int):
                print(f"line {i}: retry_count must be int")
                errors += 1
            if "flake_score" in obj and not isinstance(obj["flake_score"], (int, float)):
                print(f"line {i}: flake_score must be number")
                errors += 1
            if "artifact_policy" in obj and not isinstance(obj["artifact_policy"], dict):
                print(f"line {i}: artifact_policy must be object")
                errors += 1
        if event == "case_fail":
            for field in ("startup_path", "failure_signature", "signature_guard_triggered"):
                if field not in obj:
                    print(f"line {i}: case_fail missing {field}")
                    errors += 1
            if "signature_guard_triggered" in obj and not isinstance(obj["signature_guard_triggered"], (bool, int)):
                print(f"line {i}: signature_guard_triggered must be bool/int")
                errors += 1
        if event == "mode_pair_result":
            for field in ("scenario_id", "mode_pair_result", "drift_flags"):
                if field not in obj:
                    print(f"line {i}: mode_pair_result missing {field}")
                    errors += 1
            if "drift_flags" in obj and not isinstance(obj["drift_flags"], list):
                print(f"line {i}: drift_flags must be array")
                errors += 1
print(f"LINES={lines}")
print(f"ERRORS={errors}")
PY
)"
    log_lines="$(echo "${log_check}" | awk -F= '/^LINES=/{print $2}')"
    log_errors="$(echo "${log_check}" | awk -F= '/^ERRORS=/{print $2}')"
    if [[ "${log_errors}" -gt 0 ]]; then
        echo "FAIL: structured log validation errors:"
        echo "${log_check}" | grep -v '^LINES=' | grep -v '^ERRORS='
        failures=$((failures + 1))
    elif [[ "${log_lines}" -lt 2 ]]; then
        echo "FAIL: too few log lines (${log_lines})"
        failures=$((failures + 1))
    else
        echo "PASS: ${log_lines} structured log lines, contract satisfied"
    fi
else
    echo "FAIL: trace.jsonl not found"
    failures=$((failures + 1))
fi
echo ""

echo "--- Check 7: Artifact index ---"
if [[ -n "${latest_run}" && -f "${latest_run}/artifact_index.json" ]]; then
    idx_check="$(python3 - <<PY
import json
idx = json.load(open("${latest_run}/artifact_index.json", "r", encoding="utf-8"))
errors = []
joined_artifacts = 0
log_joined = 0
for key in ("index_version", "run_id", "bead_id", "generated_utc", "retention_policy", "artifacts"):
    if key not in idx:
        errors.append(f"missing {key}")
if idx.get("index_version") != 1:
    errors.append(f"index_version must be 1, got {idx.get('index_version')}")
if idx.get("bead_id") != "bd-2ez":
    errors.append(f"bead_id must be bd-2ez, got {idx.get('bead_id')}")
if not isinstance(idx.get("retention_policy"), dict):
    errors.append("retention_policy must be object")
arts = idx.get("artifacts", [])
for art in arts:
    for field in ("path", "kind", "retention_tier", "sha256"):
        if field not in art:
            errors.append(f"artifact missing {field}")
    join_keys = art.get("join_keys")
    if join_keys is not None:
        if not isinstance(join_keys, dict):
            errors.append(f"artifact {art.get('path')} join_keys must be object")
            continue
        trace_ids = join_keys.get("trace_ids", [])
        if trace_ids:
            if not isinstance(trace_ids, list):
                errors.append(f"artifact {art.get('path')} join_keys.trace_ids must be array")
            else:
                joined_artifacts += 1
                if art.get("path") == "trace.jsonl":
                    log_joined += 1
                for trace_id in trace_ids:
                    if not isinstance(trace_id, str) or "::" not in trace_id:
                        errors.append(
                            f"artifact {art.get('path')} has malformed trace_id {trace_id!r}"
                        )
if joined_artifacts == 0:
    errors.append("expected at least one artifact entry with join_keys.trace_ids")
if log_joined == 0:
    errors.append("expected trace.jsonl artifact entry with join_keys.trace_ids")
if errors:
    for err in errors:
        print(f"INDEX_ERROR: {err}")
print(f"ARTIFACTS={len(arts)}")
print(f"JOINED_ARTIFACTS={joined_artifacts}")
print(f"INDEX_ERRORS={len(errors)}")
PY
)"
    idx_errors="$(echo "${idx_check}" | awk -F= '/^INDEX_ERRORS=/{print $2}')"
    idx_artifacts="$(echo "${idx_check}" | awk -F= '/^ARTIFACTS=/{print $2}')"
    idx_joined="$(echo "${idx_check}" | awk -F= '/^JOINED_ARTIFACTS=/{print $2}')"
    if [[ "${idx_errors}" -gt 0 ]]; then
        echo "FAIL: artifact index validation errors:"
        echo "${idx_check}" | grep '^INDEX_ERROR:'
        failures=$((failures + 1))
    else
        echo "PASS: artifact index valid with ${idx_artifacts} entries (${idx_joined} joined)"
    fi
else
    echo "FAIL: artifact_index.json not found"
    failures=$((failures + 1))
fi
echo ""

echo "--- Check 8: Mode pair report ---"
if [[ -n "${latest_run}" && -f "${latest_run}/mode_pair_report.json" ]]; then
    pair_check="$(python3 - <<PY
import json
report = json.load(open("${latest_run}/mode_pair_report.json", "r", encoding="utf-8"))
errors = []
for key in ("schema_version", "run_id", "pair_count", "mismatch_count", "pairs"):
    if key not in report:
        errors.append(f"missing {key}")
if report.get("schema_version") != "v1":
    errors.append(f"schema_version must be v1, got {report.get('schema_version')}")
if not isinstance(report.get("pairs"), list):
    errors.append("pairs must be array")
for pair in report.get("pairs", []):
    for field in ("scenario_id", "mode_pair_result", "drift_flags"):
        if field not in pair:
            errors.append(f"pair missing {field}")
if errors:
    for err in errors:
        print(f"PAIR_ERROR: {err}")
print(f"PAIR_ERRORS={len(errors)}")
PY
)"
    pair_errors="$(echo "${pair_check}" | awk -F= '/^PAIR_ERRORS=/{print $2}')"
    if [[ "${pair_errors}" -gt 0 ]]; then
        echo "FAIL: mode-pair report errors:"
        echo "${pair_check}" | grep '^PAIR_ERROR:'
        failures=$((failures + 1))
    else
        echo "PASS: mode_pair_report.json is valid"
    fi
else
    echo "FAIL: mode_pair_report.json not found"
    failures=$((failures + 1))
fi
echo ""

echo "--- Check 9: Quarantine + scenario pack reports ---"
if [[ -n "${latest_run}" && -f "${latest_run}/flake_quarantine_report.json" && -f "${latest_run}/scenario_pack_report.json" ]]; then
    report_check="$(python3 - <<PY
import json
q = json.load(open("${latest_run}/flake_quarantine_report.json", "r", encoding="utf-8"))
p = json.load(open("${latest_run}/scenario_pack_report.json", "r", encoding="utf-8"))
errors = []
for key in ("schema_version", "quarantined_count", "quarantined_cases", "remediation_workflow"):
    if key not in q:
        errors.append(f"quarantine missing {key}")
if q.get("schema_version") != "v1":
    errors.append("quarantine schema_version must be v1")
if not isinstance(q.get("quarantined_cases"), list):
    errors.append("quarantined_cases must be array")
if not isinstance(q.get("remediation_workflow"), list) or len(q.get("remediation_workflow", [])) < 2:
    errors.append("remediation_workflow must be a non-trivial list")
for key in ("schema_version", "packs"):
    if key not in p:
        errors.append(f"pack report missing {key}")
if p.get("schema_version") != "v1":
    errors.append("pack report schema_version must be v1")
if not isinstance(p.get("packs"), list) or not p.get("packs"):
    errors.append("pack report packs must be non-empty array")
for pack in p.get("packs", []):
    for key in ("scenario_pack", "counts", "thresholds", "verdict"):
        if key not in pack:
            errors.append(f"pack row missing {key}")
    if pack.get("verdict") not in {"pass", "fail"}:
        errors.append(f"invalid pack verdict: {pack.get('verdict')}")
if errors:
    for err in errors:
        print(f"REPORT_ERROR: {err}")
print(f"REPORT_ERRORS={len(errors)}")
PY
)"
    report_errors="$(echo "${report_check}" | awk -F= '/^REPORT_ERRORS=/{print $2}')"
    if [[ "${report_errors}" -gt 0 ]]; then
        echo "FAIL: quarantine/pack report errors:"
        echo "${report_check}" | grep '^REPORT_ERROR:'
        failures=$((failures + 1))
    else
        echo "PASS: quarantine + scenario-pack reports are valid"
    fi
else
    echo "FAIL: missing flake_quarantine_report.json or scenario_pack_report.json"
    failures=$((failures + 1))
fi
echo ""

echo "--- Check 10: Startup smoke diagnostics contract ---"
startup_contract_fail=0
ld_smoke_script="${ROOT}/scripts/ld_preload_smoke.sh"
if [[ ! -f "${ld_smoke_script}" ]]; then
    echo "FAIL: scripts/ld_preload_smoke.sh not found"
    startup_contract_fail=1
else
    for marker in \
        "FAILURE_SIGNATURE_DENYLIST" \
        "signature_guard_triggered" \
        "startup_troubleshooting.md" \
        "\"startup_path\"" \
        "\"failure_signature\"" \
        "classify_failure_signature" \
        "case_startup_path"; do
        if ! grep -Fq "${marker}" "${ld_smoke_script}"; then
            echo "  missing marker in ld_preload_smoke.sh: ${marker}"
            startup_contract_fail=1
        fi
    done
fi
if [[ "${startup_contract_fail}" -ne 0 ]]; then
    echo "FAIL: startup smoke diagnostics contract regression"
    failures=$((failures + 1))
else
    echo "PASS: startup smoke diagnostics contract markers present"
fi
echo ""

echo "--- Check 11: Completion-debt evidence binding ---"
if run_completion_debt_check; then
    echo "PASS: completion-debt evidence bound to bd-2ez.1"
else
    echo "FAIL: completion-debt evidence binding failed"
    failures=$((failures + 1))
fi
echo ""

echo "=== Summary ==="
echo "Failures: ${failures}"
echo "Note: interpose-stage functional failures are expected; this gate validates deterministic E2E infrastructure and policy reporting."
if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_e2e_suite: FAILED"
    exit 1
fi

echo ""
echo "check_e2e_suite: PASS"
