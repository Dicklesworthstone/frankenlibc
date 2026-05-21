#!/usr/bin/env bash
# check_ld_preload_smoke_regeneration.sh -- adversarial LD_PRELOAD smoke gate for bd-3yr14.6
#
# Run mode rebuilds frankenlibc-abi through rch into a fresh target directory,
# reruns the existing LD_PRELOAD smoke battery, and compares the regenerated
# report against the committed summary. Validate-only mode consumes caller
# supplied report/trace files for focused tests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_LD_PRELOAD_SMOKE_REGEN_CONTRACT:-${ROOT}/tests/conformance/ld_preload_smoke_regeneration_gate.v1.json}"
CANONICAL="${FRANKENLIBC_LD_PRELOAD_SMOKE_CANONICAL:-${ROOT}/tests/conformance/ld_preload_smoke_summary.v1.json}"
OUT_DIR="${FRANKENLIBC_LD_PRELOAD_SMOKE_REGEN_OUT_DIR:-${ROOT}/target/conformance}"
RUN_ROOT="${FRANKENLIBC_LD_PRELOAD_SMOKE_REGEN_RUN_ROOT:-${ROOT}/target/ld_preload_smoke_regeneration}"
RUN_ID="${FRANKENLIBC_LD_PRELOAD_SMOKE_REGEN_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
RUN_DIR="${RUN_ROOT}/${RUN_ID}"
REPORT="${FRANKENLIBC_LD_PRELOAD_SMOKE_REGEN_REPORT:-${OUT_DIR}/ld_preload_smoke_regeneration_gate.report.json}"
LOG="${FRANKENLIBC_LD_PRELOAD_SMOKE_REGEN_LOG:-${OUT_DIR}/ld_preload_smoke_regeneration_gate.log.jsonl}"
MODE="run"
SMOKE_REPORT="${FRANKENLIBC_LD_PRELOAD_SMOKE_REPORT:-}"
SMOKE_TRACE="${FRANKENLIBC_LD_PRELOAD_SMOKE_TRACE:-}"

usage() {
  cat >&2 <<'EOF'
usage: scripts/check_ld_preload_smoke_regeneration.sh [--run|--validate-only] [--report PATH] [--trace PATH]

  --run            Build frankenlibc-abi via rch in a fresh target dir, run scripts/ld_preload_smoke.sh, then compare.
  --validate-only  Compare a supplied smoke report and trace without running cargo or the smoke battery.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)
      MODE="run"
      shift
      ;;
    --validate-only)
      MODE="validate-only"
      shift
      ;;
    --report)
      SMOKE_REPORT="${2:-}"
      shift 2
      ;;
    --trace)
      SMOKE_TRACE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

mkdir -p "${OUT_DIR}" "${RUN_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

if [[ "${MODE}" == "run" ]]; then
  if ! command -v rch >/dev/null 2>&1; then
    echo "check_ld_preload_smoke_regeneration: rch is required for --run" >&2
    exit 2
  fi

  BUILD_LOG="${RUN_DIR}/rch_build.log"
  SMOKE_LOG="${RUN_DIR}/ld_preload_smoke.stdout.stderr.log"
  export CARGO_TARGET_DIR="${RUN_DIR}/cargo-target"
  case ",${RCH_ENV_ALLOWLIST:-}," in
    *,CARGO_TARGET_DIR,*)
      ;;
    ,)
      export RCH_ENV_ALLOWLIST="CARGO_TARGET_DIR"
      ;;
    *)
      export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST},CARGO_TARGET_DIR"
      ;;
  esac
  export RCH_REQUIRE_REMOTE=1
  echo "check_ld_preload_smoke_regeneration: building frankenlibc-abi through rch"
  set +e
  rch exec -- cargo build -p frankenlibc-abi --release > "${BUILD_LOG}" 2>&1
  build_rc=$?
  set -e
  if grep -q '\[RCH\] local' "${BUILD_LOG}"; then
    echo "check_ld_preload_smoke_regeneration: refusing local rch fallback; see ${BUILD_LOG}" >&2
    exit 1
  fi
  if [[ "${build_rc}" -ne 0 ]]; then
    echo "check_ld_preload_smoke_regeneration: rch build failed; see ${BUILD_LOG}" >&2
    exit "${build_rc}"
  fi

  fresh_lib="${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so"
  if [[ ! -f "${fresh_lib}" ]]; then
    echo "check_ld_preload_smoke_regeneration: missing fresh lib ${fresh_lib}" >&2
    exit 1
  fi

  echo "check_ld_preload_smoke_regeneration: running LD_PRELOAD smoke battery"
  set +e
  TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-10}" \
    FRANKENLIBC_SMOKE_LIB_PATH="${fresh_lib}" \
    "${ROOT}/scripts/ld_preload_smoke.sh" > "${SMOKE_LOG}" 2>&1
  smoke_rc=$?
  set -e
  SMOKE_REPORT="$(awk -F': ' '/^Report: / {print $2}' "${SMOKE_LOG}" | tail -n 1)"
  if [[ -z "${SMOKE_REPORT}" || ! -f "${SMOKE_REPORT}" ]]; then
    echo "check_ld_preload_smoke_regeneration: could not locate smoke report from ${SMOKE_LOG}" >&2
    exit 1
  fi
  SMOKE_TRACE="$(dirname "${SMOKE_REPORT}")/trace.jsonl"
  if [[ ! -f "${SMOKE_TRACE}" ]]; then
    echo "check_ld_preload_smoke_regeneration: smoke trace missing next to report: ${SMOKE_TRACE}" >&2
    exit 1
  fi
  if [[ "${smoke_rc}" -ne 0 ]]; then
    echo "check_ld_preload_smoke_regeneration: smoke runner exited ${smoke_rc}; comparing failed report anyway" >&2
  fi
fi

python3 - "${ROOT}" "${CONTRACT}" "${CANONICAL}" "${SMOKE_REPORT}" "${SMOKE_TRACE}" "${REPORT}" "${LOG}" "${MODE}" "${RUN_ID}" <<'PY'
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
canonical_path = Path(sys.argv[3])
smoke_report_arg = sys.argv[4]
smoke_trace_arg = sys.argv[5]
report_path = Path(sys.argv[6])
log_path = Path(sys.argv[7])
mode_arg = sys.argv[8]
run_id_arg = sys.argv[9]

BEAD = "bd-3yr14.6"
REQUIRED_CASE_FIELDS = [
    "mode",
    "case",
    "status",
    "workload",
    "startup_path",
    "failure_signature",
    "signature_guard_triggered",
    "parity_required",
    "parity_pass",
    "perf_required",
    "perf_pass",
    "latency_ratio_ppm",
    "baseline_rc",
    "preload_rc",
    "stdout_match",
    "stderr_match",
    "baseline_latency_ns",
    "preload_latency_ns",
    "valgrind_checked",
    "valgrind_pass",
]
SUMMARY_FIELDS = [
    "total_cases",
    "passes",
    "fails",
    "skips",
    "signature_guard_failures",
    "perf_failures",
    "valgrind_failures",
    "overall_failed",
]
MODE_REPORT_FIELDS = [
    "total_cases",
    "passes",
    "fails",
    "skips",
    "signature_guard_failures",
    "strict_parity_failures",
    "perf_failures",
    "valgrind_failures",
]
OPTIONAL_SKIP_CASES = {
    "busybox_help": "busybox",
    "sqlite_memory_select": "sqlite3",
    "redis_cli_version": "redis-cli",
    "nginx_version": "nginx",
}
VALID_STATUSES = {"pass", "fail", "skip"}
VALID_MODES = {"strict", "hardened"}

errors: list[str] = []
checks: dict[str, Any] = {}
case_events: list[dict[str, Any]] = []


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


def rel(path: str | Path) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def load_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return rows
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{label}:{line_number}: malformed JSONL row: {exc}")
            continue
        if not isinstance(value, dict):
            errors.append(f"{label}:{line_number}: row must be a JSON object")
            continue
        rows.append(value)
    return rows


def bool_field(value: Any, context: str) -> bool:
    if isinstance(value, bool):
        return value
    errors.append(f"{context} must be bool")
    return False


def int_field(value: Any, context: str) -> int:
    if isinstance(value, bool):
        errors.append(f"{context} must be int, got bool")
        return 0
    if isinstance(value, int):
        return value
    errors.append(f"{context} must be int")
    return 0


def str_field(value: Any, context: str) -> str:
    if isinstance(value, str) and value:
        return value
    errors.append(f"{context} must be non-empty string")
    return ""


def status_for_counts(fails: int, guard_failures: int, perf_failures: int, valgrind_failures: int) -> str:
    return "red" if fails or guard_failures or perf_failures or valgrind_failures else "green"


def optional_skip_binaries(cases: list[dict[str, Any]]) -> list[str]:
    skips = {
        OPTIONAL_SKIP_CASES[case.get("case", "")]
        for case in cases
        if case.get("status") == "skip" and case.get("case") in OPTIONAL_SKIP_CASES
    }
    return sorted(skips)


def normalize_cases(report: dict[str, Any]) -> list[dict[str, Any]]:
    raw_cases = report.get("cases")
    if not isinstance(raw_cases, list):
        errors.append("smoke_report.cases must be an array")
        return []
    cases: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_cases):
        if not isinstance(raw, dict):
            errors.append(f"smoke_report.cases[{index}] must be object")
            continue
        case: dict[str, Any] = {}
        for field in REQUIRED_CASE_FIELDS:
            if field not in raw:
                errors.append(f"smoke_report.cases[{index}].{field} missing")
                continue
            value = raw.get(field)
            context = f"smoke_report.cases[{index}].{field}"
            if field in {"mode", "case", "status", "workload", "startup_path", "failure_signature"}:
                case[field] = str_field(value, context)
            elif field in {
                "signature_guard_triggered",
                "parity_required",
                "parity_pass",
                "perf_required",
                "perf_pass",
                "stdout_match",
                "stderr_match",
                "valgrind_checked",
                "valgrind_pass",
            }:
                case[field] = bool_field(value, context)
            else:
                case[field] = int_field(value, context)
        if case.get("mode") not in VALID_MODES:
            errors.append(f"smoke_report.cases[{index}].mode must be strict or hardened")
        if case.get("status") not in VALID_STATUSES:
            errors.append(f"smoke_report.cases[{index}].status must be pass/fail/skip")
        cases.append(case)
    return cases


def summary_from_cases(cases: list[dict[str, Any]], report: dict[str, Any]) -> dict[str, Any]:
    modes: dict[str, dict[str, Any]] = {}
    for mode in ("strict", "hardened"):
        mode_cases = [case for case in cases if case.get("mode") == mode]
        mode_signature_guard = sum(1 for case in mode_cases if case.get("signature_guard_triggered"))
        mode_perf_failures = sum(
            1 for case in mode_cases if case.get("perf_required") and not case.get("perf_pass")
        )
        mode_strict_parity_failures = sum(
            1 for case in mode_cases if case.get("parity_required") and not case.get("parity_pass")
        )
        mode_valgrind_failures = sum(
            1 for case in mode_cases if case.get("valgrind_checked") and not case.get("valgrind_pass")
        )
        mode_fails = sum(1 for case in mode_cases if case.get("status") == "fail")
        modes[mode] = {
            "total_cases": len(mode_cases),
            "passes": sum(1 for case in mode_cases if case.get("status") == "pass"),
            "fails": mode_fails,
            "skips": sum(1 for case in mode_cases if case.get("status") == "skip"),
            "signature_guard_failures": mode_signature_guard,
            "strict_parity_failures": mode_strict_parity_failures,
            "perf_failures": mode_perf_failures,
            "valgrind_failures": mode_valgrind_failures,
            "status": status_for_counts(mode_fails, mode_signature_guard, mode_perf_failures, mode_valgrind_failures),
        }
    signature_guard = sum(1 for case in cases if case.get("signature_guard_triggered"))
    perf_failures = sum(1 for case in cases if case.get("perf_required") and not case.get("perf_pass"))
    valgrind_failures = sum(
        1 for case in cases if case.get("valgrind_checked") and not case.get("valgrind_pass")
    )
    fails = sum(1 for case in cases if case.get("status") == "fail")
    summary = {
        "total_cases": len(cases),
        "passes": sum(1 for case in cases if case.get("status") == "pass"),
        "fails": fails,
        "skips": sum(1 for case in cases if case.get("status") == "skip"),
        "signature_guard_failures": signature_guard,
        "perf_failures": perf_failures,
        "valgrind_failures": valgrind_failures,
        "overall_failed": bool(fails or signature_guard or perf_failures or valgrind_failures),
    }
    return {
        "schema_version": report.get("schema_version"),
        "run_id": report.get("run_id"),
        "timeout_seconds": report.get("timeout_seconds"),
        "stress_iters": report.get("stress_iters"),
        "summary": summary,
        "modes": modes,
        "optional_skip_binaries": optional_skip_binaries(cases),
    }


def validate_report_summary(report: dict[str, Any], projection: dict[str, Any]) -> None:
    if report.get("schema_version") != "v1":
        errors.append("smoke_report.schema_version must be v1")
    for field in ["run_id", "lib_path"]:
        if not isinstance(report.get(field), str) or not report.get(field):
            errors.append(f"smoke_report.{field} must be non-empty string")
    for field in ["timeout_seconds", "stress_iters"]:
        if not isinstance(report.get(field), int):
            errors.append(f"smoke_report.{field} must be int")
    reported_summary = report.get("summary")
    if not isinstance(reported_summary, dict):
        errors.append("smoke_report.summary must be object")
        return
    for field in SUMMARY_FIELDS:
        expected = projection["summary"][field]
        actual = reported_summary.get(field)
        if actual != expected:
            errors.append(f"smoke_report.summary.{field}={actual!r} does not match cases-derived {expected!r}")
    reported_modes = report.get("modes")
    if not isinstance(reported_modes, dict):
        errors.append("smoke_report.modes must be object")
        return
    for mode in ("strict", "hardened"):
        raw_mode = reported_modes.get(mode)
        if not isinstance(raw_mode, dict):
            errors.append(f"smoke_report.modes.{mode} must be object")
            continue
        for field in MODE_REPORT_FIELDS:
            expected = projection["modes"][mode][field]
            actual = raw_mode.get(field)
            if actual != expected:
                errors.append(
                    f"smoke_report.modes.{mode}.{field}={actual!r} does not match cases-derived {expected!r}"
                )


def validate_canonical_summary(canonical: dict[str, Any]) -> None:
    if canonical.get("schema_version") != "v1":
        errors.append("canonical.schema_version must be v1")
    summary = canonical.get("summary")
    modes = canonical.get("modes")
    if not isinstance(summary, dict):
        errors.append("canonical.summary must be object")
        return
    if not isinstance(modes, dict):
        errors.append("canonical.modes must be object")
        return
    for field in SUMMARY_FIELDS:
        if field not in summary:
            errors.append(f"canonical.summary.{field} missing")
    mode_totals = Counter()
    for mode in ("strict", "hardened"):
        raw_mode = modes.get(mode)
        if not isinstance(raw_mode, dict):
            errors.append(f"canonical.modes.{mode} must be object")
            continue
        for field in ["total_cases", "passes", "fails", "skips"]:
            value = raw_mode.get(field)
            if not isinstance(value, int) or value < 0:
                errors.append(f"canonical.modes.{mode}.{field} must be non-negative int")
                value = 0
            mode_totals[field] += value
        expected_status = "green" if raw_mode.get("fails") == 0 else "red"
        if raw_mode.get("status") != expected_status:
            errors.append(f"canonical.modes.{mode}.status must be {expected_status}")
    for field in ["total_cases", "passes", "fails", "skips"]:
        if summary.get(field) != mode_totals[field]:
            errors.append(f"canonical.summary.{field} must equal strict+hardened mode totals")
    expected_failed = bool(
        summary.get("fails", 0)
        or summary.get("signature_guard_failures", 0)
        or summary.get("perf_failures", 0)
        or summary.get("valgrind_failures", 0)
    )
    if summary.get("overall_failed") != expected_failed:
        errors.append("canonical.summary.overall_failed is inconsistent with failure counters")
    optional = canonical.get("optional_skip_binaries")
    if not isinstance(optional, list) or not all(isinstance(item, str) and item for item in optional):
        errors.append("canonical.optional_skip_binaries must be non-empty strings")


def compare_projection(canonical: dict[str, Any], projection: dict[str, Any]) -> list[dict[str, Any]]:
    drift: list[dict[str, Any]] = []
    if canonical.get("schema_version") != projection.get("schema_version"):
        drift.append(
            {
                "field": "schema_version",
                "committed": canonical.get("schema_version"),
                "regenerated": projection.get("schema_version"),
            }
        )
    for field in ["timeout_seconds", "stress_iters"]:
        if canonical.get(field) != projection.get(field):
            drift.append(
                {
                    "field": field,
                    "committed": canonical.get(field),
                    "regenerated": projection.get(field),
                }
            )
    for field in SUMMARY_FIELDS:
        committed = canonical.get("summary", {}).get(field)
        regenerated = projection.get("summary", {}).get(field)
        if committed != regenerated:
            drift.append({"field": f"summary.{field}", "committed": committed, "regenerated": regenerated})
    for mode in ("strict", "hardened"):
        for field in ["total_cases", "passes", "fails", "skips", "status"]:
            committed = canonical.get("modes", {}).get(mode, {}).get(field)
            regenerated = projection.get("modes", {}).get(mode, {}).get(field)
            if committed != regenerated:
                drift.append(
                    {
                        "field": f"modes.{mode}.{field}",
                        "committed": committed,
                        "regenerated": regenerated,
                    }
                )
    committed_optional = sorted(canonical.get("optional_skip_binaries", []))
    regenerated_optional = projection.get("optional_skip_binaries", [])
    if committed_optional != regenerated_optional:
        drift.append(
            {
                "field": "optional_skip_binaries",
                "committed": committed_optional,
                "regenerated": regenerated_optional,
            }
        )
    return drift


def validate_contract(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != "v1":
        errors.append("contract.schema_version must be v1")
    if contract.get("manifest_id") != "ld-preload-smoke-regeneration-gate":
        errors.append("contract.manifest_id drift")
    if contract.get("bead") != BEAD:
        errors.append(f"contract.bead must be {BEAD}")
    inputs = contract.get("inputs")
    if not isinstance(inputs, dict):
        errors.append("contract.inputs must be object")
        return
    for key, expected in {
        "canonical_summary": "tests/conformance/ld_preload_smoke_summary.v1.json",
        "smoke_runner": "scripts/ld_preload_smoke.sh",
        "gate_script": "scripts/check_ld_preload_smoke_regeneration.sh",
    }.items():
        if inputs.get(key) != expected:
            errors.append(f"contract.inputs.{key} must be {expected}")
        if not (root / expected).exists():
            errors.append(f"contract input missing: {expected}")
    policies = contract.get("policies")
    if not isinstance(policies, dict):
        errors.append("contract.policies must be object")
        return
    for field in [
        "report_cases_must_recompute_summary",
        "committed_summary_must_be_internally_consistent",
        "trace_must_include_each_workload_case",
        "summary_divergence_fails_closed",
        "fresh_report_with_matching_summary_passes",
        "hand_edited_summary_without_matching_regeneration_fails_closed",
    ]:
        if policies.get(field) is not True:
            errors.append(f"contract.policies.{field} must be true")


def validate_trace(trace_rows: list[dict[str, Any]], cases: list[dict[str, Any]]) -> None:
    indexed: set[tuple[str, str, str]] = set()
    for index, row in enumerate(trace_rows):
        row_mode = row.get("mode")
        row_case = row.get("case")
        row_status = row.get("status")
        event = row.get("event")
        if event in {"case_pass", "case_fail", "case_skip_optional_binary_missing"}:
            if isinstance(row_mode, str) and isinstance(row_case, str) and isinstance(row_status, str):
                indexed.add((row_mode, row_case, row_status))
        for field in ["timestamp", "event", "mode", "case", "status", "run_id"]:
            if field not in row:
                errors.append(f"trace[{index}].{field} missing")
    for case in cases:
        key = (str(case.get("mode")), str(case.get("case")), str(case.get("status")))
        if key not in indexed:
            errors.append(f"trace missing case event for {key[0]}/{key[1]} status={key[2]}")


def append_case_log(case: dict[str, Any], report_ref: str, trace_ref: str, run_id: str) -> None:
    status = str(case.get("status", "unknown"))
    event = {
        "pass": "smoke_case_pass",
        "fail": "smoke_case_fail",
        "skip": "smoke_case_skip",
    }.get(status, "smoke_case_unknown")
    case_events.append(
        {
            "timestamp": utc_now(),
            "level": "error" if status == "fail" else "info",
            "event": event,
            "bead": BEAD,
            "run_id": run_id,
            "mode": case.get("mode"),
            "case": case.get("case"),
            "status": status,
            "source_commit": SOURCE_COMMIT,
            "report": report_ref,
            "trace": trace_ref,
            "failure_signature": case.get("failure_signature", "none"),
        }
    )


contract = load_json(contract_path, "contract")
canonical = load_json(canonical_path, "canonical")
validate_contract(contract)
validate_canonical_summary(canonical)

if not smoke_report_arg:
    errors.append("smoke report path is required; pass --report or set FRANKENLIBC_LD_PRELOAD_SMOKE_REPORT")
    smoke_report_path = Path("__missing_smoke_report__")
else:
    smoke_report_path = Path(smoke_report_arg)
    if not smoke_report_path.is_absolute():
        smoke_report_path = root / smoke_report_path

if not smoke_trace_arg and smoke_report_arg:
    smoke_trace_path = smoke_report_path.parent / "trace.jsonl"
else:
    smoke_trace_path = Path(smoke_trace_arg or "__missing_smoke_trace__")
    if not smoke_trace_path.is_absolute():
        smoke_trace_path = root / smoke_trace_path

smoke_report = load_json(smoke_report_path, "smoke_report") if smoke_report_arg else {}
cases = normalize_cases(smoke_report) if smoke_report else []
projection = summary_from_cases(cases, smoke_report) if smoke_report else {}
if smoke_report:
    validate_report_summary(smoke_report, projection)
trace_rows = load_jsonl(smoke_trace_path, "trace") if smoke_trace_path.exists() else []
if not smoke_trace_path.exists():
    errors.append(f"trace unreadable: {rel(smoke_trace_path)}: file not found")
else:
    validate_trace(trace_rows, cases)

drift = compare_projection(canonical, projection) if projection else []
if drift:
    errors.append(f"regenerated smoke summary diverges from committed summary ({len(drift)} field(s))")

for case in cases:
    append_case_log(case, rel(smoke_report_path), rel(smoke_trace_path), str(smoke_report.get("run_id", run_id_arg)))

status = "pass" if not errors else "fail"
checks = {
    "contract_validated": not any(error.startswith("contract.") for error in errors),
    "canonical_summary_validated": not any(error.startswith("canonical.") for error in errors),
    "smoke_report_cases_recomputed": not any("cases-derived" in error for error in errors),
    "trace_covers_cases": not any(error.startswith("trace") for error in errors),
    "regenerated_summary_matches_committed": not drift,
    "case_count": len(cases),
}

payload = {
    "schema_version": "ld_preload_smoke_regeneration_gate.report.v1",
    "bead": BEAD,
    "status": status,
    "mode": mode_arg,
    "run_id": str(smoke_report.get("run_id", run_id_arg)) if smoke_report else run_id_arg,
    "source_commit": SOURCE_COMMIT,
    "contract": rel(contract_path),
    "canonical_summary": rel(canonical_path),
    "smoke_report": rel(smoke_report_path),
    "smoke_trace": rel(smoke_trace_path),
    "checks": checks,
    "comparison": {
        "drift_count": len(drift),
        "drift": drift,
        "regenerated_projection": projection,
    },
    "errors": errors,
}

report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log_path.parent.mkdir(parents=True, exist_ok=True)
summary_event = {
    "timestamp": utc_now(),
    "level": "error" if errors else "info",
    "event": "ld_preload_smoke_regeneration_gate_" + status,
    "bead": BEAD,
    "run_id": payload["run_id"],
    "mode": "all",
    "case": "summary",
    "status": status,
    "source_commit": SOURCE_COMMIT,
    "report": rel(smoke_report_path),
    "trace": rel(smoke_trace_path),
    "drift_count": len(drift),
}
with log_path.open("w", encoding="utf-8") as handle:
    handle.write(json.dumps(summary_event, sort_keys=True) + "\n")
    for event in case_events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

if errors:
    print(f"FAIL: LD_PRELOAD smoke regeneration gate ({len(errors)} error(s)); report={report_path}")
    for error in errors[:12]:
        print(f"  {error}")
    if len(errors) > 12:
        print(f"  ... {len(errors) - 12} more")
    sys.exit(1)

print(f"PASS: LD_PRELOAD smoke regeneration gate; cases={len(cases)} report={report_path}")
PY
