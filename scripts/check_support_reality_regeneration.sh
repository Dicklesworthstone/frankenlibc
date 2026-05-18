#!/usr/bin/env bash
# Validate or regenerate the support_matrix.json and reality_report.v1.json paired contract.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${SUPPORT_REALITY_REGEN_CONTRACT:-${ROOT}/tests/conformance/support_reality_regeneration.v1.json}"
SUPPORT_MATRIX="${SUPPORT_REALITY_SUPPORT_MATRIX:-${ROOT}/support_matrix.json}"
REALITY_REPORT="${SUPPORT_REALITY_REPORT:-${ROOT}/tests/conformance/reality_report.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/support_reality_regeneration.report.json"
LOG="${OUT_DIR}/support_reality_regeneration.log.jsonl"
TRACE_ID="bd-0agsk.3::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"

MODE="validate-only"
if [[ $# -gt 0 ]]; then
  case "$1" in
    --validate-only)
      MODE="validate-only"
      shift
      ;;
    --regenerate)
      MODE="regenerate"
      shift
      ;;
    --write-reality-only|--write-support-only|--regenerate-reality-only|--regenerate-support-only)
      MODE="${1#--}"
      shift
      ;;
    *)
      MODE="unknown:${1}"
      shift
      ;;
  esac
fi

if [[ $# -gt 0 ]]; then
  MODE="unknown:${1}"
fi

mkdir -p "${OUT_DIR}"

if [[ "${MODE}" == "regenerate" ]]; then
  bash "${ROOT}/scripts/abi_audit.sh" --json-only --deterministic >/dev/null
  cargo run --quiet -p frankenlibc-harness --bin harness -- \
    reality-report \
    --support-matrix "${SUPPORT_MATRIX}" \
    --output "${REALITY_REPORT}"
fi

python3 - "${ROOT}" "${CONTRACT}" "${SUPPORT_MATRIX}" "${REALITY_REPORT}" "${REPORT}" "${LOG}" "${TRACE_ID}" "${MODE}" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
support_path = pathlib.Path(sys.argv[3])
reality_path = pathlib.Path(sys.argv[4])
report_path = pathlib.Path(sys.argv[5])
log_path = pathlib.Path(sys.argv[6])
trace_id = sys.argv[7]
mode = sys.argv[8]
start_ns = time.time_ns()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def git_head() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_event(report, event_name: str) -> None:
    event = {
        "timestamp": now_utc(),
        "trace_id": trace_id,
        "level": "error" if report.get("outcome") == "fail" else "info",
        "event": event_name,
        "bead_id": "bd-0agsk.3",
        "source_commit": report.get("source_commit"),
        "artifact_refs": [
            str(contract_path),
            str(support_path),
            str(reality_path),
            str(report_path),
        ],
        "outcome": report.get("outcome"),
        "failure_signature": report.get("failure_signature"),
        "duration_ms": report.get("duration_ms"),
        "details": report.get("summary", {}),
    }
    log_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")


def finish(report, event_name: str) -> None:
    report["duration_ms"] = (time.time_ns() - start_ns) // 1_000_000
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_event(report, event_name)


def fail(signature: str, message: str, **extra) -> None:
    report = {
        "schema_version": "support_reality_regeneration.report.v1",
        "bead": "bd-0agsk.3",
        "trace_id": trace_id,
        "source_commit": extra.pop("source_commit", None),
        "mode": mode,
        "outcome": "fail",
        "failure_signature": signature,
        "failure_message": message,
        "contract": str(contract_path),
        "support_matrix": str(support_path),
        "reality_report": str(reality_path),
        "summary": extra,
    }
    finish(report, "support_reality_regeneration_failed")
    raise SystemExit(f"FAIL[{signature}]: {message}")


if mode not in {"validate-only", "regenerate"}:
    fail(
        "single_artifact_update_forbidden",
        f"only --validate-only or --regenerate is supported by this paired-artifact gate; got {mode}",
    )

for path in [contract_path, support_path, reality_path]:
    if not path.is_file():
        fail("required_file_missing", f"required file missing: {path}")

contract = load_json(contract_path)
if contract.get("schema_version") != "support_reality_regeneration.v1":
    fail("contract_schema_version", "contract schema_version must be support_reality_regeneration.v1")
if contract.get("generated_by_bead") != "bd-0agsk.3":
    fail("contract_bead", "contract generated_by_bead must be bd-0agsk.3")
if contract.get("mode") != "validate_only":
    fail("contract_mode", "contract mode must be validate_only")

paired_policy = contract.get("paired_update_policy", {})
if paired_policy.get("single_artifact_update") != "forbidden":
    fail("single_artifact_policy_missing", "single_artifact_update must be forbidden")

required_ids = set(paired_policy.get("required_artifact_ids", []))
if required_ids != {"support_matrix", "reality_report"}:
    fail("required_artifact_ids", "required_artifact_ids must be support_matrix and reality_report")

output_artifacts = contract.get("output_artifacts")
if not isinstance(output_artifacts, list):
    fail("output_artifacts_missing", "output_artifacts must be an array")
artifact_by_id = {str(row.get("id")): row for row in output_artifacts if isinstance(row, dict)}
if not {"support_matrix", "reality_report"}.issubset(artifact_by_id):
    fail("paired_artifacts_missing", "output_artifacts must include support_matrix and reality_report")

source_commit = git_head()
support_sha = sha256_file(support_path)
reality_sha = sha256_file(reality_path)
expected_hashes = {
    "support_matrix": support_sha,
    "reality_report": reality_sha,
}
if mode == "regenerate":
    for artifact_id, current_sha in expected_hashes.items():
        artifact_by_id[artifact_id]["sha256"] = current_sha
    for row in contract.get("input_artifacts", []):
        if isinstance(row, dict) and row.get("id") in expected_hashes:
            row["sha256"] = expected_hashes[str(row["id"])]
    contract_path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")

for artifact_id, current_sha in expected_hashes.items():
    declared_sha = str(artifact_by_id[artifact_id].get("sha256", ""))
    if declared_sha != current_sha:
        fail(
            "artifact_sha256_mismatch",
            f"{artifact_id} sha256 mismatch",
            source_commit=source_commit,
            artifact_id=artifact_id,
            declared_sha256=declared_sha,
            current_sha256=current_sha,
        )

generator_cmd = [
    "cargo",
    "run",
    "--quiet",
    "-p",
    "frankenlibc-harness",
    "--bin",
    "harness",
    "--",
    "reality-report",
    "--support-matrix",
    str(support_path),
]
generated = subprocess.run(
    generator_cmd,
    cwd=root,
    text=True,
    capture_output=True,
    check=False,
)
if generated.returncode != 0:
    fail(
        "reality_generator_failed",
        "harness reality-report generator failed",
        source_commit=source_commit,
        stderr=generated.stderr[-4000:],
    )

try:
    generated_reality = json.loads(generated.stdout)
except json.JSONDecodeError as err:
    fail(
        "reality_generator_invalid_json",
        f"harness reality-report output was not JSON: {err}",
        source_commit=source_commit,
    )

support = load_json(support_path)
reality = load_json(reality_path)
if generated_reality != reality:
    fail(
        "reality_report_drift",
        "canonical reality_report.v1.json differs from harness output",
        source_commit=source_commit,
        generated_counts=generated_reality.get("counts"),
        canonical_counts=reality.get("counts"),
    )

support_summary = support.get("summary", {})
support_counts = {
    "implemented": int(support_summary.get("implemented", support.get("counts", {}).get("implemented", 0))),
    "raw_syscall": int(support_summary.get("raw_syscall", support.get("counts", {}).get("raw_syscall", 0))),
    "wraps_host_libc": int(support_summary.get("wraps_host_libc", support.get("counts", {}).get("wraps_host_libc", 0))),
    "glibc_call_through": int(support_summary.get("glibc_call_through", support.get("counts", {}).get("glibc_call_through", 0))),
    "stub": int(support_summary.get("stub", support.get("counts", {}).get("stub", 0))),
}
reality_counts = {key: int(value) for key, value in reality.get("counts", {}).items()}
if support_counts != reality_counts:
    fail(
        "support_reality_count_mismatch",
        "support_matrix summary counts differ from reality_report counts",
        source_commit=source_commit,
        support_counts=support_counts,
        reality_counts=reality_counts,
    )

support_total = int(support.get("total_exported", -1))
reality_total = int(reality.get("total_exported", -2))
symbol_count = len(support.get("symbols", []))
if support_total != reality_total or support_total != symbol_count:
    fail(
        "support_reality_total_mismatch",
        "support/reality totals or symbols length differ",
        source_commit=source_commit,
        support_total=support_total,
        reality_total=reality_total,
        symbol_count=symbol_count,
    )

if support.get("generated_at_utc") != reality.get("generated_at_utc"):
    fail(
        "support_reality_timestamp_mismatch",
        "support_matrix and reality_report generated_at_utc differ",
        source_commit=source_commit,
        support_generated_at=support.get("generated_at_utc"),
        reality_generated_at=reality.get("generated_at_utc"),
    )

checks = {
    "contract_schema_valid": "pass",
    "paired_artifacts_present": "pass",
    "artifact_sha256s_current": "pass",
    "reality_report_matches_harness_generation": "pass",
    "support_reality_counts_match": "pass",
    "regeneration_mode_refreshes_paired_hashes": "pass" if mode == "regenerate" else "not_applicable",
    "single_artifact_write_modes_rejected": "pass",
}
summary = {
    "source_commit": source_commit,
    "support_matrix_sha256": support_sha,
    "reality_report_sha256": reality_sha,
    "total_exported": support_total,
    "generated_at_utc": support.get("generated_at_utc"),
    "counts": support_counts,
    "generator_command": " ".join(generator_cmd),
}
report = {
    "schema_version": "support_reality_regeneration.report.v1",
    "bead": "bd-0agsk.3",
    "trace_id": trace_id,
    "source_commit": source_commit,
    "mode": mode,
    "outcome": "pass",
    "failure_signature": None,
    "contract": str(contract_path),
    "support_matrix": str(support_path),
    "reality_report": str(reality_path),
    "canonical_command": contract.get("canonical_command"),
    "generator_versions": contract.get("generator_versions"),
    "input_artifacts": contract.get("input_artifacts"),
    "output_hashes": expected_hashes,
    "checks": checks,
    "summary": summary,
    "regeneration_command": contract.get("regeneration_command"),
}
finish(report, "support_reality_regeneration_validated")
print(f"PASS: support/reality regeneration contract validated trace_id={trace_id}")
PY
