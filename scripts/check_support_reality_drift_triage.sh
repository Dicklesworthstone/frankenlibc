#!/usr/bin/env bash
# Validate per-symbol support/reality/version-script drift triage.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRIAGE="${SUPPORT_REALITY_DRIFT_TRIAGE_REPORT:-${ROOT}/tests/conformance/support_reality_drift_triage.v1.json}"
SUPPORT_MATRIX="${SUPPORT_REALITY_SUPPORT_MATRIX:-${ROOT}/support_matrix.json}"
REALITY_REPORT="${SUPPORT_REALITY_REPORT:-${ROOT}/tests/conformance/reality_report.v1.json}"
VERSION_SCRIPT="${SUPPORT_REALITY_VERSION_SCRIPT:-${ROOT}/crates/frankenlibc-abi/version_scripts/libc.map}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/support_reality_drift_triage.report.json"
LOG="${OUT_DIR}/support_reality_drift_triage.log.jsonl"
TRACE_ID="bd-0agsk.4::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"
MODE="${1:---validate-only}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${TRIAGE}" "${SUPPORT_MATRIX}" "${REALITY_REPORT}" "${VERSION_SCRIPT}" "${REPORT}" "${LOG}" "${TRACE_ID}" "${MODE}" <<'PY'
import json
import pathlib
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict

root = pathlib.Path(sys.argv[1])
triage_path = pathlib.Path(sys.argv[2])
support_path = pathlib.Path(sys.argv[3])
reality_path = pathlib.Path(sys.argv[4])
version_script_path = pathlib.Path(sys.argv[5])
report_path = pathlib.Path(sys.argv[6])
log_path = pathlib.Path(sys.argv[7])
trace_id = sys.argv[8]
mode = sys.argv[9]
start_ns = time.time_ns()


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def finish(report, event_name: str) -> None:
    report["duration_ms"] = (time.time_ns() - start_ns) // 1_000_000
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    event = {
        "timestamp": now_utc(),
        "trace_id": trace_id,
        "level": "error" if report.get("outcome") == "fail" else "info",
        "event": event_name,
        "bead_id": "bd-0agsk.4",
        "source_commit": report.get("source_commit"),
        "outcome": report.get("outcome"),
        "failure_signature": report.get("failure_signature"),
        "artifact_refs": [
            str(triage_path),
            str(support_path),
            str(reality_path),
            str(version_script_path),
            str(report_path),
        ],
        "duration_ms": report.get("duration_ms"),
        "details": report.get("summary", {}),
    }
    log_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")


def fail(signature: str, message: str, **extra) -> None:
    report = {
        "schema_version": "support_reality_drift_triage.report.v1",
        "bead": "bd-0agsk.4",
        "trace_id": trace_id,
        "source_commit": extra.pop("source_commit", None),
        "mode": mode,
        "outcome": "fail",
        "failure_signature": signature,
        "failure_message": message,
        "summary": extra,
    }
    finish(report, "support_reality_drift_triage_failed")
    raise SystemExit(f"FAIL[{signature}]: {message}")


def parse_version_exports(path: pathlib.Path) -> set[str]:
    exports = set()
    in_global = False
    symbol_re = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*;")
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("/*") or line.startswith("*"):
            continue
        if line.startswith("global:"):
            in_global = True
            continue
        if line.startswith("local:"):
            in_global = False
            continue
        if not in_global:
            continue
        match = symbol_re.match(line)
        if match:
            exports.add(match.group(1))
    return exports


if mode != "--validate-only":
    fail("unsupported_mode", f"only --validate-only is supported; got {mode}")

for path in [triage_path, support_path, reality_path, version_script_path]:
    if not path.is_file():
        fail("required_file_missing", f"required file missing: {path}")

source_commit = git_head()
triage = load_json(triage_path)
support = load_json(support_path)
reality = load_json(reality_path)

if triage.get("schema_version") != "support_reality_drift_triage.v1":
    fail("schema_version", "schema_version must be support_reality_drift_triage.v1", source_commit=source_commit)
if triage.get("generated_by_bead") != "bd-0agsk.4":
    fail("bead_id", "generated_by_bead must be bd-0agsk.4", source_commit=source_commit)
if triage.get("claim_status") != "triage_report_only":
    fail("claim_status", "claim_status must be triage_report_only", source_commit=source_commit)

allowed = set(triage.get("classification_policy", {}).get("allowed_classifications", []))
required_allowed = {
    "taxonomy_mismatch",
    "missing_fixture",
    "missing_export",
    "stale_evidence",
    "expected_unsupported_surface",
}
if allowed != required_allowed:
    fail("classification_policy", "allowed_classifications drift", source_commit=source_commit)

support_rows = support.get("symbols", [])
support_by_symbol = {str(row.get("symbol")): row for row in support_rows if row.get("symbol")}
support_symbols = set(support_by_symbol)
version_exports = parse_version_exports(version_script_path)

support_missing_exports = sorted(support_symbols - version_exports)
version_exports_missing_support = sorted(version_exports - support_symbols)

support_counts = Counter(str(row.get("status")) for row in support_rows)
reality_counts = reality.get("counts", {})
normalized_support_counts = {
    "implemented": support_counts["Implemented"],
    "raw_syscall": support_counts["RawSyscall"],
    "wraps_host_libc": support_counts["WrapsHostLibc"],
    "glibc_call_through": support_counts["GlibcCallThrough"],
    "stub": support_counts["Stub"],
}
normalized_reality_counts = {key: int(value) for key, value in reality_counts.items()}
taxonomy_mismatch_count = 0 if normalized_support_counts == normalized_reality_counts else 1

guard_report_path = root / "target/conformance/replacement_guard.report.json"
guard = subprocess.run(
    ["bash", str(root / "scripts/check_replacement_guard.sh"), "interpose"],
    cwd=root,
    text=True,
    capture_output=True,
    check=False,
)
if guard.returncode != 0:
    fail(
        "replacement_guard_failed",
        "replacement guard failed in interpose mode",
        source_commit=source_commit,
        stderr=guard.stderr[-4000:],
    )
guard_report = load_json(guard_report_path)
if guard_report.get("ok") is not True:
    fail("replacement_guard_not_ok", "replacement guard report ok must be true", source_commit=source_commit)

bucket_rows = triage.get("delta_buckets")
if not isinstance(bucket_rows, list):
    fail("delta_buckets_missing", "delta_buckets must be an array", source_commit=source_commit)

seen = {}
classification_counts = Counter()
for bucket in bucket_rows:
    classification = str(bucket.get("classification", ""))
    if classification == "unclassified" or classification not in allowed:
        fail(
            "unclassified_delta",
            f"bucket {bucket.get('id')} has invalid classification {classification}",
            source_commit=source_commit,
            bucket_id=bucket.get("id"),
            classification=classification,
        )
    if not bucket.get("owner_family"):
        fail("missing_owner_family", f"bucket {bucket.get('id')} missing owner_family", source_commit=source_commit)
    if not bucket.get("first_evidence_command"):
        fail(
            "missing_first_evidence_command",
            f"bucket {bucket.get('id')} missing first_evidence_command",
            source_commit=source_commit,
        )
    delta_kind = str(bucket.get("delta_kind", ""))
    symbols = bucket.get("symbols")
    if not isinstance(symbols, list):
        fail("bucket_symbols_missing", f"bucket {bucket.get('id')} symbols must be an array", source_commit=source_commit)
    for symbol in symbols:
        key = (delta_kind, str(symbol))
        if key in seen:
            fail("duplicate_delta_symbol", f"duplicate delta {key}", source_commit=source_commit)
        seen[key] = bucket
        classification_counts[classification] += 1

for symbol in support_missing_exports:
    key = ("support_symbol_missing_version_export", symbol)
    bucket = seen.get(key)
    if bucket is None:
        fail("delta_symbol_missing", f"missing triage row for {key}", source_commit=source_commit, symbol=symbol)
    if bucket.get("classification") != "missing_export":
        fail("delta_symbol_misclassified", f"{symbol} must be missing_export", source_commit=source_commit, symbol=symbol)

for symbol in version_exports_missing_support:
    key = ("version_export_not_in_support_matrix", symbol)
    bucket = seen.get(key)
    if bucket is None:
        fail("delta_symbol_missing", f"missing triage row for {key}", source_commit=source_commit, symbol=symbol)
    if bucket.get("classification") != "expected_unsupported_surface":
        fail(
            "delta_symbol_misclassified",
            f"{symbol} must be expected_unsupported_surface",
            source_commit=source_commit,
            symbol=symbol,
        )

accepted = triage.get("accepted_expected_unsupported_rows", [])
if not any(row.get("classification") == "expected_unsupported_surface" for row in accepted if isinstance(row, dict)):
    fail("expected_unsupported_example_missing", "expected unsupported example row missing", source_commit=source_commit)

summary = triage.get("summary", {})
expected_summary = {
    "support_symbol_count": len(support_symbols),
    "reality_total_exported": int(reality.get("total_exported", -1)),
    "version_script_export_count": len(version_exports),
    "delta_symbol_count": len(support_missing_exports) + len(version_exports_missing_support) + taxonomy_mismatch_count,
    "missing_export_count": len(support_missing_exports),
    "expected_unsupported_surface_count": len(version_exports_missing_support),
    "taxonomy_mismatch_count": taxonomy_mismatch_count,
    "replacement_guard_total_call_throughs": int(guard_report.get("total_call_throughs", -1)),
}
for key, expected in expected_summary.items():
    if int(summary.get(key, -1)) != expected:
        fail(
            "summary_count_mismatch",
            f"summary.{key} expected {expected} got {summary.get(key)}",
            source_commit=source_commit,
            summary_key=key,
        )
if summary.get("replacement_guard_ok") is not True:
    fail("replacement_guard_summary_not_ok", "summary replacement_guard_ok must be true", source_commit=source_commit)

checks = {
    "schema_valid": "pass",
    "support_reality_counts_consistent": "pass",
    "version_script_deltas_classified": "pass",
    "expected_unsupported_surface_accepted": "pass",
    "replacement_guard_ok": "pass",
    "unclassified_deltas_rejected": "pass",
}
report = {
    "schema_version": "support_reality_drift_triage.report.v1",
    "bead": "bd-0agsk.4",
    "trace_id": trace_id,
    "source_commit": source_commit,
    "mode": mode,
    "outcome": "pass",
    "failure_signature": None,
    "checks": checks,
    "summary": {
        **expected_summary,
        "classification_counts": dict(sorted(classification_counts.items())),
        "replacement_guard_mode": guard_report.get("mode"),
        "replacement_guard_ok": guard_report.get("ok"),
    },
}
finish(report, "support_reality_drift_triage_validated")
print(f"PASS: support/reality drift triage validated deltas={expected_summary['delta_symbol_count']} trace_id={trace_id}")
PY
