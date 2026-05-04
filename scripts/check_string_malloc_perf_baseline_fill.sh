#!/usr/bin/env bash
# check_string_malloc_perf_baseline_fill.sh -- bd-b92jd.2.1 gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_STRING_MALLOC_PERF_MANIFEST:-${ROOT}/tests/conformance/string_malloc_perf_baseline_fill.v1.json}"
OUT_DIR="${FLC_STRING_MALLOC_PERF_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FLC_STRING_MALLOC_PERF_REPORT:-${OUT_DIR}/string_malloc_perf_baseline_fill.report.json}"
LOG="${FLC_STRING_MALLOC_PERF_LOG:-${OUT_DIR}/string_malloc_perf_baseline_fill.log.jsonl}"
TARGET_DIR="${FLC_STRING_MALLOC_PERF_TARGET_DIR:-${OUT_DIR}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" "${TARGET_DIR}" <<'PY'
import json
import math
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]
target_dir = sys.argv[6]

BEAD_ID = "bd-b92jd.2.1"
GATE_ID = "string-malloc-perf-baseline-fill-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "benchmark_id",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "threshold_ns_op",
    "regression_pct",
    "source_commit",
    "target_dir",
    "artifact_refs",
    "failure_signature",
]
REQUIRED_MODES = {"strict", "hardened"}
REQUIRED_BENCHMARKS = {
    "string": {
        "memcpy_16",
        "memcpy_64",
        "memcpy_256",
        "memcpy_1024",
        "memcpy_4096",
        "memcpy_65536",
        "strlen_16",
        "strlen_256",
    },
    "malloc": {"alloc_free_cycle", "alloc_burst"},
}
LINE_RE = re.compile(
    r"^(?P<prefix>STRING_BENCH|MALLOC_BENCH) "
    r"mode=(?P<mode>[a-z_]+) "
    r"bench=(?P<bench>[A-Za-z0-9_]+) "
    r"samples=(?P<samples>[0-9]+) "
    r"p50_ns_op=(?P<p50>[0-9]+(?:\.[0-9]+)?) "
    r"p95_ns_op=(?P<p95>[0-9]+(?:\.[0-9]+)?) "
    r"p99_ns_op=(?P<p99>[0-9]+(?:\.[0-9]+)?) "
    r"mean_ns_op=(?P<mean>[0-9]+(?:\.[0-9]+)?) "
    r"throughput_ops_s=(?P<throughput>[0-9]+(?:\.[0-9]+)?)$"
)

errors = []
log_rows = []


def fail(signature, message):
    errors.append({"failure_signature": signature, "message": message})


def rel(path):
    try:
        return Path(path).resolve().relative_to(root).as_posix()
    except Exception:
        return str(path)


def resolve(path_text):
    path = Path(str(path_text))
    return path if path.is_absolute() else root / path


def load_json(path, label):
    try:
        return json.loads(resolve(path).read_text(encoding="utf-8"))
    except Exception as exc:
        fail("missing_source_artifact", f"{label}: cannot read {path}: {exc}")
        return {}


def approx_equal(left, right, tolerance=0.001):
    try:
        return math.isclose(float(left), float(right), rel_tol=0.0, abs_tol=tolerance)
    except Exception:
        return False


def commit_is_current(value):
    return value in {"current", "unknown", source_commit}


def repo_ref(path_text, context, *, must_exist):
    if not isinstance(path_text, str) or not path_text:
        fail("missing_artifact_refs", f"{context}: path must be a non-empty string")
        return None
    path = Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        fail("missing_artifact_refs", f"{context}: path must stay repo-relative: {path_text}")
        return None
    resolved = root / path
    if must_exist and not resolved.exists():
        fail("missing_source_artifact", f"{context}: missing path {path_text}")
    return resolved


def parse_bench_line(line, context):
    match = LINE_RE.match(str(line))
    if not match:
        fail("benchmark_log_parse_error", f"{context}: cannot parse benchmark row")
        return None
    return {
        "prefix": match.group("prefix"),
        "mode": match.group("mode"),
        "bench": match.group("bench"),
        "samples": int(match.group("samples")),
        "p50_ns_op": float(match.group("p50")),
        "p95_ns_op": float(match.group("p95")),
        "p99_ns_op": float(match.group("p99")),
        "mean_ns_op": float(match.group("mean")),
        "throughput_ops_s": float(match.group("throughput")),
    }


manifest = load_json(manifest_path, "manifest")
if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("source_commit") is None:
    fail("missing_source_commit", "manifest.source_commit is required")
elif not commit_is_current(manifest.get("source_commit")):
    fail("stale_source_commit", "manifest.source_commit must be current")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields must match gate log contract")
if set(manifest.get("required_modes", [])) != REQUIRED_MODES:
    fail("missing_required_slot", "required_modes must be strict+hardened")

declared = manifest.get("required_benchmarks", {})
for family, expected in REQUIRED_BENCHMARKS.items():
    if set(declared.get(family, [])) != expected:
        fail("missing_required_slot", f"required_benchmarks.{family} mismatch")

artifacts = manifest.get("artifacts", {})
baseline = load_json(artifacts.get("baseline_file", ""), "baseline")
spec = load_json(artifacts.get("baseline_spec", ""), "baseline_spec")
prevention = load_json(artifacts.get("perf_regression_report", ""), "perf_regression_report")
inventory = load_json(artifacts.get("benchmark_inventory", ""), "benchmark_inventory")

for key, path_text in artifacts.items():
    repo_ref(path_text, f"artifacts.{key}", must_exist=True)

for index, sample in enumerate(manifest.get("benchmark_log_samples", [])):
    parsed = parse_bench_line(sample.get("line", ""), f"benchmark_log_samples[{index}]")
    expected = sample.get("expected", {})
    if parsed:
        if parsed["prefix"] != sample.get("prefix"):
            fail("benchmark_log_parse_error", f"benchmark_log_samples[{index}]: prefix mismatch")
        if parsed["mode"] != expected.get("mode"):
            fail("benchmark_log_parse_error", f"benchmark_log_samples[{index}]: mode mismatch")
        if parsed["bench"] != expected.get("bench"):
            fail("benchmark_log_parse_error", f"benchmark_log_samples[{index}]: bench mismatch")
        if not approx_equal(parsed["p50_ns_op"], expected.get("p50_ns_op")):
            fail("benchmark_log_parse_error", f"benchmark_log_samples[{index}]: p50 mismatch")
if len(manifest.get("benchmark_log_samples", [])) < 2:
    fail("benchmark_log_parse_error", "benchmark_log_samples must cover string and malloc rows")

rows = manifest.get("baseline_rows")
if not isinstance(rows, list) or not rows:
    fail("missing_required_slot", "baseline_rows must be a non-empty array")
    rows = []

seen = set()
family_counts = {"string": 0, "malloc": 0}
mode_counts = {"strict": 0, "hardened": 0}
baseline_p50 = baseline.get("baseline_p50_ns_op", {})
max_regression_pct = float(manifest.get("max_regression_pct", 15.0))
threshold_multiplier = 1.0 + max_regression_pct / 100.0

for index, row in enumerate(rows):
    context = f"baseline_rows[{index}]"
    family = row.get("api_family")
    mode = row.get("runtime_mode")
    bench = row.get("benchmark_id")
    key = (family, mode, bench)
    if family not in REQUIRED_BENCHMARKS:
        fail("missing_required_slot", f"{context}: invalid api_family {family!r}")
        continue
    if mode not in REQUIRED_MODES:
        fail("missing_required_slot", f"{context}: invalid runtime_mode {mode!r}")
        continue
    if bench not in REQUIRED_BENCHMARKS[family]:
        fail("missing_required_slot", f"{context}: unexpected benchmark_id {bench!r}")
        continue
    if key in seen:
        fail("duplicate_baseline_row", f"{context}: duplicate row for {family}/{mode}/{bench}")
    seen.add(key)
    family_counts[family] += 1
    mode_counts[mode] += 1

    if row.get("source_commit") is None:
        fail("missing_source_commit", f"{context}: source_commit is required")
    elif not commit_is_current(row.get("source_commit")):
        fail("stale_source_commit", f"{context}: source_commit must be current")

    artifact_refs = row.get("artifact_refs")
    if not isinstance(artifact_refs, list) or not artifact_refs:
        fail("missing_artifact_refs", f"{context}: artifact_refs must be non-empty")
        artifact_refs = []
    for ref_index, ref in enumerate(artifact_refs):
        must_exist = not str(ref).startswith("target/")
        repo_ref(ref, f"{context}.artifact_refs[{ref_index}]", must_exist=must_exist)

    if not isinstance(row.get("target_dir"), str) or not row.get("target_dir"):
        fail("missing_field", f"{context}: target_dir must be non-empty")

    latency = row.get("latency_ns")
    baseline_value = baseline_p50.get(family, {}).get(mode, {}).get(bench)
    if baseline_value is None:
        fail("missing_required_slot", f"baseline missing {family}/{mode}/{bench}")
    elif not approx_equal(latency, baseline_value):
        fail(
            "baseline_value_mismatch",
            f"{context}: latency {latency} != baseline {baseline_value}",
        )

    threshold = row.get("threshold_ns_op")
    expected_threshold = round(float(latency) * threshold_multiplier, 3) if latency is not None else None
    if threshold is None or not approx_equal(threshold, expected_threshold):
        fail("baseline_threshold_mismatch", f"{context}: threshold must be {expected_threshold}")
    if row.get("regression_pct") != 0.0:
        fail("baseline_value_mismatch", f"{context}: regression_pct must be 0.0")

    log_rows.append(
        {
            "trace_id": f"{GATE_ID}:{family}:{mode}:{bench}",
            "bead_id": BEAD_ID,
            "runtime_mode": mode,
            "replacement_level": "L0",
            "api_family": family,
            "benchmark_id": bench,
            "expected": "baseline_slot_present",
            "actual": "baseline_slot_present" if baseline_value is not None else "missing",
            "errno": 0,
            "decision_path": ["load_manifest", "parse_benchmark_samples", "compare_perf_baseline"],
            "healing_action": "none",
            "latency_ns": latency,
            "threshold_ns_op": threshold,
            "regression_pct": row.get("regression_pct"),
            "source_commit": source_commit,
            "target_dir": row.get("target_dir") or target_dir,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if baseline_value is not None else "missing_required_slot",
        }
    )

for family, benches in REQUIRED_BENCHMARKS.items():
    for mode in REQUIRED_MODES:
        for bench in benches:
            if (family, mode, bench) not in seen:
                fail("missing_required_slot", f"missing baseline row {family}/{mode}/{bench}")
            if baseline_p50.get(family, {}).get(mode, {}).get(bench) is None:
                fail("missing_required_slot", f"missing perf_baseline slot {family}/{mode}/{bench}")

spec_suites = {
    suite.get("id"): suite
    for suite in spec.get("benchmark_suites", {}).get("suites", [])
    if isinstance(suite, dict)
}
for family in REQUIRED_BENCHMARKS:
    suite = spec_suites.get(family)
    if not suite:
        fail("missing_required_slot", f"perf_baseline_spec missing suite {family}")
    elif suite.get("enforced_in_gate") is not False:
        fail("perf_waiver_expanded", f"{family} must stay outside perf_gate.sh for this bead")

baseline_format = spec.get("baseline_format", {})
current_suites = set(baseline_format.get("current_suites_in_baseline", []))
for family in REQUIRED_BENCHMARKS:
    if family not in current_suites:
        fail("missing_required_slot", f"baseline_format.current_suites_in_baseline missing {family}")
planned_suites = set(baseline_format.get("planned_suites", []))
if planned_suites.intersection(REQUIRED_BENCHMARKS):
    fail("missing_required_slot", "string/malloc must not remain planned suites")

summary = prevention.get("summary", {})
if summary.get("baseline_slot_fill_pct") != 100.0:
    fail("stale_perf_report", "perf_regression_prevention baseline_slot_fill_pct must be 100.0")
if summary.get("suites_with_full_baselines") != summary.get("total_suites_in_spec"):
    fail("stale_perf_report", "all perf_baseline_spec suites must have full baselines")
if summary.get("suites_enforced_in_gate") != 2:
    fail("perf_waiver_expanded", "no unrelated perf waiver/gate expansion expected")

coverage = {
    row.get("suite_id"): row
    for row in prevention.get("baseline_coverage", [])
    if isinstance(row, dict)
}
for family in REQUIRED_BENCHMARKS:
    if coverage.get(family, {}).get("coverage_pct") != 100.0:
        fail("stale_perf_report", f"{family} baseline coverage must be 100.0")
    if coverage.get(family, {}).get("baselines_missing"):
        fail("stale_perf_report", f"{family} must not list missing baselines")

inv_families = {
    row.get("family"): row
    for row in inventory.get("families", [])
    if isinstance(row, dict)
}
for family in REQUIRED_BENCHMARKS:
    if inv_families.get(family, {}).get("missing_baseline_slots"):
        fail("stale_benchmark_inventory", f"{family} inventory still has missing baseline slots")
summary_inv = inventory.get("summary", {})
missing_required = set(summary_inv.get("missing_required_baseline_families", []))
if missing_required.intersection(REQUIRED_BENCHMARKS):
    fail("stale_benchmark_inventory", "string/malloc must not remain missing required baseline families")

if len(rows) != 20:
    fail("missing_required_slot", f"expected 20 baseline rows, found {len(rows)}")
if family_counts != {"string": 16, "malloc": 4}:
    fail("missing_required_slot", f"family row counts mismatch: {family_counts}")
if mode_counts != {"strict": 10, "hardened": 10}:
    fail("missing_required_slot", f"mode row counts mismatch: {mode_counts}")

report = {
    "schema_version": "v1",
    "bead_id": BEAD_ID,
    "gate_id": GATE_ID,
    "source_commit": source_commit,
    "target_dir": target_dir,
    "summary": {
        "baseline_row_count": len(rows),
        "string_row_count": family_counts["string"],
        "malloc_row_count": family_counts["malloc"],
        "strict_row_count": mode_counts["strict"],
        "hardened_row_count": mode_counts["hardened"],
        "baseline_slot_fill_pct": summary.get("baseline_slot_fill_pct"),
        "perf_waiver_expanded": any(error["failure_signature"] == "perf_waiver_expanded" for error in errors),
        "error_count": len(errors),
    },
    "errors": errors,
    "baseline_rows": rows,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as handle:
    for row in log_rows:
        handle.write(json.dumps(row, sort_keys=True) + "\n")

if errors:
    for error in errors:
        print(f"FAIL: {error['failure_signature']}: {error['message']}", file=sys.stderr)
    raise SystemExit(1)

print(
    "string_malloc_perf_baseline_fill: PASS "
    f"rows={len(rows)} string={family_counts['string']} malloc={family_counts['malloc']}"
)
PY
