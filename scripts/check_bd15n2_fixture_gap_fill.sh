#!/usr/bin/env bash
# check_bd15n2_fixture_gap_fill.sh — CI/evidence gate for bd-15n.2
#
# Validates deterministic strict+hardened fixture gap-fill artifacts:
# - tests/cve_arena/results/bd-15n.2/trace.jsonl
# - tests/cve_arena/results/bd-15n.2/artifact_index.json
# - tests/cve_arena/results/bd-15n.2/report.json
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${ROOT}/scripts/bd15n2_fixture_gap_fill_run.sh"
OUT_DIR="${ROOT}/tests/cve_arena/results/bd-15n.2"
TRACE="${OUT_DIR}/trace.jsonl"
INDEX="${OUT_DIR}/artifact_index.json"
REPORT="${OUT_DIR}/report.json"
TRACE_ID="bd-15n.2-$(date -u +%Y%m%dT%H%M%SZ)-$$"

if [[ ! -x "${RUNNER}" ]]; then
  echo "FAIL: missing executable runner ${RUNNER}" >&2
  exit 1
fi

"${RUNNER}"

for f in "${TRACE}" "${INDEX}" "${REPORT}"; do
  if [[ ! -f "${f}" ]]; then
    echo "FAIL: missing artifact ${f}" >&2
    exit 1
  fi
done

python3 - "${TRACE}" "${INDEX}" "${REPORT}" <<'PY'
import hashlib
import json
import pathlib
import sys

trace_path = pathlib.Path(sys.argv[1])
index_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
root = trace_path.parents[4]

required_log_fields = {"timestamp", "trace_id", "level", "event"}
required_result_fields = {
    "mode",
    "fixture_id",
    "api_family",
    "symbol",
    "spec_ref",
    "outcome",
    "errno",
    "latency_ns",
    "artifact_refs",
    "details",
}
required_fixtures = {"fixture_ctype", "fixture_math", "fixture_socket"}
seen_modes = set()
seen_fixtures = set()
result_events = 0

with trace_path.open("r", encoding="utf-8") as f:
    for i, raw in enumerate(f, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"FAIL: trace line {i} invalid JSON: {exc}")
        missing = required_log_fields - row.keys()
        if missing:
            raise SystemExit(f"FAIL: trace line {i} missing required fields: {sorted(missing)}")
        if row.get("event") == "test_result":
            result_events += 1
            missing_result = required_result_fields - row.keys()
            if missing_result:
                raise SystemExit(
                    f"FAIL: trace line {i} missing result fields: {sorted(missing_result)}"
                )
            mode = row.get("mode")
            if mode not in {"strict", "hardened"}:
                raise SystemExit(f"FAIL: trace line {i} invalid mode {mode!r}")
            seen_modes.add(mode)
            fixture_id = row.get("fixture_id")
            if fixture_id in required_fixtures:
                seen_fixtures.add(fixture_id)
            spec_ref = row.get("spec_ref")
            if not isinstance(spec_ref, str) or not spec_ref.strip():
                raise SystemExit(f"FAIL: trace line {i} missing non-empty spec_ref")
            details = row.get("details", {})
            if "expected_vs_actual" not in details:
                raise SystemExit(f"FAIL: trace line {i} missing details.expected_vs_actual")

if seen_modes != {"strict", "hardened"}:
    raise SystemExit(f"FAIL: expected strict+hardened results, saw {sorted(seen_modes)}")
if seen_fixtures != required_fixtures:
    raise SystemExit(
        f"FAIL: expected fixtures {sorted(required_fixtures)}, saw {sorted(seen_fixtures)}"
    )
if result_events < 6:
    raise SystemExit(f"FAIL: expected at least 6 test_result events, saw {result_events}")

idx = json.loads(index_path.read_text(encoding="utf-8"))
for key in ("index_version", "run_id", "bead_id", "generated_utc", "artifacts"):
    if key not in idx:
        raise SystemExit(f"FAIL: artifact index missing key {key!r}")
if idx.get("index_version") != 1:
    raise SystemExit(f"FAIL: artifact index version must be 1, got {idx.get('index_version')!r}")
if idx.get("bead_id") != "bd-15n.2":
    raise SystemExit(
        f"FAIL: artifact index bead_id must be bd-15n.2, got {idx.get('bead_id')!r}"
    )
arts = idx.get("artifacts", [])
if not isinstance(arts, list) or not arts:
    raise SystemExit("FAIL: artifact index artifacts must be non-empty array")
for item in arts:
    for field in ("path", "kind", "sha256"):
        if field not in item:
            raise SystemExit(f"FAIL: artifact entry missing {field!r}")
    path = root / item["path"]
    if not path.exists():
        raise SystemExit(f"FAIL: artifact path missing on disk: {item['path']}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != item["sha256"]:
        raise SystemExit(
            f"FAIL: artifact sha mismatch for {item['path']}: index={item['sha256']} actual={digest}"
        )

report = json.loads(report_path.read_text(encoding="utf-8"))
if report.get("schema_version") != "v1":
    raise SystemExit(
        f"FAIL: report schema_version must be v1, got {report.get('schema_version')!r}"
    )
if report.get("bead") != "bd-15n.2":
    raise SystemExit(f"FAIL: report bead must be bd-15n.2, got {report.get('bead')!r}")
summary = report.get("summary", {})
if int(summary.get("total_cases", 0)) < 6:
    raise SystemExit(f"FAIL: report total_cases too small: {summary.get('total_cases')!r}")
if int(summary.get("fail_count", 1)) != 0:
    raise SystemExit(
        f"FAIL: report fail_count must be 0, got {summary.get('fail_count')!r}"
    )

profiles = report.get("mode_profiles", {})
for mode in ("strict", "hardened"):
    p = profiles.get(mode)
    if not isinstance(p, dict):
        raise SystemExit(f"FAIL: missing mode profile for {mode}")
    if int(p.get("observed_fail", 1)) != 0:
        raise SystemExit(f"FAIL: {mode} observed_fail must be 0, got {p.get('observed_fail')!r}")

fixtures = report.get("fixtures", [])
if not isinstance(fixtures, list):
    raise SystemExit("FAIL: report fixtures must be an array")
fixture_map = {f.get("id"): f for f in fixtures if isinstance(f, dict)}
for fixture_id in sorted(required_fixtures):
    fixture = fixture_map.get(fixture_id)
    if fixture is None:
        raise SystemExit(f"FAIL: report fixtures missing {fixture_id}")
    traceability = fixture.get("spec_traceability", {})
    for key in ("posix", "c11", "internal"):
        vals = traceability.get(key)
        if not isinstance(vals, list) or not any(isinstance(v, str) and v.strip() for v in vals):
            raise SystemExit(f"FAIL: fixture {fixture_id} missing traceability refs for {key}")
    expectations = fixture.get("mode_expectations", {})
    for mode in ("strict", "hardened"):
        e = expectations.get(mode)
        if not isinstance(e, dict):
            raise SystemExit(f"FAIL: fixture {fixture_id} missing mode_expectations.{mode}")
        if e.get("expected_exit") != 0:
            raise SystemExit(
                f"FAIL: fixture {fixture_id} mode_expectations.{mode}.expected_exit must be 0"
            )

print(
    "PASS: bd-15n.2 fixture gap-fill artifacts valid "
    f"(result_events={result_events}, artifacts={len(arts)})"
)
PY

python3 - "${TRACE_ID}" "${REPORT}" <<'PY'
import json
import sys

trace_id, path = sys.argv[1:3]
report = json.load(open(path, "r", encoding="utf-8"))
summary = report.get("summary", {})
event = {
    "trace_id": trace_id,
    "mode": "strict+hardened",
    "api_family": "ctype|math|socket",
    "symbol": "fixture_gap_fill",
    "decision_path": "allow",
    "healing_action": "none",
    "errno": 0,
    "latency_ns": 0,
    "artifact_refs": [path],
    "cases_total": int(summary.get("total_cases", 0)),
    "cases_fail": int(summary.get("fail_count", 0)),
}
print(json.dumps(event, separators=(",", ":")))
PY
