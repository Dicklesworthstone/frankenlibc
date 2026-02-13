#!/usr/bin/env bash
# check_bd1f35_thread_stress.sh — CI/evidence gate for bd-1f35
#
# Validates deterministic strict+hardened pthread thread-stress artifacts:
# - tests/cve_arena/results/bd-1f35/trace.jsonl
# - tests/cve_arena/results/bd-1f35/artifact_index.json
# - tests/cve_arena/results/bd-1f35/report.json
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${ROOT}/scripts/bd1f35_thread_stress_run.sh"
OUT_DIR="${ROOT}/tests/cve_arena/results/bd-1f35"
TRACE="${OUT_DIR}/trace.jsonl"
INDEX="${OUT_DIR}/artifact_index.json"
REPORT="${OUT_DIR}/report.json"
SPEC="${ROOT}/tests/conformance/pthread_thread_stress_scenarios.v1.json"
TRACE_ID="bd-1f35-$(date -u +%Y%m%dT%H%M%SZ)-$$"

if [[ ! -x "${RUNNER}" ]]; then
  echo "FAIL: missing executable runner ${RUNNER}" >&2
  exit 1
fi
if [[ ! -f "${SPEC}" ]]; then
  echo "FAIL: missing scenario spec ${SPEC}" >&2
  exit 1
fi

"${RUNNER}"

for f in "${TRACE}" "${INDEX}" "${REPORT}" "${SPEC}"; do
  if [[ ! -f "${f}" ]]; then
    echo "FAIL: missing artifact ${f}" >&2
    exit 1
  fi
done

python3 - "${TRACE}" "${INDEX}" "${REPORT}" "${SPEC}" <<'PY'
import json
import pathlib
import sys

trace_path = pathlib.Path(sys.argv[1])
index_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
spec_path = pathlib.Path(sys.argv[4])
root = trace_path.parents[4]

spec = json.loads(spec_path.read_text(encoding="utf-8"))
required_scenarios = {
    row.get("id")
    for row in spec.get("scenarios", [])
    if isinstance(row, dict) and isinstance(row.get("id"), str)
}
if len(required_scenarios) < 4:
    raise SystemExit("FAIL: scenario spec must declare at least 4 scenarios")

required_log_fields = {"timestamp", "trace_id", "level", "event", "scenario_id", "mode", "op_counts", "failure_marker", "artifact_refs"}
seen_modes = set()
seen_scenarios = set()
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
            mode = row.get("mode")
            if mode not in {"strict", "hardened"}:
                raise SystemExit(f"FAIL: trace line {i} invalid mode {mode!r}")
            seen_modes.add(mode)

            scenario_id = row.get("scenario_id")
            if not isinstance(scenario_id, str) or not scenario_id:
                raise SystemExit(f"FAIL: trace line {i} missing scenario_id")
            seen_scenarios.add(scenario_id)

            op_counts = row.get("op_counts")
            if not isinstance(op_counts, dict):
                raise SystemExit(f"FAIL: trace line {i} op_counts must be object")
            for key in ("create", "join", "detach"):
                if key not in op_counts:
                    raise SystemExit(f"FAIL: trace line {i} op_counts missing {key!r}")

            refs = row.get("artifact_refs")
            if not isinstance(refs, list) or not refs:
                raise SystemExit(f"FAIL: trace line {i} artifact_refs must be non-empty array")

if seen_modes != {"strict", "hardened"}:
    raise SystemExit(f"FAIL: expected strict+hardened results, saw {sorted(seen_modes)}")
if result_events < 8:
    raise SystemExit(f"FAIL: expected at least 8 test_result events, saw {result_events}")

missing_scenarios = sorted(required_scenarios - seen_scenarios)
if missing_scenarios:
    raise SystemExit(f"FAIL: missing scenario results for {missing_scenarios}")

idx = json.loads(index_path.read_text(encoding="utf-8"))
for key in ("index_version", "run_id", "bead_id", "generated_utc", "artifacts"):
    if key not in idx:
        raise SystemExit(f"FAIL: artifact index missing key {key!r}")
if idx.get("index_version") != 1:
    raise SystemExit(f"FAIL: artifact index version must be 1, got {idx.get('index_version')!r}")
if idx.get("bead_id") != "bd-1f35":
    raise SystemExit(f"FAIL: artifact index bead_id must be bd-1f35, got {idx.get('bead_id')!r}")
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

report = json.loads(report_path.read_text(encoding="utf-8"))
if report.get("schema_version") != "v1":
    raise SystemExit(f"FAIL: report schema_version must be v1, got {report.get('schema_version')!r}")
if report.get("bead") != "bd-1f35":
    raise SystemExit(f"FAIL: report bead must be bd-1f35, got {report.get('bead')!r}")
summary = report.get("summary", {})
if int(summary.get("total_cases", 0)) < 8:
    raise SystemExit(f"FAIL: report total_cases too small: {summary.get('total_cases')!r}")
if int(summary.get("fail_count", 1)) != 0:
    raise SystemExit(f"FAIL: report fail_count must be 0, got {summary.get('fail_count')!r}")

replay_controls = report.get("replay_controls", {})
for key in ("fanout_iters", "detach_join_iters"):
    if int(replay_controls.get(key, 0)) <= 0:
        raise SystemExit(f"FAIL: replay_controls.{key} must be > 0")

profiles = report.get("mode_profiles", {})
for mode in ("strict", "hardened"):
    p = profiles.get(mode)
    if not isinstance(p, dict):
        raise SystemExit(f"FAIL: missing mode profile for {mode}")
    if int(p.get("observed_fail", 1)) != 0:
        raise SystemExit(f"FAIL: {mode} observed_fail must be 0, got {p.get('observed_fail')!r}")

print(
    "PASS: bd-1f35 thread stress artifacts valid "
    f"(result_events={result_events}, scenarios={len(seen_scenarios)}, artifacts={len(arts)})"
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
    "api_family": "pthread",
    "symbol": "pthread_create|pthread_join|pthread_detach",
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
