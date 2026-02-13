#!/usr/bin/env bash
# check_hard_parts_e2e.sh — cross-boundary hard-parts E2E catalog + classification gate (bd-2mwc)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="${ROOT}/tests/conformance/hard_parts_e2e_catalog.v1.json"
CLASS_MATRIX="${ROOT}/tests/conformance/hard_parts_e2e_failure_matrix.v1.json"
TRUTH_TABLE="${ROOT}/tests/conformance/hard_parts_truth_table.v1.json"
DEP_MATRIX="${ROOT}/tests/conformance/hard_parts_dependency_matrix.v1.json"
MANIFEST="${ROOT}/tests/conformance/e2e_scenario_manifest.v1.json"
VALIDATOR="${ROOT}/scripts/validate_e2e_manifest.py"
E2E_SCRIPT="${ROOT}/scripts/e2e_suite.sh"

TRACE_ID="bd-2mwc-$(date -u +%Y%m%dT%H%M%SZ)-$$"
START_NS="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"

for path in "$CATALOG" "$CLASS_MATRIX" "$TRUTH_TABLE" "$DEP_MATRIX" "$MANIFEST" "$VALIDATOR" "$E2E_SCRIPT"; do
    if [[ ! -f "$path" ]]; then
        echo "FAIL: required file missing: $path" >&2
        exit 1
    fi
done

python3 - "$CATALOG" "$CLASS_MATRIX" "$TRUTH_TABLE" "$DEP_MATRIX" "$MANIFEST" <<'PY'
import json
import sys
from pathlib import Path

catalog_path = Path(sys.argv[1])
matrix_path = Path(sys.argv[2])
truth_path = Path(sys.argv[3])
deps_path = Path(sys.argv[4])
manifest_path = Path(sys.argv[5])

catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
truth = json.loads(truth_path.read_text(encoding="utf-8"))
deps = json.loads(deps_path.read_text(encoding="utf-8"))
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

errors: list[str] = []

required_subsystems = {"startup", "threading", "resolver", "nss", "locale", "iconv"}

if catalog.get("schema_version") != "v1":
    errors.append("catalog schema_version must be v1")
if catalog.get("bead") != "bd-2mwc":
    errors.append("catalog bead must be bd-2mwc")

if matrix.get("schema_version") != "v1":
    errors.append("classification matrix schema_version must be v1")
if matrix.get("bead") != "bd-2mwc":
    errors.append("classification matrix bead must be bd-2mwc")

truth_rows = truth.get("subsystems", [])
truth_subsystems = {row.get("id") for row in truth_rows if isinstance(row, dict)}
missing_truth = sorted(required_subsystems - truth_subsystems)
if missing_truth:
    errors.append(f"truth table missing required subsystem rows: {missing_truth}")

dep_rows = deps.get("dependency_matrix", [])
dep_edges = {
    (str(row.get("from_subsystem")), str(row.get("to_subsystem")))
    for row in dep_rows
    if isinstance(row, dict)
}

manifest_ids = {
    row.get("id")
    for row in manifest.get("scenarios", [])
    if isinstance(row, dict) and isinstance(row.get("id"), str)
}

classes = matrix.get("classes", [])
class_ids = {row.get("id") for row in classes if isinstance(row, dict)}
required_classes = {
    "match",
    "deterministic_failure",
    "mode_pair_mismatch",
    "incomplete_pair",
    "quarantined_flake",
}
missing_classes = sorted(required_classes - class_ids)
if missing_classes:
    errors.append(f"classification matrix missing required classes: {missing_classes}")

catalog_scenarios = catalog.get("scenarios", [])
if not isinstance(catalog_scenarios, list) or not catalog_scenarios:
    errors.append("catalog scenarios must be a non-empty array")

covered_subsystems: set[str] = set()
for idx, scenario in enumerate(catalog_scenarios):
    ctx = f"catalog.scenarios[{idx}]"
    if not isinstance(scenario, dict):
        errors.append(f"{ctx}: must be object")
        continue

    sid = scenario.get("id")
    title = scenario.get("title")
    if not isinstance(sid, str) or not sid.strip():
        errors.append(f"{ctx}: id must be non-empty string")
    if not isinstance(title, str) or not title.strip():
        errors.append(f"{ctx}: title must be non-empty string")

    subsystems = scenario.get("subsystems")
    if not isinstance(subsystems, list) or len(subsystems) < 2:
        errors.append(f"{ctx}: subsystems must include at least 2 entries")
        subsystems = []
    for subsystem in subsystems:
        if subsystem not in required_subsystems:
            errors.append(f"{ctx}: unknown subsystem '{subsystem}'")
        else:
            covered_subsystems.add(subsystem)

    edges = scenario.get("dependency_edges")
    if not isinstance(edges, list) or not edges:
        errors.append(f"{ctx}: dependency_edges must be non-empty array")
    else:
        for edge_idx, edge in enumerate(edges):
            ectx = f"{ctx}.dependency_edges[{edge_idx}]"
            if not isinstance(edge, dict):
                errors.append(f"{ectx}: must be object")
                continue
            pair = (str(edge.get("from")), str(edge.get("to")))
            if pair not in dep_edges:
                errors.append(f"{ectx}: edge {pair!r} not present in hard_parts_dependency_matrix")

    bindings = scenario.get("e2e_bindings")
    if not isinstance(bindings, list) or not bindings:
        errors.append(f"{ctx}: e2e_bindings must be non-empty array")
    else:
        for binding in bindings:
            if binding not in manifest_ids:
                errors.append(f"{ctx}: e2e binding '{binding}' not found in base manifest")

    failure_classes = scenario.get("failure_classes")
    if not isinstance(failure_classes, list) or not failure_classes:
        errors.append(f"{ctx}: failure_classes must be non-empty array")
    else:
        for cls in failure_classes:
            if cls not in class_ids:
                errors.append(f"{ctx}: failure_class '{cls}' not declared in matrix")

catalog_summary = catalog.get("summary", {})
if catalog_summary.get("scenario_count") != len(catalog_scenarios):
    errors.append("catalog summary.scenario_count must equal scenarios length")

missing_coverage = sorted(required_subsystems - covered_subsystems)
if missing_coverage:
    errors.append(f"catalog does not cover required subsystems: {missing_coverage}")

if errors:
    print("FAIL: hard-parts e2e catalog validation failed")
    for err in errors:
        print(f"  - {err}")
    raise SystemExit(1)

print(
    "PASS: hard-parts e2e catalog + classification matrix validated "
    f"(scenarios={len(catalog_scenarios)}, classes={len(class_ids)})"
)
PY

SEED="${FRANKENLIBC_HARD_PARTS_E2E_SEED:-62021}"
TIMEOUT_SECONDS_VALUE="${FRANKENLIBC_HARD_PARTS_E2E_TIMEOUT_SECONDS:-1}"
SCENARIO_CLASS="${FRANKENLIBC_HARD_PARTS_E2E_SCENARIO_CLASS:-smoke}"
RETRY_MAX="${FRANKENLIBC_HARD_PARTS_E2E_RETRY_MAX:-0}"
STRESS_ITERS="${FRANKENLIBC_HARD_PARTS_E2E_STRESS_ITERS:-1}"
STABILITY_ITERS="${FRANKENLIBC_HARD_PARTS_E2E_STABILITY_ITERS:-1}"

python3 "${VALIDATOR}" validate --manifest "${MANIFEST}" >/dev/null

FRANKENLIBC_E2E_MANIFEST="${MANIFEST}" \
FRANKENLIBC_E2E_SEED="${SEED}" \
TIMEOUT_SECONDS="${TIMEOUT_SECONDS_VALUE}" \
bash "${E2E_SCRIPT}" --dry-run-manifest "${SCENARIO_CLASS}" strict >/dev/null

set +e
FRANKENLIBC_E2E_MANIFEST="${MANIFEST}" \
FRANKENLIBC_E2E_SEED="${SEED}" \
TIMEOUT_SECONDS="${TIMEOUT_SECONDS_VALUE}" \
FRANKENLIBC_E2E_RETRY_MAX="${RETRY_MAX}" \
FRANKENLIBC_E2E_STRESS_ITERS="${STRESS_ITERS}" \
FRANKENLIBC_E2E_STABILITY_ITERS="${STABILITY_ITERS}" \
bash "${E2E_SCRIPT}" "${SCENARIO_CLASS}" >/dev/null
SUITE_RC=$?
set -e

RUN_DIR="$(ls -1dt "${ROOT}"/target/e2e_suite/e2e-v*-s"${SEED}" 2>/dev/null | head -n 1 || true)"
if [[ -z "${RUN_DIR}" ]]; then
    echo "FAIL: unable to locate e2e run directory for seed ${SEED}" >&2
    exit 1
fi

PAIR_REPORT="${RUN_DIR}/mode_pair_report.json"
QUARANTINE_REPORT="${RUN_DIR}/flake_quarantine_report.json"
PACK_REPORT="${RUN_DIR}/scenario_pack_report.json"
ARTIFACT_INDEX="${RUN_DIR}/artifact_index.json"
TRACE_JSONL="${RUN_DIR}/trace.jsonl"
CLASS_REPORT="${RUN_DIR}/hard_parts_failure_classification.json"

for path in "$PAIR_REPORT" "$QUARANTINE_REPORT" "$PACK_REPORT" "$ARTIFACT_INDEX" "$TRACE_JSONL"; do
    if [[ ! -f "$path" ]]; then
        echo "FAIL: expected run artifact missing: $path" >&2
        exit 1
    fi
done

python3 - "$CATALOG" "$CLASS_MATRIX" "$PAIR_REPORT" "$QUARANTINE_REPORT" "$PACK_REPORT" "$ARTIFACT_INDEX" "$CLASS_REPORT" "$TRACE_ID" "$START_NS" "$SUITE_RC" "$RUN_DIR" "$SCENARIO_CLASS" <<'PY'
import json
import sys
import time
from collections import Counter
from pathlib import Path

catalog_path = Path(sys.argv[1])
matrix_path = Path(sys.argv[2])
pair_path = Path(sys.argv[3])
quarantine_path = Path(sys.argv[4])
pack_path = Path(sys.argv[5])
index_path = Path(sys.argv[6])
out_path = Path(sys.argv[7])
trace_id = sys.argv[8]
start_ns = int(sys.argv[9])
suite_rc = int(sys.argv[10])
run_dir = Path(sys.argv[11])
scenario_class = sys.argv[12]

catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
pair = json.loads(pair_path.read_text(encoding="utf-8"))
quarantine = json.loads(quarantine_path.read_text(encoding="utf-8"))
pack = json.loads(pack_path.read_text(encoding="utf-8"))
artifact_index = json.loads(index_path.read_text(encoding="utf-8"))

allowed_classes = {row["id"] for row in matrix["classes"]}
pair_by_id = {
    row["scenario_id"]: row
    for row in pair.get("pairs", [])
    if isinstance(row, dict) and isinstance(row.get("scenario_id"), str)
}
quarantined_by_id = {}
for row in quarantine.get("quarantined_cases", []):
    if not isinstance(row, dict):
        continue
    sid = row.get("scenario_id")
    if isinstance(sid, str):
        quarantined_by_id.setdefault(sid, []).append(row)

results = []
counts: Counter[str] = Counter()

for scenario in catalog.get("scenarios", []):
    sid = scenario["id"]
    title = scenario["title"]
    bindings = list(scenario["e2e_bindings"])
    found_pairs = [pair_by_id[b] for b in bindings if b in pair_by_id]
    missing_bindings = [b for b in bindings if b not in pair_by_id]
    quarantined_bindings = [b for b in bindings if b in quarantined_by_id]

    classification = "match"
    reasons: list[str] = []

    if quarantined_bindings:
        classification = "quarantined_flake"
        reasons.append(
            "bound scenarios quarantined: " + ", ".join(sorted(quarantined_bindings))
        )
    elif any(item.get("mode_pair_result") == "mismatch" for item in found_pairs):
        classification = "mode_pair_mismatch"
        reasons.append("mode pair mismatch present in bound scenario set")
    elif missing_bindings or any(item.get("mode_pair_result") == "incomplete" for item in found_pairs):
        classification = "incomplete_pair"
        if missing_bindings:
            reasons.append("missing pair rows: " + ", ".join(sorted(missing_bindings)))
        if any(item.get("mode_pair_result") == "incomplete" for item in found_pairs):
            reasons.append("incomplete strict/hardened coverage in mode_pair_report")
    elif any(
        item.get("strict_outcome") != "pass" or item.get("hardened_outcome") != "pass"
        for item in found_pairs
    ):
        classification = "deterministic_failure"
        reasons.append("non-pass outcome in strict/hardened bound scenario")
    else:
        reasons.append("all bound scenarios passed with matching strict/hardened outcomes")

    if classification not in allowed_classes:
        raise SystemExit(f"unknown classification emitted: {classification}")

    breakdown = []
    for binding in bindings:
        row = pair_by_id.get(binding)
        if row is None:
            breakdown.append(
                {
                    "scenario_id": binding,
                    "mode_pair_result": "missing",
                    "strict_outcome": "missing",
                    "hardened_outcome": "missing",
                    "drift_flags": ["missing_mode_pair_entry"],
                }
            )
            continue
        breakdown.append(
            {
                "scenario_id": binding,
                "mode_pair_result": row.get("mode_pair_result", "unknown"),
                "strict_outcome": row.get("strict_outcome", "missing"),
                "hardened_outcome": row.get("hardened_outcome", "missing"),
                "drift_flags": row.get("drift_flags", []),
            }
        )

    artifact_refs = [
        pair_path.as_posix(),
        quarantine_path.as_posix(),
        pack_path.as_posix(),
        index_path.as_posix(),
        run_dir.joinpath("trace.jsonl").as_posix(),
    ]

    results.append(
        {
            "catalog_scenario_id": sid,
            "scenario_title": title,
            "subsystems": scenario["subsystems"],
            "classification": classification,
            "reason": "; ".join(reasons),
            "bound_e2e_scenarios": bindings,
            "mode_pair_breakdown": breakdown,
            "artifact_refs": artifact_refs,
        }
    )
    counts[classification] += 1

required_fields = set(matrix.get("required_output_fields", []))
for idx, row in enumerate(results):
    missing_fields = sorted(required_fields - set(row.keys()))
    if missing_fields:
        raise SystemExit(
            f"classification row {idx} missing required output fields: {missing_fields}"
        )

payload = {
    "schema_version": "v1",
    "bead": "bd-2mwc",
    "trace_id": trace_id,
    "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "run_id": pair.get("run_id"),
    "seed": pair.get("seed"),
    "scenario_class": scenario_class,
    "suite_exit_code": suite_rc,
    "pair_count": pair.get("pair_count"),
    "pack_report": pack,
    "class_counts": dict(counts),
    "classifications": results,
}
out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

elapsed_ns = time.time_ns() - start_ns
event = {
    "trace_id": trace_id,
    "mode": "strict",
    "api_family": "hard_parts_e2e",
    "symbol": "catalog",
    "decision_path": "allow",
    "healing_action": "none",
    "errno": 0,
    "latency_ns": int(elapsed_ns),
    "artifact_refs": [
        catalog_path.as_posix(),
        matrix_path.as_posix(),
        pair_path.as_posix(),
        quarantine_path.as_posix(),
        pack_path.as_posix(),
        index_path.as_posix(),
        out_path.as_posix(),
    ],
}
print(json.dumps(event, separators=(",", ":")))
print(
    "PASS: hard-parts E2E classification generated "
    f"(suite_rc={suite_rc}, class_counts={dict(counts)})"
)
PY
