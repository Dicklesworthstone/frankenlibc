#!/usr/bin/env bash
# check_runtime_math_cohomology_cross_family.sh — CI/evidence gate for bd-w2c3.5.2
#
# Validates cohomology cross-family (StringMemory <-> Resolver) stage-outcome
# overlap consistency and replayable anomaly detection in strict+hardened mode.
#
# Emits:
# - target/conformance/runtime_math_cohomology_cross_family.report.json
# - target/conformance/runtime_math_cohomology_cross_family.log.jsonl
# - target/conformance/runtime_math_cohomology_cross_family.test_output.log
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${OUT_DIR}/runtime_math_cohomology_cross_family.report.json"
LOG_PATH="${OUT_DIR}/runtime_math_cohomology_cross_family.log.jsonl"
TEST_LOG_PATH="${OUT_DIR}/runtime_math_cohomology_cross_family.test_output.log"
RUN_ID="cohomology-cross-family-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}"
: >"${LOG_PATH}"
: >"${TEST_LOG_PATH}"

run_case() {
    local case_id="$1"
    local mode="$2"
    local test_name="$3"
    local decision_path="$4"
    local healing_action="$5"
    local symbol="$6"

    local cmd="cargo test -p frankenlibc-abi ${test_name} -- --nocapture"
    local start_ns
    local end_ns
    local latency_ns
    start_ns="$(date +%s%N)"
    if bash -lc "${cmd}" >>"${TEST_LOG_PATH}" 2>&1; then
        end_ns="$(date +%s%N)"
        latency_ns="$((end_ns - start_ns))"
        cat >>"${LOG_PATH}" <<JSON
{"timestamp":"$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")","trace_id":"bd-w2c3.5.2::${RUN_ID}::${case_id}","level":"info","event":"runtime_math_cohomology_cross_family","bead_id":"bd-w2c3.5.2","mode":"${mode}","api_family":"runtime_math","symbol":"${symbol}","decision_path":"${decision_path}","healing_action":"${healing_action}","outcome":"pass","errno":0,"latency_ns":${latency_ns},"artifact_refs":["crates/frankenlibc-abi/src/runtime_policy.rs","crates/frankenlibc-membrane/src/runtime_math/mod.rs","target/conformance/runtime_math_cohomology_cross_family.report.json","target/conformance/runtime_math_cohomology_cross_family.log.jsonl","target/conformance/runtime_math_cohomology_cross_family.test_output.log"]}
JSON
        return 0
    fi

    end_ns="$(date +%s%N)"
    latency_ns="$((end_ns - start_ns))"
    cat >>"${LOG_PATH}" <<JSON
{"timestamp":"$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")","trace_id":"bd-w2c3.5.2::${RUN_ID}::${case_id}","level":"error","event":"runtime_math_cohomology_cross_family","bead_id":"bd-w2c3.5.2","mode":"${mode}","api_family":"runtime_math","symbol":"${symbol}","decision_path":"${decision_path}","healing_action":"${healing_action}","outcome":"fail","errno":1,"latency_ns":${latency_ns},"artifact_refs":["crates/frankenlibc-abi/src/runtime_policy.rs","crates/frankenlibc-membrane/src/runtime_math/mod.rs","target/conformance/runtime_math_cohomology_cross_family.report.json","target/conformance/runtime_math_cohomology_cross_family.log.jsonl","target/conformance/runtime_math_cohomology_cross_family.test_output.log"]}
JSON
    return 1
}

failures=()

run_case \
    "strict_consistency" \
    "strict" \
    "runtime_policy::tests::cross_family_overlap_tracks_string_resolver_consistently" \
    "stage_ordering->compact_stage_hash->note_overlap" \
    "None" \
    "string_resolver_overlap_consistency" || failures+=("strict_consistency")

run_case \
    "strict_replay_corruption" \
    "strict" \
    "runtime_policy::tests::cohomology_overlap_replay_detects_corrupted_witness" \
    "stage_ordering->compact_stage_hash->corrupt_witness->consistency_fault" \
    "None" \
    "string_resolver_overlap_replay" || failures+=("strict_replay_corruption")

run_case \
    "hardened_consistency" \
    "hardened" \
    "runtime_policy::tests::cross_family_overlap_tracks_string_resolver_consistently_hardened" \
    "stage_ordering->compact_stage_hash->note_overlap" \
    "None" \
    "string_resolver_overlap_consistency" || failures+=("hardened_consistency")

run_case \
    "hardened_replay_corruption" \
    "hardened" \
    "runtime_policy::tests::cohomology_overlap_replay_detects_corrupted_witness_hardened" \
    "stage_ordering->compact_stage_hash->corrupt_witness->consistency_fault" \
    "None" \
    "string_resolver_overlap_replay" || failures+=("hardened_replay_corruption")

strict_total=2
hardened_total=2
strict_fail=0
hardened_fail=0
strict_cross_family_consistency_status="pass"
strict_corruption_replay_detection_status="pass"
hardened_cross_family_consistency_status="pass"
hardened_corruption_replay_detection_status="pass"

for id in "${failures[@]}"; do
    if [[ "${id}" == strict_* ]]; then
        strict_fail=$((strict_fail + 1))
    elif [[ "${id}" == hardened_* ]]; then
        hardened_fail=$((hardened_fail + 1))
    fi
    case "${id}" in
        strict_consistency) strict_cross_family_consistency_status="fail" ;;
        strict_replay_corruption) strict_corruption_replay_detection_status="fail" ;;
        hardened_consistency) hardened_cross_family_consistency_status="fail" ;;
        hardened_replay_corruption) hardened_corruption_replay_detection_status="fail" ;;
    esac
done

failures_json=""
if [[ ${#failures[@]} -gt 0 ]]; then
    for i in "${!failures[@]}"; do
        if [[ "$i" -gt 0 ]]; then
            failures_json+=$',\n'
        fi
        failures_json+="      \"${failures[$i]}\""
    done
fi

cat >"${REPORT_PATH}" <<JSON
{
  "schema_version": "v1",
  "bead": "bd-w2c3.5.2",
  "run_id": "${RUN_ID}",
  "checks": {
    "strict_cross_family_consistency": "${strict_cross_family_consistency_status}",
    "strict_corruption_replay_detection": "${strict_corruption_replay_detection_status}",
    "hardened_cross_family_consistency": "${hardened_cross_family_consistency_status}",
    "hardened_corruption_replay_detection": "${hardened_corruption_replay_detection_status}"
  },
  "summary": {
    "total_checks": 4,
    "failed_checks": ${#failures[@]},
    "strict": {
      "total": ${strict_total},
      "failed": ${strict_fail},
      "passed": $((strict_total - strict_fail))
    },
    "hardened": {
      "total": ${hardened_total},
      "failed": ${hardened_fail},
      "passed": $((hardened_total - hardened_fail))
    },
    "failures": [
${failures_json}
    ]
  },
  "expected_thresholds": {
    "strict_failures_max": 0,
    "hardened_failures_max": 0
  },
  "artifacts": [
    "crates/frankenlibc-abi/src/runtime_policy.rs",
    "crates/frankenlibc-membrane/src/runtime_math/mod.rs",
    "target/conformance/runtime_math_cohomology_cross_family.report.json",
    "target/conformance/runtime_math_cohomology_cross_family.log.jsonl",
    "target/conformance/runtime_math_cohomology_cross_family.test_output.log"
  ]
}
JSON

if [[ ${#failures[@]} -gt 0 ]]; then
    echo "FAIL: runtime-math cohomology cross-family gate failed"
    for id in "${failures[@]}"; do
        echo "  - ${id}"
    done
    exit 1
fi

echo "PASS: runtime-math cohomology cross-family gate"
echo "- ${REPORT_PATH}"
echo "- ${LOG_PATH}"
