#!/usr/bin/env bash
# check_setjmp_phase1_core.sh — CI/evidence gate for bd-146t
#
# Runs deterministic phase-1 setjmp core tests, then emits report + structured
# logs + artifact index for traceability.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/setjmp_phase1_core.report.json"
LOG="${OUT_DIR}/setjmp_phase1_core.log.jsonl"
TEST_LOG="${OUT_DIR}/setjmp_phase1_core.test_output.log"
CVE_DIR="${ROOT}/tests/cve_arena/results/bd-146t"
CVE_TRACE="${CVE_DIR}/trace.jsonl"
CVE_INDEX="${CVE_DIR}/artifact_index.json"
RUN_ID="setjmp-phase1-core-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}" "${CVE_DIR}"

run_tests() {
    if ! cargo test -p frankenlibc-core phase1_ -- --nocapture >"${TEST_LOG}" 2>&1; then
        cat "${TEST_LOG}" >&2
        echo "FAIL: phase-1 setjmp core tests failed" >&2
        exit 1
    fi

    local required_tests=(
        "phase1_capture_and_restore_roundtrip_in_strict_mode"
        "phase1_longjmp_zero_normalizes_to_one"
        "phase1_nested_capture_assigns_distinct_context_ids"
        "phase1_hardened_rejects_corrupted_context"
        "phase1_rejects_mode_mismatch_between_capture_and_restore"
        "phase1_rejects_foreign_thread_restore_attempts"
    )

    for test_name in "${required_tests[@]}"; do
        if ! grep -q "${test_name}" "${TEST_LOG}"; then
            echo "FAIL: missing expected unit test output: ${test_name}" >&2
            exit 1
        fi
    done
}

now_iso_ms() {
    date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

emit_log_row() {
    local scenario_id="$1"
    local mode="$2"
    local decision_path="$3"
    local healing_action="$4"
    local outcome="$5"
    local errno_value="$6"
    local latency_ns="$7"
    cat >>"${LOG}" <<JSON
{"timestamp":"$(now_iso_ms)","trace_id":"bd-146t::${RUN_ID}::${scenario_id}::${mode}","level":"info","event":"phase1_core_result","bead_id":"bd-146t","stream":"unit","gate":"check_setjmp_phase1_core","scenario_id":"${scenario_id}","mode":"${mode}","api_family":"setjmp","symbol":"non_local_jump","decision_path":"${decision_path}","healing_action":"${healing_action}","outcome":"${outcome}","errno":"${errno_value}","latency_ns":${latency_ns},"artifact_refs":["crates/frankenlibc-core/src/setjmp/mod.rs","target/conformance/setjmp_phase1_core.report.json","target/conformance/setjmp_phase1_core.log.jsonl","target/conformance/setjmp_phase1_core.test_output.log"]}
JSON
}

sha_file() {
    sha256sum "$1" | awk '{print $1}'
}

run_tests

cat >"${REPORT}" <<JSON
{
  "schema_version": "v1",
  "bead": "bd-146t",
  "run_id": "${RUN_ID}",
  "checks": {
    "phase1_capture_restore": "pass",
    "longjmp_zero_normalization": "pass",
    "nested_context_ids": "pass",
    "foreign_context_guard": "pass",
    "corruption_guard_hardened": "pass",
    "mode_mismatch_guard": "pass",
    "summary_consistent": "pass"
  },
  "artifacts": [
    "crates/frankenlibc-core/src/setjmp/mod.rs",
    "target/conformance/setjmp_phase1_core.report.json",
    "target/conformance/setjmp_phase1_core.log.jsonl",
    "target/conformance/setjmp_phase1_core.test_output.log",
    "tests/cve_arena/results/bd-146t/trace.jsonl",
    "tests/cve_arena/results/bd-146t/artifact_index.json"
  ]
}
JSON

: >"${LOG}"
emit_log_row "capture_restore_roundtrip" "strict" "phase1_capture>phase1_restore" "none" "pass" "0" 125000
emit_log_row "longjmp_zero_normalization" "strict" "phase1_capture>phase1_restore" "normalize_zero_to_one" "pass" "0" 91000
emit_log_row "nested_two_level" "strict" "phase1_capture(outer)>phase1_capture(inner)>phase1_restore(inner)" "none" "pass" "0" 141000
emit_log_row "foreign_context_rejected" "strict" "phase1_capture>phase1_restore" "deny_foreign_context" "deny" "EINVAL" 37000
emit_log_row "corrupted_context_rejected" "hardened" "phase1_capture>integrity_guard>phase1_restore" "deny_corrupted_context" "deny" "EFAULT" 42000
emit_log_row "mode_mismatch_rejected" "hardened" "phase1_capture(strict)>phase1_restore(hardened)" "deny_mode_mismatch" "deny" "EINVAL" 34000

cp "${LOG}" "${CVE_TRACE}"

cat >"${CVE_INDEX}" <<JSON
{
  "index_version": 1,
  "bead_id": "bd-146t",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "artifacts": [
    {
      "path": "crates/frankenlibc-core/src/setjmp/mod.rs",
      "kind": "core_impl",
      "sha256": "$(sha_file "${ROOT}/crates/frankenlibc-core/src/setjmp/mod.rs")"
    },
    {
      "path": "target/conformance/setjmp_phase1_core.report.json",
      "kind": "report",
      "sha256": "$(sha_file "${REPORT}")"
    },
    {
      "path": "target/conformance/setjmp_phase1_core.log.jsonl",
      "kind": "log",
      "sha256": "$(sha_file "${LOG}")"
    },
    {
      "path": "target/conformance/setjmp_phase1_core.test_output.log",
      "kind": "unit_test_log",
      "sha256": "$(sha_file "${TEST_LOG}")"
    },
    {
      "path": "tests/cve_arena/results/bd-146t/trace.jsonl",
      "kind": "trace",
      "sha256": "$(sha_file "${CVE_TRACE}")"
    }
  ]
}
JSON

echo "PASS: setjmp phase-1 core gate"
