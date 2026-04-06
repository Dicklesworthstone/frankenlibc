#!/usr/bin/env bash
# check_signal_native.sh — native signal + live storm evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
BEAD_ID="${BEAD_ID:-bd-2gjs.5}"
ARTIFACT_BASENAME="${ARTIFACT_BASENAME:-signal_native}"
LOG_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.log.jsonl"
REPORT_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.report.json"
TEST_OUTPUT_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.test_output.log"
RCH_CARGO_HOME="${RCH_CARGO_HOME:-/tmp/${ARTIFACT_BASENAME}_cargo_home}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-/tmp/${ARTIFACT_BASENAME}_target}"
mkdir -p "${OUT_DIR}"
declare -A TEST_OUTCOMES=()
declare -A TEST_ERRNOS=()
OVERALL_STATUS="pass"

NOW_ISO_MS() {
  date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

decision_path_for_test() {
  case "$1" in
    signal_delivery_is_deferred_inside_critical_section)
      printf '%s' "signal->critical_section->defer_or_immediate"
      ;;
    signal_delivery_remains_immediate_for_safe_classification)
      printf '%s' "signal->safe_critical_section->immediate"
      ;;
    pthread_kill_delivers_sigusr1_without_allocator_pressure)
      printf '%s' "signal->pthread_kill->baseline_handler_dispatch"
      ;;
    sigaction_query_preserves_user_handler_and_restorer_metadata)
      printf '%s' "signal->rt_sigaction->query_rewrite_and_restorer_metadata"
      ;;
    pthread_sigqueue_preserves_siginfo_and_ucontext_after_deferred_replay)
      printf '%s' "signal->pthread_sigqueue->deferred_siginfo_replay"
      ;;
    malloc_storm_prewarm_prevents_lazy_host_allocator_resolution_during_live_signal_delivery)
      printf '%s' "signal->pthread_kill->malloc_storm->prewarmed_allocator"
      ;;
    *)
      printf '%s' "signal->unknown"
      ;;
  esac
}

healing_action_for_test() {
  case "$1" in
    signal_delivery_is_deferred_inside_critical_section)
      printf '%s' "deferred_signal_delivery"
      ;;
    pthread_sigqueue_preserves_siginfo_and_ucontext_after_deferred_replay)
      printf '%s' "deferred_signal_delivery_with_siginfo_snapshot"
      ;;
    signal_delivery_remains_immediate_for_safe_classification|pthread_kill_delivers_sigusr1_without_allocator_pressure|malloc_storm_prewarm_prevents_lazy_host_allocator_resolution_during_live_signal_delivery)
      printf '%s' "None"
      ;;
    *)
      printf '%s' "None"
      ;;
  esac
}

expected_for_test() {
  case "$1" in
    signal_delivery_is_deferred_inside_critical_section)
      printf '%s' "PASS; deferred handler stays queued until the critical section exits, then flushes exactly once."
      ;;
    signal_delivery_remains_immediate_for_safe_classification)
      printf '%s' "PASS; safe classifications dispatch immediately without deferral."
      ;;
    pthread_kill_delivers_sigusr1_without_allocator_pressure)
      printf '%s' "PASS; kernel-delivered pthread_kill invokes the installed SIGUSR1 handler exactly once without allocator pressure."
      ;;
    sigaction_query_preserves_user_handler_and_restorer_metadata)
      printf '%s' "PASS; querying SIGUSR1 rewrites the trampoline back to the user handler while preserving x86_64 restorer metadata."
      ;;
    pthread_sigqueue_preserves_siginfo_and_ucontext_after_deferred_replay)
      printf '%s' "PASS; deferred pthread_sigqueue replay preserves non-null siginfo and ucontext snapshots, SI_QUEUE metadata, and the queued payload value."
      ;;
    malloc_storm_prewarm_prevents_lazy_host_allocator_resolution_during_live_signal_delivery)
      printf '%s' "PASS; no deadlock, worker completes 20k malloc/free iterations, deferred deliveries fully flush, handler accounting matches immediate+flushed deliveries, and allocator resolution fallback counters remain zero after prewarm."
      ;;
    *)
      printf '%s' "PASS"
      ;;
  esac
}

failure_signature_for_test() {
  case "$1" in
    signal_delivery_is_deferred_inside_critical_section)
      printf '%s' "SIGUSR1 should stay deferred until the critical section exits"
      ;;
    signal_delivery_remains_immediate_for_safe_classification)
      printf '%s' "safe classifications should dispatch immediately"
      ;;
    pthread_kill_delivers_sigusr1_without_allocator_pressure)
      printf '%s' "real pthread_kill delivery should invoke the installed SIGUSR1 handler exactly once"
      ;;
    sigaction_query_preserves_user_handler_and_restorer_metadata)
      printf '%s' "query path must rewrite the trampoline back to the user handler"
      ;;
    pthread_sigqueue_preserves_siginfo_and_ucontext_after_deferred_replay)
      printf '%s' "queued delivery should preserve the original sigqueue payload value"
      ;;
    malloc_storm_prewarm_prevents_lazy_host_allocator_resolution_during_live_signal_delivery)
      printf '%s' "allocator path must not re-enter raw host fallback after prewarm"
      ;;
    *)
      printf '%s' "test failure"
      ;;
  esac
}

run_test() {
  local mode="$1"
  local test_name="$2"
  local start_ns end_ns latency_ns output outcome errno_value decision_path healing_action cmd_status
  decision_path="$(decision_path_for_test "${test_name}")"
  healing_action="$(healing_action_for_test "${test_name}")"
  start_ns="$(date +%s%N)"
  if output="$(
    FRANKENLIBC_MODE="${mode}" \
    rch exec -- env CARGO_HOME="${RCH_CARGO_HOME}" CARGO_TARGET_DIR="${RCH_TARGET_DIR}" \
      cargo test -p frankenlibc-abi --test signal_abi_test "${test_name}" \
      -- --exact --nocapture --test-threads=1 2>&1
  )"; then
    cmd_status=0
    outcome="pass"
    errno_value=0
  else
    cmd_status=$?
    outcome="fail"
    errno_value=$cmd_status
    OVERALL_STATUS="fail"
  fi
  end_ns="$(date +%s%N)"
  latency_ns="$((end_ns - start_ns))"
  printf '=== %s ===\n%s\n\n' "${mode}" "${output}" >> "${TEST_OUTPUT_PATH}"
  TEST_OUTCOMES["${mode}::${test_name}"]="${outcome}"
  TEST_ERRNOS["${mode}::${test_name}"]="${errno_value}"
  printf '{"timestamp":"%s","trace_id":"%s::signal_native::%s::%s","level":"info","event":"signal_native","bead_id":"%s","mode":"%s","api_family":"signal","symbol":"%s","decision_path":"%s","healing_action":"%s","outcome":"%s","errno":%s,"latency_ns":%s,"artifact_refs":["scripts/check_signal_native.sh","crates/frankenlibc-abi/src/signal_abi.rs","crates/frankenlibc-abi/src/malloc_abi.rs","crates/frankenlibc-abi/tests/signal_abi_test.rs","target/conformance/%s.report.json","target/conformance/%s.log.jsonl","target/conformance/%s.test_output.log"]}\n' \
    "$(NOW_ISO_MS)" "${BEAD_ID}" "${mode}" "${test_name}" "${BEAD_ID}" "${mode}" "${test_name}" "${decision_path}" "${healing_action}" "${outcome}" "${errno_value}" "${latency_ns}" "${ARTIFACT_BASENAME}" "${ARTIFACT_BASENAME}" "${ARTIFACT_BASENAME}" >> "${LOG_PATH}"
  return "${cmd_status}"
}

: > "${LOG_PATH}"
: > "${TEST_OUTPUT_PATH}"

TEST_NAMES=(
  signal_delivery_is_deferred_inside_critical_section
  signal_delivery_remains_immediate_for_safe_classification
  pthread_kill_delivers_sigusr1_without_allocator_pressure
  sigaction_query_preserves_user_handler_and_restorer_metadata
  pthread_sigqueue_preserves_siginfo_and_ucontext_after_deferred_replay
  malloc_storm_prewarm_prevents_lazy_host_allocator_resolution_during_live_signal_delivery
)

for mode in strict hardened; do
  for test_name in "${TEST_NAMES[@]}"; do
    if ! run_test "${mode}" "${test_name}"; then
      :
    fi
  done
done

{
  printf '{\n'
  printf '  "schema_version": "v1",\n'
  printf '  "bead_id": "%s",\n' "${BEAD_ID}"
  printf '  "gate": "check_signal_native",\n'
  printf '  "artifact_basename": "%s",\n' "${ARTIFACT_BASENAME}"
  printf '  "status": "%s",\n' "${OVERALL_STATUS}"
  printf '  "tests": [\n'
  first_entry=1
  for mode in strict hardened; do
    for test_name in "${TEST_NAMES[@]}"; do
      if [[ "${first_entry}" -eq 0 ]]; then
        printf ',\n'
      fi
      printf '    {\n'
      printf '      "mode": "%s",\n' "${mode}"
      printf '      "command": "FRANKENLIBC_MODE=%s rch exec -- env CARGO_HOME=%s CARGO_TARGET_DIR=%s cargo test -p frankenlibc-abi --test signal_abi_test %s -- --exact --nocapture --test-threads=1",\n' \
        "${mode}" "${RCH_CARGO_HOME}" "${RCH_TARGET_DIR}" "${test_name}"
      printf '      "status": "%s",\n' "${TEST_OUTCOMES["${mode}::${test_name}"]:-unknown}"
      printf '      "errno": %s,\n' "${TEST_ERRNOS["${mode}::${test_name}"]:-0}"
      printf '      "expected": "%s",\n' "$(expected_for_test "${test_name}")"
      printf '      "failure_signature": "%s"\n' "$(failure_signature_for_test "${test_name}")"
      printf '    }'
      first_entry=0
    done
  done
  printf '\n  ],\n'
  printf '  "artifacts": [\n'
  printf '    "target/conformance/%s.report.json",\n' "${ARTIFACT_BASENAME}"
  printf '    "target/conformance/%s.log.jsonl",\n' "${ARTIFACT_BASENAME}"
  printf '    "target/conformance/%s.test_output.log"\n' "${ARTIFACT_BASENAME}"
  printf '  ]\n'
  printf '}\n'
} > "${REPORT_PATH}"

if [[ "${OVERALL_STATUS}" == "pass" ]]; then
  echo "${ARTIFACT_BASENAME}: PASS"
else
  echo "${ARTIFACT_BASENAME}: FAIL"
fi
echo "report=${REPORT_PATH}"
[[ "${OVERALL_STATUS}" == "pass" ]]
