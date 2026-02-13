#!/usr/bin/env bash
set -euo pipefail

# bd1f35_thread_stress_run.sh
# Deterministic strict+hardened pthread create/join/detach stress harness for bd-1f35.
# Emits:
# - tests/cve_arena/results/bd-1f35/trace.jsonl
# - tests/cve_arena/results/bd-1f35/artifact_index.json
# - tests/cve_arena/results/bd-1f35/report.json

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIO_SPEC="${ROOT}/tests/conformance/pthread_thread_stress_scenarios.v1.json"
OUT_DIR="${ROOT}/tests/cve_arena/results/bd-1f35"
LOG_FILE="${OUT_DIR}/trace.jsonl"
INDEX_FILE="${OUT_DIR}/artifact_index.json"
REPORT_FILE="${OUT_DIR}/report.json"
BIN_DIR="${OUT_DIR}/bin"
RUN_ID="${FLC_BD1F35_RUN_ID:-bd1f35-thread-stress-v1}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
STRESS_SEED="${FRANKENLIBC_THREAD_STRESS_SEED:-4242}"
FANOUT_ITERS="${FLC_BD1F35_FANOUT_ITERS:-3}"
DETACH_JOIN_ITERS="${FLC_BD1F35_DETACH_JOIN_ITERS:-3}"
THREAD_STRESS_TARGET_DIR="${FLC_BD1F35_CARGO_TARGET_DIR:-/data/tmp/cargo-target-bd1f35}"

if ! command -v jq >/dev/null 2>&1; then
  echo "FAIL: jq is required" >&2
  exit 2
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "FAIL: cargo is required" >&2
  exit 2
fi
if ! command -v cc >/dev/null 2>&1; then
  echo "FAIL: cc is required" >&2
  exit 2
fi
if [[ ! -f "${SCENARIO_SPEC}" ]]; then
  echo "FAIL: missing scenario spec ${SCENARIO_SPEC}" >&2
  exit 2
fi

LIB_CANDIDATES=(
  "${THREAD_STRESS_TARGET_DIR}/release/libfrankenlibc_abi.so"
  "${ROOT}/target/release/libfrankenlibc_abi.so"
  "${ROOT}/target/debug/libfrankenlibc_abi.so"
  "/data/tmp/cargo-target/release/libfrankenlibc_abi.so"
)

LIB_PATH=""
for candidate in "${LIB_CANDIDATES[@]}"; do
  if [[ -f "${candidate}" ]]; then
    LIB_PATH="${candidate}"
    break
  fi
done

if [[ -z "${LIB_PATH}" ]]; then
  CARGO_TARGET_DIR="${THREAD_STRESS_TARGET_DIR}" cargo build -p frankenlibc-abi --release >/dev/null
  for candidate in "${LIB_CANDIDATES[@]}"; do
    if [[ -f "${candidate}" ]]; then
      LIB_PATH="${candidate}"
      break
    fi
  done
fi

if [[ -z "${LIB_PATH}" ]]; then
  echo "FAIL: could not locate libfrankenlibc_abi.so" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}" "${BIN_DIR}"
: > "${LOG_FILE}"

# Prime pthread lifecycle test binary outside per-case timeouts.
CARGO_TARGET_DIR="${THREAD_STRESS_TARGET_DIR}" \
  cargo test -p frankenlibc-abi --test pthread_thread_lifecycle_test --no-run >/dev/null

SEQ=0
TOTAL_CASES=0
PASS_COUNT=0
FAIL_COUNT=0
STRICT_PASS=0
STRICT_FAIL=0
HARDENED_PASS=0
HARDENED_FAIL=0
SCENARIO_ROWS='[]'

now_iso_utc() {
  date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

emit_log() {
  local level="$1"
  local event="$2"
  local mode="$3"
  local scenario_id="$4"
  local outcome="$5"
  local errno_val="$6"
  local latency_ns="$7"
  local op_counts_json="$8"
  local failure_marker="$9"
  local details_json="${10}"
  local refs_json="${11}"

  SEQ=$((SEQ + 1))
  local trace_id
  trace_id="bd-1f35::${RUN_ID}::$(printf '%03d' "${SEQ}")"

  jq -nc \
    --arg timestamp "$(now_iso_utc)" \
    --arg trace_id "${trace_id}" \
    --arg level "${level}" \
    --arg event "${event}" \
    --arg bead_id "bd-1f35" \
    --arg stream "e2e" \
    --arg gate "bd1f35_thread_stress" \
    --arg mode "${mode}" \
    --arg api_family "pthread" \
    --arg scenario_id "${scenario_id}" \
    --arg outcome "${outcome}" \
    --arg failure_marker "${failure_marker}" \
    --argjson errno "${errno_val}" \
    --argjson latency_ns "${latency_ns}" \
    --argjson op_counts "${op_counts_json}" \
    --argjson details "${details_json}" \
    --argjson artifact_refs "${refs_json}" \
    '{
      timestamp: $timestamp,
      trace_id: $trace_id,
      level: $level,
      event: $event,
      bead_id: $bead_id,
      stream: $stream,
      gate: $gate,
      mode: $mode,
      api_family: $api_family,
      scenario_id: $scenario_id,
      outcome: $outcome,
      errno: $errno,
      latency_ns: $latency_ns,
      op_counts: $op_counts,
      failure_marker: $failure_marker,
      details: $details,
      artifact_refs: $artifact_refs
    }' >> "${LOG_FILE}"
}

run_case() {
  local mode="$1"
  local scenario_id="$2"
  local cmd="$3"
  local expected_exit="$4"
  local use_preload="$5"
  local op_counts_json="$6"

  local case_dir="${OUT_DIR}/${mode}/${scenario_id}"
  local stdout_file="${case_dir}/stdout.txt"
  local stderr_file="${case_dir}/stderr.txt"
  mkdir -p "${case_dir}"

  TOTAL_CASES=$((TOTAL_CASES + 1))

  local start_details
  start_details="$(jq -nc \
    --arg command "${cmd}" \
    --arg cwd "${ROOT}" \
    --arg seed "${STRESS_SEED}" \
    --arg cargo_target_dir "${THREAD_STRESS_TARGET_DIR}" \
    --argjson expected_exit "${expected_exit}" \
    --argjson timeout_seconds "${TIMEOUT_SECONDS}" \
    '{command:$command,cwd:$cwd,seed:$seed,cargo_target_dir:$cargo_target_dir,expected_exit:$expected_exit,timeout_seconds:$timeout_seconds}')"
  emit_log "info" "test_start" "${mode}" "${scenario_id}" "running" 0 0 "${op_counts_json}" "none" "${start_details}" '[]'

  local start_ns
  start_ns="$(date +%s%N)"

  set +e
  if [[ "${use_preload}" == "1" ]]; then
    (
      cd "${ROOT}"
      timeout "${TIMEOUT_SECONDS}" env CARGO_TARGET_DIR="${THREAD_STRESS_TARGET_DIR}" FRANKENLIBC_MODE="${mode}" FRANKENLIBC_THREAD_STRESS_SEED="${STRESS_SEED}" LD_PRELOAD="${LIB_PATH}" bash -lc "${cmd}"
    ) >"${stdout_file}" 2>"${stderr_file}"
  else
    (
      cd "${ROOT}"
      timeout "${TIMEOUT_SECONDS}" env CARGO_TARGET_DIR="${THREAD_STRESS_TARGET_DIR}" FRANKENLIBC_MODE="${mode}" FRANKENLIBC_THREAD_STRESS_SEED="${STRESS_SEED}" bash -lc "${cmd}"
    ) >"${stdout_file}" 2>"${stderr_file}"
  fi
  local rc=$?
  set -e

  local end_ns
  end_ns="$(date +%s%N)"
  local elapsed_ns=$((end_ns - start_ns))

  local outcome="pass"
  local level="info"
  local failure_marker="none"
  if [[ ${rc} -ne ${expected_exit} ]]; then
    outcome="fail"
    level="error"
    failure_marker="exit_code_mismatch"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    if [[ "${mode}" == "strict" ]]; then
      STRICT_FAIL=$((STRICT_FAIL + 1))
    else
      HARDENED_FAIL=$((HARDENED_FAIL + 1))
    fi
  else
    PASS_COUNT=$((PASS_COUNT + 1))
    if [[ "${mode}" == "strict" ]]; then
      STRICT_PASS=$((STRICT_PASS + 1))
    else
      HARDENED_PASS=$((HARDENED_PASS + 1))
    fi
  fi

  local refs_json
  refs_json="$(jq -nc --arg a "${stdout_file#${ROOT}/}" --arg b "${stderr_file#${ROOT}/}" '[$a,$b]')"
  local result_details
  result_details="$(jq -nc \
    --arg command "${cmd}" \
    --arg seed "${STRESS_SEED}" \
    --arg cargo_target_dir "${THREAD_STRESS_TARGET_DIR}" \
    --argjson expected_exit "${expected_exit}" \
    --argjson actual_exit "${rc}" \
    --argjson fanout_iters "${FANOUT_ITERS}" \
    --argjson detach_join_iters "${DETACH_JOIN_ITERS}" \
    '{command:$command,seed:$seed,cargo_target_dir:$cargo_target_dir,expected_exit:$expected_exit,actual_exit:$actual_exit,fanout_iters:$fanout_iters,detach_join_iters:$detach_join_iters}')"
  emit_log "${level}" "test_result" "${mode}" "${scenario_id}" "${outcome}" "${rc}" "${elapsed_ns}" "${op_counts_json}" "${failure_marker}" "${result_details}" "${refs_json}"

  local row
  row="$(jq -nc \
    --arg mode "${mode}" \
    --arg scenario_id "${scenario_id}" \
    --arg result "${outcome}" \
    --arg failure_marker "${failure_marker}" \
    --argjson expected_exit "${expected_exit}" \
    --argjson actual_exit "${rc}" \
    --argjson errno "${rc}" \
    --argjson timing_ns "${elapsed_ns}" \
    --argjson op_counts "${op_counts_json}" \
    --arg stdout_path "${stdout_file#${ROOT}/}" \
    --arg stderr_path "${stderr_file#${ROOT}/}" \
    '{mode:$mode,scenario_id:$scenario_id,result:$result,failure_marker:$failure_marker,expected_exit:$expected_exit,actual_exit:$actual_exit,errno:$errno,timing_ns:$timing_ns,op_counts:$op_counts,artifact_refs:[$stdout_path,$stderr_path]}')"
  SCENARIO_ROWS="$(jq -nc --argjson arr "${SCENARIO_ROWS}" --argjson item "${row}" '$arr + [$item]')"
}

FIXTURE_SRC="${ROOT}/tests/integration/fixture_pthread.c"
FIXTURE_BIN="${BIN_DIR}/fixture_pthread"
cc -O2 -Wall -Wextra "${FIXTURE_SRC}" -o "${FIXTURE_BIN}" -pthread

fanout_single_cmd="cargo test -p frankenlibc-abi --test pthread_thread_lifecycle_test pthread_equal_reflexive_and_distinct_threads_not_equal -- --exact --nocapture --test-threads=1"
create_join_churn_cmd="for i in \$(seq 1 ${FANOUT_ITERS}); do cargo test -p frankenlibc-abi --test pthread_thread_lifecycle_test pthread_equal_reflexive_and_distinct_threads_not_equal -- --exact --nocapture --test-threads=1 >/dev/null; done"
mixed_detach_join_cmd="for i in \$(seq 1 ${DETACH_JOIN_ITERS}); do cargo test -p frankenlibc-abi --test pthread_thread_lifecycle_test pthread_detach_makes_subsequent_join_fail_with_esrch -- --exact --nocapture --test-threads=1 >/dev/null; done"

for mode in strict hardened; do
  run_case "${mode}" "fanout_fanin_single" "${fanout_single_cmd}" 0 0 '{"create":1,"join":1,"detach":0}'
  run_case "${mode}" "create_join_churn" "${create_join_churn_cmd}" 0 0 "$(jq -nc --argjson n "${FANOUT_ITERS}" '{create:$n,join:$n,detach:0}')"
  run_case "${mode}" "mixed_detach_join" "${mixed_detach_join_cmd}" 101 0 "$(jq -nc --argjson n "${DETACH_JOIN_ITERS}" '{create:$n,join:$n,detach:$n}')"
  run_case "${mode}" "c_fixture_pthread_common_adversarial" "${FIXTURE_BIN}" 1 0 '{"create":4,"join":4,"detach":0}'
done

report_payload="$(jq -nc \
  --arg schema_version "v1" \
  --arg bead "bd-1f35" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso_utc)" \
  --arg seed "${STRESS_SEED}" \
  --arg cargo_target_dir "${THREAD_STRESS_TARGET_DIR}" \
  --arg trace_log "${LOG_FILE#${ROOT}/}" \
  --arg artifact_index "${INDEX_FILE#${ROOT}/}" \
  --arg scenario_spec "${SCENARIO_SPEC#${ROOT}/}" \
  --argjson fanout_iters "${FANOUT_ITERS}" \
  --argjson detach_join_iters "${DETACH_JOIN_ITERS}" \
  --argjson total_cases "${TOTAL_CASES}" \
  --argjson pass_count "${PASS_COUNT}" \
  --argjson fail_count "${FAIL_COUNT}" \
  --argjson strict_pass "${STRICT_PASS}" \
  --argjson strict_fail "${STRICT_FAIL}" \
  --argjson hardened_pass "${HARDENED_PASS}" \
  --argjson hardened_fail "${HARDENED_FAIL}" \
  --argjson scenarios "${SCENARIO_ROWS}" \
  '{
    schema_version: $schema_version,
    bead: $bead,
    run_id: $run_id,
    generated_at: $generated_at,
    seed: $seed,
    cargo_target_dir: $cargo_target_dir,
    replay_controls: {
      fanout_iters: $fanout_iters,
      detach_join_iters: $detach_join_iters
    },
    summary: {
      total_cases: $total_cases,
      pass_count: $pass_count,
      fail_count: $fail_count
    },
    mode_profiles: {
      strict: { expected_pass: 4, observed_pass: $strict_pass, observed_fail: $strict_fail },
      hardened: { expected_pass: 4, observed_pass: $hardened_pass, observed_fail: $hardened_fail }
    },
    scenarios: $scenarios,
    artifacts: {
      trace_jsonl: $trace_log,
      artifact_index_json: $artifact_index,
      scenario_spec: $scenario_spec
    }
  }')"
printf '%s\n' "${report_payload}" > "${REPORT_FILE}"

artifacts='[]'
artifact_paths_json="$(
  jq -nc \
    --arg log "${LOG_FILE#${ROOT}/}" \
    --arg report "${REPORT_FILE#${ROOT}/}" \
    --arg spec "${SCENARIO_SPEC#${ROOT}/}" \
    --arg bin "${FIXTURE_BIN#${ROOT}/}" \
    --argjson scenarios "${SCENARIO_ROWS}" \
    '([$log, $report, $spec, $bin] + ($scenarios | map(.artifact_refs[]) )) | unique'
)"
while IFS= read -r rel; do
  [[ -z "${rel}" ]] && continue
  file="${ROOT}/${rel}"
  [[ ! -f "${file}" ]] && continue

  kind="report"
  if [[ "${rel}" == *"trace.jsonl" ]]; then
    kind="log"
  fi

  sha="$(sha256sum "${file}" | awk '{print $1}')"
  size="$(wc -c < "${file}")"
  item="$(jq -nc \
    --arg path "${rel}" \
    --arg kind "${kind}" \
    --arg sha256 "${sha}" \
    --arg description "bd-1f35 pthread stress artifact" \
    --argjson size_bytes "${size}" \
    '{path:$path,kind:$kind,sha256:$sha256,size_bytes:$size_bytes,description:$description}')"
  artifacts="$(jq -nc --argjson arr "${artifacts}" --argjson item "${item}" '$arr + [$item]')"
done < <(jq -r '.[]' <<<"${artifact_paths_json}")

jq -n \
  --argjson index_version 1 \
  --arg run_id "${RUN_ID}" \
  --arg bead_id "bd-1f35" \
  --arg generated_utc "$(now_iso_utc)" \
  --argjson artifacts "${artifacts}" \
  '{
    index_version: $index_version,
    run_id: $run_id,
    bead_id: $bead_id,
    generated_utc: $generated_utc,
    artifacts: $artifacts
  }' > "${INDEX_FILE}"

summary_details="$(jq -nc --argjson pass "${PASS_COUNT}" --argjson fail "${FAIL_COUNT}" '{pass:$pass,fail:$fail}')"
emit_log "info" "run_summary" "strict+hardened" "bd1f35_thread_stress_run" "$( [[ ${FAIL_COUNT} -eq 0 ]] && echo pass || echo fail )" "${FAIL_COUNT}" 0 '{"create":0,"join":0,"detach":0}' "$( [[ ${FAIL_COUNT} -eq 0 ]] && echo "none" || echo "case_failure" )" "${summary_details}" "$(jq -nc --arg a "${INDEX_FILE#${ROOT}/}" --arg b "${LOG_FILE#${ROOT}/}" --arg c "${REPORT_FILE#${ROOT}/}" '[$a,$b,$c]')"

cat <<MSG
bd-1f35 pthread stress run complete
run_id: ${RUN_ID}
seed: ${STRESS_SEED}
log: ${LOG_FILE}
index: ${INDEX_FILE}
report: ${REPORT_FILE}
passes: ${PASS_COUNT}
fails: ${FAIL_COUNT}
MSG

if [[ ${FAIL_COUNT} -ne 0 ]]; then
  exit 1
fi
