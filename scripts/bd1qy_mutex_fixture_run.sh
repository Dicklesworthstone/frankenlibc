#!/usr/bin/env bash
set -euo pipefail

# bd1qy_mutex_fixture_run.sh
# Deterministic strict+hardened mutex fixture evidence harness for bd-1qy.
# Emits:
# - tests/cve_arena/results/bd-1qy/trace.jsonl
# - tests/cve_arena/results/bd-1qy/artifact_index.json
# - tests/cve_arena/results/bd-1qy/report.json

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/tests/cve_arena/results/bd-1qy"
LOG_FILE="${OUT_DIR}/trace.jsonl"
INDEX_FILE="${OUT_DIR}/artifact_index.json"
REPORT_FILE="${OUT_DIR}/report.json"
BIN_DIR="${OUT_DIR}/bin"
RUN_ID="${FLC_BD1QY_RUN_ID:-bd1qy-fixture-v1}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-90}"

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

LIB_CANDIDATES=(
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
  cargo build -p frankenlibc-abi --release >/dev/null
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
  local symbol="$4"
  local outcome="$5"
  local errno_val="$6"
  local latency_ns="$7"
  local details_json="$8"
  local refs_json="$9"

  SEQ=$((SEQ + 1))
  local trace_id
  trace_id="bd-1qy::${RUN_ID}::$(printf '%03d' "${SEQ}")"

  jq -nc \
    --arg timestamp "$(now_iso_utc)" \
    --arg trace_id "${trace_id}" \
    --arg level "${level}" \
    --arg event "${event}" \
    --arg bead_id "bd-1qy" \
    --arg stream "e2e" \
    --arg gate "bd1qy_mutex_fixture" \
    --arg mode "${mode}" \
    --arg api_family "pthread" \
    --arg symbol "${symbol}" \
    --arg outcome "${outcome}" \
    --argjson errno "${errno_val}" \
    --argjson latency_ns "${latency_ns}" \
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
      symbol: $symbol,
      outcome: $outcome,
      errno: $errno,
      latency_ns: $latency_ns,
      details: $details,
      artifact_refs: $artifact_refs
    }' >> "${LOG_FILE}"
}

run_case() {
  local mode="$1"
  local label="$2"
  local cmd="$3"
  local expected_exit="$4"
  local use_preload="$5"

  local case_dir="${OUT_DIR}/${mode}/${label}"
  local stdout_file="${case_dir}/stdout.txt"
  local stderr_file="${case_dir}/stderr.txt"
  mkdir -p "${case_dir}"

  TOTAL_CASES=$((TOTAL_CASES + 1))

  local start_details
  start_details="$(jq -nc --arg command "${cmd}" --arg cwd "${ROOT}" --argjson expected_exit "${expected_exit}" '{command:$command,cwd:$cwd,expected_exit:$expected_exit}')"
  emit_log "info" "test_start" "${mode}" "${label}" "pass" 0 0 "${start_details}" '[]'

  local start_ns
  start_ns="$(date +%s%N)"

  set +e
  if [[ "${use_preload}" == "1" ]]; then
    (
      cd "${ROOT}"
      timeout "${TIMEOUT_SECONDS}" env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" bash -lc "${cmd}"
    ) >"${stdout_file}" 2>"${stderr_file}"
  else
    (
      cd "${ROOT}"
      timeout "${TIMEOUT_SECONDS}" env FRANKENLIBC_MODE="${mode}" bash -lc "${cmd}"
    ) >"${stdout_file}" 2>"${stderr_file}"
  fi
  local rc=$?
  set -e

  local end_ns
  end_ns="$(date +%s%N)"
  local elapsed_ns=$((end_ns - start_ns))

  local outcome="pass"
  local level="info"
  if [[ ${rc} -ne ${expected_exit} ]]; then
    outcome="fail"
    level="error"
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
  result_details="$(jq -nc --arg command "${cmd}" --argjson expected_exit "${expected_exit}" --argjson actual_exit "${rc}" '{command:$command,expected_exit:$expected_exit,actual_exit:$actual_exit}')"
  emit_log "${level}" "test_result" "${mode}" "${label}" "${outcome}" "${rc}" "${elapsed_ns}" "${result_details}" "${refs_json}"

  local row
  row="$(jq -nc \
    --arg mode "${mode}" \
    --arg scenario_id "${label}" \
    --arg op "${label}" \
    --arg result "${outcome}" \
    --argjson expected_exit "${expected_exit}" \
    --argjson actual_exit "${rc}" \
    --argjson errno "${rc}" \
    --argjson timing_ns "${elapsed_ns}" \
    --arg stdout_path "${stdout_file#${ROOT}/}" \
    --arg stderr_path "${stderr_file#${ROOT}/}" \
    '{mode:$mode,scenario_id:$scenario_id,op:$op,result:$result,expected_exit:$expected_exit,actual_exit:$actual_exit,errno:$errno,timing_ns:$timing_ns,artifact_refs:[$stdout_path,$stderr_path]}')"
  SCENARIO_ROWS="$(jq -nc --argjson arr "${SCENARIO_ROWS}" --argjson item "${row}" '$arr + [$item]')"
}

FIXTURE_SRC="${ROOT}/tests/integration/fixture_pthread_mutex_adversarial.c"
FIXTURE_BIN="${BIN_DIR}/fixture_pthread_mutex_adversarial"
cc -O2 -Wall -Wextra "${FIXTURE_SRC}" -o "${FIXTURE_BIN}" -pthread

for mode in strict hardened; do
  run_case "${mode}" "rust_mutex_roundtrip_trylock_busy" \
    "cargo test -p frankenlibc-abi --test pthread_mutex_core_test futex_mutex_roundtrip_and_trylock_busy -- --exact --nocapture --test-threads=1" \
    0 0
  run_case "${mode}" "rust_mutex_contention_counters" \
    "cargo test -p frankenlibc-abi --test pthread_mutex_core_test futex_mutex_contention_increments_wait_and_wake_counters -- --exact --nocapture --test-threads=1" \
    0 0
  run_case "${mode}" "rust_mutex_destroy_while_locked_ebusy" \
    "cargo test -p frankenlibc-abi --test pthread_mutex_core_test futex_mutex_destroy_while_locked_is_ebusy -- --exact --nocapture --test-threads=1" \
    0 0
  run_case "${mode}" "rust_mutex_unlock_without_lock_eperm" \
    "cargo test -p frankenlibc-abi --test pthread_mutex_core_test futex_mutex_unlock_without_lock_is_eperm -- --exact --nocapture --test-threads=1" \
    0 0
  run_case "${mode}" "c_fixture_pthread_mutex_adversarial" "${FIXTURE_BIN}" 0 0
done

report_payload="$(jq -nc \
  --arg schema_version "v1" \
  --arg bead "bd-1qy" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso_utc)" \
  --arg trace_log "${LOG_FILE#${ROOT}/}" \
  --arg artifact_index "${INDEX_FILE#${ROOT}/}" \
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
    summary: {
      total_cases: $total_cases,
      pass_count: $pass_count,
      fail_count: $fail_count
    },
    mode_profiles: {
      strict: { expected_pass: 5, observed_pass: $strict_pass, observed_fail: $strict_fail },
      hardened: { expected_pass: 5, observed_pass: $hardened_pass, observed_fail: $hardened_fail }
    },
    scenarios: $scenarios,
    artifacts: {
      trace_jsonl: $trace_log,
      artifact_index_json: $artifact_index
    }
  }')"
printf '%s\n' "${report_payload}" > "${REPORT_FILE}"

artifacts='[]'
artifact_paths_json="$(
  jq -nc \
    --arg log "${LOG_FILE#${ROOT}/}" \
    --arg report "${REPORT_FILE#${ROOT}/}" \
    --arg bin "${FIXTURE_BIN#${ROOT}/}" \
    --argjson scenarios "${SCENARIO_ROWS}" \
    '([$log, $report, $bin] + ($scenarios | map(.artifact_refs[]) )) | unique'
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
    --arg description "bd-1qy mutex fixture artifact" \
    --argjson size_bytes "${size}" \
    '{path:$path,kind:$kind,sha256:$sha256,size_bytes:$size_bytes,description:$description}')"
  artifacts="$(jq -nc --argjson arr "${artifacts}" --argjson item "${item}" '$arr + [$item]')"
done < <(jq -r '.[]' <<<"${artifact_paths_json}")

jq -n \
  --argjson index_version 1 \
  --arg run_id "${RUN_ID}" \
  --arg bead_id "bd-1qy" \
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
emit_log "info" "run_summary" "strict" "bd1qy_mutex_fixture_run" "$( [[ ${FAIL_COUNT} -eq 0 ]] && echo pass || echo fail )" "${FAIL_COUNT}" 0 "${summary_details}" "$(jq -nc --arg a "${INDEX_FILE#${ROOT}/}" --arg b "${LOG_FILE#${ROOT}/}" --arg c "${REPORT_FILE#${ROOT}/}" '[$a,$b,$c]')"

cat <<MSG
bd-1qy mutex fixture run complete
run_id: ${RUN_ID}
log: ${LOG_FILE}
index: ${INDEX_FILE}
report: ${REPORT_FILE}
passes: ${PASS_COUNT}
fails: ${FAIL_COUNT}
MSG

if [[ ${FAIL_COUNT} -ne 0 ]]; then
  exit 1
fi
