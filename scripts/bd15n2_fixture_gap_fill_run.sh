#!/usr/bin/env bash
set -euo pipefail

# bd15n2_fixture_gap_fill_run.sh
# Deterministic strict+hardened fixture gap-fill evidence harness for bd-15n.2.
# Emits:
# - tests/cve_arena/results/bd-15n.2/trace.jsonl
# - tests/cve_arena/results/bd-15n.2/artifact_index.json
# - tests/cve_arena/results/bd-15n.2/report.json

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/tests/cve_arena/results/bd-15n.2"
LOG_FILE="${OUT_DIR}/trace.jsonl"
INDEX_FILE="${OUT_DIR}/artifact_index.json"
REPORT_FILE="${OUT_DIR}/report.json"
BIN_DIR="${OUT_DIR}/bin"
SPEC_FILE="${ROOT}/tests/conformance/c_fixture_spec.json"
RUN_ID="${FLC_BD15N2_RUN_ID:-bd15n2-fixture-v1}"
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
if ! command -v timeout >/dev/null 2>&1; then
  echo "FAIL: timeout is required" >&2
  exit 2
fi
if [[ ! -f "${SPEC_FILE}" ]]; then
  echo "FAIL: missing fixture spec ${SPEC_FILE}" >&2
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

FIXTURES=(
  "fixture_ctype"
  "fixture_math"
  "fixture_socket"
)

now_iso_utc() {
  date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

fixture_api_family() {
  case "$1" in
    fixture_ctype) echo "ctype" ;;
    fixture_math) echo "math" ;;
    fixture_socket) echo "socket" ;;
    *) echo "unknown" ;;
  esac
}

fixture_symbol() {
  case "$1" in
    fixture_ctype) echo "isalpha|isdigit|isspace|tolower|toupper" ;;
    fixture_math) echo "sin|cos|exp|log|floor|ceil|fmod" ;;
    fixture_socket) echo "socket|getsockopt|bind|send|recv|shutdown" ;;
    *) echo "$1" ;;
  esac
}

fixture_spec_ref() {
  case "$1" in
    fixture_ctype) echo "ISO C11 §7.4; POSIX.1-2017 <ctype.h>" ;;
    fixture_math) echo "ISO C11 §7.12; POSIX.1-2017 <math.h>" ;;
    fixture_socket) echo "POSIX.1-2017 sockets API (socket/bind/send/recv/shutdown/getsockopt)" ;;
    *) echo "unspecified" ;;
  esac
}

fixture_expected_stdout() {
  case "$1" in
    fixture_ctype) echo "fixture_ctype: PASS" ;;
    fixture_math) echo "fixture_math: PASS" ;;
    fixture_socket) echo "fixture_socket: PASS" ;;
    *) echo "PASS" ;;
  esac
}

emit_log() {
  local level="$1"
  local event="$2"
  local mode="$3"
  local fixture_id="$4"
  local api_family="$5"
  local symbol="$6"
  local spec_ref="$7"
  local outcome="$8"
  local errno_val="$9"
  local latency_ns="${10}"
  local details_json="${11}"
  local refs_json="${12}"

  SEQ=$((SEQ + 1))
  local trace_id
  trace_id="bd-15n.2::${RUN_ID}::$(printf '%03d' "${SEQ}")"

  jq -nc \
    --arg timestamp "$(now_iso_utc)" \
    --arg trace_id "${trace_id}" \
    --arg level "${level}" \
    --arg event "${event}" \
    --arg bead_id "bd-15n.2" \
    --arg stream "conformance" \
    --arg gate "bd15n2_fixture_gap_fill" \
    --arg mode "${mode}" \
    --arg fixture_id "${fixture_id}" \
    --arg api_family "${api_family}" \
    --arg symbol "${symbol}" \
    --arg spec_ref "${spec_ref}" \
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
      fixture_id: $fixture_id,
      api_family: $api_family,
      symbol: $symbol,
      spec_ref: $spec_ref,
      outcome: $outcome,
      errno: $errno,
      latency_ns: $latency_ns,
      details: $details,
      artifact_refs: $artifact_refs
    }' >> "${LOG_FILE}"
}

compile_fixture() {
  local fixture_id="$1"
  local src="${ROOT}/tests/integration/${fixture_id}.c"
  local bin="${BIN_DIR}/${fixture_id}"
  local cflags="-O2 -Wall -Wextra"
  local ldflags=""

  if [[ "${fixture_id}" == "fixture_math" ]]; then
    ldflags="-lm"
  fi

  if [[ ! -f "${src}" ]]; then
    echo "FAIL: missing fixture source ${src}" >&2
    exit 2
  fi

  cc ${cflags} "${src}" -o "${bin}" ${ldflags}
  echo "${bin}"
}

run_fixture() {
  local mode="$1"
  local fixture_id="$2"
  local bin="$3"
  local api_family
  api_family="$(fixture_api_family "${fixture_id}")"
  local symbol
  symbol="$(fixture_symbol "${fixture_id}")"
  local spec_ref
  spec_ref="$(fixture_spec_ref "${fixture_id}")"
  local stdout_marker
  stdout_marker="$(fixture_expected_stdout "${fixture_id}")"

  local case_dir="${OUT_DIR}/${mode}/${fixture_id}"
  local stdout_file="${case_dir}/stdout.txt"
  local stderr_file="${case_dir}/stderr.txt"
  mkdir -p "${case_dir}"

  TOTAL_CASES=$((TOTAL_CASES + 1))

  local start_details
  start_details="$(jq -nc --arg command "${bin}" --argjson expected_exit 0 --arg marker "${stdout_marker}" '{command:$command,expected_exit:$expected_exit,expected_stdout_contains:$marker}')"
  emit_log "info" "test_start" "${mode}" "${fixture_id}" "${api_family}" "${symbol}" "${spec_ref}" "pass" 0 0 "${start_details}" '[]'

  local start_ns
  start_ns="$(date +%s%N)"

  set +e
  (
    cd "${ROOT}"
    timeout "${TIMEOUT_SECONDS}" env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" "${bin}"
  ) >"${stdout_file}" 2>"${stderr_file}"
  local rc=$?
  set -e

  local end_ns
  end_ns="$(date +%s%N)"
  local elapsed_ns=$((end_ns - start_ns))

  local stdout_ok=0
  if grep -Fq "${stdout_marker}" "${stdout_file}"; then
    stdout_ok=1
  fi

  local outcome="pass"
  local level="info"
  if [[ ${rc} -ne 0 || ${stdout_ok} -ne 1 ]]; then
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

  printf '%s\n' "${rc}" > "${case_dir}/exit_code"

  local refs_json
  refs_json="$(jq -nc --arg out "${stdout_file#${ROOT}/}" --arg err "${stderr_file#${ROOT}/}" '[ $out, $err ]')"
  local result_details
  result_details="$(jq -nc \
    --argjson expected_exit 0 \
    --argjson actual_exit "${rc}" \
    --arg expected_stdout_contains "${stdout_marker}" \
    --argjson stdout_contains_expected "${stdout_ok}" \
    '{expected_vs_actual:{expected_exit:$expected_exit,actual_exit:$actual_exit,expected_stdout_contains:$expected_stdout_contains,stdout_contains_expected:$stdout_contains_expected}}')"
  emit_log "${level}" "test_result" "${mode}" "${fixture_id}" "${api_family}" "${symbol}" "${spec_ref}" "${outcome}" "${rc}" "${elapsed_ns}" "${result_details}" "${refs_json}"

  local row
  row="$(jq -nc \
    --arg fixture_id "${fixture_id}" \
    --arg mode "${mode}" \
    --arg api_family "${api_family}" \
    --arg symbol "${symbol}" \
    --arg spec_ref "${spec_ref}" \
    --arg outcome "${outcome}" \
    --argjson expected_exit 0 \
    --argjson actual_exit "${rc}" \
    --argjson stdout_contains_expected "${stdout_ok}" \
    --arg stdout_path "${stdout_file#${ROOT}/}" \
    --arg stderr_path "${stderr_file#${ROOT}/}" \
    --argjson timing_ns "${elapsed_ns}" \
    '{fixture_id:$fixture_id,mode:$mode,api_family:$api_family,symbol:$symbol,spec_ref:$spec_ref,outcome:$outcome,expected_exit:$expected_exit,actual_exit:$actual_exit,stdout_contains_expected:$stdout_contains_expected,timing_ns:$timing_ns,artifact_refs:[$stdout_path,$stderr_path]}')"
  SCENARIO_ROWS="$(jq -nc --argjson arr "${SCENARIO_ROWS}" --argjson item "${row}" '$arr + [$item]')"
}

declare -A BIN_BY_FIXTURE
for fixture_id in "${FIXTURES[@]}"; do
  BIN_BY_FIXTURE["${fixture_id}"]="$(compile_fixture "${fixture_id}")"
done

for mode in strict hardened; do
  for fixture_id in "${FIXTURES[@]}"; do
    run_fixture "${mode}" "${fixture_id}" "${BIN_BY_FIXTURE[${fixture_id}]}"
  done
done

fixture_metadata="$(jq -c '[.fixtures[] | select(.id=="fixture_ctype" or .id=="fixture_math" or .id=="fixture_socket") | {id,source,covered_symbols,covered_modules,spec_traceability,mode_expectations}]' "${SPEC_FILE}")"

report_payload="$(jq -nc \
  --arg schema_version "v1" \
  --arg bead "bd-15n.2" \
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
  --argjson fixtures "${fixture_metadata}" \
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
      strict: { expected_pass: 3, observed_pass: $strict_pass, observed_fail: $strict_fail },
      hardened: { expected_pass: 3, observed_pass: $hardened_pass, observed_fail: $hardened_fail }
    },
    fixtures: $fixtures,
    scenarios: $scenarios,
    artifacts: {
      trace_jsonl: $trace_log,
      artifact_index_json: $artifact_index
    }
  }')"
printf '%s\n' "${report_payload}" > "${REPORT_FILE}"

summary_outcome="pass"
summary_level="info"
if [[ ${FAIL_COUNT} -ne 0 ]]; then
  summary_outcome="fail"
  summary_level="error"
fi
summary_details="$(jq -nc --argjson pass "${PASS_COUNT}" --argjson fail "${FAIL_COUNT}" '{pass:$pass,fail:$fail}')"
summary_refs="$(jq -nc --arg a "${LOG_FILE#${ROOT}/}" --arg b "${REPORT_FILE#${ROOT}/}" '[$a,$b]')"
emit_log "${summary_level}" "run_summary" "strict" "bd15n2_fixture_gap_fill_run" "conformance" "fixture_gap_fill" "bd-15n.2 fixture summary" "${summary_outcome}" "${FAIL_COUNT}" 0 "${summary_details}" "${summary_refs}"

artifacts='[]'
while IFS= read -r file; do
  rel="${file#${ROOT}/}"
  kind="report"
  if [[ "${rel}" == *"trace.jsonl" ]]; then
    kind="log"
  elif [[ "${rel}" == *"/stdout.txt" || "${rel}" == *"/stderr.txt" || "${rel}" == *"/exit_code" ]]; then
    kind="snapshot"
  elif [[ "${rel}" == *"/bin/"* ]]; then
    kind="snapshot"
  fi

  sha="$(sha256sum "${file}" | awk '{print $1}')"
  size="$(wc -c < "${file}")"
  item="$(jq -nc \
    --arg path "${rel}" \
    --arg kind "${kind}" \
    --arg sha256 "${sha}" \
    --arg description "bd-15n.2 fixture gap-fill artifact" \
    --argjson size_bytes "${size}" \
    '{path:$path,kind:$kind,sha256:$sha256,size_bytes:$size_bytes,description:$description}')"
  artifacts="$(jq -nc --argjson arr "${artifacts}" --argjson item "${item}" '$arr + [$item]')"
done < <(find "${OUT_DIR}" -type f ! -name 'artifact_index.json' | sort)

jq -n \
  --argjson index_version 1 \
  --arg run_id "${RUN_ID}" \
  --arg bead_id "bd-15n.2" \
  --arg generated_utc "$(now_iso_utc)" \
  --argjson artifacts "${artifacts}" \
  '{
    index_version: $index_version,
    run_id: $run_id,
    bead_id: $bead_id,
    generated_utc: $generated_utc,
    artifacts: $artifacts
  }' > "${INDEX_FILE}"

cat <<MSG
bd-15n.2 fixture gap-fill run complete
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
