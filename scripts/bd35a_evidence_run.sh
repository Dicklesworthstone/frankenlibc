#!/usr/bin/env bash
set -euo pipefail

# bd35a_evidence_run.sh
# Deterministic evidence-run harness for bd-35a.
# Produces schema-compliant JSONL logs and artifact index.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="bd35a-${RUN_STAMP}"
OUT_DIR="${ROOT}/tests/cve_arena/results/bd-35a/${RUN_ID}"
LOG_FILE="${OUT_DIR}/trace.jsonl"
INDEX_FILE="${OUT_DIR}/artifact_index.json"

mkdir -p "${OUT_DIR}"
: > "${LOG_FILE}"

SEQ=0
PASS_COUNT=0
FAIL_COUNT=0

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
  trace_id="bd-35a::${RUN_ID}::$(printf '%03d' "${SEQ}")"

  jq -nc \
    --arg timestamp "$(now_iso_utc)" \
    --arg trace_id "${trace_id}" \
    --arg level "${level}" \
    --arg event "${event}" \
    --arg bead_id "bd-35a" \
    --arg mode "${mode}" \
    --arg api_family "runtime_math" \
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

  local case_dir="${OUT_DIR}/${mode}/${label}"
  local stdout_file="${case_dir}/stdout.txt"
  local stderr_file="${case_dir}/stderr.txt"
  mkdir -p "${case_dir}"

  local start_ns
  start_ns="$(date +%s%N)"

  local start_details
  start_details="$(jq -nc --arg command "${cmd}" --arg cwd "${ROOT}" '{command:$command,cwd:$cwd}')"
  emit_log "info" "test_start" "${mode}" "${label}" "pass" 0 0 "${start_details}" '[ ]'

  set +e
  (
    cd "${ROOT}"
    env FRANKENLIBC_MODE="${mode}" bash -lc "${cmd}"
  ) >"${stdout_file}" 2>"${stderr_file}"
  local rc=$?
  set -e

  local end_ns
  end_ns="$(date +%s%N)"
  local elapsed_ns=$((end_ns - start_ns))

  local refs_json
  refs_json="$(jq -nc --arg a "${stdout_file#${ROOT}/}" --arg b "${stderr_file#${ROOT}/}" '[$a,$b]')"
  local result_details
  result_details="$(jq -nc --arg command "${cmd}" '{command:$command}')"

  if [[ ${rc} -eq 0 ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    emit_log "info" "test_result" "${mode}" "${label}" "pass" 0 "${elapsed_ns}" "${result_details}" "${refs_json}"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    emit_log "error" "test_result" "${mode}" "${label}" "fail" "${rc}" "${elapsed_ns}" "${result_details}" "${refs_json}"
  fi
}

# Mode-aware runtime math checks.
CASES=(
  "loss_minimizer_tests:::cargo test -p frankenlibc-membrane runtime_math::loss_minimizer::tests:: -- --nocapture"
  "evidence_payload_test:::cargo test -p frankenlibc-membrane runtime_math::evidence::tests::encode_decision_payload_embeds_loss_evidence_block -- --exact"
  "snapshot_fields_test:::cargo test -p frankenlibc-membrane runtime_math::tests::evidence_snapshot_fields_present -- --exact"
)

for mode in strict hardened; do
  for entry in "${CASES[@]}"; do
    label="${entry%%:::*}"
    cmd="${entry#*:::}"
    run_case "${mode}" "${label}" "${cmd}"
  done

  run_case "${mode}" "expected_loss_matrix_gate" "scripts/check_expected_loss_matrix.sh"
  run_case "${mode}" "runtime_math_linkage_gate" "scripts/check_runtime_math_linkage.sh"
done

# Build artifact index.
artifacts='[]'
while IFS= read -r -d '' file; do
  rel="${file#${ROOT}/}"
  kind="report"
  if [[ "${rel}" == *".jsonl" ]]; then
    kind="log"
  elif [[ "${rel}" == *"artifact_index.json" ]]; then
    kind="report"
  elif [[ "${rel}" == *"stdout.txt" ]] || [[ "${rel}" == *"stderr.txt" ]]; then
    kind="report"
  fi

  sha="$(sha256sum "${file}" | awk '{print $1}')"
  size="$(wc -c < "${file}")"
  item="$(jq -nc \
    --arg path "${rel}" \
    --arg kind "${kind}" \
    --arg sha256 "${sha}" \
    --arg description "bd-35a evidence artifact" \
    --argjson size_bytes "${size}" \
    '{path:$path,kind:$kind,sha256:$sha256,size_bytes:$size_bytes,description:$description}')"
  artifacts="$(jq -nc --argjson arr "${artifacts}" --argjson item "${item}" '$arr + [$item]')"
done < <(find "${OUT_DIR}" -type f ! -name "artifact_index.json" -print0 | sort -z)

jq -n \
  --argjson index_version 1 \
  --arg run_id "${RUN_ID}" \
  --arg bead_id "bd-35a" \
  --arg generated_utc "$(now_iso_utc)" \
  --argjson artifacts "${artifacts}" \
  '{
    index_version: $index_version,
    run_id: $run_id,
    bead_id: $bead_id,
    generated_utc: $generated_utc,
    artifacts: $artifacts
  }' > "${INDEX_FILE}"

summary_details="$(jq -nc --arg pass "${PASS_COUNT}" --arg fail "${FAIL_COUNT}" '{pass:$pass,fail:$fail}')"
emit_log "info" "run_summary" "strict" "bd35a_evidence_run" "$( [[ ${FAIL_COUNT} -eq 0 ]] && echo pass || echo fail )" "${FAIL_COUNT}" 0 "${summary_details}" "$(jq -nc --arg a "${INDEX_FILE#${ROOT}/}" --arg b "${LOG_FILE#${ROOT}/}" '[$a,$b]')"

cat <<MSG
bd-35a evidence run complete
run_id: ${RUN_ID}
log: ${LOG_FILE}
index: ${INDEX_FILE}
passes: ${PASS_COUNT}
fails: ${FAIL_COUNT}
MSG

if [[ ${FAIL_COUNT} -ne 0 ]]; then
  exit 1
fi
