#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: build-package.sh <package-atom> <output-dir>"
    exit 2
fi

PACKAGE="$1"
OUT_DIR="$2"

mkdir -p "${OUT_DIR}"

BUILD_LOG="${OUT_DIR}/build.log"
FRANKEN_LOG="${OUT_DIR}/frankenlibc.jsonl"
METADATA="${OUT_DIR}/metadata.json"
DEFAULT_PORTAGE_LOG="${OUT_DIR}/portage-hooks.jsonl"
DEFAULT_PORTAGE_LOG_DIR="${OUT_DIR}/portage-frankenlibc"
DEFAULT_TELEMETRY_LOG="${OUT_DIR}/build-telemetry.jsonl"

json_escape() {
    local value="${1:-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf "%s" "${value}"
}

count_jsonl_matches() {
    local path="$1"
    local pattern="$2"
    if [[ -f "${path}" ]]; then
        grep -Eci "${pattern}" "${path}" || true
    else
        printf "0"
    fi
}

count_healing_actions() {
    local total=0
    local count
    count="$(count_jsonl_matches "${FRANKEN_LOG}" '"action"\s*:')"
    total="$((total + count))"
    if [[ -d "${FRANKENLIBC_LOG_DIR:-}" ]]; then
        while IFS= read -r -d '' log_path; do
            if [[ "${log_path}" == "${FRANKEN_LOG}" ]]; then
                continue
            fi
            count="$(count_jsonl_matches "${log_path}" '"action"\s*:')"
            total="$((total + count))"
        done < <(find "${FRANKENLIBC_LOG_DIR}" -type f -name '*.jsonl' -print0 2>/dev/null)
    fi
    printf "%s" "${total}"
}

count_frankenlibc_logs() {
    local total=0
    if [[ -f "${FRANKEN_LOG}" ]]; then
        total="$((total + 1))"
    fi
    if [[ -d "${FRANKENLIBC_LOG_DIR:-}" ]]; then
        while IFS= read -r -d '' _; do
            total="$((total + 1))"
        done < <(find "${FRANKENLIBC_LOG_DIR}" -type f -name '*.jsonl' -print0 2>/dev/null)
    fi
    printf "%s" "${total}"
}

count_instrumented_phase_events() {
    count_jsonl_matches "${FRANKENLIBC_PORTAGE_LOG:-}" '"event"\s*:\s*"enable"|enabled:'
}

write_telemetry_event() {
    local event="$1"
    local result="$2"
    local exit_code="$3"
    local elapsed="$4"
    local healing_actions="$5"
    local phase_events="$6"
    local log_files="$7"
    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    mkdir -p "$(dirname "${FRANKENLIBC_RUNNER_TELEMETRY}")"
    printf '{"timestamp":"%s","event":"%s","package":"%s","result":"%s","exit_code":%s,"build_time_seconds":%s,"frankenlibc_mode":"%s","portage_enabled":"%s","phase_allowlist":"%s","emerge_command":"%s","build_log":"%s","frankenlibc_log":"%s","portage_hook_log":"%s","portage_log_dir":"%s","healing_actions":%s,"instrumented_phase_events":%s,"frankenlibc_log_files":%s}\n' \
        "$(json_escape "${ts}")" \
        "$(json_escape "${event}")" \
        "$(json_escape "${PACKAGE}")" \
        "$(json_escape "${result}")" \
        "${exit_code}" \
        "${elapsed}" \
        "$(json_escape "${FRANKENLIBC_MODE}")" \
        "$(json_escape "${FRANKENLIBC_PORTAGE_ENABLE}")" \
        "$(json_escape "${FRANKENLIBC_PHASE_ALLOWLIST}")" \
        "$(json_escape "${EMERGE_CMD_TEXT}")" \
        "$(json_escape "${BUILD_LOG}")" \
        "$(json_escape "${FRANKEN_LOG}")" \
        "$(json_escape "${FRANKENLIBC_PORTAGE_LOG}")" \
        "$(json_escape "${FRANKENLIBC_LOG_DIR}")" \
        "${healing_actions}" \
        "${phase_events}" \
        "${log_files}" \
        >>"${FRANKENLIBC_RUNNER_TELEMETRY}"
}

export FRANKENLIBC_MODE="${FRANKENLIBC_MODE:-hardened}"
export FRANKENLIBC_LOG_FILE="${FRANKENLIBC_LOG_FILE:-${FRANKEN_LOG}}"
export FRANKENLIBC_LOG="${FRANKENLIBC_LOG_FILE}"
export FRANKENLIBC_PORTAGE_ENABLE="${FRANKENLIBC_PORTAGE_ENABLE:-1}"
export FRANKENLIBC_PHASE_ALLOWLIST="${FRANKENLIBC_PHASE_ALLOWLIST:-src_test pkg_test}"
export FRANKENLIBC_LOG_DIR="${FRANKENLIBC_LOG_DIR:-${DEFAULT_PORTAGE_LOG_DIR}}"
export FRANKENLIBC_PORTAGE_LOG="${FRANKENLIBC_PORTAGE_LOG:-${DEFAULT_PORTAGE_LOG}}"
export FRANKENLIBC_RUNNER_TELEMETRY="${FRANKENLIBC_RUNNER_TELEMETRY:-${DEFAULT_TELEMETRY_LOG}}"

mkdir -p "${FRANKENLIBC_LOG_DIR}" "$(dirname "${FRANKENLIBC_PORTAGE_LOG}")" "$(dirname "${FRANKENLIBC_RUNNER_TELEMETRY}")"

START_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
START_EPOCH="$(date +%s)"

EMERGE_CMD=(emerge --verbose --buildpkg "${PACKAGE}")
if [[ -n "${FLC_EMERGE_EXTRA_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    EXTRA_ARGS=( ${FLC_EMERGE_EXTRA_ARGS} )
    EMERGE_CMD+=("${EXTRA_ARGS[@]}")
fi
EMERGE_CMD_TEXT="$(printf '%q ' "${EMERGE_CMD[@]}")"
EMERGE_CMD_TEXT="${EMERGE_CMD_TEXT% }"

write_telemetry_event "start" "pending" 0 0 0 0 0

set +e
if [[ "${FLC_BUILD_TIMEOUT_SECONDS:-0}" =~ ^[0-9]+$ ]] && [[ "${FLC_BUILD_TIMEOUT_SECONDS:-0}" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout --signal=TERM --kill-after=30 "${FLC_BUILD_TIMEOUT_SECONDS}" "${EMERGE_CMD[@]}" >"${BUILD_LOG}" 2>&1
    EXIT_CODE=$?
else
    "${EMERGE_CMD[@]}" >"${BUILD_LOG}" 2>&1
    EXIT_CODE=$?
fi
set -e

END_EPOCH="$(date +%s)"
END_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
BUILD_TIME="$((END_EPOCH - START_EPOCH))"

RESULT="failed"
if [[ "${EXIT_CODE}" -eq 0 ]]; then
    RESULT="success"
elif [[ "${EXIT_CODE}" -eq 124 ]]; then
    RESULT="timeout"
fi

if grep -Eqi '(cannot allocate memory|out of memory|oom)' "${BUILD_LOG}" 2>/dev/null; then
    RESULT="oom"
fi

HEAL_COUNT=0
HEAL_COUNT="$(count_healing_actions)"
INSTRUMENTED_PHASE_EVENTS="$(count_instrumented_phase_events)"
FRANKENLIBC_LOG_FILES="$(count_frankenlibc_logs)"

write_telemetry_event "finish" "${RESULT}" "${EXIT_CODE}" "${BUILD_TIME}" "${HEAL_COUNT}" "${INSTRUMENTED_PHASE_EVENTS}" "${FRANKENLIBC_LOG_FILES}"

cat >"${METADATA}" <<EOF
{
  "package": "${PACKAGE}",
  "result": "${RESULT}",
  "build_time_seconds": ${BUILD_TIME},
  "frankenlibc_healing_actions": ${HEAL_COUNT},
  "frankenlibc_mode": "${FRANKENLIBC_MODE}",
  "log_file": "${BUILD_LOG}",
  "frankenlibc_log": "${FRANKEN_LOG}",
  "telemetry_log": "${FRANKENLIBC_RUNNER_TELEMETRY}",
  "portage_hook_log": "${FRANKENLIBC_PORTAGE_LOG}",
  "portage_log_dir": "${FRANKENLIBC_LOG_DIR}",
  "instrumented_phase_events": ${INSTRUMENTED_PHASE_EVENTS},
  "frankenlibc_log_files": ${FRANKENLIBC_LOG_FILES},
  "binary_package": "",
  "exit_code": ${EXIT_CODE},
  "started_at": "${START_TS}",
  "timestamp": "${END_TS}"
}
EOF

if [[ "${RESULT}" == "success" ]]; then
    exit 0
fi
exit 1
