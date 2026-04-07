#!/usr/bin/env bash
# check_property_suite.sh — deterministic 10k-case property-suite evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
BEAD_ID="${BEAD_ID:-bd-1sp.8}"
ARTIFACT_BASENAME="${ARTIFACT_BASENAME:-property_suite}"
PROPTEST_CASES="${FRANKENLIBC_PROPTEST_CASES:-10000}"
LOG_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.log.jsonl"
REPORT_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.report.json"
TEST_OUTPUT_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.test_output.log"
# Leave CARGO_HOME unset by default so local `rch` fallback can reuse the
# prewarmed workspace cache instead of creating an empty temp registry and
# spuriously requiring network access.
RCH_CARGO_HOME="${RCH_CARGO_HOME:-}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-/tmp/${ARTIFACT_BASENAME}_target}"
mkdir -p "${OUT_DIR}"

now_iso_ms() {
    date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

suite_api_family() {
    case "$1" in
        core_property_tests)
            printf '%s' "core"
            ;;
        membrane_lattice)
            printf '%s' "membrane"
            ;;
        membrane_ptr_validator)
            printf '%s' "membrane"
            ;;
        string_mem_local|string_str_local)
            printf '%s' "string"
            ;;
        string_wide_local)
            printf '%s' "wchar"
            ;;
        ctype_local)
            printf '%s' "ctype"
            ;;
        math_trig_local)
            printf '%s' "math"
            ;;
        pthread_mutex_local)
            printf '%s' "pthread"
            ;;
        stdio_buffer_local)
            printf '%s' "stdio"
            ;;
        stdlib_conversion_local)
            printf '%s' "stdlib"
            ;;
        *)
            printf '%s' "property"
            ;;
    esac
}

suite_symbol() {
    case "$1" in
        core_property_tests)
            printf '%s' "property_tests"
            ;;
        membrane_lattice)
            printf '%s' "lattice"
            ;;
        membrane_ptr_validator)
            printf '%s' "ptr_validator"
            ;;
        string_mem_local)
            printf '%s' "memcpy"
            ;;
        string_str_local)
            printf '%s' "strlen"
            ;;
        string_wide_local)
            printf '%s' "wcslen"
            ;;
        ctype_local)
            printf '%s' "isalnum"
            ;;
        math_trig_local)
            printf '%s' "sin"
            ;;
        pthread_mutex_local)
            printf '%s' "pthread_mutex_init"
            ;;
        stdio_buffer_local)
            printf '%s' "setvbuf"
            ;;
        stdlib_conversion_local)
            printf '%s' "strtol"
            ;;
        *)
            printf '%s' "$1"
            ;;
    esac
}

suite_decision_path() {
    case "$1" in
        core_property_tests)
            printf '%s' "property->shared_suite->major_families"
            ;;
        membrane_lattice)
            printf '%s' "property->membrane->lattice_algebra"
            ;;
        membrane_ptr_validator)
            printf '%s' "property->membrane->ptr_validator_alloc_free"
            ;;
        string_mem_local)
            printf '%s' "property->string->mem_local_env_config"
            ;;
        string_str_local)
            printf '%s' "property->string->str_local_env_config"
            ;;
        string_wide_local)
            printf '%s' "property->wchar->wide_local_env_config"
            ;;
        ctype_local)
            printf '%s' "property->ctype->local_env_config"
            ;;
        math_trig_local)
            printf '%s' "property->math->trig_local_env_config"
            ;;
        pthread_mutex_local)
            printf '%s' "property->pthread->mutex_local_env_config"
            ;;
        stdio_buffer_local)
            printf '%s' "property->stdio->buffer_local_env_config"
            ;;
        stdlib_conversion_local)
            printf '%s' "property->stdlib->conversion_local_env_config"
            ;;
        *)
            printf '%s' "property->unknown"
            ;;
    esac
}

suite_expected() {
    case "$1" in
        core_property_tests)
            printf '%s' "PASS; 10k-case shared property suite covers string, math, conversion, ctype, inet, and allocator invariants."
            ;;
        membrane_lattice)
            printf '%s' "PASS; 10k-case lattice suite preserves commutativity, associativity, idempotence, and permission monotonicity."
            ;;
        membrane_ptr_validator)
            printf '%s' "PASS; 10k-case ptr-validator suite preserves alloc/live and free/temporal-violation properties plus dependency-safe stage ordering."
            ;;
        string_mem_local)
            printf '%s' "PASS; the local mem.rs proptest block honors FRANKENLIBC_PROPTEST_CASES at 10k cases."
            ;;
        string_str_local)
            printf '%s' "PASS; the local str.rs proptest block honors FRANKENLIBC_PROPTEST_CASES at 10k cases."
            ;;
        string_wide_local)
            printf '%s' "PASS; the local wide.rs proptest block honors FRANKENLIBC_PROPTEST_CASES at 10k cases."
            ;;
        ctype_local)
            printf '%s' "PASS; the local ctype property block honors FRANKENLIBC_PROPTEST_CASES at 10k cases."
            ;;
        math_trig_local)
            printf '%s' "PASS; the local trig.rs proptest block honors FRANKENLIBC_PROPTEST_CASES at 10k cases."
            ;;
        pthread_mutex_local)
            printf '%s' "PASS; the local pthread mutex proptest block honors FRANKENLIBC_PROPTEST_CASES at 10k cases."
            ;;
        stdio_buffer_local)
            printf '%s' "PASS; the local stdio buffer proptest block honors FRANKENLIBC_PROPTEST_CASES at 10k cases."
            ;;
        stdlib_conversion_local)
            printf '%s' "PASS; the local stdlib conversion proptest block honors FRANKENLIBC_PROPTEST_CASES at 10k cases."
            ;;
        *)
            printf '%s' "PASS"
            ;;
    esac
}

suite_failure_signature() {
    case "$1" in
        core_property_tests)
            printf '%s' "property_tests must stay green at FRANKENLIBC_PROPTEST_CASES=10000"
            ;;
        membrane_lattice)
            printf '%s' "lattice proptests must stay green at FRANKENLIBC_PROPTEST_CASES=10000"
            ;;
        membrane_ptr_validator)
            printf '%s' "ptr_validator proptests must stay green at FRANKENLIBC_PROPTEST_CASES=10000"
            ;;
        string_mem_local)
            printf '%s' "prop_memcpy_matches_prefix_copy must stay green at FRANKENLIBC_PROPTEST_CASES=10000"
            ;;
        string_str_local)
            printf '%s' "prop_strlen_matches_first_nul_or_slice_len must stay green at FRANKENLIBC_PROPTEST_CASES=10000"
            ;;
        string_wide_local)
            printf '%s' "prop_wcslen_matches_first_nul_or_slice_len must stay green at FRANKENLIBC_PROPTEST_CASES=10000"
            ;;
        ctype_local)
            printf '%s' "prop_core_classification_invariants must stay green at FRANKENLIBC_PROPTEST_CASES=10000"
            ;;
        math_trig_local)
            printf '%s' "prop_sin_is_odd must stay green at FRANKENLIBC_PROPTEST_CASES=10000"
            ;;
        pthread_mutex_local)
            printf '%s' "prop_sanitize_always_returns_supported_kind must stay green at FRANKENLIBC_PROPTEST_CASES=10000"
            ;;
        stdio_buffer_local)
            printf '%s' "prop_set_mode_before_io_resets_state must stay green at FRANKENLIBC_PROPTEST_CASES=10000"
            ;;
        stdlib_conversion_local)
            printf '%s' "prop_strtol_round_trips_all_i64_values must stay green at FRANKENLIBC_PROPTEST_CASES=10000"
            ;;
        *)
            printf '%s' "property suite failure"
            ;;
    esac
}

suite_command() {
    case "$1" in
        core_property_tests)
            printf '%s' "cargo test --locked -p frankenlibc-core --test property_tests -- --nocapture --test-threads=1"
            ;;
        membrane_lattice)
            printf '%s' "cargo test --locked -p frankenlibc-membrane lattice --lib -- --nocapture --test-threads=1"
            ;;
        membrane_ptr_validator)
            printf '%s' "cargo test --locked -p frankenlibc-membrane ptr_validator --lib -- --nocapture --test-threads=1"
            ;;
        string_mem_local)
            printf '%s' "cargo test --locked -p frankenlibc-core prop_memcpy_matches_prefix_copy --lib -- --exact --nocapture --test-threads=1"
            ;;
        string_str_local)
            printf '%s' "cargo test --locked -p frankenlibc-core prop_strlen_matches_first_nul_or_slice_len --lib -- --exact --nocapture --test-threads=1"
            ;;
        string_wide_local)
            printf '%s' "cargo test --locked -p frankenlibc-core prop_wcslen_matches_first_nul_or_slice_len --lib -- --exact --nocapture --test-threads=1"
            ;;
        ctype_local)
            printf '%s' "cargo test --locked -p frankenlibc-core prop_core_classification_invariants --lib -- --exact --nocapture --test-threads=1"
            ;;
        math_trig_local)
            printf '%s' "cargo test --locked -p frankenlibc-core prop_sin_is_odd --lib -- --exact --nocapture --test-threads=1"
            ;;
        pthread_mutex_local)
            printf '%s' "cargo test --locked -p frankenlibc-core prop_sanitize_always_returns_supported_kind --lib -- --exact --nocapture --test-threads=1"
            ;;
        stdio_buffer_local)
            printf '%s' "cargo test --locked -p frankenlibc-core prop_set_mode_before_io_resets_state --lib -- --exact --nocapture --test-threads=1"
            ;;
        stdlib_conversion_local)
            printf '%s' "cargo test --locked -p frankenlibc-core prop_strtol_round_trips_all_i64_values --lib -- --exact --nocapture --test-threads=1"
            ;;
        *)
            return 1
            ;;
    esac
}

run_suite() {
    local suite="$1" api_family symbol decision_path command expected failure_signature
    local start_ns end_ns latency_ns output status errno_value command_banner cargo_home_banner
    api_family="$(suite_api_family "${suite}")"
    symbol="$(suite_symbol "${suite}")"
    decision_path="$(suite_decision_path "${suite}")"
    command="$(suite_command "${suite}")"
    expected="$(suite_expected "${suite}")"
    failure_signature="$(suite_failure_signature "${suite}")"
    command_banner="FRANKENLIBC_PROPTEST_CASES=${PROPTEST_CASES} rch exec -- env"
    if [[ -n "${RCH_CARGO_HOME}" ]]; then
        cargo_home_banner=" CARGO_HOME=${RCH_CARGO_HOME}"
    else
        cargo_home_banner=""
    fi
    command_banner="${command_banner}${cargo_home_banner} CARGO_TARGET_DIR=${RCH_TARGET_DIR} ${command}"

    start_ns="$(date +%s%N)"
    if [[ -n "${RCH_CARGO_HOME}" ]]; then
        if output="$(
            rch exec -- env \
                FRANKENLIBC_PROPTEST_CASES="${PROPTEST_CASES}" \
                CARGO_HOME="${RCH_CARGO_HOME}" \
                CARGO_TARGET_DIR="${RCH_TARGET_DIR}" \
                ${command} 2>&1
        )"; then
            status="pass"
            errno_value=0
        else
            status="fail"
            errno_value=1
            FAILURES=$((FAILURES + 1))
        fi
    elif output="$(
        rch exec -- env \
            FRANKENLIBC_PROPTEST_CASES="${PROPTEST_CASES}" \
            CARGO_TARGET_DIR="${RCH_TARGET_DIR}" \
            ${command} 2>&1
    )"; then
        status="pass"
        errno_value=0
    else
        status="fail"
        errno_value=1
        FAILURES=$((FAILURES + 1))
    fi
    end_ns="$(date +%s%N)"
    latency_ns="$((end_ns - start_ns))"

    printf '=== %s ===\ncommand: FRANKENLIBC_PROPTEST_CASES=%s rch exec -- env CARGO_HOME=%s CARGO_TARGET_DIR=%s %s\n%s\n\n' \
        "${suite}" "${PROPTEST_CASES}" "${RCH_CARGO_HOME:-<default>}" "${RCH_TARGET_DIR}" "${command}" "${output}" >> "${TEST_OUTPUT_PATH}"

    printf '{"timestamp":"%s","trace_id":"%s::property_suite::%s","level":"info","event":"property_suite","bead_id":"%s","stream":"unit","gate":"check_property_suite","api_family":"%s","symbol":"%s","decision_path":"%s","healing_action":"none","outcome":"%s","errno":%s,"latency_ns":%s,"artifact_refs":["scripts/check_property_suite.sh","crates/frankenlibc-core/tests/property_tests.rs","crates/frankenlibc-membrane/src/lattice.rs","crates/frankenlibc-membrane/src/ptr_validator.rs","crates/frankenlibc-core/src/string/mem.rs","crates/frankenlibc-core/src/string/str.rs","crates/frankenlibc-core/src/string/wide.rs","crates/frankenlibc-core/src/ctype/mod.rs","crates/frankenlibc-core/src/math/trig.rs","crates/frankenlibc-core/src/pthread/mutex.rs","crates/frankenlibc-core/src/stdio/buffer.rs","crates/frankenlibc-core/src/stdlib/conversion.rs","target/conformance/%s.report.json","target/conformance/%s.log.jsonl","target/conformance/%s.test_output.log"]}\n' \
        "$(now_iso_ms)" "${BEAD_ID}" "${suite}" "${BEAD_ID}" "${api_family}" "${symbol}" "${decision_path}" "${status}" "${errno_value}" "${latency_ns}" "${ARTIFACT_BASENAME}" "${ARTIFACT_BASENAME}" "${ARTIFACT_BASENAME}" >> "${LOG_PATH}"

    SUITE_NAMES+=("${suite}")
    SUITE_STATUSES["${suite}"]="${status}"
    SUITE_COMMANDS["${suite}"]="${command_banner}"
    SUITE_EXPECTED["${suite}"]="${expected}"
    SUITE_FAILURE_SIGNATURES["${suite}"]="${failure_signature}"
}

cd "${ROOT}"
: > "${LOG_PATH}"
: > "${TEST_OUTPUT_PATH}"

FAILURES=0
declare -a SUITE_NAMES=()
declare -A SUITE_STATUSES=()
declare -A SUITE_COMMANDS=()
declare -A SUITE_EXPECTED=()
declare -A SUITE_FAILURE_SIGNATURES=()

SUITES=(
    core_property_tests
    membrane_lattice
    membrane_ptr_validator
    string_mem_local
    string_str_local
    string_wide_local
    ctype_local
    math_trig_local
    pthread_mutex_local
    stdio_buffer_local
    stdlib_conversion_local
)

for suite in "${SUITES[@]}"; do
    run_suite "${suite}"
done

{
    printf '{\n'
    printf '  "schema_version": "v1",\n'
    printf '  "bead_id": "%s",\n' "${BEAD_ID}"
    printf '  "gate": "check_property_suite",\n'
    printf '  "artifact_basename": "%s",\n' "${ARTIFACT_BASENAME}"
    printf '  "proptest_cases": %s,\n' "${PROPTEST_CASES}"
    if [[ "${FAILURES}" -eq 0 ]]; then
        printf '  "status": "pass",\n'
    else
        printf '  "status": "fail",\n'
    fi
    printf '  "tests": [\n'
    first_entry=1
    for suite in "${SUITE_NAMES[@]}"; do
        if [[ "${first_entry}" -eq 0 ]]; then
            printf ',\n'
        fi
        printf '    {\n'
        printf '      "suite": "%s",\n' "${suite}"
        printf '      "status": "%s",\n' "${SUITE_STATUSES[${suite}]}"
        printf '      "command": "%s",\n' "${SUITE_COMMANDS[${suite}]}"
        printf '      "expected": "%s",\n' "${SUITE_EXPECTED[${suite}]}"
        printf '      "failure_signature": "%s"\n' "${SUITE_FAILURE_SIGNATURES[${suite}]}"
        printf '    }'
        first_entry=0
    done
    printf '\n  ],\n'
    printf '  "artifacts": [\n'
    printf '    "target/conformance/%s.report.json",\n' "${ARTIFACT_BASENAME}"
    printf '    "target/conformance/%s.log.jsonl",\n' "${ARTIFACT_BASENAME}"
    printf '    "target/conformance/%s.test_output.log"\n' "${ARTIFACT_BASENAME}"
    printf '  ]\n'
    printf '}\n'
} > "${REPORT_PATH}"

if [[ "${FAILURES}" -ne 0 ]]; then
    echo "${ARTIFACT_BASENAME}: FAIL (${FAILURES} suite(s))" >&2
    echo "report=${REPORT_PATH}" >&2
    exit 1
fi

echo "${ARTIFACT_BASENAME}: PASS"
echo "report=${REPORT_PATH}"
