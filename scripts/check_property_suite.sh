#!/usr/bin/env bash
# check_property_suite.sh — deterministic 10k-case property-suite evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
BEAD_ID="${BEAD_ID:-bd-2tq.3}"
ARTIFACT_BASENAME="${ARTIFACT_BASENAME:-property_suite}"
PROPTEST_CASES="${FRANKENLIBC_PROPTEST_CASES:-10000}"
LOG_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.log.jsonl"
REPORT_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.report.json"
TEST_OUTPUT_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.test_output.log"
RCH_CARGO_HOME="${RCH_CARGO_HOME:-/tmp/${ARTIFACT_BASENAME}_cargo_home}"
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
        *)
            printf '%s' "property suite failure"
            ;;
    esac
}

suite_command() {
    case "$1" in
        core_property_tests)
            printf '%s' "cargo test -p frankenlibc-core --test property_tests -- --nocapture --test-threads=1"
            ;;
        membrane_lattice)
            printf '%s' "cargo test -p frankenlibc-membrane lattice --lib -- --nocapture --test-threads=1"
            ;;
        membrane_ptr_validator)
            printf '%s' "cargo test -p frankenlibc-membrane ptr_validator --lib -- --nocapture --test-threads=1"
            ;;
        string_mem_local)
            printf '%s' "cargo test -p frankenlibc-core prop_memcpy_matches_prefix_copy --lib -- --exact --nocapture --test-threads=1"
            ;;
        string_str_local)
            printf '%s' "cargo test -p frankenlibc-core prop_strlen_matches_first_nul_or_slice_len --lib -- --exact --nocapture --test-threads=1"
            ;;
        string_wide_local)
            printf '%s' "cargo test -p frankenlibc-core prop_wcslen_matches_first_nul_or_slice_len --lib -- --exact --nocapture --test-threads=1"
            ;;
        ctype_local)
            printf '%s' "cargo test -p frankenlibc-core prop_core_classification_invariants --lib -- --exact --nocapture --test-threads=1"
            ;;
        *)
            return 1
            ;;
    esac
}

run_suite() {
    local suite="$1" api_family symbol decision_path command expected failure_signature
    local start_ns end_ns latency_ns output status errno_value
    api_family="$(suite_api_family "${suite}")"
    symbol="$(suite_symbol "${suite}")"
    decision_path="$(suite_decision_path "${suite}")"
    command="$(suite_command "${suite}")"
    expected="$(suite_expected "${suite}")"
    failure_signature="$(suite_failure_signature "${suite}")"

    start_ns="$(date +%s%N)"
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
    end_ns="$(date +%s%N)"
    latency_ns="$((end_ns - start_ns))"

    printf '=== %s ===\ncommand: FRANKENLIBC_PROPTEST_CASES=%s rch exec -- env CARGO_HOME=%s CARGO_TARGET_DIR=%s %s\n%s\n\n' \
        "${suite}" "${PROPTEST_CASES}" "${RCH_CARGO_HOME}" "${RCH_TARGET_DIR}" "${command}" "${output}" >> "${TEST_OUTPUT_PATH}"

    printf '{"timestamp":"%s","trace_id":"%s::property_suite::%s","level":"info","event":"property_suite","bead_id":"%s","mode":"property","api_family":"%s","symbol":"%s","decision_path":"%s","healing_action":"none","outcome":"%s","errno":%s,"latency_ns":%s,"artifact_refs":["scripts/check_property_suite.sh","crates/frankenlibc-core/tests/property_tests.rs","crates/frankenlibc-membrane/src/lattice.rs","crates/frankenlibc-membrane/src/ptr_validator.rs","crates/frankenlibc-core/src/string/mem.rs","crates/frankenlibc-core/src/string/str.rs","crates/frankenlibc-core/src/string/wide.rs","crates/frankenlibc-core/src/ctype/mod.rs","target/conformance/%s.report.json","target/conformance/%s.log.jsonl","target/conformance/%s.test_output.log"]}\n' \
        "$(now_iso_ms)" "${BEAD_ID}" "${suite}" "${BEAD_ID}" "${api_family}" "${symbol}" "${decision_path}" "${status}" "${errno_value}" "${latency_ns}" "${ARTIFACT_BASENAME}" "${ARTIFACT_BASENAME}" "${ARTIFACT_BASENAME}" >> "${LOG_PATH}"

    SUITE_NAMES+=("${suite}")
    SUITE_STATUSES["${suite}"]="${status}"
    SUITE_COMMANDS["${suite}"]="FRANKENLIBC_PROPTEST_CASES=${PROPTEST_CASES} rch exec -- env CARGO_HOME=${RCH_CARGO_HOME} CARGO_TARGET_DIR=${RCH_TARGET_DIR} ${command}"
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
