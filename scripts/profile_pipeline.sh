#!/usr/bin/env bash
# profile_pipeline.sh — reproducible CPU/alloc/syscall profiling for critical benches.
#
# Produces timestamped artifacts under target/profiles/ so optimization rounds can be compared.
# Default scope is strict-mode critical benches; use MODE=hardened for hardened.
#
# Usage:
#   scripts/profile_pipeline.sh
#   MODE=hardened PROFILE_TIME=2 scripts/profile_pipeline.sh
#   MODE=strict PROFILE_TARGETS="runtime_math_decide_strict membrane_validate_known_strict" scripts/profile_pipeline.sh
#
# Environment:
#   MODE             strict|hardened (default: strict)
#   PROFILE_TIME     Criterion profile time in seconds per benchmark (default: 1)
#   PROFILE_FREQ     perf sampling frequency for perf record (default: 199)
#   OUT_ROOT         Output root directory (default: target/profiles)
#   PROFILE_TARGETS  Space-delimited slugs to profile (default: all critical slugs)

set -euo pipefail

MODE="${MODE:-strict}"
PROFILE_TIME="${PROFILE_TIME:-1}"
PROFILE_FREQ="${PROFILE_FREQ:-199}"
OUT_ROOT="${OUT_ROOT:-target/profiles}"
RUN_TS="${RUN_TS:-$(date -u +%Y%m%dT%H%M%SZ)}"

if [[ "${MODE}" != "strict" && "${MODE}" != "hardened" ]]; then
    echo "ERROR: MODE must be strict or hardened (got: ${MODE})" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo not found in PATH" >&2
    exit 1
fi
if ! command -v perf >/dev/null 2>&1; then
    echo "ERROR: perf not found in PATH" >&2
    exit 1
fi
if ! command -v strace >/dev/null 2>&1; then
    echo "ERROR: strace not found in PATH" >&2
    exit 1
fi
if ! command -v cargo-flamegraph >/dev/null 2>&1; then
    echo "ERROR: cargo-flamegraph not found in PATH" >&2
    exit 1
fi
CARGO_BIN="$(command -v cargo)"
ORIG_PERF_PARANOID=""
PARANOID_ADJUSTED=0

if [[ -r /proc/sys/kernel/perf_event_paranoid ]]; then
    ORIG_PERF_PARANOID="$(cat /proc/sys/kernel/perf_event_paranoid)"
    if [[ "${ORIG_PERF_PARANOID}" -ge 2 ]]; then
        if ! sudo -n true >/dev/null 2>&1; then
            echo "ERROR: perf_event_paranoid=${ORIG_PERF_PARANOID} requires sudo -n to lower temporarily" >&2
            exit 1
        fi
        sudo -n sysctl -w kernel.perf_event_paranoid=1 >/dev/null
        PARANOID_ADJUSTED=1
    fi
fi

restore_perf_paranoid() {
    if [[ "${PARANOID_ADJUSTED}" -eq 1 && -n "${ORIG_PERF_PARANOID}" ]]; then
        sudo -n sysctl -w "kernel.perf_event_paranoid=${ORIG_PERF_PARANOID}" >/dev/null || true
    fi
}
trap restore_perf_paranoid EXIT

RUN_DIR="${OUT_ROOT}/${RUN_TS}/${MODE}"
CPU_DIR="${RUN_DIR}/cpu"
ALLOC_DIR="${RUN_DIR}/alloc"
SYSCALL_DIR="${RUN_DIR}/syscall"
mkdir -p "${CPU_DIR}" "${ALLOC_DIR}" "${SYSCALL_DIR}"

COMMAND_LOG="${RUN_DIR}/commands.log"
SUMMARY_LOG="${RUN_DIR}/summary.log"
MANIFEST="${RUN_DIR}/manifest.txt"

declare -a TARGET_MATRIX=(
    "runtime_math_bench|runtime_math/decide/${MODE}|runtime_math_decide_${MODE}"
    "runtime_math_bench|runtime_math/observe_fast/${MODE}|runtime_math_observe_fast_${MODE}"
    "runtime_math_bench|runtime_math/decide_observe/${MODE}|runtime_math_decide_observe_${MODE}"
    "membrane_bench|validate_known|membrane_validate_known_${MODE}"
)

if [[ -n "${PROFILE_TARGETS:-}" ]]; then
    declare -a FILTERED=()
    for row in "${TARGET_MATRIX[@]}"; do
        slug="${row##*|}"
        for wanted in ${PROFILE_TARGETS}; do
            if [[ "${slug}" == "${wanted}" ]]; then
                FILTERED+=("${row}")
            fi
        done
    done
    TARGET_MATRIX=("${FILTERED[@]}")
fi

if [[ "${#TARGET_MATRIX[@]}" -eq 0 ]]; then
    echo "ERROR: no targets selected; check PROFILE_TARGETS" >&2
    exit 1
fi

append_cmd() {
    printf '%s\n' "$*" >>"${COMMAND_LOG}"
}

extract_cpu_top5() {
    local perf_data="$1"
    local out_file="$2"
    perf report -i "${perf_data}" --stdio --no-children --sort=symbol \
        | awk '/^ *[0-9]+\.[0-9]+%/ {print; c++; if (c==5) exit}' >"${out_file}"
}

extract_alloc_top5() {
    local perf_data="$1"
    local out_file="$2"
    local raw_file="${out_file%.top5.txt}.report.txt"
    perf report -i "${perf_data}" --stdio --no-children --sort=symbol >"${raw_file}"

    grep -Ei 'alloc|malloc|calloc|realloc|free|__rdl|jemalloc|mmap|munmap|brk' "${raw_file}" \
        | head -n 5 >"${out_file}" || true

    if [[ ! -s "${out_file}" ]]; then
        awk '/^ *[0-9]+\.[0-9]+%/ {print; c++; if (c==5) exit}' "${raw_file}" >"${out_file}"
    fi
}

extract_syscall_top5() {
    local strace_file="$1"
    local out_file="$2"
    awk '/^ *[0-9]+\.[0-9]+/ {print; c++; if (c==5) exit}' "${strace_file}" >"${out_file}"
}

profile_target() {
    local bench="$1"
    local bench_id="$2"
    local slug="$3"

    echo "== Profiling ${slug} ==" | tee -a "${SUMMARY_LOG}"

    local cpu_svg="${CPU_DIR}/${slug}.svg"
    local cpu_data="${CPU_DIR}/${slug}.perf.data"
    local cpu_top5="${CPU_DIR}/${slug}.top5.txt"

    append_cmd "FRANKENLIBC_MODE=${MODE} CARGO_PROFILE_BENCH_DEBUG=true cargo flamegraph -F ${PROFILE_FREQ} -p frankenlibc-bench --bench ${bench} --deterministic -o ${cpu_svg} -- --bench --profile-time ${PROFILE_TIME} --exact ${bench_id}"
    FRANKENLIBC_MODE="${MODE}" CARGO_PROFILE_BENCH_DEBUG=true \
        cargo flamegraph -F "${PROFILE_FREQ}" -p frankenlibc-bench --bench "${bench}" --deterministic \
        -o "${cpu_svg}" -- \
        --bench --profile-time "${PROFILE_TIME}" --exact "${bench_id}"

    if [[ -f perf.data ]]; then
        mv perf.data "${cpu_data}"
        extract_cpu_top5 "${cpu_data}" "${cpu_top5}"
    else
        echo "WARN: perf.data missing after flamegraph for ${slug}" | tee -a "${SUMMARY_LOG}"
    fi

    local alloc_data="${ALLOC_DIR}/${slug}.perf.data"
    local alloc_top5="${ALLOC_DIR}/${slug}.top5.txt"
    append_cmd "perf record -F ${PROFILE_FREQ} -g -o ${alloc_data} -- env FRANKENLIBC_MODE=${MODE} ${CARGO_BIN} bench -p frankenlibc-bench --bench ${bench} -- --profile-time ${PROFILE_TIME} --exact ${bench_id}"
    perf record -F "${PROFILE_FREQ}" -g -o "${alloc_data}" -- \
        env FRANKENLIBC_MODE="${MODE}" "${CARGO_BIN}" bench -p frankenlibc-bench --bench "${bench}" -- \
            --profile-time "${PROFILE_TIME}" --exact "${bench_id}" >/dev/null
    extract_alloc_top5 "${alloc_data}" "${alloc_top5}"

    local syscall_raw="${SYSCALL_DIR}/${slug}.strace.txt"
    local syscall_top5="${SYSCALL_DIR}/${slug}.top5.txt"
    append_cmd "strace -f -qq -c -o ${syscall_raw} env FRANKENLIBC_MODE=${MODE} ${CARGO_BIN} bench -p frankenlibc-bench --bench ${bench} -- --profile-time ${PROFILE_TIME} --exact ${bench_id}"
    strace -f -qq -c -o "${syscall_raw}" \
        env FRANKENLIBC_MODE="${MODE}" "${CARGO_BIN}" bench -p frankenlibc-bench --bench "${bench}" -- \
            --profile-time "${PROFILE_TIME}" --exact "${bench_id}" >/dev/null 2>&1
    extract_syscall_top5 "${syscall_raw}" "${syscall_top5}"

    echo "  CPU top-5: ${cpu_top5}" | tee -a "${SUMMARY_LOG}"
    echo "  Alloc top-5: ${alloc_top5}" | tee -a "${SUMMARY_LOG}"
    echo "  Syscall top-5: ${syscall_top5}" | tee -a "${SUMMARY_LOG}"
    echo "" | tee -a "${SUMMARY_LOG}"
}

{
    echo "run_ts=${RUN_TS}"
    echo "mode=${MODE}"
    echo "profile_time=${PROFILE_TIME}"
    echo "profile_freq=${PROFILE_FREQ}"
    echo "run_dir=${RUN_DIR}"
} >"${MANIFEST}"

for row in "${TARGET_MATRIX[@]}"; do
    IFS='|' read -r bench bench_id slug <<<"${row}"
    profile_target "${bench}" "${bench_id}" "${slug}"
done

echo "Profiling complete."
echo "Artifacts: ${RUN_DIR}"
echo "Command log: ${COMMAND_LOG}"
echo "Summary: ${SUMMARY_LOG}"
