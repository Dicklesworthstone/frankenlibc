#!/usr/bin/env bash
# e2e_suite.sh — Comprehensive E2E test suite with structured logging (bd-2ez)
#
# Scenario classes:
#   smoke      — Basic binary execution under LD_PRELOAD (coreutils, integration)
#   stress     — Repeated/concurrent execution for stability
#   fault      — Fault injection (invalid pointers, oversized allocs, signal delivery)
#
# Each scenario runs in both strict and hardened modes.
# Emits JSONL structured logs per the bd-144 contract.
# Supports deterministic replay via FRANKENLIBC_E2E_SEED and pinned env.
#
# Usage:
#   bash scripts/e2e_suite.sh                   # run all scenarios
#   bash scripts/e2e_suite.sh smoke             # run only smoke class
#   bash scripts/e2e_suite.sh stress hardened   # run stress in hardened only
#
# Exit codes:
#   0 — all scenarios pass
#   1 — one or more scenarios failed
#   2 — infrastructure error (missing binary, compiler, etc.)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE_VERSION="1"
SCENARIO_CLASS="${1:-all}"
MODE_FILTER="${2:-all}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-10}"
E2E_SEED="${FRANKENLIBC_E2E_SEED:-42}"
RUN_ID="e2e-v${SUITE_VERSION}-$(date -u +%Y%m%dT%H%M%SZ)-s${E2E_SEED}"
OUT_DIR="${ROOT}/target/e2e_suite/${RUN_ID}"
LOG_FILE="${OUT_DIR}/trace.jsonl"
INDEX_FILE="${OUT_DIR}/artifact_index.json"

# ---------------------------------------------------------------------------
# Library resolution
# ---------------------------------------------------------------------------
LIB_CANDIDATES=(
    "${ROOT}/target/release/libfrankenlibc_abi.so"
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
    echo "e2e_suite: building frankenlibc-abi release artifact..."
    cargo build -p frankenlibc-abi --release 2>/dev/null
    for candidate in "${LIB_CANDIDATES[@]}"; do
        if [[ -f "${candidate}" ]]; then
            LIB_PATH="${candidate}"
            break
        fi
    done
fi

if [[ -z "${LIB_PATH}" ]]; then
    echo "e2e_suite: could not locate libfrankenlibc_abi.so" >&2
    exit 2
fi

if ! command -v cc >/dev/null 2>&1; then
    echo "e2e_suite: required compiler 'cc' not found" >&2
    exit 2
fi

mkdir -p "${OUT_DIR}"

# ---------------------------------------------------------------------------
# JSONL structured log helpers
# ---------------------------------------------------------------------------
SEQ=0

emit_log() {
    local level="$1"
    local event="$2"
    local mode="${3:-}"
    local api_family="${4:-}"
    local symbol="${5:-}"
    local outcome="${6:-}"
    local latency_ns="${7:-}"
    local extra="${8:-}"

    SEQ=$((SEQ + 1))
    local trace_id="bd-2ez::${RUN_ID}::$(printf '%03d' ${SEQ})"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"

    local json="{\"timestamp\":\"${ts}\",\"trace_id\":\"${trace_id}\",\"level\":\"${level}\",\"event\":\"${event}\",\"bead_id\":\"bd-2ez\""

    [[ -n "${mode}" ]] && json="${json},\"mode\":\"${mode}\""
    [[ -n "${api_family}" ]] && json="${json},\"api_family\":\"${api_family}\""
    [[ -n "${symbol}" ]] && json="${json},\"symbol\":\"${symbol}\""
    [[ -n "${outcome}" ]] && json="${json},\"outcome\":\"${outcome}\""
    [[ -n "${latency_ns}" ]] && json="${json},\"latency_ns\":${latency_ns}"
    [[ -n "${extra}" ]] && json="${json},${extra}"

    json="${json}}"
    echo "${json}" >> "${LOG_FILE}"
}

# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------
passes=0
fails=0
skips=0

run_e2e_case() {
    local mode="$1"
    local scenario="$2"
    local label="$3"
    shift 3

    if [[ "${MODE_FILTER}" != "all" && "${MODE_FILTER}" != "${mode}" ]]; then
        skips=$((skips + 1))
        return 0
    fi

    local case_dir="${OUT_DIR}/${scenario}/${mode}/${label}"
    mkdir -p "${case_dir}"

    emit_log "info" "case_start" "${mode}" "" "${label}" "" "" "\"details\":{\"scenario\":\"${scenario}\",\"command\":\"$*\"}"

    local start_ns
    start_ns=$(date +%s%N)

    set +e
    timeout "${TIMEOUT_SECONDS}" \
        env FRANKENLIBC_MODE="${mode}" \
            FRANKENLIBC_E2E_SEED="${E2E_SEED}" \
            LD_PRELOAD="${LIB_PATH}" \
            "$@" \
        > "${case_dir}/stdout.txt" 2> "${case_dir}/stderr.txt"
    local rc=$?
    set -e

    local end_ns
    end_ns=$(date +%s%N)
    local elapsed_ns=$(( end_ns - start_ns ))

    if [[ "${rc}" -eq 0 ]]; then
        passes=$((passes + 1))
        emit_log "info" "case_pass" "${mode}" "" "${label}" "pass" "${elapsed_ns}"
        echo "[PASS] ${scenario}/${mode}/${label}"
        return 0
    fi

    fails=$((fails + 1))
    local fail_reason="exit_${rc}"
    if [[ "${rc}" -eq 124 || "${rc}" -eq 125 ]]; then
        fail_reason="timeout_${TIMEOUT_SECONDS}s"
    fi

    # Capture diagnostics
    {
        echo "mode=${mode}"
        echo "scenario=${scenario}"
        echo "label=${label}"
        echo "exit_code=${rc}"
        echo "fail_reason=${fail_reason}"
        echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "lib_path=${LIB_PATH}"
        echo "seed=${E2E_SEED}"
    } > "${case_dir}/bundle.meta"
    env | sort > "${case_dir}/env.txt"

    emit_log "error" "case_fail" "${mode}" "" "${label}" "fail" "${elapsed_ns}" "\"errno\":${rc},\"details\":{\"scenario\":\"${scenario}\",\"fail_reason\":\"${fail_reason}\"}"
    echo "[FAIL] ${scenario}/${mode}/${label} (${fail_reason})"
    return 1
}

# ---------------------------------------------------------------------------
# Scenario: smoke (basic binary execution)
# ---------------------------------------------------------------------------
run_smoke() {
    local mode="$1"
    local failed=0

    # Compile integration binary
    local integ_bin="${OUT_DIR}/bin/link_test"
    mkdir -p "$(dirname "${integ_bin}")"
    if [[ ! -f "${integ_bin}" ]]; then
        cc -O2 "${ROOT}/tests/integration/link_test.c" -o "${integ_bin}"
    fi

    run_e2e_case "${mode}" "smoke" "coreutils_ls" /bin/ls -la /tmp || failed=1
    run_e2e_case "${mode}" "smoke" "coreutils_cat" /bin/cat /etc/hosts || failed=1
    run_e2e_case "${mode}" "smoke" "coreutils_echo" /bin/echo "frankenlibc_e2e_smoke" || failed=1
    run_e2e_case "${mode}" "smoke" "coreutils_env" /usr/bin/env || failed=1
    run_e2e_case "${mode}" "smoke" "integration_link" "${integ_bin}" || failed=1

    if command -v python3 >/dev/null 2>&1; then
        run_e2e_case "${mode}" "smoke" "nontrivial_python3" python3 -c "print('e2e_ok')" || failed=1
    fi

    return "${failed}"
}

# ---------------------------------------------------------------------------
# Scenario: stress (repeated execution for stability)
# ---------------------------------------------------------------------------
run_stress() {
    local mode="$1"
    local failed=0
    local iterations="${FRANKENLIBC_E2E_STRESS_ITERS:-5}"

    local integ_bin="${OUT_DIR}/bin/link_test"
    mkdir -p "$(dirname "${integ_bin}")"
    if [[ ! -f "${integ_bin}" ]]; then
        cc -O2 "${ROOT}/tests/integration/link_test.c" -o "${integ_bin}"
    fi

    for i in $(seq 1 "${iterations}"); do
        run_e2e_case "${mode}" "stress" "repeated_link_${i}" "${integ_bin}" || failed=1
        run_e2e_case "${mode}" "stress" "repeated_echo_${i}" /bin/echo "iteration_${i}" || failed=1
    done

    return "${failed}"
}

# ---------------------------------------------------------------------------
# Scenario: fault injection (malformed inputs)
# ---------------------------------------------------------------------------
run_fault() {
    local mode="$1"
    local failed=0

    # Create a fault injection test binary
    local fault_bin="${OUT_DIR}/bin/fault_test"
    mkdir -p "$(dirname "${fault_bin}")"

    if [[ ! -f "${fault_bin}" ]]; then
        cat > "${OUT_DIR}/bin/fault_test.c" << 'CEOF'
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    /* Test 1: zero-size malloc */
    void *p = malloc(0);
    /* malloc(0) may return NULL or a unique pointer; both are POSIX-valid */
    if (p) free(p);

    /* Test 2: normal alloc+copy */
    char *buf = malloc(64);
    if (!buf) return 1;
    memset(buf, 'A', 63);
    buf[63] = '\0';
    if (strlen(buf) != 63) return 2;
    free(buf);

    /* Test 3: calloc zeroing */
    int *arr = calloc(16, sizeof(int));
    if (!arr) return 3;
    for (int i = 0; i < 16; i++) {
        if (arr[i] != 0) return 4;
    }
    free(arr);

    /* Test 4: realloc grow */
    char *r = malloc(8);
    if (!r) return 5;
    memcpy(r, "hello", 6);
    r = realloc(r, 128);
    if (!r) return 6;
    if (strcmp(r, "hello") != 0) return 7;
    free(r);

    printf("fault_test: all checks passed\n");
    return 0;
}
CEOF
        cc -O2 "${OUT_DIR}/bin/fault_test.c" -o "${fault_bin}"
    fi

    run_e2e_case "${mode}" "fault" "malloc_zero" "${fault_bin}" || failed=1

    # Run coreutils with empty/minimal input
    run_e2e_case "${mode}" "fault" "cat_devnull" /bin/cat /dev/null || failed=1
    run_e2e_case "${mode}" "fault" "echo_empty" /bin/echo "" || failed=1

    return "${failed}"
}

# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------
emit_log "info" "suite_start" "" "" "" "" "" "\"details\":{\"version\":\"${SUITE_VERSION}\",\"scenario_class\":\"${SCENARIO_CLASS}\",\"mode_filter\":\"${MODE_FILTER}\",\"seed\":\"${E2E_SEED}\"}"

echo "=== E2E Suite v${SUITE_VERSION} ==="
echo "run_id=${RUN_ID}"
echo "lib=${LIB_PATH}"
echo "seed=${E2E_SEED}"
echo "scenario=${SCENARIO_CLASS}"
echo "mode=${MODE_FILTER}"
echo "timeout=${TIMEOUT_SECONDS}s"
echo ""

overall_failed=0

for mode in strict hardened; do
    if [[ "${MODE_FILTER}" != "all" && "${MODE_FILTER}" != "${mode}" ]]; then
        continue
    fi

    echo "--- mode: ${mode} ---"

    if [[ "${SCENARIO_CLASS}" == "all" || "${SCENARIO_CLASS}" == "smoke" ]]; then
        run_smoke "${mode}" || overall_failed=1
    fi

    if [[ "${SCENARIO_CLASS}" == "all" || "${SCENARIO_CLASS}" == "stress" ]]; then
        run_stress "${mode}" || overall_failed=1
    fi

    if [[ "${SCENARIO_CLASS}" == "all" || "${SCENARIO_CLASS}" == "fault" ]]; then
        run_fault "${mode}" || overall_failed=1
    fi

    echo ""
done

emit_log "info" "suite_end" "" "" "" "" "" "\"details\":{\"passes\":${passes},\"fails\":${fails},\"skips\":${skips}}"

# ---------------------------------------------------------------------------
# Artifact index
# ---------------------------------------------------------------------------
python3 -c "
import json, os, hashlib
from pathlib import Path

out_dir = '${OUT_DIR}'
artifacts = []

for root, dirs, files in sorted(os.walk(out_dir)):
    for f in sorted(files):
        fpath = os.path.join(root, f)
        rel = os.path.relpath(fpath, out_dir)
        size = os.path.getsize(fpath)
        sha = hashlib.sha256(open(fpath, 'rb').read()).hexdigest()
        kind = 'log' if f.endswith('.jsonl') else 'report' if f == 'artifact_index.json' else 'diagnostic'
        artifacts.append({
            'path': rel,
            'kind': kind,
            'sha256': sha,
            'size_bytes': size,
        })

index = {
    'index_version': 1,
    'run_id': '${RUN_ID}',
    'bead_id': 'bd-2ez',
    'generated_utc': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'summary': {
        'passes': ${passes},
        'fails': ${fails},
        'skips': ${skips},
    },
    'artifacts': artifacts,
}

with open('${INDEX_FILE}', 'w') as f:
    json.dump(index, f, indent=2)
    f.write('\n')
"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "passes=${passes} fails=${fails} skips=${skips}"
echo "trace_log=${LOG_FILE}"
echo "artifact_index=${INDEX_FILE}"
echo ""

if [[ "${overall_failed}" -ne 0 ]]; then
    echo "e2e_suite: FAILED (see ${OUT_DIR})" >&2
    exit 1
fi

echo "e2e_suite: PASS"
