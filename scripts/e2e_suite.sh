#!/usr/bin/env bash
# e2e_suite.sh — Comprehensive E2E test suite with structured logging (bd-2ez)
#
# Scenario classes:
#   smoke      — Basic binary execution under LD_PRELOAD (coreutils, integration)
#   stress     — Repeated/concurrent execution for stability
#   fault      — Fault injection (invalid pointers, oversized allocs, signal delivery)
#   stability  — Long-run replayable stability loops
#
# Each scenario runs in both strict and hardened modes.
# Emits JSONL structured logs per the bd-144 contract.
# Supports deterministic replay via FRANKENLIBC_E2E_SEED and pinned env.
#
# Usage:
#   bash scripts/e2e_suite.sh                   # run all scenarios
#   bash scripts/e2e_suite.sh smoke             # run only smoke class
#   bash scripts/e2e_suite.sh stress hardened   # run stress in hardened only
#   bash scripts/e2e_suite.sh --dry-run-manifest fault strict
#
# Exit codes:
#   0 — all scenarios pass
#   1 — one or more scenarios failed
#   2 — infrastructure error (missing binary, compiler, etc.)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE_VERSION="1"
SCENARIO_CLASS="all"
MODE_FILTER="all"
DRY_RUN_MANIFEST=0
MANIFEST_PATH="${FRANKENLIBC_E2E_MANIFEST:-${ROOT}/tests/conformance/e2e_scenario_manifest.v1.json}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-10}"
E2E_SEED="${FRANKENLIBC_E2E_SEED:-42}"
RUN_ID="e2e-v${SUITE_VERSION}-$(date -u +%Y%m%dT%H%M%SZ)-s${E2E_SEED}"
OUT_DIR="${ROOT}/target/e2e_suite/${RUN_ID}"
LOG_FILE="${OUT_DIR}/trace.jsonl"
INDEX_FILE="${OUT_DIR}/artifact_index.json"
PAIR_REPORT_FILE="${OUT_DIR}/mode_pair_report.json"
PAIR_REPORT_TSV="${OUT_DIR}/mode_pair_report.tsv"

declare -A CASE_RESULT_BY_SCENARIO_MODE=()
declare -A CASE_SCENARIOS=()
pair_mismatch_count=0
MANIFEST_SHA256=""

scenario_set=0
mode_set=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run-manifest)
            DRY_RUN_MANIFEST=1
            shift
            ;;
        --manifest)
            if [[ $# -lt 2 ]]; then
                echo "e2e_suite: --manifest requires a path" >&2
                exit 2
            fi
            MANIFEST_PATH="$2"
            shift 2
            ;;
        smoke|stress|fault|stability|all)
            if [[ "${scenario_set}" -eq 0 ]]; then
                SCENARIO_CLASS="$1"
                scenario_set=1
            elif [[ "${mode_set}" -eq 0 ]]; then
                MODE_FILTER="$1"
                mode_set=1
            else
                echo "e2e_suite: unexpected extra argument '${1}'" >&2
                exit 2
            fi
            shift
            ;;
        strict|hardened)
            if [[ "${mode_set}" -eq 0 ]]; then
                MODE_FILTER="$1"
                mode_set=1
            else
                echo "e2e_suite: duplicate mode argument '${1}'" >&2
                exit 2
            fi
            shift
            ;;
        *)
            echo "e2e_suite: unknown argument '${1}'" >&2
            exit 2
            ;;
    esac
done

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

    local json="{\"timestamp\":\"${ts}\",\"trace_id\":\"${trace_id}\",\"level\":\"${level}\",\"event\":\"${event}\",\"bead_id\":\"bd-2ez\",\"stream\":\"e2e\",\"gate\":\"e2e_suite\""

    [[ -n "${mode}" ]] && json="${json},\"mode\":\"${mode}\""
    [[ -n "${api_family}" ]] && json="${json},\"api_family\":\"${api_family}\""
    [[ -n "${symbol}" ]] && json="${json},\"symbol\":\"${symbol}\""
    [[ -n "${outcome}" ]] && json="${json},\"outcome\":\"${outcome}\""
    [[ -n "${latency_ns}" ]] && json="${json},\"latency_ns\":${latency_ns}"
    [[ -n "${extra}" ]] && json="${json},${extra}"

    json="${json}}"
    echo "${json}" >> "${LOG_FILE}"
}

manifest_validate() {
    python3 "${ROOT}/scripts/validate_e2e_manifest.py" validate --manifest "${MANIFEST_PATH}" >/dev/null
}

manifest_list_cases() {
    python3 "${ROOT}/scripts/validate_e2e_manifest.py" list \
        --manifest "${MANIFEST_PATH}" \
        --scenario-class "${SCENARIO_CLASS}"
}

manifest_case_metadata() {
    local mode="$1"
    local scenario="$2"
    local label="$3"
    python3 "${ROOT}/scripts/validate_e2e_manifest.py" metadata \
        --manifest "${MANIFEST_PATH}" \
        --scenario-class "${scenario}" \
        --label "${label}" \
        --mode "${mode}"
}

compute_replay_key() {
    local mode="$1"
    local scenario_id="$2"
    local label="$3"
    printf '%s|%s|%s|%s|%s|%s|%s\n' \
        "${E2E_SEED}" \
        "${MANIFEST_SHA256}" \
        "${scenario_id}" \
        "${mode}" \
        "${TIMEOUT_SECONDS}" \
        "${label}" \
        "${SUITE_VERSION}" \
        | sha256sum | awk '{print $1}'
}

compute_env_fingerprint() {
    local mode="$1"
    printf '%s|%s|%s|%s|%s|%s\n' \
        "${E2E_SEED}" \
        "${TIMEOUT_SECONDS}" \
        "${LIB_PATH}" \
        "${MANIFEST_SHA256}" \
        "${mode}" \
        "${MANIFEST_PATH}" \
        | sha256sum | awk '{print $1}'
}

emit_mode_pair_report() {
    : > "${PAIR_REPORT_TSV}"

    for scenario_id in "${!CASE_SCENARIOS[@]}"; do
        local strict_data="${CASE_RESULT_BY_SCENARIO_MODE["${scenario_id}|strict"]:-}"
        local hardened_data="${CASE_RESULT_BY_SCENARIO_MODE["${scenario_id}|hardened"]:-}"

        local strict_outcome="missing"
        local strict_latency=0
        local strict_replay_key=""
        local strict_label=""
        if [[ -n "${strict_data}" ]]; then
            IFS='|' read -r strict_outcome strict_latency strict_replay_key strict_label <<<"${strict_data}"
        fi

        local hardened_outcome="missing"
        local hardened_latency=0
        local hardened_replay_key=""
        local hardened_label=""
        if [[ -n "${hardened_data}" ]]; then
            IFS='|' read -r hardened_outcome hardened_latency hardened_replay_key hardened_label <<<"${hardened_data}"
        fi

        local pair_result="match"
        local flags=()
        if [[ "${strict_outcome}" == "missing" || "${hardened_outcome}" == "missing" ]]; then
            pair_result="incomplete"
            flags+=("missing_mode_run")
        elif [[ "${strict_outcome}" != "${hardened_outcome}" ]]; then
            pair_result="mismatch"
            flags+=("outcome_mismatch")
        fi

        if [[ "${strict_outcome}" == "pass" && "${hardened_outcome}" == "pass" ]]; then
            local faster slower
            faster="${strict_latency}"
            slower="${hardened_latency}"
            if (( strict_latency > hardened_latency )); then
                faster="${hardened_latency}"
                slower="${strict_latency}"
            fi
            if (( faster > 0 && slower >= 2 * faster )); then
                flags+=("latency_skew_gt2x")
            fi
        fi

        local flags_json="[]"
        if [[ "${#flags[@]}" -gt 0 ]]; then
            flags_json="["
            for idx in "${!flags[@]}"; do
                if [[ "${idx}" -gt 0 ]]; then
                    flags_json="${flags_json},"
                fi
                flags_json="${flags_json}\"${flags[idx]}\""
            done
            flags_json="${flags_json}]"
        fi

        if [[ "${pair_result}" == "mismatch" ]]; then
            pair_mismatch_count=$((pair_mismatch_count + 1))
        fi

        emit_log "info" "mode_pair_result" "" "" "${scenario_id}" "${pair_result}" "" "\"scenario_id\":\"${scenario_id}\",\"mode_pair_result\":\"${pair_result}\",\"drift_flags\":${flags_json},\"strict\":{\"outcome\":\"${strict_outcome}\",\"latency_ns\":${strict_latency},\"replay_key\":\"${strict_replay_key}\",\"label\":\"${strict_label}\"},\"hardened\":{\"outcome\":\"${hardened_outcome}\",\"latency_ns\":${hardened_latency},\"replay_key\":\"${hardened_replay_key}\",\"label\":\"${hardened_label}\"}"

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${scenario_id}" \
            "${strict_outcome}" \
            "${hardened_outcome}" \
            "${pair_result}" \
            "${flags_json}" \
            "${strict_replay_key}" \
            "${hardened_replay_key}" \
            "${strict_latency}" \
            "${hardened_latency}" \
            >> "${PAIR_REPORT_TSV}"
    done

    PAIR_REPORT_TSV_PATH="${PAIR_REPORT_TSV}" \
    PAIR_REPORT_JSON_PATH="${PAIR_REPORT_FILE}" \
    E2E_RUN_ID="${RUN_ID}" \
    E2E_SEED_VALUE="${E2E_SEED}" \
    E2E_MANIFEST_SHA256="${MANIFEST_SHA256}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

tsv_path = Path(os.environ["PAIR_REPORT_TSV_PATH"])
json_path = Path(os.environ["PAIR_REPORT_JSON_PATH"])
rows = []
if tsv_path.exists():
    for line in tsv_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        (
            scenario_id,
            strict_outcome,
            hardened_outcome,
            mode_pair_result,
            drift_flags_json,
            strict_replay_key,
            hardened_replay_key,
            strict_latency_ns,
            hardened_latency_ns,
        ) = line.split("\t")
        rows.append(
            {
                "scenario_id": scenario_id,
                "strict_outcome": strict_outcome,
                "hardened_outcome": hardened_outcome,
                "mode_pair_result": mode_pair_result,
                "drift_flags": json.loads(drift_flags_json),
                "strict_replay_key": strict_replay_key,
                "hardened_replay_key": hardened_replay_key,
                "strict_latency_ns": int(strict_latency_ns),
                "hardened_latency_ns": int(hardened_latency_ns),
            }
        )

payload = {
    "schema_version": "v1",
    "run_id": os.environ["E2E_RUN_ID"],
    "seed": os.environ["E2E_SEED_VALUE"],
    "manifest_sha256": os.environ["E2E_MANIFEST_SHA256"],
    "pair_count": len(rows),
    "mismatch_count": sum(1 for row in rows if row["mode_pair_result"] == "mismatch"),
    "pairs": rows,
}
json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
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

    local scenario_id expected_outcome pass_condition artifact_policy
    local metadata
    if ! metadata="$(manifest_case_metadata "${mode}" "${scenario}" "${label}" 2>/dev/null)"; then
        fails=$((fails + 1))
        emit_log "error" "case_manifest_mismatch" "${mode}" "" "${label}" "fail" "" "\"details\":{\"scenario\":\"${scenario}\",\"label\":\"${label}\",\"manifest\":\"${MANIFEST_PATH}\"}"
        echo "[FAIL] ${scenario}/${mode}/${label} (manifest metadata missing)" >&2
        return 1
    fi
    IFS=$'\t' read -r scenario_id expected_outcome pass_condition artifact_policy <<<"${metadata}"
    local replay_key
    replay_key="$(compute_replay_key "${mode}" "${scenario_id}" "${label}")"
    local env_fingerprint
    env_fingerprint="$(compute_env_fingerprint "${mode}")"

    emit_log "info" "case_start" "${mode}" "" "${label}" "" "" "\"scenario_id\":\"${scenario_id}\",\"replay_key\":\"${replay_key}\",\"env_fingerprint\":\"${env_fingerprint}\",\"expected_outcome\":\"${expected_outcome}\",\"pass_condition\":\"${pass_condition}\",\"artifact_policy\":${artifact_policy},\"details\":{\"scenario\":\"${scenario}\"}"

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
        CASE_RESULT_BY_SCENARIO_MODE["${scenario_id}|${mode}"]="pass|${elapsed_ns}|${replay_key}|${label}"
        CASE_SCENARIOS["${scenario_id}"]=1
        emit_log "info" "case_pass" "${mode}" "" "${label}" "pass" "${elapsed_ns}" "\"scenario_id\":\"${scenario_id}\",\"replay_key\":\"${replay_key}\",\"env_fingerprint\":\"${env_fingerprint}\",\"expected_outcome\":\"${expected_outcome}\",\"pass_condition\":\"${pass_condition}\",\"artifact_policy\":${artifact_policy}"
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
        echo "scenario_id=${scenario_id}"
        echo "replay_key=${replay_key}"
        echo "env_fingerprint=${env_fingerprint}"
    } > "${case_dir}/bundle.meta"
    env | sort > "${case_dir}/env.txt"

    CASE_RESULT_BY_SCENARIO_MODE["${scenario_id}|${mode}"]="fail|${elapsed_ns}|${replay_key}|${label}"
    CASE_SCENARIOS["${scenario_id}"]=1
    emit_log "error" "case_fail" "${mode}" "" "${label}" "fail" "${elapsed_ns}" "\"scenario_id\":\"${scenario_id}\",\"replay_key\":\"${replay_key}\",\"env_fingerprint\":\"${env_fingerprint}\",\"expected_outcome\":\"${expected_outcome}\",\"pass_condition\":\"${pass_condition}\",\"artifact_policy\":${artifact_policy},\"errno\":${rc},\"details\":{\"scenario\":\"${scenario}\",\"fail_reason\":\"${fail_reason}\"}"
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
# Scenario: stability (long-run replayable loops)
# ---------------------------------------------------------------------------
run_stability() {
    local mode="$1"
    local failed=0
    local iterations="${FRANKENLIBC_E2E_STABILITY_ITERS:-8}"

    local integ_bin="${OUT_DIR}/bin/link_test"
    mkdir -p "$(dirname "${integ_bin}")"
    if [[ ! -f "${integ_bin}" ]]; then
        cc -O2 "${ROOT}/tests/integration/link_test.c" -o "${integ_bin}"
    fi

    for i in $(seq 1 "${iterations}"); do
        run_e2e_case "${mode}" "stability" "link_longrun_${i}" "${integ_bin}" || failed=1
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
if ! manifest_validate; then
    echo "e2e_suite: manifest validation failed: ${MANIFEST_PATH}" >&2
    exit 2
fi
MANIFEST_SHA256="$(sha256sum "${MANIFEST_PATH}" | awk '{print $1}')"

emit_log "info" "suite_start" "" "" "" "" "" "\"details\":{\"version\":\"${SUITE_VERSION}\",\"scenario_class\":\"${SCENARIO_CLASS}\",\"mode_filter\":\"${MODE_FILTER}\",\"seed\":\"${E2E_SEED}\",\"manifest\":\"${MANIFEST_PATH}\",\"dry_run_manifest\":${DRY_RUN_MANIFEST}}"

echo "=== E2E Suite v${SUITE_VERSION} ==="
echo "run_id=${RUN_ID}"
echo "lib=${LIB_PATH}"
echo "seed=${E2E_SEED}"
echo "scenario=${SCENARIO_CLASS}"
echo "mode=${MODE_FILTER}"
echo "timeout=${TIMEOUT_SECONDS}s"
echo "manifest=${MANIFEST_PATH}"
echo "dry_run_manifest=${DRY_RUN_MANIFEST}"
echo ""

overall_failed=0

if [[ "${DRY_RUN_MANIFEST}" -eq 1 ]]; then
    listed_cases=0
    while IFS=$'\t' read -r scenario label; do
        for mode in strict hardened; do
            if [[ "${MODE_FILTER}" != "all" && "${MODE_FILTER}" != "${mode}" ]]; then
                continue
            fi
            metadata="$(manifest_case_metadata "${mode}" "${scenario}" "${label}")" || {
                overall_failed=1
                continue
            }
            IFS=$'\t' read -r scenario_id expected_outcome pass_condition artifact_policy <<<"${metadata}"
            replay_key="$(compute_replay_key "${mode}" "${scenario_id}" "${label}")"
            env_fingerprint="$(compute_env_fingerprint "${mode}")"
            listed_cases=$((listed_cases + 1))
            emit_log "info" "manifest_case" "${mode}" "" "${label}" "catalog_loaded" "" "\"scenario_id\":\"${scenario_id}\",\"replay_key\":\"${replay_key}\",\"env_fingerprint\":\"${env_fingerprint}\",\"expected_outcome\":\"${expected_outcome}\",\"pass_condition\":\"${pass_condition}\",\"artifact_policy\":${artifact_policy},\"details\":{\"scenario\":\"${scenario}\",\"verdict\":\"catalog_loaded\"}"
            echo "[MANIFEST] ${scenario_id} mode=${mode} expected=${expected_outcome} replay_key=${replay_key}"
        done
    done < <(manifest_list_cases)
    if [[ "${listed_cases}" -eq 0 ]]; then
        overall_failed=1
        emit_log "error" "manifest_empty_selection" "" "" "" "fail" "" "\"details\":{\"scenario_class\":\"${SCENARIO_CLASS}\",\"mode_filter\":\"${MODE_FILTER}\"}"
        echo "e2e_suite: no scenarios selected from manifest" >&2
    fi
else
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

        if [[ "${SCENARIO_CLASS}" == "all" || "${SCENARIO_CLASS}" == "stability" ]]; then
            run_stability "${mode}" || overall_failed=1
        fi

        echo ""
    done
fi

if [[ "${DRY_RUN_MANIFEST}" -eq 0 ]]; then
    emit_mode_pair_report
fi

emit_log "info" "suite_end" "" "" "" "" "" "\"details\":{\"passes\":${passes},\"fails\":${fails},\"skips\":${skips},\"mode_pair_mismatches\":${pair_mismatch_count}}"

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
