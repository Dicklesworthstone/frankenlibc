#!/usr/bin/env bash
# e2e_suite.sh — Comprehensive E2E test suite with structured logging (bd-2ez)
#
# Scenario classes:
#   smoke      — Basic binary execution plus shadow-diff comparisons against host runs
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
RETRY_MAX="${FRANKENLIBC_E2E_RETRY_MAX:-1}"
RETRY_ON_NONZERO="${FRANKENLIBC_E2E_RETRY_ON_NONZERO:-1}"
RETRYABLE_CODES="${FRANKENLIBC_E2E_RETRYABLE_CODES:-124,125}"
FLAKE_QUARANTINE_THRESHOLD="${FRANKENLIBC_E2E_FLAKE_QUARANTINE_THRESHOLD:-0.34}"

PACK_MAX_FAILS_SMOKE="${FRANKENLIBC_E2E_PACK_MAX_FAILS_SMOKE:-2}"
PACK_MAX_FAILS_STRESS="${FRANKENLIBC_E2E_PACK_MAX_FAILS_STRESS:-4}"
PACK_MAX_FAILS_FAULT="${FRANKENLIBC_E2E_PACK_MAX_FAILS_FAULT:-6}"
PACK_MAX_FAILS_STABILITY="${FRANKENLIBC_E2E_PACK_MAX_FAILS_STABILITY:-4}"

PACK_MAX_QUARANTINED_SMOKE="${FRANKENLIBC_E2E_PACK_MAX_QUARANTINED_SMOKE:-0}"
PACK_MAX_QUARANTINED_STRESS="${FRANKENLIBC_E2E_PACK_MAX_QUARANTINED_STRESS:-2}"
PACK_MAX_QUARANTINED_FAULT="${FRANKENLIBC_E2E_PACK_MAX_QUARANTINED_FAULT:-2}"
PACK_MAX_QUARANTINED_STABILITY="${FRANKENLIBC_E2E_PACK_MAX_QUARANTINED_STABILITY:-2}"

RUN_ID="e2e-v${SUITE_VERSION}-$(date -u +%Y%m%dT%H%M%SZ)-p$$-s${E2E_SEED}"
OUT_DIR="${ROOT}/target/e2e_suite/${RUN_ID}"
LOG_FILE="${OUT_DIR}/trace.jsonl"
INDEX_FILE="${OUT_DIR}/artifact_index.json"
PAIR_REPORT_FILE="${OUT_DIR}/mode_pair_report.json"
PAIR_REPORT_TSV="${OUT_DIR}/mode_pair_report.tsv"
PACK_REPORT_FILE="${OUT_DIR}/scenario_pack_report.json"
QUARANTINE_REPORT_FILE="${OUT_DIR}/flake_quarantine_report.json"
QUARANTINE_TSV="${OUT_DIR}/flake_quarantine.tsv"
FLAKE_POLICY="${ROOT}/scripts/e2e_flake_policy.py"

declare -A CASE_RESULT_BY_SCENARIO_MODE=()
declare -A CASE_SCENARIOS=()
declare -A PACK_FAILS=()
declare -A PACK_FLAKES=()
declare -A PACK_QUARANTINED=()
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
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    LIB_CANDIDATES+=("${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so")
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "e2e_suite: required runtime 'python3' not found" >&2
    exit 2
fi

if [[ ! -f "${FLAKE_POLICY}" ]]; then
    echo "e2e_suite: missing flake policy helper: ${FLAKE_POLICY}" >&2
    exit 2
fi

mkdir -p "${OUT_DIR}"
: > "${QUARANTINE_TSV}"

LIB_PATH="${FRANKENLIBC_E2E_LIB_PATH:-}"

echo "=== E2E Suite v${SUITE_VERSION} ==="
echo "run_id=${RUN_ID}"
echo "lib=${LIB_PATH:-unresolved}"
echo "seed=${E2E_SEED}"
echo "scenario=${SCENARIO_CLASS}"
echo "mode=${MODE_FILTER}"
echo "timeout=${TIMEOUT_SECONDS}s"
echo "manifest=${MANIFEST_PATH}"
echo "dry_run_manifest=${DRY_RUN_MANIFEST}"
echo "retry_max=${RETRY_MAX}"
echo "retry_on_nonzero=${RETRY_ON_NONZERO}"
echo "retryable_codes=${RETRYABLE_CODES}"
echo "flake_quarantine_threshold=${FLAKE_QUARANTINE_THRESHOLD}"
echo ""

if [[ "${DRY_RUN_MANIFEST}" -eq 0 ]]; then
    if [[ -z "${LIB_PATH}" ]]; then
        for candidate in "${LIB_CANDIDATES[@]}"; do
            if [[ -f "${candidate}" ]]; then
                LIB_PATH="${candidate}"
                break
            fi
        done
    fi

    if [[ -z "${LIB_PATH}" ]]; then
        echo "e2e_suite: building frankenlibc-abi release artifact..."
        if ! command -v rch >/dev/null 2>&1; then
            echo "e2e_suite: rch is required for cargo build offload but was not found in PATH" >&2
            exit 2
        fi
        rch exec -- cargo build -p frankenlibc-abi --release
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
else
    LIB_PATH="${LIB_PATH:-dry-run-manifest}"
fi

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

pack_max_fails() {
    local pack="$1"
    case "${pack}" in
        smoke) echo "${PACK_MAX_FAILS_SMOKE}" ;;
        stress) echo "${PACK_MAX_FAILS_STRESS}" ;;
        fault) echo "${PACK_MAX_FAILS_FAULT}" ;;
        stability) echo "${PACK_MAX_FAILS_STABILITY}" ;;
        *) echo "0" ;;
    esac
}

pack_max_quarantined() {
    local pack="$1"
    case "${pack}" in
        smoke) echo "${PACK_MAX_QUARANTINED_SMOKE}" ;;
        stress) echo "${PACK_MAX_QUARANTINED_STRESS}" ;;
        fault) echo "${PACK_MAX_QUARANTINED_FAULT}" ;;
        stability) echo "${PACK_MAX_QUARANTINED_STABILITY}" ;;
        *) echo "0" ;;
    esac
}

classify_attempt_history() {
    local exit_codes_csv="$1"
    python3 "${FLAKE_POLICY}" classify \
        --exit-codes "${exit_codes_csv}" \
        --quarantine-threshold "${FLAKE_QUARANTINE_THRESHOLD}"
}

should_retry_attempt() {
    local exit_code="$1"
    local attempt_index="$2"
    python3 "${FLAKE_POLICY}" should-retry \
        --exit-code "${exit_code}" \
        --attempt-index "${attempt_index}" \
        --max-retries "${RETRY_MAX}" \
        --retry-on-any-nonzero "${RETRY_ON_NONZERO}" \
        --retryable-codes "${RETRYABLE_CODES}"
}

classify_failure_signature() {
    local exit_code="$1"
    local stdout_path="$2"
    local stderr_path="$3"

    local stdout_size=0
    local stderr_size=0
    if [[ -f "${stdout_path}" ]]; then
        stdout_size=$(wc -c < "${stdout_path}" | tr -d ' ')
    fi
    if [[ -f "${stderr_path}" ]]; then
        stderr_size=$(wc -c < "${stderr_path}" | tr -d ' ')
    fi

    local startup_path="steady_state"
    local failure_signature="none"
    local signature_guard_triggered=0

    if [[ "${exit_code}" -eq 124 || "${exit_code}" -eq 125 ]]; then
        startup_path="startup_or_early_runtime"
        signature_guard_triggered=1
        if [[ "${stdout_size}" -eq 0 && "${stderr_size}" -eq 0 ]]; then
            failure_signature="timeout_silent_startup"
        else
            failure_signature="timeout_after_partial_output"
        fi
    elif [[ "${exit_code}" -eq 139 ]]; then
        startup_path="runtime_fault"
        failure_signature="segfault_139"
        signature_guard_triggered=1
    elif [[ "${exit_code}" -eq 134 ]]; then
        startup_path="runtime_fault"
        failure_signature="abort_134"
        signature_guard_triggered=1
    elif [[ "${exit_code}" -eq 127 ]]; then
        startup_path="loader_or_exec"
        failure_signature="exec_not_found_127"
        signature_guard_triggered=1
    elif [[ "${exit_code}" -ne 0 ]]; then
        startup_path="runtime_nonzero"
        failure_signature="nonzero_${exit_code}"
        signature_guard_triggered=1
    fi

    if [[ -f "${stderr_path}" ]]; then
        if grep -qiE 'undefined symbol|symbol lookup error' "${stderr_path}"; then
            startup_path="dynamic_loader"
            failure_signature="loader_symbol_lookup_error"
            signature_guard_triggered=1
        elif grep -qiE 'cannot open shared object file|No such file or directory' "${stderr_path}"; then
            startup_path="dynamic_loader"
            failure_signature="loader_shared_object_missing"
            signature_guard_triggered=1
        elif grep -qiE 'illegal instruction' "${stderr_path}"; then
            startup_path="runtime_fault"
            failure_signature="illegal_instruction"
            signature_guard_triggered=1
        fi
    fi

    printf '%s\t%s\t%s\n' \
        "${startup_path}" \
        "${failure_signature}" \
        "${signature_guard_triggered}"
}

emit_quarantine_report() {
    QUARANTINE_TSV_PATH="${QUARANTINE_TSV}" \
    QUARANTINE_JSON_PATH="${QUARANTINE_REPORT_FILE}" \
    E2E_RUN_ID="${RUN_ID}" \
    E2E_SEED_VALUE="${E2E_SEED}" \
    E2E_MANIFEST_SHA256="${MANIFEST_SHA256}" \
    E2E_THRESHOLD="${FLAKE_QUARANTINE_THRESHOLD}" \
    E2E_RETRY_MAX="${RETRY_MAX}" \
    E2E_RETRY_ANY="${RETRY_ON_NONZERO}" \
    E2E_RETRY_CODES="${RETRYABLE_CODES}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

rows = []
tsv_path = Path(os.environ["QUARANTINE_TSV_PATH"])
if tsv_path.exists():
    for line in tsv_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        (
            scenario_pack,
            scenario_id,
            mode,
            label,
            flake_score,
            retry_count,
            final_exit_code,
            replay_key,
            verdict,
            artifact_refs_json,
        ) = line.split("\t", 9)
        rows.append(
            {
                "scenario_pack": scenario_pack,
                "scenario_id": scenario_id,
                "mode": mode,
                "label": label,
                "flake_score": float(flake_score),
                "retry_count": int(retry_count),
                "final_exit_code": int(final_exit_code),
                "replay_key": replay_key,
                "verdict": verdict,
                "artifact_refs": json.loads(artifact_refs_json),
            }
        )

payload = {
    "schema_version": "v1",
    "run_id": os.environ["E2E_RUN_ID"],
    "seed": os.environ["E2E_SEED_VALUE"],
    "manifest_sha256": os.environ["E2E_MANIFEST_SHA256"],
    "quarantine_threshold": float(os.environ["E2E_THRESHOLD"]),
    "retry_policy": {
        "max_retries": int(os.environ["E2E_RETRY_MAX"]),
        "retry_on_nonzero": bool(int(os.environ["E2E_RETRY_ANY"])),
        "retryable_codes": [
            int(code.strip())
            for code in os.environ["E2E_RETRY_CODES"].split(",")
            if code.strip()
        ],
    },
    "quarantined_count": len(rows),
    "quarantined_cases": rows,
    "remediation_workflow": [
        "reproduce each quarantined case with replay_key and identical mode",
        "inspect stdout/stderr + bundle.meta + env.txt from artifact_refs",
        "fix root cause or tighten retry policy only with explicit evidence",
        "remove quarantine label after two deterministic clean reruns",
    ],
}

Path(os.environ["QUARANTINE_JSON_PATH"]).write_text(
    json.dumps(payload, indent=2) + "\n", encoding="utf-8"
)
PY
}

emit_pack_report() {
    PACK_REPORT_FILE_PATH="${PACK_REPORT_FILE}" \
    PACK_FAILS_SMOKE="${PACK_FAILS["smoke"]:-0}" \
    PACK_FAILS_STRESS="${PACK_FAILS["stress"]:-0}" \
    PACK_FAILS_FAULT="${PACK_FAILS["fault"]:-0}" \
    PACK_FAILS_STABILITY="${PACK_FAILS["stability"]:-0}" \
    PACK_FLAKES_SMOKE="${PACK_FLAKES["smoke"]:-0}" \
    PACK_FLAKES_STRESS="${PACK_FLAKES["stress"]:-0}" \
    PACK_FLAKES_FAULT="${PACK_FLAKES["fault"]:-0}" \
    PACK_FLAKES_STABILITY="${PACK_FLAKES["stability"]:-0}" \
    PACK_QUAR_SMOKE="${PACK_QUARANTINED["smoke"]:-0}" \
    PACK_QUAR_STRESS="${PACK_QUARANTINED["stress"]:-0}" \
    PACK_QUAR_FAULT="${PACK_QUARANTINED["fault"]:-0}" \
    PACK_QUAR_STABILITY="${PACK_QUARANTINED["stability"]:-0}" \
    PACK_MAX_FAILS_SMOKE="${PACK_MAX_FAILS_SMOKE}" \
    PACK_MAX_FAILS_STRESS="${PACK_MAX_FAILS_STRESS}" \
    PACK_MAX_FAILS_FAULT="${PACK_MAX_FAILS_FAULT}" \
    PACK_MAX_FAILS_STABILITY="${PACK_MAX_FAILS_STABILITY}" \
    PACK_MAX_QUARANTINED_SMOKE="${PACK_MAX_QUARANTINED_SMOKE}" \
    PACK_MAX_QUARANTINED_STRESS="${PACK_MAX_QUARANTINED_STRESS}" \
    PACK_MAX_QUARANTINED_FAULT="${PACK_MAX_QUARANTINED_FAULT}" \
    PACK_MAX_QUARANTINED_STABILITY="${PACK_MAX_QUARANTINED_STABILITY}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

packs = []
for name in ("smoke", "stress", "fault", "stability"):
    fails = int(os.environ[f"PACK_FAILS_{name.upper()}"])
    flakes = int(os.environ[f"PACK_FLAKES_{name.upper()}"])
    quarantined = int(os.environ[f"PACK_QUAR_{name.upper()}"])
    max_fails = int(os.environ[f"PACK_MAX_FAILS_{name.upper()}"])
    max_quarantined = int(os.environ[f"PACK_MAX_QUARANTINED_{name.upper()}"])
    fail_ok = fails <= max_fails
    quarantine_ok = quarantined <= max_quarantined
    packs.append(
        {
            "scenario_pack": name,
            "counts": {
                "fails": fails,
                "flakes": flakes,
                "quarantined": quarantined,
            },
            "thresholds": {
                "max_fails": max_fails,
                "max_quarantined": max_quarantined,
            },
            "verdict": "pass" if (fail_ok and quarantine_ok) else "fail",
        }
    )

payload = {
    "schema_version": "v1",
    "packs": packs,
}

Path(os.environ["PACK_REPORT_FILE_PATH"]).write_text(
    json.dumps(payload, indent=2) + "\n", encoding="utf-8"
)
PY
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
        emit_log "error" "case_manifest_mismatch" "${mode}" "" "${label}" "fail" "" "\"scenario_pack\":\"${scenario}\",\"retry_count\":0,\"flake_score\":0.0,\"artifact_refs\":[],\"verdict\":\"manifest_mismatch\",\"details\":{\"scenario\":\"${scenario}\",\"label\":\"${label}\",\"manifest\":\"${MANIFEST_PATH}\"}"
        echo "[FAIL] ${scenario}/${mode}/${label} (manifest metadata missing)" >&2
        return 1
    fi
    IFS=$'\t' read -r scenario_id expected_outcome pass_condition artifact_policy <<<"${metadata}"
    local replay_key
    replay_key="$(compute_replay_key "${mode}" "${scenario_id}" "${label}")"
    local env_fingerprint
    env_fingerprint="$(compute_env_fingerprint "${mode}")"

    emit_log "info" "case_start" "${mode}" "" "${label}" "" "" "\"scenario_id\":\"${scenario_id}\",\"scenario_pack\":\"${scenario}\",\"retry_count\":0,\"flake_score\":0.0,\"artifact_refs\":[],\"verdict\":\"running\",\"replay_key\":\"${replay_key}\",\"env_fingerprint\":\"${env_fingerprint}\",\"expected_outcome\":\"${expected_outcome}\",\"pass_condition\":\"${pass_condition}\",\"artifact_policy\":${artifact_policy},\"details\":{\"scenario\":\"${scenario}\"}"

    local -a exit_codes=()
    local -a latencies=()
    local attempt_index=0
    local final_rc=0
    local last_attempt_stdout=""
    local last_attempt_stderr=""

    while :; do
        local attempt_num=$((attempt_index + 1))
        local attempt_stdout="${case_dir}/stdout.attempt${attempt_num}.txt"
        local attempt_stderr="${case_dir}/stderr.attempt${attempt_num}.txt"
        local start_ns
        start_ns=$(date +%s%N)

        set +e
        timeout "${TIMEOUT_SECONDS}" \
            env FRANKENLIBC_MODE="${mode}" \
                FRANKENLIBC_E2E_SEED="${E2E_SEED}" \
                LD_PRELOAD="${LIB_PATH}" \
                "$@" \
            > "${attempt_stdout}" 2> "${attempt_stderr}"
        local rc=$?
        set -e

        local end_ns
        end_ns=$(date +%s%N)
        local elapsed_ns=$(( end_ns - start_ns ))
        exit_codes+=("${rc}")
        latencies+=("${elapsed_ns}")
        final_rc="${rc}"
        last_attempt_stdout="${attempt_stdout}"
        last_attempt_stderr="${attempt_stderr}"

        emit_log "info" "case_attempt" "${mode}" "" "${label}" "" "${elapsed_ns}" "\"scenario_id\":\"${scenario_id}\",\"scenario_pack\":\"${scenario}\",\"attempt_index\":${attempt_num},\"attempt_exit_code\":${rc},\"retry_count\":${attempt_index},\"flake_score\":0.0,\"artifact_refs\":[\"${scenario}/${mode}/${label}/stdout.attempt${attempt_num}.txt\",\"${scenario}/${mode}/${label}/stderr.attempt${attempt_num}.txt\"],\"verdict\":\"attempt_recorded\",\"replay_key\":\"${replay_key}\",\"env_fingerprint\":\"${env_fingerprint}\",\"expected_outcome\":\"${expected_outcome}\",\"pass_condition\":\"${pass_condition}\",\"artifact_policy\":${artifact_policy}"

        local retry_decision
        retry_decision="$(should_retry_attempt "${rc}" "${attempt_index}")"
        if [[ "${retry_decision}" != "1" ]]; then
            break
        fi

        attempt_index=$((attempt_index + 1))
        emit_log "info" "case_retry" "${mode}" "" "${label}" "" "" "\"scenario_id\":\"${scenario_id}\",\"scenario_pack\":\"${scenario}\",\"retry_count\":${attempt_index},\"flake_score\":0.0,\"artifact_refs\":[\"${scenario}/${mode}/${label}/stdout.attempt${attempt_num}.txt\",\"${scenario}/${mode}/${label}/stderr.attempt${attempt_num}.txt\"],\"verdict\":\"retry_scheduled\",\"replay_key\":\"${replay_key}\",\"env_fingerprint\":\"${env_fingerprint}\",\"expected_outcome\":\"${expected_outcome}\",\"pass_condition\":\"${pass_condition}\",\"artifact_policy\":${artifact_policy}"
    done

    cp "${last_attempt_stdout}" "${case_dir}/stdout.txt"
    cp "${last_attempt_stderr}" "${case_dir}/stderr.txt"

    local exit_codes_csv
    exit_codes_csv="$(IFS=,; echo "${exit_codes[*]}")"
    local classification
    classification="$(classify_attempt_history "${exit_codes_csv}")"

    local retry_count flake_score verdict final_outcome final_exit_code is_flaky should_quarantine
    IFS=$'\t' read -r retry_count flake_score verdict final_outcome final_exit_code is_flaky should_quarantine <<<"${classification}"

    local startup_path failure_signature signature_guard_triggered
    local signature_classification
    signature_classification="$(classify_failure_signature "${final_rc}" "${case_dir}/stdout.txt" "${case_dir}/stderr.txt")"
    IFS=$'\t' read -r startup_path failure_signature signature_guard_triggered <<<"${signature_classification}"

    local total_elapsed_ns=0
    local latency_ns
    for latency_ns in "${latencies[@]}"; do
        total_elapsed_ns=$((total_elapsed_ns + latency_ns))
    done

    if [[ "${final_outcome}" != "pass" || "${should_quarantine}" == "1" ]]; then
        local fail_reason="exit_${final_rc}"
        if [[ "${final_rc}" -eq 124 || "${final_rc}" -eq 125 ]]; then
            fail_reason="timeout_${TIMEOUT_SECONDS}s"
        fi
        {
            echo "mode=${mode}"
            echo "scenario=${scenario}"
            echo "label=${label}"
            echo "exit_codes=${exit_codes_csv}"
            echo "exit_code=${final_rc}"
            echo "fail_reason=${fail_reason}"
            echo "retry_count=${retry_count}"
            echo "flake_score=${flake_score}"
            echo "verdict=${verdict}"
            echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            echo "lib_path=${LIB_PATH}"
            echo "seed=${E2E_SEED}"
            echo "scenario_id=${scenario_id}"
            echo "replay_key=${replay_key}"
            echo "env_fingerprint=${env_fingerprint}"
            echo "startup_path=${startup_path}"
            echo "failure_signature=${failure_signature}"
            echo "signature_guard_triggered=${signature_guard_triggered}"
        } > "${case_dir}/bundle.meta"
        env | sort > "${case_dir}/env.txt"
    fi

    local artifact_refs_json="["
    local first_ref=1
    local i
    for i in $(seq 1 "${#exit_codes[@]}"); do
        for suffix in "stdout.attempt${i}.txt" "stderr.attempt${i}.txt"; do
            if [[ "${first_ref}" -eq 0 ]]; then
                artifact_refs_json="${artifact_refs_json},"
            fi
            artifact_refs_json="${artifact_refs_json}\"${scenario}/${mode}/${label}/${suffix}\""
            first_ref=0
        done
    done
    for suffix in "stdout.txt" "stderr.txt"; do
        if [[ "${first_ref}" -eq 0 ]]; then
            artifact_refs_json="${artifact_refs_json},"
        fi
        artifact_refs_json="${artifact_refs_json}\"${scenario}/${mode}/${label}/${suffix}\""
        first_ref=0
    done
    if [[ -f "${case_dir}/bundle.meta" ]]; then
        artifact_refs_json="${artifact_refs_json},\"${scenario}/${mode}/${label}/bundle.meta\",\"${scenario}/${mode}/${label}/env.txt\""
    fi
    artifact_refs_json="${artifact_refs_json}]"

    if [[ "${final_outcome}" == "pass" ]]; then
        passes=$((passes + 1))
        CASE_RESULT_BY_SCENARIO_MODE["${scenario_id}|${mode}"]="pass|${total_elapsed_ns}|${replay_key}|${label}"
    else
        fails=$((fails + 1))
        PACK_FAILS["${scenario}"]=$(( ${PACK_FAILS["${scenario}"]:-0} + 1 ))
        CASE_RESULT_BY_SCENARIO_MODE["${scenario_id}|${mode}"]="fail|${total_elapsed_ns}|${replay_key}|${label}"
    fi
    CASE_SCENARIOS["${scenario_id}"]=1

    if [[ "${is_flaky}" == "1" ]]; then
        PACK_FLAKES["${scenario}"]=$(( ${PACK_FLAKES["${scenario}"]:-0} + 1 ))
    fi
    if [[ "${should_quarantine}" == "1" ]]; then
        PACK_QUARANTINED["${scenario}"]=$(( ${PACK_QUARANTINED["${scenario}"]:-0} + 1 ))
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${scenario}" \
            "${scenario_id}" \
            "${mode}" \
            "${label}" \
            "${flake_score}" \
            "${retry_count}" \
            "${final_exit_code}" \
            "${replay_key}" \
            "${verdict}" \
            "${artifact_refs_json}" \
            >> "${QUARANTINE_TSV}"
    fi

    local level="info"
    local event="case_pass"
    if [[ "${final_outcome}" != "pass" ]]; then
        level="error"
        event="case_fail"
    elif [[ "${verdict}" == "quarantined_flake" ]]; then
        level="warn"
    fi

    emit_log "${level}" "${event}" "${mode}" "" "${label}" "${final_outcome}" "${total_elapsed_ns}" "\"scenario_id\":\"${scenario_id}\",\"scenario_pack\":\"${scenario}\",\"retry_count\":${retry_count},\"flake_score\":${flake_score},\"artifact_refs\":${artifact_refs_json},\"verdict\":\"${verdict}\",\"final_exit_code\":${final_exit_code},\"replay_key\":\"${replay_key}\",\"env_fingerprint\":\"${env_fingerprint}\",\"expected_outcome\":\"${expected_outcome}\",\"pass_condition\":\"${pass_condition}\",\"artifact_policy\":${artifact_policy},\"startup_path\":\"${startup_path}\",\"failure_signature\":\"${failure_signature}\",\"signature_guard_triggered\":${signature_guard_triggered}"

    if [[ "${final_outcome}" == "pass" ]]; then
        echo "[PASS] ${scenario}/${mode}/${label} (verdict=${verdict}, retry_count=${retry_count}, flake_score=${flake_score})"
        return 0
    fi

    echo "[FAIL] ${scenario}/${mode}/${label} (verdict=${verdict}, exit=${final_exit_code}, retry_count=${retry_count}, flake_score=${flake_score}, signature=${failure_signature})"
    return 1
}

# ---------------------------------------------------------------------------
# Shadow-run helper: compare preloaded output against host baseline.
# ---------------------------------------------------------------------------
run_shadow_compare_case() {
    local mode="$1"
    local scenario="$2"
    local label="$3"
    shift 3

    local case_dir="${OUT_DIR}/${scenario}/${mode}/${label}"
    mkdir -p "${case_dir}"

    local baseline_stdout="${case_dir}/baseline.stdout.txt"
    local baseline_stderr="${case_dir}/baseline.stderr.txt"
    local baseline_rc=0

    set +e
    timeout "${TIMEOUT_SECONDS}" "$@" > "${baseline_stdout}" 2> "${baseline_stderr}"
    baseline_rc=$?
    set -e
    printf '%s\n' "${baseline_rc}" > "${case_dir}/baseline.exit_code"

    local baseline_refs="[\"${scenario}/${mode}/${label}/baseline.stdout.txt\",\"${scenario}/${mode}/${label}/baseline.stderr.txt\",\"${scenario}/${mode}/${label}/baseline.exit_code\"]"
    emit_log "info" "shadow_baseline" "${mode}" "" "${label}" "" "" "\"scenario_pack\":\"${scenario}\",\"retry_count\":0,\"flake_score\":0.0,\"artifact_refs\":${baseline_refs},\"verdict\":\"baseline_recorded\",\"details\":{\"baseline_exit_code\":${baseline_rc}}"

    if [[ "${baseline_rc}" -ne 0 ]]; then
        fails=$((fails + 1))
        PACK_FAILS["${scenario}"]=$(( ${PACK_FAILS["${scenario}"]:-0} + 1 ))
        CASE_RESULT_BY_SCENARIO_MODE["${scenario}.${label}|${mode}"]="fail|0|baseline_rc_${baseline_rc}|${label}"
        CASE_SCENARIOS["${scenario}.${label}"]=1
        emit_log "error" "shadow_baseline_fail" "${mode}" "" "${label}" "fail" "" "\"scenario_pack\":\"${scenario}\",\"retry_count\":0,\"flake_score\":0.0,\"artifact_refs\":${baseline_refs},\"verdict\":\"baseline_nonzero\",\"details\":{\"baseline_exit_code\":${baseline_rc}}"
        echo "[FAIL] ${scenario}/${mode}/${label} (baseline exit ${baseline_rc})"
        return 1
    fi

    if ! run_e2e_case "${mode}" "${scenario}" "${label}" "$@"; then
        return 1
    fi

    local preloaded_stdout="${case_dir}/stdout.txt"
    local preloaded_stderr="${case_dir}/stderr.txt"
    local mismatch=0
    cmp -s "${baseline_stdout}" "${preloaded_stdout}" || mismatch=1
    cmp -s "${baseline_stderr}" "${preloaded_stderr}" || mismatch=1

    if [[ "${mismatch}" -ne 0 ]]; then
        local stdout_diff="${case_dir}/shadow.stdout.diff"
        local stderr_diff="${case_dir}/shadow.stderr.diff"
        local divergence_report="${case_dir}/shadow_divergence_report.txt"
        diff -u "${baseline_stdout}" "${preloaded_stdout}" > "${stdout_diff}" || true
        diff -u "${baseline_stderr}" "${preloaded_stderr}" > "${stderr_diff}" || true
        local stdout_diff_lines=0
        local stderr_diff_lines=0
        if [[ -s "${stdout_diff}" ]]; then
            stdout_diff_lines="$(wc -l < "${stdout_diff}" | tr -d '[:space:]')"
        fi
        if [[ -s "${stderr_diff}" ]]; then
            stderr_diff_lines="$(wc -l < "${stderr_diff}" | tr -d '[:space:]')"
        fi
        cat > "${divergence_report}" <<EOF
Shadow divergence report
scenario: ${scenario}
mode: ${mode}
label: ${label}
baseline_exit_code: 0
stdout_diff_lines: ${stdout_diff_lines}
stderr_diff_lines: ${stderr_diff_lines}
baseline_stdout: ${baseline_stdout}
preloaded_stdout: ${preloaded_stdout}
baseline_stderr: ${baseline_stderr}
preloaded_stderr: ${preloaded_stderr}
EOF

        passes=$((passes - 1))
        fails=$((fails + 1))
        PACK_FAILS["${scenario}"]=$(( ${PACK_FAILS["${scenario}"]:-0} + 1 ))
        local scenario_key="${scenario}.${label}|${mode}"
        local scenario_result="${CASE_RESULT_BY_SCENARIO_MODE["${scenario_key}"]:-}"
        if [[ -n "${scenario_result}" ]]; then
            IFS='|' read -r _ latency_ns replay_key saved_label <<<"${scenario_result}"
            CASE_RESULT_BY_SCENARIO_MODE["${scenario_key}"]="fail|${latency_ns}|${replay_key}|${saved_label}"
        else
            CASE_RESULT_BY_SCENARIO_MODE["${scenario_key}"]="fail|0|shadow_mismatch|${label}"
        fi
        local diff_refs="[\"${scenario}/${mode}/${label}/baseline.stdout.txt\",\"${scenario}/${mode}/${label}/baseline.stderr.txt\",\"${scenario}/${mode}/${label}/stdout.txt\",\"${scenario}/${mode}/${label}/stderr.txt\",\"${scenario}/${mode}/${label}/shadow.stdout.diff\",\"${scenario}/${mode}/${label}/shadow.stderr.diff\",\"${scenario}/${mode}/${label}/shadow_divergence_report.txt\"]"
        emit_log "error" "shadow_diff_mismatch" "${mode}" "" "${label}" "fail" "" "\"scenario_pack\":\"${scenario}\",\"retry_count\":0,\"flake_score\":0.0,\"artifact_refs\":${diff_refs},\"verdict\":\"shadow_mismatch\",\"details\":{\"baseline_exit_code\":0,\"stdout_diff_lines\":${stdout_diff_lines},\"stderr_diff_lines\":${stderr_diff_lines}}"
        emit_log "info" "shadow_divergence_report" "${mode}" "" "${label}" "fail" "" "\"scenario_pack\":\"${scenario}\",\"retry_count\":0,\"flake_score\":0.0,\"artifact_refs\":${diff_refs},\"verdict\":\"shadow_mismatch_report\""
        echo "[FAIL] ${scenario}/${mode}/${label} (shadow diff mismatch)"
        return 1
    fi

    local diff_refs="[\"${scenario}/${mode}/${label}/baseline.stdout.txt\",\"${scenario}/${mode}/${label}/baseline.stderr.txt\",\"${scenario}/${mode}/${label}/stdout.txt\",\"${scenario}/${mode}/${label}/stderr.txt\"]"
    emit_log "info" "shadow_diff_match" "${mode}" "" "${label}" "pass" "" "\"scenario_pack\":\"${scenario}\",\"retry_count\":0,\"flake_score\":0.0,\"artifact_refs\":${diff_refs},\"verdict\":\"shadow_match\""
    return 0
}

run_optional_shadow_compare_case() {
    local required_binary="$1"
    local mode="$2"
    local scenario="$3"
    local label="$4"
    shift 4

    if ! command -v "${required_binary}" >/dev/null 2>&1; then
        skips=$((skips + 1))
        emit_log "warn" "case_skip_optional_binary_missing" "${mode}" "" "${label}" "skip" "" "\"scenario_pack\":\"${scenario}\",\"retry_count\":0,\"flake_score\":0.0,\"artifact_refs\":[],\"verdict\":\"optional_binary_missing\",\"details\":{\"required_binary\":\"${required_binary}\"}"
        echo "[SKIP] ${scenario}/${mode}/${label} (missing optional binary: ${required_binary})"
        return 0
    fi

    run_shadow_compare_case "${mode}" "${scenario}" "${label}" "$@"
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

    local smoke_fixture="${OUT_DIR}/fixtures/smoke_shadow_input.txt"
    mkdir -p "$(dirname "${smoke_fixture}")"
    if [[ ! -f "${smoke_fixture}" ]]; then
        cat > "${smoke_fixture}" <<'EOF'
charlie
alpha
bravo
alpha
EOF
    fi

    run_e2e_case "${mode}" "smoke" "coreutils_ls" /bin/ls -la /tmp || failed=1
    run_e2e_case "${mode}" "smoke" "coreutils_cat" /bin/cat /etc/hosts || failed=1
    run_e2e_case "${mode}" "smoke" "coreutils_echo" /bin/echo "frankenlibc_e2e_smoke" || failed=1
    run_e2e_case "${mode}" "smoke" "coreutils_env" /usr/bin/env || failed=1
    run_e2e_case "${mode}" "smoke" "integration_link" "${integ_bin}" || failed=1
    run_shadow_compare_case "${mode}" "smoke" "coreutils_cat_shadow" /bin/cat "${smoke_fixture}" || failed=1
    run_shadow_compare_case "${mode}" "smoke" "coreutils_sort" /usr/bin/env LC_ALL=C /bin/sort "${smoke_fixture}" || failed=1
    run_shadow_compare_case "${mode}" "smoke" "coreutils_wc" /usr/bin/env LC_ALL=C /usr/bin/wc -l "${smoke_fixture}" || failed=1

    if command -v python3 >/dev/null 2>&1; then
        run_e2e_case "${mode}" "smoke" "nontrivial_python3" python3 -c "print('e2e_ok')" || failed=1
    fi

    run_optional_shadow_compare_case "busybox" "${mode}" "smoke" "busybox_help" busybox --help || failed=1
    run_optional_shadow_compare_case "sqlite3" "${mode}" "smoke" "sqlite_memory_select" sqlite3 :memory: "select 41 + 1;" || failed=1
    run_optional_shadow_compare_case "redis-cli" "${mode}" "smoke" "redis_cli_version" redis-cli --version || failed=1
    run_optional_shadow_compare_case "redis-server" "${mode}" "smoke" "redis_server_version" redis-server --version || failed=1

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

emit_log "info" "suite_start" "" "" "" "" "" "\"details\":{\"version\":\"${SUITE_VERSION}\",\"scenario_class\":\"${SCENARIO_CLASS}\",\"mode_filter\":\"${MODE_FILTER}\",\"seed\":\"${E2E_SEED}\",\"manifest\":\"${MANIFEST_PATH}\",\"dry_run_manifest\":${DRY_RUN_MANIFEST},\"retry_max\":${RETRY_MAX},\"retry_on_nonzero\":${RETRY_ON_NONZERO},\"retryable_codes\":\"${RETRYABLE_CODES}\",\"flake_quarantine_threshold\":${FLAKE_QUARANTINE_THRESHOLD}}"

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
            emit_log "info" "manifest_case" "${mode}" "" "${label}" "catalog_loaded" "" "\"scenario_id\":\"${scenario_id}\",\"scenario_pack\":\"${scenario}\",\"retry_count\":0,\"flake_score\":0.0,\"artifact_refs\":[],\"verdict\":\"catalog_loaded\",\"replay_key\":\"${replay_key}\",\"env_fingerprint\":\"${env_fingerprint}\",\"expected_outcome\":\"${expected_outcome}\",\"pass_condition\":\"${pass_condition}\",\"artifact_policy\":${artifact_policy},\"details\":{\"scenario\":\"${scenario}\"}"
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
    emit_quarantine_report
    emit_pack_report

    for pack in smoke stress fault stability; do
        if [[ "${SCENARIO_CLASS}" != "all" && "${SCENARIO_CLASS}" != "${pack}" ]]; then
            continue
        fi
        local_fail_count="${PACK_FAILS["${pack}"]:-0}"
        local_quarantine_count="${PACK_QUARANTINED["${pack}"]:-0}"
        max_fail_count="$(pack_max_fails "${pack}")"
        max_quarantine_count="$(pack_max_quarantined "${pack}")"
        if (( local_fail_count > max_fail_count )); then
            overall_failed=1
            emit_log "error" "scenario_pack_gate_fail" "" "" "${pack}" "fail" "" "\"scenario_pack\":\"${pack}\",\"retry_count\":0,\"flake_score\":0.0,\"artifact_refs\":[\"scenario_pack_report.json\"],\"verdict\":\"pack_fail_budget_exceeded\",\"details\":{\"fails\":${local_fail_count},\"max_fails\":${max_fail_count}}"
        fi
        if (( local_quarantine_count > max_quarantine_count )); then
            overall_failed=1
            emit_log "error" "scenario_pack_gate_fail" "" "" "${pack}" "fail" "" "\"scenario_pack\":\"${pack}\",\"retry_count\":0,\"flake_score\":0.0,\"artifact_refs\":[\"scenario_pack_report.json\",\"flake_quarantine_report.json\"],\"verdict\":\"pack_quarantine_budget_exceeded\",\"details\":{\"quarantined\":${local_quarantine_count},\"max_quarantined\":${max_quarantine_count}}"
        fi
    done
fi

emit_log "info" "suite_end" "" "" "" "" "" "\"details\":{\"passes\":${passes},\"fails\":${fails},\"skips\":${skips},\"mode_pair_mismatches\":${pair_mismatch_count},\"pack_fails\":{\"smoke\":${PACK_FAILS["smoke"]:-0},\"stress\":${PACK_FAILS["stress"]:-0},\"fault\":${PACK_FAILS["fault"]:-0},\"stability\":${PACK_FAILS["stability"]:-0}},\"pack_quarantined\":{\"smoke\":${PACK_QUARANTINED["smoke"]:-0},\"stress\":${PACK_QUARANTINED["stress"]:-0},\"fault\":${PACK_QUARANTINED["fault"]:-0},\"stability\":${PACK_QUARANTINED["stability"]:-0}}}"

# ---------------------------------------------------------------------------
# Artifact index
# ---------------------------------------------------------------------------
E2E_OUT_DIR="${OUT_DIR}" \
E2E_INDEX_FILE="${INDEX_FILE}" \
E2E_RUN_ID="${RUN_ID}" \
E2E_GENERATED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
E2E_PASSES="${passes}" \
E2E_FAILS="${fails}" \
E2E_SKIPS="${skips}" \
python3 - <<'PY'
import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path

out_dir = Path(os.environ["E2E_OUT_DIR"])
index_path = Path(os.environ["E2E_INDEX_FILE"])
trace_path = out_dir / "trace.jsonl"

artifact_trace_ids: dict[str, set[str]] = defaultdict(set)
all_trace_ids: list[str] = []
seen_trace_ids: set[str] = set()

if trace_path.exists():
    for raw in trace_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        obj = json.loads(line)
        trace_id = obj.get("trace_id")
        if isinstance(trace_id, str) and trace_id:
            if trace_id not in seen_trace_ids:
                all_trace_ids.append(trace_id)
                seen_trace_ids.add(trace_id)
            for artifact_ref in obj.get("artifact_refs", []):
                if isinstance(artifact_ref, str) and artifact_ref:
                    artifact_trace_ids[artifact_ref].add(trace_id)

artifacts = []

for root, dirs, files in sorted(os.walk(out_dir)):
    dirs.sort()
    files.sort()
    for file_name in files:
        file_path = Path(root) / file_name
        rel_path = file_path.relative_to(out_dir).as_posix()
        size_bytes = file_path.stat().st_size
        sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if file_name.endswith(".jsonl"):
            kind = "log"
            retention_tier = "release"
        elif file_name in {
            "artifact_index.json",
            "mode_pair_report.json",
            "scenario_pack_report.json",
            "flake_quarantine_report.json",
        }:
            kind = "report"
            retention_tier = "release"
        elif file_name.endswith(".diff"):
            kind = "diff"
            retention_tier = "debug"
        else:
            kind = "diagnostic"
            retention_tier = "debug"

        trace_ids = []
        if rel_path == "trace.jsonl":
            trace_ids = list(all_trace_ids)
        elif rel_path in artifact_trace_ids:
            trace_ids = sorted(artifact_trace_ids[rel_path])

        entry = {
            "path": rel_path,
            "kind": kind,
            "retention_tier": retention_tier,
            "sha256": sha256,
            "size_bytes": size_bytes,
        }
        if trace_ids:
            entry["join_keys"] = {"trace_ids": trace_ids}
        artifacts.append(entry)

index = {
    "index_version": 1,
    "run_id": os.environ["E2E_RUN_ID"],
    "bead_id": "bd-2ez",
    "generated_utc": os.environ["E2E_GENERATED_UTC"],
    "summary": {
        "passes": int(os.environ["E2E_PASSES"]),
        "fails": int(os.environ["E2E_FAILS"]),
        "skips": int(os.environ["E2E_SKIPS"]),
    },
    "retention_policy": {
        "policy_version": "v1",
        "tier_days": {
            "release": 90,
            "debug": 14,
        },
    },
    "artifacts": artifacts,
}

index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
PY

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "passes=${passes} fails=${fails} skips=${skips}"
echo "trace_log=${LOG_FILE}"
echo "artifact_index=${INDEX_FILE}"
if [[ "${DRY_RUN_MANIFEST}" -eq 0 ]]; then
    echo "mode_pair_report=${PAIR_REPORT_FILE}"
    echo "scenario_pack_report=${PACK_REPORT_FILE}"
    echo "flake_quarantine_report=${QUARANTINE_REPORT_FILE}"
fi
echo ""

if [[ "${overall_failed}" -ne 0 ]]; then
    echo "e2e_suite: FAILED (see ${OUT_DIR})" >&2
    exit 1
fi

echo "e2e_suite: PASS"
