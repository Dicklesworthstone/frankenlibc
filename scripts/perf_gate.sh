#!/usr/bin/env bash
# Performance regression gate for runtime_math + membrane hot paths.
#
# Behavior:
# - runs strict+hardened benchmark checks (or injected observations for tests),
# - applies baseline regression thresholds with attribution policy overrides,
# - emits structured attribution logs (jsonl),
# - fails deterministically on baseline regressions (and optionally target breaches).
set -euo pipefail

BASELINE_FILE="${BASELINE_FILE:-scripts/perf_baseline.json}"
# Default warning/block thresholds for baseline regression checks.
WARN_REGRESSION_PCT_DEFAULT="5"
MAX_REGRESSION_PCT="${FRANKENLIBC_PERF_MAX_REGRESSION_PCT:-20}"
ALLOW_TARGET_VIOLATION="${FRANKENLIBC_PERF_ALLOW_TARGET_VIOLATION:-1}"
SKIP_OVERLOADED="${FRANKENLIBC_PERF_SKIP_OVERLOADED:-1}"
MAX_LOAD_FACTOR="${FRANKENLIBC_PERF_MAX_LOAD_FACTOR:-0.85}"
ENABLE_KERNEL_SUITE="${FRANKENLIBC_PERF_ENABLE_KERNEL_SUITE:-0}"

# Optional deterministic inputs/logs for E2E and attribution replay.
INJECT_RESULTS_FILE="${FRANKENLIBC_PERF_INJECT_RESULTS:-}"
ATTRIBUTION_POLICY_FILE="${FRANKENLIBC_PERF_ATTRIBUTION_POLICY_FILE:-tests/conformance/perf_regression_attribution.v1.json}"
EVENT_LOG_PATH="${FRANKENLIBC_PERF_EVENT_LOG:-}"
TRACE_ID="${FRANKENLIBC_PERF_TRACE_ID:-perf_gate::$(date -u +%Y%m%dT%H%M%SZ)}"

if [[ ! -f "${BASELINE_FILE}" ]]; then
    echo "perf_gate: missing baseline file: ${BASELINE_FILE}" >&2
    exit 2
fi

if [[ -n "${INJECT_RESULTS_FILE}" && ! -f "${INJECT_RESULTS_FILE}" ]]; then
    echo "perf_gate: missing injected results file: ${INJECT_RESULTS_FILE}" >&2
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "perf_gate: jq is required" >&2
    exit 2
fi

if [[ -n "${EVENT_LOG_PATH}" ]]; then
    mkdir -p "$(dirname "${EVENT_LOG_PATH}")"
    : >"${EVENT_LOG_PATH}"
fi

should_skip_overloaded() {
    # Synthetic regression replays should never be skipped for host load.
    if [[ -n "${INJECT_RESULTS_FILE}" ]]; then
        return 1
    fi
    if [[ "${SKIP_OVERLOADED}" != "1" || ! -r /proc/loadavg ]]; then
        return 1
    fi
    if ! command -v nproc >/dev/null 2>&1; then
        return 1
    fi

    local load1 cpus threshold overloaded
    load1="$(awk '{print $1}' /proc/loadavg)"
    cpus="$(nproc)"
    threshold="$(awk -v c="${cpus}" -v f="${MAX_LOAD_FACTOR}" 'BEGIN { printf "%.2f", c*f }')"
    overloaded="$(awk -v l="${load1}" -v t="${threshold}" 'BEGIN { print (l > t) ? 1 : 0 }')"

    if [[ "${overloaded}" == "1" ]]; then
        echo "perf_gate: SKIP (system overloaded) load1=${load1} cpus=${cpus} threshold=${threshold}"
        echo "perf_gate: top CPU processes:"
        ps -eo pid,user,comm,%cpu,etime --sort=-%cpu | head -n 10 || true
        return 0
    fi

    return 1
}

extract_p50() {
    local prefix="$1" mode="$2" bench="$3"
    awk -v prefix="$prefix" -v mode="$mode" -v bench="$bench" '
    $1==prefix {
      have_mode=0; have_bench=0; p50="";
      for (i=2; i<=NF; i++) {
        if ($i=="mode="mode) have_mode=1;
        if ($i=="bench="bench) have_bench=1;
        if ($i ~ /^p50_ns_op=/) { split($i,a,"="); p50=a[2]; }
      }
      if (have_mode && have_bench && p50!="") { print p50; exit 0; }
    }'
}

inject_metric() {
    local mode="$1" suite="$2" bench="$3"
    jq -r --arg mode "${mode}" --arg suite "${suite}" --arg bench "${bench}" \
        '.[$suite][$mode][$bench] // empty' "${INJECT_RESULTS_FILE}"
}

resolve_threshold_pct() {
    local mode="$1" benchmark_id="$2"
    local pct=""
    if [[ -f "${ATTRIBUTION_POLICY_FILE}" ]]; then
        pct="$(jq -r --arg mode "${mode}" --arg benchmark_id "${benchmark_id}" '
          .threshold_policy.per_benchmark_overrides[$benchmark_id][$mode]
          // .threshold_policy.per_mode_max_regression_pct[$mode]
          // .threshold_policy.default_max_regression_pct
          // empty
        ' "${ATTRIBUTION_POLICY_FILE}" 2>/dev/null || true)"
    fi
    if [[ -z "${pct}" || "${pct}" == "null" ]]; then
        pct="${MAX_REGRESSION_PCT}"
    fi
    printf "%s" "${pct}"
}

resolve_warning_pct() {
    local mode="$1" benchmark_id="$2"
    local pct=""
    if [[ -f "${ATTRIBUTION_POLICY_FILE}" ]]; then
        pct="$(jq -r --arg mode "${mode}" --arg benchmark_id "${benchmark_id}" '
          .warning_policy.per_benchmark_overrides[$benchmark_id][$mode]
          // .warning_policy.per_mode_warning_pct[$mode]
          // .warning_policy.default_warning_pct
          // empty
        ' "${ATTRIBUTION_POLICY_FILE}" 2>/dev/null || true)"
    fi
    if [[ -z "${pct}" || "${pct}" == "null" ]]; then
        pct="${WARN_REGRESSION_PCT_DEFAULT}"
    fi
    printf "%s" "${pct}"
}

resolve_suspect_component() {
    local benchmark_id="$1"
    local component=""
    if [[ -f "${ATTRIBUTION_POLICY_FILE}" ]]; then
        component="$(jq -r --arg benchmark_id "${benchmark_id}" \
            '.attribution.suspect_component_map[$benchmark_id] // .attribution.unknown_component_label // empty' \
            "${ATTRIBUTION_POLICY_FILE}" 2>/dev/null || true)"
    fi
    if [[ -z "${component}" || "${component}" == "null" ]]; then
        component="unknown_component"
    fi
    printf "%s" "${component}"
}

emit_event() {
    local mode="$1" benchmark_id="$2" threshold="$3" observed="$4" regression_class="$5"
    local suspect_component="$6" baseline="$7" target="$8" threshold_pct="$9" delta_pct="${10}"
    local verdict="${11}" warning_threshold="${12}" warning_pct="${13}"
    local ts json
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    json="$(jq -cn \
        --arg timestamp "${ts}" \
        --arg trace_id "${TRACE_ID}" \
        --arg mode "${mode}" \
        --arg benchmark_id "${benchmark_id}" \
        --arg threshold "${threshold}" \
        --arg observed "${observed}" \
        --arg regression_class "${regression_class}" \
        --arg suspect_component "${suspect_component}" \
        --arg baseline "${baseline}" \
        --arg target "${target}" \
        --arg threshold_pct "${threshold_pct}" \
        --arg delta_pct "${delta_pct}" \
        --arg verdict "${verdict}" \
        --arg warning_threshold "${warning_threshold}" \
        --arg warning_pct "${warning_pct}" \
        '{
          timestamp: $timestamp,
          trace_id: $trace_id,
          mode: $mode,
          benchmark_id: $benchmark_id,
          threshold: $threshold,
          observed: $observed,
          regression_class: $regression_class,
          suspect_component: $suspect_component,
          baseline: $baseline,
          target: $target,
          threshold_pct: $threshold_pct,
          delta_pct: $delta_pct,
          verdict: $verdict,
          warning_threshold: $warning_threshold,
          warning_pct: $warning_pct
        }')"
    if [[ -n "${EVENT_LOG_PATH}" ]]; then
        echo "${json}" >>"${EVENT_LOG_PATH}"
    fi
}

check_metric() {
    local label="$1" mode="$2" bench="$3" baseline="$4" target="$5" current="$6"
    local benchmark_id threshold_pct warning_pct threshold warning_threshold delta_pct ok_reg ok_target warn_hit
    local regression_class suspect verdict

    benchmark_id="${label}/${bench}"
    threshold_pct="$(resolve_threshold_pct "${mode}" "${benchmark_id}")"
    warning_pct="$(resolve_warning_pct "${mode}" "${benchmark_id}")"
    warning_pct="$(awk -v w="${warning_pct}" -v t="${threshold_pct}" 'BEGIN { print (w > t) ? t : w }')"
    warning_threshold="$(awk -v b="${baseline}" -v pct="${warning_pct}" 'BEGIN { printf "%.3f", b*(1.0 + pct/100.0) }')"
    threshold="$(awk -v b="${baseline}" -v pct="${threshold_pct}" 'BEGIN { printf "%.3f", b*(1.0 + pct/100.0) }')"
    delta_pct="$(awk -v c="${current}" -v b="${baseline}" 'BEGIN { if (b==0) { print "inf"; exit } printf "%.2f", ((c-b)/b)*100.0 }')"

    ok_reg="$(awk -v c="${current}" -v th="${threshold}" 'BEGIN { print (c <= th) ? "1" : "0" }')"
    ok_target="$(awk -v c="${current}" -v t="${target}" 'BEGIN { print (c <= t) ? "1" : "0" }')"
    warn_hit="$(awk -v c="${current}" -v th="${warning_threshold}" 'BEGIN { print (c > th) ? "1" : "0" }')"

    regression_class="ok"
    verdict="OK"
    if [[ "${warn_hit}" == "1" ]]; then
        regression_class="baseline_warning"
        verdict="WARN"
    fi

    if [[ "${ok_reg}" != "1" && "${ok_target}" != "1" ]]; then
        regression_class="baseline_and_budget_violation"
        verdict="BASELINE+TARGET_VIOLATION"
    elif [[ "${ok_reg}" != "1" ]]; then
        regression_class="baseline_regression"
        verdict="BASELINE_REGRESSION"
    elif [[ "${ok_target}" != "1" ]]; then
        regression_class="target_budget_violation"
        verdict="TARGET_VIOLATION"
    fi

    suspect="$(resolve_suspect_component "${benchmark_id}")"
    emit_event "${mode}" "${benchmark_id}" "${threshold}" "${current}" "${regression_class}" \
        "${suspect}" "${baseline}" "${target}" "${threshold_pct}" "${delta_pct}" "${verdict}" \
        "${warning_threshold}" "${warning_pct}"

    printf "%-18s %-8s %-16s baseline=%9.3f current=%9.3f delta=%7s%% target=%7.0f warn_pct=%5s threshold_pct=%5s suspect=%s " \
        "${label}" "${mode}" "${bench}" "${baseline}" "${current}" "${delta_pct}" "${target}" "${warning_pct}" "${threshold_pct}" "${suspect}"

    if [[ "${regression_class}" == "ok" ]]; then
        echo "OK"
        return 0
    fi

    if [[ "${regression_class}" == "baseline_warning" ]]; then
        echo "WARN"
        return 0
    fi

    if [[ "${regression_class}" == "target_budget_violation" && "${ALLOW_TARGET_VIOLATION}" == "1" ]]; then
        echo "TARGET_VIOLATION (allowed)"
        return 0
    fi

    if [[ "${regression_class}" == "target_budget_violation" ]]; then
        echo "TARGET_VIOLATION"
        return 2
    fi

    echo "${verdict}"
    return 1
}

run_mode() {
    local mode="$1"
    local out_rt out_mem out_kernels rt_decide rt_observe rt_decide_observe mem_validate_known
    local b_decide b_observe b_decide_observe b_validate_known
    local t_decide t_observe t_decide_observe t_validate_known
    local failures=0 target_failures=0

    echo ""
    echo "=== perf_gate: mode=${mode} ==="

    if should_skip_overloaded; then
        return 0
    fi

    if [[ -n "${INJECT_RESULTS_FILE}" ]]; then
        rt_decide="$(inject_metric "${mode}" "runtime_math" "decide")"
        rt_observe="$(inject_metric "${mode}" "runtime_math" "observe_fast")"
        rt_decide_observe="$(inject_metric "${mode}" "runtime_math" "decide_observe")"
        mem_validate_known="$(inject_metric "${mode}" "membrane" "validate_known")"
        out_rt=""
        out_mem=""
        out_kernels=""
    else
        out_rt="$(
            FRANKENLIBC_BENCH_PIN=1 FRANKENLIBC_MODE="${mode}" \
                cargo bench -p frankenlibc-bench --bench runtime_math_bench 2>/dev/null \
                | rg '^RUNTIME_MATH_BENCH ' || true
        )"

        out_mem="$(
            FRANKENLIBC_BENCH_PIN=1 FRANKENLIBC_MODE="${mode}" \
                cargo bench -p frankenlibc-bench --bench membrane_bench 2>/dev/null \
                | rg '^MEMBRANE_BENCH ' || true
        )"

        if [[ "${ENABLE_KERNEL_SUITE}" == "1" ]]; then
            out_kernels="$(
                FRANKENLIBC_BENCH_PIN=1 FRANKENLIBC_MODE="${mode}" \
                    cargo bench -p frankenlibc-bench --bench runtime_math_kernels_bench 2>/dev/null \
                    | rg '^RUNTIME_MATH_KERNEL_BENCH ' || true
            )"
        else
            out_kernels=""
        fi

        if [[ -z "${out_rt}" ]]; then
            echo "perf_gate: failed to collect RUNTIME_MATH_BENCH lines for mode=${mode}" >&2
            exit 2
        fi
        if [[ -z "${out_mem}" ]]; then
            echo "perf_gate: failed to collect MEMBRANE_BENCH lines for mode=${mode}" >&2
            exit 2
        fi

        rt_decide="$(printf "%s\n" "${out_rt}" | extract_p50 "RUNTIME_MATH_BENCH" "${mode}" "decide")"
        rt_observe="$(printf "%s\n" "${out_rt}" | extract_p50 "RUNTIME_MATH_BENCH" "${mode}" "observe_fast")"
        rt_decide_observe="$(printf "%s\n" "${out_rt}" | extract_p50 "RUNTIME_MATH_BENCH" "${mode}" "decide_observe")"
        mem_validate_known="$(printf "%s\n" "${out_mem}" | extract_p50 "MEMBRANE_BENCH" "${mode}" "validate_known")"
    fi

    if [[ -z "${rt_decide}" || -z "${rt_observe}" || -z "${rt_decide_observe}" || -z "${mem_validate_known}" ]]; then
        echo "perf_gate: missing metric values for mode=${mode}" >&2
        echo "--- runtime_math lines ---" >&2
        printf "%s\n" "${out_rt}" >&2
        echo "--- membrane lines ---" >&2
        printf "%s\n" "${out_mem}" >&2
        exit 2
    fi

    b_decide="$(jq -r ".baseline_p50_ns_op.runtime_math.${mode}.decide" "${BASELINE_FILE}")"
    b_observe="$(jq -r ".baseline_p50_ns_op.runtime_math.${mode}.observe_fast" "${BASELINE_FILE}")"
    b_decide_observe="$(jq -r ".baseline_p50_ns_op.runtime_math.${mode}.decide_observe" "${BASELINE_FILE}")"
    b_validate_known="$(jq -r ".baseline_p50_ns_op.membrane.${mode}.validate_known" "${BASELINE_FILE}")"

    t_decide="$(jq -r ".targets_ns_op.${mode}.decide" "${BASELINE_FILE}")"
    t_observe="$(jq -r ".targets_ns_op.${mode}.observe_fast" "${BASELINE_FILE}")"
    t_decide_observe="$(jq -r ".targets_ns_op.${mode}.decide_observe" "${BASELINE_FILE}")"
    t_validate_known="$(jq -r ".targets_ns_op.${mode}.validate_known" "${BASELINE_FILE}")"

    check_metric "runtime_math" "${mode}" "decide" "${b_decide}" "${t_decide}" "${rt_decide}" || {
        rc=$?
        if [[ "${rc}" == "1" ]]; then failures=$((failures + 1)); else target_failures=$((target_failures + 1)); fi
    }
    check_metric "runtime_math" "${mode}" "observe_fast" "${b_observe}" "${t_observe}" "${rt_observe}" || {
        rc=$?
        if [[ "${rc}" == "1" ]]; then failures=$((failures + 1)); else target_failures=$((target_failures + 1)); fi
    }
    check_metric "runtime_math" "${mode}" "decide_observe" "${b_decide_observe}" "${t_decide_observe}" "${rt_decide_observe}" || {
        rc=$?
        if [[ "${rc}" == "1" ]]; then failures=$((failures + 1)); else target_failures=$((target_failures + 1)); fi
    }
    check_metric "membrane" "${mode}" "validate_known" "${b_validate_known}" "${t_validate_known}" "${mem_validate_known}" || {
        rc=$?
        if [[ "${rc}" == "1" ]]; then failures=$((failures + 1)); else target_failures=$((target_failures + 1)); fi
    }

    if [[ "${failures}" -gt 0 ]]; then
        echo "perf_gate: ${failures} baseline regression failure(s) in mode=${mode}" >&2
        return 1
    fi
    if [[ "${target_failures}" -gt 0 && "${ALLOW_TARGET_VIOLATION}" != "1" ]]; then
        echo "perf_gate: ${target_failures} target-budget failure(s) in mode=${mode}" >&2
        return 2
    fi

    if [[ "${ENABLE_KERNEL_SUITE}" == "1" && -z "${INJECT_RESULTS_FILE}" ]]; then
        if [[ -z "${out_kernels}" ]]; then
            echo "perf_gate: kernel suite enabled but no RUNTIME_MATH_KERNEL_BENCH lines collected for mode=${mode}" >&2
            return 1
        fi
        echo "perf_gate: kernel suite collected (mode=${mode}) lines=$(printf "%s\n" "${out_kernels}" | wc -l | tr -d ' ')"
    fi

    return 0
}

echo "=== perf_gate ==="
echo "trace_id=${TRACE_ID}"
echo "baseline=${BASELINE_FILE}"
echo "warn_regression_pct_default=${WARN_REGRESSION_PCT_DEFAULT}"
echo "max_regression_pct=${MAX_REGRESSION_PCT}"
echo "allow_target_violation=${ALLOW_TARGET_VIOLATION}"
echo "skip_overloaded=${SKIP_OVERLOADED} max_load_factor=${MAX_LOAD_FACTOR}"
echo "enable_kernel_suite=${ENABLE_KERNEL_SUITE}"
echo "inject_results=${INJECT_RESULTS_FILE:-<none>}"
echo "attribution_policy=${ATTRIBUTION_POLICY_FILE}"
echo "event_log=${EVENT_LOG_PATH:-<none>}"

if should_skip_overloaded; then
    exit 0
fi

run_mode strict
run_mode hardened

echo ""
echo "perf_gate: PASS"
