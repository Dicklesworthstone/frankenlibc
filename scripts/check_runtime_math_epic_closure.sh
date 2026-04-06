#!/usr/bin/env bash
# check_runtime_math_epic_closure.sh — aggregate closure gate for bd-5vr
#
# This gate proves the runtime-math epic is closure-ready by aggregating the
# existing manifest/governance/linkage/admission/value/branch-diversity checks
# into one deterministic report + structured log.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/runtime_math_epic_closure.log.jsonl"
CHECKS_PATH="${OUT_DIR}/runtime_math_epic_closure.checks.jsonl"
REPORT_PATH="${OUT_DIR}/runtime_math_epic_closure.report.json"
MOD_RS="${ROOT}/crates/frankenlibc-membrane/src/runtime_math/mod.rs"
MANIFEST="${ROOT}/tests/runtime_math/production_kernel_manifest.v1.json"
ADMISSION_REPORT="${ROOT}/tests/runtime_math/admission_gate_report.v1.json"
ABLATION_REPORT="${ROOT}/tests/runtime_math/controller_ablation_report.v1.json"
REVERSE_ROUND_REPORT="${ROOT}/tests/conformance/reverse_round_contracts.v1.json"

if ! command -v jq >/dev/null 2>&1; then
    echo "FAIL: jq is required for runtime_math epic closure checks"
    exit 1
fi

mkdir -p "${OUT_DIR}"
: > "${LOG_PATH}"
: > "${CHECKS_PATH}"

check_count=0
failed=0

append_check() {
    local gate="$1"
    local name="$2"
    local cmd="$3"
    local artifacts="$4"

    local start_ns end_ns latency_ns rc level status timestamp summary_line output_excerpt
    start_ns="$(date +%s%N)"
    set +e
    output_excerpt="$(cd "${ROOT}" && eval "${cmd}" 2>&1)"
    rc=$?
    set -e
    end_ns="$(date +%s%N)"
    latency_ns=$((end_ns - start_ns))
    check_count=$((check_count + 1))

    if [[ ${rc} -eq 0 ]]; then
        status="pass"
        level="info"
    else
        status="fail"
        level="error"
        failed=$((failed + 1))
    fi

    output_excerpt="$(printf '%s\n' "${output_excerpt}" | tail -n 20)"
    summary_line="$(printf '%s\n' "${output_excerpt}" | awk 'NF{line=$0} END{print line}')"
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    jq -nc \
        --arg timestamp "${timestamp}" \
        --arg trace_id "bd-5vr::runtime-math-epic-closure::${gate}" \
        --arg level "${level}" \
        --arg event "runtime_math.epic_closure.check" \
        --arg bead_id "bd-5vr" \
        --arg gate_name "${name}" \
        --arg gate "${gate}" \
        --arg mode "strict+hardened" \
        --arg api_family "runtime_math" \
        --arg symbol "${gate}" \
        --arg decision_path "aggregate_epic_closure" \
        --arg healing_action "none" \
        --arg status "${status}" \
        --arg check_cmd "${cmd}" \
        --arg summary_line "${summary_line}" \
        --arg output_excerpt "${output_excerpt}" \
        --argjson exit_code "${rc}" \
        --argjson latency_ns "${latency_ns}" \
        --argjson artifact_refs "$(printf '%s' "${artifacts}" | jq -Rc 'split(";") | map(select(length > 0))')" \
        '{
            timestamp: $timestamp,
            trace_id: $trace_id,
            level: $level,
            event: $event,
            bead_id: $bead_id,
            gate: $gate_name,
            mode: $mode,
            api_family: $api_family,
            symbol: $symbol,
            decision_path: $decision_path,
            healing_action: $healing_action,
            errno: 0,
            exit_code: $exit_code,
            latency_ns: $latency_ns,
            artifact_refs: $artifact_refs,
            details: {
                gate_id: $gate,
                status: $status,
                check_cmd: $check_cmd,
                summary_line: $summary_line,
                output_excerpt: $output_excerpt
            }
        }' >> "${LOG_PATH}"

    jq -nc \
        --arg gate "${gate}" \
        --arg name "${name}" \
        --arg check_cmd "${cmd}" \
        --arg status "${status}" \
        --arg summary_line "${summary_line}" \
        --arg output_excerpt "${output_excerpt}" \
        --argjson exit_code "${rc}" \
        --argjson latency_ns "${latency_ns}" \
        --argjson artifact_refs "$(printf '%s' "${artifacts}" | jq -Rc 'split(";") | map(select(length > 0))')" \
        '{
            gate: $gate,
            name: $name,
            check_cmd: $check_cmd,
            status: $status,
            exit_code: $exit_code,
            latency_ns: $latency_ns,
            artifact_refs: $artifact_refs,
            summary_line: $summary_line,
            output_excerpt: $output_excerpt
        }' >> "${CHECKS_PATH}"
}

echo "=== Runtime Math Epic Closure Gate (bd-5vr) ==="

append_check \
    "manifest" \
    "Runtime math production manifest" \
    "bash scripts/check_runtime_math_manifest.sh" \
    "tests/runtime_math/production_kernel_manifest.v1.json"

append_check \
    "linkage" \
    "Runtime math linkage ledger" \
    "bash scripts/check_runtime_math_linkage.sh" \
    "tests/runtime_math/runtime_math_linkage.v1.json"

append_check \
    "linkage_proofs" \
    "Runtime math linkage proofs" \
    "bash scripts/check_runtime_math_linkage_proofs.sh" \
    "target/conformance/runtime_math_linkage_proofs.report.json;target/conformance/runtime_math_linkage_proofs.log.jsonl"

append_check \
    "admission" \
    "Runtime math admission gate" \
    "bash scripts/check_runtime_math_admission.sh" \
    "tests/runtime_math/admission_gate_report.v1.json;tests/runtime_math/controller_manifest.v1.json;target/conformance/runtime_math_admission_gate.log.jsonl"

append_check \
    "ablation" \
    "Controller ablation partitioning" \
    "bash scripts/check_controller_ablation.sh" \
    "tests/runtime_math/controller_ablation_report.v1.json"

append_check \
    "governance" \
    "Math governance policy" \
    "bash scripts/check_math_governance.sh" \
    "tests/conformance/math_governance.json"

append_check \
    "classification_matrix" \
    "Runtime math classification matrix" \
    "bash scripts/check_runtime_math_classification_matrix.sh" \
    "tests/runtime_math/runtime_math_classification_matrix.v1.json;target/conformance/runtime_math_classification_matrix.report.json;target/conformance/runtime_math_classification_matrix.log.jsonl"

append_check \
    "value_proof" \
    "Math value proof" \
    "bash scripts/check_math_value_proof.sh" \
    "tests/conformance/math_value_proof.json"

append_check \
    "reverse_round_contracts" \
    "Reverse-round branch diversity contracts" \
    "bash scripts/check_reverse_round_contracts.sh" \
    "tests/conformance/reverse_round_contracts.v1.json"

module_count="$(grep -oP '^pub mod \K[a-z_]+' "${MOD_RS}" | sort -u | wc -l | tr -d ' ')"
production_modules="$(jq '.production_modules | length' "${MANIFEST}")"
research_only_modules="$(jq '.research_only_modules | length' "${MANIFEST}")"
admission_blocked="$(jq '.summary.blocked // 0' "${ADMISSION_REPORT}")"
admission_admitted="$(jq '.summary.admitted // 0' "${ADMISSION_REPORT}")"
ablation_blocked="$(jq '.summary.blocked // 0' "${ABLATION_REPORT}")"
all_rounds_diverse="$(jq '.summary.all_rounds_diverse // false' "${REVERSE_ROUND_REPORT}")"
status="pass"
summary_level="info"
if [[ ${failed} -ne 0 ]]; then
    status="fail"
    summary_level="error"
fi

jq -s \
    --arg schema_version "v1" \
    --arg bead "bd-5vr" \
    --arg status "${status}" \
    --arg structured_log "target/conformance/runtime_math_epic_closure.log.jsonl" \
    --arg checks_log "target/conformance/runtime_math_epic_closure.checks.jsonl" \
    --arg manifest_ref "tests/runtime_math/production_kernel_manifest.v1.json" \
    --arg admission_ref "tests/runtime_math/admission_gate_report.v1.json" \
    --arg controller_manifest_ref "tests/runtime_math/controller_manifest.v1.json" \
    --arg ablation_ref "tests/runtime_math/controller_ablation_report.v1.json" \
    --arg governance_ref "tests/conformance/math_governance.json" \
    --arg linkage_ref "tests/runtime_math/runtime_math_linkage.v1.json" \
    --arg reverse_round_ref "tests/conformance/reverse_round_contracts.v1.json" \
    --arg value_proof_ref "tests/conformance/math_value_proof.json" \
    --argjson total_checks "${check_count}" \
    --argjson passed_checks "$((check_count - failed))" \
    --argjson failed_checks "${failed}" \
    --argjson total_modules "${module_count}" \
    --argjson production_modules "${production_modules}" \
    --argjson research_only_modules "${research_only_modules}" \
    --argjson admission_blocked "${admission_blocked}" \
    --argjson admission_admitted "${admission_admitted}" \
    --argjson ablation_blocked "${ablation_blocked}" \
    --argjson all_rounds_diverse "${all_rounds_diverse}" \
    '{
        schema_version: $schema_version,
        bead: $bead,
        status: $status,
        summary: {
            total_checks: $total_checks,
            passed_checks: $passed_checks,
            failed_checks: $failed_checks,
            total_modules: $total_modules,
            production_modules: $production_modules,
            research_only_modules: $research_only_modules,
            admission_blocked: $admission_blocked,
            admission_admitted: $admission_admitted,
            ablation_blocked: $ablation_blocked,
            all_rounds_diverse: $all_rounds_diverse,
            all_checks_passed: ($failed_checks == 0)
        },
        checks: .,
        artifacts: {
            manifest: $manifest_ref,
            admission_report: $admission_ref,
            controller_manifest: $controller_manifest_ref,
            ablation_report: $ablation_ref,
            governance: $governance_ref,
            linkage: $linkage_ref,
            reverse_round_contracts: $reverse_round_ref,
            value_proof: $value_proof_ref,
            structured_log: $structured_log,
            checks_log: $checks_log
        }
    }' "${CHECKS_PATH}" > "${REPORT_PATH}"

jq -nc \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg trace_id "bd-5vr::runtime-math-epic-closure::summary" \
    --arg level "${summary_level}" \
    --arg event "runtime_math.epic_closure.summary" \
    --arg bead_id "bd-5vr" \
    --arg gate "Runtime math epic closure" \
    --arg mode "strict+hardened" \
    --arg api_family "runtime_math" \
    --arg symbol "bd-5vr" \
    --arg decision_path "aggregate_epic_closure" \
    --arg healing_action "none" \
    --arg status "${status}" \
    --arg report_ref "target/conformance/runtime_math_epic_closure.report.json" \
    --arg checks_ref "target/conformance/runtime_math_epic_closure.checks.jsonl" \
    --arg log_ref "target/conformance/runtime_math_epic_closure.log.jsonl" \
    --argjson latency_ns 0 \
    --argjson total_checks "${check_count}" \
    --argjson failed_checks "${failed}" \
    --argjson total_modules "${module_count}" \
    --argjson admission_blocked "${admission_blocked}" \
    --argjson all_rounds_diverse "${all_rounds_diverse}" \
    '{
        timestamp: $timestamp,
        trace_id: $trace_id,
        level: $level,
        event: $event,
        bead_id: $bead_id,
        gate: $gate,
        mode: $mode,
        api_family: $api_family,
        symbol: $symbol,
        decision_path: $decision_path,
        healing_action: $healing_action,
        errno: 0,
        latency_ns: $latency_ns,
        artifact_refs: [$report_ref, $checks_ref, $log_ref],
        details: {
            status: $status,
            total_checks: $total_checks,
            failed_checks: $failed_checks,
            total_modules: $total_modules,
            admission_blocked: $admission_blocked,
            all_rounds_diverse: $all_rounds_diverse
        }
    }' >> "${LOG_PATH}"

if [[ ${failed} -ne 0 ]]; then
    echo "FAIL: runtime math epic closure gate found ${failed} failing check(s)"
    echo "Report: ${REPORT_PATH}"
    echo "Structured log: ${LOG_PATH}"
    exit 1
fi

echo "PASS: runtime math epic closure gate validated ${check_count} checks for ${module_count} modules"
echo "Report: ${REPORT_PATH}"
echo "Structured log: ${LOG_PATH}"
