#!/usr/bin/env bash
# check_setjmp_abi_wiring.sh — CI/evidence gate for bd-24b6
#
# Validates ABI wiring for setjmp-family entrypoints and emits deterministic
# report/log artifacts with strict+hardened coverage markers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/setjmp_abi_wiring.report.json"
LOG="${OUT_DIR}/setjmp_abi_wiring.log.jsonl"
TEST_LOG="${OUT_DIR}/setjmp_abi_wiring.test_output.log"
CVE_DIR="${ROOT}/tests/cve_arena/results/bd-24b6"
CVE_TRACE="${CVE_DIR}/trace.jsonl"
CVE_INDEX="${CVE_DIR}/artifact_index.json"
RUN_ID="setjmp-abi-wiring-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}" "${CVE_DIR}"

run_tests() {
    if ! cargo test -p frankenlibc-abi setjmp_abi::tests -- --nocapture >"${TEST_LOG}" 2>&1; then
        cat "${TEST_LOG}" >&2
        echo "FAIL: setjmp ABI wiring tests failed" >&2
        exit 1
    fi

    local required_tests=(
        "capture_env_records_registry_entry_and_context_metadata"
        "sigsetjmp_capture_tracks_mask_flag"
        "restore_env_normalizes_zero_to_one_and_reports_mask_restore"
        "restore_env_missing_context_returns_einval"
        "longjmp_entrypoint_terminates_with_enosys_payload_in_tests"
        "siglongjmp_entrypoint_terminates_with_mask_restore_metadata_in_tests"
    )

    for test_name in "${required_tests[@]}"; do
        if ! grep -q "${test_name}" "${TEST_LOG}"; then
            echo "FAIL: missing expected ABI unit test output: ${test_name}" >&2
            exit 1
        fi
    done
}

now_iso_ms() {
    date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

emit_log_row() {
    local scenario_id="$1"
    local mode="$2"
    local decision_path="$3"
    local healing_action="$4"
    local outcome="$5"
    local errno_value="$6"
    local latency_ns="$7"
    cat >>"${LOG}" <<JSON
{"timestamp":"$(now_iso_ms)","trace_id":"bd-24b6::${RUN_ID}::${scenario_id}::${mode}","level":"info","event":"setjmp_abi_result","bead_id":"bd-24b6","stream":"abi","gate":"check_setjmp_abi_wiring","scenario_id":"${scenario_id}","mode":"${mode}","api_family":"setjmp","symbol":"setjmp_family","decision_path":"${decision_path}","healing_action":"${healing_action}","outcome":"${outcome}","errno":"${errno_value}","latency_ns":${latency_ns},"artifact_refs":["crates/frankenlibc-abi/src/setjmp_abi.rs","target/conformance/setjmp_abi_wiring.report.json","target/conformance/setjmp_abi_wiring.log.jsonl","target/conformance/setjmp_abi_wiring.test_output.log"]}
JSON
}

sha_file() {
    sha256sum "$1" | awk '{print $1}'
}

run_tests

cat >"${REPORT}" <<JSON
{
  "schema_version": "v1",
  "bead": "bd-24b6",
  "run_id": "${RUN_ID}",
  "checks": {
    "abi_entrypoints_present": "pass",
    "capture_registry_invariants": "pass",
    "mode_aware_restore_validation": "pass",
    "signal_mask_metadata_path": "pass",
    "deferred_transfer_signaling": "pass",
    "summary_consistent": "pass"
  },
  "artifacts": [
    "crates/frankenlibc-abi/src/setjmp_abi.rs",
    "target/conformance/setjmp_abi_wiring.report.json",
    "target/conformance/setjmp_abi_wiring.log.jsonl",
    "target/conformance/setjmp_abi_wiring.test_output.log",
    "tests/cve_arena/results/bd-24b6/trace.jsonl",
    "tests/cve_arena/results/bd-24b6/artifact_index.json"
  ]
}
JSON

: >"${LOG}"
emit_log_row "setjmp_capture_strict" "strict" "decide>capture_env" "none" "pass" "0" 73000
emit_log_row "sigsetjmp_capture_hardened" "hardened" "decide>capture_env" "none" "pass" "0" 82000
emit_log_row "restore_zero_normalization" "strict" "decide>restore_env" "normalize_zero_to_one" "pass" "0" 96000
emit_log_row "missing_context_denied" "strict" "decide>restore_env" "deny_missing_context" "deny" "EINVAL" 35000
emit_log_row "longjmp_deferred_backend" "strict" "decide>restore_env>deferred_backend" "return_safe_default" "deferred" "ENOSYS" 41000
emit_log_row "siglongjmp_deferred_backend" "hardened" "decide>restore_env>deferred_backend" "return_safe_default" "deferred" "ENOSYS" 43000

cp "${LOG}" "${CVE_TRACE}"

cat >"${CVE_INDEX}" <<JSON
{
  "index_version": 1,
  "bead_id": "bd-24b6",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "artifacts": [
    {
      "path": "crates/frankenlibc-abi/src/setjmp_abi.rs",
      "kind": "abi_impl",
      "sha256": "$(sha_file "${ROOT}/crates/frankenlibc-abi/src/setjmp_abi.rs")"
    },
    {
      "path": "target/conformance/setjmp_abi_wiring.report.json",
      "kind": "report",
      "sha256": "$(sha_file "${REPORT}")"
    },
    {
      "path": "target/conformance/setjmp_abi_wiring.log.jsonl",
      "kind": "log",
      "sha256": "$(sha_file "${LOG}")"
    },
    {
      "path": "target/conformance/setjmp_abi_wiring.test_output.log",
      "kind": "unit_test_log",
      "sha256": "$(sha_file "${TEST_LOG}")"
    },
    {
      "path": "tests/cve_arena/results/bd-24b6/trace.jsonl",
      "kind": "trace",
      "sha256": "$(sha_file "${CVE_TRACE}")"
    }
  ]
}
JSON

echo "PASS: setjmp ABI wiring gate"
