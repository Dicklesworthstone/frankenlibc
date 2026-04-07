#!/usr/bin/env bash
# CI gate: proof-chain E2E integrity, dashboard verification, and contradiction checks.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/proof_chain_e2e.log.jsonl"
REPORT_PATH="${OUT_DIR}/proof_chain_e2e.report.json"
BINDER_LOG_PATH="${OUT_DIR}/proof_chain_e2e.proof_binder.log.jsonl"
BINDER_REPORT_PATH="${OUT_DIR}/proof_chain_e2e.proof_binder.report.json"
VALIDATOR_REPORT_PATH="${OUT_DIR}/proof_chain_e2e.validator.current.v1.json"
CROSS_REPORT_PATH="${OUT_DIR}/proof_chain_e2e.cross_report.current.v1.json"

mkdir -p "${OUT_DIR}"

cargo run -p frankenlibc-harness --bin harness -- proof-chain-e2e \
  --workspace-root "${ROOT}" \
  --log "${LOG_PATH}" \
  --report "${REPORT_PATH}" \
  --binder-log "${BINDER_LOG_PATH}" \
  --binder-report "${BINDER_REPORT_PATH}" \
  --validator-report "${VALIDATOR_REPORT_PATH}" \
  --cross-report "${CROSS_REPORT_PATH}"

echo "OK: proof chain E2E emitted:"
echo "- ${LOG_PATH}"
echo "- ${REPORT_PATH}"
echo "- ${BINDER_REPORT_PATH}"
echo "- ${VALIDATOR_REPORT_PATH}"
echo "- ${CROSS_REPORT_PATH}"
