#!/usr/bin/env bash
# CI gate: Proof obligations binder integrity + regression proofing.
#
# Emits:
# - structured JSONL logs
# - a machine-readable gate report
# - a fresh validator snapshot for replay/drift review
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/proof_binder_proofs.log.jsonl"
REPORT_PATH="${OUT_DIR}/proof_binder_proofs.report.json"
VALIDATOR_REPORT_PATH="${OUT_DIR}/proof_binder_validation.current.v1.json"

mkdir -p "${OUT_DIR}"

cargo run -p frankenlibc-harness --bin harness -- proof-binder-proofs \
  --workspace-root "${ROOT}" \
  --log "${LOG_PATH}" \
  --report "${REPORT_PATH}" \
  --validator-report "${VALIDATOR_REPORT_PATH}"

echo "OK: proof binder proofs emitted:"
echo "- ${LOG_PATH}"
echo "- ${REPORT_PATH}"
echo "- ${VALIDATOR_REPORT_PATH}"
