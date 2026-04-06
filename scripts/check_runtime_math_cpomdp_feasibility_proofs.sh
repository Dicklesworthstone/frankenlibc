#!/usr/bin/env bash
# check_runtime_math_cpomdp_feasibility_proofs.sh — Prove finite CPOMDP safety feasibility.
#
# Bead: bd-249m.4
#
# This gate runs a dedicated harness subcommand which:
# - constructs the finite CPOMDP abstraction over TSM safety states,
# - solves the constrained primal/dual LP exactly over deterministic policy vertices,
# - emits structured JSONL logs plus JSON feasibility/sensitivity artifacts,
# - verifies the live runtime_math wiring still exposes pomdp_repair surfaces.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/runtime_math_cpomdp_feasibility_proofs.log.jsonl"
REPORT_PATH="${OUT_DIR}/runtime_math_cpomdp_feasibility_proofs.report.json"
FEASIBILITY_PATH="${OUT_DIR}/cpomdp_feasibility.json"
SENSITIVITY_PATH="${OUT_DIR}/cpomdp_sensitivity.json"

mkdir -p "${OUT_DIR}"

cargo run -p frankenlibc-harness --bin harness -- runtime-math-cpomdp-feasibility-proofs \
  --workspace-root "${ROOT}" \
  --log "${LOG_PATH}" \
  --report "${REPORT_PATH}" \
  --feasibility-artifact "${FEASIBILITY_PATH}" \
  --sensitivity-artifact "${SENSITIVITY_PATH}"

echo "OK: runtime_math CPOMDP feasibility proofs emitted:"
echo "- ${LOG_PATH}"
echo "- ${REPORT_PATH}"
echo "- ${FEASIBILITY_PATH}"
echo "- ${SENSITIVITY_PATH}"
