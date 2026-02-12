#!/usr/bin/env bash
# check_runtime_math_determinism_proofs.sh — Prove runtime_math determinism + invariants (decide+observe).
#
# Bead: bd-1fk1
#
# This gate runs a dedicated harness subcommand which:
# - drives two fresh kernels identically (strict + hardened),
# - asserts per-step decision determinism + final snapshot equality,
# - checks basic invariants (finite f64 fields, ppm bounds, monotone counters),
# - emits structured JSONL logs and a machine-readable JSON report.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/runtime_math_determinism_proofs.log.jsonl"
REPORT_PATH="${OUT_DIR}/runtime_math_determinism_proofs.report.json"

mkdir -p "${OUT_DIR}"

cargo run -p frankenlibc-harness --bin harness -- runtime-math-determinism-proofs \
  --workspace-root "${ROOT}" \
  --log "${LOG_PATH}" \
  --report "${REPORT_PATH}"

echo "OK: runtime_math determinism proofs emitted:"
echo "- ${LOG_PATH}"
echo "- ${REPORT_PATH}"

