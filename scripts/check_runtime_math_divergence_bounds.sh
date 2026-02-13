#!/usr/bin/env bash
# check_runtime_math_divergence_bounds.sh — Enforce strict-vs-hardened divergence bounds for runtime_math.
#
# Bead: bd-2625
#
# This gate runs a dedicated harness subcommand which:
# - loads the divergence bounds matrix (tests/runtime_math/runtime_math_divergence_bounds.v1.json),
# - evaluates representative contexts under strict + hardened kernels,
# - asserts forbidden divergence patterns never occur,
# - asserts required strict/hardened decision pairs remain stable,
# - emits structured JSONL logs and a machine-readable JSON report.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/runtime_math_divergence_bounds.log.jsonl"
REPORT_PATH="${OUT_DIR}/runtime_math_divergence_bounds.report.json"

mkdir -p "${OUT_DIR}"

cargo run -p frankenlibc-harness --bin harness -- runtime-math-divergence-bounds \
  --workspace-root "${ROOT}" \
  --log "${LOG_PATH}" \
  --report "${REPORT_PATH}"

echo "OK: runtime_math divergence bounds emitted:"
echo "- ${LOG_PATH}"
echo "- ${REPORT_PATH}"

