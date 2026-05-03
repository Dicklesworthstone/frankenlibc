#!/usr/bin/env bash
# Run the host-glibc baseline Criterion benchmark and tee machine-readable rows.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="${FRANKENLIBC_GLIBC_BASELINE_LOG:-${ROOT}/target/conformance/glibc_baseline_bench.log}"

mkdir -p "$(dirname "${LOG}")"

cd "${ROOT}"
CMD=(cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- --quiet)

if [[ "${FRANKENLIBC_GLIBC_BASELINE_USE_RCH:-1}" == "1" ]] && command -v rch >/dev/null 2>&1; then
    RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:-CARGO_TARGET_DIR}" rch exec -- "${CMD[@]}" 2>&1 | tee "${LOG}"
else
    "${CMD[@]}" 2>&1 | tee "${LOG}"
fi
