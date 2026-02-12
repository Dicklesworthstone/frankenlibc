#!/usr/bin/env bash
# Golden snapshot regression gate for runtime_math telemetry.
#
# Generates deterministic kernel snapshots via frankenlibc-harness and verifies
# sha256 against the committed golden set under tests/runtime_math/golden/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLDEN_DIR="${ROOT}/tests/runtime_math/golden"
OUT_DIR="${ROOT}/target/runtime_math_golden"

GOLDEN_SHA_FILE="${GOLDEN_DIR}/sha256sums.txt"
GOLDEN_SNAPSHOT="${GOLDEN_DIR}/kernel_snapshot_smoke.v1.json"

OUT_SNAPSHOT="${OUT_DIR}/kernel_snapshot_smoke.v1.json"

if [[ ! -f "${GOLDEN_SHA_FILE}" ]]; then
  echo "snapshot_gate: missing golden sha file: ${GOLDEN_SHA_FILE}" >&2
  exit 2
fi
if [[ ! -f "${GOLDEN_SNAPSHOT}" ]]; then
  echo "snapshot_gate: missing golden snapshot: ${GOLDEN_SNAPSHOT}" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"

echo "=== snapshot_gate ==="
echo "golden_dir=${GOLDEN_DIR}"
echo "out_dir=${OUT_DIR}"

# Keep parameters in sync with tests/runtime_math/golden/kernel_snapshot_smoke.v1.json.
cargo run -q -p frankenlibc-harness --bin harness -- snapshot-kernel \
  --output "${OUT_SNAPSHOT}" \
  --mode both \
  --seed 0xDEAD_BEEF \
  --steps 512

set +e
(cd "${OUT_DIR}" && sha256sum -c "${GOLDEN_SHA_FILE}")
rc=$?
set -e

if [[ "${rc}" -ne 0 ]]; then
  echo ""
  echo "snapshot_gate: sha256 mismatch; diff vs golden (first 200 lines):" >&2
  diff -u "${GOLDEN_SNAPSHOT}" "${OUT_SNAPSHOT}" | head -n 200 >&2 || true
  exit 1
fi

echo ""
echo "snapshot_gate: PASS"

