#!/usr/bin/env bash
# Regenerate committed golden runtime_math snapshot fixtures + sha256sums.
#
# This is the intentional-update path when kernel snapshot behavior changes
# and you have an isomorphism proof for the change (see:
# scripts/POLICY_CHANGE_ISOMORPHISM_PROOF_TEMPLATE.md).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLDEN_DIR="${ROOT}/tests/runtime_math/golden"

SNAPSHOT_FILE="${GOLDEN_DIR}/kernel_snapshot_smoke.v1.json"
SHA_FILE="${GOLDEN_DIR}/sha256sums.txt"

mkdir -p "${GOLDEN_DIR}"

echo "=== update_golden_snapshots ==="
echo "golden_dir=${GOLDEN_DIR}"

# Parameters define the canonical golden scenario.
cargo run -q -p frankenlibc-harness --bin harness -- snapshot-kernel \
  --output "${SNAPSHOT_FILE}" \
  --mode both \
  --seed 0xDEAD_BEEF \
  --steps 512

sha256sum "${SNAPSHOT_FILE}" | awk '{print $1"  kernel_snapshot_smoke.v1.json"}' > "${SHA_FILE}"

(cd "${GOLDEN_DIR}" && sha256sum -c "${SHA_FILE}")

echo ""
echo "update_golden_snapshots: updated:"
echo "- ${SNAPSHOT_FILE}"
echo "- ${SHA_FILE}"
