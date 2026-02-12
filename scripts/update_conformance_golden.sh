#!/usr/bin/env bash
# Regenerate deterministic conformance verify goldens + sha256 sums.
#
# This captures strict+hardened fixture verification outputs and updates
# committed golden artifacts under tests/conformance/golden/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="${ROOT}/tests/conformance/fixtures"
GOLDEN_DIR="${ROOT}/tests/conformance/golden"

REPORT_MD="${GOLDEN_DIR}/fixture_verify_strict_hardened.v1.md"
REPORT_JSON="${GOLDEN_DIR}/fixture_verify_strict_hardened.v1.json"
SHA_FILE="${GOLDEN_DIR}/sha256sums.txt"

mkdir -p "${GOLDEN_DIR}"

echo "=== update_conformance_golden ==="
echo "fixture_dir=${FIXTURE_DIR}"
echo "golden_dir=${GOLDEN_DIR}"

# Fixed timestamp keeps golden outputs byte-stable across runs.
cargo run -q -p frankenlibc-harness --bin harness -- verify \
  --fixture "${FIXTURE_DIR}" \
  --report "${REPORT_MD}" \
  --timestamp "1970-01-01T00:00:00Z"

(
  cd "${GOLDEN_DIR}"
  sha256sum \
    fixture_verify_strict_hardened.v1.md \
    fixture_verify_strict_hardened.v1.json \
    > "${SHA_FILE}"
  sha256sum -c "${SHA_FILE}"
)

echo ""
echo "update_conformance_golden: updated:"
echo "- ${REPORT_MD}"
echo "- ${REPORT_JSON}"
echo "- ${SHA_FILE}"
