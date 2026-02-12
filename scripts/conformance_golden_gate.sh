#!/usr/bin/env bash
# Golden conformance regression gate.
#
# Regenerates deterministic fixture verify outputs and verifies sha256 hashes
# against committed goldens under tests/conformance/golden/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="${ROOT}/tests/conformance/fixtures"
GOLDEN_DIR="${ROOT}/tests/conformance/golden"
OUT_DIR="${ROOT}/target/conformance_golden"

GOLDEN_SHA_FILE="${GOLDEN_DIR}/sha256sums.txt"
GOLDEN_MD="${GOLDEN_DIR}/fixture_verify_strict_hardened.v1.md"
GOLDEN_JSON="${GOLDEN_DIR}/fixture_verify_strict_hardened.v1.json"

OUT_MD="${OUT_DIR}/fixture_verify_strict_hardened.v1.md"
OUT_JSON="${OUT_DIR}/fixture_verify_strict_hardened.v1.json"

if [[ ! -f "${GOLDEN_SHA_FILE}" ]]; then
  echo "conformance_golden_gate: missing golden sha file: ${GOLDEN_SHA_FILE}" >&2
  exit 2
fi
if [[ ! -f "${GOLDEN_MD}" ]]; then
  echo "conformance_golden_gate: missing golden markdown report: ${GOLDEN_MD}" >&2
  exit 2
fi
if [[ ! -f "${GOLDEN_JSON}" ]]; then
  echo "conformance_golden_gate: missing golden json report: ${GOLDEN_JSON}" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"

echo "=== conformance_golden_gate ==="
echo "fixture_dir=${FIXTURE_DIR}"
echo "golden_dir=${GOLDEN_DIR}"
echo "out_dir=${OUT_DIR}"

cargo run -q -p frankenlibc-harness --bin harness -- verify \
  --fixture "${FIXTURE_DIR}" \
  --report "${OUT_MD}" \
  --timestamp "1970-01-01T00:00:00Z"

(
  cd "${OUT_DIR}"
  sha256sum \
    fixture_verify_strict_hardened.v1.md \
    fixture_verify_strict_hardened.v1.json \
    > "${OUT_DIR}/sha256sums.txt"
  sha256sum -c "${GOLDEN_SHA_FILE}"
)

if [[ ! -s "${OUT_MD}" || ! -s "${OUT_JSON}" ]]; then
  echo "conformance_golden_gate: generated outputs are empty" >&2
  exit 1
fi

echo ""
echo "conformance_golden_gate: PASS"
