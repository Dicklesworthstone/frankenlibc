#!/usr/bin/env bash
# CI gate: Tier 1 Fast Validation artifact + test integrity (bd-2icq.18).
#
# Checks:
# 1. tier1-mini.txt exists and has exactly 5 valid packages
# 2. fast-validate.sh passes bash syntax check
# 3. No tier1 package is in the exclusion list
# 4. All tier1 packages are in top100-packages.txt
# 5. Python tests pass
#
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIER1="${ROOT}/configs/gentoo/tier1-mini.txt"
SCRIPT="${ROOT}/scripts/gentoo/fast-validate.sh"
EXCLUSIONS="${ROOT}/configs/gentoo/exclusions.json"
TOP100="${ROOT}/configs/gentoo/top100-packages.txt"
TEST_FILE="${ROOT}/tests/gentoo/test_fast_validate.py"

echo "=== Tier 1 Fast Validation Gate (bd-2icq.18) ==="

fail() { echo "FAIL: $1"; exit 1; }

# 1. tier1-mini.txt exists and has 5 packages
[[ -f "${TIER1}" ]] || fail "tier1-mini.txt not found at ${TIER1}"
PKG_COUNT=$(grep -cv '^\s*#\|^\s*$' "${TIER1}" || true)
[[ "${PKG_COUNT}" -eq 5 ]] || fail "Expected 5 packages in tier1-mini.txt, found ${PKG_COUNT}"
echo "PASS: tier1-mini.txt has ${PKG_COUNT} packages"

# 2. fast-validate.sh exists and parses
[[ -f "${SCRIPT}" ]] || fail "fast-validate.sh not found"
[[ -x "${SCRIPT}" ]] || fail "fast-validate.sh is not executable"
bash -n "${SCRIPT}" || fail "fast-validate.sh has syntax errors"
echo "PASS: fast-validate.sh syntax valid"

# 3. No exclusion overlap
if [[ -f "${EXCLUSIONS}" ]]; then
  while IFS= read -r pkg; do
    [[ -z "${pkg}" || "${pkg}" == \#* ]] && continue
    if python3 -c "
import json, sys
data = json.load(open('${EXCLUSIONS}'))
excluded = {e['package'] for e in data.get('exclusions', [])}
sys.exit(1 if '${pkg}' in excluded else 0)
" 2>/dev/null; then
      true
    else
      fail "Package '${pkg}' is in exclusion list"
    fi
  done < "${TIER1}"
  echo "PASS: no tier1 packages in exclusion list"
fi

# 4. All tier1 packages in top100
if [[ -f "${TOP100}" ]]; then
  while IFS= read -r pkg; do
    [[ -z "${pkg}" || "${pkg}" == \#* ]] && continue
    if ! grep -qFx "${pkg}" "${TOP100}"; then
      fail "Package '${pkg}' not in top100-packages.txt"
    fi
  done < "${TIER1}"
  echo "PASS: all tier1 packages in top100-packages.txt"
fi

# 5. Python tests pass
if [[ -f "${TEST_FILE}" ]] && command -v python3 >/dev/null 2>&1; then
  python3 -m pytest "${TEST_FILE}" -q --tb=short 2>&1 | tail -5
  echo "PASS: test_fast_validate.py tests passed"
fi

echo ""
echo "PASS: Tier 1 Fast Validation gate (bd-2icq.18) all checks passed"
