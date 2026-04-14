#!/usr/bin/env bash
#
# check_glibc_offsets.sh - Verify _IO_FILE offsets match FrankenLibC's pinned baseline
#
# Usage: ./check_glibc_offsets.sh [--json] [-v|--verbose]
#
# Exit codes:
#   0 - All offsets match
#   1 - Offset mismatch detected
#   2 - Compilation or execution error
#
# Part of bd-9chy.41: glibc version matrix CI

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SCRIPT_DIR}/../.."
OUT_DIR="${ROOT}/target/glibc_offset_check"

mkdir -p "${OUT_DIR}"

SRC="${SCRIPT_DIR}/extract_io_file_offsets.c"
BIN="${OUT_DIR}/extract_io_file_offsets"
LOG="${OUT_DIR}/glibc_offset_check.log"
JSON="${OUT_DIR}/glibc_offset_check.json"

echo "[glibc-offset-check] Compiling offset extractor..." | tee "${LOG}"

if ! cc -std=c11 -Wall -Wextra -O2 "${SRC}" -o "${BIN}" >>"${LOG}" 2>&1; then
    echo "FAIL: Failed to compile offset extractor. See ${LOG}" >&2
    exit 2
fi

echo "[glibc-offset-check] Running offset check..." | tee -a "${LOG}"

# Run with JSON output for CI artifacts
if ! "${BIN}" --json > "${JSON}" 2>>"${LOG}"; then
    echo "[glibc-offset-check] Offset mismatch detected!" | tee -a "${LOG}"
fi

# Also run verbose human-readable output
"${BIN}" -v 2>&1 | tee -a "${LOG}"

# Extract result from JSON
if command -v jq >/dev/null 2>&1; then
    compatible=$(jq -r '.compatible' "${JSON}")
    glibc_ver=$(jq -r '.glibc_version' "${JSON}")
    file_size=$(jq -r '.sizeof_FILE' "${JSON}")
    echo "" | tee -a "${LOG}"
    echo "[glibc-offset-check] glibc ${glibc_ver}: sizeof(FILE)=${file_size}" | tee -a "${LOG}"
    if [[ "${compatible}" == "true" ]]; then
        echo "PASS: glibc ${glibc_ver} is compatible with FrankenLibC NativeFile" | tee -a "${LOG}"
        exit 0
    else
        echo "FAIL: glibc ${glibc_ver} is NOT compatible with FrankenLibC NativeFile" | tee -a "${LOG}"
        echo "      FrankenLibC's NativeFile struct may need adjustment for this glibc version" | tee -a "${LOG}"
        exit 1
    fi
else
    # Fallback: check exit code from binary
    if "${BIN}" >/dev/null 2>&1; then
        echo "PASS: glibc compatible" | tee -a "${LOG}"
        exit 0
    else
        echo "FAIL: glibc not compatible" | tee -a "${LOG}"
        exit 1
    fi
fi
