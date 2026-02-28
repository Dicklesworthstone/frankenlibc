#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: warm_cache.sh [--packages FILE] [--cache-dir DIR] [--results-dir DIR] [--mode MODE] [--franken-version VER] [--dry-run]

Build packages once with --buildpkg and register artifacts in cache metadata.

Options:
  --packages FILE        Package atom list (default: configs/gentoo/top100-packages.txt)
  --cache-dir DIR        Binary package cache root (default: /var/cache/binpkgs)
  --results-dir DIR      Build output root (default: artifacts/gentoo-builds/cache-warm)
  --mode MODE            FRANKENLIBC_MODE for builds (default: hardened)
  --franken-version VER  FrankenLibC version tag for provenance (default: 0.1.0-dev)
  --dry-run              Print commands without executing emerge/build
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGE_FILE="${ROOT_DIR}/configs/gentoo/top100-packages.txt"
CACHE_DIR="/var/cache/binpkgs"
RESULTS_DIR="${ROOT_DIR}/artifacts/gentoo-builds/cache-warm"
MODE="hardened"
FRANKEN_VERSION="0.1.0-dev"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --packages)
            PACKAGE_FILE="$2"
            shift 2
            ;;
        --cache-dir)
            CACHE_DIR="$2"
            shift 2
            ;;
        --results-dir)
            RESULTS_DIR="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        --franken-version)
            FRANKEN_VERSION="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if [[ ! -f "${PACKAGE_FILE}" ]]; then
    echo "Package file not found: ${PACKAGE_FILE}" >&2
    exit 2
fi

mkdir -p "${RESULTS_DIR}"

atom_key() {
    local atom="$1"
    echo "${atom//\//__}"
}

find_tbz2() {
    local atom="$1"
    local category="${atom%%/*}"
    local package="${atom##*/}"
    find "${CACHE_DIR}/${category}" -maxdepth 1 -type f -name "${package}-*.tbz2" 2>/dev/null | sort | tail -n 1
}

extract_version() {
    local atom="$1"
    local tbz2="$2"
    local package="${atom##*/}"
    local base
    base="$(basename "${tbz2}")"
    base="${base%.tbz2}"
    echo "${base#${package}-}"
}

run_cmd() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run] $*"
        return 0
    fi
    "$@"
}

while IFS= read -r atom; do
    [[ -z "${atom}" || "${atom}" =~ ^# ]] && continue
    key="$(atom_key "${atom}")"
    out_dir="${RESULTS_DIR}/${key}"
    mkdir -p "${out_dir}"

    echo "==> Warming cache for ${atom}"
    if ! run_cmd env FRANKENLIBC_MODE="${MODE}" "${ROOT_DIR}/scripts/gentoo/build-package.sh" "${atom}" "${out_dir}"; then
        echo "WARNING: build failed for ${atom}; skipping cache registration" >&2
        continue
    fi

    tbz2_path="$(find_tbz2 "${atom}")"
    if [[ -z "${tbz2_path}" ]]; then
        echo "WARNING: no tbz2 artifact discovered for ${atom}; skipping cache registration" >&2
        continue
    fi
    version="$(extract_version "${atom}" "${tbz2_path}")"
    heal_count="0"
    if [[ -f "${out_dir}/metadata.json" ]] && command -v jq >/dev/null 2>&1; then
        heal_count="$(jq -r '.frankenlibc_healing_actions // 0' "${out_dir}/metadata.json")"
    fi

    run_cmd python3 "${ROOT_DIR}/scripts/gentoo/cache_manager.py" \
        --cache-dir "${CACHE_DIR}" \
        put \
        --package "${atom}" \
        --version "${version}" \
        --tbz2 "${tbz2_path}" \
        --franken-version "${FRANKEN_VERSION}" \
        --mode "${MODE}" \
        --build-log "${out_dir}/build.log" \
        --healing-actions-count "${heal_count}" >/dev/null
done < "${PACKAGE_FILE}"

echo "==> Cache validation summary"
run_cmd python3 "${ROOT_DIR}/scripts/gentoo/validate_cache.py" \
    --cache-dir "${CACHE_DIR}" \
    --mode "${MODE}" \
    --franken-version "${FRANKEN_VERSION}" \
    --strict
