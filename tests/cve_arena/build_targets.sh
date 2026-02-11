#!/usr/bin/env bash
# F3: CVE Arena container build system for external targets.
#
# Builds Docker images for each external software target with both
# stock glibc and glibc_rust support. Images are cached and only
# rebuilt when Dockerfiles or build scripts change.
#
# Usage:
#   ./build_targets.sh              # Build all targets
#   ./build_targets.sh redis sudo   # Build specific targets
#   ./build_targets.sh --clean      # Remove all built images
#   ./build_targets.sh --list       # List available targets

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_DIR="${SCRIPT_DIR}/targets"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GLIBC_RUST_LIB="${PROJECT_ROOT}/target/release/libglibc_rs_abi.so"
IMAGE_PREFIX="cve-arena"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $*"; }

list_targets() {
    echo "Available CVE Arena external targets:"
    echo ""
    for target_dir in "${TARGETS_DIR}"/*/; do
        if [ -f "${target_dir}/Dockerfile" ]; then
            local name
            name="$(basename "${target_dir}")"
            local manifest="${target_dir}/manifest.json"
            if [ -f "${manifest}" ]; then
                local cve_id description
                cve_id="$(jq -r '.cve_id // "unknown"' "${manifest}")"
                description="$(jq -r '.description // "no description"' "${manifest}")"
                printf "  %-12s %s - %s\n" "${name}" "${cve_id}" "${description}"
            else
                printf "  %-12s (no manifest)\n" "${name}"
            fi
        fi
    done
}

clean_images() {
    log_info "Removing all CVE Arena Docker images..."
    local images
    images="$(docker images --filter "reference=${IMAGE_PREFIX}-*" -q 2>/dev/null || true)"
    if [ -n "${images}" ]; then
        echo "${images}" | xargs docker rmi -f
        log_ok "Cleaned all CVE Arena images"
    else
        log_info "No CVE Arena images found"
    fi
}

build_target() {
    local target_name="$1"
    local target_dir="${TARGETS_DIR}/${target_name}"
    local image_name="${IMAGE_PREFIX}-${target_name}"

    if [ ! -d "${target_dir}" ]; then
        log_err "Target directory not found: ${target_dir}"
        return 1
    fi

    if [ ! -f "${target_dir}/Dockerfile" ]; then
        log_err "No Dockerfile in ${target_dir}"
        return 1
    fi

    log_info "Building target: ${target_name}"

    # Check if glibc_rust library exists
    if [ -f "${GLIBC_RUST_LIB}" ]; then
        log_info "  glibc_rust library: ${GLIBC_RUST_LIB}"
        # Copy library into build context for Docker
        cp "${GLIBC_RUST_LIB}" "${target_dir}/libglibc_rs_abi.so"
    else
        log_warn "  glibc_rust library not found at ${GLIBC_RUST_LIB}"
        log_warn "  Building without TSM support (stock glibc only)"
    fi

    # Build the Docker image
    local build_start
    build_start="$(date +%s)"

    if docker build \
        -t "${image_name}" \
        --build-arg "BUILDKIT_INLINE_CACHE=1" \
        -f "${target_dir}/Dockerfile" \
        "${target_dir}" 2>&1; then
        local build_end
        build_end="$(date +%s)"
        local duration=$(( build_end - build_start ))
        log_ok "Built ${image_name} in ${duration}s"
    else
        log_err "Failed to build ${image_name}"
        return 1
    fi

    # Clean up copied library
    rm -f "${target_dir}/libglibc_rs_abi.so"
}

verify_prerequisites() {
    if ! command -v docker &>/dev/null; then
        log_err "Docker is required but not installed"
        log_err "Install Docker: https://docs.docker.com/engine/install/"
        exit 1
    fi

    if ! docker info &>/dev/null; then
        log_err "Docker daemon is not running or current user lacks permissions"
        exit 1
    fi

    if ! command -v jq &>/dev/null; then
        log_warn "jq not installed; manifest parsing will be limited"
    fi
}

main() {
    if [ "${1:-}" = "--list" ]; then
        list_targets
        exit 0
    fi

    if [ "${1:-}" = "--clean" ]; then
        clean_images
        exit 0
    fi

    verify_prerequisites

    local targets=()

    if [ $# -eq 0 ] || [ "${1:-}" = "--all" ]; then
        # Build all targets
        for target_dir in "${TARGETS_DIR}"/*/; do
            if [ -f "${target_dir}/Dockerfile" ]; then
                targets+=("$(basename "${target_dir}")")
            fi
        done
    else
        targets=("$@")
    fi

    if [ ${#targets[@]} -eq 0 ]; then
        log_warn "No targets found in ${TARGETS_DIR}"
        exit 0
    fi

    log_info "Building ${#targets[@]} target(s): ${targets[*]}"
    echo ""

    local built=0
    local failed=0

    for target in "${targets[@]}"; do
        if build_target "${target}"; then
            (( built++ ))
        else
            (( failed++ ))
        fi
        echo ""
    done

    echo "=========================================="
    log_info "Build complete: ${built} succeeded, ${failed} failed"

    if [ "${failed}" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
