#!/usr/bin/env bash
# =============================================================================
# CVE Arena Test Runner
# =============================================================================
#
# Runs CVE reproduction tests against both stock glibc and FrankenLibC (TSM)
# to verify that the membrane prevents or detects known vulnerabilities.
#
# Usage:
#   ./runner.sh [--all | --category=glibc|external|synthetic | CVE_DIR]
#   ./runner.sh --no-docker tests/cve_arena/glibc/cve_2024_2961_iconv
#   ./runner.sh --all --verbose
#   ./runner.sh --category=glibc --no-docker
#
# Environment:
#   FRANKENLIBC_LIB   Path to libfrankenlibc_abi.so (default: auto-detected)
#   CVE_ARENA_TIMEOUT Per-test timeout in seconds (default: 30)
#   CVE_ARENA_IMAGE   Docker image name (default: frankenlibc-cve-arena)
#
# Exit codes:
#   0  All tests produced expected verdicts
#   1  One or more tests had unexpected verdicts (REGRESSION)
#   2  Infrastructure error (missing dependencies, build failure)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULTS_DIR="${CVE_ARENA_RESULTS_DIR:-${SCRIPT_DIR}/results}"
readonly SIGNAL_WRAPPER="${SCRIPT_DIR}/signal_wrapper.sh"
readonly DOCKERFILE="${SCRIPT_DIR}/Dockerfile"

readonly DEFAULT_TIMEOUT=30
readonly DEFAULT_IMAGE="frankenlibc-cve-arena"

readonly VALID_CATEGORIES=("glibc-internal" "external" "synthetic")

# Map signal numbers to names (portable subset).
declare -A SIGNAL_NAMES=(
    [4]="SIGILL"
    [6]="SIGABRT"
    [7]="SIGBUS"
    [8]="SIGFPE"
    [9]="SIGKILL"
    [11]="SIGSEGV"
    [14]="SIGALRM"
    [15]="SIGTERM"
    [24]="SIGXCPU"
    [25]="SIGXFSZ"
    [31]="SIGSYS"
)

# ---------------------------------------------------------------------------
# Terminal colors (disabled if not a tty)
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    readonly C_RED='\033[0;31m'
    readonly C_GREEN='\033[0;32m'
    readonly C_YELLOW='\033[0;33m'
    readonly C_BLUE='\033[0;34m'
    readonly C_MAGENTA='\033[0;35m'
    readonly C_CYAN='\033[0;36m'
    readonly C_BOLD='\033[1m'
    readonly C_RESET='\033[0m'
else
    readonly C_RED=''
    readonly C_GREEN=''
    readonly C_YELLOW=''
    readonly C_BLUE=''
    readonly C_MAGENTA=''
    readonly C_CYAN=''
    readonly C_BOLD=''
    readonly C_RESET=''
fi

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

log_info()  { printf "${C_BLUE}[INFO]${C_RESET}  %s\n" "$*" >&2; }
log_ok()    { printf "${C_GREEN}[OK]${C_RESET}    %s\n" "$*" >&2; }
log_warn()  { printf "${C_YELLOW}[WARN]${C_RESET}  %s\n" "$*" >&2; }
log_error() { printf "${C_RED}[ERROR]${C_RESET} %s\n" "$*" >&2; }
log_fatal() { printf "${C_RED}[FATAL]${C_RESET} %s\n" "$*" >&2; exit 2; }

log_verdict() {
    local verdict="$1" cve_id="$2"
    case "${verdict}" in
        PREVENTED)  printf "${C_GREEN}${C_BOLD}[PREVENTED]${C_RESET}  %s\n" "${cve_id}" ;;
        DETECTED)   printf "${C_CYAN}${C_BOLD}[DETECTED]${C_RESET}   %s\n" "${cve_id}" ;;
        REGRESSION) printf "${C_RED}${C_BOLD}[REGRESSION]${C_RESET} %s\n" "${cve_id}" ;;
        BASELINE)   printf "${C_YELLOW}[BASELINE]${C_RESET}   %s\n" "${cve_id}" ;;
        *)          printf "${C_MAGENTA}[UNKNOWN]${C_RESET}    %s (verdict=%s)\n" "${cve_id}" "${verdict}" ;;
    esac
}

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

OPT_ALL=false
OPT_CATEGORY=""
OPT_CVE_DIR=""
OPT_NO_DOCKER=false
OPT_VERBOSE=false
OPT_EVALUATE_HSFP=""
OPT_QUALIFICATION_MANIFEST=""
OPT_QUALIFICATION_DEMO=false
OPT_TIMEOUT="${CVE_ARENA_TIMEOUT:-${DEFAULT_TIMEOUT}}"
OPT_IMAGE="${CVE_ARENA_IMAGE:-${DEFAULT_IMAGE}}"

usage() {
    cat <<'USAGE'
CVE Arena Test Runner

Usage:
  runner.sh --all                        Run all CVE tests
  runner.sh --category=glibc-internal    Run tests in a category
  runner.sh <CVE_DIR>                    Run a single CVE test
  runner.sh --no-docker <CVE_DIR>        Run without Docker (glibc-internal only)

Options:
  --all                  Run every CVE test across all categories
  --category=CATEGORY    Run all tests in a category (glibc-internal|external|synthetic)
  --results-dir=DIR      Output directory for result JSON files
  --no-docker            Skip Docker; run glibc-internal and synthetic tests on host
  --verbose              Show full stdout/stderr from test programs
  --timeout=SECONDS      Per-test timeout (default: 30)
  --image=NAME           Docker image name (default: frankenlibc-cve-arena)
  --help                 Show this help message
USAGE
    exit 0
}

parse_args() {
    if [[ $# -eq 0 ]]; then
        usage
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all)
                OPT_ALL=true
                shift
                ;;
            --category=*)
                OPT_CATEGORY="${1#--category=}"
                shift
                ;;
            --category)
                OPT_CATEGORY="${2:-}"
                shift 2
                ;;
            --results-dir=*)
                RESULTS_DIR="${1#--results-dir=}"
                shift
                ;;
            --results-dir)
                RESULTS_DIR="${2:-}"
                shift 2
                ;;
            --no-docker)
                OPT_NO_DOCKER=true
                shift
                ;;
            --verbose)
                OPT_VERBOSE=true
                shift
                ;;
            --timeout=*)
                OPT_TIMEOUT="${1#--timeout=}"
                shift
                ;;
            --image=*)
                OPT_IMAGE="${1#--image=}"
                shift
                ;;
            --evaluate-hsfp=*)
                OPT_EVALUATE_HSFP="${1#--evaluate-hsfp=}"
                shift
                ;;
            --evaluate-hsfp)
                OPT_EVALUATE_HSFP="${2:-}"
                shift 2
                ;;
            --qualification-manifest=*)
                OPT_QUALIFICATION_MANIFEST="${1#--qualification-manifest=}"
                shift
                ;;
            --qualification-manifest)
                OPT_QUALIFICATION_MANIFEST="${2:-}"
                shift 2
                ;;
            --demo)
                OPT_QUALIFICATION_DEMO=true
                shift
                ;;
            --help|-h)
                usage
                ;;
            -*)
                log_fatal "Unknown option: $1"
                ;;
            *)
                # Positional argument: treat as CVE directory path.
                if [[ -n "${OPT_CVE_DIR}" ]]; then
                    log_fatal "Multiple CVE directories specified. Use --all or --category instead."
                fi
                OPT_CVE_DIR="$1"
                shift
                ;;
        esac
    done

    # Validate category if provided.
    if [[ -n "${OPT_CATEGORY}" ]]; then
        local valid=false
        for cat in "${VALID_CATEGORIES[@]}"; do
            if [[ "${OPT_CATEGORY}" == "${cat}" ]]; then
                valid=true
                break
            fi
        done
        # Also accept short aliases.
        case "${OPT_CATEGORY}" in
            glibc)     OPT_CATEGORY="glibc-internal"; valid=true ;;
            ext)       OPT_CATEGORY="external"; valid=true ;;
            synth)     OPT_CATEGORY="synthetic"; valid=true ;;
        esac
        if [[ "${valid}" != "true" ]]; then
            log_fatal "Invalid category: ${OPT_CATEGORY} (valid: ${VALID_CATEGORIES[*]})"
        fi
    fi

    if [[ -n "${OPT_EVALUATE_HSFP}" || -n "${OPT_QUALIFICATION_MANIFEST}" ]]; then
        return 0
    fi

    # Ensure exactly one selection mode.
    local modes=0
    [[ "${OPT_ALL}" == "true" ]] && (( modes++ )) || true
    [[ -n "${OPT_CATEGORY}" ]] && (( modes++ )) || true
    [[ -n "${OPT_CVE_DIR}" ]] && (( modes++ )) || true

    if [[ ${modes} -eq 0 ]]; then
        log_fatal "Specify --all, --category=..., or a CVE test directory."
    fi
    if [[ ${modes} -gt 1 ]]; then
        log_fatal "Specify only one of --all, --category=..., or a CVE directory."
    fi
}

# ---------------------------------------------------------------------------
# Locate the FrankenLibC shared library
# ---------------------------------------------------------------------------

resolve_FrankenLibC_lib() {
    local candidate=""
    if [[ -n "${FRANKENLIBC_LIB:-}" ]]; then
        if [[ ! -f "${FRANKENLIBC_LIB}" ]]; then
            log_fatal "INVALID_ADMISSION: FRANKENLIBC_LIB points to missing file: ${FRANKENLIBC_LIB}"
        fi
        candidate="${FRANKENLIBC_LIB}"
    elif [[ -n "${CARGO_TARGET_DIR:-}" && -f "${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so" ]]; then
        candidate="${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so"
    elif [[ -f "/data/tmp/cargo-target/release/libfrankenlibc_abi.so" ]]; then
        candidate="/data/tmp/cargo-target/release/libfrankenlibc_abi.so"
    elif [[ -f "${PROJECT_ROOT}/target/release/libfrankenlibc_abi.so" ]]; then
        candidate="${PROJECT_ROOT}/target/release/libfrankenlibc_abi.so"
    elif [[ -f "${PROJECT_ROOT}/target/debug/libfrankenlibc_abi.so" ]]; then
        log_fatal "INVALID_ADMISSION: debug build rejected (${PROJECT_ROOT}/target/debug/libfrankenlibc_abi.so); release libfrankenlibc_abi.so required"
    else
        log_fatal "INVALID_ADMISSION: Cannot find release libfrankenlibc_abi.so"
    fi

    # SQ S05: Reject debug artifacts and verify expected SHA-256 when pinned.
    case "${candidate}" in
        */debug/*|*/debug/libfrankenlibc_abi.so)
            log_fatal "INVALID_ADMISSION: debug build rejected (${candidate}); release artifact required"
            ;;
    esac
    if [[ -n "${FRANKENLIBC_EXPECTED_LIB_SHA256:-}" ]]; then
        local actual_sha
        actual_sha=$(sha256sum "${candidate}" | awk '{print $1}')
        if [[ "${actual_sha,,}" != "${FRANKENLIBC_EXPECTED_LIB_SHA256,,}" ]]; then
            log_fatal "INVALID_ADMISSION: candidate SHA-256 mismatch (expected ${FRANKENLIBC_EXPECTED_LIB_SHA256}, got ${actual_sha})"
        fi
    fi

    echo "${candidate}"
}

# ---------------------------------------------------------------------------
# Docker infrastructure
# ---------------------------------------------------------------------------

ensure_docker_image() {
    if [[ "${OPT_NO_DOCKER}" == "true" ]]; then
        return 0
    fi

    if docker image inspect "${OPT_IMAGE}" &>/dev/null; then
        log_info "Docker image '${OPT_IMAGE}' already exists."
        return 0
    fi

    log_info "Building Docker image '${OPT_IMAGE}' from ${DOCKERFILE}..."
    if ! docker build -t "${OPT_IMAGE}" -f "${DOCKERFILE}" "${SCRIPT_DIR}"; then
        log_fatal "Failed to build Docker image."
    fi
    log_ok "Docker image built successfully."
}

# ---------------------------------------------------------------------------
# Manifest reading helpers (requires jq)
# ---------------------------------------------------------------------------

read_manifest_field() {
    local manifest="$1" field="$2"
    jq -r "${field}" < "${manifest}"
}

validate_manifest() {
    local manifest="$1"

    if [[ ! -f "${manifest}" ]]; then
        log_error "Missing manifest.json in test directory."
        return 1
    fi

    if ! jq empty < "${manifest}" 2>/dev/null; then
        log_error "Invalid JSON in ${manifest}"
        return 1
    fi

    # Check required fields.
    local required_fields=(".cve_id" ".test_name" ".category" ".build_cmd")
    for field in "${required_fields[@]}"; do
        local value
        value=$(jq -r "${field} // empty" < "${manifest}")
        if [[ -z "${value}" ]]; then
            log_error "Missing required field '${field}' in ${manifest}"
            return 1
        fi
    done

    local run_cmd run_cmd_stock run_cmd_tsm
    run_cmd=$(jq -r '.run_cmd // empty' < "${manifest}")
    run_cmd_stock=$(jq -r '.run_cmd_stock // empty' < "${manifest}")
    run_cmd_tsm=$(jq -r '.run_cmd_tsm // empty' < "${manifest}")
    if [[ -z "${run_cmd}" && ( -z "${run_cmd_stock}" || -z "${run_cmd_tsm}" ) ]]; then
        log_error "Missing required run_cmd (or run_cmd_stock + run_cmd_tsm) in ${manifest}"
        return 1
    fi

    return 0
}

# ---------------------------------------------------------------------------
# Signal name resolution
# ---------------------------------------------------------------------------

# Translate an exit code to a signal name. If the process was killed by a
# signal, the exit code is 128 + signal_number (bash convention).
exit_code_to_signal() {
    local exit_code="$1"

    if [[ ${exit_code} -le 128 ]]; then
        echo "null"
        return
    fi

    local sig_num=$(( exit_code - 128 ))
    if [[ -n "${SIGNAL_NAMES[${sig_num}]+x}" ]]; then
        echo "${SIGNAL_NAMES[${sig_num}]}"
    else
        echo "SIG${sig_num}"
    fi
}

# Determine whether an exit code indicates an exploitable crash.
is_exploitable_exit() {
    local exit_code="$1"
    local signal
    signal=$(exit_code_to_signal "${exit_code}")

    case "${signal}" in
        SIGSEGV|SIGBUS|SIGABRT|SIGFPE|SIGILL|SIGSYS)
            echo "true"
            ;;
        *)
            # Non-zero exit without a crash signal is suspicious but not
            # definitively exploitable from exit code alone.
            if [[ ${exit_code} -ne 0 ]]; then
                echo "false"
            else
                echo "false"
            fi
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Extract TSM healing actions from stderr/log output
# ---------------------------------------------------------------------------

extract_healing_actions() {
    local tsm_stderr="$1"

    # The membrane logs healing actions in a recognizable format.
    # Look for known action names in the output.
    local actions=()
    local known_actions=(
        "ClampSize"
        "TruncateWithNull"
        "IgnoreDoubleFree"
        "IgnoreForeignFree"
        "ReallocAsMalloc"
        "ReturnSafeDefault"
        "UpgradeToSafeVariant"
    )

    for action in "${known_actions[@]}"; do
        if echo "${tsm_stderr}" | grep -q "${action}"; then
            actions+=("\"${action}\"")
        fi
    done

    # Format as JSON array.
    if [[ ${#actions[@]} -eq 0 ]]; then
        echo "[]"
    else
        local joined
        joined=$(IFS=,; echo "${actions[*]}")
        echo "[${joined}]"
    fi
}

# ---------------------------------------------------------------------------
# Run a single test execution (one mode: stock or tsm)
# ---------------------------------------------------------------------------

# Execute a test program and capture results. Writes a JSON fragment to stdout.
#
# Arguments:
#   $1 - test_dir:   absolute path to CVE test directory
#   $2 - mode:       "stock" or "tsm"
#   $3 - run_cmd:    command to execute (from manifest)
#   $4 - build_cmd:  build command (from manifest)
#   $5 - glibc_lib:  path to libfrankenlibc_abi.so (only used in tsm mode)
run_single_mode() {
    local test_dir="$1"
    local mode="$2"
    local run_cmd="$3"
    local build_cmd="$4"
    local glibc_lib="${5:-}"
    local stem="${6:-$(basename "${test_dir}")}"

    local logs_dir="${RESULTS_DIR}/logs"
    mkdir -p "${logs_dir}"
    local stdout_file="${logs_dir}/${stem}_${mode}.stdout"
    local stderr_file="${logs_dir}/${stem}_${mode}.stderr"
    local log_file="${logs_dir}/${stem}_${mode}.log"
    : > "${stdout_file}"
    : > "${stderr_file}"
    : > "${log_file}"

    local exit_code=0
    local duration_ms=0
    local start_ns end_ns

    if [[ "${OPT_NO_DOCKER}" == "true" ]]; then
        # ---------------------------------------------------------------
        # Staged local-confinement mode: private staging copy + process-group timeout
        # ---------------------------------------------------------------
        log_info "  [${mode}] Running in private staged directory (no Docker)..."
        local stage_dir="${logs_dir}/stage_${stem}_${mode}_$$"
        local stage_src="${stage_dir}/src"
        local stage_work="${stage_dir}/work"
        mkdir -p "${stage_src}" "${stage_work}"
        cp -a "${test_dir}/." "${stage_src}/"
        chmod -R a-w "${stage_src}" 2>/dev/null || true
        cp -a "${test_dir}/." "${stage_work}/"
        chmod -R u+rwX "${stage_work}" 2>/dev/null || true

        # Build the test if a build command is specified.
        if [[ -n "${build_cmd}" && "${build_cmd}" != "null" ]]; then
            local effective_build_cmd="${build_cmd}"
            if [[ "${effective_build_cmd}" == cc\ * || "${effective_build_cmd}" == gcc\ * ]]; then
                effective_build_cmd="${effective_build_cmd} -fno-builtin"
            fi
            log_info "  [${mode}] Building: ${effective_build_cmd}"
            if ! (cd "${stage_work}" && eval "${effective_build_cmd}") >"${stdout_file}" 2>"${stderr_file}"; then
                log_error "  [${mode}] Build failed."
                cat "${stderr_file}" >&2
                echo '{"exit_code": 2, "signal": null, "stdout": "", "stderr": "BUILD FAILED", "duration_ms": 0, "exploitable": false, "provider_bound": false}'
                return
            fi
        fi

        # Execute in a dedicated session/process group so timeout kills forked children too (SQ S06/S07).
        local ld_bind_prefix="${logs_dir}/${stem}_${mode}.ld_bindings"
        start_ns=$(date +%s%N)
        set +e
        setsid timeout --kill-after=2s "${OPT_TIMEOUT}" bash -c '
            set -e
            cd "$1"
            ulimit -c 0 2>/dev/null || true
            ulimit -f 65536 2>/dev/null || true
            if [[ "$2" == "tsm" && -n "$3" ]]; then
                export LD_PRELOAD="$3"
                export FRANKENLIBC_MODE="${FRANKENLIBC_CVE_MODE:-hardened}"
                export FRANKENLIBC_LOG="$4"
                export FRANKENLIBC_LOG_FILE="$4"
                export LD_DEBUG="bindings"
                export LD_DEBUG_OUTPUT="$5"
            fi
            exec bash -c "$6"
        ' _ "${stage_work}" "${mode}" "${glibc_lib}" "${log_file}" "${ld_bind_prefix}" "${run_cmd}" \
            >"${stdout_file}" 2>"${stderr_file}"
        exit_code=$?
        set -e
        end_ns=$(date +%s%N)

        duration_ms=$(( (end_ns - start_ns) / 1000000 ))

    else
        # ---------------------------------------------------------------
        # Docker mode: run inside container
        # ---------------------------------------------------------------
        log_info "  [${mode}] Running in Docker container..."

        local docker_args=(
            docker run --rm
            --network=none
            --memory=256m
            --cpus=1
            -v "${test_dir}:/cve_arena/test:ro"
            -v "${SIGNAL_WRAPPER}:/cve_arena/signal_wrapper.sh:ro"
            -w /cve_arena/test
        )

        # In TSM mode, mount the FrankenLibC library and set environment.
        if [[ "${mode}" == "tsm" && -n "${glibc_lib}" ]]; then
            docker_args+=(
                -v "${glibc_lib}:/cve_arena/libfrankenlibc_abi.so:ro"
                -e "LD_PRELOAD=/cve_arena/libfrankenlibc_abi.so"
                -e "FRANKENLIBC_MODE=hardened"
            )
        fi

        docker_args+=(
            "${OPT_IMAGE}"
        )

        # Build step inside container.
        if [[ -n "${build_cmd}" && "${build_cmd}" != "null" ]]; then
            log_info "  [${mode}] Building inside container: ${build_cmd}"

            # Use a writable copy for building.
            local build_docker_args=(
                docker run --rm
                --network=none
                --memory=256m
                --cpus=1
                -v "${test_dir}:/cve_arena/test_src:ro"
                -w /cve_arena/build
                "${OPT_IMAGE}"
                bash -c "cp -a /cve_arena/test_src/. . && ${build_cmd}"
            )
            if ! "${build_docker_args[@]}" >"${stdout_file}" 2>"${stderr_file}"; then
                log_error "  [${mode}] Build failed inside container."
                echo '{"exit_code": 2, "signal": null, "stdout": "", "stderr": "BUILD FAILED", "duration_ms": 0, "exploitable": false}'
                return
            fi
        fi

        # Run the test inside the container with the signal wrapper.
        start_ns=$(date +%s%N)
        set +e
        "${docker_args[@]}" \
            bash -c "timeout ${OPT_TIMEOUT} /cve_arena/signal_wrapper.sh '${run_cmd}' /tmp/signal_result; cat /tmp/signal_result 2>/dev/null" \
            >"${stdout_file}" 2>"${stderr_file}"
        exit_code=$?
        set -e
        end_ns=$(date +%s%N)

        duration_ms=$(( (end_ns - start_ns) / 1000000 ))

        # If the signal wrapper wrote a result file, parse the exit code from it.
        local wrapper_output
        wrapper_output=$(cat "${stdout_file}" 2>/dev/null || true)
        if echo "${wrapper_output}" | grep -q '^SIGNAL_RESULT:'; then
            local parsed_exit
            parsed_exit=$(echo "${wrapper_output}" | grep '^SIGNAL_RESULT:' | tail -1 | cut -d: -f2)
            if [[ -n "${parsed_exit}" ]]; then
                exit_code="${parsed_exit}"
            fi
            # Remove the SIGNAL_RESULT line from stdout.
            wrapper_output=$(echo "${wrapper_output}" | grep -v '^SIGNAL_RESULT:' || true)
            echo "${wrapper_output}" > "${stdout_file}"
        fi
    fi

    # ---------------------------------------------------------------
    # Capture and format results
    # ---------------------------------------------------------------

    local stdout_content stderr_content log_content signal exploitable
    stdout_content=$(head -c 4096 "${stdout_file}" 2>/dev/null || true)
    stderr_content=$(head -c 4096 "${stderr_file}" 2>/dev/null || true)
    log_content=$(head -c 16384 "${log_file}" 2>/dev/null || true)
    signal=$(exit_code_to_signal "${exit_code}")
    exploitable=$(is_exploitable_exit "${exit_code}")

    # Verbose output if requested.
    if [[ "${OPT_VERBOSE}" == "true" ]]; then
        if [[ -n "${stdout_content}" ]]; then
            printf "    stdout: %s\n" "${stdout_content}" >&2
        fi
        if [[ -n "${stderr_content}" ]]; then
            printf "    stderr: %s\n" "${stderr_content}" >&2
        fi
    fi

    # JSON-escape the output strings and compute digests (SQ S02 / S04).
    local stdout_json stderr_json stdout_sha256 stderr_sha256
    stdout_json=$(printf '%s' "${stdout_content}" | jq -Rs '.')
    stderr_json=$(printf '%s' "${stderr_content}" | jq -Rs '.')
    stdout_sha256=$(sha256sum "${stdout_file}" 2>/dev/null | awk '{print $1}')
    stderr_sha256=$(sha256sum "${stderr_file}" 2>/dev/null | awk '{print $1}')

    # Build the JSON result for this mode.
    if [[ "${mode}" == "tsm" ]]; then
        local healing_actions tsm_log_json combined_log provider_bound lib_sha256
        combined_log="${stderr_content}"$'\n'"${log_content}"
        healing_actions=$(extract_healing_actions "${combined_log}")
        tsm_log_json=$(printf '%s' "${combined_log}" | jq -Rs '.')
        lib_sha256=""
        if [[ -n "${glibc_lib}" && -f "${glibc_lib}" ]]; then
            lib_sha256=$(sha256sum "${glibc_lib}" | awk '{print $1}')
        fi
        provider_bound="false"
        if compgen -G "${logs_dir}/${stem}_${mode}.ld_bindings*" >/dev/null; then
            if grep -qE "to .*libfrankenlibc_abi\.so" "${logs_dir}/${stem}_${mode}.ld_bindings"* 2>/dev/null; then
                provider_bound="true"
            fi
        elif [[ "${OPT_NO_DOCKER}" != "true" && -n "${glibc_lib}" ]]; then
            provider_bound="true"
        fi

        cat <<EOFJSON
{
    "exit_code": ${exit_code},
    "signal": $(if [[ "${signal}" == "null" ]]; then echo 'null'; else echo "\"${signal}\""; fi),
    "stdout": ${stdout_json},
    "stderr": ${stderr_json},
    "stdout_sha256": "${stdout_sha256}",
    "stderr_sha256": "${stderr_sha256}",
    "lib_sha256": "${lib_sha256}",
    "provider_bound": ${provider_bound},
    "duration_ms": ${duration_ms},
    "exploitable": ${exploitable},
    "healing_actions": ${healing_actions},
    "tsm_log": ${tsm_log_json}
}
EOFJSON
    else
        cat <<EOFJSON
{
    "exit_code": ${exit_code},
    "signal": $(if [[ "${signal}" == "null" ]]; then echo 'null'; else echo "\"${signal}\""; fi),
    "stdout": ${stdout_json},
    "stderr": ${stderr_json},
    "stdout_sha256": "${stdout_sha256}",
    "stderr_sha256": "${stderr_sha256}",
    "duration_ms": ${duration_ms},
    "exploitable": ${exploitable}
}
EOFJSON
    fi
}

# ---------------------------------------------------------------------------
# Verdict determination
# ---------------------------------------------------------------------------

# Compute the verdict based on stock and FrankenLibC results.
#
# Verdicts:
#   PREVENTED  - Stock crashes/exploits, FrankenLibC succeeds or heals without crash
#   DETECTED   - Stock crashes/exploits, FrankenLibC catches it (exit non-zero, no crash signal)
#   REGRESSION - FrankenLibC crashes with a signal (bug in our implementation)
#   BASELINE   - Stock also succeeds (test may not be triggering the bug)
compute_hsfp_json() {
    local payload_json="$1"
    python3 - "${payload_json}" <<'PY'
import hashlib
import json
import re
import sys

data = json.loads(sys.argv[1])
admitted = bool(data.get("admitted", True))
scope_boundary = str(data.get("scope_boundary") or "in_scope")
stock_exit = int(data.get("stock_exit", 0))
tsm_exit = int(data.get("tsm_exit", 0))
expected_tsm_exit = int(data.get("expected_tsm_exit", 0))
stock_exploitable = bool(data.get("stock_exploitable", False))
tsm_exploitable = bool(data.get("tsm_exploitable", False))
stock_stdout = str(data.get("stock_stdout") or "")
stock_stderr = str(data.get("stock_stderr") or "")
tsm_stdout = str(data.get("tsm_stdout") or "")
tsm_stderr = str(data.get("tsm_stderr") or "")
healing_actions = list(data.get("healing_actions") or [])
provider_bound = bool(data.get("provider_bound", True))
lib_sha256 = str(data.get("lib_sha256") or "")
expected_lib_sha256 = str(data.get("expected_lib_sha256") or "")
expected_stdout_sha256 = str(data.get("expected_stdout_sha256") or "")
expected_stdout_regex = str(data.get("expected_stdout_regex") or "")
forbidden_stdout_regex = str(data.get("forbidden_stdout_regex") or "")
harm_forbidden_regex = str(data.get("harm_forbidden_regex") or "")

HARM_RE = re.compile(
    r"EXPLOITABLE|VULNERABLE|SAME ADDRESS|HEAP CORRUPTION|ERROR: AddressSanitizer|"
    r"HARM_OBSERVED|CANARY_CORRUPTED_SILENT",
    re.IGNORECASE,
)
CORRUPT_OUT_RE = re.compile(
    r"CORRUPTED_OUTPUT|SILENT_CORRUPTION|INVALID_ARCHIVE",
    re.IGNORECASE,
)

stock_combined = f"{stock_stdout}\n{stock_stderr}"
tsm_combined = f"{tsm_stdout}\n{tsm_stderr}"

h_stock = bool(
    data["h_stock"]
    if "h_stock" in data
    else (stock_exploitable or bool(HARM_RE.search(stock_combined)))
)
h_candidate = bool(
    data["h_candidate"]
    if "h_candidate" in data
    else (
        tsm_exploitable
        or tsm_exit in (124, 137)
        or bool(HARM_RE.search(tsm_combined))
        or (bool(harm_forbidden_regex) and bool(re.search(harm_forbidden_regex, tsm_combined)))
    )
)

s_telemetry = len(healing_actions) > 0

actual_stdout_sha256 = hashlib.sha256(tsm_stdout.encode("utf-8")).hexdigest()
if "f_accepted" in data:
    f_accepted = bool(data["f_accepted"])
else:
    f_accepted = (tsm_exit == expected_tsm_exit) and not bool(CORRUPT_OUT_RE.search(tsm_stdout))
    if f_accepted and expected_stdout_sha256:
        f_accepted = actual_stdout_sha256.lower() == expected_stdout_sha256.lower()
    if f_accepted and expected_stdout_regex:
        f_accepted = bool(re.search(expected_stdout_regex, tsm_stdout))
    if f_accepted and forbidden_stdout_regex:
        f_accepted = not bool(re.search(forbidden_stdout_regex, tsm_stdout))

if "p_verified" in data:
    p_verified = bool(data["p_verified"])
else:
    p_verified = provider_bound
    if p_verified and expected_lib_sha256:
        p_verified = bool(lib_sha256) and lib_sha256.lower() == expected_lib_sha256.lower()

if expected_lib_sha256 and lib_sha256 and lib_sha256.lower() != expected_lib_sha256.lower():
    admitted = False

if not admitted:
    verdict = "INVALID_ADMISSION"
elif not p_verified:
    verdict = "UNSUPPORTED_PROVIDER"
elif scope_boundary == "not_mitigated_by_design":
    verdict = "NOT_MITIGATED_BY_DESIGN"
elif h_candidate:
    verdict = "REGRESSION"
elif not h_stock:
    verdict = "BASELINE"
elif f_accepted:
    # SQ.11 conservative rule: admitted && H_stock && !H_candidate && F_accepted && P_verified
    verdict = "PREVENTED"
else:
    verdict = "DETECTED"

result = {
    "verdict": verdict,
    "admitted": admitted,
    "scope_boundary": scope_boundary,
    "H": {
        "stock_harm": h_stock,
        "candidate_harm": h_candidate,
    },
    "S": {
        "telemetry_observed": s_telemetry,
        "healing_actions": healing_actions,
    },
    "F": {
        "accepted": f_accepted,
        "expected_exit": expected_tsm_exit,
        "actual_exit": tsm_exit,
        "stdout_sha256": actual_stdout_sha256,
    },
    "P": {
        "verified": p_verified,
        "provider_bound": provider_bound,
        "lib_sha256": lib_sha256,
    },
}
print(json.dumps(result))
PY
}

compute_verdict() {
    local stock_exit="$1"
    local tsm_exit="$2"
    local stock_stdout="${3:-}"
    local tsm_stdout="${4:-}"
    local tsm_healing="${5:-[]}"
    local expected_tsm_exit="${6:-0}"
    local provider_bound="${7:-true}"
    local scope_boundary="${8:-in_scope}"
    local stock_stderr="${9:-}"
    local tsm_stderr="${10:-}"
    local lib_sha256="${11:-}"
    local expected_lib_sha256="${12:-}"
    local expected_stdout_sha256="${13:-}"
    local expected_stdout_regex="${14:-}"
    local forbidden_stdout_regex="${15:-}"
    local harm_forbidden_regex="${16:-}"

    local stock_exploitable tsm_exploitable payload hsfp_json
    stock_exploitable=$(is_exploitable_exit "${stock_exit}")
    tsm_exploitable=$(is_exploitable_exit "${tsm_exit}")

    payload=$(jq -n \
        --argjson stock_exit "${stock_exit}" \
        --argjson tsm_exit "${tsm_exit}" \
        --argjson expected_tsm_exit "${expected_tsm_exit}" \
        --argjson stock_exploitable "${stock_exploitable}" \
        --argjson tsm_exploitable "${tsm_exploitable}" \
        --arg stock_stdout "${stock_stdout}" \
        --arg stock_stderr "${stock_stderr}" \
        --arg tsm_stdout "${tsm_stdout}" \
        --arg tsm_stderr "${tsm_stderr}" \
        --argjson healing_actions "${tsm_healing}" \
        --argjson provider_bound "${provider_bound}" \
        --arg scope_boundary "${scope_boundary}" \
        --arg lib_sha256 "${lib_sha256}" \
        --arg expected_lib_sha256 "${expected_lib_sha256}" \
        --arg expected_stdout_sha256 "${expected_stdout_sha256}" \
        --arg expected_stdout_regex "${expected_stdout_regex}" \
        --arg forbidden_stdout_regex "${forbidden_stdout_regex}" \
        --arg harm_forbidden_regex "${harm_forbidden_regex}" \
        '{
            admitted: true,
            scope_boundary: $scope_boundary,
            stock_exit: $stock_exit,
            tsm_exit: $tsm_exit,
            expected_tsm_exit: $expected_tsm_exit,
            stock_exploitable: $stock_exploitable,
            tsm_exploitable: $tsm_exploitable,
            stock_stdout: $stock_stdout,
            stock_stderr: $stock_stderr,
            tsm_stdout: $tsm_stdout,
            tsm_stderr: $tsm_stderr,
            healing_actions: $healing_actions,
            provider_bound: $provider_bound,
            lib_sha256: $lib_sha256,
            expected_lib_sha256: $expected_lib_sha256,
            expected_stdout_sha256: $expected_stdout_sha256,
            expected_stdout_regex: $expected_stdout_regex,
            forbidden_stdout_regex: $forbidden_stdout_regex,
            harm_forbidden_regex: $harm_forbidden_regex
        }')
    hsfp_json=$(compute_hsfp_json "${payload}")
    LAST_HSFP_JSON="${hsfp_json}"
    echo "${hsfp_json}" | jq -r '.verdict'
}

# ---------------------------------------------------------------------------
# Run a single CVE test (both modes, produce JSON result)
# ---------------------------------------------------------------------------

sanitize_result_stem() {
    local cve_id="$1" test_name="$2"
    local clean_cve="${cve_id//[-. ()]/_}"
    echo "${clean_cve}_${test_name}"
}

run_cve_test() {
    local test_dir="$1"
    local glibc_lib="$2"

    # Resolve to absolute path.
    test_dir="$(cd "${test_dir}" && pwd)"

    local manifest="${test_dir}/manifest.json"
    if ! validate_manifest "${manifest}"; then
        log_error "Skipping ${test_dir}: invalid manifest."
        return 1
    fi

    # Read manifest fields.
    local cve_id test_name category description build_cmd run_cmd_stock run_cmd_tsm
    cve_id=$(read_manifest_field "${manifest}" '.cve_id')
    test_name=$(read_manifest_field "${manifest}" '.test_name')
    category=$(read_manifest_field "${manifest}" '.category')
    description=$(read_manifest_field "${manifest}" '.description // "No description"')
    build_cmd=$(read_manifest_field "${manifest}" '.build_cmd // empty')
    run_cmd_stock=$(read_manifest_field "${manifest}" '.run_cmd_stock // .run_cmd')
    run_cmd_tsm=$(read_manifest_field "${manifest}" '.run_cmd_tsm // .run_cmd')

    printf "\n${C_BOLD}========================================${C_RESET}\n"
    printf "${C_BOLD}CVE:${C_RESET}      %s\n" "${cve_id}"
    printf "${C_BOLD}Test:${C_RESET}     %s\n" "${test_name}"
    printf "${C_BOLD}Category:${C_RESET} %s\n" "${category}"
    printf "${C_BOLD}Desc:${C_RESET}     %s\n" "${description}"
    printf "${C_BOLD}========================================${C_RESET}\n"

    # Enforce no-docker restriction: external target containers require Docker.
    if [[ "${OPT_NO_DOCKER}" == "true" && "${category}" == "external" ]]; then
        log_warn "Skipping ${cve_id}: --no-docker only supports glibc-internal and synthetic tests."
        return 0
    fi

    local timestamp stem expected_tsm_exit
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    stem=$(sanitize_result_stem "${cve_id}" "${test_name}")
    expected_tsm_exit=$(jq -r '.expected_tsm.exit_code // 0' < "${manifest}")

    # Run stock mode.
    log_info "Running stock glibc mode..."
    local stock_json
    stock_json=$(run_single_mode "${test_dir}" "stock" "${run_cmd_stock}" "${build_cmd}" "" "${stem}")
    local stock_exit stock_stdout stock_stderr
    stock_exit=$(echo "${stock_json}" | jq -r '.exit_code')
    stock_stdout=$(echo "${stock_json}" | jq -r '.stdout // ""')
    stock_stderr=$(echo "${stock_json}" | jq -r '.stderr // ""')
    log_info "  Stock exit code: ${stock_exit}"

    # Run TSM mode.
    log_info "Running FrankenLibC (TSM) mode..."
    local tsm_json
    tsm_json=$(run_single_mode "${test_dir}" "tsm" "${run_cmd_tsm}" "${build_cmd}" "${glibc_lib}" "${stem}")
    local tsm_exit tsm_stdout tsm_stderr tsm_healing tsm_provider_bound tsm_lib_sha256
    tsm_exit=$(echo "${tsm_json}" | jq -r '.exit_code')
    tsm_stdout=$(echo "${tsm_json}" | jq -r '.stdout // ""')
    tsm_stderr=$(echo "${tsm_json}" | jq -r '.stderr // ""')
    tsm_healing=$(echo "${tsm_json}" | jq -c '.healing_actions // []')
    tsm_provider_bound=$(echo "${tsm_json}" | jq -r '.provider_bound // true')
    tsm_lib_sha256=$(echo "${tsm_json}" | jq -r '.lib_sha256 // ""')
    log_info "  TSM exit code: ${tsm_exit} (healing=${tsm_healing}, provider_bound=${tsm_provider_bound})"

    # Read optional SQ S01 / S02 / S04 / S12 protocol contracts from manifest.
    local scope_boundary expected_lib_sha256 expected_stdout_sha256 expected_stdout_regex forbidden_stdout_regex harm_forbidden_regex
    scope_boundary=$(jq -r '.qualification_protocol.scope_boundary // "in_scope"' < "${manifest}")
    expected_lib_sha256=$(jq -r '.qualification_protocol.provider_binding.expected_lib_sha256 // ""' < "${manifest}")
    expected_stdout_sha256=$(jq -r '.qualification_protocol.output_validator.expected_stdout_sha256 // ""' < "${manifest}")
    expected_stdout_regex=$(jq -r '.qualification_protocol.output_validator.expected_stdout_regex // ""' < "${manifest}")
    forbidden_stdout_regex=$(jq -r '.qualification_protocol.output_validator.forbidden_stdout_regex // ""' < "${manifest}")
    harm_forbidden_regex=$(jq -r '.qualification_protocol.harm_oracle.forbidden_regex // ""' < "${manifest}")

    # Compute conservative 4-axis (H, S, F, P) verdict.
    local verdict hsfp_json
    LAST_HSFP_JSON=""
    verdict=$(compute_verdict \
        "${stock_exit}" \
        "${tsm_exit}" \
        "${stock_stdout}" \
        "${tsm_stdout}" \
        "${tsm_healing}" \
        "${expected_tsm_exit}" \
        "${tsm_provider_bound}" \
        "${scope_boundary}" \
        "${stock_stderr}" \
        "${tsm_stderr}" \
        "${tsm_lib_sha256}" \
        "${expected_lib_sha256}" \
        "${expected_stdout_sha256}" \
        "${expected_stdout_regex}" \
        "${forbidden_stdout_regex}" \
        "${harm_forbidden_regex}")
    hsfp_json="${LAST_HSFP_JSON}"
    if [[ -z "${hsfp_json}" ]]; then
        hsfp_json='{}'
    fi
    log_verdict "${verdict}" "${cve_id}"

    # Read additional manifest metadata for the result JSON.
    local cwe_ids cvss_score tsm_features
    cwe_ids=$(jq -c '.cwe_ids // []' < "${manifest}")
    cvss_score=$(jq -r '.cvss_score // 0.0' < "${manifest}")
    tsm_features=$(jq -c '.tsm_features_tested // []' < "${manifest}")

    local result_file="${RESULTS_DIR}/${stem}.result.json"
    local hsfp_jsonl="${RESULTS_DIR}/logs/hsfp_verdicts.jsonl"
    mkdir -p "${RESULTS_DIR}/logs"

    jq -n \
        --arg cve_id "${cve_id}" \
        --arg test_name "${test_name}" \
        --arg category "${category}" \
        --arg description "${description}" \
        --arg timestamp "${timestamp}" \
        --argjson stock "${stock_json}" \
        --argjson tsm "${tsm_json}" \
        --arg verdict "${verdict}" \
        --argjson hsfp "${hsfp_json}" \
        --argjson cwe_ids "${cwe_ids}" \
        --argjson cvss_score "${cvss_score}" \
        --argjson tsm_features "${tsm_features}" \
        --arg test_dir "${test_dir}" \
        '{
            cve: $cve_id,
            cve_id: $cve_id,
            test_name: $test_name,
            category: $category,
            description: $description,
            cvss: $cvss_score,
            timestamp: $timestamp,
            stock_exit: $stock.exit_code,
            stock_signal: $stock.signal,
            stock_output: $stock.stdout,
            rust_exit: $tsm.exit_code,
            rust_signal: $tsm.signal,
            rust_output: $tsm.stdout,
            tsm_features: (if ($tsm.healing_actions | length) > 0 then $tsm.healing_actions else $tsm_features end),
            stock_glibc: $stock,
            FrankenLibC: $tsm,
            verdict: $verdict,
            hsfp: $hsfp,
            metadata: {
                cwe_ids: $cwe_ids,
                cvss_score: $cvss_score,
                tsm_features_tested: $tsm_features,
                test_directory: $test_dir
            }
        }' > "${result_file}"

    jq -cn \
        --arg cve_id "${cve_id}" \
        --arg test_name "${test_name}" \
        --arg timestamp "${timestamp}" \
        --argjson hsfp "${hsfp_json}" \
        '{cve_id: $cve_id, test_name: $test_name, timestamp: $timestamp} + $hsfp' >> "${hsfp_jsonl}"

    log_info "Result written to ${result_file}"
    return 0
}

# ---------------------------------------------------------------------------
# Collect test directories based on selection mode
# ---------------------------------------------------------------------------

# Category directory mapping:
#   glibc-internal  -> tests/cve_arena/glibc/
#   external        -> tests/cve_arena/targets/
#   synthetic       -> tests/cve_arena/synthetic/
category_to_dir() {
    local category="$1"
    case "${category}" in
        glibc-internal) echo "${SCRIPT_DIR}/glibc" ;;
        external)       echo "${SCRIPT_DIR}/targets" ;;
        synthetic)      echo "${SCRIPT_DIR}/synthetic" ;;
        *)              log_fatal "Unknown category: ${category}" ;;
    esac
}

collect_test_dirs() {
    local -a dirs=()

    if [[ -n "${OPT_CVE_DIR}" ]]; then
        # Single test directory.
        if [[ ! -d "${OPT_CVE_DIR}" ]]; then
            # Try relative to project root.
            if [[ -d "${PROJECT_ROOT}/${OPT_CVE_DIR}" ]]; then
                OPT_CVE_DIR="${PROJECT_ROOT}/${OPT_CVE_DIR}"
            else
                log_fatal "CVE test directory not found: ${OPT_CVE_DIR}"
            fi
        fi
        dirs+=("${OPT_CVE_DIR}")

    elif [[ -n "${OPT_CATEGORY}" ]]; then
        # All tests in a category.
        local cat_dir
        cat_dir=$(category_to_dir "${OPT_CATEGORY}")
        if [[ ! -d "${cat_dir}" ]]; then
            log_fatal "Category directory not found: ${cat_dir}"
        fi
        while IFS= read -r -d '' d; do
            if [[ -f "${d}/manifest.json" ]]; then
                dirs+=("${d}")
            fi
        done < <(find "${cat_dir}" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)

    elif [[ "${OPT_ALL}" == "true" ]]; then
        # All categories.
        for category in "${VALID_CATEGORIES[@]}"; do
            local cat_dir
            cat_dir=$(category_to_dir "${category}")
            if [[ -d "${cat_dir}" ]]; then
                while IFS= read -r -d '' d; do
                    if [[ -f "${d}/manifest.json" ]]; then
                        dirs+=("${d}")
                    fi
                done < <(find "${cat_dir}" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
            fi
        done
    fi

    if [[ ${#dirs[@]} -eq 0 ]]; then
        log_fatal "No CVE test directories found with manifest.json."
    fi

    printf '%s\n' "${dirs[@]}"
}

# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

print_summary() {
    local total="$1" prevented="$2" detected="$3" regression="$4" baseline="$5"

    printf "\n${C_BOLD}============================================${C_RESET}\n"
    printf "${C_BOLD}            CVE Arena Summary${C_RESET}\n"
    printf "${C_BOLD}============================================${C_RESET}\n"
    printf "  Total tests:   %d\n" "${total}"
    printf "  ${C_GREEN}PREVENTED:${C_RESET}     %d\n" "${prevented}"
    printf "  ${C_CYAN}DETECTED:${C_RESET}      %d\n" "${detected}"
    printf "  ${C_YELLOW}BASELINE:${C_RESET}      %d\n" "${baseline}"
    printf "  ${C_RED}REGRESSION:${C_RESET}    %d\n" "${regression}"
    printf "${C_BOLD}============================================${C_RESET}\n"

    if [[ ${regression} -gt 0 ]]; then
        printf "\n${C_RED}${C_BOLD}FAIL: %d regression(s) detected.${C_RESET}\n" "${regression}"
    elif [[ $(( prevented + detected )) -gt 0 ]]; then
        printf "\n${C_GREEN}${C_BOLD}PASS: All vulnerabilities handled correctly.${C_RESET}\n"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    if [[ -n "${OPT_EVALUATE_HSFP}" ]]; then
        compute_hsfp_json "${OPT_EVALUATE_HSFP}"
        exit 0
    fi

    if [[ -n "${OPT_QUALIFICATION_MANIFEST}" ]]; then
        local -a qual_cmd=(
            python3 "${SCRIPT_DIR}/libarchive_qualification.py" run
            --manifest "${OPT_QUALIFICATION_MANIFEST}"
            --results-dir "${RESULTS_DIR}"
        )
        if [[ -n "${FRANKENLIBC_LIB:-}" ]]; then
            qual_cmd+=(--frankenlibc-lib "${FRANKENLIBC_LIB}")
        fi
        if [[ "${OPT_QUALIFICATION_DEMO}" == "true" ]]; then
            qual_cmd+=(--demo)
        fi
        exec "${qual_cmd[@]}"
    fi

    log_info "CVE Arena Test Runner"
    log_info "Project root: ${PROJECT_ROOT}"
    log_info "Results dir:  ${RESULTS_DIR}"

    # Ensure prerequisites.
    if ! command -v jq &>/dev/null; then
        log_fatal "jq is required but not installed. Install with: apt install jq"
    fi

    # Create results directory early so confinement blocks leave machine-readable evidence (SQ S06/S07).
    mkdir -p "${RESULTS_DIR}"

    if [[ "${CVE_ARENA_FORCE_MISSING_ISOLATION:-0}" == "1" ]]; then
        jq -n '{status: "blocked_missing_isolation", reason: "forced missing isolation negative control"}' > "${RESULTS_DIR}/isolation_status.json"
        log_fatal "blocked_missing_isolation: isolation backend forced unavailable"
    fi

    if [[ "${OPT_NO_DOCKER}" != "true" ]]; then
        if ! command -v docker &>/dev/null || ! docker info &>/dev/null; then
            jq -n '{status: "blocked_missing_isolation", reason: "docker daemon/cli unavailable"}' > "${RESULTS_DIR}/isolation_status.json"
            log_fatal "blocked_missing_isolation: Docker isolation is required (daemon/CLI unavailable)"
        fi
    fi

    # Resolve the FrankenLibC library.
    local glibc_lib
    glibc_lib=$(resolve_FrankenLibC_lib)
    log_info "FrankenLibC library: ${glibc_lib}"

    # Build Docker image if needed.
    ensure_docker_image

    # Collect test directories.
    local -a test_dirs=()
    while IFS= read -r dir; do
        test_dirs+=("${dir}")
    done < <(collect_test_dirs)

    log_info "Found ${#test_dirs[@]} CVE test(s) to run."

    # Run each test and track verdicts.
    local total=0 prevented=0 detected=0 regression=0 baseline=0 errors=0

    for test_dir in "${test_dirs[@]}"; do
        (( total++ )) || true

        local result_file
        if run_cve_test "${test_dir}" "${glibc_lib}"; then
            # Read the verdict from the written result JSON.
            local cve_id test_name stem
            cve_id=$(jq -r '.cve_id' < "${test_dir}/manifest.json")
            test_name=$(jq -r '.test_name' < "${test_dir}/manifest.json")
            stem=$(sanitize_result_stem "${cve_id}" "${test_name}")
            result_file="${RESULTS_DIR}/${stem}.result.json"

            if [[ -f "${result_file}" ]]; then
                local verdict
                verdict=$(jq -r '.verdict' < "${result_file}")
                case "${verdict}" in
                    PREVENTED)  (( prevented++ ))  || true ;;
                    DETECTED)   (( detected++ ))   || true ;;
                    REGRESSION) (( regression++ ))  || true ;;
                    BASELINE)   (( baseline++ ))   || true ;;
                esac
            fi
        else
            (( errors++ )) || true
            log_error "Test execution failed for ${test_dir}"
        fi
    done

    # Print summary.
    print_summary "${total}" "${prevented}" "${detected}" "${regression}" "${baseline}"

    if [[ ${errors} -gt 0 ]]; then
        log_warn "${errors} test(s) had execution errors."
    fi

    # Exit with failure if any regressions, admission/provider rejections, or execution errors occurred.
    if [[ ${regression} -gt 0 || ${errors} -gt 0 ]]; then
        exit 1
    fi

    exit 0
}

main "$@"
