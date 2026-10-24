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
    if [[ -n "${FRANKENLIBC_LIB:-}" ]]; then
        if [[ ! -f "${FRANKENLIBC_LIB}" ]]; then
            log_fatal "FRANKENLIBC_LIB points to missing file: ${FRANKENLIBC_LIB}"
        fi
        echo "${FRANKENLIBC_LIB}"
        return
    fi

    if [[ -n "${CARGO_TARGET_DIR:-}" && -f "${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so" ]]; then
        echo "${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so"
        return
    fi

    if [[ -f "/data/tmp/cargo-target/release/libfrankenlibc_abi.so" ]]; then
        echo "/data/tmp/cargo-target/release/libfrankenlibc_abi.so"
        return
    fi

    # Default: project build output.
    local default_path="${PROJECT_ROOT}/target/release/libfrankenlibc_abi.so"
    if [[ -f "${default_path}" ]]; then
        echo "${default_path}"
        return
    fi

    # Fallback: check debug build.
    local debug_path="${PROJECT_ROOT}/target/debug/libfrankenlibc_abi.so"
    if [[ -f "${debug_path}" ]]; then
        log_warn "Using debug build of libfrankenlibc_abi.so (consider building release)"
        echo "${debug_path}"
        return
    fi

    log_fatal "Cannot find libfrankenlibc_abi.so. Build with: cargo build --release -p frankenlibc-abi"
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

    local stdout_file stderr_file result_file log_file
    stdout_file=$(mktemp)
    stderr_file=$(mktemp)
    result_file=$(mktemp)
    log_file=$(mktemp)

    # Ensure cleanup of temp files.
    trap "rm -f '${stdout_file}' '${stderr_file}' '${result_file}' '${log_file}'" RETURN

    local exit_code=0
    local duration_ms=0
    local start_ns end_ns

    if [[ "${OPT_NO_DOCKER}" == "true" ]]; then
        # ---------------------------------------------------------------
        # No-Docker mode: run directly on host
        # ---------------------------------------------------------------
        log_info "  [${mode}] Running on host (no Docker)..."

        # Build the test if a build command is specified.
        if [[ -n "${build_cmd}" && "${build_cmd}" != "null" ]]; then
            local effective_build_cmd="${build_cmd}"
            if [[ "${effective_build_cmd}" == cc\ * || "${effective_build_cmd}" == gcc\ * ]]; then
                effective_build_cmd="${effective_build_cmd} -fno-builtin"
            fi
            log_info "  [${mode}] Building: ${effective_build_cmd}"
            if ! (cd "${test_dir}" && eval "${effective_build_cmd}") >"${stdout_file}" 2>"${stderr_file}"; then
                log_error "  [${mode}] Build failed."
                cat "${stderr_file}" >&2
                echo '{"exit_code": 2, "signal": null, "stdout": "", "stderr": "BUILD FAILED", "duration_ms": 0, "exploitable": false}'
                return
            fi
        fi

        # Execute with timeout and signal wrapper.
        start_ns=$(date +%s%N)
        set +e
        (
            cd "${test_dir}"
            if [[ "${mode}" == "tsm" && -n "${glibc_lib}" ]]; then
                export LD_PRELOAD="${glibc_lib}"
                export FRANKENLIBC_MODE="hardened"
                export FRANKENLIBC_LOG="${log_file}"
                export FRANKENLIBC_LOG_FILE="${log_file}"
            fi
            timeout "${OPT_TIMEOUT}" bash -c "${run_cmd}" \
                >"${stdout_file}" 2>"${stderr_file}"
        )
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

    # JSON-escape the output strings.
    local stdout_json stderr_json
    stdout_json=$(printf '%s' "${stdout_content}" | jq -Rs '.')
    stderr_json=$(printf '%s' "${stderr_content}" | jq -Rs '.')

    # Build the JSON result for this mode.
    if [[ "${mode}" == "tsm" ]]; then
        local healing_actions tsm_log_json combined_log
        combined_log="${stderr_content}"$'\n'"${log_content}"
        healing_actions=$(extract_healing_actions "${combined_log}")
        tsm_log_json=$(printf '%s' "${combined_log}" | jq -Rs '.')

        cat <<EOFJSON
{
    "exit_code": ${exit_code},
    "signal": $(if [[ "${signal}" == "null" ]]; then echo 'null'; else echo "\"${signal}\""; fi),
    "stdout": ${stdout_json},
    "stderr": ${stderr_json},
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
compute_verdict() {
    local stock_exit="$1"
    local tsm_exit="$2"
    local stock_stdout="${3:-}"
    local tsm_stdout="${4:-}"
    local tsm_healing="${5:-[]}"

    local stock_signal tsm_signal stock_exploitable tsm_exploitable
    stock_signal=$(exit_code_to_signal "${stock_exit}")
    tsm_signal=$(exit_code_to_signal "${tsm_exit}")
    stock_exploitable=$(is_exploitable_exit "${stock_exit}")
    tsm_exploitable=$(is_exploitable_exit "${tsm_exit}")

    # Case 1: FrankenLibC itself crashes -- always a regression regardless of stock.
    if [[ "${tsm_exploitable}" == "true" ]]; then
        echo "REGRESSION"
        return
    fi

    # Case 2: Stock crashes/exploits, FrankenLibC does not crash.
    if [[ "${stock_exploitable}" == "true" ]]; then
        if [[ ${tsm_exit} -eq 0 || "${tsm_healing}" != "[]" ]]; then
            echo "PREVENTED"
        else
            echo "DETECTED"
        fi
        return
    fi

    # Case 3: Stock exits non-zero (but no crash signal), FrankenLibC succeeds or heals.
    if [[ ${stock_exit} -ne 0 ]]; then
        if [[ ${tsm_exit} -eq 0 || "${tsm_healing}" != "[]" ]]; then
            echo "PREVENTED"
            return
        fi
    fi

    # Case 4: Both exit 0 (e.g. multi-vector harness catching signals or checking reuse),
    # but TSM emitted healing actions or quarantine prevented reuse.
    if [[ ${tsm_exit} -eq 0 ]]; then
        if [[ "${tsm_healing}" != "[]" ]]; then
            echo "PREVENTED"
            return
        fi
        if echo "${stock_stdout}" | grep -qiE 'EXPLOITABLE|VULNERABLE|SAME ADDRESS|HEAP CORRUPTION' && \
           echo "${tsm_stdout}" | grep -qiE 'quarantine working|Prevented|SAFE|mitigated|DETECTED'; then
            echo "PREVENTED"
            return
        fi
    fi

    # Case 5: Both succeed or both fail the same way.
    echo "BASELINE"
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

    # Run stock mode.
    log_info "Running stock glibc mode..."
    local stock_json
    stock_json=$(run_single_mode "${test_dir}" "stock" "${run_cmd_stock}" "${build_cmd}" "")
    local stock_exit stock_stdout
    stock_exit=$(echo "${stock_json}" | jq -r '.exit_code')
    stock_stdout=$(echo "${stock_json}" | jq -r '.stdout // ""')
    log_info "  Stock exit code: ${stock_exit}"

    # Run TSM mode.
    log_info "Running FrankenLibC (TSM) mode..."
    local tsm_json
    tsm_json=$(run_single_mode "${test_dir}" "tsm" "${run_cmd_tsm}" "${build_cmd}" "${glibc_lib}")
    local tsm_exit tsm_stdout tsm_healing
    tsm_exit=$(echo "${tsm_json}" | jq -r '.exit_code')
    tsm_stdout=$(echo "${tsm_json}" | jq -r '.stdout // ""')
    tsm_healing=$(echo "${tsm_json}" | jq -c '.healing_actions // []')
    log_info "  TSM exit code: ${tsm_exit} (healing=${tsm_healing})"

    # Compute verdict.
    local verdict
    verdict=$(compute_verdict "${stock_exit}" "${tsm_exit}" "${stock_stdout}" "${tsm_stdout}" "${tsm_healing}")
    log_verdict "${verdict}" "${cve_id}"

    # Read additional manifest metadata for the result JSON.
    local cwe_ids cvss_score tsm_features
    cwe_ids=$(jq -c '.cwe_ids // []' < "${manifest}")
    cvss_score=$(jq -r '.cvss_score // 0.0' < "${manifest}")
    tsm_features=$(jq -c '.tsm_features_tested // []' < "${manifest}")

    # Assemble the full result JSON.
    local timestamp stem
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    stem=$(sanitize_result_stem "${cve_id}" "${test_name}")

    local result_file="${RESULTS_DIR}/${stem}.result.json"

    jq -n \
        --arg cve_id "${cve_id}" \
        --arg test_name "${test_name}" \
        --arg category "${category}" \
        --arg description "${description}" \
        --arg timestamp "${timestamp}" \
        --argjson stock "${stock_json}" \
        --argjson tsm "${tsm_json}" \
        --arg verdict "${verdict}" \
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
            rust_exit: (if $verdict == "PREVENTED" then 0 else $tsm.exit_code end),
            rust_signal: $tsm.signal,
            rust_output: $tsm.stdout,
            tsm_features: (if ($tsm.healing_actions | length) > 0 then $tsm.healing_actions else $tsm_features end),
            stock_glibc: $stock,
            FrankenLibC: $tsm,
            verdict: $verdict,
            metadata: {
                cwe_ids: $cwe_ids,
                cvss_score: $cvss_score,
                tsm_features_tested: $tsm_features,
                test_directory: $test_dir
            }
        }' > "${result_file}"

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

    log_info "CVE Arena Test Runner"
    log_info "Project root: ${PROJECT_ROOT}"
    log_info "Results dir:  ${RESULTS_DIR}"

    # Ensure prerequisites.
    if ! command -v jq &>/dev/null; then
        log_fatal "jq is required but not installed. Install with: apt install jq"
    fi

    if ! command -v docker &>/dev/null && [[ "${OPT_NO_DOCKER}" != "true" ]]; then
        log_fatal "Docker is required (or use --no-docker for glibc-internal tests)."
    fi

    # Create results directory.
    mkdir -p "${RESULTS_DIR}"

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

    # Exit with failure if any regressions occurred.
    if [[ ${regression} -gt 0 ]]; then
        exit 1
    fi

    exit 0
}

main "$@"
