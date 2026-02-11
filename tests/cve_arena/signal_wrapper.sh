#!/usr/bin/env bash
# =============================================================================
# Signal-Catching Wrapper for CVE Arena Tests
# =============================================================================
#
# Executes a program and captures signal/exit information. Designed to run
# inside the CVE Arena Docker container. Traps fatal signals that indicate
# memory corruption or undefined behavior, records which signal was received,
# and writes structured output for the test runner to parse.
#
# Usage:
#   signal_wrapper.sh "command to run" [result_file]
#
# Output:
#   Writes to result_file (default: /tmp/signal_result):
#     SIGNAL_RESULT:<exit_code>
#     SIGNAL_NAME:<signal_name_or_none>
#     SIGNAL_NUM:<signal_number_or_0>
#
#   Also prints SIGNAL_RESULT:<exit_code> to stdout for pipe-based capture.
#
# Notes:
#   - The wrapper itself uses a child process so that fatal signals delivered
#     to the child do not kill this script.
#   - Exit code follows bash convention: 128 + signal_number for signal deaths.
# =============================================================================

set -uo pipefail
# Note: -e is intentionally omitted. We need to capture non-zero exits.

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

if [[ $# -lt 1 ]]; then
    echo "Usage: signal_wrapper.sh 'command' [result_file]" >&2
    exit 2
fi

readonly CMD="$1"
readonly RESULT_FILE="${2:-/tmp/signal_result}"

# ---------------------------------------------------------------------------
# Signal name lookup
# ---------------------------------------------------------------------------

signal_name_from_num() {
    local num="$1"
    case "${num}" in
        4)  echo "SIGILL"  ;;
        6)  echo "SIGABRT" ;;
        7)  echo "SIGBUS"  ;;
        8)  echo "SIGFPE"  ;;
        9)  echo "SIGKILL" ;;
        11) echo "SIGSEGV" ;;
        14) echo "SIGALRM" ;;
        15) echo "SIGTERM" ;;
        24) echo "SIGXCPU" ;;
        25) echo "SIGXFSZ" ;;
        31) echo "SIGSYS"  ;;
        *)  echo "SIG${num}" ;;
    esac
}

# ---------------------------------------------------------------------------
# Execute the command in a child process
# ---------------------------------------------------------------------------

# Run the command. We use bash -c to support compound commands (pipes, etc).
bash -c "${CMD}" &
CHILD_PID=$!

# Wait for the child to finish. `wait` returns the child's exit status.
wait "${CHILD_PID}" 2>/dev/null
EXIT_CODE=$?

# ---------------------------------------------------------------------------
# Analyze the exit code
# ---------------------------------------------------------------------------

SIGNAL_NAME="none"
SIGNAL_NUM=0

if [[ ${EXIT_CODE} -gt 128 ]]; then
    # Process was killed by a signal. Exit code = 128 + signal number.
    SIGNAL_NUM=$(( EXIT_CODE - 128 ))
    SIGNAL_NAME=$(signal_name_from_num "${SIGNAL_NUM}")
elif [[ ${EXIT_CODE} -eq 124 ]]; then
    # GNU timeout returns 124 when the command times out.
    SIGNAL_NAME="TIMEOUT"
    SIGNAL_NUM=0
fi

# ---------------------------------------------------------------------------
# Write results
# ---------------------------------------------------------------------------

# Write to the result file.
{
    echo "SIGNAL_RESULT:${EXIT_CODE}"
    echo "SIGNAL_NAME:${SIGNAL_NAME}"
    echo "SIGNAL_NUM:${SIGNAL_NUM}"
    echo "CHILD_PID:${CHILD_PID}"
    echo "TIMESTAMP:$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")"
} > "${RESULT_FILE}" 2>/dev/null || true

# Also emit to stdout for the runner to parse when result file is not accessible.
echo "SIGNAL_RESULT:${EXIT_CODE}"

# Exit with the child's exit code so the caller sees the same status.
exit "${EXIT_CODE}"
