#!/usr/bin/env bash
# CVE-2024-6197 trigger harness for curl ASN.1 stack use-after-free
#
# This script starts a mock TLS server that sends a crafted certificate
# designed to trigger the ASN1 parser bug, then runs curl against it.
# The crafted certificate causes free() to be called on a stack address
# in the UTF-8 conversion path of the ASN.1 parser.
set -euo pipefail

RESULT_FILE="/cve_arena/result.json"
SERVER_PORT=4443
SERVER_PID=""
SERVER_LOG="/tmp/mock_tls_server.log"

cleanup() {
    if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[cve_arena] CVE-2024-6197: curl ASN.1 stack use-after-free"
echo "[cve_arena] curl version: $(curl --version | head -1)"

# Step 1: Generate the crafted TLS certificate and start mock server
echo "[cve_arena] Starting mock TLS server with crafted certificate..."
python3 /cve_arena/mock_tls_server.py \
    --port "${SERVER_PORT}" \
    --log "${SERVER_LOG}" \
    &
SERVER_PID=$!

# Wait for server to start
sleep 2
if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "[cve_arena] ERROR: Mock TLS server failed to start"
    cat "${SERVER_LOG}" 2>/dev/null || true
    echo '{"status":"error","reason":"mock_server_failed"}' > "${RESULT_FILE}"
    exit 1
fi
echo "[cve_arena] Mock TLS server running on port ${SERVER_PORT} (PID ${SERVER_PID})"

# Step 2: Run curl against the mock server
# Use --insecure to skip CA verification (we want to reach the ASN1 parser)
# The crafted cert's ASN1 content triggers the free-on-stack-address bug
echo "[cve_arena] Executing curl against crafted TLS server..."

CRASHED=false
SIGNAL=""
HEALED=false
HEALING_ACTIONS="[]"

set +e

# Attempt 1: Basic HTTPS request
echo "[cve_arena] Attempt 1: Basic HTTPS GET..."
CURL_OUTPUT=$(curl \
    --insecure \
    --connect-timeout 5 \
    --max-time 10 \
    --silent \
    --show-error \
    --output /dev/null \
    --write-out "%{http_code}:%{exitcode}" \
    "https://127.0.0.1:${SERVER_PORT}/" 2>&1)
CURL_EXIT=$?
echo "[cve_arena]   Exit code: ${CURL_EXIT}, Output: ${CURL_OUTPUT:0:200}"

if [ ${CURL_EXIT} -ge 128 ]; then
    SIGNAL_NUM=$((CURL_EXIT - 128))
    case ${SIGNAL_NUM} in
        6)  SIGNAL="SIGABRT" ;;
        11) SIGNAL="SIGSEGV" ;;
        7)  SIGNAL="SIGBUS"  ;;
        *)  SIGNAL="SIG_${SIGNAL_NUM}" ;;
    esac
    CRASHED=true
    echo "[cve_arena]   Crashed with signal: ${SIGNAL}"
fi

# Attempt 2: Request with verbose cert info (deeper ASN1 parsing)
if [ "${CRASHED}" = "false" ]; then
    echo "[cve_arena] Attempt 2: Verbose cert-info request..."
    CURL_OUTPUT2=$(curl \
        --insecure \
        --connect-timeout 5 \
        --max-time 10 \
        --silent \
        --show-error \
        --cert-status \
        --output /dev/null \
        "https://127.0.0.1:${SERVER_PORT}/deep" 2>&1)
    CURL_EXIT2=$?
    echo "[cve_arena]   Exit code: ${CURL_EXIT2}"

    if [ ${CURL_EXIT2} -ge 128 ]; then
        SIGNAL_NUM=$((CURL_EXIT2 - 128))
        case ${SIGNAL_NUM} in
            6)  SIGNAL="SIGABRT" ;;
            11) SIGNAL="SIGSEGV" ;;
            7)  SIGNAL="SIGBUS"  ;;
            *)  SIGNAL="SIG_${SIGNAL_NUM}" ;;
        esac
        CRASHED=true
        echo "[cve_arena]   Crashed with signal: ${SIGNAL}"
    fi
fi

# Attempt 3: Multiple rapid connections (race the stack layout)
if [ "${CRASHED}" = "false" ]; then
    echo "[cve_arena] Attempt 3: Rapid connection burst..."
    for i in $(seq 1 8); do
        CURL_OUTPUTN=$(curl \
            --insecure \
            --connect-timeout 3 \
            --max-time 5 \
            --silent \
            --output /dev/null \
            "https://127.0.0.1:${SERVER_PORT}/burst_${i}" 2>&1)
        CURL_EXITN=$?
        if [ ${CURL_EXITN} -ge 128 ]; then
            SIGNAL_NUM=$((CURL_EXITN - 128))
            case ${SIGNAL_NUM} in
                6)  SIGNAL="SIGABRT" ;;
                11) SIGNAL="SIGSEGV" ;;
                *)  SIGNAL="SIG_${SIGNAL_NUM}" ;;
            esac
            CRASHED=true
            echo "[cve_arena]   Burst ${i}: Crashed with signal: ${SIGNAL}"
            break
        fi
    done
fi

set -e

# Check for TSM healing in curl output
ALL_OUTPUT="${CURL_OUTPUT:-}${CURL_OUTPUT2:-}${CURL_OUTPUTN:-}"
if echo "${ALL_OUTPUT}" | grep -qiE "TSM_HEAL|IgnoreForeignFree|stack_address_rejected|invalid_free_target"; then
    HEALED=true
    HEALING_ACTIONS=$(echo "${ALL_OUTPUT}" | \
        grep -oiE "TSM_HEAL[^ ]*|IgnoreForeignFree|stack_address_rejected|invalid_free_target" | \
        sort -u | jq -R -s 'split("\n") | map(select(length > 0))')
fi

# Also check server log for any crash info
if grep -qiE "TSM_HEAL|IgnoreForeignFree" "${SERVER_LOG}" 2>/dev/null; then
    HEALED=true
fi

# Build result JSON
jq -n \
    --arg cve "CVE-2024-6197" \
    --arg software "curl" \
    --arg version "8.6.0" \
    --argjson crashed "${CRASHED}" \
    --arg signal "${SIGNAL}" \
    --argjson healed "${HEALED}" \
    --argjson healing_actions "${HEALING_ACTIONS}" \
    '{
        cve: $cve,
        software: $software,
        version: $version,
        crashed: $crashed,
        crash_signal: $signal,
        tsm_healed: $healed,
        tsm_healing_actions: $healing_actions,
        timestamp: (now | todate)
    }' > "${RESULT_FILE}"

echo "[cve_arena] Result:"
cat "${RESULT_FILE}"

if [ "${CRASHED}" = "true" ]; then
    echo "[cve_arena] VERDICT: VULNERABLE (crash detected: ${SIGNAL})"
    exit 2
elif [ "${HEALED}" = "true" ]; then
    echo "[cve_arena] VERDICT: PROTECTED (TSM healed the invalid free)"
    exit 0
else
    echo "[cve_arena] VERDICT: INCONCLUSIVE"
    exit 3
fi
