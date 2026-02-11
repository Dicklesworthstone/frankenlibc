#!/usr/bin/env bash
# CVE-2025-49844 trigger harness for Redis Lua GC use-after-free
# This script orchestrates the vulnerable Redis instance and the
# trigger payload, capturing crash/healing signals for the CVE arena.
set -euo pipefail

RESULT_FILE="/cve_arena/result.json"
REDIS_PORT=6379
REDIS_LOG="/tmp/redis-cve.log"
REDIS_PID=""

cleanup() {
    if [ -n "${REDIS_PID}" ] && kill -0 "${REDIS_PID}" 2>/dev/null; then
        kill "${REDIS_PID}" 2>/dev/null || true
        wait "${REDIS_PID}" 2>/dev/null || true
    fi
    rm -f /tmp/redis-cve.pid
}
trap cleanup EXIT

echo "[cve_arena] CVE-2025-49844: Redis Lua GC use-after-free"
echo "[cve_arena] Starting redis-server on port ${REDIS_PORT}..."

# Start Redis with no protection, system allocator, and aggressive memory settings
redis-server \
    --port "${REDIS_PORT}" \
    --protected-mode no \
    --daemonize no \
    --loglevel verbose \
    --logfile "${REDIS_LOG}" \
    --save "" \
    --appendonly no \
    --activedefrag no \
    --lua-time-limit 30000 \
    &
REDIS_PID=$!
echo "${REDIS_PID}" > /tmp/redis-cve.pid

# Wait for Redis to accept connections (up to 15 seconds)
echo "[cve_arena] Waiting for Redis to accept connections..."
for i in $(seq 1 30); do
    if redis-cli -p "${REDIS_PORT}" ping 2>/dev/null | grep -q PONG; then
        echo "[cve_arena] Redis ready after ~$((i / 2))s"
        break
    fi
    if ! kill -0 "${REDIS_PID}" 2>/dev/null; then
        echo "[cve_arena] ERROR: Redis exited prematurely"
        cat "${REDIS_LOG}" 2>/dev/null || true
        echo '{"status":"error","reason":"redis_exited_prematurely"}' > "${RESULT_FILE}"
        exit 1
    fi
    sleep 0.5
done

# Verify connection
if ! redis-cli -p "${REDIS_PORT}" ping 2>/dev/null | grep -q PONG; then
    echo "[cve_arena] ERROR: Redis did not start in time"
    cat "${REDIS_LOG}" 2>/dev/null || true
    echo '{"status":"error","reason":"redis_startup_timeout"}' > "${RESULT_FILE}"
    exit 1
fi

# Run the trigger script
echo "[cve_arena] Executing UAF trigger payload..."
TRIGGER_EXIT=0
python3 /cve_arena/trigger.py 2>&1 || TRIGGER_EXIT=$?

# Check if Redis is still alive
REDIS_ALIVE=true
if ! kill -0 "${REDIS_PID}" 2>/dev/null; then
    REDIS_ALIVE=false
    wait "${REDIS_PID}" 2>/dev/null
    REDIS_EXIT=$?
    echo "[cve_arena] Redis exited with code ${REDIS_EXIT}"
fi

# Check for crash signals in the log
CRASHED=false
SIGNAL=""
if grep -qiE "SIGSEGV|SIGABRT|SIGBUS|signal 11|signal 6" "${REDIS_LOG}" 2>/dev/null; then
    CRASHED=true
    SIGNAL=$(grep -oiE "SIGSEGV|SIGABRT|SIGBUS|signal 11|signal 6" "${REDIS_LOG}" | head -1)
fi

# Check for TSM healing actions in the log
HEALED=false
HEALING_ACTIONS="[]"
if grep -qiE "TSM_HEAL|IgnoreDoubleFree|ClampSize|quarantine|generation_mismatch" "${REDIS_LOG}" 2>/dev/null; then
    HEALED=true
    HEALING_ACTIONS=$(grep -oiE "TSM_HEAL[^ ]*|IgnoreDoubleFree|ClampSize|quarantine_intercept|generation_mismatch" "${REDIS_LOG}" | \
        sort -u | jq -R -s 'split("\n") | map(select(length > 0))')
fi

# Build result JSON
jq -n \
    --arg cve "CVE-2025-49844" \
    --arg software "redis" \
    --arg version "7.4.0" \
    --argjson trigger_exit "${TRIGGER_EXIT}" \
    --argjson redis_alive "${REDIS_ALIVE}" \
    --argjson crashed "${CRASHED}" \
    --arg signal "${SIGNAL}" \
    --argjson healed "${HEALED}" \
    --argjson healing_actions "${HEALING_ACTIONS}" \
    '{
        cve: $cve,
        software: $software,
        version: $version,
        trigger_exit_code: $trigger_exit,
        server_survived: $redis_alive,
        crashed: $crashed,
        crash_signal: $signal,
        tsm_healed: $healed,
        tsm_healing_actions: $healing_actions,
        timestamp: (now | todate)
    }' > "${RESULT_FILE}"

echo "[cve_arena] Result:"
cat "${RESULT_FILE}"

# Exit with appropriate code
if [ "${CRASHED}" = "true" ]; then
    echo "[cve_arena] VERDICT: VULNERABLE (crash detected)"
    exit 2
elif [ "${HEALED}" = "true" ]; then
    echo "[cve_arena] VERDICT: PROTECTED (TSM healed the attempt)"
    exit 0
else
    echo "[cve_arena] VERDICT: INCONCLUSIVE"
    exit 3
fi
