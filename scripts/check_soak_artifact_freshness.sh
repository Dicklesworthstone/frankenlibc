#!/bin/bash
# bd-gq1kz7.14: WS8 soak artifact freshness preflight
# Verifies replacement artifact exists and matches current source revision.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Artifact paths to check
ARTIFACT_PATHS=(
    "$PROJECT_ROOT/target/standalone_replacement_artifact/cargo-target/release/libfrankenlibc_replace.so"
    "$PROJECT_ROOT/target/release/deps/libfrankenlibc_abi.so"
    "$PROJECT_ROOT/target/release/libfrankenlibc_abi.so"
)

main() {
    local timestamp artifact source_rev artifact_mtime source_mtime
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    source_rev=$(git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")
    source_mtime=$(git -C "$PROJECT_ROOT" log -1 --format=%ct 2>/dev/null || echo "0")

    # Find artifact
    artifact=""
    for p in "${ARTIFACT_PATHS[@]}"; do
        if [[ -f "$p" ]] && [[ -s "$p" ]]; then
            artifact="$p"
            break
        fi
    done

    if [[ -z "$artifact" ]]; then
        printf '{"status":"fail","reason":"artifact_missing","timestamp":"%s","gate":"bd-gq1kz7.14","source_revision":"%s"}\n' "$timestamp" "$source_rev" | jq .
        exit 1
    fi

    artifact_mtime=$(stat -c %Y "$artifact" 2>/dev/null || echo "0")
    local artifact_size
    artifact_size=$(stat -c %s "$artifact" 2>/dev/null || echo "0")

    local is_stale="false"
    local staleness=$((source_mtime - artifact_mtime))
    [[ $staleness -gt 0 ]] && is_stale="true"

    local status="pass"
    [[ "$is_stale" == "true" ]] && status="fail"

    printf '{"status":"%s","timestamp":"%s","gate":"bd-gq1kz7.14","source_revision":"%s","artifact":{"path":"%s","size_bytes":%d,"mtime_epoch":%d,"is_stale":%s,"staleness_seconds":%d},"soak_ready":%s}\n' \
        "$status" "$timestamp" "$source_rev" "$artifact" "$artifact_size" "$artifact_mtime" "$is_stale" "$staleness" \
        "$([ "$status" = "pass" ] && echo "true" || echo "false")" | jq .
}

main
