#!/bin/bash
# bd-gq1kz7.9: Host-backed surface burn-down dashboard for WrapsHostLibc rows
# Groups remaining host-backed symbols by module, risk, and proof family.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MATRIX="$PROJECT_ROOT/support_matrix.json"

if [[ ! -f "$MATRIX" ]]; then
    echo '{"status":"error","message":"support_matrix.json not found"}'
    exit 1
fi

# Extract host-backed symbols and group by module
generate_report() {
    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Total counts
    local total_symbols
    total_symbols=$(jq '.symbols | length' "$MATRIX")

    local wraps_host
    wraps_host=$(jq '[.symbols[] | select(.status == "WrapsHostLibc")] | length' "$MATRIX")

    local glibc_callthrough
    glibc_callthrough=$(jq '[.symbols[] | select(.status == "GlibcCallThrough")] | length' "$MATRIX")

    local total_host_backed=$((wraps_host + glibc_callthrough))

    # Group by module
    local by_module
    by_module=$(jq -r '
        [.symbols[] | select(.status == "WrapsHostLibc" or .status == "GlibcCallThrough")]
        | group_by(.module)
        | map({
            module: .[0].module,
            count: length,
            symbols: [.[].symbol] | sort,
            risk: (if length > 50 then "high" elif length > 10 then "medium" else "low" end)
        })
        | sort_by(-.count)
    ' "$MATRIX")

    # Generate proof family mapping
    local proof_families
    proof_families=$(jq -r '
        [.symbols[] | select(.status == "WrapsHostLibc" or .status == "GlibcCallThrough")]
        | group_by(.module)
        | map({
            module: .[0].module,
            proof_family: (
                if .[0].module == "stdio_abi" then "stdio-owned"
                elif .[0].module == "io_internal_abi" then "io-internal-owned"
                else "generic-owned"
                end
            ),
            owner_crate: (
                if .[0].module == "stdio_abi" then "frankenlibc-abi"
                elif .[0].module == "io_internal_abi" then "frankenlibc-abi"
                else "frankenlibc-abi"
                end
            )
        })
    ' "$MATRIX")

    cat <<EOF
{
  "status": "ok",
  "timestamp": "$timestamp",
  "gate": "bd-gq1kz7.9",
  "summary": {
    "total_symbols": $total_symbols,
    "wraps_host_libc": $wraps_host,
    "glibc_callthrough": $glibc_callthrough,
    "total_host_backed": $total_host_backed,
    "standalone_capable": $((total_symbols - total_host_backed)),
    "standalone_percent": $(echo "scale=2; ($total_symbols - $total_host_backed) * 100 / $total_symbols" | bc)
  },
  "by_module": $by_module,
  "proof_families": $proof_families,
  "burndown_targets": [
    {
      "priority": 1,
      "module": "stdio_abi",
      "action": "Implement owned FILE* and stdio operations",
      "blockers": ["owned-malloc", "owned-tls"],
      "estimated_symbols": 92
    },
    {
      "priority": 2,
      "module": "io_internal_abi",
      "action": "Lift internal I/O helpers to pure Rust",
      "blockers": ["stdio_abi"],
      "estimated_symbols": 63
    }
  ]
}
EOF
}

generate_report | jq .
