#!/usr/bin/env bash
# check_runtime_math_linkage.sh — Verify runtime_math decision linkage ledger completeness.
#
# Ensures every `pub mod` declared in runtime_math/mod.rs has a machine-readable
# linkage entry with required fields, and that Production modules have concrete
# decision-linkage payloads.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MOD_RS="$REPO_ROOT/crates/frankenlibc-membrane/src/runtime_math/mod.rs"
LEDGER="$REPO_ROOT/tests/runtime_math/runtime_math_linkage.v1.json"

if [[ ! -f "$MOD_RS" ]]; then
    echo "ERROR: runtime_math/mod.rs not found at $MOD_RS" >&2
    exit 1
fi
if [[ ! -f "$LEDGER" ]]; then
    echo "ERROR: linkage ledger not found at $LEDGER" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required to validate linkage ledger" >&2
    exit 1
fi

runtime_modules=$(grep -oP '^pub mod \K[a-z_]+' "$MOD_RS" | sort -u)
ledger_modules=$(jq -r '.modules | keys[]' "$LEDGER" | sort -u)
required_fields=$(jq -r '.required_fields[]' "$LEDGER")

drift=0

missing_in_ledger=$(comm -23 <(echo "$runtime_modules") <(echo "$ledger_modules"))
extra_in_ledger=$(comm -13 <(echo "$runtime_modules") <(echo "$ledger_modules"))

if [[ -n "$missing_in_ledger" ]]; then
    echo "=== LINKAGE DRIFT: Modules missing from ledger ==="
    echo "$missing_in_ledger"
    echo ""
    drift=1
fi

if [[ -n "$extra_in_ledger" ]]; then
    echo "=== LINKAGE DRIFT: Ledger has modules not declared in runtime_math/mod.rs ==="
    echo "$extra_in_ledger"
    echo ""
    drift=1
fi

for mod in $runtime_modules; do
    for field in $required_fields; do
        if ! jq -e --arg m "$mod" --arg f "$field" '.modules[$m][$f] != null' "$LEDGER" >/dev/null; then
            echo "ERROR: module '$mod' missing required field '$field'"
            drift=1
        fi
    done

    status=$(jq -r --arg m "$mod" '.modules[$m].linkage_status // ""' "$LEDGER")
    if [[ "$status" != "Production" && "$status" != "ResearchOnly" ]]; then
        echo "ERROR: module '$mod' has invalid linkage_status '$status'"
        drift=1
        continue
    fi

    if [[ "$status" == "Production" ]]; then
        if ! jq -e --arg m "$mod" '(.modules[$m].decision_target | type == "string" and length > 0)' "$LEDGER" >/dev/null; then
            echo "ERROR: Production module '$mod' lacks non-empty decision_target"
            drift=1
        fi
        if ! jq -e --arg m "$mod" '(.modules[$m].evidence_inputs | type == "array" and length > 0)' "$LEDGER" >/dev/null; then
            echo "ERROR: Production module '$mod' lacks evidence_inputs[]"
            drift=1
        fi
        if ! jq -e --arg m "$mod" '(.modules[$m].action_outputs | type == "array" and length > 0)' "$LEDGER" >/dev/null; then
            echo "ERROR: Production module '$mod' lacks action_outputs[]"
            drift=1
        fi
    else
        if ! jq -e --arg m "$mod" '(.modules[$m].research_reason? // "" | type == "string" and length > 0)' "$LEDGER" >/dev/null; then
            echo "ERROR: ResearchOnly module '$mod' must define non-empty research_reason"
            drift=1
        fi
    fi
done

if [[ $drift -ne 0 ]]; then
    echo ""
    echo "LINKAGE CHECK FAILED: runtime_math linkage ledger is incomplete or out of sync."
    exit 1
fi

module_count=$(echo "$runtime_modules" | wc -l | tr -d ' ')
production_count=$(jq '[.modules[] | select(.linkage_status == "Production")] | length' "$LEDGER")
research_count=$(jq '[.modules[] | select(.linkage_status == "ResearchOnly")] | length' "$LEDGER")

echo "OK: runtime_math linkage ledger covers $module_count modules (Production=$production_count, ResearchOnly=$research_count)."
