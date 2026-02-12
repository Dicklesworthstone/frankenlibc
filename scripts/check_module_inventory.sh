#!/usr/bin/env bash
# check_module_inventory.sh — Drift detector for AGENTS.md vs runtime_math code
#
# Compares the runtime_math module inventory in AGENTS.md against the actual
# `pub mod` declarations in crates/frankenlibc-membrane/src/runtime_math/mod.rs.
#
# Exit 0 if in sync, exit 1 if drift detected.
#
# Usage: scripts/check_module_inventory.sh [--fix]
#   --fix  Print suggested AGENTS.md additions (does not auto-edit)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENTS_MD="$REPO_ROOT/AGENTS.md"
MOD_RS="$REPO_ROOT/crates/frankenlibc-membrane/src/runtime_math/mod.rs"

if [[ ! -f "$AGENTS_MD" ]]; then
    echo "ERROR: AGENTS.md not found at $AGENTS_MD" >&2
    exit 1
fi
if [[ ! -f "$MOD_RS" ]]; then
    echo "ERROR: runtime_math/mod.rs not found at $MOD_RS" >&2
    exit 1
fi

# --- Extract runtime_math module names from AGENTS.md Module Inventory ---
# Matches lines like:  - `runtime_math/foo.rs` — description
# in the section between "### frankenlibc-membrane" and "### frankenlibc-core"
agents_modules=$(
    sed -n '/^### frankenlibc-membrane/,/^### frankenlibc-core/p' "$AGENTS_MD" \
    | grep -oP '`runtime_math/\K[a-z_]+(?=\.rs`)' \
    | grep -v '^mod$' \
    | sort -u
)

# --- Extract pub mod declarations from mod.rs ---
code_modules=$(
    grep -oP '^pub mod \K[a-z_]+' "$MOD_RS" \
    | sort -u
)

# --- Compare ---
agents_only=$(comm -23 <(echo "$agents_modules") <(echo "$code_modules"))
code_only=$(comm -13 <(echo "$agents_modules") <(echo "$code_modules"))

drift=0

if [[ -n "$agents_only" ]]; then
    echo "=== DRIFT: In AGENTS.md but NOT in runtime_math/mod.rs ==="
    echo "These modules are documented but have no pub mod declaration."
    echo "They may be top-level membrane modules or may have been removed."
    echo ""
    while IFS= read -r mod; do
        # Check if it exists as a top-level membrane module
        top_level="$REPO_ROOT/crates/frankenlibc-membrane/src/${mod}.rs"
        if [[ -f "$top_level" ]]; then
            echo "  $mod  (exists as top-level membrane module — AGENTS.md path is wrong)"
        else
            echo "  $mod  (MISSING from codebase entirely)"
        fi
    done <<< "$agents_only"
    echo ""
    drift=1
fi

if [[ -n "$code_only" ]]; then
    echo "=== DRIFT: In runtime_math/mod.rs but NOT in AGENTS.md ==="
    echo "These modules exist in code but are not documented in the Module Inventory."
    echo ""
    while IFS= read -r mod; do
        echo "  $mod"
    done <<< "$code_only"
    echo ""
    if [[ "${1:-}" == "--fix" ]]; then
        echo "=== Suggested AGENTS.md additions ==="
        echo "(Add these to the '### frankenlibc-membrane (Safety Substrate)' section)"
        echo ""
        while IFS= read -r mod; do
            # Try to extract the module doc comment
            mod_file="$REPO_ROOT/crates/frankenlibc-membrane/src/runtime_math/${mod}.rs"
            desc=""
            if [[ -f "$mod_file" ]]; then
                desc=$(head -5 "$mod_file" | grep -oP '//!?\s*\K.*' | head -1)
            fi
            echo "- \`runtime_math/${mod}.rs\` — ${desc:-TODO: add description}"
        done <<< "$code_only"
        echo ""
    fi
    drift=1
fi

# --- Also check mandatory live modules (lines 159-169) ---
mandatory_live=$(
    sed -n '/^Mandatory live modules/,/^$/p' "$AGENTS_MD" \
    | grep -oP '`\K[a-z_]+(?=\.rs`)' \
    | sort -u
)

if [[ -n "$mandatory_live" ]]; then
    mandatory_missing=$(comm -23 <(echo "$mandatory_live") <(echo "$code_modules"))
    if [[ -n "$mandatory_missing" ]]; then
        echo "=== CRITICAL: Mandatory live modules missing from code ==="
        while IFS= read -r mod; do
            echo "  $mod"
        done <<< "$mandatory_missing"
        echo ""
        drift=1
    fi
fi

# --- Check decision-law keywords ---
# The documented decision law: mode + context + risk + budget + pareto + design + barrier + consistency
decision_law_keywords="risk pareto design barrier"
decide_fn=$(grep -A 50 'pub fn decide' "$MOD_RS" 2>/dev/null | head -60 || true)

if [[ -n "$decide_fn" ]]; then
    missing_keywords=""
    for kw in $decision_law_keywords; do
        if ! echo "$decide_fn" | grep -qi "$kw"; then
            missing_keywords="$missing_keywords $kw"
        fi
    done
    if [[ -n "$missing_keywords" ]]; then
        echo "=== WARNING: Decision-law keywords not found in decide() ==="
        echo "  Missing references:$missing_keywords"
        echo "  (This may be a false positive if the keywords appear in called functions)"
        echo ""
        # Don't fail on this — it's advisory
    fi
fi

# --- Summary ---
if [[ $drift -eq 0 ]]; then
    agents_count=$(echo "$agents_modules" | wc -l)
    code_count=$(echo "$code_modules" | wc -l)
    echo "OK: AGENTS.md ($agents_count modules) and runtime_math/mod.rs ($code_count modules) are in sync."
    exit 0
else
    echo "DRIFT DETECTED: AGENTS.md and runtime_math/mod.rs are out of sync."
    echo "Run 'scripts/check_module_inventory.sh --fix' for suggested additions."
    exit 1
fi
