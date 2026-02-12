#!/usr/bin/env bash
# check_runtime_math_manifest.sh — Validate production kernel manifest coverage + feature gates.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MOD_RS="$REPO_ROOT/crates/frankenlibc-membrane/src/runtime_math/mod.rs"
CARGO_TOML="$REPO_ROOT/crates/frankenlibc-membrane/Cargo.toml"
MANIFEST="$REPO_ROOT/tests/runtime_math/production_kernel_manifest.v1.json"

if [[ ! -f "$MOD_RS" ]]; then
    echo "ERROR: runtime_math/mod.rs not found at $MOD_RS" >&2
    exit 1
fi
if [[ ! -f "$CARGO_TOML" ]]; then
    echo "ERROR: Cargo.toml not found at $CARGO_TOML" >&2
    exit 1
fi
if [[ ! -f "$MANIFEST" ]]; then
    echo "ERROR: manifest not found at $MANIFEST" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required" >&2
    exit 1
fi

code_modules=$(grep -oP '^pub mod \K[a-z_]+' "$MOD_RS" | sort -u)
prod_modules=$(jq -r '.production_modules[]' "$MANIFEST" | sort -u)
research_modules=$(jq -r '.research_only_modules[]?' "$MANIFEST" | sort -u)

status=0

# Manifest sanity
if ! jq -e '.schema_version == "v1"' "$MANIFEST" >/dev/null; then
    echo "ERROR: manifest schema_version must be v1"
    status=1
fi
if ! jq -e '.latency_budgets_ns.strict_hot_path_max == 20 and .latency_budgets_ns.hardened_hot_path_max == 200' "$MANIFEST" >/dev/null; then
    echo "ERROR: manifest latency budgets must be strict=20ns and hardened=200ns"
    status=1
fi

# Feature sanity
if ! grep -q '^\[features\]' "$CARGO_TOML"; then
    echo "ERROR: crates/frankenlibc-membrane/Cargo.toml missing [features] section"
    status=1
fi
if ! grep -q '^default = \["runtime-math-production"\]' "$CARGO_TOML"; then
    echo "ERROR: default feature set must include runtime-math-production"
    status=1
fi
if ! grep -q '^runtime-math-production = \[\]' "$CARGO_TOML"; then
    echo "ERROR: runtime-math-production feature missing"
    status=1
fi
if ! grep -q '^runtime-math-research = \["runtime-math-production"\]' "$CARGO_TOML"; then
    echo "ERROR: runtime-math-research feature must depend on runtime-math-production"
    status=1
fi

# Set coverage checks
union_modules=$(printf "%s\n%s\n" "$prod_modules" "$research_modules" | sed '/^$/d' | sort -u)
missing_from_manifest=$(comm -23 <(echo "$code_modules") <(echo "$union_modules"))
extra_in_manifest=$(comm -13 <(echo "$code_modules") <(echo "$union_modules"))
overlap=$(comm -12 <(echo "$prod_modules") <(echo "$research_modules"))

if [[ -n "$missing_from_manifest" ]]; then
    echo "=== MANIFEST DRIFT: runtime_math modules missing from manifest ==="
    echo "$missing_from_manifest"
    echo ""
    status=1
fi
if [[ -n "$extra_in_manifest" ]]; then
    echo "=== MANIFEST DRIFT: manifest entries not present in runtime_math/mod.rs ==="
    echo "$extra_in_manifest"
    echo ""
    status=1
fi
if [[ -n "$overlap" ]]; then
    echo "=== MANIFEST ERROR: modules listed as both production and research ==="
    echo "$overlap"
    echo ""
    status=1
fi

# Ensure compile-time feature constants exist in runtime_math/mod.rs.
if ! grep -q 'RUNTIME_MATH_PRODUCTION_ENABLED' "$MOD_RS"; then
    echo "ERROR: runtime_math/mod.rs missing RUNTIME_MATH_PRODUCTION_ENABLED"
    status=1
fi
if ! grep -q 'RUNTIME_MATH_RESEARCH_ENABLED' "$MOD_RS"; then
    echo "ERROR: runtime_math/mod.rs missing RUNTIME_MATH_RESEARCH_ENABLED"
    status=1
fi

if [[ $status -ne 0 ]]; then
    echo ""
    echo "runtime_math production kernel manifest check FAILED"
    exit 1
fi

code_count=$(echo "$code_modules" | wc -l | tr -d ' ')
prod_count=$(echo "$prod_modules" | sed '/^$/d' | wc -l | tr -d ' ')
research_count=$(echo "$research_modules" | sed '/^$/d' | wc -l | tr -d ' ')

echo "OK: runtime_math production manifest covers $code_count modules (Production=$prod_count, ResearchOnly=$research_count)."
