#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/tools/stdio_synth/Cargo.toml"
OUTPUT_PATH="${TMPDIR:-/tmp}/frankenlibc_stdio_tables.smt2"
BUDGET_SECONDS="${SMT_BUDGET_SECONDS:-90}"
SOLVER="${FRANKENLIBC_SMT_SOLVER:-}"

SECONDS=0

cargo run \
  --manifest-path "$MANIFEST_PATH" \
  --bin smt-prove \
  -- \
  --output "$OUTPUT_PATH" \
  >/dev/null

elapsed_seconds="$SECONDS"

if [[ -z "$SOLVER" ]]; then
  if command -v cvc5 >/dev/null 2>&1; then
    SOLVER="cvc5"
  elif command -v z3 >/dev/null 2>&1; then
    SOLVER="z3"
  fi
fi

if [[ -n "$SOLVER" ]]; then
  solver_status="$("$SOLVER" "$OUTPUT_PATH" | awk 'NF { print; exit }')"
  if [[ "$solver_status" != "sat" ]]; then
    echo "stdio_synth SMT solver failed: ${SOLVER} returned '${solver_status:-<empty>}'" >&2
    echo "artifact: $OUTPUT_PATH" >&2
    exit 1
  fi
fi

if (( elapsed_seconds > BUDGET_SECONDS )); then
  echo "stdio_synth SMT budget exceeded: ${elapsed_seconds}s > ${BUDGET_SECONDS}s" >&2
  echo "artifact: $OUTPUT_PATH" >&2
  exit 1
fi

echo "stdio_synth SMT budget OK: ${elapsed_seconds}s <= ${BUDGET_SECONDS}s"
echo "artifact: $OUTPUT_PATH"
if [[ -n "$SOLVER" ]]; then
  echo "solver: $SOLVER (sat)"
else
  echo "solver: unavailable (generation-only budget enforced)"
fi
