#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/tools/stdio_synth/Cargo.toml"
OUTPUT_PATH="${TMPDIR:-/tmp}/frankenlibc_stdio_tables.smt2"
BUDGET_SECONDS="${SMT_BUDGET_SECONDS:-90}"

SECONDS=0

cargo run \
  --manifest-path "$MANIFEST_PATH" \
  --bin smt-prove \
  -- \
  --output "$OUTPUT_PATH" \
  >/dev/null

elapsed_seconds="$SECONDS"

if (( elapsed_seconds > BUDGET_SECONDS )); then
  echo "stdio_synth SMT budget exceeded: ${elapsed_seconds}s > ${BUDGET_SECONDS}s" >&2
  echo "artifact: $OUTPUT_PATH" >&2
  exit 1
fi

echo "stdio_synth SMT budget OK: ${elapsed_seconds}s <= ${BUDGET_SECONDS}s"
echo "artifact: $OUTPUT_PATH"
