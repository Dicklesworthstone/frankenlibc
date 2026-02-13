#!/usr/bin/env bash
# check_feature_parity_gap_ledger.sh — CI gate for bd-w2c3.1.1
#
# Validates:
# 1) parser unit tests pass (malformed rows / duplicates / status transitions)
# 2) feature parity gap ledger artifact is reproducible from source
# 3) artifact has stable row IDs and no parser errors
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_feature_parity_gap_ledger.py"
OUT="${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json"

if [[ ! -f "${GEN}" ]]; then
  echo "FAIL: missing generator script ${GEN}"
  exit 1
fi

if [[ ! -f "${OUT}" ]]; then
  echo "FAIL: missing gap ledger ${OUT}"
  exit 1
fi

echo "=== Feature Parity Gap Ledger Gate (bd-w2c3.1.1) ==="
(
  cd "${ROOT}"
  python3 "${GEN}" --self-test
  python3 "${GEN}" --output "${OUT}" --check
)

python3 - "${OUT}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)

rows = payload.get("rows", [])
parse_errors = payload.get("parse_errors", [])
summary = payload.get("summary", {})

if not isinstance(rows, list) or not rows:
    raise SystemExit("FAIL: rows must be a non-empty array")

if parse_errors:
    print("FAIL: parser errors present in gap ledger artifact")
    for row in parse_errors[:10]:
        print(f"  - {row.get('section')}:{row.get('line')} {row.get('message')}")
    raise SystemExit(1)

ids = [row.get("row_id") for row in rows]
if any(not isinstance(x, str) or not x for x in ids):
    raise SystemExit("FAIL: every row must include non-empty row_id")

if len(ids) != len(set(ids)):
    raise SystemExit("FAIL: duplicate row_id values detected")

print(
    "PASS: feature parity gap ledger valid "
    f"(rows={len(rows)}, gaps={summary.get('gap_count', 0)}, "
    f"deltas={summary.get('delta_count', 0)})"
)
PY
