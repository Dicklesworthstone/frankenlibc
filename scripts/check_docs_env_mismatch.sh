#!/usr/bin/env bash
# check_docs_env_mismatch.sh — CI gate for bd-29b.2
#
# Validates that:
#   1) docs env inventory/report are reproducible.
#   2) each mismatch has explicit remediation_action.
#   3) unresolved_ambiguous mismatch list is empty.
#   4) docs/code mismatch counts are fully reconciled (all zero).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_docs_env_mismatch_report.py"
REPORT="${ROOT}/tests/conformance/env_docs_code_mismatch_report.v1.json"

if [[ ! -f "${GEN}" ]]; then
  echo "FAIL: missing generator script ${GEN}"
  exit 1
fi

python3 "${GEN}" --root "${ROOT}" --check

python3 - "${REPORT}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)

failures = []
for row in payload.get("classifications", []):
    if not row.get("remediation_action"):
        failures.append(f"{row.get('env_key')}: missing remediation_action")
    if not row.get("mismatch_class"):
        failures.append(f"{row.get('env_key')}: missing mismatch_class")

unresolved = payload.get("unresolved_ambiguous", [])
if unresolved:
    failures.append(f"unresolved_ambiguous_count={len(unresolved)}")

summary = payload.get("summary", {})
for key in ("missing_in_docs_count", "missing_in_code_count", "semantic_drift_count"):
    count = int(summary.get(key, 0))
    if count != 0:
        failures.append(f"{key}={count}")

if failures:
    print("FAIL: docs/code mismatch report unresolved")
    for row in failures:
        print(f"  - {row}")
    raise SystemExit(1)

print(
    "PASS: docs/code mismatch report reconciled "
    f"(total={summary.get('total_classifications', 0)}, "
    f"missing_in_docs={summary.get('missing_in_docs_count', 0)}, "
    f"missing_in_code={summary.get('missing_in_code_count', 0)}, "
    f"semantic_drift={summary.get('semantic_drift_count', 0)})"
)
PY
