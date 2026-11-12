#!/usr/bin/env bash
# check_claim_reconciliation.sh — CI gate for bd-w2c3.10.1
# Cross-checks FEATURE_PARITY/support/reality/replacement/docs for contradictions.
# Exit 0 = clean, 1 = contradictions found, 2 = missing artifacts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CANONICAL_REPORT="${FLC_CLAIM_RECON_CANONICAL_REPORT:-$REPO_ROOT/tests/conformance/claim_reconciliation_report.v1.json}"
REPORT_OUT="${1:-$CANONICAL_REPORT}"
TMP_REPORT="$(mktemp "${TMPDIR:-/tmp}/claim_reconciliation_report.XXXXXX.json")"

echo "=== Claim Reconciliation Gate (bd-w2c3.10.1) ==="
echo "Repo root: $REPO_ROOT"
echo "Report output: $REPORT_OUT"
echo ""

cd "$REPO_ROOT"
mkdir -p "$(dirname "$REPORT_OUT")"

rc=0
python3 scripts/claim_reconciliation.py > "$TMP_REPORT" || rc=$?
mv "$TMP_REPORT" "$REPORT_OUT"

if [ "$rc" -eq 0 ]; then
    echo "PASS: No contradictions detected across canonical artifacts."
    echo ""
    python3 -c "
import json
with open('$REPORT_OUT') as f:
    r = json.load(f)
gt = r.get('ground_truth', {})
print(f'Ground truth (support_matrix.json):')
print(f'  Total: {gt.get(\"total\", \"?\")}')
print(f'  Implemented: {gt.get(\"Implemented\", \"?\")}')
print(f'  RawSyscall: {gt.get(\"RawSyscall\", \"?\")}')
print(f'  GlibcCallThrough: {gt.get(\"GlibcCallThrough\", \"?\")}')
print(f'  Stub: {gt.get(\"Stub\", \"?\")}')
s = r.get('summary', {})
print(f'Findings: {s.get(\"total_findings\", 0)} (errors={s.get(\"errors\", 0)}, warnings={s.get(\"warnings\", 0)})')
"
elif [ "$rc" -eq 1 ]; then
    echo "FAIL: Contradictions detected."
    echo ""
    python3 -c "
import json
with open('$REPORT_OUT') as f:
    r = json.load(f)
s = r.get('summary', {})
print(f'Summary: {s.get(\"errors\", 0)} errors, {s.get(\"warnings\", 0)} warnings')
owners = r.get('owner_summary', [])
if owners:
    print('Remediation owners:')
    for row in owners:
        print(
            f'  - {row.get(\"owner_bead\", \"unknown\")}: '
            f'{row.get(\"finding_count\", 0)} finding(s)'
        )
print()
for f in r.get('findings', []):
    sev = f['severity'].upper()
    owner = f.get('owner_bead', 'unknown')
    print(f'[{sev}] {f[\"source\"]} ({owner}): {f[\"message\"]}')
"
    echo ""
    echo "Full report: $REPORT_OUT"
elif [ "$rc" -eq 2 ]; then
    echo "ERROR: Missing critical artifacts."
    python3 -c "
import json
with open('$REPORT_OUT') as f:
    r = json.load(f)
for f in r.get('findings', []):
    print(f'  MISSING: {f[\"source\"]}')
"
fi

exit "$rc"
