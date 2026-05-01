#!/usr/bin/env bash
# check_evidence_compliance.sh — CI gate for bd-33p.3
#
# Runs evidence-compliance integration tests, including failure-injection paths
# that must fail for deterministic, actionable reasons.
set -euo pipefail

echo "=== Evidence Compliance Gate (bd-33p.3) ==="
echo ""
echo "--- Building harness CLI for integration tests ---"
cargo build -p frankenlibc-harness --bin harness
echo "PASS: harness CLI builds"
echo ""
echo "--- Running evidence compliance integration tests ---"
cargo test -p frankenlibc-harness --test evidence_compliance_test -- --nocapture
echo "PASS: evidence compliance tests"
echo ""
echo "check_evidence_compliance: PASS"
