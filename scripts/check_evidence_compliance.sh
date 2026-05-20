#!/usr/bin/env bash
# check_evidence_compliance.sh — CI gate for bd-33p.3
#
# Runs evidence-compliance integration tests, including failure-injection paths
# that must fail for deterministic, actionable reasons.
set -euo pipefail

RUN_MODE="rch"

usage() {
    cat <<'EOF'
Usage: check_evidence_compliance.sh [--rch|--local]

Runs the evidence-compliance CLI build and integration suite.

Modes:
  --rch    Run cargo commands through remote rch execution (default).
  --local  Run cargo commands directly. Use only inside an already-remote worker
           or for deliberate local debugging.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rch)
            RUN_MODE="rch"
            ;;
        --local)
            RUN_MODE="local"
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "FAIL: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

run_cargo() {
    if [[ "${RUN_MODE}" == "rch" ]]; then
        RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" rch exec -- "$@"
    else
        "$@"
    fi
}

echo "=== Evidence Compliance Gate (bd-33p.3) ==="
echo ""
echo "--- Building harness CLI for integration tests ---"
run_cargo cargo build -p frankenlibc-harness --bin harness
echo "PASS: harness CLI builds"
echo ""
echo "--- Running evidence compliance integration tests ---"
run_cargo cargo test -p frankenlibc-harness --test evidence_compliance_test -- --nocapture
echo "PASS: evidence compliance tests"
echo ""
echo "check_evidence_compliance: PASS"
