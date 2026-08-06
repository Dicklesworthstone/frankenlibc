#!/usr/bin/env bash
# check_abi_bench_feature_build.sh — CI gate for bd-25bzch
#
# Builds the frankenlibc-bench crate WITH the `abi-bench` feature. Nothing else
# in scripts/ or .github/ does this: the only other occurrence of
# `--features abi-bench` is one ad-hoc script that runs three named benches.
#
# WHY THIS GATE EXISTS. `frankenlibc-abi` is an OPTIONAL dependency of
# frankenlibc-bench behind the `abi-bench` feature, and every example that needs
# it declares `required-features = ["abi-bench"]`. Cargo SKIPS such targets
# unless the feature is on — so the default `cargo check --all-targets` never
# builds the A/B perf harnesses at all. A configuration nobody builds is a
# configuration nobody tests, and this one holds the instruments the perf
# campaign's numbers come from.
#
# It is not hypothetical. On 2026-08-06 three harnesses were found broken here,
# each calling a `*_for_bench` hook that a later refactor had deleted as dead
# code — including the harness behind a published 3.98-4.13x vs-glibc claim,
# unbuildable since 2026-06-26 (bd-5ibpa3). The hook is unreferenced in the
# default build so it looks dead; the harness is not in the default build
# either, so nothing notices. Two mutually invisible halves.
#
# Exit 0 = the feature-enabled build is clean, 1 = a target failed to build,
#          2 = the build did not actually run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="${REPO_ROOT}/target/conformance"
OUT="${OUT_DIR}/abi_bench_feature_build.log"
mkdir -p "$OUT_DIR"

echo "=== abi-bench feature build gate (bd-25bzch) ==="

# --keep-going is REQUIRED, not a nicety: without it cargo stops at the first
# failing target and reports a fraction of the damage. The 2026-08-06 sweep read
# 2 failures bare and 62 with --keep-going.
CARGO_ARGS=(check -p frankenlibc-bench --all-targets --features abi-bench --keep-going)

set +e
if command -v rch >/dev/null 2>&1 && [[ "${FRANKENLIBC_ABI_BENCH_GATE_LOCAL:-0}" != "1" ]]; then
    RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo "${CARGO_ARGS[@]}" >"$OUT" 2>&1
else
    cargo "${CARGO_ARGS[@]}" >"$OUT" 2>&1
fi
build_rc=$?
set -e

# ---------------------------------------------------------------------------
# A RESULT OF ZERO IS ONLY EVIDENCE IF YOU ALSO OBSERVED THE RUNNER DOING WORK.
#
# Checking "no target failed" alone would pass when the build never ran. That is
# exactly how this gate's own subject was nearly closed on a false green: rch
# refused the job ("all workers failed preflight checks") and the absence of
# output read as "0 targets failed". So assert the POSITIVE fact first — that
# cargo emitted Compiling/Checking lines — and only then that nothing failed.
# ---------------------------------------------------------------------------
units_built=$(grep -cE '^ +(Compiling|Checking)' "$OUT" || true)
failed=$(grep -cE 'could not compile' "$OUT" || true)

echo "units compiled/checked : ${units_built}"
echo "targets failed to build: ${failed}"
echo "log: ${OUT}"

if [[ "${units_built}" -eq 0 ]]; then
    echo ""
    echo "FAIL(2): the build produced NO Compiling/Checking lines — it did not run."
    echo "         A zero failure count here means nothing. Common causes:"
    echo "           - rch refused the job (grep the log for 'failed preflight checks')"
    echo "           - every unit was already fresh; force with 'touch crates/frankenlibc-bench/src/lib.rs'"
    tail -20 "$OUT" >&2
    exit 2
fi

if [[ "${failed}" -ne 0 || "${build_rc}" -ne 0 ]]; then
    echo ""
    echo "FAIL(1): the abi-bench configuration does not build (cargo rc=${build_rc})."
    grep -E 'could not compile' "$OUT" >&2 || true
    echo "" >&2
    grep -E '^error' -A 4 "$OUT" | head -60 >&2 || true
    exit 1
fi

echo ""
echo "PASS: abi-bench configuration builds clean (${units_built} units)."
exit 0
