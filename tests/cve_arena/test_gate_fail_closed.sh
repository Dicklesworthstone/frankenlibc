#!/usr/bin/env bash
# Regression tests for CVE Arena gate fail-closed behavior.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="${ROOT}/scripts/cve_arena_gate.sh"
if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not installed"
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
RESULTS="${TMP}/results"
mkdir -p "${RESULTS}"
RUNNER="${TMP}/runner.sh"
REPORTER="${TMP}/report.sh"

cat > "${RUNNER}" <<'RUN'
#!/usr/bin/env bash
set -euo pipefail
exit "${MOCK_RUNNER_EXIT:-0}"
RUN
chmod +x "${RUNNER}"

cat > "${REPORTER}" <<'REPORT'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$1"
printf '%s\n' "${MOCK_SUMMARY:-"{}"}" > "$1/summary.json"
REPORT
chmod +x "${REPORTER}"

run_gate() {
    CVE_ARENA_RESULTS_DIR="${RESULTS}" \
    CVE_ARENA_RUNNER="${1}" \
    CVE_ARENA_REPORT="${2}" \
    CVE_ARENA_SKIP_RUN="${3}" \
    MOCK_RUNNER_EXIT="${MOCK_RUNNER_EXIT:-0}" \
    MOCK_SUMMARY="${MOCK_SUMMARY:-"{}"}" \
        bash "${GATE}" > "${TMP}/stdout" 2> "${TMP}/stderr"
}

expect_exit() {
    local expected="$1"
    shift
    local actual=0
    run_gate "$@" || actual=$?
    if [[ "${actual}" -ne "${expected}" ]]; then
        echo "FAIL: expected exit ${expected}, got ${actual}" >&2
        cat "${TMP}/stdout" "${TMP}/stderr" >&2
        exit 1
    fi
}

# Missing runner cannot be replaced by unrelated cargo tests.
expect_exit 2 "${TMP}/missing-runner" "${REPORTER}" 0

# A failing runner must invalidate an old passing summary.
printf '%s\n' '{"total_cves":1,"prevented":1,"detected":0,"regressions":0,"baseline":0,"prevention_rate":1}' > "${RESULTS}/summary.json"
MOCK_RUNNER_EXIT=1 expect_exit 1 "${RUNNER}" "${REPORTER}" 0
if [[ -e "${RESULTS}/summary.json" ]]; then
    echo "FAIL: stale summary survived a failed run" >&2
    exit 1
fi

# Missing reporter cannot reuse a prior summary.
expect_exit 2 "${RUNNER}" "${TMP}/missing-report" 0

# Malformed and inconsistent evidence must fail before threshold evaluation.
MOCK_SUMMARY='{"total_cves":1,"prevented":"1","detected":0,"regressions":0,"baseline":0,"prevention_rate":1}' \
    expect_exit 2 "${RUNNER}" "${REPORTER}" 0
MOCK_SUMMARY='{"total_cves":1,"prevented":2,"detected":0,"regressions":0,"baseline":0,"prevention_rate":1}' \
    expect_exit 2 "${RUNNER}" "${REPORTER}" 0

# Valid, independently generated counters retain the existing success path.
MOCK_SUMMARY='{"total_cves":1,"prevented":1,"detected":0,"regressions":0,"baseline":0,"prevention_rate":1}' \
    expect_exit 0 "${RUNNER}" "${REPORTER}" 0
echo "PASS: CVE Arena gate fail-closed regressions"
