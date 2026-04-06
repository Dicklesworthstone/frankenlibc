#!/usr/bin/env bash
# check_differential_glibc.sh — differential test: FrankenLibC vs host glibc (bd-2tq.2)
#
# Compiles a C test program that exercises key libc functions, runs it
# with and without LD_PRELOAD, and compares outputs. Differences indicate
# behavior divergence from glibc.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance/differential"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_DIR}/${RUN_ID}"
LIB="${ROOT}/target/release/libfrankenlibc_abi.so"
TRACE="${RUN_DIR}/trace.jsonl"
REPORT="${RUN_DIR}/report.json"
mkdir -p "${RUN_DIR}"
: > "${TRACE}"

if [ ! -f "${LIB}" ]; then
    echo "FAIL: ${LIB} not found. Run: cargo build -p frankenlibc-abi --release" >&2
    exit 1
fi

# -----------------------------------------------------------------------
# Generate the C test program
# -----------------------------------------------------------------------
TEST_SRC="${RUN_DIR}/differential_test.c"
TEST_BIN="${RUN_DIR}/differential_test"

cat > "${TEST_SRC}" << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <errno.h>
#include <locale.h>
#include <time.h>
#include <unistd.h>

/* Each test prints a deterministic line: "TEST_NAME: result" */

static void test_strlen(void) {
    printf("strlen_hello: %zu\n", strlen("hello"));
    printf("strlen_empty: %zu\n", strlen(""));
    printf("strlen_10: %zu\n", strlen("0123456789"));
}

static void test_strcmp(void) {
    printf("strcmp_eq: %d\n", strcmp("abc", "abc") == 0 ? 1 : 0);
    printf("strcmp_lt: %d\n", strcmp("abc", "abd") < 0 ? 1 : 0);
    printf("strcmp_gt: %d\n", strcmp("abd", "abc") > 0 ? 1 : 0);
}

static void test_memset(void) {
    char buf[10];
    memset(buf, 'A', 5);
    buf[5] = '\0';
    printf("memset_A5: %s\n", buf);
}

static void test_memcpy(void) {
    char src[] = "hello";
    char dst[10] = {0};
    memcpy(dst, src, 6);
    printf("memcpy_hello: %s\n", dst);
}

static void test_strchr(void) {
    const char *s = "hello world";
    const char *p = strchr(s, 'w');
    printf("strchr_w: %d\n", p ? (int)(p - s) : -1);
    printf("strchr_x: %d\n", strchr(s, 'x') ? 1 : 0);
}

static void test_strstr(void) {
    printf("strstr_world: %d\n", strstr("hello world", "world") ? 1 : 0);
    printf("strstr_empty: %d\n", strstr("hello", "") ? 1 : 0);
    printf("strstr_miss: %d\n", strstr("hello", "xyz") ? 1 : 0);
}

static void test_atoi(void) {
    printf("atoi_42: %d\n", atoi("42"));
    printf("atoi_neg: %d\n", atoi("-123"));
    printf("atoi_zero: %d\n", atoi("0"));
    printf("atoi_space: %d\n", atoi("  456"));
    printf("atoi_trail: %d\n", atoi("789abc"));
}

static void test_strtol(void) {
    char *end;
    printf("strtol_hex: %ld\n", strtol("0xff", &end, 16));
    printf("strtol_oct: %ld\n", strtol("077", &end, 8));
    printf("strtol_auto: %ld\n", strtol("0x1A", &end, 0));
}

static void test_snprintf(void) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%d", 42);
    printf("snprintf_d: %s\n", buf);
    snprintf(buf, sizeof(buf), "%s", "hello");
    printf("snprintf_s: %s\n", buf);
    snprintf(buf, sizeof(buf), "%05d", 42);
    printf("snprintf_05d: %s\n", buf);
    snprintf(buf, sizeof(buf), "%x", 255);
    printf("snprintf_x: %s\n", buf);
    snprintf(buf, sizeof(buf), "%.3f", 3.14159);
    printf("snprintf_f: %s\n", buf);
    snprintf(buf, sizeof(buf), "%%");
    printf("snprintf_pct: %s\n", buf);
    /* Positional */
    snprintf(buf, sizeof(buf), "%2$s is %1$d", 42, "answer");
    printf("snprintf_pos: %s\n", buf);
}

static void test_ctype(void) {
    printf("isalpha_A: %d\n", isalpha('A') ? 1 : 0);
    printf("isalpha_0: %d\n", isalpha('0') ? 1 : 0);
    printf("isdigit_5: %d\n", isdigit('5') ? 1 : 0);
    printf("isdigit_a: %d\n", isdigit('a') ? 1 : 0);
    printf("tolower_A: %c\n", tolower('A'));
    printf("toupper_a: %c\n", toupper('a'));
}

static void test_math(void) {
    printf("sqrt_4: %.1f\n", sqrt(4.0));
    printf("sqrt_2: %.6f\n", sqrt(2.0));
    printf("pow_2_10: %.0f\n", pow(2.0, 10.0));
    printf("sin_0: %.1f\n", sin(0.0));
    printf("fabs_neg: %.1f\n", fabs(-42.5));
    printf("ceil_3_2: %.1f\n", ceil(3.2));
    printf("floor_3_8: %.1f\n", floor(3.8));
}

static void test_getenv(void) {
    const char *path = getenv("PATH");
    printf("getenv_PATH: %d\n", path ? 1 : 0);
    printf("getenv_NONE: %d\n", getenv("FRANKENLIBC_NONEXISTENT_ZZZ") ? 1 : 0);
}

static void test_qsort(void) {
    int arr[] = {5, 3, 1, 4, 2};
    int cmp(const void *a, const void *b) { return *(const int*)a - *(const int*)b; }
    qsort(arr, 5, sizeof(int), cmp);
    printf("qsort: %d,%d,%d,%d,%d\n", arr[0], arr[1], arr[2], arr[3], arr[4]);
}

int main(void) {
    test_strlen();
    test_strcmp();
    test_memset();
    test_memcpy();
    test_strchr();
    test_strstr();
    test_atoi();
    test_strtol();
    test_snprintf();
    test_ctype();
    test_math();
    test_getenv();
    test_qsort();
    return 0;
}
CEOF

echo "=== Differential test: FrankenLibC vs host glibc (bd-2tq.2) ==="
echo "run_id: ${RUN_ID}"

# Compile
gcc -O2 -o "${TEST_BIN}" "${TEST_SRC}" -lm -Wall -Wextra 2>&1 || {
    echo "FAIL: compilation failed" >&2
    exit 1
}

# Run without LD_PRELOAD (baseline = host glibc)
"${TEST_BIN}" > "${RUN_DIR}/baseline.txt" 2>&1
baseline_rc=$?

# Run with LD_PRELOAD (FrankenLibC)
LD_PRELOAD="${LIB}" "${TEST_BIN}" > "${RUN_DIR}/frankenlibc.txt" 2>&1
frankenlibc_rc=$?

# Compare
diff_output=$(diff "${RUN_DIR}/baseline.txt" "${RUN_DIR}/frankenlibc.txt" 2>&1 || true)
diff_lines=$(echo "${diff_output}" | grep -c "^[<>]" || true)

total_tests=$(wc -l < "${RUN_DIR}/baseline.txt")
matching=$(comm -12 <(sort "${RUN_DIR}/baseline.txt") <(sort "${RUN_DIR}/frankenlibc.txt") | wc -l)

echo "Baseline exit: ${baseline_rc}"
echo "FrankenLibC exit: ${frankenlibc_rc}"
echo "Total test lines: ${total_tests}"
echo "Matching lines: ${matching}"
echo "Divergent lines: ${diff_lines}"

if [ "${diff_lines}" -gt 0 ]; then
    echo "DIFFERENCES:"
    echo "${diff_output}" | head -20
fi

# Generate structured trace
python3 - "${RUN_DIR}" "${RUN_ID}" "${total_tests}" "${matching}" "${diff_lines}" "${baseline_rc}" "${frankenlibc_rc}" << 'PY'
import json, sys, time
run_dir, run_id, total, matching, divergent, b_rc, f_rc = sys.argv[1:]
status = "PASS" if int(divergent) == 0 and b_rc == f_rc else "FAIL"
report = {
    "schema_version": "v1",
    "run_id": run_id,
    "test_binary": f"{run_dir}/differential_test",
    "baseline": "host glibc",
    "subject": "FrankenLibC (LD_PRELOAD)",
    "total_test_lines": int(total),
    "matching_lines": int(matching),
    "divergent_lines": int(divergent),
    "baseline_exit": int(b_rc),
    "frankenlibc_exit": int(f_rc),
    "parity_pct": round(100.0 * int(matching) / max(int(total), 1), 2),
    "status": status
}
with open(f"{run_dir}/report.json", "w") as f:
    json.dump(report, indent=2, fp=f)
print(f"Parity: {report['parity_pct']}%")
print(f"Report: {run_dir}/report.json")
print(f"check_differential_glibc: {status}")
PY

echo "=== done ==="
