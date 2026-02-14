/* fixture_setjmp_nested.c — deterministic nested non-local jump fixture (bd-ahjd)
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <setjmp.h>
#include <stdio.h>

static jmp_buf g_outer;
static jmp_buf g_inner;

static int run_nested_jump(void) {
    int outer = setjmp(g_outer);
    if (outer != 0) {
        return outer;
    }

    int inner = setjmp(g_inner);
    if (inner == 0) {
        longjmp(g_inner, 7);
    }
    if (inner != 7) {
        return -100;
    }

    longjmp(g_outer, 42);
}

int main(void) {
    int result = run_nested_jump();
    if (result != 42) {
        fprintf(stderr, "FAIL: nested jump result=%d expected=42\n", result);
        return 1;
    }

    printf("fixture_setjmp_nested: PASS (inner=7 outer=42)\n");
    return 0;
}
