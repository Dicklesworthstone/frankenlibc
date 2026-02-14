/* fixture_setjmp_edges.c — deterministic edge-path non-local jump fixture (bd-ahjd)
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#define _POSIX_C_SOURCE 200809L
#include <setjmp.h>
#include <stdio.h>

static int test_longjmp_zero_becomes_one(void) {
    jmp_buf env;
    int value = setjmp(env);
    if (value == 0) {
        longjmp(env, 0);
    }
    if (value != 1) {
        fprintf(stderr, "FAIL: setjmp value=%d expected=1 after longjmp(...,0)\n", value);
        return 1;
    }
    return 0;
}

static int test_sigsetjmp_siglongjmp_roundtrip(void) {
    sigjmp_buf env;
    int value = sigsetjmp(env, 1);
    if (value == 0) {
        siglongjmp(env, 5);
    }
    if (value != 5) {
        fprintf(stderr, "FAIL: sigsetjmp value=%d expected=5 after siglongjmp\n", value);
        return 1;
    }
    return 0;
}

int main(void) {
    if (test_longjmp_zero_becomes_one() != 0) {
        return 1;
    }
    if (test_sigsetjmp_siglongjmp_roundtrip() != 0) {
        return 1;
    }

    printf("fixture_setjmp_edges: PASS (longjmp0->1 sigsetjmp->siglongjmp)\n");
    return 0;
}
