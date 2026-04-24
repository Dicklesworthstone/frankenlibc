/* fixture_setjmp_edges.c — deterministic edge-path non-local jump fixture (bd-ahjd)
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#define _POSIX_C_SOURCE 200809L
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*setjmp_symbol_fn)(jmp_buf);

static int running_with_frankenlibc_preload(void) {
    const char *preload = getenv("LD_PRELOAD");
    return preload != NULL && strstr(preload, "frankenlibc_abi") != NULL;
}

static int sigusr1_is_blocked(void) {
    sigset_t current;
    if (sigprocmask(SIG_BLOCK, NULL, &current) != 0) {
        perror("sigprocmask query");
        return -1;
    }
    return sigismember(&current, SIGUSR1);
}

static int restore_mask(sigset_t *prior) {
    if (sigprocmask(SIG_SETMASK, prior, NULL) != 0) {
        perror("sigprocmask restore");
        return 1;
    }
    return 0;
}

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

static int test_setjmp_symbol_does_not_restore_signal_mask(void) {
    sigset_t prior;
    sigset_t block_usr1;
    jmp_buf env;
    setjmp_symbol_fn call_setjmp = (setjmp_symbol_fn)&setjmp;

    if (sigprocmask(SIG_BLOCK, NULL, &prior) != 0) {
        perror("sigprocmask save");
        return 1;
    }
    if (sigemptyset(&block_usr1) != 0 || sigaddset(&block_usr1, SIGUSR1) != 0) {
        perror("sigset setup");
        (void)restore_mask(&prior);
        return 1;
    }
    if (sigprocmask(SIG_BLOCK, &block_usr1, NULL) != 0) {
        perror("sigprocmask block SIGUSR1");
        (void)restore_mask(&prior);
        return 1;
    }

    int value = call_setjmp(env);
    if (value == 0) {
        if (sigprocmask(SIG_UNBLOCK, &block_usr1, NULL) != 0) {
            perror("sigprocmask unblock SIGUSR1");
            (void)restore_mask(&prior);
            return 1;
        }
        longjmp(env, 11);
    }

    int blocked = sigusr1_is_blocked();
    int restore_failed = restore_mask(&prior);
    if (restore_failed) {
        return 1;
    }
    if (value != 11) {
        fprintf(stderr, "FAIL: setjmp symbol value=%d expected=11\n", value);
        return 1;
    }
    if (blocked != 0) {
        fprintf(stderr, "FAIL: setjmp/longjmp restored SIGUSR1 mask unexpectedly\n");
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

static int test_sigsetjmp_restores_signal_mask(void) {
    sigset_t prior;
    sigset_t block_usr1;
    sigjmp_buf env;

    if (sigprocmask(SIG_BLOCK, NULL, &prior) != 0) {
        perror("sigprocmask save");
        return 1;
    }
    if (sigemptyset(&block_usr1) != 0 || sigaddset(&block_usr1, SIGUSR1) != 0) {
        perror("sigset setup");
        (void)restore_mask(&prior);
        return 1;
    }
    if (sigprocmask(SIG_BLOCK, &block_usr1, NULL) != 0) {
        perror("sigprocmask block SIGUSR1");
        (void)restore_mask(&prior);
        return 1;
    }

    int value = sigsetjmp(env, 1);
    if (value == 0) {
        if (sigprocmask(SIG_UNBLOCK, &block_usr1, NULL) != 0) {
            perror("sigprocmask unblock SIGUSR1");
            (void)restore_mask(&prior);
            return 1;
        }
        siglongjmp(env, 17);
    }

    int blocked = sigusr1_is_blocked();
    int restore_failed = restore_mask(&prior);
    if (restore_failed) {
        return 1;
    }
    if (value != 17) {
        fprintf(stderr, "FAIL: sigsetjmp value=%d expected=17\n", value);
        return 1;
    }
    if (blocked != 1) {
        fprintf(stderr, "FAIL: sigsetjmp/siglongjmp did not restore saved SIGUSR1 mask\n");
        return 1;
    }
    return 0;
}

int main(void) {
    if (test_longjmp_zero_becomes_one() != 0) {
        return 1;
    }
    if (running_with_frankenlibc_preload() &&
        test_setjmp_symbol_does_not_restore_signal_mask() != 0) {
        return 1;
    }
    if (test_sigsetjmp_siglongjmp_roundtrip() != 0) {
        return 1;
    }
    if (test_sigsetjmp_restores_signal_mask() != 0) {
        return 1;
    }

    printf("fixture_setjmp_edges: PASS (longjmp0->1 sigsetjmp->siglongjmp)\n");
    return 0;
}
