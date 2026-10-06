/* fixture_setjmp_edges.c — deterministic edge-path non-local jump fixture (bd-ahjd)
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 *
 * On aarch64 this also proves the native release path mangles the saved
 * frame pointer / return address / stack pointer with FrankenLibC's pointer
 * guard, and that a jmp_buf whose saved return address is overwritten with a
 * plaintext attacker address is NOT jumped to (bd-rc0923-epic-eeuy4f.12). The
 * x86_64 equivalents live in fixture_setjmp_guard.c, which is byte-compared to
 * glibc in the preload smoke corpus; the aarch64 jmp_buf layout differs from
 * glibc's, so these read FrankenLibC's own slots and run only under its
 * preload. They are silent on stdout (diagnostics go to stderr) so they do not
 * perturb any byte-for-byte parity comparison.
 */
#define _POSIX_C_SOURCE 200809L
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__aarch64__)
#include <fcntl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

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

#if defined(__aarch64__)
/* FrankenLibC aarch64 jmp_buf: x29 @ byte 80 (word 10), x30 @ byte 88
 * (word 11), sp @ byte 96 (word 12). Each is stored as value ^ guard, where
 * guard is FrankenLibC's own per-process __frankenlibc_pointer_guard (seeded
 * from AT_RANDOM). The test recovers it from the one slot whose plaintext it
 * knows (sp), so it needs no symbol lookup.
 */
static int __attribute__((noinline)) test_aarch64_saved_pointers_are_mangled(void) {
    jmp_buf env;
    uint64_t real_sp;
    __asm__ volatile("mov %0, sp" : "=r"(real_sp));
    if (setjmp(env) == 0) {
        const uint64_t *w = (const uint64_t *)env;
        uint64_t raw_sp = w[12];
        uint64_t raw_pc = w[11];
        /* eor-only mangling means the guard is recoverable from the one word
         * whose plaintext we know (the stack pointer we just read). */
        uint64_t guard = raw_sp ^ real_sp;
        uint64_t pc = raw_pc ^ guard;
        uint64_t fn = (uint64_t)(uintptr_t)&test_aarch64_saved_pointers_are_mangled;
        if (raw_sp == real_sp) {
            fprintf(stderr, "FAIL: aarch64 saved sp stored in plaintext\n");
            return 1;
        }
        if (guard == 0) {
            fprintf(stderr, "FAIL: aarch64 pointer guard is zero (no mangling)\n");
            return 1;
        }
        if (pc < fn || pc >= fn + 65536) {
            fprintf(stderr,
                    "FAIL: aarch64 saved pc 0x%llx does not demangle into this "
                    "function (0x%llx)\n",
                    (unsigned long long)pc, (unsigned long long)fn);
            return 1;
        }
        longjmp(env, 1);
    }
    return 0;
}

static void __attribute__((noinline)) hijack_target_aarch64(void) {
    /* Harmless stand-in for an attacker-chosen gadget. Only reachable if a
     * plaintext address written into the jmp_buf is used verbatim as the jump
     * target — which is exactly the pre-fix (origin/main) behavior. */
    _exit(66);
}

static int test_aarch64_overwritten_pc_not_jumped(void) {
    /* A child overwrites the saved return-address slot with a plaintext
     * address. With mangling, longjmp demangles it to junk and faults; the
     * attacker address is never branched to. Without mangling (origin/main)
     * the plaintext address is used verbatim and the child reaches
     * hijack_target_aarch64 -> _exit(66): the planted negative. */
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        jmp_buf env;
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, 2);
        }
        if (setjmp(env) == 0) {
            ((uint64_t *)env)[11] = (uint64_t)(uintptr_t)&hijack_target_aarch64;
            longjmp(env, 1);
        }
        _exit(3); /* longjmp returned normally — unexpected with a corrupt pc */
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) {
        perror("waitpid");
        return 1;
    }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 66) {
        fprintf(stderr,
                "FAIL: aarch64 overwritten saved pc was branched to the "
                "attacker-chosen address (control-flow hijack)\n");
        return 1;
    }
    if (!WIFSIGNALED(st)) {
        fprintf(stderr,
                "FAIL: aarch64 corrupted jmp_buf neither faulted nor was "
                "detected (wait status %d)\n",
                st);
        return 1;
    }
    return 0;
}
#endif /* __aarch64__ */

int main(void) {
    if (test_longjmp_zero_becomes_one() != 0) {
        return 1;
    }
#if defined(__aarch64__)
    if (running_with_frankenlibc_preload()) {
        if (test_aarch64_saved_pointers_are_mangled() != 0) {
            return 1;
        }
        if (test_aarch64_overwritten_pc_not_jumped() != 0) {
            return 1;
        }
    }
#endif
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
