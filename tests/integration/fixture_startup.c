/* fixture_startup.c — controlled __libc_start_main phase-0 fixture under LD_PRELOAD
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef int (*startup_main_fn_t)(int, char **, char **);
typedef void (*startup_hook_fn_t)(void);

extern int __frankenlibc_startup_phase0(startup_main_fn_t main, int argc, char **ubp_av,
                                     startup_hook_fn_t init, startup_hook_fn_t fini,
                                     startup_hook_fn_t rtld_fini, void *stack_end)
    __attribute__((weak));
typedef struct startup_snapshot_t {
    size_t argc;
    size_t argv_count;
    size_t env_count;
    size_t auxv_count;
    int secure_mode;
} startup_snapshot_t;
extern int __frankenlibc_startup_snapshot(startup_snapshot_t *out) __attribute__((weak));

static int g_main_called = 0;
static int g_init_called = 0;
static int g_fini_called = 0;
static int g_rtld_fini_called = 0;

static void hook_init(void) { g_init_called++; }
static void hook_fini(void) { g_fini_called++; }
static void hook_rtld_fini(void) { g_rtld_fini_called++; }

static int fake_main(int argc, char **argv, char **envp) {
    g_main_called++;

    if (argc != 2) {
        fprintf(stderr, "FAIL: fake_main argc=%d expected=2\n", argc);
        return 101;
    }
    if (argv == NULL || argv[0] == NULL || argv[1] == NULL || argv[2] != NULL) {
        fprintf(stderr, "FAIL: fake_main argv shape invalid\n");
        return 102;
    }
    if (envp == NULL || envp[0] == NULL || envp[1] != NULL) {
        fprintf(stderr, "FAIL: fake_main envp shape invalid\n");
        return 103;
    }
    if (strcmp(envp[0], "FOO=BAR") != 0) {
        fprintf(stderr, "FAIL: fake_main envp[0]='%s' expected='FOO=BAR'\n", envp[0]);
        return 104;
    }

    return 37;
}

static int test_startup_happy_path(void) {
    char arg0[] = "fixture_startup";
    char arg1[] = "phase0";
    char *argv[] = {arg0, arg1, NULL};

    char env0[] = "FOO=BAR";
    char *envp[] = {env0, NULL};

    /* phase-0 auxv-style key/value pairs: AT_SECURE=1, AT_NULL terminator */
    unsigned long auxv[] = {23UL, 1UL, 0UL, 0UL};

    (void)envp;

    if (!__frankenlibc_startup_phase0) {
        fprintf(stderr, "FAIL: __frankenlibc_startup_phase0 not resolved (check LD_PRELOAD)\n");
        return 1;
    }

    int rc = __frankenlibc_startup_phase0(fake_main, 2, argv, hook_init, hook_fini,
                                       hook_rtld_fini, (void *)auxv);
    if (rc != 37) {
        fprintf(stderr, "FAIL: __libc_start_main rc=%d expected=37\n", rc);
        return 1;
    }

    if (g_init_called != 1 || g_main_called != 1 ||
        g_fini_called != 1 || g_rtld_fini_called != 1) {
        fprintf(stderr,
                "FAIL: callback counts init=%d main=%d fini=%d rtld_fini=%d\n",
                g_init_called, g_main_called, g_fini_called, g_rtld_fini_called);
        return 2;
    }

    if (!__frankenlibc_startup_snapshot) {
        fprintf(stderr, "FAIL: __frankenlibc_startup_snapshot not resolved\n");
        return 3;
    }
    startup_snapshot_t snap = {0};
    errno = 0;
    int snap_rc = __frankenlibc_startup_snapshot(&snap);
    if (snap_rc != 0) {
        fprintf(stderr, "FAIL: startup snapshot rc=%d errno=%d\n", snap_rc, errno);
        return 4;
    }
    if (snap.argc != 2 || snap.argv_count != 2 || snap.env_count != 1 ||
        snap.auxv_count != 1 || snap.secure_mode != 1) {
        fprintf(stderr,
                "FAIL: snapshot mismatch argc=%zu argv=%zu env=%zu auxv=%zu secure=%d\n",
                snap.argc, snap.argv_count, snap.env_count, snap.auxv_count, snap.secure_mode);
        return 5;
    }

    return 0;
}

static int test_startup_rejects_null_main(void) {
    char arg0[] = "fixture_startup";
    char *argv[] = {arg0, NULL};
    unsigned long auxv[] = {0UL, 0UL};

    errno = 0;
    int rc = __frankenlibc_startup_phase0(NULL, 1, argv, hook_init, hook_fini, hook_rtld_fini,
                                       (void *)auxv);
    if (rc != -1) {
        fprintf(stderr, "FAIL: null-main rc=%d expected=-1\n", rc);
        return 1;
    }
    if (errno != EINVAL) {
        fprintf(stderr, "FAIL: null-main errno=%d expected=%d (EINVAL)\n", errno, EINVAL);
        return 2;
    }

    return 0;
}

int main(void) {
    int fails = 0;

    fails += test_startup_happy_path();
    fails += test_startup_rejects_null_main();

    if (fails) {
        fprintf(stderr, "fixture_startup: %d FAILED\n", fails);
        return 1;
    }

    printf("fixture_startup: PASS (2 tests)\n");
    return 0;
}
