/* fixture_startup.c — controlled __libc_start_main phase-0 fixture under LD_PRELOAD
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 * FRANKENLIBC_LEGACY_CRT_FIXTURE with --wrap=__libc_start_main exercises the
 * real process entrypoint with the non-null init callback used by older CRTs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*startup_main_fn_t)(int, char **, char **);
typedef void (*startup_init_fn_t)(int, char **, char **);
typedef void (*startup_fini_fn_t)(void);

#ifdef FRANKENLIBC_LEGACY_CRT_FIXTURE

#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>

extern int __real___libc_start_main(startup_main_fn_t, int, char **,
                                  startup_init_fn_t, startup_fini_fn_t,
                                  startup_fini_fn_t, void *);
extern startup_init_fn_t __init_array_start[], __init_array_end[];
extern void _init(void);

static int expected_argc;
static char **expected_argv, **expected_envp;
static startup_init_fn_t original_init;
static int legacy_init_calls, constructor_calls, preinit_calls, main_calls;
static int legacy_error;

static int vectors_match(int argc, char **argv, char **envp) {
    /* Check identities before dereferencing: the broken zero-argument call
     * supplies arbitrary register contents and must fail without a bad read. */
    if (argc != expected_argc || argv != expected_argv || envp != expected_envp)
        return 0;
    if (argc != 3 || !argv[0] || !argv[1] || !argv[2] || argv[3])
        return 0;
    if (strcmp(argv[1], "first argument") || strcmp(argv[2], "second"))
        return 0;
    for (size_t i = 0; envp[i]; ++i) {
        if (!strcmp(envp[i], "FRANKENLIBC_LEGACY_INIT_MARKER=process-vectors"))
            return 1;
    }
    return 0;
}

static void legacy_preinit(int argc, char **argv, char **envp) {
    (void)argc;
    (void)argv;
    (void)envp;
    ++preinit_calls;
}

__attribute__((used, section(".preinit_array")))
static startup_init_fn_t preinit_entry = legacy_preinit;

__attribute__((constructor(101)))
static void legacy_constructor_first(int argc, char **argv, char **envp) {
    if (legacy_init_calls != 1 || constructor_calls != 0 || preinit_calls != 1 ||
        !vectors_match(argc, argv, envp))
        legacy_error = 1;
    ++constructor_calls;
}

__attribute__((constructor(102)))
static void legacy_constructor_second(int argc, char **argv, char **envp) {
    if (legacy_init_calls != 1 || constructor_calls != 1 ||
        !vectors_match(argc, argv, envp))
        legacy_error = 2;
    ++constructor_calls;
}

static void legacy_csu_init(int argc, char **argv, char **envp) {
    ++legacy_init_calls;
    if (!vectors_match(argc, argv, envp)) {
        legacy_error = 3;
        return;
    }
    if (original_init) {
        original_init(argc, argv, envp);
    } else {
        _init();
        for (startup_init_fn_t *entry = __init_array_start;
             entry != __init_array_end; ++entry)
            (*entry)(argc, argv, envp);
    }
}

/* The ordinary CRT still supplies the real kernel stack, main, rtld finalizer
 * and stack boundary. Only its init argument is replaced, recreating the old
 * __libc_csu_init handoff even with a modern CRT that otherwise passes NULL. */
int __wrap___libc_start_main(startup_main_fn_t main_fn, int argc, char **argv,
                           startup_init_fn_t init, startup_fini_fn_t fini,
                           startup_fini_fn_t rtld_fini, void *stack_end) {
    expected_argc = argc;
    expected_argv = argv;
    expected_envp = argv + argc + 1;
    original_init = init;
    return __real___libc_start_main(main_fn, argc, argv, legacy_csu_init,
                                  fini, rtld_fini, stack_end);
}

static int startup_provider_matches(void) {
    const char *expected = getenv("FRANKENLIBC_EXPECTED_STARTUP_LIBRARY");
    Dl_info info;
    void *actual = (void *)__real___libc_start_main;
    if (!dladdr(actual, &info) || !info.dli_fname)
        return 0;
    if (expected && *expected) {
        struct stat observed, required;
        return stat(info.dli_fname, &observed) == 0 && stat(expected, &required) == 0 &&
               observed.st_dev == required.st_dev && observed.st_ino == required.st_ino;
    }
    void *host = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
    return host && dlsym(host, "__libc_start_main") == actual;
}

__attribute__((destructor(101)))
static void legacy_finalizer(void) {
    if (legacy_error || legacy_init_calls != 1 || constructor_calls != 2 ||
        preinit_calls != 1 || main_calls != 1)
        _exit(82);
    puts("legacy_crt_fini=ok");
}

int main(int argc, char **argv, char **envp) {
    ++main_calls;
    if (legacy_error || legacy_init_calls != 1 || constructor_calls != 2 ||
        preinit_calls != 1 || !vectors_match(argc, argv, envp)) {
        fprintf(stderr, "FAIL legacy CRT: error=%d init=%d constructors=%d preinit=%d\n",
                legacy_error, legacy_init_calls, constructor_calls, preinit_calls);
        return 81;
    }
    if (!startup_provider_matches()) {
        legacy_error = 4;
        fputs("FAIL legacy CRT: wrong __libc_start_main provider\n", stderr);
        return 83;
    }
    puts("legacy_crt_init=ok argc=3 constructors=2 preinit=1");
    return 0;
}

#else

extern int __frankenlibc_startup_phase0(startup_main_fn_t main, int argc, char **ubp_av,
                                     startup_init_fn_t init, startup_fini_fn_t fini,
                                     startup_fini_fn_t rtld_fini, void *stack_end)
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

static void hook_init(int argc, char **argv, char **envp) {
    (void)argc;
    (void)argv;
    (void)envp;
    g_init_called++;
}
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
    char env0[] = "FOO=BAR";
    /* Phase-0 fixtures mirror the initial process stack layout:
     * argv entries, argv NULL terminator, envp entries, envp NULL terminator.
     */
    char *argv_env[] = {arg0, arg1, NULL, env0, NULL};

    /* phase-0 auxv-style key/value pairs: AT_SECURE=1, AT_NULL terminator */
    unsigned long auxv[] = {23UL, 1UL, 0UL, 0UL};

    if (!__frankenlibc_startup_phase0) {
        fprintf(stderr, "FAIL: __frankenlibc_startup_phase0 not resolved (check LD_PRELOAD)\n");
        return 1;
    }

    int rc = __frankenlibc_startup_phase0(fake_main, 2, argv_env, hook_init, hook_fini,
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

    /* The phase-0 fixture's envp is stack-owned. Its execution must not
     * replace the real process environment that later teardown code reads. */
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (mode == NULL) {
        fprintf(stderr, "FAIL: phase-0 fixture replaced process environment\n");
        return 6;
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

#endif
