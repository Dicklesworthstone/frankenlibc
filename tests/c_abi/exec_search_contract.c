#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef FRANKENLIBC_ASYNC_ALLOCATOR_PROBE
#include <dlfcn.h>
#include <stdint.h>
#include <sys/syscall.h>

/* Build this translation unit separately: an application-owned allocator
 * prevents constructor-time policy prewarming, and turns allocator reentry
 * into a deterministic exit instead of an occasionally reproduced deadlock.
 * No fixture setup below enters the candidate's policy before the armed call. */
static _Alignas(16) unsigned char app_heap[4 * 1024 * 1024];
static size_t app_used;
static volatile sig_atomic_t allocator_armed, interrupt_allocator, operation;
static int *error_slot;

static long raw_call4(long number, long a, long b, long c, long d) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = d;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10)
                     : "rcx", "r11", "memory");
    return result;
#elif defined(__aarch64__)
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc 0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory", "cc");
    return x0;
#else
#error This fixture requires Linux x86-64 or AArch64.
#endif
}

__attribute__((noreturn)) static void raw_exit(int status) {
    raw_call4(SYS_exit_group, status, 0, 0, 0);
    for (;;) {}
}

void *malloc(size_t length) {
    if (allocator_armed) raw_exit(91);
    if (interrupt_allocator) {
        interrupt_allocator = 0;
        allocator_armed = 1;
        long pid = raw_call4(SYS_getpid, 0, 0, 0, 0);
        long tid = raw_call4(SYS_gettid, 0, 0, 0, 0);
        raw_call4(SYS_tgkill, pid, tid, SIGUSR1, 0);
        raw_exit(93); /* Every handler either execs or terminates. */
    }
    if (!length) length = 1;
    if (length > sizeof app_heap - 31) return NULL;
    size_t amount = ((length + 15) & ~(size_t)15) + 16;
    if (app_used > sizeof app_heap - amount) return NULL;
    unsigned char *result = app_heap + app_used + 16;
    app_used += amount;
    ((size_t *)result)[-1] = length;
    return result;
}

void free(void *pointer) {
    (void)pointer;
    if (allocator_armed) raw_exit(91);
}

void *calloc(size_t count, size_t size) {
    if (size && count > SIZE_MAX / size) return NULL;
    size_t length = count * size;
    volatile unsigned char *result = malloc(length);
    if (result) for (size_t i = 0; i < length; ++i) result[i] = 0;
    return (void *)result;
}

void *realloc(void *pointer, size_t length) {
    volatile unsigned char *result = malloc(length);
    if (result && pointer) {
        size_t old = ((size_t *)pointer)[-1];
        for (size_t i = 0; i < old && i < length; ++i)
            result[i] = ((volatile unsigned char *)pointer)[i];
    }
    return (void *)result;
}

__attribute__((noreturn)) static void exercise_boundary(int signal_number) {
    (void)signal_number;
    if (operation == 'x') _exit(0x12b);
    if (operation == 'X') _Exit(-213);
    char *args[] = {"async-process-probe", NULL};
    char *env[] = {NULL};
    const char *path = operation == 'e' ? "/bin/true" : "/dev/null/no-executable";
    int result = execve(path, args, env);
    raw_exit(operation == 'f' && result == -1 && *error_slot == ENOTDIR ? 43 : 94);
}

#if defined(__x86_64__)
__attribute__((naked)) static void signal_restorer(void) {
    __asm__ volatile("mov $15, %rax\nsyscall");
}
#endif

int main(int argc, char **argv) {
    if (argc == 3 && argv[1][0] == 'p') {
        /* Ownership is checked in a separate fresh process: dladdr here may
         * initialize policy and must never warm the armed execution cases. */
        void *symbols[] = {(void *)execve, (void *)_exit, (void *)_Exit};
        for (size_t i = 0; i < sizeof symbols / sizeof symbols[0]; ++i) {
            Dl_info info;
            if (!dladdr(symbols[i], &info) || !info.dli_fname ||
                strcmp(info.dli_fname, argv[2])) return 92;
        }
        return 0;
    }
    if (argc != 3) return 95;
    operation = argv[1][0];
    if (operation != 'x' && operation != 'X' && operation != 'e' &&
        operation != 'f' && operation != 'a') return 95;
    error_slot = &errno;
    if (argv[2][0] == 's') {
        struct {
            void (*handler)(int);
            unsigned long flags;
            void (*restorer)(void);
            unsigned long mask;
        } action = {exercise_boundary, 0, NULL, 0};
#if defined(__x86_64__)
        action.flags = 0x04000000; /* Linux SA_RESTORER. */
        action.restorer = signal_restorer;
#endif
        if (raw_call4(SYS_rt_sigaction, SIGUSR1, (long)&action, 0,
                      sizeof action.mask) != 0) return 96;
        interrupt_allocator = 1;
    } else {
        allocator_armed = 1;
        if (operation != 'a') exercise_boundary(0);
    }
    /* A volatile call prevents the compiler deleting the allocation. The
     * 'a' control must exit 91, proving that the reentry detector is armed. */
    void *(*volatile allocate)(size_t) = malloc;
    (void)allocate(1);
    raw_exit(97);
}

#else

/* Black-box launch tests. Scripts only use shell builtins. No caller-provided
 * argument is interpreted as a command string. All fixtures are private. */
extern char **environ;
static char root[PATH_MAX], first[PATH_MAX], second[PATH_MAX];
static unsigned passed, failed;
static void die(const char *s) { perror(s); exit(2); }
static void join(char *out, const char *a, const char *b) {
    if (snprintf(out, PATH_MAX, "%s/%s", a, b) >= PATH_MAX) { errno = ENAMETOOLONG; die("join"); }
}
static void make_file(const char *dir, const char *name, const char *text, mode_t mode) {
    char path[PATH_MAX]; join(path, dir, name);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
    if (fd < 0) die("open fixture");
    size_t left = strlen(text); const char *p = text;
    while (left) {
        ssize_t n = write(fd, p, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) die("write fixture");
        p += n; left -= (size_t)n;
    }
    if (fchmod(fd, mode) || close(fd)) die("finish fixture");
}
enum entry { VP, VPE, LP, VE, V, SPAWNP };
static const char *entry_name(enum entry e) {
    static const char *names[] = {"execvp", "execvpe", "execlp", "execve", "execv", "posix_spawnp"};
    return names[e];
}
static void check(const char *name, enum entry entry, const char *file,
                  const char *path, char *const args[], int empty_env,
                  int expected_status, const char *expected_text) {
    int pipefd[2]; if (pipe2(pipefd, O_CLOEXEC)) die("pipe2");
    fflush(NULL);
    pid_t pid = fork(); if (pid < 0) die("fork");
    if (!pid) {
        alarm(10);
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(120);
        close(pipefd[1]);
        if (chdir(first) || setenv("CHECK_MARKER", "parent", 1)) _exit(121);
        if (path ? setenv("PATH", path, 1) : unsetenv("PATH")) _exit(122);
        char *custom[] = {"CHECK_MARKER=child", "PATH=/not-the-search-path", NULL};
        char *none[] = {NULL};
        char *const *env = empty_env ? none : custom;
        switch (entry) {
        case VP: execvp(file, args); break;
        case VPE: execvpe(file, args, env); break;
        case LP: execlp(file, args[0], args[1], args[2], (char *)NULL); break;
        case VE: execve(file, args, env); break;
        case V: execv(file, args); break;
        case SPAWNP: {
            pid_t child = -1;
            int rc = posix_spawnp(&child, file, NULL, NULL, args, environ);
            if (!rc) {
                int status;
                while (waitpid(child, &status, 0) < 0) {
                    if (errno != EINTR) _exit(123);
                }
                _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 123);
            }
            errno = rc; break;
        }
        }
        int error = errno;
        dprintf(STDOUT_FILENO, "error=%d\n", error);
        _exit(111);
    }
    close(pipefd[1]);
    char output[8192]; size_t used = 0;
    while (used < sizeof output - 1) {
        ssize_t n = read(pipefd[0], output + used, sizeof output - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) die("read output");
        if (!n) break;
        used += (size_t)n;
    }
    output[used] = 0; close(pipefd[0]);
    int status; while (waitpid(pid, &status, 0) < 0) { if (errno != EINTR) die("waitpid"); }
    int okay = WIFEXITED(status) && WEXITSTATUS(status) == expected_status && !strcmp(output, expected_text);
    if (okay) ++passed; else ++failed;
    printf("%s %s/%s\n", okay ? "PASS" : "FAIL", entry_name(entry), name);
    if (!okay) fprintf(stderr, "  status=%d expected=%d; output=[%s] expected=[%s]\n", status, expected_status, output, expected_text);
}
static void error_check(const char *name, enum entry e, const char *file, const char *path,
                        char *const args[], int wanted) {
    char output[64]; snprintf(output, sizeof output, "error=%d\n", wanted);
    check(name, e, file, path, args, 0, 111, output);
}

/* Exercise the real C variadic boundary, including the register/stack spill and
 * both sides of the small argument-buffer boundary. Re-executing this fixture
 * lets the kernel and a new process inspect the complete argument/environment
 * vectors; no test-side replacement of execve can hide a marshalling error. */
typedef int (*list_exec_fn)(const char *, const char *, ...);
#define LIST_ARGS_14 "00", "01", "02", "03", "04", "05", "06", "07", \
                     "08", "09", "10", "11", "12", "13"
#define LIST_ARGS_16 LIST_ARGS_14, "14", "15"
#define LIST_ARGS_64 LIST_ARGS_16, LIST_ARGS_16, LIST_ARGS_16, LIST_ARGS_16
#define LIST_ARGS_256 LIST_ARGS_64, LIST_ARGS_64, LIST_ARGS_64, LIST_ARGS_64
#define LIST_ARGS_1024 LIST_ARGS_256, LIST_ARGS_256, LIST_ARGS_256, LIST_ARGS_256

static int call_list_exec(list_exec_fn function, const char *file, unsigned count,
                          char *const envp[]) {
    char *poison_env[] = {"FRANKENLIBC_LIST_CHILD=poison", "FRANKENLIBC_LIST_COUNT=0", NULL};
    /* The extra values after envp are legal unused variadic arguments. They make
     * an execle implementation that skips the named NULL forward a distinct
     * wrong environment deterministically instead of depending on stack junk. */
#define CALL_LIST(...) function(file, __VA_ARGS__, (char *)NULL, envp, \
                               (char *)NULL, poison_env)
    switch (count) {
    case 0: return function(file, (char *)NULL, envp, (char *)NULL, poison_env);
    case 1: return CALL_LIST("variadic-zero");
    case 4: return CALL_LIST("variadic-zero", "00", "01", "02");
    case 5: return CALL_LIST("variadic-zero", "00", "01", "02", "03");
    case 6: return CALL_LIST("variadic-zero", "00", "01", "02", "03", "04");
    case 63: return CALL_LIST("variadic-zero", LIST_ARGS_16, LIST_ARGS_16,
                             LIST_ARGS_16, LIST_ARGS_14);
    case 64: return CALL_LIST("variadic-zero", LIST_ARGS_16, LIST_ARGS_16,
                             LIST_ARGS_16, LIST_ARGS_14, "14");
    case 65: return CALL_LIST("variadic-zero", LIST_ARGS_64);
    case 1025: return CALL_LIST("variadic-zero", LIST_ARGS_1024);
    default: errno = EINVAL; return -1;
    }
#undef CALL_LIST
}

static int list_exec_child(int argc, char **argv, const char *kind) {
    const char *count_text = getenv("FRANKENLIBC_LIST_COUNT");
    if (!count_text) return 125;
    unsigned count = (unsigned)strtoul(count_text, NULL, 10);
    /* Linux supplies one empty argv[0] when exec receives an empty vector. */
    if (!count) {
        if (argc != 1 || !argv[0] || argv[0][0]) return 125;
    } else {
        if ((unsigned)argc != count || strcmp(argv[0], "variadic-zero")) return 125;
        for (unsigned i = 1; i < count; ++i) {
            char expected[3]; snprintf(expected, sizeof expected, "%02u", (i - 1) % 16);
            if (!argv[i] || strcmp(argv[i], expected)) return 125;
        }
    }
    if (argv[argc] != NULL) return 125;
    if (!strcmp(kind, "inherited")) return 42;
    if (!strcmp(kind, "explicit")) return 43;
    return 126;
}

static void check_list_exec(unsigned entry, unsigned count, const char *file,
                            int wanted_errno) {
    static const char *names[] = {"execl", "execlp", "execle"};
    list_exec_fn functions[] = {execl, execlp, execle};
    fflush(NULL);
    pid_t pid = fork(); if (pid < 0) die("fork list exec");
    if (!pid) {
        alarm(10);
        char count_text[16], explicit_count[64];
        snprintf(count_text, sizeof count_text, "%u", count);
        snprintf(explicit_count, sizeof explicit_count, "FRANKENLIBC_LIST_COUNT=%u", count);
        if (setenv("FRANKENLIBC_LIST_CHILD", "inherited", 1) ||
            setenv("FRANKENLIBC_LIST_COUNT", count_text, 1)) _exit(124);
        char *envp[] = {"FRANKENLIBC_LIST_CHILD=explicit", explicit_count, NULL};
        /* Both stack and mmap failure-return paths must preserve exec's errno. */
        errno = EINTR;
        int rc = call_list_exec(functions[entry], file, count, envp);
        int error = errno;
        _exit(wanted_errno && rc == -1 && error == wanted_errno ? 44 : 127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0) { if (errno != EINTR) die("waitpid list exec"); }
    int expected = wanted_errno ? 44 : entry == 2 ? 43 : 42;
    int okay = WIFEXITED(status) && WEXITSTATUS(status) == expected;
    if (okay) ++passed; else ++failed;
    printf("%s %s/variadic-%u-%s\n", okay ? "PASS" : "FAIL", names[entry],
           count, wanted_errno ? "error" : "exec");
    if (!okay) fprintf(stderr, "  status=%d expected=%d errno=%d\n", status, expected, wanted_errno);
}

int main(int argc, char **argv) {
    const char *list_child = getenv("FRANKENLIBC_LIST_CHILD");
    if (list_child) return list_exec_child(argc, argv, list_child);
    alarm(120);
    strcpy(root, "/tmp/frankenlibc-exec-XXXXXX"); if (!mkdtemp(root)) die("mkdtemp");
    join(first, root, "first"); join(second, root, "second");
    if (mkdir(first, 0700) || mkdir(second, 0700)) die("mkdir");
    const char text[] = "printf 'marker=%s argc=%s a1=<%s> a2=<%s> zero=<%s>\\n' \"${CHECK_MARKER-unset}\" \"$#\" \"$1\" \"$2\" \"$0\"\nexit 37\n";
    make_file(first, "plain", text, 0700);
    make_file(first, "denied", "exit 99\n", 0600);
    make_file(second, "denied", text, 0700);
    make_file(first, "stops", "exit 23\n", 0700);
    make_file(second, "stops", "exit 99\n", 0700);
    make_file(first, "shebang", "#!/bin/sh\nexit 47\n", 0700);
    make_file(first, "many", "[ \"$#\" -eq 4096 ] && exit 29\nexit 99\n", 0700);
    char plain[PATH_MAX], denied[PATH_MAX], nested[PATH_MAX];
    join(plain, first, "plain"); join(denied, first, "denied"); join(nested, plain, "child");
    char path[2 * PATH_MAX + 2]; snprintf(path, sizeof path, "%s:%s", first, second);
    char *args[] = {"caller-argv-zero", "one two", "$(printf INJECTED);*", NULL};
    char expected[PATH_MAX + 256];
    for (enum entry e = VP; e <= LP; ++e) {
        const char *marker = e == VPE ? "child" : "parent";
        snprintf(expected, sizeof expected, "marker=%s argc=2 a1=<one two> a2=<$(printf INJECTED);*> zero=<%s>\n", marker, plain);
        check("text-via-PATH", e, "plain", first, args, 0, 37, expected);
        check("text-with-slash", e, plain, "/no-such-path", args, 0, 37, expected);
        snprintf(expected, sizeof expected, "marker=%s argc=2 a1=<one two> a2=<$(printf INJECTED);*> zero=<plain>\n", marker);
        check("empty-PATH", e, "plain", "", args, 0, 37, expected);
        char with_empty[PATH_MAX + 32]; snprintf(with_empty, sizeof with_empty, "/absent:");
        check("trailing-empty-PATH", e, "plain", with_empty, args, 0, 37, expected);
        snprintf(expected, sizeof expected, "marker=%s argc=2 a1=<one two> a2=<$(printf INJECTED);*> zero=<%s/denied>\n", marker, second);
        check("EACCES-then-script", e, "denied", path, args, 0, 37, expected);
        check("shell-is-terminal", e, "stops", path, args, 0, 23, "");
        check("kernel-shebang", e, "shebang", first, args, 0, 47, "");
        error_check("permission-is-not-shell-fallback", e, denied, first, args, EACCES);
        error_check("missing-name", e, "missing", first, args, ENOENT);
        error_check("empty-name", e, "", first, args, ENOENT);
        error_check("direct-ENOTDIR", e, nested, first, args, ENOTDIR);
    }
    snprintf(expected, sizeof expected, "marker=unset argc=2 a1=<one two> a2=<$(printf INJECTED);*> zero=<%s>\n", plain);
    check("empty-child-environment", VPE, "plain", first, args, 1, 37, expected);
    char *zero[] = {NULL};
    snprintf(expected, sizeof expected, "marker=child argc=0 a1=<> a2=<> zero=<%s>\n", plain);
    check("empty-argv", VPE, "plain", first, zero, 0, 37, expected);
    char *one[] = {"unused", NULL};
    check("argv-zero-only", VPE, "plain", first, one, 0, 37, expected);
    char **many = calloc(4098, sizeof *many); if (!many) die("calloc args");
    for (unsigned i = 0; i < 4097; ++i) many[i] = "value";
    check("large-shell-argument-vector", VPE, "many", first, many, 0, 29, "");
    free(many);
    error_check("raw-execve-no-fallback", VE, plain, first, args, ENOEXEC);
    error_check("raw-execv-no-fallback", V, plain, first, args, ENOEXEC);
    error_check("spawnp-no-fallback", SPAWNP, "plain", first, args, ENOEXEC);
    /* Search errors come from resolving the entire pathname. Even a long
     * basename can encounter ENOTDIR or ENOENT in a preceding component. */
    char long_name[NAME_MAX + 2];
    memset(long_name, 'x', sizeof long_name - 1);
    long_name[sizeof long_name - 1] = 0;
    enum entry searching[] = {VP, VPE, LP, SPAWNP};
    for (unsigned i = 0; i < sizeof searching / sizeof searching[0]; ++i) {
        enum entry e = searching[i];
        error_check("long-name-missing-parent", e, long_name, "/no-such-launch-dir", args, ENOENT);
        error_check("long-name-nondirectory", e, long_name, "/dev/null", args, ENOTDIR);
        error_check("long-name-existing-parent", e, long_name, first, args, ENAMETOOLONG);
    }
    /* The first candidate succeeds. Thousands of later empty components
     * must neither change the executable nor inflate child argument storage. */
    char large_path[65536];
    size_t prefix = strlen(first);
    memcpy(large_path, first, prefix);
    memset(large_path + prefix, ':', sizeof large_path - prefix - 1);
    large_path[sizeof large_path - 1] = 0;
    check("large-PATH-first-match", SPAWNP, "shebang", large_path, args, 0, 47, "");
    check("unset-PATH-default", VP, "true", NULL, one, 0, 0, "");
    check("unset-PATH-custom-env", VPE, "true", NULL, one, 0, 0, "");
    error_check("last-PATH-error", VP, "missing", plain, args, ENOTDIR);
    int busy = open(plain, O_WRONLY); if (busy < 0) die("busy fixture");
    error_check("ETXTBSY-no-shell", VP, "plain", first, args, ETXTBSY);
    close(busy);
    const unsigned list_counts[] = {0, 1, 4, 5, 6, 63, 64, 65, 1025};
    char missing[PATH_MAX]; join(missing, first, "missing-variadic-exec");
    for (unsigned e = 0; e < 3; ++e) {
        for (unsigned i = 0; i < sizeof list_counts / sizeof list_counts[0]; ++i) {
            /* Named-NULL execle is an explicit FrankenLibC extension: the host
             * glibc consumes another variadic terminator before envp. Its
             * environment contract is tested in process_abi_test.rs, separately
             * from these host-differential cases. */
            if (e == 2 && list_counts[i] == 0) continue;
            check_list_exec(e, list_counts[i], "/proc/self/exe", 0);
        }
        check_list_exec(e, 0, missing, ENOENT);
        check_list_exec(e, 5, missing, ENOENT);
        check_list_exec(e, 1025, missing, ENOENT);
        if (e != 1) {
            check_list_exec(e, 5, plain, ENOEXEC);
            check_list_exec(e, 1025, plain, ENOEXEC);
        }
    }
    const char *names[] = {"plain", "denied", "stops", "shebang", "many"};
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; ++i) { char p[PATH_MAX]; join(p, first, names[i]); unlink(p); }
    const char *other[] = {"denied", "stops"};
    for (unsigned i = 0; i < 2; ++i) { char p[PATH_MAX]; join(p, second, other[i]); unlink(p); }
    rmdir(first); rmdir(second); rmdir(root);
    printf("SUMMARY passed=%u failed=%u\n", passed, failed);
    return failed ? 1 : 0;
}

#endif /* FRANKENLIBC_ASYNC_ALLOCATOR_PROBE */
