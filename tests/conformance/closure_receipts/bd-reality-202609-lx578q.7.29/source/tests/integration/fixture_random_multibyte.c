/* fixture_random_multibyte.c — glibc-observable PRNG and multibyte results
 * (2026-09-28). Byte-identical to glibc in strict and hardened:
 *  - rand/srand/rand_r/random/srandom sequences, initstate over all five
 *    generator sizes, setstate RESUMING a saved generator and returning the
 *    previous buffer, the drand48 family, seed48/lcong48, random_r;
 *  - mbrtowc/wcrtomb/mbstowcs/wcstombs/mblen/wcwidth/towupper in C, C.UTF-8
 *    and en_US.UTF-8, including EILSEQ from mbstowcs/wcstombs.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <locale.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>

static void show_mbrtowc(const char *label, const char *s, size_t n) {
    mbstate_t st;
    memset(&st, 0, sizeof st);
    wchar_t wc = 0;
    errno = 0;
    size_t r = mbrtowc(&wc, s, n, &st);
    printf("  mbrtowc %-14s n=%zu -> %zd wc=U+%04X errno=%d init=%d\n", label, n, (ssize_t)r, (unsigned)wc, errno, mbsinit(&st));
}

static void random_sequences(void) {
    printf("rand default:");
    for (int i = 0; i < 5; i++) printf(" %d", rand());
    srand(42);
    printf("\nrand srand(42):");
    for (int i = 0; i < 5; i++) printf(" %d", rand());
    srand(0);
    printf("\nrand srand(0):");
    for (int i = 0; i < 3; i++) printf(" %d", rand());
    unsigned seed = 7;
    printf("\nrand_r(7):");
    for (int i = 0; i < 5; i++) printf(" %d", rand_r(&seed));
    srandom(99);
    printf("\nrandom srandom(99):");
    for (int i = 0; i < 5; i++) printf(" %ld", random());
    static char st8[8], st32[32], st64[64], st128[128], st256[256];
    char *states[] = {st8, st32, st64, st128, st256};
    size_t lens[] = {8, 32, 64, 128, 256};
    for (int s = 0; s < 5; s++) {
        initstate(1234, states[s], lens[s]);
        printf("\ninitstate(%zu):", lens[s]);
        for (int i = 0; i < 4; i++) printf(" %ld", random());
    }
    char *prev = setstate(st32);
    printf("\nsetstate back to 32 -> next %ld (prev==st256:%d)", random(), prev == st256);
    srand48(2024);
    printf("\ndrand48:");
    for (int i = 0; i < 3; i++) printf(" %.17g", drand48());
    printf("\nlrand48:");
    for (int i = 0; i < 3; i++) printf(" %ld", lrand48());
    printf("\nmrand48:");
    for (int i = 0; i < 3; i++) printf(" %ld", mrand48());
    unsigned short xs[3] = {1, 2, 3};
    printf("\nerand48/nrand48/jrand48: %.17g %ld %ld", erand48(xs), nrand48(xs), jrand48(xs));
    unsigned short s48[3] = {0x1234, 0x5678, 0x9abc};
    unsigned short *old = seed48(s48);
    printf("\nseed48 old=%x,%x,%x next lrand48=%ld", old[0], old[1], old[2], lrand48());
    unsigned short p[7] = {1, 2, 3, 5, 0, 0, 11};
    lcong48(p);
    printf("\nlcong48 lrand48=%ld %ld", lrand48(), lrand48());
    struct random_data rd;
    memset(&rd, 0, sizeof rd);
    static char rbuf[64];
    initstate_r(5, rbuf, sizeof rbuf, &rd);
    int32_t r1, r2;
    random_r(&rd, &r1);
    random_r(&rd, &r2);
    printf("\nrandom_r: %d %d\n", r1, r2);
    }

static void multibyte(void) {
    const char *locs[] = {"C", "C.UTF-8", "en_US.UTF-8"};
    for (int l = 0; l < 3; l++) {
        const char *got = setlocale(LC_ALL, locs[l]);
        printf("locale %s -> %s MB_CUR_MAX=%zu\n", locs[l], got ? got : "NULL", MB_CUR_MAX);
        show_mbrtowc("ascii", "A", 1);
        show_mbrtowc("e-acute", "\xc3\xa9", 2);
        show_mbrtowc("e-acute part", "\xc3", 1);
        show_mbrtowc("euro", "\xe2\x82\xac", 3);
        show_mbrtowc("emoji", "\xf0\x9f\x98\x80", 4);
        show_mbrtowc("invalid", "\xff", 1);
        show_mbrtowc("overlong", "\xc0\xaf", 2);
        show_mbrtowc("surrogate", "\xed\xa0\x80", 3);
        show_mbrtowc("high-byte", "\x80", 1);
        show_mbrtowc("nul", "", 1);
        mbstate_t st;
        memset(&st, 0, sizeof st);
        wchar_t wc = 0;
        size_t a = mbrtowc(&wc, "\xe2\x82", 2, &st);
        size_t b = mbrtowc(&wc, "\xac", 1, &st);
        printf("  split euro: %zd then %zd wc=U+%04X\n", (ssize_t)a, (ssize_t)b, (unsigned)wc);
        char buf[8];
        memset(&st, 0, sizeof st);
        wchar_t tests[] = {L'A', 0xE9, 0x20AC, 0x1F600, 0xD800, 0x110000};
        for (int i = 0; i < 6; i++) {
            errno = 0;
            size_t n = wcrtomb(buf, tests[i], &st);
            printf("  wcrtomb U+%04X -> %zd errno=%d", (unsigned)tests[i], (ssize_t)n, errno);
            for (size_t k = 0; n != (size_t)-1 && k < n; k++) printf(" %02x", (unsigned char)buf[k]);
            printf("\n");
        }
        wchar_t wbuf[16];
        errno = 0;
        size_t n = mbstowcs(wbuf, "h\xc3\xa9llo\xff", 16);
        printf("  mbstowcs with invalid -> %zd errno=%d\n", (ssize_t)n, errno);
        n = mbstowcs(NULL, "h\xc3\xa9llo", 0);
        printf("  mbstowcs(NULL) -> %zd\n", (ssize_t)n);
        errno = 0;
        n = wcstombs(buf, L"héllo", sizeof buf);
        printf("  wcstombs -> %zd errno=%d\n", (ssize_t)n, errno);
        printf("  mblen(\"\\xc3\\xa9\",2)=%d mblen(NULL)=%d wctob(0xE9)=%d btowc(0xE9)=%d\n", mblen("\xc3\xa9", 2), mblen(NULL, 0), wctob(0xE9), (int)btowc(0xE9));
        printf("  wcwidth: A=%d U+00E9=%d U+4E00=%d U+0301=%d U+1F600=%d U+0007=%d\n", wcwidth(L'A'), wcwidth(0xE9), wcwidth(0x4E00), wcwidth(0x301), wcwidth(0x1F600), wcwidth(7));
        printf("  towupper(U+00E9)=U+%04X iswalpha(U+00E9)=%d iswupper(U+00C9)=%d\n", (unsigned)towupper(0xE9), !!iswalpha(0xE9), !!iswupper(0xC9));
    }
    }

/* The same observer is called through actual ABI pointers by Rust tests and
 * through the deployed executable. Faults are kernel seccomp decisions, not
 * replacement entropy functions. Each fault lives in a fresh child process. */
static int entropy_descriptor_count(void) {
    int count = 0;
    for (int fd = 0; fd < 1024; fd++) {
        if (syscall(SYS_fcntl, fd, F_GETFD, 0) >= 0) count++;
    }
    return count;
}

int flc_entropy_observe(unsigned id, void *const functions[5]) {
    int (*entropy)(void *, size_t) = functions[0];
    uint32_t (*draw)(void) = functions[1];
    void (*fill)(void *, size_t) = functions[2];
    uint32_t (*uniform)(uint32_t) = functions[3];
    int *(*error_location)(void) = functions[4];
    unsigned char data[4098];
    memset(data, 0xa5, sizeof data);
    int descriptors = entropy_descriptor_count();
    int *error = error_location();
    *error = 1234;
    unsigned fault = 0, api = 0;
    int blocked = -1;
    if (id >= 9 && id <= 17) {
        fault = (id - 9) / 3 + 1;
        api = (id - 9) % 3;
    } else if (id >= 18 && id <= 26) {
        fault = 4; /* ENOSYS alone permits the initialized device fallback. */
        api = (id - 18) % 3;
        if (id >= 24) blocked = SYS_read;
        else if (id >= 21) blocked = SYS_openat;
    } else if (id >= 27 && id <= 30) {
        const unsigned faults[] = {1, 2, 4, 3};
        fault = faults[id - 27];
    } else if (id == 8) {
        fault = 1;
    } else if (id > 34) {
        return 90;
    }
    if (fault) {
        const unsigned errors[] = {0, EPERM, EIO, 0, ENOSYS};
#if defined(__x86_64__)
        const unsigned arch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
        const unsigned arch = AUDIT_ARCH_AARCH64;
#else
#error Unsupported entropy fault architecture
#endif
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getrandom, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | errors[fault]),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)blocked, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EIO),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
        };
        struct sock_fprog program = {
            .len = sizeof filter / sizeof filter[0], .filter = filter
        };
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
            prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) return 91;
    }
#define ENTROPY_CHECK(c) do { if (!(c)) return __LINE__; } while (0)
    if (id >= 31) {
        if (id == 31) {
            ENTROPY_CHECK(entropy(data + 1, 32) == 0);
            ENTROPY_CHECK(data[33] == 0xa5);
        } else if (id == 32) {
            (void)draw();
        } else if (id == 33) {
            fill(data + 1, 4096);
        } else {
            ENTROPY_CHECK(uniform(256) < 256);
        }
        ENTROPY_CHECK(data[0] == 0xa5 && data[4097] == 0xa5);
    } else if (id == 0 || id == 8) {
        ENTROPY_CHECK(entropy(NULL, 0) == 0);
        fill(NULL, 0);
        ENTROPY_CHECK(uniform(0) == 0 && uniform(1) == 0);
    } else if (id == 1 || id == 2) {
        size_t length = id == 1 ? 1 : 256;
        unsigned changed = 0;
        for (size_t sample = 0; sample < 32; sample++) {
            ENTROPY_CHECK(entropy(data + 1, length) == 0);
            for (size_t i = 1; i <= length; i++) changed |= data[i] != 0xa5;
        }
        ENTROPY_CHECK(changed); /* Smoke check only; exact random bytes vary. */
        ENTROPY_CHECK(data[0] == 0xa5 && data[length + 1] == 0xa5);
    } else if (id == 3) {
        ENTROPY_CHECK(entropy(data + 1, 257) == -1 && *error == EIO);
        for (size_t i = 0; i < sizeof data; i++) ENTROPY_CHECK(data[i] == 0xa5);
    } else if (id == 4) {
        ENTROPY_CHECK(entropy((void *)(uintptr_t)1, 16) == -1 && *error == EFAULT);
    } else if (id == 5) {
        uint32_t samples[32];
        unsigned different = 0;
        for (size_t i = 0; i < 32; i++) samples[i] = draw();
        for (size_t i = 1; i < 32; i++) different |= samples[i] != samples[0];
        ENTROPY_CHECK(different); /* A smoke check, not a randomness proof. */
    } else if (id == 6) {
        fill(data + 1, 4096);
        ENTROPY_CHECK(data[0] == 0xa5 && data[4097] == 0xa5);
        for (size_t start = 1; start < 4097; start += 32) {
            unsigned changed = 0;
            for (size_t i = start; i < start + 32; i++) changed |= data[i] != 0xa5;
            ENTROPY_CHECK(changed);
        }
    } else if (id == 7) {
        ENTROPY_CHECK(uniform(0) == 0 && uniform(1) == 0);
        for (size_t i = 0; i < 128; i++) ENTROPY_CHECK(uniform(257) < 257);
    } else if (id >= 27) {
        int expected = fault == 1 ? EPERM : fault == 4 ? ENOSYS : EIO;
        ENTROPY_CHECK(entropy(data + 1, 32) == -1 && *error == expected);
        for (size_t i = 0; i < sizeof data; i++) ENTROPY_CHECK(data[i] == 0xa5);
    } else {
        if (api == 0) {
            uint32_t first = draw(), different = 0;
            if (id >= 18 && id <= 20) {
                for (size_t i = 0; i < 32; i++) different |= draw() != first;
                ENTROPY_CHECK(different);
            }
        } else if (api == 1) {
            fill(data + 1, 4096);
            if (id >= 18 && id <= 20) {
                unsigned changed = 0;
                for (size_t i = 1; i < 4097; i++) changed |= data[i] != 0xa5;
                ENTROPY_CHECK(changed && data[0] == 0xa5 && data[4097] == 0xa5);
            }
        } else {
            uint32_t value = uniform(256);
            ENTROPY_CHECK(value < 256);
            if (id >= 18 && id <= 20) {
                unsigned different = 0;
                for (size_t i = 0; i < 32; i++) {
                    uint32_t next = uniform(256);
                    ENTROPY_CHECK(next < 256);
                    different |= next != value;
                }
                ENTROPY_CHECK(different);
            }
        }
        /* An entropy API without an error return must not return on failure. */
        if (id < 18 || id > 20) return 92;
    }
    ENTROPY_CHECK(entropy_descriptor_count() == descriptors);
#undef ENTROPY_CHECK
    return 0;
}

#if defined(__x86_64__)
static int entropy_trace_error(pid_t child, int result, int deliver) {
    /* Release our own tracee on a probe error instead of leaving it stopped.
     * These cases have no permanent seccomp policy or blocking input. */
    (void)ptrace(PTRACE_DETACH, child, 0, deliver);
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) break;
    return result;
}
#endif

int flc_entropy_run(unsigned id, void *const functions[5]) {
    pid_t child = fork();
    if (child < 0) return 93;
    if (!child) {
        struct rlimit limit = {0, 0};
        if (setrlimit(RLIMIT_CORE, &limit)) _exit(94);
        signal(SIGABRT, SIG_DFL);
#if defined(__x86_64__)
        if (id >= 31) {
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) || raise(SIGSTOP)) _exit(99);
        }
#endif
        int result = flc_entropy_observe(id, functions);
        if (result) dprintf(STDERR_FILENO, "entropy case=%u failure_line=%d\n", id, result);
        _exit(result ? 95 : 0);
    }
    int status;
#if defined(__x86_64__)
    if (id >= 31) {
        /* Exercise real progress, not fabricated random bytes: shorten the
         * first getrandom request to one byte, interrupt the next syscall,
         * then let the kernel fill the exact remaining output region. */
        if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) return 100;
        if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD))
            return entropy_trace_error(child, 101, 0);
        unsigned calls = 0;
        unsigned long long requested = id == 31 ? 32 : id == 33 ? 4096 : 4;
        unsigned long long original_buffer = 0, original_length = 0;
        int entering = 1, interrupt = 0;
        for (;;) {
            if (ptrace(PTRACE_SYSCALL, child, 0, 0))
                return entropy_trace_error(child, 102, 0);
            if (waitpid(child, &status, 0) != child)
                return entropy_trace_error(child, 103, 0);
            if (WIFEXITED(status)) {
                if (WEXITSTATUS(status) != 0 || calls != 3)
                    dprintf(STDERR_FILENO, "entropy trace case=%u exit=%d calls=%u\n",
                            id, WEXITSTATUS(status), calls);
                /* Some GNU implementations obtain entropy without issuing
                 * this request as a syscall. No injection means no retry
                 * evidence: preserve a distinct unexercised result. */
                if (WEXITSTATUS(status) == 0 && calls == 0) return 112;
                return WEXITSTATUS(status) == 0 && calls == 3 ? 0 : 104;
            }
            if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
            if (!WIFSTOPPED(status)) return entropy_trace_error(child, 105, 0);
            if (WSTOPSIG(status) != (SIGTRAP | 0x80))
                return entropy_trace_error(child, 105, WSTOPSIG(status));
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, child, 0, &regs))
                return entropy_trace_error(child, 106, 0);
            /* Lazy libc initialization may obtain unrelated 32-byte entropy
             * before the requested draw. Inject only into this operation's
             * request, then require its exact continuation after each fault. */
            if (entering && regs.orig_rax == SYS_getrandom &&
                (calls || regs.rsi == requested)) {
                calls++;
                if (calls == 1) {
                    original_buffer = regs.rdi;
                    original_length = regs.rsi;
                    if (original_length <= 1) return entropy_trace_error(child, 110, 0);
                    regs.rsi = 1;
                } else if (regs.rdi != original_buffer + 1 ||
                           regs.rsi != original_length - 1) {
                    dprintf(STDERR_FILENO,
                            "entropy trace case=%u call=%u offset=%lld length=%llu initial=%llu\n",
                            id, calls, (long long)(regs.rdi - original_buffer),
                            regs.rsi, original_length);
                    return entropy_trace_error(child, 111, 0);
                }
                if (calls == 2) {
                    regs.orig_rax = (unsigned long long)-1;
                    interrupt = 1;
                }
                if (ptrace(PTRACE_SETREGS, child, 0, &regs))
                    return entropy_trace_error(child, 107, 0);
            } else if (!entering && interrupt) {
                regs.rax = (unsigned long long)-EINTR;
                if (ptrace(PTRACE_SETREGS, child, 0, &regs))
                    return entropy_trace_error(child, 108, 0);
                interrupt = 0;
            }
            entering = !entering;
        }
    }
#else
    if (id >= 31) return 109; /* Explicitly unqualified on other architectures. */
#endif
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 96;
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 97;
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--entropy-case")) {
        const char *names[] = {"getentropy", "arc4random", "arc4random_buf",
                               "arc4random_uniform", "__errno_location"};
        void *functions[5];
        const char *pin = getenv("FLC_ENTROPY_EXPECT_PROVIDER");
        struct stat expected;
        if (!pin || syscall(SYS_newfstatat, AT_FDCWD, pin, &expected, 0)) return 42;
        for (size_t i = 0; i < 5; i++) {
            functions[i] = dlsym(RTLD_DEFAULT, names[i]);
            Dl_info info;
            struct stat actual;
            if (!functions[i] || !dladdr(functions[i], &info) || !info.dli_fname ||
                syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0) ||
                actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino) return 42;
        }
        char *end;
        unsigned long id = strtoul(argv[2], &end, 10);
        if (*end || id > 34) return 98;
        return flc_entropy_run((unsigned)id, functions);
    }
    random_sequences();
    multibyte();
    return 0;
}
