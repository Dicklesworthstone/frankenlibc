#if defined(FLC_FDEXEC_STATIC_PAYLOAD)
/* A real executable with no interpreter or libc dependency. It runs inside
   an empty chroot and checks the arguments, environment and inherited fd. */
#if !defined(__x86_64__)
#error "The descriptor-exec static payload currently targets x86-64"
#endif
static long raw3(long nr, long a, long b, long c) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return result;
}
static int equal(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}
static const char *value(const char *s, const char *name) {
    while (*name && *s == *name) { s++; name++; }
    return *name ? (const char *)0 : s;
}
__attribute__((used, noinline, noreturn)) static void fd_payload(unsigned long *stack) {
    unsigned long argc = stack[0];
    char **argv = (char **)(stack + 1), **env = argv + argc + 1;
    int ok = argc == 3 && equal(argv[0], "fd-exec") && equal(argv[1], "payload") && equal(argv[2], "argument-sentinel");
    long fd = -1; int token = 0, cloexec = -1, opath = -1;
    for (int i = 0; i < 16 && env[i]; i++) {
        const char *p;
        if (equal(env[i], "FLC_FD_EXEC_TOKEN=environment-sentinel")) token = 1;
        if ((p = value(env[i], "FLC_FD_EXEC_FD="))) {
            fd = 0;
            while (*p >= '0' && *p <= '9') { fd = fd * 10 + *p - '0'; p++; }
        }
        if ((p = value(env[i], "FLC_FD_EXEC_CLOEXEC="))) cloexec = *p - '0';
        if ((p = value(env[i], "FLC_FD_EXEC_OPATH="))) opath = *p - '0';
    }
    ok = ok && token && fd >= 0 && cloexec >= 0 && opath >= 0;
    if (ok) {
        long flags = raw3(72, fd, 1, 0); /* fcntl(F_GETFD) */
        if (cloexec) ok = flags == -9;
        else {
            long status = raw3(72, fd, 3, 0); /* fcntl(F_GETFL) */
            ok = flags == 0 && status >= 0 && !!(status & 0x200000) == opath;
            if (!opath) ok = ok && raw3(8, fd, 0, 1) == 7; /* lseek(SEEK_CUR) */
        }
    }
    if (ok) {
        static const char message[] = "FD_EXEC_PAYLOAD_OK\n";
        ok = raw3(1, 1, (long)message, sizeof message - 1) == (long)sizeof message - 1;
    }
    raw3(60, ok ? 37 : 93, 0, 0);
    __builtin_unreachable();
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall fd_payload\nud2\n");
#else
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <pthread.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef int (*fd_exec_fn)(int, char *const [], char *const []);
typedef int *(*fd_errno_fn)(void);
struct fd_exec_observation {
    int status, returned, result, error, stage, flags;
    long position;
    char output[64];
};
struct child_return { int returned, result, error, stage; };

/* Fault injection for one syscall in this child, not a security sandbox. */
static int fd_exec_filter(int nr, int error) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (unsigned)error),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = {(unsigned short)(sizeof code / sizeof *code), code};
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

/* policy: plain, execve denied, execveat ENOSYS, execveat EACCES,
   empty chroot, empty chroot plus execveat ENOSYS. Invalid: negative fd,
   NULL argv, NULL envp, closed fd. Every child is waited for normally. */
int fl_fdexec_observe(fd_exec_fn execute, fd_errno_fn error_slot,
                      const char *payload, const char *jail, int form,
                      int policy, int invalid, struct fd_exec_observation *out) {
    memset(out, 0, sizeof *out);
    int fd = open(payload, (form & 2 ? O_PATH : O_RDONLY) | (form & 1 ? O_CLOEXEC : 0));
    if (fd < 0) return 1;
    if (!(form & 2) && lseek(fd, 7, SEEK_SET) != 7) { close(fd); return 2; }
    int output[2], report[2];
    if (pipe2(output, O_CLOEXEC) != 0) { close(fd); return 3; }
    if (pipe2(report, O_CLOEXEC) != 0) { close(fd); close(output[0]); close(output[1]); return 4; }
    char fd_env[64], close_env[64], path_env[64];
    if (snprintf(fd_env, sizeof fd_env, "FLC_FD_EXEC_FD=%d", fd) < 0 ||
        snprintf(close_env, sizeof close_env, "FLC_FD_EXEC_CLOEXEC=%d", !!(form & 1)) < 0 ||
        snprintf(path_env, sizeof path_env, "FLC_FD_EXEC_OPATH=%d", !!(form & 2)) < 0) return 5;
    char *args[] = {"fd-exec", "payload", "argument-sentinel", NULL};
    char *env[] = {"FLC_FD_EXEC_TOKEN=environment-sentinel", fd_env, close_env, path_env, NULL};
    pid_t child = fork();
    if (child < 0) return 6;
    if (child == 0) {
        struct child_return r = {0, 0, 0, 0};
        close(output[0]); close(report[0]);
        if (dup2(output[1], STDOUT_FILENO) < 0) r.stage = 1;
        close(output[1]);
        if (!r.stage && policy >= 4) {
            if (!jail || chroot(jail) != 0 || chdir("/") != 0) r.stage = 2;
            else {
                long probe = syscall(SYS_openat, AT_FDCWD, "/proc/self/fd", O_RDONLY | O_DIRECTORY, 0);
                if (probe != -1 || errno != ENOENT) r.stage = 3;
                if (probe >= 0) close((int)probe);
            }
        }
        int nr = policy == 1 ? SYS_execve : SYS_execveat;
        int injected = policy == 1 ? EPERM : policy == 3 ? EACCES : ENOSYS;
        if (!r.stage && policy != 0 && policy != 4) {
            if (fd_exec_filter(nr, injected) != 0) r.stage = 4;
            else {
                /* Empty-path execve and fd -1 execveat cannot replace the
                   process even if the filter was accidentally ineffective. */
                long check = policy == 1 ? syscall(SYS_execve, "", args, env) :
                    syscall(SYS_execveat, -1, "", args, env, AT_EMPTY_PATH);
                if (check != -1 || errno != injected) r.stage = 5;
            }
        }
        if (!r.stage) {
            int target = invalid == 1 ? -1 : fd;
            if (invalid == 4 && close(fd) != 0) r.stage = 6;
            if (!r.stage) {
                *error_slot() = 0;
                r.result = execute(target, invalid == 2 ? NULL : args, invalid == 3 ? NULL : env);
                r.error = *error_slot(); r.returned = 1;
            }
        }
        ssize_t written = write(report[1], &r, sizeof r);
        _exit(written == (ssize_t)sizeof r ? 0 : 125);
    }
    close(output[1]); close(report[1]);
    size_t used = 0;
    for (;;) {
        char bytes[64]; ssize_t count = read(output[0], bytes, sizeof bytes);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return 7;
        if (count == 0) break;
        if (used + (size_t)count >= sizeof out->output) return 8;
        memcpy(out->output + used, bytes, (size_t)count); used += (size_t)count;
    }
    struct child_return r = {0, 0, 0, 0};
    ssize_t got;
    do { got = read(report[0], &r, sizeof r); } while (got < 0 && errno == EINTR);
    if (got != 0 && got != (ssize_t)sizeof r) return 9;
    pid_t waited;
    do { waited = waitpid(child, &out->status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != child) return 10;
    out->returned = r.returned; out->result = r.result; out->error = r.error; out->stage = r.stage;
    out->flags = fcntl(fd, F_GETFD);
    out->position = form & 2 ? -1 : lseek(fd, 0, SEEK_CUR);
    close(output[0]); close(report[0]); close(fd);
    return 0;
}

#if !defined(FLC_FDEXEC_LIBRARY)
static int via_execveat(int fd, char *const args[], char *const env[]) {
    return execveat(fd, "", args, env, AT_EMPTY_PATH);
}
static int fd_exec_provider(void) {
    const char *expected = getenv("FLC_FDEXEC_EXPECT_PROVIDER");
    if (!expected) return 0;
    struct stat want, actual;
    if (stat(expected, &want) != 0) return 42;
    const void *symbols[] = {(const void *)fexecve, (const void *)execveat, (const void *)__errno_location};
    for (size_t i = 0; i < sizeof symbols / sizeof *symbols; i++) {
        Dl_info info;
        if (!dladdr(symbols[i], &info) || !info.dli_fname || stat(info.dli_fname, &actual) != 0 ||
            want.st_dev != actual.st_dev || want.st_ino != actual.st_ino) return 42;
    }
    return 0;
}
static int fd_exec_contract(const char *payload, const char *jail) {
    int provider = fd_exec_provider(); if (provider) return provider;
    int cases = 0, successes = 0;
    for (int form = 0; form < 4; form++) {
        for (int policy = 0; policy < 6; policy++) {
            struct fd_exec_observation o;
            if (fl_fdexec_observe(fexecve, __errno_location, payload, jail, form, policy, 0, &o) != 0) return 11;
            int success = policy != 3 && policy != 5;
            printf("fexecve form=%d policy=%d status=%d returned=%d rc=%d errno=%d stage=%d flags=%d pos=%ld output=%s",
                   form, policy, o.status, o.returned, o.result, o.error, o.stage, o.flags, o.position, o.output);
            if (!*o.output) putchar('\n');
            if (o.stage || o.flags != !!(form & 1) || o.position != (form & 2 ? -1 : 7)) return 12;
            if (success) {
                if (o.status != (37 << 8) || o.returned || strcmp(o.output, "FD_EXEC_PAYLOAD_OK\n")) return 13;
                successes++;
            } else if (o.status || !o.returned || o.result != -1 || o.error != (policy == 3 ? EACCES : ENOSYS) || *o.output) return 14;
            cases++;
        }
    }
    if (cases != 24 || successes != 16) return 15;
    int errors = 0;
    for (int form = 0; form < 4; form++) for (int invalid = 1; invalid <= 4; invalid++) {
        struct fd_exec_observation o;
        if (fl_fdexec_observe(fexecve, __errno_location, payload, jail, form, 0, invalid, &o) != 0) return 16;
        printf("fexecve form=%d invalid=%d status=%d returned=%d rc=%d errno=%d stage=%d\n",
               form, invalid, o.status, o.returned, o.result, o.error, o.stage);
        if (o.stage || o.status || !o.returned || o.result != -1 || o.error != (invalid == 4 ? EBADF : EINVAL) || *o.output) return 17;
        if (o.flags != !!(form & 1) || o.position != (form & 2 ? -1 : 7)) return 18;
        errors++;
    }
    int at_successes = 0;
    for (int form = 0; form < 4; form++) for (int p = 0; p < 3; p++) {
        int policy = p == 2 ? 4 : p;
        struct fd_exec_observation o;
        if (fl_fdexec_observe(via_execveat, __errno_location, payload, jail, form, policy, 0, &o) != 0) return 19;
        printf("execveat form=%d policy=%d status=%d stage=%d output=%s", form, policy, o.status, o.stage, o.output);
        if (o.stage || o.status != (37 << 8) || o.returned || strcmp(o.output, "FD_EXEC_PAYLOAD_OK\n")) return 20;
        at_successes++;
    }
    printf("fd exec contract: %d fexecve cases, %d replacements, %d errors, %d execveat replacements passed\n", cases, successes, errors, at_successes);
    return errors == 16 && at_successes == 12 ? 0 : 21;
}

/* posix_spawn in one thread while another thread fork()s children that stay
   alive for a while. A spawn must not wait for those unrelated children: fl's
   spawn once reported exec failure through an O_CLOEXEC pipe whose write end
   the concurrent fork children inherited, so the parent's EOF waited ~300 ms
   for each of them (bd-vgvlej; glibc and fixed fl: ~1 ms). Also checks that a
   failed exec still reports ENOENT. */
extern char **environ;
static atomic_int stop;

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void *forker(void *arg) {
    (void)arg;
    while (!atomic_load(&stop)) {
        pid_t p = fork();
        if (p == 0) {
            usleep(300000); /* holds every fd the parent had at fork time */
            _exit(0);
        }
        if (p > 0) waitpid(p, NULL, 0);
    }
    return NULL;
}

int main(int argc, char **command_argv) {
    if (argc == 4 && strcmp(command_argv[1], "--fd-exec") == 0) return fd_exec_contract(command_argv[2], command_argv[3]);
    pthread_t t;
    pthread_create(&t, NULL, forker, NULL);
    double worst = 0;
    int failed = 0;
    for (int i = 0; i < 200; i++) {
        char *argv[] = {"/bin/true", NULL};
        pid_t pid;
        double t0 = now();
        int rc = posix_spawn(&pid, "/bin/true", NULL, NULL, argv, environ);
        double dt = now() - t0;
        if (rc != 0) failed++;
        else waitpid(pid, NULL, 0);
        if (dt > worst) worst = dt;
    }
    char *argv[] = {"/nonexistent", NULL};
    pid_t pid;
    int enoent = posix_spawn(&pid, "/nonexistent/prog", NULL, NULL, argv, environ);
    atomic_store(&stop, 1);
    pthread_join(t, NULL);
    printf("failed=%d slow_spawns=%s enoent_reported=%d\n", failed, worst > 0.2 ? "yes" : "no",
           enoent == 2);
    return 0;
}
#endif /* !FLC_FDEXEC_LIBRARY */
#endif /* !FLC_FDEXEC_STATIC_PAYLOAD */
