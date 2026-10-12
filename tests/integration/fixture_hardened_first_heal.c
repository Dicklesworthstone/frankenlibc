/* fixture_hardened_first_heal.c — first heal of a hardened process must not
 * deadlock (bd-rc0923-epic-eeuy4f.9).
 *
 * This fixture now covers three related startup/evidence regressions. Its first
 * repair attempt runs strlen(NULL) inside SIGUSR1, proving the sink was opened
 * and the signal-context probe installed before user code. A bounded memcpy
 * then requests more bytes than its tracked allocations contain, preserving
 * the original first-heal deadlock regression. Host glibc skips both invalid
 * probes and strict mode emits no repair rows. Invalid kill supplies one
 * deterministic semantic denial. Finally, the fixture rotates the runtime log
 * before fork: the child must reopen the current path rather than keep writing
 * through the parent's inherited open-file description. A final one-second
 * denial burst exhausts the production limiter and leaves the unthrottled
 * exit summary to report the exact suppressed-record count.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern int __frankenlibc_is_runtime_ready(void) __attribute__((weak));

static volatile sig_atomic_t signal_handler_seen;
static volatile sig_atomic_t signal_strlen_returned_zero;
static volatile sig_atomic_t signal_pthread_kill_returned_einval;

static void signal_strlen_probe(int signum) {
    (void)signum;
    size_t (*volatile strlen_fn)(const char *) = strlen;
    int (*volatile pthread_kill_fn)(pthread_t, int) = pthread_kill;
    const char *volatile null_string = NULL;
    size_t result = strlen_fn(null_string);
    int deny_result = pthread_kill_fn((pthread_t)0, -1);
    signal_strlen_returned_zero = result == 0;
    signal_pthread_kill_returned_einval = deny_result == EINVAL;
    signal_handler_seen = 1;
}

static int exercise_signal_time_repair(void) {
    /* Never expose the deliberate NULL call to host glibc. Both FrankenLibC
     * modes run the same trampoline: strict returns the ABI fallback without
     * repair evidence; hardened must emit one signal-safe repair row. */
    if (!__frankenlibc_is_runtime_ready)
        return 0;
    if (!__frankenlibc_is_runtime_ready())
        return 13;

    struct sigaction action;
    struct sigaction previous;
    memset(&action, 0, sizeof(action));
    action.sa_handler = signal_strlen_probe;
    if (sigemptyset(&action.sa_mask) != 0)
        return 14;
    if (sigaction(SIGUSR1, &action, &previous) != 0)
        return 15;

    signal_handler_seen = 0;
    signal_strlen_returned_zero = 0;
    signal_pthread_kill_returned_einval = 0;
    if (raise(SIGUSR1) != 0)
        return 16;
    if (!signal_handler_seen)
        return 17;
    if (!signal_strlen_returned_zero)
        return 18;
    if (!signal_pthread_kill_returned_einval)
        return 20;
    if (sigaction(SIGUSR1, &previous, NULL) != 0)
        return 19;
    return 0;
}

static int induce_hardened_bounds_repair(void) {
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (!__frankenlibc_is_runtime_ready || !__frankenlibc_is_runtime_ready() || mode == NULL ||
        strcmp(mode, "hardened") != 0)
        return 0;

    unsigned char *src = malloc(8), *dst = malloc(8);
    if (src == NULL || dst == NULL) {
        free(src);
        free(dst);
        return 3;
    }
    memset(src, 'R', 8);
    memset(dst, 0, 8);

    /* Prevent the compiler from replacing this test of the interposed ABI
     * entrypoint with an inline builtin copy. */
    void *(*volatile copy_fn)(void *, const void *, size_t) = memcpy;
    void *ret = copy_fn(dst, src, 32);
    int failed = ret != dst;
    for (size_t i = 0; i < 8; i++)
        failed |= dst[i] != 'R';
    free(dst);
    free(src);
    return failed ? 4 : 0;
}

static int invalid_signal_is_denied(void) {
    errno = 0;
    return kill(getpid(), -1) == -1 && errno == EINVAL ? 0 : 2;
}

enum { RATE_LIMIT_ATTEMPTS = 1100 };

static int exercise_runtime_log_rate_limit(void) {
    const char *log_path = getenv("FRANKENLIBC_LOG");
    if (!__frankenlibc_is_runtime_ready || !__frankenlibc_is_runtime_ready() ||
        log_path == NULL || log_path[0] == '\0')
        return 0;

    /* Begin immediately after a monotonic-second transition so every denial
     * competes for one fresh production rate window. Crossing another second
     * makes the probe inconclusive and is a hard fixture failure. */
    struct timespec before;
    struct timespec start;
    struct timespec finish;
    if (clock_gettime(CLOCK_MONOTONIC, &before) != 0)
        return 21;
    do {
        if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
            return 21;
    } while (start.tv_sec == before.tv_sec);

    for (int attempt = 0; attempt < RATE_LIMIT_ATTEMPTS; attempt++) {
        if (invalid_signal_is_denied() != 0)
            return 22;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &finish) != 0)
        return 21;
    return finish.tv_sec == start.tv_sec ? 0 : 23;
}

static int exercise_runtime_log_fork_reopen(void) {
    const char *log_path = getenv("FRANKENLIBC_LOG");
    if (!__frankenlibc_is_runtime_ready || !__frankenlibc_is_runtime_ready() ||
        log_path == NULL || log_path[0] == '\0')
        return 0;

    /* Append a normal denial before rotation so the parent demonstrably owns
     * and uses the startup-opened descriptor for the old inode. */
    if (invalid_signal_is_denied() != 0)
        return 5;

    static const char suffix[] = ".pre_fork";
    size_t path_len = strlen(log_path);
    if (path_len + sizeof(suffix) > PATH_MAX)
        return 6;
    char before_fork[PATH_MAX];
    memcpy(before_fork, log_path, path_len);
    memcpy(before_fork + path_len, suffix, sizeof(suffix));

    if (rename(log_path, before_fork) != 0)
        return 7;
    int replacement = open(log_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (replacement < 0)
        return 8;
    if (close(replacement) != 0)
        return 9;

    pid_t child = fork();
    if (child < 0)
        return 10;
    if (child == 0) {
        int rc = induce_hardened_bounds_repair();
        if (rc == 0)
            rc = invalid_signal_is_denied();
        /* exit(), rather than _exit(), is intentional: the child's DSO fini
         * hook must append its exit_summary through the reopened sink. */
        exit(rc);
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child)
        return 11;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 12;
    return 0;
}

int main(void) {
    /* This must be the first repair attempt: it proves constructor-time sink
     * setup rather than succeeding because a normal call primed the logger. */
    int repair_rc = exercise_signal_time_repair();
    if (repair_rc != 0)
        return repair_rc;

    repair_rc = induce_hardened_bounds_repair();
    if (repair_rc != 0)
        return repair_rc;

    repair_rc = exercise_runtime_log_fork_reopen();
    if (repair_rc != 0)
        return repair_rc;

    /* Host glibc and callers without FRANKENLIBC_LOG skip the fork probe but
     * still exercise the harmless invalid-signal contract. */
    if (invalid_signal_is_denied() != 0)
        return 2;

    repair_rc = exercise_runtime_log_rate_limit();
    if (repair_rc != 0)
        return repair_rc;

    char *b = malloc(120);
    if (b == NULL) return 1;
    memset(b, 'z', 120);
    memcpy(b, "alpha one\n", 10);
    long sum = 0;
    for (size_t n = 1; n <= 120; n += 7) {
        char *p = memchr(b, 'a', n), *q = memrchr(b, 'a', n), *r = memchr(b, '\n', n);
        sum += (p ? p - b : -1) + (q ? q - b : -1) + (r ? r - b : -1);
    }
    printf("fixture_hardened_first_heal: sum=%ld\n", sum);
    free(b);
    return 0;
}
