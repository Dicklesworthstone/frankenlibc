/* Signals aimed at the main thread, and semaphore waits they interrupt.
 *
 * Found with CPython 3.14's test suite under fl:
 * - pthread_kill(main, sig) from another thread returned ESRCH, and
 *   pthread_sigqueue returned 301: fl's main thread has its tid as its
 *   pthread_t, and only the main thread itself could resolve it
 *   (test_wsgiref's signal.pthread_kill(main_thread, SIGUSR1)).
 * - sem_clockwait restarted after a signal handler instead of failing with
 *   EINTR, so CPython's lock.acquire(timeout=5) ignored SIGALRM for the
 *   full 5 s (test_threadsignals).
 * Output is compared byte-for-byte with glibc; durations only as
 * "interrupted" (< 1 s) or "waited".
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static pthread_t main_thread;
static volatile sig_atomic_t got;

static void handler(int sig) { got = sig; }

static void *signal_main(void *arg) {
    (void)arg;
    printf("pthread_kill(main, SIGUSR1) = %d\n", pthread_kill(main_thread, SIGUSR1));
    printf("pthread_kill(main, 0) = %d\n", pthread_kill(main_thread, 0));
    union sigval v = {.sival_int = 7};
    printf("pthread_sigqueue(main, SIGUSR1) = %d\n", pthread_sigqueue(main_thread, SIGUSR1, v));
    return NULL;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

/* Run before creating peers so a process-directed signal can only be consumed
 * by this blocked main thread. The kernel and public C siginfo_t accessors are
 * the oracle for the sender identity, independent of our encoding helper. */
static int queued_signals(const char *expected_library) {
    if (expected_library != NULL) {
        char expected[PATH_MAX];
        if (realpath(expected_library, expected) == NULL) {
            perror("queued signals expected library");
            return 1;
        }
        const char *names[] = {"sigqueue", "pthread_sigqueue"};
        const void *functions[] = {(const void *)sigqueue, (const void *)pthread_sigqueue};
        for (size_t i = 0; i < sizeof functions / sizeof functions[0]; i++) {
            Dl_info provider;
            char actual[PATH_MAX];
            if (dladdr(functions[i], &provider) == 0 || provider.dli_fname == NULL ||
                realpath(provider.dli_fname, actual) == NULL || strcmp(actual, expected) != 0) {
                fprintf(stderr, "queued signals: %s is not supplied by expected library\n", names[i]);
                return 1;
            }
        }
    }

    const int signum = SIGRTMIN;
    sigset_t set, previous;
    if (sigemptyset(&set) != 0 || sigaddset(&set, signum) != 0 ||
        sigprocmask(SIG_BLOCK, &set, &previous) != 0) {
        perror("queued signals block");
        return 1;
    }
    const pid_t sender_pid = getpid();
    const uid_t sender_uid = getuid();
    int token = 17;
    union sigval value = {.sival_ptr = &token};
    int failed = 0;
    for (int thread_directed = 0; thread_directed < 2; thread_directed++) {
        const char *name = thread_directed ? "pthread_sigqueue" : "sigqueue";
        errno = E2BIG;
        int rc = thread_directed ? pthread_sigqueue(pthread_self(), signum, value)
                                 : sigqueue(sender_pid, signum, value);
        int send_errno = errno;
        if (rc != 0) {
            fprintf(stderr, "%s: queue failed rc=%d errno=%d\n", name, rc, send_errno);
            failed = 1;
            break;
        }
        siginfo_t info;
        memset(&info, 0, sizeof info);
        struct timespec timeout = {.tv_sec = 5, .tv_nsec = 0};
        int received = sigtimedwait(&set, &info, &timeout);
        if (received != signum || info.si_signo != signum || info.si_code != SI_QUEUE ||
            info.si_errno != 0 || info.si_pid != sender_pid || info.si_uid != sender_uid ||
            info.si_value.sival_ptr != value.sival_ptr || send_errno != E2BIG) {
            fprintf(stderr,
                    "%s: metadata mismatch received=%d signo=%d code=%d pid=%ld/%ld "
                    "uid=%lu/%lu value=%p/%p send_errno=%d info_errno=%d\n",
                    name, received, info.si_signo, info.si_code, (long)info.si_pid,
                    (long)sender_pid, (unsigned long)info.si_uid, (unsigned long)sender_uid,
                    info.si_value.sival_ptr, value.sival_ptr, send_errno, info.si_errno);
            failed = 1;
            break;
        }
    }
    if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0) {
        perror("queued signals restore");
        return 1;
    }
    if (!failed)
        puts("queued signals: process and thread preserve sender identity and pointer payload");
    return failed;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--queued-signals") == 0) {
        if (argc > 3) return 2;
        return queued_signals(argc == 3 ? argv[2] : NULL);
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGUSR1, handler);
    main_thread = pthread_self();
    pthread_t t;
    pthread_create(&t, NULL, signal_main, NULL);
    pthread_join(t, NULL);
    printf("main received signal %d\n", (int)got);

    for (int restart = 0; restart < 2; restart++) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = handler;
        sa.sa_flags = restart ? SA_RESTART : 0;
        sigaction(SIGALRM, &sa, NULL);
        sem_t s;
        sem_init(&s, 0, 0);
        const char *names[] = {"sem_wait", "sem_timedwait", "sem_clockwait(MONOTONIC)",
                               "sem_clockwait(REALTIME)"};
        /* sem_wait under SA_RESTART restarts forever (signal(7)): skipped. */
        for (int k = restart; k < 4; k++) {
            clockid_t clock = k == 2 ? CLOCK_MONOTONIC : CLOCK_REALTIME;
            struct timespec deadline;
            clock_gettime(clock, &deadline);
            deadline.tv_sec += 2;
            ualarm(200000, 0);
            double t0 = now();
            errno = 0;
            int r = k == 0   ? sem_wait(&s)
                    : k == 1 ? sem_timedwait(&s, &deadline)
                             : sem_clockwait(&s, clock, &deadline);
            int e = errno;
            printf("SA_RESTART=%d %s: r=%d errno=%s %s\n", restart, names[k], r,
                   e == EINTR ? "EINTR" : e == ETIMEDOUT ? "ETIMEDOUT" : "other",
                   now() - t0 < 1.0 ? "interrupted" : "waited");
        }
        sem_destroy(&s);
    }
    return 0;
}
