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
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
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

int main(void) {
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
