#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

/* Run each case in a fresh process. A missed cancellation must fail by timeout,
 * not leave the fixture suite hanging. No test relies on external DNS or files.
 * Deliberately use pthread-created threads here to isolate thrd_sleep from the
 * independent C11 start-trampoline/exit/join unwind boundaries. */
static atomic_int ready;
static atomic_int cleaned;
static atomic_int returned;
static int worker_result;
static int worker_errno;
static int worker_type;
static struct timespec worker_remaining;
static volatile sig_atomic_t signal_seen;
static char normal_return;

static void check(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", what);
        exit(1);
    }
}

static void cleanup(void *unused) {
    (void)unused;
    atomic_fetch_add_explicit(&cleaned, 1, memory_order_relaxed);
}

static void signal_handler(int signo) {
    (void)signo;
    signal_seen = 1;
}

static void pause_briefly(void) {
    const struct timespec delay = {0, 5000000};
    (void)nanosleep(&delay, NULL);
}

static void await_ready(void) {
    while (!atomic_load_explicit(&ready, memory_order_acquire))
        sched_yield();
}

static void *sleep_worker(void *arg) {
    const char *kind = arg;
    struct timespec delay = {30, 0};
    pthread_cleanup_push(cleanup, NULL);
    if (strcmp(kind, "sleep-pending") == 0 || strcmp(kind, "sleep-disabled") == 0) {
        check(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0, "disable cancellation");
        check(pthread_cancel(pthread_self()) == 0, "queue cancellation");
        delay.tv_sec = 0;
        if (strcmp(kind, "sleep-pending") == 0)
            check(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0, "enable cancellation");
    }
    errno = EDOM;
    atomic_store_explicit(&ready, 1, memory_order_release);
    worker_result = thrd_sleep(&delay, &worker_remaining);
    worker_errno = errno;
    atomic_store_explicit(&returned, 1, memory_order_release);
    if (strcmp(kind, "sleep-disabled") == 0) {
        check(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &worker_type) == 0, "query restored type");
        check(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0, "reenable cancellation");
        pthread_testcancel();
    }
    pthread_cleanup_pop(0);
    return &normal_return;
}

static void run_sleep_case(const char *kind) {
    pthread_t thread;
    void *result = NULL;
    check(pthread_create(&thread, NULL, sleep_worker, (void *)kind) == 0, "pthread_create");
    await_ready();
    if (strcmp(kind, "sleep-blocked") == 0) {
        pause_briefly();
        check(pthread_cancel(thread) == 0, "cancel sleeping thread");
    } else if (strcmp(kind, "sleep-signal") == 0) {
        /* Retry so delivery just before entry cannot lose the wakeup. */
        while (!atomic_load_explicit(&returned, memory_order_acquire)) {
            check(pthread_kill(thread, SIGUSR1) == 0, "interrupt sleep");
            pause_briefly();
        }
    }
    check(pthread_join(thread, &result) == 0, "pthread_join");
    if (strcmp(kind, "sleep-signal") == 0) {
        check(result == &normal_return, "signal must not cancel");
        check(worker_result == -1 && signal_seen, "thrd_sleep interrupted result");
        check(worker_errno == EDOM, "thrd_sleep preserves errno on interruption");
        check(worker_remaining.tv_sec >= 0 && worker_remaining.tv_sec <= 30 &&
              worker_remaining.tv_nsec >= 0 && worker_remaining.tv_nsec < 1000000000L &&
              (worker_remaining.tv_sec || worker_remaining.tv_nsec), "remaining duration");
        check(atomic_load(&cleaned) == 0, "ordinary interruption does not run cleanup");
    } else {
        check(result == PTHREAD_CANCELED, "thread must be canceled rather than return");
        check(atomic_load(&cleaned) == 1, "cancellation runs cleanup exactly once");
        if (strcmp(kind, "sleep-disabled") == 0) {
            check(atomic_load(&returned) == 1 && worker_result == 0, "disabled sleep completes");
            check(worker_type == PTHREAD_CANCEL_DEFERRED, "cancel type restored");
            check(worker_errno == EDOM, "successful sleep preserves errno");
        } else {
            check(atomic_load(&returned) == 0, "cancellation must not return from sleep");
        }
    }
}

static void run_sleep_values(void) {
    const struct timespec zero = {0, 0};
    const struct timespec bad_nsec = {0, 1000000000L};
    const struct timespec bad_sec = {-1, 0};
    errno = EDOM;
    check(thrd_sleep(&zero, NULL) == 0 && errno == EDOM, "zero duration and null remaining");
    check(thrd_sleep(&bad_nsec, NULL) == -2 && errno == EDOM, "invalid nanoseconds");
    check(thrd_sleep(&bad_sec, NULL) == -2 && errno == EDOM, "negative seconds");
}

int main(int argc, char **argv) {
    check(argc == 2, "one case name required");
    const char *library = getenv("FRANKENLIBC_TEST_LIBRARY");
    if (library) {
        Dl_info origin;
        struct stat actual, expected;
        check(dladdr((void *)thrd_sleep, &origin) != 0, "locate thrd_sleep provider");
        check(stat(origin.dli_fname, &actual) == 0 && stat(library, &expected) == 0,
              "stat thrd_sleep provider");
        check(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino,
              "thrd_sleep must bind to the candidate, not host libc");
    }
    alarm(8);
    struct sigaction action = {0};
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    check(sigaction(SIGUSR1, &action, NULL) == 0, "install signal handler");
    if (strcmp(argv[1], "sleep-values") == 0)
        run_sleep_values();
    else if (strcmp(argv[1], "sleep-pending") == 0 || strcmp(argv[1], "sleep-blocked") == 0 ||
             strcmp(argv[1], "sleep-disabled") == 0 || strcmp(argv[1], "sleep-signal") == 0)
        run_sleep_case(argv[1]);
    else
        check(0, "unknown case");
    alarm(0);
    printf("PASS %s\n", argv[1]);
    return 0;
}
