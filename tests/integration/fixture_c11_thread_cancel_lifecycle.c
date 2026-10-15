#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

/* Each invocation tests one process-isolated contract under a bounded timeout.
 * Unlike the sleep fixture, these workers use thrd_create's Rust trampoline. */
static atomic_int ready;
static atomic_int release_target;
static atomic_int cleaned;
static atomic_int destructed;
static atomic_int returned;
static tss_t key;
static int tls_value;
static thrd_t target;
static int join_result = 0x12345678;

static void check(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", what);
        exit(1);
    }
}

static void check_provider(void *symbol) {
    const char *library = getenv("FRANKENLIBC_TEST_LIBRARY");
    if (!library)
        return;
    Dl_info origin;
    struct stat actual, expected;
    check(dladdr(symbol, &origin) != 0, "locate C11 symbol provider");
    check(stat(origin.dli_fname, &actual) == 0 && stat(library, &expected) == 0,
          "stat C11 symbol provider");
    check(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino,
          "C11 symbol must bind to candidate, not host libc");
}

static void cleanup(void *unused) {
    (void)unused;
    atomic_fetch_add_explicit(&cleaned, 1, memory_order_relaxed);
}

static void destructor(void *value) {
    check(value == &tls_value, "thread-specific destructor value");
    atomic_fetch_add_explicit(&destructed, 1, memory_order_relaxed);
}

static void await_ready(void) {
    while (!atomic_load_explicit(&ready, memory_order_acquire))
        sched_yield();
}

static void queue_self_cancel(void) {
    check(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0, "disable cancellation");
    check(pthread_cancel(pthread_self()) == 0, "queue self cancellation");
    check(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0, "enable cancellation");
}

static int lifecycle_worker(void *arg) {
    const char *kind = arg;
    const struct timespec zero = {0, 0};
    const struct timespec delay = {30, 0};
    check(tss_set(key, &tls_value) == thrd_success, "set thread-specific value");
    pthread_cleanup_push(cleanup, NULL);
    if (strcmp(kind, "create-exit") == 0)
        thrd_exit(-37);
    if (strcmp(kind, "create-pthread-exit") == 0)
        pthread_exit((void *)(intptr_t)-37);
    if (strcmp(kind, "create-cancel-pending") == 0) {
        queue_self_cancel();
        (void)thrd_sleep(&zero, NULL);
    }
    if (strcmp(kind, "create-cancel-blocked") == 0) {
        atomic_store_explicit(&ready, 1, memory_order_release);
        (void)thrd_sleep(&delay, NULL);
    }
    atomic_store_explicit(&returned, 1, memory_order_release);
    pthread_cleanup_pop(0);
    return -37;
}

static void run_create_case(const char *kind) {
    thrd_t thread;
    int result = 123;
    check(tss_create(&key, destructor) == thrd_success, "create thread-specific key");
    check(thrd_create(&thread, lifecycle_worker, (void *)kind) == thrd_success, "thrd_create");
    if (strcmp(kind, "create-cancel-blocked") == 0) {
        await_ready();
        const struct timespec delay = {0, 5000000};
        (void)nanosleep(&delay, NULL);
        check(pthread_cancel((pthread_t)thread) == 0, "cancel C11 worker");
    }
    check(thrd_join(thread, &result) == thrd_success, "join C11 worker");
    const int canceled = strstr(kind, "cancel") != NULL;
    const int normal = strcmp(kind, "create-return") == 0;
    check(result == (canceled ? -1 : -37), "preserve exit or canceled result");
    check(atomic_load(&returned) == normal, "nonreturning worker must not fall through");
    check(atomic_load(&cleaned) == !normal, "cleanup handler runs exactly once on unwind");
    check(atomic_load(&destructed) == 1, "thread-specific destructor runs exactly once");
    tss_delete(key);
}

static int target_worker(void *unused) {
    (void)unused;
    while (!atomic_load_explicit(&release_target, memory_order_acquire))
        sched_yield();
    return 73;
}

static void *join_worker(void *arg) {
    const char *kind = arg;
    pthread_cleanup_push(cleanup, NULL);
    if (strcmp(kind, "join-pending") == 0)
        queue_self_cancel();
    atomic_store_explicit(&ready, 1, memory_order_release);
    (void)thrd_join(target, &join_result);
    atomic_store_explicit(&returned, 1, memory_order_release);
    pthread_cleanup_pop(0);
    return NULL;
}

static void run_join_case(const char *kind) {
    pthread_t joiner;
    void *result = NULL;
    check(thrd_create(&target, target_worker, NULL) == thrd_success, "create join target");
    check(pthread_create(&joiner, NULL, join_worker, (void *)kind) == 0, "create joiner");
    await_ready();
    if (strcmp(kind, "join-blocked") == 0) {
        const struct timespec delay = {0, 5000000};
        (void)nanosleep(&delay, NULL);
        check(pthread_cancel(joiner) == 0, "cancel blocked C11 join");
    }
    check(pthread_join(joiner, &result) == 0 && result == PTHREAD_CANCELED, "joiner cancellation");
    check(atomic_load(&cleaned) == 1 && atomic_load(&returned) == 0, "joiner unwound once");
    check(join_result == 0x12345678, "canceled join must not modify result output");
    atomic_store_explicit(&release_target, 1, memory_order_release);
    int target_result = 0;
    check(thrd_join(target, &target_result) == thrd_success && target_result == 73,
          "canceled join must leave target joinable");
}

int main(int argc, char **argv) {
    check(argc == 2, "one case name required");
    alarm(8);
    check_provider((void *)thrd_create);
    check_provider((void *)thrd_join);
    check_provider((void *)thrd_exit);
    check_provider((void *)thrd_sleep);
    if (strcmp(argv[1], "create-return") == 0 || strcmp(argv[1], "create-exit") == 0 ||
        strcmp(argv[1], "create-pthread-exit") == 0 || strcmp(argv[1], "create-cancel-pending") == 0 ||
        strcmp(argv[1], "create-cancel-blocked") == 0)
        run_create_case(argv[1]);
    else if (strcmp(argv[1], "join-pending") == 0 || strcmp(argv[1], "join-blocked") == 0)
        run_join_case(argv[1]);
    else
        check(0, "unknown case");
    alarm(0);
    printf("PASS %s\n", argv[1]);
    return 0;
}
