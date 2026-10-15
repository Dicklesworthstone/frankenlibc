#define _GNU_SOURCE
#include <aio.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

_Static_assert(offsetof(struct aiocb, aio_sigevent) == 32, "LP64 aiocb event");
_Static_assert(offsetof(struct aiocb, aio_offset) == 128, "LP64 aiocb offset");
_Static_assert(offsetof(struct sigevent, sigev_notify_function) == 16, "event function");
_Static_assert(offsetof(struct sigevent, sigev_notify_attributes) == 24, "event attributes");

static const char payload[] = "completion-notification";
static sigset_t notifications;
static atomic_int callbacks, cleaned, ready, returned;
static int waiter_rc, waiter_errno;
static struct aiocb requests[2];
static struct aiocb *wait_list[] = {&requests[0]};
static char buffers[2][64];
static int pipes[2][2];
static int use_lio, use_large, test_cancellation;
static size_t requested_stack;

static void check(int ok, const char *message) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
        _Exit(1); /* Never free a request that a worker may still own. */
    }
}

static void provider(void *symbol) {
    const char *library = getenv("FRANKENLIBC_TEST_LIBRARY");
    if (!library) return;
    Dl_info info;
    struct stat actual, expected;
    check(dladdr(symbol, &info) != 0, "resolve AIO provider");
    check(stat(info.dli_fname, &actual) == 0 && stat(library, &expected) == 0,
          "stat AIO provider");
    check(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino,
          "AIO entry must bind to candidate");
}

static void pause_briefly(void) {
    const struct timespec delay = {0, 1000000};
    (void)nanosleep(&delay, NULL);
}

static void await_count(atomic_int *counter, int expected) {
    while (atomic_load_explicit(counter, memory_order_acquire) != expected)
        pause_briefly();
}

static void setup_request(int i) {
    check(pipe(pipes[i]) == 0, "pipe");
    memset(&requests[i], 0, sizeof(requests[i]));
    requests[i].aio_fildes = pipes[i][0];
    requests[i].aio_lio_opcode = LIO_READ;
    requests[i].aio_buf = buffers[i];
    requests[i].aio_nbytes = sizeof(payload);
    requests[i].aio_offset = 7; /* A real nonzero offset; streams ignore it. */
    requests[i].aio_sigevent.sigev_notify = SIGEV_NONE;
}

static void complete_request(int i) {
    check(write(pipes[i][1], payload, sizeof(payload)) == (ssize_t)sizeof(payload), "release AIO read");
}

static void reap_request(int i) {
    while (aio_error(&requests[i]) == EINPROGRESS) pause_briefly();
    check(aio_error(&requests[i]) == 0, "successful AIO status");
    check(aio_return(&requests[i]) == (ssize_t)sizeof(payload), "successful AIO count");
    check(memcmp(buffers[i], payload, sizeof(payload)) == 0, "exact AIO bytes");
}

static struct sigevent signal_notice(void *value) {
    struct sigevent event;
    memset(&event, 0, sizeof(event));
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = SIGRTMIN;
    event.sigev_value.sival_ptr = value;
    return event;
}

static void receive_notice(void *value) {
    siginfo_t info;
    const struct timespec timeout = {2, 0};
    check(sigtimedwait(&notifications, &info, &timeout) == SIGRTMIN, "completion signal arrives");
    check(info.si_code == SI_ASYNCIO, "completion signal has SI_ASYNCIO");
    check(info.si_value.sival_ptr == value, "completion signal payload");
    check(info.si_pid == getpid() && info.si_uid == getuid(), "completion signal sender");
}

static void no_notice(void) {
    const struct timespec zero = {0, 0};
    errno = 0;
    check(sigtimedwait(&notifications, NULL, &zero) == -1 && errno == EAGAIN,
          "no premature or duplicate notification");
}

static void signal_case(int fail) {
    setup_request(0);
    requests[0].aio_sigevent = signal_notice(&requests[0]);
    if (fail) requests[0].aio_fildes = -1;
    check(aio_read(&requests[0]) == 0, "enqueue signaled read");
    if (!fail) {
        check(aio_error(&requests[0]) == EINPROGRESS, "empty pipe stays in progress");
        no_notice();
        complete_request(0);
    }
    receive_notice(&requests[0]);
    if (fail) {
        check(aio_error(&requests[0]) == EBADF, "failed AIO retains syscall errno");
        check(aio_return(&requests[0]) == -1, "failed AIO result");
    } else reap_request(0);
    no_notice();
}

static void callback_cleanup(void *ignored) {
    (void)ignored;
    atomic_fetch_add_explicit(&cleaned, 1, memory_order_release);
}

struct callback_request { struct aiocb cb; char data[64]; int exits; };
static void request_callback(union sigval value) {
    struct callback_request *request = value.sival_ptr;
    check(aio_error(&request->cb) == 0, "callback observes published result");
    check(aio_return(&request->cb) == (ssize_t)sizeof(payload), "callback can reap request");
    check(memcmp(request->data, payload, sizeof(payload)) == 0, "callback sees completed bytes");
    if (requested_stack) {
        pthread_attr_t actual;
        size_t size;
        int state;
        check(pthread_getattr_np(pthread_self(), &actual) == 0, "get callback thread attributes");
        check(pthread_attr_getstacksize(&actual, &size) == 0 && size == requested_stack,
              "notification uses requested stack size");
        check(pthread_attr_getdetachstate(&actual, &state) == 0 && state == PTHREAD_CREATE_DETACHED,
              "notification thread is detached before user code");
        check(pthread_attr_destroy(&actual) == 0, "destroy observed attributes");
    }
    const int exits = request->exits;
    free(request); /* The completion implementation must never touch it again. */
    atomic_fetch_add_explicit(&callbacks, 1, memory_order_release);
    pthread_cleanup_push(callback_cleanup, NULL);
    if (exits) pthread_exit(NULL);
    pthread_cleanup_pop(1);
}

static void thread_case(int exits) {
    int descriptors[2];
    check(pipe(descriptors) == 0, "callback pipe");
    struct callback_request *request = calloc(1, sizeof(*request));
    check(request != NULL, "allocate callback request");
    request->cb.aio_fildes = descriptors[0];
    request->cb.aio_buf = request->data;
    request->cb.aio_nbytes = sizeof(payload);
    request->cb.aio_sigevent.sigev_notify = SIGEV_THREAD;
    request->cb.aio_sigevent.sigev_notify_function = request_callback;
    request->cb.aio_sigevent.sigev_value.sival_ptr = request;
    request->exits = exits;
    pthread_attr_t attributes;
    requested_stack = 256 * 1024;
    check(pthread_attr_init(&attributes) == 0, "init callback attributes");
    check(pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) == 0, "set callback detached");
    check(pthread_attr_setstacksize(&attributes, requested_stack) == 0, "set callback stack");
    request->cb.aio_sigevent.sigev_notify_attributes = &attributes;
    check(aio_read(&request->cb) == 0, "enqueue callback read");
    check(atomic_load(&callbacks) == 0, "callback waits for I/O");
    check(write(descriptors[1], payload, sizeof(payload)) == (ssize_t)sizeof(payload), "release callback read");
    await_count(&cleaned, 1);
    check(atomic_load(&callbacks) == 1, "callback runs exactly once");
    check(pthread_attr_destroy(&attributes) == 0, "release callback attributes");
}

static void batch_callback(union sigval value) {
    check(value.sival_ptr == requests, "batch callback payload");
    check(aio_error(&requests[0]) == 0 && aio_error(&requests[1]) == 0,
          "batch callback sees every I/O complete");
    atomic_fetch_add_explicit(&callbacks, 1, memory_order_release);
}

static void exiting_item_callback(union sigval value) {
    check(value.sival_ptr == requests, "item callback payload");
    check(aio_error(&requests[0]) == 0, "item completed before callback");
    atomic_fetch_add_explicit(&cleaned, 1, memory_order_release);
    pthread_exit(NULL); /* Must not strand batch bookkeeping. */
}

static void batch_case(int threaded) {
    setup_request(0); setup_request(1);
    struct aiocb nop;
    memset(&nop, 0xa5, sizeof(nop)); nop.aio_lio_opcode = LIO_NOP;
    struct aiocb *list[] = {&requests[0], NULL, &nop, &requests[1]};
    struct sigevent event = signal_notice(requests);
    if (threaded) {
        event.sigev_notify = SIGEV_THREAD;
        event.sigev_notify_function = batch_callback;
        requests[0].aio_sigevent.sigev_notify = SIGEV_THREAD;
        requests[0].aio_sigevent.sigev_notify_function = exiting_item_callback;
        requests[0].aio_sigevent.sigev_value.sival_ptr = requests;
    }
    check(lio_listio(LIO_NOWAIT, list, 4, &event) == 0, "enqueue batch");
    /* Event storage, unlike the request list, is not used after submission. */
    memset(&event, 0xa5, sizeof(event));
    complete_request(0);
    while (aio_error(&requests[0]) == EINPROGRESS) pause_briefly();
    if (threaded) { await_count(&cleaned, 1); check(atomic_load(&callbacks) == 0, "batch waits for last request"); }
    else no_notice();
    check(aio_error(&requests[1]) == EINPROGRESS, "second request still pending");
    complete_request(1);
    if (threaded) await_count(&callbacks, 1); else receive_notice(requests);
    reap_request(0); reap_request(1);
    if (!threaded) no_notice();
}

static void empty_case(void) {
    struct sigevent event = signal_notice(&event);
    struct aiocb *empty[] = {NULL, NULL};
    check(lio_listio(LIO_NOWAIT, empty, 0, &event) == 0, "empty batch succeeds");
    receive_notice(&event); no_notice();
    check(aio_suspend((const struct aiocb *const *)empty, 0, NULL) == 0, "empty suspend returns immediately");
    check(aio_suspend((const struct aiocb *const *)empty, 2, NULL) == 0, "all-null suspend returns immediately");
    check(lio_listio(LIO_WAIT, empty, 0, (struct sigevent *)(uintptr_t)1) == 0,
          "LIO_WAIT ignores notification pointer");
}

static void errors_case(void) {
    setup_request(0); setup_request(1);
    requests[0].aio_fildes = -1;
    complete_request(1);
    struct aiocb *list[] = {&requests[0], &requests[1]};
    errno = 0;
    check(lio_listio(LIO_WAIT, list, 2, NULL) == -1 && errno == EIO, "LIO_WAIT reports failed member");
    check(aio_error(&requests[0]) == EBADF && aio_return(&requests[0]) == -1, "individual failure retained");
    reap_request(1);
    struct aiocb invalid;
    memset(&invalid, 0, sizeof(invalid));
    errno = 0;
    check(aio_fsync(0, &invalid) == -1 && errno == EINVAL, "invalid aio_fsync operation rejected");
}

static void signal_handler(int signo) { (void)signo; }

static void *waiter(void *arg) {
    const int pending_cancel = (int)(intptr_t)arg;
    pthread_cleanup_push(callback_cleanup, NULL);
    if (pending_cancel) {
        check(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0, "disable waiter cancellation");
        check(pthread_cancel(pthread_self()) == 0, "queue waiter cancellation");
        check(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0, "enable waiter cancellation");
    }
    atomic_store_explicit(&ready, 1, memory_order_release);
    errno = 0;
    if (use_lio) {
        waiter_rc = use_large ? lio_listio64(LIO_WAIT, (struct aiocb64 *const *)wait_list, 1, NULL)
                              : lio_listio(LIO_WAIT, wait_list, 1, NULL);
    } else {
        const struct aiocb *list[] = {&requests[0]};
        waiter_rc = use_large ? aio_suspend64((const struct aiocb64 *const *)list, 1, NULL)
                              : aio_suspend(list, 1, NULL);
    }
    waiter_errno = errno;
    atomic_store_explicit(&returned, 1, memory_order_release);
    /* Unlike aio_suspend, glibc declares list I/O noexcept. Pending deferred
     * cancellation must survive it and act at the next explicit point. */
    if (use_lio && test_cancellation) pthread_testcancel();
    pthread_cleanup_pop(0);
    return NULL;
}

static void wait_case(int cancel, int pending) {
    test_cancellation = cancel;
    setup_request(0);
    if (!use_lio) check(aio_read(&requests[0]) == 0, "enqueue suspend request");
    struct sigaction action;
    memset(&action, 0, sizeof(action)); action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    check(sigaction(SIGUSR1, &action, NULL) == 0, "install interrupting handler");
    pthread_t thread;
    check(pthread_create(&thread, NULL, waiter, (void *)(intptr_t)pending) == 0, "create waiter");
    await_count(&ready, 1);
    if (cancel && !pending) {
        while (aio_error(&requests[0]) != EINPROGRESS) pause_briefly();
        check(pthread_cancel(thread) == 0, "cancel blocked waiter");
    } else if (!cancel) {
        /* Repeated directed signals avoid depending on a guessed sleep to
         * prove that at least one signal hits the actual kernel wait. */
        while (!atomic_load_explicit(&returned, memory_order_acquire)) {
            check(pthread_kill(thread, SIGUSR1) == 0, "interrupt waiter");
            pause_briefly();
        }
    }
    if (cancel && use_lio) complete_request(0);
    void *result;
    check(pthread_join(thread, &result) == 0, "join waiter");
    if (cancel) {
        check(result == PTHREAD_CANCELED && atomic_load(&cleaned) == 1, "wait cancellation runs cleanup");
        check(atomic_load(&returned) == use_lio, "only aio_suspend is a cancellation point");
    } else check(waiter_rc == -1 && waiter_errno == EINTR, "wait returns EINTR on ordinary signal");
    if (!cancel || !use_lio) {
        check(aio_error(&requests[0]) == EINPROGRESS, "ending wait does not cancel I/O");
        complete_request(0);
    }
    reap_request(0);
}

static void timeout_case(void) {
    setup_request(0); check(aio_read(&requests[0]) == 0, "enqueue timed request");
    const struct aiocb *list[] = {&requests[0]};
    const struct timespec timeout = {0, 30000000};
    struct timespec before, after;
    check(clock_gettime(CLOCK_MONOTONIC, &before) == 0, "clock before timeout");
    errno = 0;
    check(aio_suspend(list, 1, &timeout) == -1 && errno == EAGAIN, "suspend deadline expires");
    check(clock_gettime(CLOCK_MONOTONIC, &after) == 0, "clock after timeout");
    const int64_t elapsed = (after.tv_sec-before.tv_sec)*INT64_C(1000000000) + after.tv_nsec-before.tv_nsec;
    check(elapsed >= 25000000 && elapsed < INT64_C(2000000000), "relative timeout remains bounded");
    complete_request(0); reap_request(0);
}

int main(int argc, char **argv) {
    check(argc == 2, "one case required"); alarm(8);
    provider((void *)aio_read); provider((void *)aio_error); provider((void *)aio_return);
    provider((void *)aio_suspend); provider((void *)lio_listio);
    provider((void *)aio_fsync); provider((void *)lio_listio64); provider((void *)aio_suspend64);
    sigemptyset(&notifications); sigaddset(&notifications, SIGRTMIN);
    check(pthread_sigmask(SIG_BLOCK, &notifications, NULL) == 0, "block completion signal before workers exist");
    const char *name = argv[1];
    use_lio = strncmp(name, "list", 4) == 0;
    use_large = strstr(name, "64") != NULL;
    if (strcmp(name, "signal-read") == 0) signal_case(0);
    else if (strcmp(name, "signal-error") == 0) signal_case(1);
    else if (strcmp(name, "thread-return") == 0) thread_case(0);
    else if (strcmp(name, "thread-exit") == 0) thread_case(1);
    else if (strcmp(name, "batch-signal") == 0) batch_case(0);
    else if (strcmp(name, "batch-thread") == 0) batch_case(1);
    else if (strcmp(name, "empty") == 0) empty_case();
    else if (strcmp(name, "errors") == 0) errors_case();
    else if (strcmp(name, "timeout") == 0) timeout_case();
    else if (strstr(name, "signal")) wait_case(0, 0);
    else if (strstr(name, "pending")) wait_case(1, 1);
    else if (strstr(name, "cancel")) wait_case(1, 0);
    else check(0, "unknown case");
    alarm(0); printf("PASS %s\n", name); return 0;
}
