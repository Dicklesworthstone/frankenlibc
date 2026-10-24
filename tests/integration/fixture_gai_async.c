#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(struct gaicb) == 56, "Linux LP64 gaicb size");
_Static_assert(offsetof(struct gaicb, ar_result) == 24, "gaicb result offset");
_Static_assert(offsetof(struct gaicb, __return) == 32, "gaicb error offset");
_Static_assert(SI_ASYNCNL == -60, "GNU resolver signal code");

static void fail(const char *expression, int line) {
    fprintf(stderr, "FAIL line %d: %s (errno=%d)\n", line, expression, errno);
    _Exit(1);
}
#define CHECK(expr) do { if (!(expr)) fail(#expr, __LINE__); } while (0)
static atomic_int notices, cleanups;

static void pause_ms(long ms) {
    struct timespec delay = {ms / 1000, ms % 1000 * 1000000};
    while (nanosleep(&delay, &delay) && errno == EINTR) {}
}

static void provider(void *symbol) {
    const char *wanted = getenv("FRANKENLIBC_TEST_LIBRARY");
    if (!wanted) return;
    Dl_info info;
    struct stat actual, expected;
    CHECK(dladdr(symbol, &info) && stat(info.dli_fname, &actual) == 0 && stat(wanted, &expected) == 0);
    if (actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino) {
        fprintf(stderr, "FAIL provider mismatch\n");
        _Exit(1);
    }
}

static struct addrinfo hint(int family) {
    struct addrinfo h = {0};
    h.ai_family = family;
    h.ai_socktype = SOCK_STREAM;
    h.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    return h;
}

static void init(struct gaicb *cb, const char *name, const struct addrinfo *h) {
    memset(cb, 0, sizeof(*cb));
    cb->ar_name = name;
    cb->ar_service = "43127";
    cb->ar_request = h;
}

static void wait_cb(struct gaicb *cb) {
    const struct gaicb *list[] = {cb};
    const struct timespec timeout = {3, 0};
    for (int tries = 0; gai_error(cb) == EAI_INPROGRESS; ++tries) {
        CHECK(tries < 1000);
        int rc = gai_suspend(list, 1, &timeout);
        CHECK(rc == 0 || rc == EAI_ALLDONE || rc == EAI_INTR);
    }
}

static void verify(struct gaicb *cb, int family, const char *text) {
    CHECK(gai_error(cb) == 0);
    struct addrinfo *ai = cb->ar_result;
    CHECK(ai != NULL);
    int count = 0;
    for (; ai; ai = ai->ai_next) {
        CHECK(++count < 8 && ai->ai_family == family && ai->ai_socktype == SOCK_STREAM);
        unsigned char expected[16];
        CHECK(inet_pton(family, text, expected) == 1);
        if (family == AF_INET) {
            struct sockaddr_in *a = (struct sockaddr_in *)ai->ai_addr;
            CHECK(ai->ai_addrlen == sizeof(*a) && a->sin_family == family);
            CHECK(a->sin_port == htons(43127) && !memcmp(&a->sin_addr, expected, 4));
        } else {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)ai->ai_addr;
            CHECK(ai->ai_addrlen == sizeof(*a) && a->sin6_family == family);
            CHECK(a->sin6_port == htons(43127) && !memcmp(&a->sin6_addr, expected, 16));
        }
    }
    CHECK(count > 0);
}

static void numeric(int mode, int family) {
    struct addrinfo h = hint(family);
    const char *name = family == AF_INET ? "127.0.0.7" : "::1";
    struct gaicb cb;
    init(&cb, name, &h);
    // Output fields are not input: an old/poisoned result must not be followed.
    cb.ar_result = (struct addrinfo *)(uintptr_t)1;
    struct gaicb *list[] = {&cb};
    errno = E2BIG;
    CHECK(getaddrinfo_a(mode, list, 1, NULL) == 0);
    CHECK(errno == E2BIG);
    wait_cb(&cb);
    verify(&cb, family, name);
    errno = E2BIG;
    CHECK(gai_cancel(&cb) == EAI_ALLDONE && errno == E2BIG);
    const struct gaicb *done[] = {&cb};
    CHECK(gai_suspend(done, 1, NULL) == EAI_ALLDONE);
    freeaddrinfo(cb.ar_result);
}

static void mixed(int mode) {
    struct addrinfo h4 = hint(AF_INET), h6 = hint(AF_INET6);
    struct gaicb good4, good6, bad, zero = {0};
    init(&good4, "127.0.0.8", &h4);
    init(&good6, "::1", &h6);
    init(&bad, "not-numeric.invalid", &h4);
    struct gaicb *list[] = {&good4, NULL, &bad, &zero, &good6};
    errno = E2BIG;
    // Enqueue success is distinct from a name/service resolution failure.
    CHECK(getaddrinfo_a(mode, list, 5, NULL) == 0 && errno == E2BIG);
    wait_cb(&good4); wait_cb(&bad); wait_cb(&zero); wait_cb(&good6);
    verify(&good4, AF_INET, "127.0.0.8");
    verify(&good6, AF_INET6, "::1");
    CHECK(gai_error(&bad) == EAI_NONAME && gai_error(&zero) == EAI_NONAME);
    freeaddrinfo(good4.ar_result); freeaddrinfo(good6.ar_result);
}

static void signal_batch(void) {
    const int signo = SIGRTMIN + 4;
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, signo);
    CHECK(pthread_sigmask(SIG_BLOCK, &mask, NULL) == 0);
    struct addrinfo h = hint(AF_INET);
    struct gaicb first, second, bad;
    init(&first, "127.0.0.9", &h); init(&second, "127.0.0.10", &h);
    init(&bad, "not-numeric.invalid", &h);
    struct gaicb *list[] = {&first, &second, NULL, &bad};
    struct sigevent event = {0};
    event.sigev_notify = SIGEV_SIGNAL; event.sigev_signo = signo;
    event.sigev_value.sival_ptr = (void *)(uintptr_t)0x712345678ULL;
    CHECK(getaddrinfo_a(GAI_NOWAIT, list, 4, &event) == 0);
    siginfo_t info;
    const struct timespec timeout = {3, 0}, zero = {0, 0};
    CHECK(sigtimedwait(&mask, &info, &timeout) == signo);
    CHECK(info.si_code == SI_ASYNCNL && info.si_value.sival_ptr == event.sigev_value.sival_ptr);
    verify(&first, AF_INET, "127.0.0.9"); verify(&second, AF_INET, "127.0.0.10");
    CHECK(gai_error(&bad) == EAI_NONAME);
    freeaddrinfo(first.ar_result); freeaddrinfo(second.ar_result);
    CHECK(sigtimedwait(&mask, &info, &zero) == -1 && errno == EAGAIN);
}

struct batch {
    struct gaicb requests[3];
    struct gaicb *list[3];
    struct addrinfo hints;
    int kind;
};

static void cleanup(void *unused) {
    (void)unused;
    atomic_fetch_add_explicit(&cleanups, 1, memory_order_release);
}

static void callback(union sigval value) {
    struct batch *batch = value.sival_ptr;
    int kind = batch->kind;
    for (int i = 0; i < 3; ++i) {
        verify(&batch->requests[i], AF_INET, "127.0.0.11");
        freeaddrinfo(batch->requests[i].ar_result);
    }
    // This frees the gaicbs, list, and hints from inside notification.
    free(batch);
    if (kind == 1 || kind == 2) numeric(GAI_WAIT, AF_INET6);
    if (kind == 3) {
        pthread_attr_t actual;
        size_t size;
        CHECK(pthread_getattr_np(pthread_self(), &actual) == 0);
        CHECK(pthread_attr_getstacksize(&actual, &size) == 0 && size >= 512 * 1024 && size <= 1024 * 1024);
        CHECK(pthread_attr_destroy(&actual) == 0);
    }
    pthread_cleanup_push(cleanup, NULL);
    atomic_fetch_add_explicit(&notices, 1, memory_order_release);
    if (kind == 2) pthread_exit(NULL);
    pthread_cleanup_pop(0);
}

static void thread_batch(int kind) {
    struct batch *batch = calloc(1, sizeof(*batch)); CHECK(batch);
    batch->hints = hint(AF_INET); batch->kind = kind;
    for (int i = 0; i < 3; ++i) {
        init(&batch->requests[i], "127.0.0.11", &batch->hints);
        batch->list[i] = &batch->requests[i];
    }
    pthread_attr_t attr;
    CHECK(pthread_attr_init(&attr) == 0);
    CHECK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0);
    CHECK(pthread_attr_setstacksize(&attr, 512 * 1024) == 0);
    struct sigevent event = {0};
    event.sigev_notify = SIGEV_THREAD; event.sigev_notify_function = callback;
    event.sigev_value.sival_ptr = batch;
    if (kind == 3) event.sigev_notify_attributes = &attr;
    CHECK(getaddrinfo_a(GAI_NOWAIT, batch->list, 3, &event) == 0);
    // The callback may have freed batch before getaddrinfo_a returned.
    CHECK(pthread_attr_destroy(&attr) == 0);
    for (int i = 0; i < 3000; ++i) {
        if (atomic_load_explicit(&notices, memory_order_acquire) == 1 &&
            (kind != 2 || atomic_load_explicit(&cleanups, memory_order_acquire) == 1)) break;
        pause_ms(1);
    }
    CHECK(atomic_load_explicit(&notices, memory_order_acquire) == 1);
    CHECK(atomic_load_explicit(&cleanups, memory_order_acquire) == (kind == 2));
}

static void reuse(void) {
    struct addrinfo h = hint(AF_INET);
    struct gaicb cb;
    for (int iteration = 0; iteration < 128; ++iteration) {
        init(&cb, "127.0.0.12", &h);
        struct gaicb *list[] = {&cb};
        CHECK(getaddrinfo_a(GAI_NOWAIT, list, 1, NULL) == 0);
        wait_cb(&cb); verify(&cb, AF_INET, "127.0.0.12");
        freeaddrinfo(cb.ar_result);
        // Old worker/batch teardown may still be executing at this address.
    }
}

static void ignored_event(void) {
    void *page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED);
    struct addrinfo h = hint(AF_INET);
    struct gaicb cb; init(&cb, "127.0.0.13", &h);
    struct gaicb *list[] = {&cb};
    CHECK(getaddrinfo_a(GAI_WAIT, list, 1, page) == 0);
    verify(&cb, AF_INET, "127.0.0.13"); freeaddrinfo(cb.ar_result);
    CHECK(munmap(page, 4096) == 0);
}

static void zero_request(void) {
    struct gaicb cb = {0}; struct gaicb *list[] = {&cb};
    errno = E2BIG;
    CHECK(getaddrinfo_a(GAI_WAIT, list, 1, NULL) == 0 && errno == E2BIG);
    CHECK(gai_error(&cb) == EAI_NONAME);
    CHECK(gai_cancel(&cb) == EAI_ALLDONE);
}

static void controls(void) {
    struct gaicb *nulls[3] = {NULL, NULL, NULL};
    const struct timespec bad = {-1, 1000000000};
    errno = E2BIG;
    CHECK(getaddrinfo_a(GAI_WAIT, NULL, 0, NULL) == 0 && errno == E2BIG);
    CHECK(getaddrinfo_a(GAI_NOWAIT, nulls, 3, NULL) == 0 && errno == E2BIG);
    CHECK(gai_suspend((const struct gaicb *const *)nulls, 3, &bad) == EAI_ALLDONE && errno == E2BIG);
    CHECK(gai_cancel(NULL) == EAI_ALLDONE && errno == E2BIG);
    CHECK(getaddrinfo_a(99, nulls, 3, NULL) == EAI_SYSTEM && errno == EINVAL);
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    alarm(12);
    provider((void *)getaddrinfo_a); provider((void *)gai_error);
    provider((void *)gai_suspend); provider((void *)gai_cancel);
    provider((void *)getaddrinfo); provider((void *)freeaddrinfo);
    const char *name = argv[1];
    if (!strcmp(name, "wait-v4")) numeric(GAI_WAIT, AF_INET);
    else if (!strcmp(name, "wait-v6")) numeric(GAI_WAIT, AF_INET6);
    else if (!strcmp(name, "nowait-v4")) numeric(GAI_NOWAIT, AF_INET);
    else if (!strcmp(name, "nowait-v6")) numeric(GAI_NOWAIT, AF_INET6);
    else if (!strcmp(name, "wait-mixed")) mixed(GAI_WAIT);
    else if (!strcmp(name, "nowait-mixed")) mixed(GAI_NOWAIT);
    else if (!strcmp(name, "signal-batch")) signal_batch();
    else if (!strcmp(name, "thread-free")) thread_batch(0);
    else if (!strcmp(name, "thread-nested")) thread_batch(1);
    else if (!strcmp(name, "thread-exit")) thread_batch(2);
    else if (!strcmp(name, "thread-attributes")) thread_batch(3);
    else if (!strcmp(name, "reuse")) reuse();
    else if (!strcmp(name, "wait-ignores-event")) ignored_event();
    else if (!strcmp(name, "zero-request")) zero_request();
    else if (!strcmp(name, "controls")) controls();
    else CHECK(0 && "unknown case");
    printf("PASS %s\n", name);
    return 0;
}
