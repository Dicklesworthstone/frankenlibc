/* Real blocked poll/epoll cancellation and signal behavior, with a GNU oracle.
 * Successful blocked cases require a sleeping syscall and a kernel snapshot of
 * its pollfd array. Missing procfs evidence is an explicit, non-passing SKIP.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static const char *case_name;
static int expect_native;
static uintptr_t creator_tp;
static pid_t creator_tid;
static pthread_t creator_thread;
static _Atomic int signals_delivered;
typedef int (*ppoll_function)(struct pollfd *, nfds_t, const struct timespec *,
                              const sigset_t *);
static ppoll_function selected_ppoll;
typedef int (*epoll_wait_function)(int, struct epoll_event *, int, int);
typedef int (*epoll_pwait_function)(int, struct epoll_event *, int, int, const sigset_t *);
typedef int (*epoll_pwait2_function)(int, struct epoll_event *, int,
                                   const struct timespec *, const sigset_t *);
static epoll_wait_function selected_epoll_wait;
static epoll_pwait_function selected_epoll_pwait;
static epoll_pwait2_function selected_epoll_pwait2;
static const sigset_t *guarded_mask;
enum event_api { EVENT_NONE, EVENT_WAIT, EVENT_PWAIT, EVENT_PWAIT2 };
static const uint64_t event_tokens[] = {UINT64_C(0x123456789abcdef0), UINT64_C(0xfedcba9876543210)};

static void fail(const char *message) {
    fprintf(stderr, "pthread-native-poll:%s:FAIL:%s\n", case_name, message);
    _Exit(1);
}
#define REQUIRE(condition, message) do { if (!(condition)) fail(message); } while (0)

static void skip(const char *message) {
    printf("pthread-native-poll:%s:SKIP\n", case_name);
    fprintf(stderr, "pthread-native-poll:%s:SKIP:%s\n", case_name, message);
    fflush(stdout);
    _Exit(77);
}

static int64_t monotonic_ns(void) {
    struct timespec now;
    REQUIRE(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic clock");
    return (int64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

static void pause_briefly(void) {
    struct timespec delay = {0, 1000000};
    while (nanosleep(&delay, &delay) != 0)
        REQUIRE(errno == EINTR, "observation pause");
}

static void user_signal(int signal_number) {
    (void)signal_number;
    atomic_fetch_add_explicit(&signals_delivered, 1, memory_order_relaxed);
}
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal observer needs lock-free atomics");

static int pin_providers(const char *expected, int alias, enum event_api event_api) {
    const char *names[] = {
        "pthread_create", "pthread_join", "pthread_tryjoin_np", "pthread_cancel",
        "pthread_self", "pthread_setcancelstate", "pthread_setcanceltype",
        "pthread_testcancel", "pthread_kill", "pthread_sigmask", "sigaction",
        "poll", "ppoll", "__errno_location", "__pthread_register_cancel",
        "__pthread_unregister_cancel", "__pthread_unwind_next",
        alias && event_api == EVENT_NONE ? "__ppoll" : "ppoll",
        event_api == EVENT_NONE ? "poll" : "epoll_create1",
        event_api == EVENT_NONE ? "poll" : "epoll_ctl",
        event_api == EVENT_WAIT ? (alias ? "__epoll_wait" : "epoll_wait") :
        event_api == EVENT_PWAIT ? (alias ? "__epoll_pwait" : "epoll_pwait") :
        event_api == EVENT_PWAIT2 ? "epoll_pwait2" : "poll"
    };
    struct stat wanted;
    if (stat(expected, &wanted) != 0) return 86;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        Dl_info info = {0};
        struct stat actual;
        void *symbol = dlsym(RTLD_DEFAULT, names[i]);
        if (symbol == NULL || !dladdr(symbol, &info) || info.dli_fname == NULL ||
            stat(info.dli_fname, &actual) != 0 || actual.st_dev != wanted.st_dev ||
            actual.st_ino != wanted.st_ino) {
            fprintf(stderr, "pthread-native-poll:provider-mismatch:%s\n", names[i]);
            return 86;
        }
    }
    selected_ppoll = (ppoll_function)dlsym(RTLD_DEFAULT,
                                        alias && event_api == EVENT_NONE ? "__ppoll" : "ppoll");
    if (event_api == EVENT_WAIT)
        selected_epoll_wait = (epoll_wait_function)dlsym(RTLD_DEFAULT,
                                                        alias ? "__epoll_wait" : "epoll_wait");
    if (event_api == EVENT_PWAIT)
        selected_epoll_pwait = (epoll_pwait_function)dlsym(RTLD_DEFAULT,
                                                          alias ? "__epoll_pwait" : "epoll_pwait");
    if (event_api == EVENT_PWAIT2)
        selected_epoll_pwait2 = (epoll_pwait2_function)dlsym(RTLD_DEFAULT, "epoll_pwait2");
    return 0;
}

enum kind {
    BLOCKED, PENDING, DISABLED, SIGNAL, SIGNAL_RESTART, READY, REUSE,
    MASK_UNBLOCK, MASK_BLOCK, READONLY_TIMEOUT, EMPTY_BLOCKED, MASK_CANCEL, MASK_CANCEL_BLOCK,
    FINITE_TIMEOUT, READY_LATE, EDGE_READY, EVENT_ERRORS
};

struct state {
    enum kind kind;
    int use_ppoll;
    int pipefd[2];
    struct pollfd fds[4], expected[4];
    nfds_t count;
    const struct timespec *timeout;
    sigset_t temporary_mask;
    pthread_t thread;
    _Atomic int ready, release, returned, cleaned;
    char proc_path[128];
    int result, error, restored_usr1;
    enum event_api event_api;
    int epfd, duplicate_fd, maxevents, timeout_ms;
    struct epoll_event events[4];
    int64_t elapsed_ns;
};

static int epoll_call(const struct state *state, int epfd, struct epoll_event *events,
                      int maxevents, int timeout_ms, const struct timespec *timeout,
                      const sigset_t *mask) {
    if (state->event_api == EVENT_WAIT)
        return selected_epoll_wait(epfd, events, maxevents, timeout_ms);
    if (state->event_api == EVENT_PWAIT)
        return selected_epoll_pwait(epfd, events, maxevents, timeout_ms, mask);
    return selected_epoll_pwait2(epfd, events, maxevents, timeout, mask);
}

static unsigned event_token(uint64_t token) {
    for (unsigned i = 0; i < 2; ++i)
        if (token == event_tokens[i]) return 1U << i;
    fail("epoll changed the application's event data");
    return 0;
}

static void epoll_edges(struct state *state) {
    const struct timespec zero = {0, 0};
    struct epoll_event events[2];
    REQUIRE(state->result == 1 && state->events[0].events == EPOLLIN,
            "maxevents one returns exactly one application event");
    unsigned tokens = event_token(state->events[0].data.u64);
    REQUIRE(epoll_call(state, state->epfd, events, 1, 0, &zero, NULL) == 1,
            "second ready registration survives the first bounded result");
    REQUIRE(events[0].events == EPOLLIN, "second application readiness flags");
    unsigned second = event_token(events[0].data.u64);
    REQUIRE((tokens & second) == 0, "distinct ready registrations retain distinct data");
    REQUIRE(epoll_call(state, state->epfd, events, 2, 0, &zero, NULL) == 0,
            "EPOLLONESHOT must not be silently rearmed by a wait");
    const int fds[] = {state->pipefd[0], state->duplicate_fd};
    for (unsigned i = 0; i < 2; ++i) {
        struct epoll_event event = {.events = EPOLLIN | EPOLLET | EPOLLONESHOT};
        event.data.u64 = event_tokens[i];
        REQUIRE(epoll_ctl(state->epfd, EPOLL_CTL_MOD, fds[i], &event) == 0,
                "application explicitly rearms its one-shot registrations");
    }
    REQUIRE(epoll_call(state, state->epfd, events, 2, 0, &zero, NULL) == 2,
            "explicit rearm publishes both still-ready application entries");
    tokens = 0;
    for (unsigned i = 0; i < 2; ++i) {
        REQUIRE(events[i].events == EPOLLIN, "rearmed readiness flags");
        tokens |= event_token(events[i].data.u64);
    }
    REQUIRE(tokens == 3, "rearmed data payloads survive native wait routing");
    REQUIRE(epoll_call(state, state->epfd, events, 2, 0, &zero, NULL) == 0,
            "one-shot registrations remain disabled after their second delivery");
}

static void epoll_errors(struct state *state) {
    const struct timespec zero = {0, 0};
    sigset_t temporary, after;
    sigemptyset(&temporary);
    sigaddset(&temporary, SIGUSR1);
    const int fds[] = {-1, state->pipefd[0], state->epfd};
    const int maximum[] = {4, 4, 0};
    const int errors[] = {EBADF, EINVAL, EINVAL};
    for (unsigned i = 0; i < 3; ++i) {
        errno = EDOM;
        REQUIRE(epoll_call(state, fds[i], state->events, maximum[i], 0, &zero, &temporary) == -1 &&
                errno == errors[i], "epoll preserves kernel error selection");
        REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &after) == 0 &&
                sigismember(&after, SIGUSR1) == 0, "epoll error restores the original signal mask");
    }
    if (state->event_api == EVENT_PWAIT2) {
        const struct timespec invalid[] = {{-1, 0}, {0, 1000000000}};
        for (unsigned i = 0; i < 2; ++i) {
            errno = EDOM;
            REQUIRE(epoll_call(state, state->epfd, state->events, 4, 0, &invalid[i],
                               (const sigset_t *)(uintptr_t)1) == -1 && errno == EINVAL,
                    "invalid epoll_pwait2 timeout is rejected before reading the signal mask");
        }
        errno = EDOM;
        REQUIRE(epoll_call(state, state->epfd, state->events, 4, 0,
                           (const struct timespec *)(uintptr_t)1, NULL) == -1 && errno == EFAULT,
                "epoll_pwait2 rejects an unreadable timeout without a process fault");
        _Alignas(struct timespec) unsigned char unaligned[sizeof(struct timespec) + 1];
        memcpy(unaligned + 1, &zero, sizeof(zero));
        REQUIRE(epoll_call(state, state->epfd, state->events, 4, 0,
                           (const struct timespec *)(unaligned + 1), NULL) == 0,
                "epoll_pwait2 accepts an unaligned kernel-readable timeout");
    }
    if (state->event_api != EVENT_WAIT) {
        errno = EDOM;
        REQUIRE(epoll_call(state, state->epfd, state->events, 4, 0, &zero,
                           (const sigset_t *)(uintptr_t)1) == -1 && errno == EFAULT,
                "epoll rejects an inaccessible temporary signal mask");
        REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &after) == 0 &&
                sigismember(&after, SIGUSR1) == 0, "bad-mask error preserves the original signal mask");
        REQUIRE(epoll_call(state, state->epfd, state->events, 4, 0, &zero, guarded_mask) == 0,
                "epoll reads only the eight-byte kernel signal mask at a guard-page boundary");
    }
    for (size_t i = 0; i < sizeof(state->events); ++i)
        REQUIRE(((unsigned char *)state->events)[i] == 0xa5, "epoll errors preserve event output");
}

static void capture_identity(struct state *state) {
    pid_t tid = (pid_t)syscall(SYS_gettid);
    REQUIRE(tid > 0 && tid != creator_tid, "distinct kernel thread");
    REQUIRE(!pthread_equal(pthread_self(), creator_thread), "distinct pthread identity");
    /* Current native clone deliberately omits CLONE_SETTLS, including the
     * owned-tls-cache feature. Replace this witness when it gains its own TCB. */
    REQUIRE(((uintptr_t)__builtin_thread_pointer() == creator_tp) == expect_native,
            "thread backend does not match inherited/native or hosted TP");
    char target[104];
    ssize_t length = readlink("/proc/thread-self", target, sizeof(target) - 1);
    if (length < 0) skip("proc-thread-self-unavailable");
    REQUIRE((size_t)length < sizeof(target) - 1, "proc thread path truncated");
    target[length] = 0;
    int count = snprintf(state->proc_path, sizeof(state->proc_path), "/proc/%s", target);
    REQUIRE(count > 0 && (size_t)count < sizeof(state->proc_path), "proc path capacity");
}

static void cleanup(void *argument) {
    struct state *state = argument;
    sigset_t restored;
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &restored) == 0, "cleanup signal mask query");
    /* GNU blocked cancellation unwinds under ppoll's temporary mask. Ordinary
     * return and a request already pending at entry retain the original mask. */
    REQUIRE(sigismember(&restored, SIGUSR1) ==
                (state->kind == MASK_UNBLOCK || state->kind == MASK_CANCEL_BLOCK),
            "cleanup signal mask must match the observed GNU cancellation phase");
    if (state->kind == MASK_CANCEL_BLOCK)
        REQUIRE(atomic_load_explicit(&signals_delivered, memory_order_relaxed) == 0,
                "blocked cancellation must not expose an original-mask signal gap");
    REQUIRE(atomic_fetch_add_explicit(&state->cleaned, 1, memory_order_release) == 0,
            "cleanup ran more than once");
}

static void *worker(void *argument) {
    struct state *state = argument;
    capture_identity(state);
    REQUIRE(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0, "deferred type");
    if (state->kind == DISABLED)
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0, "disable cancellation");
    sigset_t mask;
    sigemptyset(&mask);
    if (state->kind == MASK_UNBLOCK || state->kind == MASK_CANCEL) sigaddset(&mask, SIGUSR1);
    REQUIRE(pthread_sigmask(SIG_SETMASK, &mask, NULL) == 0, "worker signal mask");
    pthread_cleanup_push(cleanup, state);
    atomic_store_explicit(&state->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&state->release, memory_order_acquire))
        (void)syscall(SYS_sched_yield);
    errno = EDOM;
    struct pollfd *fds = state->count == 0 ? NULL : state->fds;
    const sigset_t *temporary = state->kind == MASK_UNBLOCK || state->kind == MASK_BLOCK ||
                                state->kind == MASK_CANCEL || state->kind == MASK_CANCEL_BLOCK
                                  ? &state->temporary_mask : NULL;
    int64_t started = monotonic_ns();
    if (state->event_api != EVENT_NONE) {
        if (state->kind == EVENT_ERRORS) {
            epoll_errors(state);
            state->result = 0;
        } else {
            state->result = epoll_call(state, state->epfd, state->events, state->maxevents,
                                       state->timeout_ms, state->timeout, temporary);
            if (state->kind == EDGE_READY) epoll_edges(state);
        }
    } else if (state->use_ppoll) {
        state->result = selected_ppoll(fds, state->count, state->timeout, temporary);
    } else {
        state->result = poll(fds, state->count, -1);
    }
    state->error = errno;
    state->elapsed_ns = monotonic_ns() - started;
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0, "query restored mask");
    state->restored_usr1 = sigismember(&mask, SIGUSR1);
    atomic_store_explicit(&state->returned, 1, memory_order_release);
    pthread_cleanup_pop(1);
    if (state->kind == DISABLED) {
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0, "restore cancellation");
        pthread_testcancel();
        fail("disabled poll lost its pending cancellation");
    }
    return state;
}

static void wait_ready(struct state *state) {
    int64_t deadline = monotonic_ns() + 2000000000;
    while (!atomic_load_explicit(&state->ready, memory_order_acquire)) {
        REQUIRE(monotonic_ns() < deadline, "worker readiness deadline");
        pause_briefly();
    }
}

static int read_proc(const struct state *state, const char *leaf, char *buffer, size_t capacity) {
    char path[160];
    int count = snprintf(path, sizeof(path), "%s/%s", state->proc_path, leaf);
    REQUIRE(count > 0 && (size_t)count < sizeof(path), "observation path capacity");
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) skip("proc-thread-observation-unavailable");
    ssize_t length = read(fd, buffer, capacity - 1);
    int error = errno;
    REQUIRE(close(fd) == 0, "close proc observation");
    if (length < 0 && (error == EPERM || error == EACCES))
        skip("proc-thread-observation-denied");
    if (length <= 0) return 0;
    buffer[length] = 0;
    return 1;
}

static int snapshot(int memory, unsigned long long address, void *out, size_t length) {
    ssize_t copied = pread(memory, out, length, (off_t)address);
    if (copied < 0 && (errno == EPERM || errno == EACCES || errno == ENOSYS))
        skip("kernel-poll-array-snapshot-unavailable");
    return copied == (ssize_t)length;
}

static void observe_parked(struct state *state, int memory) {
    int64_t deadline = monotonic_ns() + 2000000000;
    int sliced = expect_native && state->kind != DISABLED;
    while (monotonic_ns() < deadline) {
        REQUIRE(!atomic_load_explicit(&state->returned, memory_order_acquire),
                "worker returned before the intended blocked operation");
        char call[512], status[512];
        long number = -1;
        unsigned long long args[6] = {0};
        if (!read_proc(state, "syscall", call, sizeof(call)) ||
            sscanf(call, "%ld %llx %llx %llx %llx %llx %llx", &number,
                   &args[0], &args[1], &args[2], &args[3], &args[4], &args[5]) < 3)
            goto retry;
        if (state->event_api != EVENT_NONE) {
            int is_epoll_wait = 0;
#ifdef SYS_epoll_wait
            is_epoll_wait = number == SYS_epoll_wait;
#endif
            if ((!is_epoll_wait && number != SYS_epoll_pwait && number != SYS_epoll_pwait2) ||
                args[0] != (unsigned)state->epfd || args[2] != (unsigned)state->maxevents)
                goto retry;
            if (sliced && number != (state->event_api == EVENT_PWAIT2 ? SYS_epoll_pwait2 : SYS_epoll_pwait))
                goto retry;
            if (!read_proc(state, "stat", status, sizeof(status))) goto retry;
            char *end = strrchr(status, ')');
            if (end == NULL || end[1] != ' ' || end[2] != 'S') goto retry;
            if (sliced) {
                uint64_t mask;
                if (args[4] == 0 || !snapshot(memory, args[4], &mask, sizeof(mask))) goto retry;
                REQUIRE(args[5] == sizeof(mask), "native epoll uses the kernel signal-mask width");
                REQUIRE(((mask >> (SIGUSR1 - 1)) & 1) ==
                            (uint64_t)(state->kind == MASK_BLOCK || state->kind == MASK_CANCEL_BLOCK),
                        "native epoll submits the intended user signal mask");
                if (state->event_api == EVENT_PWAIT2) {
                    struct timespec quantum;
                    if (args[3] == 0 || !snapshot(memory, args[3], &quantum, sizeof(quantum))) goto retry;
                    REQUIRE(quantum.tv_sec == 0 && quantum.tv_nsec > 0 && quantum.tv_nsec <= 50000000,
                            "native epoll_pwait2 has a bounded nonzero wait quantum");
                } else {
                    REQUIRE(args[3] > 0 && args[3] <= 50,
                            "native epoll_pwait has a bounded nonzero wait quantum");
                }
            }
            return;
        }
        int is_poll = 0;
#ifdef SYS_poll
        is_poll = number == SYS_poll;
#endif
        if ((!is_poll && number != SYS_ppoll) || args[1] != state->count)
            goto retry;
        if (sliced && number != SYS_ppoll) goto retry;
        struct pollfd observed[4];
        size_t bytes = (size_t)args[1] * sizeof(observed[0]);
        if (bytes != 0 && !snapshot(memory, args[0], observed, bytes)) goto retry;
        for (nfds_t i = 0; i < state->count; ++i)
            if (observed[i].fd != state->expected[i].fd ||
                observed[i].events != state->expected[i].events) goto retry;
        if (!read_proc(state, "stat", status, sizeof(status))) goto retry;
        char *end = strrchr(status, ')');
        if (end == NULL || end[1] != ' ' || end[2] != 'S') goto retry;
        if (sliced) {
            struct timespec quantum;
            uint64_t mask;
            if (args[2] == 0 || !snapshot(memory, args[2], &quantum, sizeof(quantum)) ||
                args[3] == 0 || !snapshot(memory, args[3], &mask, sizeof(mask))) goto retry;
            REQUIRE(quantum.tv_sec == 0 && quantum.tv_nsec > 0 && quantum.tv_nsec <= 100000000,
                    "native ppoll has a bounded nonzero wait quantum");
            REQUIRE(((mask >> (SIGUSR1 - 1)) & 1) ==
                        (uint64_t)(state->kind == MASK_BLOCK || state->kind == MASK_CANCEL_BLOCK),
                    "native ppoll submits the intended user signal mask");
        }
        return;
retry:
        pause_briefly();
    }
    fail("no sleeping syscall with the intended application wait arguments");
}

static void *join_bounded(struct state *state) {
    int64_t deadline = monotonic_ns() + 3000000000;
    void *result = NULL;
    for (;;) {
        int rc = pthread_tryjoin_np(state->thread, &result);
        if (rc == 0) return result;
        REQUIRE(rc == EBUSY, "tryjoin result");
        REQUIRE(monotonic_ns() < deadline, "join deadline without rescue readiness");
        pause_briefly();
    }
}

static void initialize(struct state *state, enum kind kind, int use_ppoll,
                       const int pipefd[2], const struct timespec *timeout,
                       enum event_api event_api, int epfd, int duplicate_fd) {
    memset(state, 0, sizeof(*state));
    state->kind = kind;
    state->use_ppoll = use_ppoll;
    memcpy(state->pipefd, pipefd, sizeof(state->pipefd));
    state->count = kind == EMPTY_BLOCKED ? 0 : kind == READY ? 4 : 1;
    state->fds[0] = (struct pollfd){pipefd[0], POLLIN, 0x4000};
    state->fds[1] = (struct pollfd){-1, POLLIN | POLLOUT, 0x4000};
    state->fds[2] = (struct pollfd){pipefd[0], POLLIN, 0x4000};
    state->fds[3] = (struct pollfd){-pipefd[0] - 1, 0, 0x4000};
    memcpy(state->expected, state->fds, sizeof(state->fds));
    state->timeout = timeout;
    if (event_api == EVENT_PWAIT2 && (kind == BLOCKED || kind == EMPTY_BLOCKED))
        state->timeout = NULL;
    state->event_api = event_api;
    state->epfd = epfd;
    state->duplicate_fd = duplicate_fd;
    state->maxevents = kind == EDGE_READY ? 1 : 4;
    state->timeout_ms = kind == FINITE_TIMEOUT ? 250 : kind == READY_LATE ? 1000 : -7;
    memset(state->events, 0xa5, sizeof(state->events));
    sigemptyset(&state->temporary_mask);
    if (kind == MASK_BLOCK || kind == MASK_CANCEL_BLOCK) sigaddset(&state->temporary_mask, SIGUSR1);
    atomic_init(&state->ready, 0);
    atomic_init(&state->release, 0);
    atomic_init(&state->returned, 0);
    atomic_init(&state->cleaned, 0);
}

static void seed_pipe(const struct state *state) {
    REQUIRE(write(state->pipefd[1], "P", 1) == 1, "publish controlled readiness");
}

static void verify_pipe(const struct state *state, int seeded) {
    char byte = 0;
    ssize_t result = read(state->pipefd[0], &byte, 1);
    if (seeded) {
        REQUIRE(result == 1 && byte == 'P', "poll must not consume application data");
        result = read(state->pipefd[0], &byte, 1);
    }
    REQUIRE(result == -1 && errno == EAGAIN, "pipe has exactly the expected data");
}

static void run_case(struct state *state, int memory) {
    enum kind kind = state->kind;
    int seeded = kind == PENDING || kind == READY || kind == EDGE_READY;
    if (seeded) seed_pipe(state);
    REQUIRE(pthread_create(&state->thread, NULL, worker, state) == 0, "create worker");
    wait_ready(state);
    if (kind == PENDING)
        REQUIRE(pthread_cancel(state->thread) == 0, "queue pending cancellation");
    if (kind == MASK_UNBLOCK)
        REQUIRE(pthread_kill(state->thread, SIGUSR1) == 0, "queue masked user signal");
    atomic_store_explicit(&state->release, 1, memory_order_release);
    if (kind != PENDING && kind != READY && kind != MASK_UNBLOCK &&
        kind != EDGE_READY && kind != EVENT_ERRORS)
        observe_parked(state, memory);
    if (kind == BLOCKED || kind == EMPTY_BLOCKED || kind == MASK_CANCEL ||
        kind == MASK_CANCEL_BLOCK || kind == DISABLED) {
        if (kind == MASK_CANCEL_BLOCK) {
            REQUIRE(pthread_kill(state->thread, SIGUSR1) == 0, "queue signal blocked by temporary mask");
            observe_parked(state, memory);
            REQUIRE(atomic_load_explicit(&signals_delivered, memory_order_relaxed) == 0,
                    "user signal is pending before blocked cancellation");
        }
        REQUIRE(pthread_cancel(state->thread) == 0, "cancel observed blocked poll");
        if (kind == DISABLED) {
            observe_parked(state, memory);
            REQUIRE(atomic_load_explicit(&state->cleaned, memory_order_acquire) == 0,
                    "disabled cancellation must not run cleanup");
            seed_pipe(state);
            seeded = 1;
        }
    } else if (kind == SIGNAL || kind == SIGNAL_RESTART || kind == MASK_BLOCK) {
        REQUIRE(pthread_kill(state->thread, SIGUSR1) == 0, "interrupt observed blocked poll");
        if (kind == MASK_BLOCK) {
            /* Span multiple 50 ms native slices: restoring an unblocked mask
             * between them would incorrectly deliver the pending signal. */
            int64_t held_until = monotonic_ns() + 220000000;
            do {
                observe_parked(state, memory);
                REQUIRE(atomic_load_explicit(&signals_delivered, memory_order_relaxed) == 0,
                        "temporary ppoll mask must defer user signal across slices");
                pause_briefly();
            } while (monotonic_ns() < held_until);
            seed_pipe(state);
            seeded = 1;
        }
    } else if (kind == READY_LATE) {
        int64_t held_until = monotonic_ns() + 170000000;
        do {
            observe_parked(state, memory);
            pause_briefly();
        } while (monotonic_ns() < held_until);
        seed_pipe(state);
        seeded = 1;
    }
    void *result = join_bounded(state);
    int canceled = kind == BLOCKED || kind == EMPTY_BLOCKED || kind == MASK_CANCEL ||
                   kind == MASK_CANCEL_BLOCK || kind == PENDING || kind == DISABLED;
    REQUIRE(result == (canceled ? PTHREAD_CANCELED : (void *)state), "thread result");
    REQUIRE(atomic_load_explicit(&state->cleaned, memory_order_acquire) == 1, "one cleanup");
    int returned = atomic_load_explicit(&state->returned, memory_order_acquire);
    REQUIRE(returned == (!canceled || kind == DISABLED), "operation return versus cancellation");
    for (nfds_t i = 0; i < state->count; ++i)
        REQUIRE(state->fds[i].fd == state->expected[i].fd &&
                state->fds[i].events == state->expected[i].events, "poll inputs unchanged");
    if (kind == PENDING && state->event_api == EVENT_NONE)
        REQUIRE(state->fds[0].revents == 0x4000, "pending cancellation precedes output publication");
    if (kind == PENDING && state->event_api != EVENT_NONE) {
        for (size_t i = 0; i < sizeof(state->events); ++i)
            REQUIRE(((unsigned char *)state->events)[i] == 0xa5,
                    "pending epoll cancellation precedes event output publication");
        struct epoll_event remaining[2];
        const struct timespec zero = {0, 0};
        REQUIRE(epoll_call(state, state->epfd, remaining, 2, 0, &zero, NULL) == 2,
                "pending cancellation leaves application readiness in the epoll instance");
    }
    if (kind == SIGNAL || kind == SIGNAL_RESTART || kind == MASK_UNBLOCK) {
        REQUIRE(state->result == -1 && state->error == EINTR, "user signal returns EINTR without restart");
        REQUIRE(atomic_load_explicit(&signals_delivered, memory_order_relaxed) == 1, "one user signal delivered");
    } else if (kind == READY && state->event_api == EVENT_NONE) {
        REQUIRE(state->result == 2, "duplicate pollfd entries retain multiplicity");
        REQUIRE(state->fds[0].revents == POLLIN && state->fds[2].revents == POLLIN &&
                state->fds[1].revents == 0 && state->fds[3].revents == 0,
                "ready and ignored pollfd outputs");
    } else if (state->event_api != EVENT_NONE &&
               (kind == READY || kind == READY_LATE || kind == DISABLED || kind == MASK_BLOCK)) {
        REQUIRE(state->result == 2, "epoll returns both application registrations");
        unsigned tokens = 0;
        for (int i = 0; i < state->result; ++i) {
            REQUIRE(state->events[i].events == EPOLLIN, "epoll returns the application readiness flags");
            tokens |= event_token(state->events[i].data.u64);
        }
        REQUIRE(tokens == 3, "epoll retains both distinct application data payloads");
        for (size_t i = 2 * sizeof(state->events[0]); i < sizeof(state->events); ++i)
            REQUIRE(((unsigned char *)state->events)[i] == 0xa5,
                    "epoll preserves unused output entries");
    } else if (kind == DISABLED || kind == MASK_BLOCK) {
        REQUIRE(state->result == 1 && state->fds[0].revents == POLLIN, "controlled readiness result");
    } else if (kind == READONLY_TIMEOUT && state->event_api == EVENT_NONE) {
        REQUIRE(state->result == 0 && state->fds[0].revents == 0, "read-only timeout expires normally");
    } else if (kind == FINITE_TIMEOUT || kind == READONLY_TIMEOUT) {
        REQUIRE(state->result == 0, "finite epoll timeout expires normally");
        REQUIRE(state->elapsed_ns >= (kind == FINITE_TIMEOUT ? 220000000 : 450000000) &&
                state->elapsed_ns < 2000000000,
                "epoll finite deadline spans slices without restarting or rounding early");
        for (size_t i = 0; i < sizeof(state->events); ++i)
            REQUIRE(((unsigned char *)state->events)[i] == 0xa5, "epoll timeout preserves event output");
    }
    if (kind == READY_LATE)
        REQUIRE(state->elapsed_ns >= 160000000 && state->elapsed_ns < 2000000000,
                "epoll returns real readiness after several empty native slices");
    if (!canceled || kind == DISABLED)
        REQUIRE(state->restored_usr1 == (kind == MASK_UNBLOCK), "caller signal mask restored");
    if (kind == MASK_BLOCK)
        REQUIRE(atomic_load_explicit(&signals_delivered, memory_order_relaxed) == 1,
                "deferred signal delivered after temporary mask restoration");
    if (kind == MASK_CANCEL_BLOCK)
        REQUIRE(atomic_load_explicit(&signals_delivered, memory_order_relaxed) == 0,
                "thread-directed blocked signal stays undelivered through cancellation");
    verify_pipe(state, seeded);
}

static size_t descriptor_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) skip("descriptor-accounting-unavailable");
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
        if (entry->d_name[0] != '.') ++count;
    REQUIRE(closedir(directory) == 0, "close descriptor inventory");
    return count;
}

static void reuse_case(int use_ppoll, const int pipefd[2],
                       const struct timespec *timeout, int memory,
                       enum event_api event_api, int epfd, int duplicate_fd) {
    struct state state;
    initialize(&state, READY, use_ppoll, pipefd, timeout, event_api, epfd, duplicate_fd);
    run_case(&state, memory); /* Resolve runtime state before measuring lifetime. */
    size_t before = descriptor_count();
    for (int round = 0; round < 8; ++round) {
        initialize(&state, BLOCKED, use_ppoll, pipefd, timeout, event_api, epfd, duplicate_fd);
        run_case(&state, memory);
        REQUIRE(descriptor_count() == before, "retired poll thread leaked a descriptor");
        initialize(&state, READY, use_ppoll, pipefd, timeout, event_api, epfd, duplicate_fd);
        run_case(&state, memory);
        REQUIRE(descriptor_count() == before, "replacement thread leaked or inherited cancellation");
    }
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    case_name = argv[1];
    int use_ppoll = strncmp(case_name, "ppoll-", 6) == 0;
    int alias = strncmp(case_name, "ppoll-alias-", 12) == 0;
    enum event_api event_api = EVENT_NONE;
    const char *suffix;
    if (strncmp(case_name, "epoll-wait-", 11) == 0) {
        event_api = EVENT_WAIT;
        suffix = case_name + 11;
    } else if (strncmp(case_name, "epoll-pwait-", 12) == 0) {
        event_api = EVENT_PWAIT;
        suffix = case_name + 12;
    } else if (strncmp(case_name, "epoll-pwait2-", 13) == 0) {
        event_api = EVENT_PWAIT2;
        suffix = case_name + 13;
    } else {
        if (!use_ppoll && strncmp(case_name, "poll-", 5) != 0) return 2;
        suffix = case_name + (alias ? 12 : use_ppoll ? 6 : 5);
    }
    if (event_api != EVENT_NONE && strncmp(suffix, "alias-", 6) == 0) {
        if (event_api == EVENT_PWAIT2) return 2;
        alias = 1;
        suffix += 6;
    }
    const char *names[] = {"blocked", "pending", "disabled", "signal", "signal-restart", "ready",
                          "reuse", "mask-unblock", "mask-block", "readonly-timeout", "empty-blocked",
                          "mask-cancel", "mask-cancel-block", "timeout", "ready-late",
                          "edge-ready", "errors"};
    int index = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(suffix, names[i]) == 0) index = (int)i;
    if (index < 0) return 2;
    if (event_api == EVENT_NONE && (index >= FINITE_TIMEOUT ||
        (!use_ppoll && ((index >= MASK_UNBLOCK && index <= READONLY_TIMEOUT) ||
                       index == MASK_CANCEL || index == MASK_CANCEL_BLOCK)))) return 2;
    if (event_api == EVENT_WAIT && ((index >= MASK_UNBLOCK && index <= READONLY_TIMEOUT) ||
                                   index == MASK_CANCEL || index == MASK_CANCEL_BLOCK)) return 2;
    if (event_api == EVENT_PWAIT && index == READONLY_TIMEOUT) return 2;
    enum kind kind = (enum kind)index;
    int pin = pin_providers(argv[2], alias, event_api);
    if (pin != 0) return pin;
    expect_native = getenv("FRANKENLIBC_THREAD_NATIVE") != NULL &&
                    strcmp(getenv("FRANKENLIBC_THREAD_NATIVE"), "1") == 0;
    creator_tp = (uintptr_t)__builtin_thread_pointer();
    creator_tid = (pid_t)syscall(SYS_gettid);
    creator_thread = pthread_self();
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = user_signal;
    action.sa_flags = kind == SIGNAL_RESTART ? SA_RESTART : 0;
    sigemptyset(&action.sa_mask);
    REQUIRE(sigaction(SIGUSR1, &action, NULL) == 0, "install user signal handler");
    sigset_t unblocked;
    sigemptyset(&unblocked);
    REQUIRE(pthread_sigmask(SIG_SETMASK, &unblocked, NULL) == 0, "creator signal mask");
    alarm(15);
    int pipefd[2];
    REQUIRE(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) == 0, "create application pipe");
    int epfd = -1, duplicate_fd = -1;
    if (event_api != EVENT_NONE) {
        epfd = epoll_create1(EPOLL_CLOEXEC);
        REQUIRE(epfd >= 0, "create application epoll instance");
        duplicate_fd = fcntl(pipefd[0], F_DUPFD_CLOEXEC, 0);
        REQUIRE(duplicate_fd >= 0, "duplicate application pipe descriptor");
        if (kind != EMPTY_BLOCKED) {
            const int fds[] = {pipefd[0], duplicate_fd};
            for (unsigned i = 0; i < 2; ++i) {
                struct epoll_event event = {.events = EPOLLIN};
                if (kind == EDGE_READY || kind == PENDING) event.events |= EPOLLET | EPOLLONESHOT;
                event.data.u64 = event_tokens[i];
                REQUIRE(epoll_ctl(epfd, EPOLL_CTL_ADD, fds[i], &event) == 0,
                        "register application epoll interest with opaque data");
            }
        }
    }
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (memory < 0) skip("kernel-poll-array-snapshot-unavailable");
    long page = sysconf(_SC_PAGESIZE);
    REQUIRE(page > 0, "page size");
    struct timespec *timeout = mmap(NULL, 2 * (size_t)page, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(timeout != MAP_FAILED, "map timeout storage");
    *timeout = kind == READONLY_TIMEOUT ? (struct timespec){0, 500000000} :
               kind == FINITE_TIMEOUT ? (struct timespec){0, 250000000} :
               kind == READY_LATE ? (struct timespec){1, 0} : (struct timespec){60, 0};
    struct timespec expected = *timeout;
    REQUIRE(mprotect(timeout, (size_t)page, PROT_READ) == 0, "protect timeout storage");
    REQUIRE(mprotect((char *)timeout + page, (size_t)page, PROT_NONE) == 0,
            "protect inaccessible page after kernel-width signal mask");
    guarded_mask = (const sigset_t *)((const char *)timeout + page - sizeof(uint64_t));
    if (kind == REUSE) {
        reuse_case(use_ppoll, pipefd, timeout, memory, event_api, epfd, duplicate_fd);
    } else {
        struct state state;
        initialize(&state, kind, use_ppoll, pipefd, timeout, event_api, epfd, duplicate_fd);
        run_case(&state, memory);
    }
    REQUIRE(timeout->tv_sec == expected.tv_sec && timeout->tv_nsec == expected.tv_nsec,
            "poll family must not change the caller's const timeout");
    REQUIRE(munmap(timeout, 2 * (size_t)page) == 0, "release timeout storage");
    if (event_api != EVENT_NONE)
        REQUIRE(close(epfd) == 0 && close(duplicate_fd) == 0, "release application epoll descriptors");
    REQUIRE(close(memory) == 0 && close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "release fixture descriptors");
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}
