/* Real blocked poll/select/epoll/sleep/suspend cancellation and signal behavior, with a GNU oracle.
 * Successful blocked cases require a sleeping syscall and a kernel snapshot of
 * its pollfd array. Missing procfs evidence is an explicit, non-passing SKIP.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
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
#include <sys/select.h>
#include <sys/socket.h>
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
static int sleep_handler_delay;
static _Atomic int64_t sleep_signal_started, sleep_signal_finished;
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
typedef int (*select_function)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
typedef int (*pselect_function)(int, fd_set *, fd_set *, fd_set *,
                                const struct timespec *, const sigset_t *);
static select_function selected_select;
static pselect_function selected_pselect;
enum select_api { SELECT_NONE, SELECT_PLAIN, SELECT_MASK };
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
    if (sleep_handler_delay) {
        struct timespec now;
        if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now) != 0) _Exit(90);
        int64_t started = (int64_t)now.tv_sec * 1000000000 + now.tv_nsec;
        atomic_store_explicit(&sleep_signal_started, started, memory_order_relaxed);
        do {
            if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now) != 0) _Exit(90);
        } while ((int64_t)now.tv_sec * 1000000000 + now.tv_nsec - started < 300000000);
        atomic_store_explicit(&sleep_signal_finished,
                              (int64_t)now.tv_sec * 1000000000 + now.tv_nsec,
                              memory_order_relaxed);
    }
    atomic_fetch_add_explicit(&signals_delivered, 1, memory_order_relaxed);
}
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal observer needs lock-free atomics");
_Static_assert(ATOMIC_LONG_LOCK_FREE == 2, "signal timestamps need lock-free atomics");

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
    enum select_api select_api;
    int select_nfds, select_remainder;
    fd_set sets[3], expected_sets[3];
    struct timeval select_timeout;
};

static int select_call(struct state *state, int nfds, fd_set *readfds,
                       fd_set *writefds, fd_set *exceptfds, struct timeval *timeval,
                       const struct timespec *timespec, const sigset_t *mask) {
    if (state->select_api == SELECT_PLAIN)
        return selected_select(nfds, readfds, writefds, exceptfds, timeval);
    return selected_pselect(nfds, readfds, writefds, exceptfds, timespec, mask);
}

static void select_errors(struct state *state) {
    struct timeval zero = {0, 0};
    const struct timespec zero_ts = {0, 0};
    sigset_t temporary, after;
    sigemptyset(&temporary);
    sigaddset(&temporary, SIGUSR1);
    errno = EDOM;
    REQUIRE(select_call(state, -1, NULL, NULL, NULL, &zero, &zero_ts, NULL) == -1 &&
            errno == EINVAL, "select preserves invalid nfds");
    int closed = fcntl(state->pipefd[0], F_DUPFD_CLOEXEC, 128);
    REQUIRE(closed >= 128 && closed < FD_SETSIZE && close(closed) == 0,
            "reserve then close a descriptor in the kernel table");
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(closed, &readfds);
    struct timeval finite = {0, 250000};
    const struct timespec finite_ts = {0, 250000000};
    errno = EDOM;
    REQUIRE(select_call(state, closed + 1, &readfds, NULL, NULL, &finite, &finite_ts,
                        &temporary) == -1 && errno == EBADF,
            "select rejects a closed descriptor without losing its requested bit");
    REQUIRE(FD_ISSET(closed, &readfds), "select error preserves its input mask");
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &after) == 0 &&
            sigismember(&after, SIGUSR1) == 0, "select error restores the original mask");
    struct timeval invalid = {-1, 0};
    const struct timespec invalid_ts = {-1, 0};
    errno = EDOM;
    REQUIRE(select_call(state, 1, (fd_set *)(uintptr_t)1, NULL, NULL, &invalid, &invalid_ts,
                        (const sigset_t *)(uintptr_t)1) == -1 && errno == EINVAL,
            "select rejects timeout syntax before reading sets or temporary mask");
    errno = EDOM;
    REQUIRE(select_call(state, 1, (fd_set *)(uintptr_t)1, NULL, NULL, &zero, &zero_ts,
                        NULL) == -1 && errno == EFAULT,
            "select retains fault-checked kernel fd-set access");
    FD_ZERO(&readfds);
    FD_SET(state->pipefd[1], &readfds);
    errno = EDOM;
    REQUIRE(select_call(state, state->pipefd[1] + 1, &readfds, &readfds, NULL,
                        &zero, &zero_ts, NULL) == 1 && FD_ISSET(state->pipefd[1], &readfds),
            "select preserves aliased input/output sets and kernel write order");
    if (state->select_api == SELECT_MASK) {
        errno = EDOM;
        REQUIRE(selected_pselect(0, NULL, NULL, NULL, &finite_ts,
                                 (const sigset_t *)(uintptr_t)1) == -1 && errno == EFAULT,
                "pselect rejects an unreadable temporary mask");
        REQUIRE(selected_pselect(0, NULL, NULL, NULL, &zero_ts, guarded_mask) == 0,
                "pselect reads only the eight-byte kernel signal mask");
        REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &after) == 0 &&
                sigismember(&after, SIGUSR1) == 0, "pselect mask error preserves caller state");
    }
}

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
    /* Keep the witness allocation-free: inherited GNU TLS makes formatted I/O
     * in a native worker a separate runtime hazard, unrelated to its wait. */
    state->proc_path[0] = '/';
    state->proc_path[1] = 'p';
    state->proc_path[2] = 'r';
    state->proc_path[3] = 'o';
    state->proc_path[4] = 'c';
    state->proc_path[5] = '/';
    ssize_t length = syscall(SYS_readlinkat, AT_FDCWD, "/proc/thread-self",
                             state->proc_path + 6, sizeof(state->proc_path) - 7);
    if (length < 0) skip("proc-thread-self-unavailable");
    REQUIRE((size_t)length < sizeof(state->proc_path) - 7, "proc thread path truncated");
    state->proc_path[6 + (size_t)length] = 0;
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
    if (state->select_api != SELECT_NONE) {
        if (state->kind == EVENT_ERRORS) {
            select_errors(state);
            state->result = 0;
        } else {
            int empty = state->select_nfds == 0;
            state->result = select_call(state, state->select_nfds,
                empty ? NULL : &state->sets[0], empty ? NULL : &state->sets[1],
                empty ? NULL : &state->sets[2],
                state->timeout ? &state->select_timeout : NULL, state->timeout, temporary);
        }
    } else if (state->event_api != EVENT_NONE) {
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
        if (state->select_api != SELECT_NONE) {
            int is_select = 0;
#ifdef SYS_select
            is_select = number == SYS_select;
#endif
            if ((!is_select && number != SYS_pselect6) ||
                args[0] != (unsigned)state->select_nfds || (sliced && number != SYS_pselect6))
                goto retry;
            fd_set observed;
            size_t bytes = ((size_t)state->select_nfds + 63) / 64 * sizeof(uint64_t);
            for (unsigned i = 0; i < 3 && bytes != 0; ++i) {
                if (args[i + 1] == 0 || !snapshot(memory, args[i + 1], &observed, bytes) ||
                    memcmp(&observed, &state->expected_sets[i], bytes) != 0) goto retry;
            }
            if (!read_proc(state, "stat", status, sizeof(status))) goto retry;
            char *end = strrchr(status, ')');
            if (end == NULL || end[1] != ' ' || end[2] != 'S') goto retry;
            if (sliced) {
                struct timespec quantum;
                uintptr_t mask_argument[2];
                uint64_t mask;
                if (args[4] == 0 || !snapshot(memory, args[4], &quantum, sizeof(quantum)) ||
                    args[5] == 0 || !snapshot(memory, args[5], mask_argument, sizeof(mask_argument)) ||
                    mask_argument[0] == 0 || !snapshot(memory, mask_argument[0], &mask, sizeof(mask)))
                    goto retry;
                REQUIRE(quantum.tv_sec == 0 && quantum.tv_nsec > 0 && quantum.tv_nsec <= 50000000,
                        "native select has a bounded nonzero pselect6 quantum");
                REQUIRE(mask_argument[1] == sizeof(mask), "select uses a kernel-width signal mask");
                REQUIRE(((mask >> (SIGUSR1 - 1)) & 1) ==
                            (uint64_t)(state->kind == MASK_BLOCK || state->kind == MASK_CANCEL_BLOCK),
                        "select submits the intended atomic signal mask");
            }
            return;
        }
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

static void initialize_select(struct state *state, enum kind kind,
                               const int pipefd[2], const struct timespec *timeout,
                               enum select_api api, int remainder) {
    initialize(state, kind, 0, pipefd, timeout, EVENT_NONE, -1, -1);
    state->select_api = api;
    state->select_remainder = remainder;
    state->select_nfds = kind == EMPTY_BLOCKED ? 0 :
                        (pipefd[0] > pipefd[1] ? pipefd[0] : pipefd[1]) + 1;
    if (kind == BLOCKED || kind == EMPTY_BLOCKED) state->timeout = NULL;
    if (state->timeout) {
        state->select_timeout.tv_sec = timeout->tv_sec;
        state->select_timeout.tv_usec = timeout->tv_nsec / 1000;
    }
    for (unsigned i = 0; i < 3; ++i) {
        FD_ZERO(&state->sets[i]);
        FD_SET(FD_SETSIZE - 1, &state->sets[i]); /* Untouched beyond nfds. */
    }
    if (state->select_nfds) {
        FD_SET(pipefd[0], &state->sets[0]);
        FD_SET(pipefd[0], &state->sets[2]);
        if (kind == READY) FD_SET(pipefd[1], &state->sets[1]);
    }
    memcpy(state->expected_sets, state->sets, sizeof(state->sets));
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
    if (kind == PENDING && state->select_api != SELECT_NONE)
        REQUIRE(memcmp(state->sets, state->expected_sets, sizeof(state->sets)) == 0,
                "pending select cancellation precedes output publication");
    if (kind == PENDING && state->event_api == EVENT_NONE && state->select_api == SELECT_NONE)
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
    } else if (state->select_api != SELECT_NONE &&
               (kind == READY || kind == READY_LATE || kind == DISABLED || kind == MASK_BLOCK)) {
        REQUIRE(state->result == (kind == READY ? 2 : 1), "select counts ready bits across sets");
        REQUIRE(FD_ISSET(state->pipefd[0], &state->sets[0]) &&
                FD_ISSET(state->pipefd[1], &state->sets[1]) == (kind == READY) &&
                !FD_ISSET(state->pipefd[0], &state->sets[2]),
                "select returns only ready interest bits after internal slices");
    } else if (state->select_api != SELECT_NONE &&
               (kind == FINITE_TIMEOUT || kind == READONLY_TIMEOUT)) {
        REQUIRE(state->result == 0 && !FD_ISSET(state->pipefd[0], &state->sets[0]) &&
                !FD_ISSET(state->pipefd[0], &state->sets[2]), "select timeout clears watched bits");
        REQUIRE(state->elapsed_ns >= (kind == FINITE_TIMEOUT ? 220000000 : 450000000) &&
                state->elapsed_ns < 2000000000, "select retains one deadline across empty slices");
        if (state->select_api == SELECT_PLAIN)
            REQUIRE(state->select_timeout.tv_sec == 0 && state->select_timeout.tv_usec == 0,
                    "select publishes an exhausted timeval");
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
    if (state->select_api != SELECT_NONE) {
        for (unsigned i = 0; i < 3; ++i)
            REQUIRE(FD_ISSET(FD_SETSIZE - 1, &state->sets[i]), "select preserves words beyond nfds");
        if (state->select_api == SELECT_PLAIN && kind == READY_LATE)
            REQUIRE(state->select_timeout.tv_sec == 0 && state->select_timeout.tv_usec > 300000 &&
                    state->select_timeout.tv_usec < 900000, "select publishes its unslept duration");
        if (state->select_remainder) {
            REQUIRE(atomic_load_explicit(&sleep_signal_finished, memory_order_relaxed) -
                    atomic_load_explicit(&sleep_signal_started, memory_order_relaxed) >= 300000000,
                    "remainder check actually ran a slow signal handler");
            if (state->select_api == SELECT_PLAIN)
                REQUIRE(state->select_timeout.tv_sec == 0 && state->select_timeout.tv_usec > 100000 &&
                        state->select_timeout.tv_usec <= 250000,
                        "select remainder excludes time spent in the signal handler");
        }
    }
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

enum sleep_api { SLEEP_NANO, SLEEP_CLOCK, SLEEP_ABSOLUTE, SLEEP_SECONDS, SLEEP_MICRO, SLEEP_C11 };
enum sleep_kind {
    SLEEP_BLOCKED, SLEEP_PENDING, SLEEP_DISABLED, SLEEP_SIGNAL, SLEEP_SIGNAL_RESTART,
    SLEEP_TIMEOUT, SLEEP_MASK_BLOCK, SLEEP_ZERO, SLEEP_READONLY, SLEEP_UNALIGNED,
    SLEEP_REMAINDER, SLEEP_ALIAS_REMAINDER, SLEEP_READONLY_REMAINDER, SLEEP_ERRORS
};
typedef int (*nanosleep_function)(const struct timespec *, struct timespec *);
typedef int (*clock_sleep_function)(clockid_t, int, const struct timespec *, struct timespec *);
static nanosleep_function selected_nanosleep, selected_thrd_sleep;
static clock_sleep_function selected_clock_sleep;
static unsigned (*selected_sleep)(unsigned);
static int (*selected_usleep)(useconds_t);

struct sleep_probe {
    struct state observed;
    enum sleep_api api;
    enum sleep_kind kind;
    const struct timespec *request;
    struct timespec *output;
    struct timespec remaining;
    int64_t started;
};

static int pin_sleep_provider(const char *expected, enum sleep_api api, int alias) {
    int rc = pin_providers(expected, 0, EVENT_NONE);
    if (rc != 0) return rc;
    const char *name = api == SLEEP_NANO ? (alias ? "__nanosleep" : "nanosleep") :
        api == SLEEP_CLOCK || api == SLEEP_ABSOLUTE ? (alias ? "__clock_nanosleep" : "clock_nanosleep") :
        api == SLEEP_SECONDS ? "sleep" : api == SLEEP_MICRO ? "usleep" : "thrd_sleep";
    struct stat wanted, actual;
    Dl_info info = {0};
    void *address = dlsym(RTLD_DEFAULT, name);
    if (stat(expected, &wanted) != 0 || address == NULL || !dladdr(address, &info) ||
        info.dli_fname == NULL || stat(info.dli_fname, &actual) != 0 ||
        actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
        fprintf(stderr, "pthread-native-poll:provider-mismatch:%s\n", name);
        return 86;
    }
    if (api == SLEEP_NANO) selected_nanosleep = (nanosleep_function)address;
    else if (api == SLEEP_CLOCK || api == SLEEP_ABSOLUTE)
        selected_clock_sleep = (clock_sleep_function)address;
    else if (api == SLEEP_SECONDS) selected_sleep = (unsigned (*)(unsigned))address;
    else if (api == SLEEP_MICRO) selected_usleep = (int (*)(useconds_t))address;
    else selected_thrd_sleep = (nanosleep_function)address;
    return 0;
}

static int invoke_sleep(const struct sleep_probe *probe, const struct timespec *request,
                        struct timespec *remaining) {
    switch (probe->api) {
    case SLEEP_NANO: return selected_nanosleep(request, remaining);
    case SLEEP_CLOCK: return selected_clock_sleep(CLOCK_REALTIME, 0, request, remaining);
    case SLEEP_ABSOLUTE:
        return selected_clock_sleep(CLOCK_MONOTONIC, TIMER_ABSTIME, request, remaining);
    case SLEEP_SECONDS: return (int)selected_sleep((unsigned)request->tv_sec);
    case SLEEP_MICRO:
        return selected_usleep((useconds_t)(request->tv_sec * 1000000 + request->tv_nsec / 1000));
    case SLEEP_C11: return selected_thrd_sleep(request, remaining);
    }
    fail("sleep API selection");
    return -1;
}

static void verify_sleep_error(const struct sleep_probe *probe, int result, int error,
                              int expected) {
    if (probe->api == SLEEP_CLOCK || probe->api == SLEEP_ABSOLUTE)
        REQUIRE(result == expected && error == EDOM, "clock_nanosleep returns errors without changing errno");
    else if (probe->api == SLEEP_C11)
        REQUIRE(result == (expected == EINTR ? -1 : -2) && error == EDOM,
                "thrd_sleep preserves errno and its distinct error convention");
    else
        REQUIRE(result == -1 && error == expected, "nanosleep/usleep errno convention");
}

static void sleep_errors(struct sleep_probe *probe) {
    const struct timespec invalid[] = {{-1, 0}, {0, 1000000000}};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        errno = EDOM;
        int result = invoke_sleep(probe, &invalid[i], &probe->remaining);
        verify_sleep_error(probe, result, errno, EINVAL);
    }
    errno = EDOM;
    int result = invoke_sleep(probe, (const struct timespec *)(uintptr_t)1, &probe->remaining);
    verify_sleep_error(probe, result, errno, EFAULT);
    struct timespec zero = {0, 0};
    errno = EDOM;
    REQUIRE(invoke_sleep(probe, &zero, (struct timespec *)(uintptr_t)1) == 0 && errno == EDOM,
            "successful zero/past sleep does not access remainder output");
    REQUIRE(probe->remaining.tv_sec == 71 && probe->remaining.tv_nsec == 72,
            "invalid sleep requests do not publish a remainder");
    if (probe->api == SLEEP_CLOCK || probe->api == SLEEP_ABSOLUTE) {
        errno = EDOM;
        REQUIRE(selected_clock_sleep(CLOCK_THREAD_CPUTIME_ID, 0, &zero, NULL) == EINVAL && errno == EDOM,
                "unsupported sleep clock retains original error convention");
    }
}

static void sleep_cleanup(void *argument) {
    struct sleep_probe *probe = argument;
    sigset_t mask;
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0 && sigismember(&mask, SIGUSR2) == 1,
            "sleep cleanup retains the original blocked signal");
    cleanup(&probe->observed);
}

static void *sleep_worker(void *argument) {
    struct sleep_probe *probe = argument;
    struct state *state = &probe->observed;
    capture_identity(state);
    REQUIRE(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0, "sleep deferred cancellation");
    if (probe->kind == SLEEP_DISABLED)
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0, "sleep disable cancellation");
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    if (probe->kind == SLEEP_MASK_BLOCK) sigaddset(&mask, SIGUSR1);
    REQUIRE(pthread_sigmask(SIG_SETMASK, &mask, NULL) == 0, "sleep worker signal mask");
    pthread_cleanup_push(sleep_cleanup, probe);
    atomic_store_explicit(&state->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&state->release, memory_order_acquire))
        (void)syscall(SYS_sched_yield);
    errno = EDOM;
    probe->started = monotonic_ns();
    if (probe->kind == SLEEP_ERRORS) {
        sleep_errors(probe);
        state->result = 0;
    } else {
        state->result = invoke_sleep(probe, probe->request, probe->output);
    }
    state->error = errno;
    state->elapsed_ns = monotonic_ns() - probe->started;
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0 && sigismember(&mask, SIGUSR2) == 1 &&
                sigismember(&mask, SIGUSR1) == (probe->kind == SLEEP_MASK_BLOCK),
            "sleep ordinary return restores the complete original signal mask");
    atomic_store_explicit(&state->returned, 1, memory_order_release);
    pthread_cleanup_pop(1);
    if (probe->kind == SLEEP_DISABLED) {
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0, "reenable sleep cancellation");
        pthread_testcancel();
        fail("disabled sleep lost its pending cancellation");
    }
    return state;
}

static void observe_sleep_parked(struct sleep_probe *probe, int memory) {
    struct state *state = &probe->observed;
    const int sliced = expect_native && probe->kind != SLEEP_DISABLED;
    int64_t deadline = monotonic_ns() + 2000000000;
    while (monotonic_ns() < deadline) {
        REQUIRE(!atomic_load_explicit(&state->returned, memory_order_acquire),
                "sleep returned before observation of its blocking syscall");
        char call[512], status[512];
        long number = -1;
        unsigned long long args[6] = {0};
        if (!read_proc(state, "syscall", call, sizeof(call)) ||
            sscanf(call, "%ld %llx %llx %llx %llx %llx %llx", &number,
                   &args[0], &args[1], &args[2], &args[3], &args[4], &args[5]) < 5)
            goto retry_sleep;
        struct timespec duration;
        if (sliced) {
            uint64_t mask;
            if (number != SYS_ppoll || args[0] != 0 || args[1] != 0 || args[2] == 0 || args[3] == 0 ||
                !snapshot(memory, args[2], &duration, sizeof(duration)) ||
                !snapshot(memory, args[3], &mask, sizeof(mask))) goto retry_sleep;
            REQUIRE(args[4] == sizeof(mask), "native sleep uses the kernel signal-mask width");
            REQUIRE(duration.tv_sec == 0 && duration.tv_nsec > 0 && duration.tv_nsec <= 50000000,
                    "native sleep blocks for a bounded nonzero quantum");
            REQUIRE(((mask >> (SIGUSR1 - 1)) & 1) == (uint64_t)(probe->kind == SLEEP_MASK_BLOCK) &&
                    ((mask >> (SIGUSR2 - 1)) & 1) == 1,
                    "native sleep submits the original signal mask atomically");
        } else {
            unsigned long long request = 0;
#ifdef SYS_nanosleep
            if (number == SYS_nanosleep) request = args[0];
#endif
            if (number == SYS_clock_nanosleep) request = args[2];
            if (request == 0 || !snapshot(memory, request, &duration, sizeof(duration))) goto retry_sleep;
            REQUIRE(duration.tv_sec > 0 || duration.tv_nsec > 0, "original sleep has a positive duration");
        }
        if (!read_proc(state, "stat", status, sizeof(status))) goto retry_sleep;
        char *end = strrchr(status, ')');
        if (end != NULL && end[1] == ' ' && end[2] == 'S') return;
retry_sleep:
        pause_briefly();
    }
    fail("no observed kernel sleep with the expected native/hosted arguments");
}

static int sleep_contract_main(char **argv) {
    const char *entry = case_name + 6;
    const char *prefixes[] = {"nano-", "clock-", "absolute-", "seconds-", "micro-", "c11-"};
    int api = -1;
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i)
        if (strncmp(entry, prefixes[i], strlen(prefixes[i])) == 0) { api = (int)i; entry += strlen(prefixes[i]); break; }
    if (api < 0) return 2;
    int alias = strncmp(entry, "alias-", 6) == 0;
    /* alias-remainder is a pointer-aliasing case, not an exported symbol. */
    if (strcmp(entry, "alias-remainder") == 0) alias = 0;
    if (alias) entry += 6;
    if (alias && api != SLEEP_NANO && api != SLEEP_CLOCK) return 2;
    const char *names[] = {"blocked", "pending", "disabled", "signal", "signal-restart", "timeout",
                          "mask-block", "zero", "readonly-request", "unaligned-request", "remainder",
                          "alias-remainder", "readonly-remainder", "errors"};
    int kind = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(entry, names[i]) == 0) kind = (int)i;
    if (kind < 0 || ((api == SLEEP_SECONDS || api == SLEEP_MICRO) && kind >= SLEEP_READONLY)) return 2;
    int pin = pin_sleep_provider(argv[2], (enum sleep_api)api, alias);
    if (pin != 0) return pin;
    expect_native = getenv("FRANKENLIBC_THREAD_NATIVE") != NULL &&
                    strcmp(getenv("FRANKENLIBC_THREAD_NATIVE"), "1") == 0;
    creator_tp = (uintptr_t)__builtin_thread_pointer();
    creator_tid = (pid_t)syscall(SYS_gettid);
    creator_thread = pthread_self();
    struct sigaction action = {0};
    action.sa_handler = user_signal;
    action.sa_flags = kind == SLEEP_SIGNAL_RESTART ? SA_RESTART : 0;
    sigemptyset(&action.sa_mask);
    REQUIRE(sigaction(SIGUSR1, &action, NULL) == 0, "install sleep signal handler");
    sleep_handler_delay = kind == SLEEP_REMAINDER;
    sigset_t unblocked;
    sigemptyset(&unblocked);
    REQUIRE(pthread_sigmask(SIG_SETMASK, &unblocked, NULL) == 0, "sleep creator signal mask");
    alarm(12);
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (memory < 0) skip("sleep-kernel-snapshot-unavailable");
    long page = sysconf(_SC_PAGESIZE);
    REQUIRE(page > 0, "sleep page size");
    unsigned char *storage = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(storage != MAP_FAILED, "sleep timeout mapping");
    int interrupted = kind == SLEEP_SIGNAL || kind == SLEEP_SIGNAL_RESTART || kind == SLEEP_REMAINDER ||
                      kind == SLEEP_ALIAS_REMAINDER || kind == SLEEP_READONLY_REMAINDER;
    struct timespec duration = {0, 250000000};
    if (kind == SLEEP_BLOCKED || kind == SLEEP_PENDING) duration = (struct timespec){60, 0};
    else if (interrupted) duration = (struct timespec){2, 0};
    else if (kind == SLEEP_ZERO || kind == SLEEP_ERRORS) duration = (struct timespec){0, 0};
    else if (api == SLEEP_SECONDS) duration = (struct timespec){1, 0};
    struct timespec request = duration;
    if (api == SLEEP_ABSOLUTE && kind != SLEEP_ZERO && kind != SLEEP_ERRORS) {
        int64_t end = monotonic_ns() + duration.tv_sec * 1000000000 + duration.tv_nsec;
        request = (struct timespec){end / 1000000000, end % 1000000000};
    }
    const size_t offset = kind == SLEEP_UNALIGNED ? 1 : 0;
    memcpy(storage + offset, &request, sizeof(request));
    const struct timespec sentinel = {71, 72};
    memcpy(storage + 64, &sentinel, sizeof(sentinel));
    REQUIRE(mprotect(storage, (size_t)page, PROT_READ) == 0, "protect sleep request and remainder controls");
    struct sleep_probe probe = {0};
    probe.api = (enum sleep_api)api;
    probe.kind = (enum sleep_kind)kind;
    probe.request = (const struct timespec *)(storage + offset);
    probe.remaining = sentinel;
    probe.output = &probe.remaining;
    probe.observed.kind = kind == SLEEP_MASK_BLOCK ? MASK_UNBLOCK : BLOCKED;
    if (kind == SLEEP_ALIAS_REMAINDER) {
        probe.remaining = request;
        probe.request = &probe.remaining;
    }
    if (kind == SLEEP_READONLY_REMAINDER) probe.output = (struct timespec *)(storage + 64);
    struct state *state = &probe.observed;
    REQUIRE(pthread_create(&state->thread, NULL, sleep_worker, &probe) == 0, "create sleep worker");
    wait_ready(state);
    if (kind == SLEEP_PENDING) REQUIRE(pthread_cancel(state->thread) == 0, "queue pending sleep cancellation");
    atomic_store_explicit(&state->release, 1, memory_order_release);
    if (kind != SLEEP_PENDING && kind != SLEEP_ZERO && kind != SLEEP_ERRORS)
        observe_sleep_parked(&probe, memory);
    if (kind == SLEEP_BLOCKED || kind == SLEEP_DISABLED) {
        REQUIRE(pthread_cancel(state->thread) == 0, "cancel observed kernel sleep");
        if (kind == SLEEP_DISABLED) {
            observe_sleep_parked(&probe, memory);
            REQUIRE(atomic_load_explicit(&state->cleaned, memory_order_acquire) == 0,
                    "disabled sleep cancellation cannot run cleanup early");
        }
    } else if (interrupted || kind == SLEEP_MASK_BLOCK) {
        REQUIRE(pthread_kill(state->thread, SIGUSR1) == 0, "send sleep user signal");
    }
    void *result = join_bounded(state);
    int canceled = kind == SLEEP_BLOCKED || kind == SLEEP_PENDING || kind == SLEEP_DISABLED;
    REQUIRE(result == (canceled ? PTHREAD_CANCELED : (void *)state), "sleep thread result");
    REQUIRE(atomic_load_explicit(&state->cleaned, memory_order_acquire) == 1, "sleep cleanup exactly once");
    REQUIRE(atomic_load_explicit(&state->returned, memory_order_acquire) == (!canceled || kind == SLEEP_DISABLED),
            "sleep return versus cancellation");
    if (interrupted) {
        int expected = kind == SLEEP_READONLY_REMAINDER && api != SLEEP_ABSOLUTE ? EFAULT : EINTR;
        if (api == SLEEP_SECONDS)
            REQUIRE(state->result == 1 && state->error == EINTR,
                    "sleep truncates fractional unslept seconds as GNU does");
        else verify_sleep_error(&probe, state->result, state->error, expected);
        REQUIRE(atomic_load_explicit(&signals_delivered, memory_order_relaxed) == 1,
                "sleep interruption invokes one signal handler without SA_RESTART retry");
        if (api == SLEEP_ABSOLUTE)
            REQUIRE(probe.remaining.tv_sec == (kind == SLEEP_ALIAS_REMAINDER ? request.tv_sec : 71) &&
                        probe.remaining.tv_nsec == (kind == SLEEP_ALIAS_REMAINDER ? request.tv_nsec : 72),
                    "absolute sleep leaves the remainder unused");
        else if (api != SLEEP_SECONDS && api != SLEEP_MICRO && kind != SLEEP_READONLY_REMAINDER) {
            int64_t left = probe.remaining.tv_sec * 1000000000 + probe.remaining.tv_nsec;
            REQUIRE(probe.remaining.tv_sec >= 0 && probe.remaining.tv_nsec >= 0 &&
                        probe.remaining.tv_nsec < 1000000000 && left > 0 && left < 2000000000,
                    "interrupted relative sleep publishes a normalized unslept duration");
        }
        if (kind == SLEEP_REMAINDER && api != SLEEP_ABSOLUTE) {
            int64_t onset = atomic_load_explicit(&sleep_signal_started, memory_order_relaxed);
            int64_t ended = atomic_load_explicit(&sleep_signal_finished, memory_order_relaxed);
            int64_t expected_left = 2000000000 - (onset - probe.started);
            int64_t left = probe.remaining.tv_sec * 1000000000 + probe.remaining.tv_nsec;
            REQUIRE(ended - onset >= 300000000, "long handler actually consumed wall time");
            REQUIRE(llabs(left - expected_left) < 100000000,
                    "remaining duration excludes signal handler time rather than recomputing after it");
        }
    } else if (!canceled || kind == SLEEP_DISABLED) {
        REQUIRE(state->result == 0, "sleep reaches its finite deadline");
        if (kind != SLEEP_ZERO && kind != SLEEP_ERRORS)
            REQUIRE(state->elapsed_ns >= (api == SLEEP_SECONDS ? 900000000 : 200000000) &&
                        state->elapsed_ns < 2000000000,
                    "sleep finite deadline spans quanta without early return or repeated-duration drift");
    }
    if (!interrupted) {
        /* GNU's cancellation signal can make the kernel write a remainder
         * before forced unwind begins. Only successful sleeps and requests
         * canceled before entering the syscall promise this untouched output. */
        if (!canceled || kind == SLEEP_DISABLED || kind == SLEEP_PENDING)
            REQUIRE(probe.remaining.tv_sec == 71 && probe.remaining.tv_nsec == 72,
                    "successful and pending-canceled sleeps leave remainder output untouched");
        REQUIRE(atomic_load_explicit(&signals_delivered, memory_order_relaxed) == 0,
                "blocked sleep signals remain blocked across quanta and thread exit");
    }
    REQUIRE(memcmp(storage + offset, &request, sizeof(request)) == 0,
            "sleep never changes the caller's const request");
    REQUIRE(memcmp(storage + 64, &sentinel, sizeof(sentinel)) == 0,
            "read-only sleep remainder control remains untouched");
    REQUIRE(munmap(storage, (size_t)page) == 0 && close(memory) == 0, "release sleep fixture resources");
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}

static int select_contract_main(char **argv) {
    enum select_api api = strncmp(case_name, "pselect-", 8) == 0 ? SELECT_MASK : SELECT_PLAIN;
    const char *suffix = case_name + (api == SELECT_MASK ? 8 : 7);
    int alias = strncmp(suffix, "alias-", 6) == 0;
    if (alias) suffix += 6;
    const char *names[] = {"blocked", "pending", "disabled", "signal", "signal-restart", "ready",
                          "reuse", "mask-unblock", "mask-block", "readonly-timeout", "empty-blocked",
                          "mask-cancel", "mask-cancel-block", "timeout", "ready-late",
                          "edge-ready", "errors"};
    int index = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(suffix, names[i]) == 0) index = (int)i;
    int remainder = strcmp(suffix, "remainder") == 0;
    if (remainder) index = SIGNAL;
    if (index < 0 || index == EDGE_READY || (api == SELECT_PLAIN &&
        ((index >= MASK_UNBLOCK && index <= READONLY_TIMEOUT) ||
         index == MASK_CANCEL || index == MASK_CANCEL_BLOCK))) return 2;
    enum kind kind = (enum kind)index;
    int pin = pin_providers(argv[2], 0, EVENT_NONE);
    if (pin != 0) return pin;
    const char *name = api == SELECT_MASK ? (alias ? "__pselect" : "pselect") :
                                          (alias ? "__select" : "select");
    void *address = dlsym(RTLD_DEFAULT, name);
    struct stat wanted, actual;
    Dl_info info = {0};
    if (stat(argv[2], &wanted) != 0 || address == NULL || !dladdr(address, &info) ||
        info.dli_fname == NULL || stat(info.dli_fname, &actual) != 0 ||
        actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
        fprintf(stderr, "pthread-native-poll:provider-mismatch:%s\n", name);
        return 86;
    }
    if (api == SELECT_MASK) selected_pselect = (pselect_function)address;
    else selected_select = (select_function)address;
    expect_native = getenv("FRANKENLIBC_THREAD_NATIVE") != NULL &&
                    strcmp(getenv("FRANKENLIBC_THREAD_NATIVE"), "1") == 0;
    creator_tp = (uintptr_t)__builtin_thread_pointer();
    creator_tid = (pid_t)syscall(SYS_gettid);
    creator_thread = pthread_self();
    sleep_handler_delay = remainder;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = user_signal;
    action.sa_flags = kind == SIGNAL_RESTART ? SA_RESTART : 0;
    sigemptyset(&action.sa_mask);
    REQUIRE(sigaction(SIGUSR1, &action, NULL) == 0, "install select signal handler");
    sigset_t unblocked;
    sigemptyset(&unblocked);
    REQUIRE(pthread_sigmask(SIG_SETMASK, &unblocked, NULL) == 0, "creator signal mask");
    alarm(15);
    int pipefd[2];
    REQUIRE(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) == 0, "create select application pipe");
    int high = fcntl(pipefd[0], F_DUPFD_CLOEXEC, 130);
    REQUIRE(high >= 130 && high < FD_SETSIZE - 64 && close(pipefd[0]) == 0,
            "watch a descriptor beyond the first two fd-set words");
    pipefd[0] = high;
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (memory < 0) skip("kernel-select-mask-snapshot-unavailable");
    long page = sysconf(_SC_PAGESIZE);
    REQUIRE(page > 0, "page size");
    struct timespec *timeout = mmap(NULL, 2 * (size_t)page, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(timeout != MAP_FAILED, "map select timeout storage");
    *timeout = kind == READONLY_TIMEOUT ? (struct timespec){0, 500000000} :
               kind == FINITE_TIMEOUT || remainder ? (struct timespec){0, 250000000} :
               kind == READY_LATE ? (struct timespec){1, 0} : (struct timespec){60, 0};
    struct timespec expected = *timeout;
    REQUIRE(mprotect(timeout, (size_t)page, PROT_READ) == 0, "protect pselect timeout storage");
    REQUIRE(mprotect((char *)timeout + page, (size_t)page, PROT_NONE) == 0,
            "protect page after kernel-width select mask");
    guarded_mask = (const sigset_t *)((const char *)timeout + page - sizeof(uint64_t));
    struct state state;
    if (kind == REUSE) {
        initialize_select(&state, READY, pipefd, timeout, api, 0);
        run_case(&state, memory);
        size_t before = descriptor_count();
        for (int round = 0; round < 8; ++round) {
            initialize_select(&state, BLOCKED, pipefd, timeout, api, 0);
            run_case(&state, memory);
            REQUIRE(descriptor_count() == before, "retired select thread leaked a descriptor");
            initialize_select(&state, READY, pipefd, timeout, api, 0);
            run_case(&state, memory);
            REQUIRE(descriptor_count() == before, "select replacement inherited cancellation or leaked");
        }
    } else {
        initialize_select(&state, kind, pipefd, timeout, api, remainder);
        run_case(&state, memory);
    }
    REQUIRE(timeout->tv_sec == expected.tv_sec && timeout->tv_nsec == expected.tv_nsec,
            "pselect must not change the caller's const timeout");
    REQUIRE(munmap(timeout, 2 * (size_t)page) == 0, "release select timeout storage");
    REQUIRE(close(memory) == 0 && close(pipefd[0]) == 0 && close(pipefd[1]) == 0,
            "release select fixture descriptors");
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}

enum suspend_kind {
    SUSPEND_PENDING, SUSPEND_BLOCKED, SUSPEND_DISABLED, SUSPEND_SIGNAL,
    SUSPEND_SIGNAL_RESTART, SUSPEND_MASK_BLOCK, SUSPEND_MASK_UNBLOCK,
    SUSPEND_MASK_CANCEL, SUSPEND_MASK_CANCEL_BLOCK, SUSPEND_ERRORS, SUSPEND_GUARDED
};
static int (*selected_pause)(void);
static int (*selected_sigsuspend)(const sigset_t *);
static _Atomic int suspend_usr1, suspend_usr2;

struct suspend_probe {
    struct state observed;
    enum suspend_kind kind;
    int use_mask, original_usr1, temporary_usr1;
    sigset_t original, temporary;
    const sigset_t *argument;
};

static void suspend_signal(int signo) {
    if (signo == SIGUSR1)
        atomic_fetch_add_explicit(&suspend_usr1, 1, memory_order_relaxed);
    else if (signo == SIGUSR2)
        atomic_fetch_add_explicit(&suspend_usr2, 1, memory_order_relaxed);
}

static int pin_suspend_provider(const char *expected, int use_mask, int alias) {
    int rc = pin_providers(expected, 0, EVENT_NONE);
    if (rc != 0) return rc;
    const char *name = use_mask ? (alias ? "__sigsuspend" : "sigsuspend") :
                                 (alias ? "__pause" : "pause");
    void *address = dlsym(RTLD_DEFAULT, name);
    struct stat wanted, actual;
    Dl_info info = {0};
    if (stat(expected, &wanted) != 0 || address == NULL || !dladdr(address, &info) ||
        info.dli_fname == NULL || stat(info.dli_fname, &actual) != 0 ||
        actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
        fprintf(stderr, "pthread-native-poll:provider-mismatch:%s\n", name);
        return 86;
    }
    if (use_mask) selected_sigsuspend = (int (*)(const sigset_t *))address;
    else selected_pause = (int (*)(void))address;
    return 0;
}

static void suspend_check_mask(int usr1, const char *message) {
    sigset_t current;
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &current) == 0, "query suspend signal mask");
    if (sigismember(&current, SIGUSR1) != usr1 || sigismember(&current, SIGUSR2) != 0 ||
        sigismember(&current, SIGTERM) != 1)
        fprintf(stderr, "suspend-mask:USR1=%d expected=%d USR2=%d TERM=%d handlers=%d/%d\n",
                sigismember(&current, SIGUSR1), usr1, sigismember(&current, SIGUSR2),
                sigismember(&current, SIGTERM),
                atomic_load_explicit(&suspend_usr1, memory_order_relaxed),
                atomic_load_explicit(&suspend_usr2, memory_order_relaxed));
    REQUIRE(sigismember(&current, SIGUSR1) == usr1 &&
                sigismember(&current, SIGUSR2) == 0 && sigismember(&current, SIGTERM) == 1,
            message);
}

static void suspend_cleanup(void *argument) {
    struct suspend_probe *probe = argument;
    /* Observed GNU 2.41 restores the entry mask before sigsuspend cancellation
       cleanup, including delivery of a signal blocked only by the wait mask. */
    suspend_check_mask(probe->original_usr1, "suspend cleanup restores the original mask");
    if (probe->kind == SUSPEND_MASK_CANCEL_BLOCK)
        REQUIRE(atomic_load_explicit(&suspend_usr1, memory_order_relaxed) == 1,
                "suspend cancellation delivers a signal unblocked by the restored original mask");
    REQUIRE(atomic_fetch_add_explicit(&probe->observed.cleaned, 1, memory_order_release) == 0,
            "suspend cleanup runs exactly once");
}

static void *suspend_worker(void *argument) {
    struct suspend_probe *probe = argument;
    struct state *state = &probe->observed;
    capture_identity(state);
    REQUIRE(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0, "suspend deferred cancellation");
    if (probe->kind == SUSPEND_DISABLED)
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0, "disable suspend cancellation");
    REQUIRE(pthread_sigmask(SIG_SETMASK, &probe->original, NULL) == 0, "install suspend entry mask");
    pthread_cleanup_push(suspend_cleanup, probe);
    atomic_store_explicit(&state->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&state->release, memory_order_acquire))
        (void)syscall(SYS_sched_yield);
    errno = EDOM;
    if (probe->kind == SUSPEND_ERRORS) {
        const sigset_t *invalid[] = {
            NULL, (const sigset_t *)(uintptr_t)1,
            (const sigset_t *)((const unsigned char *)probe->argument + 1)
        };
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
            errno = EDOM;
            REQUIRE(selected_sigsuspend(invalid[i]) == -1 && errno == EFAULT,
                    "sigsuspend reports EFAULT for null, unreadable and truncated kernel masks");
            suspend_check_mask(probe->original_usr1, "sigsuspend mask faults preserve the entry mask");
        }
        state->result = 0;
    } else {
        state->result = probe->use_mask ? selected_sigsuspend(probe->argument) : selected_pause();
    }
    state->error = errno;
    suspend_check_mask(probe->original_usr1, "suspend ordinary return restores the original mask");
    atomic_store_explicit(&state->returned, 1, memory_order_release);
    pthread_cleanup_pop(1);
    if (probe->kind == SUSPEND_DISABLED) {
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0, "reenable suspend cancellation");
        pthread_testcancel();
        fail("disabled suspend lost its pending cancellation");
    }
    return state;
}

static void observe_suspend_parked(struct suspend_probe *probe, int memory) {
    struct state *state = &probe->observed;
    const int sliced = expect_native && probe->kind != SUSPEND_DISABLED;
    int64_t deadline = monotonic_ns() + 2000000000;
    while (monotonic_ns() < deadline) {
        REQUIRE(!atomic_load_explicit(&state->returned, memory_order_acquire),
                "suspend returned before its intended blocked syscall");
        char call[512], status[512];
        long number = -1;
        unsigned long long args[6] = {0};
        if (!read_proc(state, "syscall", call, sizeof(call)) ||
            sscanf(call, "%ld %llx %llx %llx %llx %llx %llx", &number,
                   &args[0], &args[1], &args[2], &args[3], &args[4], &args[5]) < 3)
            goto retry_suspend;
        uint64_t mask = 0;
        if (sliced) {
            struct timespec quantum;
            if (number != SYS_ppoll || args[0] != 0 || args[1] != 0 ||
                args[2] == 0 || args[3] == 0 ||
                !snapshot(memory, args[2], &quantum, sizeof(quantum)) ||
                !snapshot(memory, args[3], &mask, sizeof(mask))) goto retry_suspend;
            REQUIRE(args[4] == sizeof(mask), "native suspend uses the kernel signal-mask width");
            REQUIRE(quantum.tv_sec == 0 && quantum.tv_nsec > 0 && quantum.tv_nsec <= 50000000,
                    "native suspend uses a bounded nonzero no-descriptor ppoll quantum");
        } else if (probe->use_mask) {
            if (number != SYS_rt_sigsuspend || args[0] == 0 || args[1] != sizeof(mask) ||
                !snapshot(memory, args[0], &mask, sizeof(mask))) goto retry_suspend;
        } else {
#ifdef SYS_pause
            if (number != SYS_pause) goto retry_suspend;
#else
            if (number != SYS_ppoll || args[0] != 0 || args[1] != 0 || args[2] != 0 || args[3] != 0)
                goto retry_suspend;
#endif
        }
        if (sliced || probe->use_mask)
            REQUIRE(((mask >> (SIGUSR1 - 1)) & 1) == (uint64_t)probe->temporary_usr1 &&
                    ((mask >> (SIGUSR2 - 1)) & 1) == 0 && ((mask >> (SIGTERM - 1)) & 1) == 1,
                    "suspend atomically submits the intended signal mask");
        if (!read_proc(state, "stat", status, sizeof(status))) goto retry_suspend;
        char *end = strrchr(status, ')');
        if (end != NULL && end[1] == ' ' && end[2] == 'S') return;
retry_suspend:
        pause_briefly();
    }
    fail("no observed sleeping pause/sigsuspend syscall with the intended mask");
}

static int suspend_contract_main(char **argv) {
    const int use_mask = strncmp(case_name, "sigsuspend-", 11) == 0;
    const char *suffix = case_name + (use_mask ? 11 : 6);
    const int alias = strncmp(suffix, "alias-", 6) == 0;
    if (alias) suffix += 6;
    const char *names[] = {"pending", "blocked", "disabled", "signal", "signal-restart", "mask-block",
                          "mask-unblock", "mask-cancel", "mask-cancel-block", "errors", "guarded-mask"};
    int kind = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(suffix, names[i]) == 0) kind = (int)i;
    if (kind < 0 || (!use_mask && kind > SUSPEND_MASK_BLOCK)) return 2;
    int pin = pin_suspend_provider(argv[2], use_mask, alias);
    if (pin != 0) return pin;
    expect_native = getenv("FRANKENLIBC_THREAD_NATIVE") != NULL &&
                    strcmp(getenv("FRANKENLIBC_THREAD_NATIVE"), "1") == 0;
    creator_tp = (uintptr_t)__builtin_thread_pointer();
    creator_tid = (pid_t)syscall(SYS_gettid);
    creator_thread = pthread_self();
    struct sigaction action = {0};
    action.sa_handler = suspend_signal;
    action.sa_flags = kind == SUSPEND_SIGNAL_RESTART ? SA_RESTART : 0;
    sigemptyset(&action.sa_mask);
    REQUIRE(sigaction(SIGUSR1, &action, NULL) == 0 && sigaction(SIGUSR2, &action, NULL) == 0,
            "install suspend signal handlers");
    sigset_t empty;
    sigemptyset(&empty);
    REQUIRE(pthread_sigmask(SIG_SETMASK, &empty, NULL) == 0, "suspend creator signal mask");
    alarm(12);
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (memory < 0) skip("suspend-kernel-snapshot-unavailable");
    struct suspend_probe probe = {0};
    probe.use_mask = use_mask;
    probe.kind = (enum suspend_kind)kind;
    probe.original_usr1 = use_mask ? kind != SUSPEND_MASK_BLOCK && kind != SUSPEND_MASK_CANCEL_BLOCK :
                                   kind == SUSPEND_MASK_BLOCK;
    probe.temporary_usr1 = kind == SUSPEND_MASK_BLOCK || kind == SUSPEND_MASK_CANCEL_BLOCK;
    sigemptyset(&probe.original);
    sigemptyset(&probe.temporary);
    sigaddset(&probe.original, SIGTERM);
    sigaddset(&probe.temporary, SIGTERM);
    if (probe.original_usr1) sigaddset(&probe.original, SIGUSR1);
    if (probe.temporary_usr1) sigaddset(&probe.temporary, SIGUSR1);
    probe.argument = &probe.temporary;
    unsigned char *storage = NULL;
    long page = 0;
    uint64_t expected_mask = 0;
    if (kind == SUSPEND_ERRORS || kind == SUSPEND_GUARDED) {
        page = sysconf(_SC_PAGESIZE);
        REQUIRE(page > 0, "suspend mask page size");
        storage = mmap(NULL, 2 * (size_t)page, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(storage != MAP_FAILED, "map suspend kernel-width signal mask");
        memcpy(&expected_mask, &probe.temporary, sizeof(expected_mask));
        memcpy(storage + page - sizeof(expected_mask), &expected_mask, sizeof(expected_mask));
        REQUIRE(mprotect(storage, (size_t)page, PROT_READ) == 0 &&
                mprotect(storage + page, (size_t)page, PROT_NONE) == 0,
                "protect exact eight-byte suspend mask and following guard page");
        probe.argument = (const sigset_t *)(storage + page - sizeof(expected_mask));
    }
    struct state *state = &probe.observed;
    REQUIRE(pthread_create(&state->thread, NULL, suspend_worker, &probe) == 0, "create suspend worker");
    wait_ready(state);
    if (kind == SUSPEND_PENDING)
        REQUIRE(pthread_cancel(state->thread) == 0, "queue pending suspend cancellation");
    const int immediate_signal = kind == SUSPEND_MASK_UNBLOCK || kind == SUSPEND_GUARDED;
    if (immediate_signal)
        REQUIRE(pthread_kill(state->thread, SIGUSR1) == 0, "queue signal blocked before atomic suspend");
    atomic_store_explicit(&state->release, 1, memory_order_release);
    if (kind != SUSPEND_PENDING && kind != SUSPEND_ERRORS && !immediate_signal)
        observe_suspend_parked(&probe, memory);
    if (kind == SUSPEND_MASK_BLOCK || kind == SUSPEND_MASK_CANCEL_BLOCK) {
        REQUIRE(pthread_kill(state->thread, SIGUSR1) == 0, "queue signal blocked by suspend mask");
        int64_t held_until = monotonic_ns() + 220000000;
        do {
            observe_suspend_parked(&probe, memory);
            REQUIRE(atomic_load_explicit(&suspend_usr1, memory_order_relaxed) == 0,
                    "suspend holds a blocked signal across successive wait quanta");
            pause_briefly();
        } while (monotonic_ns() < held_until);
    }
    if (kind == SUSPEND_BLOCKED || kind == SUSPEND_DISABLED || kind == SUSPEND_MASK_CANCEL ||
        kind == SUSPEND_MASK_CANCEL_BLOCK) {
        REQUIRE(pthread_cancel(state->thread) == 0, "cancel an observed blocked suspend");
        if (kind == SUSPEND_DISABLED) {
            observe_suspend_parked(&probe, memory);
            REQUIRE(atomic_load_explicit(&state->cleaned, memory_order_acquire) == 0,
                    "disabled suspend cancellation does not run cleanup");
            REQUIRE(pthread_kill(state->thread, SIGUSR1) == 0, "interrupt disabled suspend with a caught signal");
        }
    } else if (kind == SUSPEND_SIGNAL || kind == SUSPEND_SIGNAL_RESTART || kind == SUSPEND_MASK_BLOCK) {
        REQUIRE(pthread_kill(state->thread, kind == SUSPEND_MASK_BLOCK ? SIGUSR2 : SIGUSR1) == 0,
                "interrupt observed suspend with an unblocked signal");
    }
    void *result = join_bounded(state);
    const int canceled = kind == SUSPEND_PENDING || kind == SUSPEND_BLOCKED || kind == SUSPEND_DISABLED ||
                         kind == SUSPEND_MASK_CANCEL || kind == SUSPEND_MASK_CANCEL_BLOCK;
    REQUIRE(result == (canceled ? PTHREAD_CANCELED : (void *)state), "suspend thread result");
    REQUIRE(atomic_load_explicit(&state->cleaned, memory_order_acquire) == 1, "one suspend cleanup");
    REQUIRE(atomic_load_explicit(&state->returned, memory_order_acquire) == (!canceled || kind == SUSPEND_DISABLED),
            "suspend return versus cancellation");
    if (kind != SUSPEND_ERRORS && (!canceled || kind == SUSPEND_DISABLED))
        REQUIRE(state->result == -1 && state->error == EINTR,
                "caught signals interrupt pause/sigsuspend even with SA_RESTART");
    const int usr1 = kind == SUSPEND_DISABLED || kind == SUSPEND_SIGNAL || kind == SUSPEND_SIGNAL_RESTART ||
                     immediate_signal || (use_mask && kind == SUSPEND_MASK_BLOCK) ||
                     kind == SUSPEND_MASK_CANCEL_BLOCK;
    REQUIRE(atomic_load_explicit(&suspend_usr1, memory_order_relaxed) == usr1 &&
            atomic_load_explicit(&suspend_usr2, memory_order_relaxed) == (kind == SUSPEND_MASK_BLOCK),
            "suspend invokes exactly the expected unblocked signal handlers");
    if (storage != NULL) {
        REQUIRE(memcmp(storage + page - sizeof(expected_mask), &expected_mask, sizeof(expected_mask)) == 0,
                "sigsuspend preserves its const eight-byte input mask");
        REQUIRE(munmap(storage, 2 * (size_t)page) == 0, "release suspend signal-mask mapping");
    }
    REQUIRE(close(memory) == 0, "close suspend kernel observation descriptor");
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}

/* Receives use per-call nonblocking probes only. Unlike readiness tests, these
 * cases also check that bytes/datagrams are neither consumed by cancellation
 * nor lost when another receiver wins the readiness race. */
enum receive_kind {
    RECEIVE_BLOCKED, RECEIVE_PENDING, RECEIVE_DISABLED, RECEIVE_READY,
    RECEIVE_READY_LATE, RECEIVE_PEEK, RECEIVE_NONBLOCK, RECEIVE_DONTWAIT,
    RECEIVE_TIMEOUT, RECEIVE_SIGNAL, RECEIVE_SIGNAL_RESTART, RECEIVE_COMPETING,
    RECEIVE_WAITALL, RECEIVE_LOWAT, RECEIVE_EOF, RECEIVE_ZERO, RECEIVE_ERRORS,
    RECEIVE_LENGTH_ZERO, RECEIVE_TRUNCATE
};
struct receive_probe {
    struct state observed;
    enum receive_kind kind;
    int fd, from, fortified, flags;
    size_t length;
    unsigned char data[8];
    struct sockaddr_storage address;
    socklen_t address_length;
};
static ssize_t (*selected_recv)(int, void *, size_t, int);
static ssize_t (*selected_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static ssize_t (*selected_recv_chk)(int, void *, size_t, size_t, int);
static ssize_t (*selected_recvfrom_chk)(int, void *, size_t, size_t, int,
                                      struct sockaddr *, socklen_t *);

static int pin_receive_provider(const char *expected, int from, int alias, int fortified) {
    int base = pin_providers(expected, 0, EVENT_NONE);
    if (base != 0) return base;
    const char *name = from ? (fortified ? "__recvfrom_chk" : "recvfrom") :
                             fortified ? "__recv_chk" : alias ? "__recv" : "recv";
    Dl_info info = {0};
    struct stat actual, wanted;
    void *symbol = dlsym(RTLD_DEFAULT, name);
    if (!symbol || !dladdr(symbol, &info) || !info.dli_fname ||
        stat(expected, &wanted) || stat(info.dli_fname, &actual) ||
        actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
        fprintf(stderr, "pthread-native-poll:provider-mismatch:%s\n", name);
        return 86;
    }
    if (from && fortified) selected_recvfrom_chk = (__typeof__(selected_recvfrom_chk))symbol;
    else if (from) selected_recvfrom = (__typeof__(selected_recvfrom))symbol;
    else if (fortified) selected_recv_chk = (__typeof__(selected_recv_chk))symbol;
    else selected_recv = (__typeof__(selected_recv))symbol;
    return 0;
}

static ssize_t receive_call(struct receive_probe *probe) {
    if (probe->from && probe->fortified)
        return selected_recvfrom_chk(probe->fd, probe->data, probe->length, sizeof(probe->data),
                                     probe->flags, (struct sockaddr *)&probe->address,
                                     &probe->address_length);
    if (probe->from)
        return selected_recvfrom(probe->fd, probe->data, probe->length, probe->flags,
                                 (struct sockaddr *)&probe->address, &probe->address_length);
    if (probe->fortified)
        return selected_recv_chk(probe->fd, probe->data, probe->length, sizeof(probe->data),
                                 probe->flags);
    return selected_recv(probe->fd, probe->data, probe->length, probe->flags);
}

static void receive_cleanup(void *argument) {
    struct receive_probe *probe = argument;
    sigset_t mask;
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0 &&
                sigismember(&mask, SIGUSR1) == 0 && sigismember(&mask, SIGUSR2) == 1,
            "receive cleanup preserves the complete original signal mask");
    REQUIRE(atomic_fetch_add_explicit(&probe->observed.cleaned, 1, memory_order_release) == 0,
            "receive cleanup executes exactly once");
}

static void *receive_worker(void *argument) {
    struct receive_probe *probe = argument;
    struct state *state = &probe->observed;
    capture_identity(state);
    REQUIRE(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0,
            "deferred receive cancellation");
    if (probe->kind == RECEIVE_DISABLED)
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0,
                "disable receive cancellation");
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    REQUIRE(pthread_sigmask(SIG_SETMASK, &mask, NULL) == 0, "receive entry signal mask");
    pthread_cleanup_push(receive_cleanup, probe);
    atomic_store_explicit(&state->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&state->release, memory_order_acquire))
        (void)syscall(SYS_sched_yield);
    errno = EDOM;
    int64_t started = monotonic_ns();
    if (probe->kind == RECEIVE_ERRORS) {
        int original = probe->fd;
        probe->fd = -1;
        REQUIRE(receive_call(probe) == -1 && errno == EBADF, "invalid receive fd retains EBADF");
        int pipefd[2];
        REQUIRE(pipe(pipefd) == 0, "receive error pipe");
        probe->fd = pipefd[0];
        REQUIRE(receive_call(probe) == -1 && errno == ENOTSOCK,
                "receive metadata probes do not replace ENOTSOCK");
        REQUIRE(close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "close receive error pipe");
        probe->fd = original;
        state->result = 0;
    } else {
        state->result = (int)receive_call(probe);
    }
    state->error = errno;
    state->elapsed_ns = monotonic_ns() - started;
    atomic_store_explicit(&state->returned, 1, memory_order_release);
    pthread_cleanup_pop(1);
    if (probe->kind == RECEIVE_DISABLED) {
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0,
                "reenable receive cancellation");
        pthread_testcancel();
        fail("disabled receive lost its pending cancellation");
    }
    return state;
}

static void observe_receive_parked(struct receive_probe *probe, int memory) {
    struct state *state = &probe->observed;
    int sliced = expect_native && probe->kind != RECEIVE_DISABLED &&
                 probe->kind != RECEIVE_TIMEOUT && probe->kind != RECEIVE_WAITALL &&
                 probe->kind != RECEIVE_LOWAT && probe->kind != RECEIVE_SIGNAL &&
                 probe->kind != RECEIVE_SIGNAL_RESTART;
    int64_t deadline = monotonic_ns() + 2000000000;
    while (monotonic_ns() < deadline) {
        REQUIRE(!atomic_load_explicit(&state->returned, memory_order_acquire),
                "receive returned before its intended blocked operation");
        char call[512], status[512];
        long number = -1;
        unsigned long long args[6] = {0};
        if (!read_proc(state, "syscall", call, sizeof(call)) ||
            sscanf(call, "%ld %llx %llx %llx %llx %llx %llx", &number,
                   &args[0], &args[1], &args[2], &args[3], &args[4], &args[5]) < 5)
            goto retry_receive;
        if (sliced) {
            struct pollfd interest;
            struct timespec duration;
            uint64_t mask;
            if (number != SYS_ppoll || args[1] != 1 ||
                !snapshot(memory, args[0], &interest, sizeof(interest)) ||
                interest.fd != probe->fd || interest.events != POLLIN ||
                args[2] == 0 || !snapshot(memory, args[2], &duration, sizeof(duration)) ||
                args[3] == 0 || !snapshot(memory, args[3], &mask, sizeof(mask))) goto retry_receive;
            REQUIRE(duration.tv_sec == 0 && duration.tv_nsec > 0 && duration.tv_nsec <= 50000000,
                    "native receive waits in bounded nonzero slices");
            REQUIRE(args[4] == sizeof(mask) && ((mask >> (SIGUSR2 - 1)) & 1) == 1 &&
                        ((mask >> (SIGUSR1 - 1)) & 1) == 0,
                    "native receive atomically reinstates the complete original mask");
        } else if (number != SYS_recvfrom || args[0] != (unsigned)probe->fd ||
                   args[1] != (uintptr_t)probe->data || args[2] != probe->length) {
            goto retry_receive;
        }
        if (!read_proc(state, "stat", status, sizeof(status))) goto retry_receive;
        char *end = strrchr(status, ')');
        if (end != NULL && end[1] == ' ' && end[2] == 'S') return;
retry_receive:
        pause_briefly();
    }
    fail("no observed socket receive with the expected native/hosted wait arguments");
}

static void send_receive_bytes(int fd, const char *bytes, size_t length) {
    REQUIRE(syscall(SYS_sendto, fd, bytes, length, MSG_NOSIGNAL, NULL, 0) == (ssize_t)length,
            "send exact receive payload");
}

static void receive_initialize(struct receive_probe *probe, enum receive_kind kind,
                               int fd, int from, int fortified) {
    memset(probe, 0, sizeof(*probe));
    probe->kind = kind;
    probe->fd = fd;
    probe->from = from;
    probe->fortified = fortified;
    probe->flags = kind == RECEIVE_PEEK ? MSG_PEEK :
                   kind == RECEIVE_DONTWAIT ? MSG_DONTWAIT :
                   kind == RECEIVE_WAITALL ? MSG_WAITALL :
                   kind == RECEIVE_TRUNCATE ? MSG_TRUNC : 0;
    probe->length = kind == RECEIVE_LENGTH_ZERO ? 0 :
                    kind == RECEIVE_WAITALL || kind == RECEIVE_LOWAT ? 4 : 1;
    probe->address_length = sizeof(probe->address);
    memset(probe->data, 0xa5, sizeof(probe->data));
    memset(&probe->address, 0xa5, sizeof(probe->address));
    probe->observed.result = -222;
    atomic_init(&probe->observed.ready, 0);
    atomic_init(&probe->observed.release, 0);
    atomic_init(&probe->observed.returned, 0);
    atomic_init(&probe->observed.cleaned, 0);
}

static void check_received_payload(const struct receive_probe *probe,
                                   const struct sockaddr_in *peer) {
    int expected = probe->kind == RECEIVE_TRUNCATE ? 4 : (int)probe->length;
    REQUIRE(probe->observed.result == expected && probe->observed.error == EDOM,
            "receive returns exact payload length without changing errno");
    REQUIRE(memcmp(probe->data, "DATA", probe->length) == 0,
            "receive preserves payload bytes");
    for (size_t i = probe->length; i < sizeof(probe->data); ++i)
        REQUIRE(probe->data[i] == 0xa5, "receive leaves trailing buffer bytes alone");
    if (probe->from) {
        const struct sockaddr_in *address = (const struct sockaddr_in *)&probe->address;
        REQUIRE(probe->address_length == sizeof(*address) && address->sin_family == AF_INET &&
                    address->sin_addr.s_addr == peer->sin_addr.s_addr &&
                    address->sin_port == peer->sin_port,
                "recvfrom publishes the actual sender address exactly once");
    }
}

static int receive_contract_main(char **argv) {
    int from = strncmp(case_name, "recvfrom-", 9) == 0;
    const char *suffix = case_name + (from ? 9 : 5);
    int alias = strncmp(suffix, "alias-", 6) == 0;
    int fortified = strncmp(suffix, "fortified-", 10) == 0;
    if (alias) suffix += 6;
    if (fortified) suffix += 10;
    const char *names[] = {"blocked", "pending", "disabled", "ready", "ready-late", "peek",
                          "nonblock", "dontwait", "timeout", "signal", "signal-restart",
                          "competing", "waitall", "lowat", "eof", "zero", "errors",
                          "length-zero", "truncate"};
    int value = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(suffix, names[i]) == 0) value = (int)i;
    if (value < 0 || (from && alias) || (!from && (value == RECEIVE_ZERO || value == RECEIVE_TRUNCATE)) ||
        (from && (value == RECEIVE_WAITALL || value == RECEIVE_LOWAT || value == RECEIVE_EOF)))
        return 2;
    enum receive_kind kind = (enum receive_kind)value;
    int pin = pin_receive_provider(argv[2], from, alias, fortified);
    if (pin != 0) return pin;
    expect_native = getenv("FRANKENLIBC_THREAD_NATIVE") != NULL &&
                    strcmp(getenv("FRANKENLIBC_THREAD_NATIVE"), "1") == 0;
    creator_tp = (uintptr_t)__builtin_thread_pointer();
    creator_tid = (pid_t)syscall(SYS_gettid);
    creator_thread = pthread_self();
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = kind == RECEIVE_SIGNAL || kind == RECEIVE_SIGNAL_RESTART ? user_signal : SIG_DFL;
    action.sa_flags = kind == RECEIVE_SIGNAL_RESTART ? SA_RESTART : 0;
    sigemptyset(&action.sa_mask);
    REQUIRE(sigaction(SIGUSR1, &action, NULL) == 0, "receive signal disposition");
    alarm(15);
    int pair[2];
    struct sockaddr_in peer = {0};
    if (from) {
        struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        pair[0] = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        pair[1] = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        REQUIRE(pair[0] >= 0 && pair[1] >= 0, "create loopback datagram endpoints");
        REQUIRE(bind(pair[0], (struct sockaddr *)&local, sizeof(local)) == 0 &&
                    bind(pair[1], (struct sockaddr *)&local, sizeof(local)) == 0,
                "bind independent datagram endpoints");
        socklen_t size = sizeof(local);
        REQUIRE(getsockname(pair[0], (struct sockaddr *)&local, &size) == 0,
                "resolve datagram receiver address");
        size = sizeof(peer);
        REQUIRE(getsockname(pair[1], (struct sockaddr *)&peer, &size) == 0 &&
                    connect(pair[1], (struct sockaddr *)&local, sizeof(local)) == 0,
                "connect datagram sender to receiver");
    } else {
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0,
                "create stream receive endpoints");
    }
    if (kind == RECEIVE_NONBLOCK)
        REQUIRE(fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_NONBLOCK) == 0,
                "set caller-owned nonblocking flag");
    if (kind == RECEIVE_TIMEOUT) {
        struct timeval timeout = {0, 150000};
        REQUIRE(setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
                "set caller-owned receive timeout");
    }
    if (kind == RECEIVE_LOWAT) {
        int lowat = 4;
        REQUIRE(setsockopt(pair[0], SOL_SOCKET, SO_RCVLOWAT, &lowat, sizeof(lowat)) == 0,
                "set caller-owned receive low-water mark");
    }
    int original_flags = fcntl(pair[0], F_GETFL);
    REQUIRE(original_flags >= 0, "capture original socket flags");
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (memory < 0) skip("socket-wait-snapshot-unavailable");
    struct receive_probe probe;
    receive_initialize(&probe, kind, pair[0], from, fortified);
    if (kind == RECEIVE_PENDING || kind == RECEIVE_READY || kind == RECEIVE_PEEK ||
        kind == RECEIVE_LENGTH_ZERO)
        send_receive_bytes(pair[1], "DATA", 1);
    if (kind == RECEIVE_TRUNCATE) send_receive_bytes(pair[1], "DATA", 4);
    if (kind == RECEIVE_ZERO) send_receive_bytes(pair[1], "", 0);
    if (kind == RECEIVE_EOF)
        REQUIRE(shutdown(pair[1], SHUT_WR) == 0, "close receive peer write side");
    REQUIRE(pthread_create(&probe.observed.thread, NULL, receive_worker, &probe) == 0,
            "create receive worker");
    wait_ready(&probe.observed);
    if (kind == RECEIVE_PENDING)
        REQUIRE(pthread_cancel(probe.observed.thread) == 0, "request pending receive cancellation");
    atomic_store_explicit(&probe.observed.release, 1, memory_order_release);
    if (kind == RECEIVE_COMPETING) {
        struct receive_probe competitor;
        receive_initialize(&competitor, kind, pair[0], from, fortified);
        REQUIRE(pthread_create(&competitor.observed.thread, NULL, receive_worker, &competitor) == 0,
                "create competing socket receiver");
        wait_ready(&competitor.observed);
        atomic_store_explicit(&competitor.observed.release, 1, memory_order_release);
        observe_receive_parked(&probe, memory);
        observe_receive_parked(&competitor, memory);
        send_receive_bytes(pair[1], "DATA", 1);
        int64_t deadline = monotonic_ns() + 2000000000;
        while (!atomic_load_explicit(&probe.observed.returned, memory_order_acquire) &&
               !atomic_load_explicit(&competitor.observed.returned, memory_order_acquire)) {
            REQUIRE(monotonic_ns() < deadline, "one competing receiver acquires the payload");
            pause_briefly();
        }
        struct receive_probe *winner = atomic_load_explicit(&probe.observed.returned, memory_order_acquire)
                                         ? &probe : &competitor;
        struct receive_probe *loser = winner == &probe ? &competitor : &probe;
        REQUIRE(join_bounded(&winner->observed) == &winner->observed, "join winning receiver");
        check_received_payload(winner, &peer);
        observe_receive_parked(loser, memory);
        REQUIRE(pthread_cancel(loser->observed.thread) == 0, "cancel receiver after losing readiness");
        REQUIRE(join_bounded(&loser->observed) == PTHREAD_CANCELED &&
                    !atomic_load_explicit(&loser->observed.returned, memory_order_acquire),
                "losing receiver stays cancellable without rescue data");
        REQUIRE(loser->data[0] == 0xa5 && winner->observed.cleaned == 1 && loser->observed.cleaned == 1,
                "competing receivers acquire only one payload and clean up once");
    } else {
        if (kind == RECEIVE_BLOCKED || kind == RECEIVE_DISABLED || kind == RECEIVE_READY_LATE ||
            kind == RECEIVE_SIGNAL || kind == RECEIVE_SIGNAL_RESTART ||
            kind == RECEIVE_WAITALL || kind == RECEIVE_LOWAT) {
            observe_receive_parked(&probe, memory);
            if (kind == RECEIVE_BLOCKED || kind == RECEIVE_DISABLED)
                REQUIRE(pthread_cancel(probe.observed.thread) == 0, "request blocked receive cancellation");
            if (kind == RECEIVE_SIGNAL || kind == RECEIVE_SIGNAL_RESTART) {
                REQUIRE(pthread_kill(probe.observed.thread, SIGUSR1) == 0, "interrupt socket receive");
                int64_t deadline = monotonic_ns() + 2000000000;
                while (!atomic_load_explicit(&signals_delivered, memory_order_acquire)) {
                    REQUIRE(monotonic_ns() < deadline, "receive signal delivery deadline");
                    pause_briefly();
                }
                if (kind == RECEIVE_SIGNAL_RESTART) observe_receive_parked(&probe, memory);
            }
            if (kind == RECEIVE_WAITALL || kind == RECEIVE_LOWAT) {
                send_receive_bytes(pair[1], "D", 1);
                int64_t short_read_deadline = monotonic_ns() + 50000000;
                while (monotonic_ns() < short_read_deadline) {
                    REQUIRE(!atomic_load_explicit(&probe.observed.returned, memory_order_acquire),
                            "receive must keep waiting below its caller-selected threshold");
                    pause_briefly();
                }
                observe_receive_parked(&probe, memory);
                REQUIRE(!atomic_load_explicit(&probe.observed.returned, memory_order_acquire),
                        "WAITALL and low-water contracts do not return a premature short read");
                send_receive_bytes(pair[1], "ATA", 3);
            } else if (kind == RECEIVE_DISABLED || kind == RECEIVE_READY_LATE ||
                       kind == RECEIVE_SIGNAL_RESTART) {
                send_receive_bytes(pair[1], "DATA", 1);
            }
        }
        void *result = join_bounded(&probe.observed);
        int canceled = kind == RECEIVE_PENDING || kind == RECEIVE_BLOCKED || kind == RECEIVE_DISABLED;
        REQUIRE(result == (canceled ? PTHREAD_CANCELED : &probe.observed), "receive join result");
        REQUIRE(probe.observed.cleaned == 1, "receive cleanup count");
        if (kind == RECEIVE_PENDING || kind == RECEIVE_BLOCKED) {
            REQUIRE(!probe.observed.returned && probe.data[0] == 0xa5 &&
                        probe.address_length == sizeof(probe.address),
                    "cancellation precedes payload and address publication");
        } else if (kind == RECEIVE_NONBLOCK || kind == RECEIVE_DONTWAIT || kind == RECEIVE_TIMEOUT) {
            REQUIRE(probe.observed.result == -1 && probe.observed.error == EAGAIN,
                    "caller nonblocking and timeout contracts preserve EAGAIN");
            if (kind == RECEIVE_TIMEOUT)
                REQUIRE(probe.observed.elapsed_ns >= 100000000 && probe.observed.elapsed_ns < 2000000000,
                        "receive timeout retains its kernel deadline");
        } else if (kind == RECEIVE_SIGNAL) {
            REQUIRE(probe.observed.result == -1 && probe.observed.error == EINTR,
                    "non-restarting receive preserves EINTR");
        } else if (kind == RECEIVE_EOF || kind == RECEIVE_ZERO) {
            REQUIRE(probe.observed.result == 0 && probe.observed.error == EDOM && probe.data[0] == 0xa5,
                    "EOF and zero-byte datagrams retain successful zero results");
        } else if (kind != RECEIVE_ERRORS) {
            check_received_payload(&probe, &peer);
        }
    }
    if (kind == RECEIVE_PENDING || kind == RECEIVE_PEEK || (kind == RECEIVE_LENGTH_ZERO && !from)) {
        unsigned char remaining = 0;
        REQUIRE(syscall(SYS_recvfrom, pair[0], &remaining, 1, MSG_DONTWAIT, NULL, NULL) == 1 &&
                    remaining == 'D', "pending cancellation, PEEK and empty stream reads preserve payload");
    }
    if (kind != RECEIVE_EOF) {
        unsigned char remaining;
        REQUIRE(syscall(SYS_recvfrom, pair[0], &remaining, 1, MSG_DONTWAIT, NULL, NULL) == -1 &&
                    errno == EAGAIN, "receive consumes each queued payload at most once");
    }
    REQUIRE(fcntl(pair[0], F_GETFL) == original_flags, "receive never changes shared O_NONBLOCK flags");
    REQUIRE(close(memory) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0,
            "release receive fixture descriptors");
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}

enum send_kind {
    SEND_BLOCKED, SEND_PENDING, SEND_DISABLED, SEND_READY, SEND_READY_LATE,
    SEND_NONBLOCK, SEND_DONTWAIT, SEND_TIMEOUT, SEND_SIGNAL, SEND_SIGNAL_RESTART,
    SEND_ERRORS, SEND_LENGTH_ZERO, SEND_PEER_CLOSED, SEND_PARTIAL,
    SEND_PARTIAL_CANCEL, SEND_PARTIAL_ERROR, SEND_ADDRESS, SEND_OVERSIZE, SEND_SEQPACKET
};
struct send_probe {
    struct state observed;
    enum send_kind kind;
    int fd, to, flags;
    size_t length;
    unsigned char data[65536];
    struct sockaddr_in address;
    socklen_t address_length;
};
static ssize_t (*selected_send)(int, const void *, size_t, int);
static ssize_t (*selected_sendto)(int, const void *, size_t, int,
                                 const struct sockaddr *, socklen_t);

static int pin_send_provider(const char *expected, int to, int alias) {
    int base = pin_providers(expected, 0, EVENT_NONE);
    if (base != 0) return base;
    const char *name = to ? (alias ? "__sendto" : "sendto") : alias ? "__send" : "send";
    Dl_info info = {0};
    struct stat actual, wanted;
    void *symbol = dlsym(RTLD_DEFAULT, name);
    if (!symbol || !dladdr(symbol, &info) || !info.dli_fname ||
        stat(expected, &wanted) || stat(info.dli_fname, &actual) ||
        actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
        fprintf(stderr, "pthread-native-poll:provider-mismatch:%s\n", name);
        return 86;
    }
    if (to) selected_sendto = (__typeof__(selected_sendto))symbol;
    else selected_send = (__typeof__(selected_send))symbol;
    return 0;
}

static ssize_t send_call(struct send_probe *probe) {
    if (probe->to)
        return selected_sendto(probe->fd, probe->data, probe->length, probe->flags,
                               probe->address_length ? (struct sockaddr *)&probe->address : NULL,
                               probe->address_length);
    return selected_send(probe->fd, probe->data, probe->length, probe->flags);
}

static void send_cleanup(void *argument) {
    struct send_probe *probe = argument;
    sigset_t mask;
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0 &&
                sigismember(&mask, SIGUSR1) == 0 && sigismember(&mask, SIGUSR2) == 1,
            "send cleanup preserves the complete original signal mask");
    REQUIRE(atomic_fetch_add_explicit(&probe->observed.cleaned, 1, memory_order_release) == 0,
            "send cleanup executes exactly once");
}

static void *send_worker(void *argument) {
    struct send_probe *probe = argument;
    struct state *state = &probe->observed;
    capture_identity(state);
    REQUIRE(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0,
            "deferred send cancellation");
    if (probe->kind == SEND_DISABLED)
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0,
                "disable send cancellation");
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    REQUIRE(pthread_sigmask(SIG_SETMASK, &mask, NULL) == 0, "send entry signal mask");
    pthread_cleanup_push(send_cleanup, probe);
    atomic_store_explicit(&state->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&state->release, memory_order_acquire))
        (void)syscall(SYS_sched_yield);
    errno = EDOM;
    int64_t started = monotonic_ns();
    if (probe->kind == SEND_ERRORS) {
        int original = probe->fd;
        probe->fd = -1;
        REQUIRE(send_call(probe) == -1 && errno == EBADF, "invalid send fd retains EBADF");
        int pipefd[2];
        REQUIRE(pipe(pipefd) == 0, "send error pipe");
        probe->fd = pipefd[1];
        REQUIRE(send_call(probe) == -1 && errno == ENOTSOCK,
                "send metadata probes do not replace ENOTSOCK");
        REQUIRE(close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "close send error pipe");
        probe->fd = original;
        state->result = 0;
    } else {
        state->result = (int)send_call(probe);
    }
    state->error = errno;
    state->elapsed_ns = monotonic_ns() - started;
    atomic_store_explicit(&state->returned, 1, memory_order_release);
    pthread_cleanup_pop(1);
    if (probe->kind == SEND_DISABLED || probe->kind == SEND_PARTIAL_CANCEL) {
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0,
                "reenable send cancellation");
        pthread_testcancel();
        fail("completed send lost its pending cancellation");
    }
    return state;
}

static void send_initialize(struct send_probe *probe, enum send_kind kind, int fd, int to) {
    memset(probe, 0, sizeof(*probe));
    probe->kind = kind;
    probe->fd = fd;
    probe->to = to;
    probe->flags = kind == SEND_DONTWAIT ? MSG_DONTWAIT | MSG_NOSIGNAL :
                   kind == SEND_PARTIAL_ERROR ? 0 : MSG_NOSIGNAL;
    probe->length = kind == SEND_LENGTH_ZERO ? 0 :
                    kind == SEND_PARTIAL || kind == SEND_PARTIAL_CANCEL ||
                    kind == SEND_PARTIAL_ERROR || kind == SEND_OVERSIZE ? sizeof(probe->data) : 1;
    memset(probe->data, 'D', sizeof(probe->data));
    probe->observed.result = -222;
    atomic_init(&probe->observed.ready, 0);
    atomic_init(&probe->observed.release, 0);
    atomic_init(&probe->observed.returned, 0);
    atomic_init(&probe->observed.cleaned, 0);
}

static size_t fill_send_socket(int fd) {
    unsigned char bytes[4096];
    memset(bytes, 'F', sizeof(bytes));
    size_t total = 0;
    for (size_t length = sizeof(bytes); length != 0; length = length == 1 ? 0 : 1) {
        for (;;) {
            ssize_t sent = syscall(SYS_sendto, fd, bytes, length,
                                   MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0);
            if (sent < 0) {
                REQUIRE(errno == EAGAIN, "fill sender until kernel backpressure");
                break;
            }
            REQUIRE(sent > 0 && (size_t)sent <= length, "positive send-buffer fill");
            total += (size_t)sent;
        }
    }
    REQUIRE(total > 0, "nonempty backpressure payload");
    return total;
}

static void drain_send_socket(int fd, size_t *filler, size_t *payload, int *empty_records) {
    unsigned char bytes[8192];
    for (;;) {
        ssize_t received = syscall(SYS_recvfrom, fd, bytes, sizeof(bytes), MSG_DONTWAIT, NULL, NULL);
        if (received < 0) {
            REQUIRE(errno == EAGAIN, "drain only available send payload");
            return;
        }
        if (received == 0) {
            ++*empty_records;
            return;
        }
        for (ssize_t i = 0; i < received; ++i) {
            REQUIRE(bytes[i] == 'F' || bytes[i] == 'D', "send preserves payload bytes");
            if (bytes[i] == 'F') ++*filler;
            else ++*payload;
        }
    }
}

static void observe_send_parked(struct send_probe *probe, int memory) {
    struct state *state = &probe->observed;
    int sliced = expect_native && probe->kind != SEND_DISABLED &&
                 probe->kind != SEND_TIMEOUT && probe->kind != SEND_SIGNAL &&
                 probe->kind != SEND_SIGNAL_RESTART;
    int64_t deadline = monotonic_ns() + 2000000000;
    while (monotonic_ns() < deadline) {
        REQUIRE(!atomic_load_explicit(&state->returned, memory_order_acquire),
                "send returned before its intended blocked operation");
        char call[512], status[512];
        long number = -1;
        unsigned long long args[6] = {0};
        if (!read_proc(state, "syscall", call, sizeof(call)) ||
            sscanf(call, "%ld %llx %llx %llx %llx %llx %llx", &number,
                   &args[0], &args[1], &args[2], &args[3], &args[4], &args[5]) < 5)
            goto retry_send;
        if (sliced) {
            struct pollfd interest;
            struct timespec duration;
            uint64_t mask;
            if (number != SYS_ppoll || args[1] != 1 ||
                !snapshot(memory, args[0], &interest, sizeof(interest)) ||
                interest.fd != probe->fd || interest.events != POLLOUT ||
                args[2] == 0 || !snapshot(memory, args[2], &duration, sizeof(duration)) ||
                args[3] == 0 || !snapshot(memory, args[3], &mask, sizeof(mask))) goto retry_send;
            REQUIRE(duration.tv_sec == 0 && duration.tv_nsec > 0 && duration.tv_nsec <= 50000000,
                    "native send waits in bounded nonzero slices");
            REQUIRE(args[4] == sizeof(mask) && ((mask >> (SIGUSR2 - 1)) & 1) == 1 &&
                        ((mask >> (SIGUSR1 - 1)) & 1) == 0,
                    "native send atomically reinstates the complete original mask");
        } else if (number != SYS_sendto || args[0] != (unsigned)probe->fd ||
                   args[1] != (uintptr_t)probe->data || args[2] != probe->length) {
            goto retry_send;
        }
        if (!read_proc(state, "stat", status, sizeof(status))) goto retry_send;
        char *end = strrchr(status, ')');
        if (end != NULL && end[1] == ' ' && end[2] == 'S') return;
retry_send:
        pause_briefly();
    }
    fail("no observed socket send with the expected native/hosted wait arguments");
}

static int send_contract_main(char **argv) {
    int to = strncmp(case_name, "sendto-", 7) == 0;
    const char *suffix = case_name + (to ? 7 : 5);
    int alias = strncmp(suffix, "alias-", 6) == 0;
    if (alias) suffix += 6;
    const char *names[] = {"blocked", "pending", "disabled", "ready", "ready-late",
                          "nonblock", "dontwait", "timeout", "signal", "signal-restart",
                          "errors", "length-zero", "peer-closed", "partial",
                          "partial-cancel", "partial-error", "address", "oversize", "seqpacket"};
    int value = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(suffix, names[i]) == 0) value = (int)i;
    if (value < 0 ||
        (to && (value == SEND_PARTIAL || value == SEND_PARTIAL_CANCEL || value == SEND_PARTIAL_ERROR)) ||
        (!to && (value == SEND_ADDRESS || value == SEND_OVERSIZE))) return 2;
    enum send_kind kind = (enum send_kind)value;
    int pin = pin_send_provider(argv[2], to, alias);
    if (pin != 0) return pin;
    expect_native = getenv("FRANKENLIBC_THREAD_NATIVE") != NULL &&
                    strcmp(getenv("FRANKENLIBC_THREAD_NATIVE"), "1") == 0;
    creator_tp = (uintptr_t)__builtin_thread_pointer();
    creator_tid = (pid_t)syscall(SYS_gettid);
    creator_thread = pthread_self();
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = kind == SEND_SIGNAL || kind == SEND_SIGNAL_RESTART ? user_signal : SIG_DFL;
    action.sa_flags = kind == SEND_SIGNAL_RESTART ? SA_RESTART : 0;
    sigemptyset(&action.sa_mask);
    REQUIRE(sigaction(SIGUSR1, &action, NULL) == 0, "send signal disposition");
    action.sa_handler = SIG_DFL;
    action.sa_flags = 0;
    REQUIRE(sigaction(SIGPIPE, &action, NULL) == 0, "default SIGPIPE catches duplicated send errors");
    alarm(15);
    int pair[2];
    int type = kind == SEND_SEQPACKET ? SOCK_SEQPACKET : to ? SOCK_DGRAM : SOCK_STREAM;
    struct sockaddr_in address = {0};
    if (kind == SEND_ADDRESS) {
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        pair[0] = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        pair[1] = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        REQUIRE(pair[0] >= 0 && pair[1] >= 0, "create addressed send endpoints");
        REQUIRE(bind(pair[1], (struct sockaddr *)&address, sizeof(address)) == 0,
                "bind addressed send receiver");
        socklen_t length = sizeof(address);
        REQUIRE(getsockname(pair[1], (struct sockaddr *)&address, &length) == 0,
                "resolve send destination");
    } else {
        REQUIRE(socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, pair) == 0,
                "create socket send endpoints");
    }
    int send_buffer = 8192;
    REQUIRE(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) == 0,
            "bound the kernel send buffer");
    if (kind == SEND_NONBLOCK)
        REQUIRE(fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_NONBLOCK) == 0,
                "set caller-owned send nonblocking flag");
    if (kind == SEND_TIMEOUT) {
        struct timeval timeout = {0, 150000};
        REQUIRE(setsockopt(pair[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0,
                "set caller-owned send timeout");
    }
    int original_flags = fcntl(pair[0], F_GETFL);
    REQUIRE(original_flags >= 0, "capture original sender flags");
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (memory < 0) skip("socket-send-wait-snapshot-unavailable");
    size_t initial = 0, filler = 0, payload = 0;
    int empty_records = 0;
    if (kind == SEND_BLOCKED || kind == SEND_DISABLED || kind == SEND_READY_LATE ||
        kind == SEND_NONBLOCK || kind == SEND_DONTWAIT || kind == SEND_TIMEOUT ||
        kind == SEND_SIGNAL || kind == SEND_SIGNAL_RESTART || kind == SEND_SEQPACKET)
        initial = fill_send_socket(pair[0]);
    if (kind == SEND_PEER_CLOSED)
        REQUIRE(close(pair[1]) == 0, "close send peer");
    struct send_probe probe;
    send_initialize(&probe, kind, pair[0], to);
    if (kind == SEND_ADDRESS) {
        probe.address = address;
        probe.address_length = sizeof(address);
    }
    REQUIRE(pthread_create(&probe.observed.thread, NULL, send_worker, &probe) == 0,
            "create send worker");
    wait_ready(&probe.observed);
    if (kind == SEND_PENDING)
        REQUIRE(pthread_cancel(probe.observed.thread) == 0, "request pending send cancellation");
    atomic_store_explicit(&probe.observed.release, 1, memory_order_release);
    int partial = kind == SEND_PARTIAL || kind == SEND_PARTIAL_CANCEL || kind == SEND_PARTIAL_ERROR;
    if (kind == SEND_BLOCKED || kind == SEND_DISABLED || kind == SEND_READY_LATE ||
        kind == SEND_SIGNAL || kind == SEND_SIGNAL_RESTART || kind == SEND_SEQPACKET || partial) {
        observe_send_parked(&probe, memory);
        if (kind == SEND_BLOCKED || kind == SEND_DISABLED || kind == SEND_PARTIAL_CANCEL)
            REQUIRE(pthread_cancel(probe.observed.thread) == 0, "request blocked send cancellation");
        if (kind == SEND_SIGNAL || kind == SEND_SIGNAL_RESTART) {
            REQUIRE(pthread_kill(probe.observed.thread, SIGUSR1) == 0, "interrupt socket send");
            int64_t deadline = monotonic_ns() + 2000000000;
            while (!atomic_load_explicit(&signals_delivered, memory_order_acquire)) {
                REQUIRE(monotonic_ns() < deadline, "send signal delivery deadline");
                pause_briefly();
            }
            if (kind == SEND_SIGNAL_RESTART) observe_send_parked(&probe, memory);
        }
        if (kind == SEND_PARTIAL_ERROR)
            REQUIRE(shutdown(pair[1], SHUT_RD) == 0, "fail send after its accepted prefix");
        if (kind == SEND_DISABLED || kind == SEND_READY_LATE || kind == SEND_SIGNAL_RESTART ||
            kind == SEND_PARTIAL || kind == SEND_SEQPACKET) {
            int64_t deadline = monotonic_ns() + 2000000000;
            while (!atomic_load_explicit(&probe.observed.returned, memory_order_acquire)) {
                REQUIRE(monotonic_ns() < deadline, "send completion after draining backpressure");
                drain_send_socket(pair[1], &filler, &payload, &empty_records);
                pause_briefly();
            }
        }
    }
    void *result = join_bounded(&probe.observed);
    int canceled = kind == SEND_PENDING || kind == SEND_BLOCKED ||
                   kind == SEND_DISABLED || kind == SEND_PARTIAL_CANCEL;
    REQUIRE(result == (canceled ? PTHREAD_CANCELED : &probe.observed), "send join result");
    REQUIRE(probe.observed.cleaned == 1, "send cleanup count");
    if (kind == SEND_PENDING || kind == SEND_BLOCKED) {
        REQUIRE(!probe.observed.returned, "cancellation precedes any send result");
    } else if (kind == SEND_NONBLOCK || kind == SEND_DONTWAIT || kind == SEND_TIMEOUT) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EAGAIN,
                "caller nonblocking and send timeout contracts preserve EAGAIN");
        if (kind == SEND_TIMEOUT)
            REQUIRE(probe.observed.elapsed_ns >= 100000000 && probe.observed.elapsed_ns < 2000000000,
                    "send timeout retains its kernel deadline");
    } else if (kind == SEND_SIGNAL) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EINTR,
                "non-restarting send preserves EINTR");
    } else if (kind == SEND_PEER_CLOSED) {
        REQUIRE(probe.observed.result == -1 &&
                    probe.observed.error == (to ? ECONNREFUSED : EPIPE),
                "closed peer preserves its socket error without SIGPIPE");
    } else if (kind == SEND_PARTIAL_CANCEL || kind == SEND_PARTIAL_ERROR) {
        REQUIRE(probe.observed.returned && probe.observed.result > 0 &&
                    probe.observed.result < (int)probe.length && probe.observed.error == EDOM,
                "interrupted partial send returns its committed prefix");
    } else if (kind == SEND_OVERSIZE) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EMSGSIZE,
                "oversized atomic datagram preserves EMSGSIZE");
    } else if (kind != SEND_ERRORS) {
        REQUIRE(probe.observed.result == (int)probe.length && probe.observed.error == EDOM,
                "send completes the entire payload without changing errno");
    }
    if (kind != SEND_PEER_CLOSED && kind != SEND_PARTIAL_ERROR) {
        drain_send_socket(pair[1], &filler, &payload, &empty_records);
        size_t accepted = probe.observed.result > 0 ? (size_t)probe.observed.result : 0;
        REQUIRE(payload == accepted, "each accepted send byte is delivered exactly once");
        REQUIRE(empty_records == (kind == SEND_LENGTH_ZERO && type != SOCK_STREAM),
                "zero-byte sends preserve datagram records and stream behavior");
    }
    REQUIRE(filler == initial, "send cancellation does not consume queued peer data");
    REQUIRE(fcntl(pair[0], F_GETFL) == original_flags, "send never changes shared O_NONBLOCK flags");
    REQUIRE(close(memory) == 0 && close(pair[0]) == 0, "release sender fixture descriptors");
    if (kind != SEND_PEER_CLOSED) REQUIRE(close(pair[1]) == 0, "release sender peer");
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    case_name = argv[1];
    if (strncmp(case_name, "send-", 5) == 0 || strncmp(case_name, "sendto-", 7) == 0)
        return send_contract_main(argv);
    if (strncmp(case_name, "recv-", 5) == 0 || strncmp(case_name, "recvfrom-", 9) == 0)
        return receive_contract_main(argv);
    if (strncmp(case_name, "sleep-", 6) == 0) return sleep_contract_main(argv);
    if (strncmp(case_name, "select-", 7) == 0 || strncmp(case_name, "pselect-", 8) == 0)
        return select_contract_main(argv);
    if (strncmp(case_name, "pause-", 6) == 0 || strncmp(case_name, "sigsuspend-", 11) == 0)
        return suspend_contract_main(argv);
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
