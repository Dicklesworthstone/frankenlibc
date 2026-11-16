/* Real blocked poll/select/epoll/sleep/suspend cancellation and signal behavior, with a GNU oracle.
 * Successful blocked cases require a sleeping syscall and a kernel snapshot of
 * its pollfd array. Missing procfs evidence is an explicit, non-passing SKIP.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
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

/* Native I/O keeps a private descriptor for the same socket while sleeping.
 * Compare the kernel object identity, not a public fd number that can be reused. */
static int same_io_object(unsigned long long actual, int expected) {
    struct stat left, right;
    if (actual > INT32_MAX || syscall(SYS_fstat, (int)actual, &left) != 0 ||
        syscall(SYS_fstat, expected, &right) != 0) return 0;
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           (left.st_mode & S_IFMT) == (right.st_mode & S_IFMT);
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

enum sleep_api {
    SLEEP_NANO, SLEEP_CLOCK, SLEEP_ABSOLUTE, SLEEP_SECONDS, SLEEP_MICRO, SLEEP_C11,
    SLEEP_REALTIME, SLEEP_BOOTTIME
};
enum sleep_kind {
    SLEEP_BLOCKED, SLEEP_PENDING, SLEEP_DISABLED, SLEEP_SIGNAL, SLEEP_SIGNAL_RESTART,
    SLEEP_TIMEOUT, SLEEP_MASK_BLOCK, SLEEP_ZERO, SLEEP_READONLY, SLEEP_UNALIGNED,
    SLEEP_REMAINDER, SLEEP_ALIAS_REMAINDER, SLEEP_READONLY_REMAINDER, SLEEP_ERRORS,
    SLEEP_EXPIRED, SLEEP_TIMER_CREATE_DENIED, SLEEP_TIMER_ARM_DENIED, SLEEP_PERSONALITY_DENIED
};

static void deny_io_probe(int number, int error);

static int sleep_is_absolute(enum sleep_api api) {
    return api == SLEEP_ABSOLUTE || api == SLEEP_REALTIME || api == SLEEP_BOOTTIME;
}

static int sleep_is_clock(enum sleep_api api) {
    return api == SLEEP_CLOCK || sleep_is_absolute(api);
}

static int sleep_uses_timer(enum sleep_api api) {
    return api == SLEEP_REALTIME || api == SLEEP_BOOTTIME;
}

static clockid_t sleep_clock(enum sleep_api api) {
    return api == SLEEP_REALTIME ? CLOCK_REALTIME :
           api == SLEEP_BOOTTIME ? CLOCK_BOOTTIME : CLOCK_MONOTONIC;
}

static int sleep_has_deliverable_handler(enum sleep_kind kind) {
    return kind == SLEEP_SIGNAL || kind == SLEEP_SIGNAL_RESTART ||
           kind == SLEEP_REMAINDER || kind == SLEEP_ALIAS_REMAINDER ||
           kind == SLEEP_READONLY_REMAINDER;
}
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
    int import_denied;
    int syscall_denied;
    const struct timespec *request;
    struct timespec *output;
    struct timespec remaining;
    int64_t started;
};

static int pin_sleep_provider(const char *expected, enum sleep_api api, int alias) {
    int rc = pin_providers(expected, 0, EVENT_NONE);
    if (rc != 0) return rc;
    const char *name = api == SLEEP_NANO ? (alias ? "__nanosleep" : "nanosleep") :
        sleep_is_clock(api) ? (alias ? "__clock_nanosleep" : "clock_nanosleep") :
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
    else if (sleep_is_clock(api))
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
    case SLEEP_REALTIME:
    case SLEEP_BOOTTIME:
        return selected_clock_sleep(sleep_clock(probe->api), TIMER_ABSTIME, request, remaining);
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
    if (sleep_is_clock(probe->api))
        REQUIRE(result == expected && error == EDOM, "clock_nanosleep returns errors without changing errno");
    else if (probe->api == SLEEP_C11)
        REQUIRE(result == (expected == EINTR ? -1 : -2) && error == EDOM,
                "thrd_sleep preserves errno and its distinct error convention");
    else
        REQUIRE(result == -1 && error == expected, "nanosleep/usleep errno convention");
}

static void sleep_errors(struct sleep_probe *probe) {
    const struct timespec invalid[] = {{-1, 0}, {0, -1}, {0, 1000000000}};
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
    if (sleep_is_clock(probe->api)) {
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
    if (probe->import_denied) {
        deny_io_probe(SYS_process_vm_readv, EPERM);
        deny_io_probe(SYS_pipe2, EPERM);
    }
    if (probe->syscall_denied) {
#ifdef SYS_nanosleep
        deny_io_probe(SYS_nanosleep, EPERM);
#endif
        deny_io_probe(SYS_clock_nanosleep, EPERM);
    }
    if (probe->kind == SLEEP_TIMER_CREATE_DENIED)
        deny_io_probe(SYS_timerfd_create, EPERM);
    else if (probe->kind == SLEEP_TIMER_ARM_DENIED)
        deny_io_probe(SYS_timerfd_settime, EPERM);
    else if (probe->kind == SLEEP_PERSONALITY_DENIED)
        deny_io_probe(SYS_personality, EPERM);
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

static int sleep_timer_matches(int descriptor, clockid_t expected_clock) {
    char path[80], identity[64], info[512];
    int length = snprintf(path, sizeof(path), "/proc/self/fd/%d", descriptor);
    REQUIRE(length > 0 && (size_t)length < sizeof(path), "timer descriptor path");
    ssize_t count = readlink(path, identity, sizeof(identity) - 1);
    if (count < 0) return 0;
    identity[count] = 0;
    REQUIRE(strcmp(identity, "anon_inode:[timerfd]") == 0,
            "absolute clock sleep waits on its kernel timer");
    length = snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", descriptor);
    REQUIRE(length > 0 && (size_t)length < sizeof(path), "timer descriptor metadata path");
    int file = open(path, O_RDONLY | O_CLOEXEC);
    if (file < 0) return 0;
    count = read(file, info, sizeof(info) - 1);
    REQUIRE(close(file) == 0, "close timer descriptor metadata");
    if (count <= 0) return 0;
    info[count] = 0;
    const char *clock = strstr(info, "clockid:");
    const char *flags = strstr(info, "settime flags:");
    int observed_clock = -1;
    unsigned observed_flags = 0;
    REQUIRE(clock != NULL && sscanf(clock, "clockid: %d", &observed_clock) == 1 &&
                observed_clock == expected_clock,
            "kernel timer retains the requested REALTIME or BOOTTIME clock");
    REQUIRE(flags != NULL && sscanf(flags, "settime flags: %x", &observed_flags) == 1 &&
                observed_flags == TIMER_ABSTIME,
            "kernel timer uses an absolute deadline without CANCEL_ON_SET");
    return 1;
}

static void observe_sleep_parked(struct sleep_probe *probe, int memory) {
    struct state *state = &probe->observed;
    const int timer = sleep_uses_timer(probe->api);
    const int fallback = timer && (sleep_has_deliverable_handler(probe->kind) ||
        probe->kind == SLEEP_TIMER_CREATE_DENIED || probe->kind == SLEEP_TIMER_ARM_DENIED ||
        probe->kind == SLEEP_PERSONALITY_DENIED);
    const int sliced = expect_native && probe->kind != SLEEP_DISABLED &&
                       !fallback && !probe->import_denied;
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
            if (number != SYS_ppoll || args[2] == 0 || args[3] == 0 ||
                !snapshot(memory, args[2], &duration, sizeof(duration)) ||
                !snapshot(memory, args[3], &mask, sizeof(mask))) goto retry_sleep;
            if (timer) {
                struct pollfd interest;
                if (args[0] == 0 || args[1] != 1 ||
                    !snapshot(memory, args[0], &interest, sizeof(interest))) goto retry_sleep;
                REQUIRE(interest.fd >= 0 && interest.events == POLLIN,
                        "absolute sleep observes its one private timer");
                if (!sleep_timer_matches(interest.fd, sleep_clock(probe->api))) goto retry_sleep;
            } else if (args[0] != 0 || args[1] != 0) goto retry_sleep;
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
            if (timer)
                REQUIRE(number == SYS_clock_nanosleep && args[0] == (unsigned long long)sleep_clock(probe->api) &&
                            args[1] == TIMER_ABSTIME,
                        "unsupported timer adapter retains the original clock and absolute deadline");
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
    const char *prefixes[] = {"nano-", "clock-", "absolute-", "seconds-", "micro-", "c11-", "realtime-", "boottime-"};
    int api = -1;
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i)
        if (strncmp(entry, prefixes[i], strlen(prefixes[i])) == 0) { api = (int)i; entry += strlen(prefixes[i]); break; }
    if (api < 0) return 2;
    int import_denied = strncmp(entry, "import-denied-", 14) == 0;
    if (import_denied) entry += 14;
    int syscall_denied = strncmp(entry, "syscall-denied-", 15) == 0;
    if (syscall_denied) entry += 15;
    if (syscall_denied && !import_denied) return 2;
    int alias = strncmp(entry, "alias-", 6) == 0;
    /* alias-remainder is a pointer-aliasing case, not an exported symbol. */
    if (strcmp(entry, "alias-remainder") == 0) alias = 0;
    if (alias) entry += 6;
    if (alias && api != SLEEP_NANO && api != SLEEP_CLOCK) return 2;
    const char *names[] = {"blocked", "pending", "disabled", "signal", "signal-restart", "timeout",
                          "mask-block", "zero", "readonly-request", "unaligned-request", "remainder",
                          "alias-remainder", "readonly-remainder", "errors", "expired",
                          "timer-create-denied", "timer-arm-denied", "personality-denied"};
    int kind = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(entry, names[i]) == 0) kind = (int)i;
    if (kind < 0 || ((api == SLEEP_SECONDS || api == SLEEP_MICRO) && kind >= SLEEP_READONLY)) return 2;
    if (syscall_denied && kind != SLEEP_TIMEOUT) return 2;
    if (kind == SLEEP_EXPIRED && !sleep_is_absolute((enum sleep_api)api)) return 2;
    if ((kind == SLEEP_TIMER_CREATE_DENIED || kind == SLEEP_TIMER_ARM_DENIED ||
         kind == SLEEP_PERSONALITY_DENIED) && !sleep_uses_timer((enum sleep_api)api)) return 2;
    int pin = pin_sleep_provider(argv[2], (enum sleep_api)api, alias);
    if (pin != 0) return pin;
    expect_native = getenv("FRANKENLIBC_THREAD_NATIVE") != NULL &&
                    strcmp(getenv("FRANKENLIBC_THREAD_NATIVE"), "1") == 0;
    creator_tp = (uintptr_t)__builtin_thread_pointer();
    creator_tid = (pid_t)syscall(SYS_gettid);
    creator_thread = pthread_self();
    struct sigaction action = {0};
    action.sa_handler = sleep_uses_timer((enum sleep_api)api) &&
                        !sleep_has_deliverable_handler((enum sleep_kind)kind) && kind != SLEEP_MASK_BLOCK
                          ? SIG_DFL : user_signal;
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
    int interrupted = sleep_has_deliverable_handler((enum sleep_kind)kind);
    struct timespec duration = {0, 250000000};
    if (kind == SLEEP_BLOCKED || kind == SLEEP_PENDING) duration = (struct timespec){60, 0};
    else if (interrupted) duration = (struct timespec){2, 0};
    else if (kind == SLEEP_ZERO || kind == SLEEP_ERRORS) duration = (struct timespec){0, 0};
    else if (api == SLEEP_SECONDS) duration = (struct timespec){1, 0};
    struct timespec request = duration;
    if (sleep_is_absolute((enum sleep_api)api) && kind != SLEEP_ZERO && kind != SLEEP_ERRORS) {
        if (kind == SLEEP_EXPIRED) {
            request = (struct timespec){1, 1};
        } else {
            REQUIRE(clock_gettime(sleep_clock((enum sleep_api)api), &request) == 0,
                    "read the requested absolute sleep clock");
            request.tv_sec += duration.tv_sec;
            request.tv_nsec += duration.tv_nsec;
            if (request.tv_nsec >= 1000000000) {
                ++request.tv_sec;
                request.tv_nsec -= 1000000000;
            }
        }
    }
    const size_t offset = kind == SLEEP_UNALIGNED ? 1 : 0;
    memcpy(storage + offset, &request, sizeof(request));
    const struct timespec sentinel = {71, 72};
    memcpy(storage + 64, &sentinel, sizeof(sentinel));
    REQUIRE(mprotect(storage, (size_t)page, PROT_READ) == 0, "protect sleep request and remainder controls");
    struct sleep_probe probe = {0};
    probe.api = (enum sleep_api)api;
    probe.kind = (enum sleep_kind)kind;
    probe.import_denied = import_denied;
    probe.syscall_denied = syscall_denied;
    probe.request = (const struct timespec *)(storage + offset);
    probe.remaining = sentinel;
    probe.output = &probe.remaining;
    probe.observed.kind = kind == SLEEP_MASK_BLOCK ? MASK_UNBLOCK : BLOCKED;
    if (kind == SLEEP_ALIAS_REMAINDER) {
        probe.remaining = request;
        probe.request = &probe.remaining;
    }
    if (kind == SLEEP_READONLY_REMAINDER) probe.output = (struct timespec *)(storage + 64);
    if (kind == SLEEP_EXPIRED) probe.output = (struct timespec *)(uintptr_t)1;
    size_t original_descriptors = descriptor_count();
    struct state *state = &probe.observed;
    REQUIRE(pthread_create(&state->thread, NULL, sleep_worker, &probe) == 0, "create sleep worker");
    wait_ready(state);
    if (kind == SLEEP_PENDING) REQUIRE(pthread_cancel(state->thread) == 0, "queue pending sleep cancellation");
    atomic_store_explicit(&state->release, 1, memory_order_release);
    if (!syscall_denied && kind != SLEEP_PENDING && kind != SLEEP_ZERO &&
        kind != SLEEP_ERRORS && kind != SLEEP_EXPIRED)
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
    if (syscall_denied) {
        verify_sleep_error(&probe, state->result, state->error, EPERM);
    } else if (interrupted) {
        int expected = kind == SLEEP_READONLY_REMAINDER && !sleep_is_absolute((enum sleep_api)api) ? EFAULT : EINTR;
        if (api == SLEEP_SECONDS)
            REQUIRE(state->result == 1 && state->error == EINTR,
                    "sleep truncates fractional unslept seconds as GNU does");
        else verify_sleep_error(&probe, state->result, state->error, expected);
        REQUIRE(atomic_load_explicit(&signals_delivered, memory_order_relaxed) == 1,
                "sleep interruption invokes one signal handler without SA_RESTART retry");
        if (sleep_is_absolute((enum sleep_api)api))
            REQUIRE(probe.remaining.tv_sec == (kind == SLEEP_ALIAS_REMAINDER ? request.tv_sec : 71) &&
                        probe.remaining.tv_nsec == (kind == SLEEP_ALIAS_REMAINDER ? request.tv_nsec : 72),
                    "absolute sleep leaves the remainder unused");
        else if (api != SLEEP_SECONDS && api != SLEEP_MICRO && kind != SLEEP_READONLY_REMAINDER) {
            int64_t left = probe.remaining.tv_sec * 1000000000 + probe.remaining.tv_nsec;
            REQUIRE(probe.remaining.tv_sec >= 0 && probe.remaining.tv_nsec >= 0 &&
                        probe.remaining.tv_nsec < 1000000000 && left > 0 && left < 2000000000,
                    "interrupted relative sleep publishes a normalized unslept duration");
        }
        if (kind == SLEEP_REMAINDER && !sleep_is_absolute((enum sleep_api)api)) {
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
        if (import_denied && kind != SLEEP_ERRORS)
            REQUIRE(state->error == EDOM, "successful import fallback preserves the caller's errno");
        if (kind != SLEEP_ZERO && kind != SLEEP_ERRORS && kind != SLEEP_EXPIRED)
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
    REQUIRE(descriptor_count() == original_descriptors,
            "completed, canceled and fallback sleeps release every private timer descriptor");
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
enum descriptor_transport {
    DESCRIPTOR_STREAM, DESCRIPTOR_DATAGRAM, DESCRIPTOR_SEQPACKET,
    DESCRIPTOR_UDP, DESCRIPTOR_UDP6
};

static enum descriptor_transport parse_descriptor_transport(const char **suffix) {
    const char *names[] = {"datagram-", "seqpacket-", "udp-", "udp6-"};
    /* Keep the original fallback regression addressable: it now exercises the
     * newly admitted descriptor path as well as its unchanged byte contract. */
    if (strcmp(*suffix, "datagram-fallback") == 0) return DESCRIPTOR_STREAM;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        size_t length = strlen(names[i]);
        if (strncmp(*suffix, names[i], length) == 0) {
            *suffix += length;
            return (enum descriptor_transport)(i + 1);
        }
    }
    return DESCRIPTOR_STREAM;
}

static void descriptor_socket_pair(enum descriptor_transport transport, int pair[2]) {
    if (transport <= DESCRIPTOR_SEQPACKET) {
        int type = transport == DESCRIPTOR_DATAGRAM ? SOCK_DGRAM :
                   transport == DESCRIPTOR_SEQPACKET ? SOCK_SEQPACKET : SOCK_STREAM;
        REQUIRE(socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, pair) == 0,
                "create independent local descriptor socket endpoints");
        return;
    }
    int domain = transport == DESCRIPTOR_UDP6 ? AF_INET6 : AF_INET;
    struct sockaddr_storage addresses[2];
    memset(addresses, 0, sizeof(addresses));
    socklen_t length = domain == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    for (int i = 0; i < 2; ++i) {
        pair[i] = socket(domain, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        REQUIRE(pair[i] >= 0, "create loopback descriptor datagram endpoint");
        if (domain == AF_INET6) {
            struct sockaddr_in6 *address = (struct sockaddr_in6 *)&addresses[i];
            address->sin6_family = AF_INET6;
            address->sin6_addr = in6addr_loopback;
        } else {
            struct sockaddr_in *address = (struct sockaddr_in *)&addresses[i];
            address->sin_family = AF_INET;
            address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
        REQUIRE(bind(pair[i], (struct sockaddr *)&addresses[i], length) == 0,
                "bind descriptor datagram endpoint to an ephemeral loopback port");
        socklen_t actual = length;
        REQUIRE(getsockname(pair[i], (struct sockaddr *)&addresses[i], &actual) == 0 && actual == length,
                "resolve the actual descriptor datagram address");
    }
    REQUIRE(connect(pair[0], (struct sockaddr *)&addresses[1], length) == 0 &&
                connect(pair[1], (struct sockaddr *)&addresses[0], length) == 0,
            "connect independent descriptor datagram endpoints in both directions");
}

enum receive_kind {
    RECEIVE_BLOCKED, RECEIVE_PENDING, RECEIVE_DISABLED, RECEIVE_READY,
    RECEIVE_READY_LATE, RECEIVE_PEEK, RECEIVE_NONBLOCK, RECEIVE_DONTWAIT,
    RECEIVE_TIMEOUT, RECEIVE_SIGNAL, RECEIVE_SIGNAL_RESTART, RECEIVE_COMPETING,
    RECEIVE_WAITALL, RECEIVE_LOWAT, RECEIVE_EOF, RECEIVE_ZERO, RECEIVE_ERRORS,
    RECEIVE_LENGTH_ZERO, RECEIVE_TRUNCATE, RECEIVE_EMPTY_RECORD,
    RECEIVE_READ_PIPE, RECEIVE_READ_DATAGRAM, RECEIVE_READ_NOSYS,
    RECEIVE_READ_PERM, RECEIVE_READ_ACCESS, RECEIVE_RIGHTS, RECEIVE_RIGHTS_CLOEXEC,
    RECEIVE_CONTROL_TRUNCATE, RECEIVE_RIGHTS_PRESSURE
};
struct receive_probe {
    struct state observed;
    enum receive_kind kind;
    int fd, from, fortified, flags, message, mapped, reading, vector_read;
    size_t length;
    unsigned char data[8];
    struct sockaddr_storage address;
    socklen_t address_length;
    struct msghdr header;
    struct iovec vectors[9];
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control;
};
static ssize_t (*selected_recv)(int, void *, size_t, int);
static ssize_t (*selected_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static ssize_t (*selected_recv_chk)(int, void *, size_t, size_t, int);
static ssize_t (*selected_recvfrom_chk)(int, void *, size_t, size_t, int,
                                      struct sockaddr *, socklen_t *);
static ssize_t (*selected_recvmsg)(int, struct msghdr *, int);
static ssize_t (*selected_read)(int, void *, size_t);
static ssize_t (*selected_read_chk)(int, void *, size_t, size_t);
static ssize_t (*selected_readv)(int, const struct iovec *, int);

static int pin_receive_provider(const char *expected, int from, int alias, int fortified,
                                int message, int reading, int vector_read) {
    int base = pin_providers(expected, 0, EVENT_NONE);
    if (base != 0) return base;
    const char *name = vector_read ? (alias ? "__readv" : "readv") :
                      reading ? (fortified ? "__read_chk" : alias ? "__read" : "read") :
                      message ? (alias ? "__recvmsg" : "recvmsg") :
                      from ? (fortified ? "__recvfrom_chk" : "recvfrom") :
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
    if (vector_read) selected_readv = (__typeof__(selected_readv))symbol;
    else if (reading && fortified) selected_read_chk = (__typeof__(selected_read_chk))symbol;
    else if (reading) selected_read = (__typeof__(selected_read))symbol;
    else if (message) selected_recvmsg = (__typeof__(selected_recvmsg))symbol;
    else if (from && fortified) selected_recvfrom_chk = (__typeof__(selected_recvfrom_chk))symbol;
    else if (from) selected_recvfrom = (__typeof__(selected_recvfrom))symbol;
    else if (fortified) selected_recv_chk = (__typeof__(selected_recv_chk))symbol;
    else selected_recv = (__typeof__(selected_recv))symbol;
    return 0;
}

static ssize_t read_call(const struct receive_probe *probe, int fd, void *buffer, size_t length) {
    if (probe->vector_read) {
        struct iovec vector = {buffer, length};
        return selected_readv(fd, &vector, 1);
    }
    return probe->fortified ? selected_read_chk(fd, buffer, length, sizeof(probe->data)) :
                              selected_read(fd, buffer, length);
}

static ssize_t receive_call(struct receive_probe *probe) {
    if (probe->vector_read) {
        struct iovec original[9];
        int count = probe->mapped ? 9 : 3;
        memcpy(original, probe->vectors, sizeof(original));
        ssize_t result = selected_readv(probe->fd, probe->vectors, count);
        REQUIRE(memcmp(original, probe->vectors, sizeof(original)) == 0,
                "readv leaves the caller's vector geometry unchanged");
        return result;
    }
    if (probe->reading) return read_call(probe, probe->fd, probe->data, probe->length);
    if (probe->message) return selected_recvmsg(probe->fd, &probe->header, probe->flags);
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

static int read_probe_denial(enum receive_kind kind) {
    return kind == RECEIVE_READ_NOSYS ? ENOSYS : kind == RECEIVE_READ_PERM ? EPERM :
           kind == RECEIVE_READ_ACCESS ? EACCES : 0;
}

/* A sandbox may allow read but reject recvfrom. Restrict only this worker so
 * the parent can independently observe the original read sleeping in-kernel. */
static void deny_io_probe(int number, int error) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)number, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (unsigned)error),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {sizeof(filter) / sizeof(filter[0]), filter};
    REQUIRE(syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0,
            "enable the worker's independent syscall filter");
    REQUIRE(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == 0,
            "deny the receive probe while retaining read");
}

static void check_read_errors(struct receive_probe *probe) {
    int pipefd[2];
    unsigned char buffer[8] = {0};
    REQUIRE(pipe(pipefd) == 0 && syscall(SYS_write, pipefd[1], "P", 1) == 1,
            "queue a byte for non-socket read fallback");
    REQUIRE(read_call(probe, -1, NULL, 0) == -1 && errno == EBADF,
            "empty read still validates the descriptor");
    REQUIRE(read_call(probe, pipefd[1], buffer, 0) == -1 && errno == EBADF,
            "empty read still rejects a write-only descriptor");
    errno = EDOM;
    REQUIRE(read_call(probe, pipefd[0], NULL, 0) == 0 && errno == EDOM,
            "empty pipe read accepts a null buffer and preserves errno");
    REQUIRE(read_call(probe, pipefd[0], NULL, 1) == -1 && errno == EFAULT,
            "nonempty read preserves EFAULT without consuming pipe data");
    errno = EDOM;
    REQUIRE(read_call(probe, pipefd[0], buffer, 1) == 1 && buffer[0] == 'P' && errno == EDOM,
            "non-socket fallback reads the original pipe byte");
    REQUIRE(close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "release read error pipe");

    int pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0 &&
                syscall(SYS_write, pair[1], "S", 1) == 1,
            "queue a byte before an invalid stream read buffer");
    long page = sysconf(_SC_PAGESIZE);
    REQUIRE(page > 0, "read error guard page size");
    void *guard = mmap(NULL, (size_t)page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(guard != MAP_FAILED, "allocate inaccessible stream read buffer");
    REQUIRE(read_call(probe, pair[0], guard, 1) == -1 && errno == EFAULT,
            "stream probe preserves the kernel's inaccessible-buffer EFAULT");
    errno = EDOM;
    REQUIRE(read_call(probe, pair[0], buffer, 1) == 1 && buffer[0] == 'S' && errno == EDOM,
            "failed stream read leaves the queued byte available");
    REQUIRE(munmap(guard, (size_t)page) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0,
            "release stream read error resources");
}

static void check_readv_descriptors(struct receive_probe *probe) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *guard = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(guard != MAP_FAILED, "guarded readv descriptor array");
    REQUIRE(selected_readv(probe->fd, guard, 1) == -1 && errno == EFAULT,
            "readv rejects inaccessible descriptor bytes without a Rust fault");
    REQUIRE(selected_readv(probe->fd, guard, 1025) == -1 && errno == EINVAL,
            "readv retains invalid-count precedence before descriptor copying");
    REQUIRE(selected_readv(probe->fd, guard, -1) == -1 && errno == EINVAL,
            "readv retains negative-count EINVAL");
    REQUIRE(selected_readv(-1, guard, 0) == -1 && errno == EBADF,
            "empty readv still checks the descriptor");
    errno = EDOM;
    REQUIRE(selected_readv(probe->fd, guard, 0) == 0 && errno == EDOM,
            "empty readv does not access the descriptor array");
    struct iovec empty[3] = {{guard, 0}, {NULL, 0}, {probe->data, 0}};
    REQUIRE(selected_readv(probe->fd, empty, 3) == 0 && errno == EDOM,
            "all-zero readv entries return immediately without receiving");
    struct iovec overflow[2] = {{probe->data, SIZE_MAX}, {NULL, 1}};
    REQUIRE(selected_readv(probe->fd, overflow, 2) == -1 && errno == EINVAL,
            "readv aggregate overflow retains kernel EINVAL");
    REQUIRE(munmap(guard, page) == 0, "release readv descriptor guard");
}

static ssize_t receive_with_one_fd_slot(struct receive_probe *probe) {
    struct rlimit original, limited;
    REQUIRE(syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &original) == 0,
            "capture descriptor capacity before ancillary pressure test");
    limited = original;
    if (limited.rlim_cur > 64) limited.rlim_cur = 64;
    REQUIRE(limited.rlim_cur >= 16 && syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, &limited, NULL) == 0,
            "bound this isolated fixture's descriptor table");
    int occupied[64];
    size_t count = 0;
    for (;;) {
        int fd = (int)syscall(SYS_fcntl, probe->fd, F_DUPFD_CLOEXEC, 0);
        if (fd < 0) {
            REQUIRE(errno == EMFILE, "fill the descriptor table exactly to its limit");
            break;
        }
        REQUIRE(count < sizeof(occupied) / sizeof(occupied[0]), "bounded descriptor-pressure storage");
        occupied[count++] = fd;
    }
    REQUIRE(count != 0 && syscall(SYS_close, occupied[--count]) == 0,
            "leave exactly one descriptor available for SCM_RIGHTS");
    errno = EDOM;
    ssize_t result = receive_call(probe);
    int error = errno;
    REQUIRE(syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, &original, NULL) == 0,
            "restore descriptor capacity before parent inspection");
    while (count != 0)
        REQUIRE(syscall(SYS_close, occupied[--count]) == 0, "release pressure-only descriptors");
    errno = error;
    return result;
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
    if (read_probe_denial(probe->kind))
        deny_io_probe(probe->vector_read ? SYS_recvmsg : SYS_recvfrom, read_probe_denial(probe->kind));
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
        if (probe->reading) {
            check_read_errors(probe);
        } else {
            int pipefd[2];
            REQUIRE(pipe(pipefd) == 0, "receive error pipe");
            probe->fd = pipefd[0];
            REQUIRE(receive_call(probe) == -1 && errno == ENOTSOCK,
                    "receive metadata probes do not replace ENOTSOCK");
            REQUIRE(close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "close receive error pipe");
        }
        probe->fd = original;
        if (probe->vector_read) check_readv_descriptors(probe);
        state->result = 0;
    } else if (probe->kind == RECEIVE_RIGHTS_PRESSURE) {
        state->result = (int)receive_with_one_fd_slot(probe);
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
                 probe->kind != RECEIVE_SIGNAL_RESTART &&
                 probe->kind != RECEIVE_READ_PIPE &&
                 !read_probe_denial(probe->kind);
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
        /* A missing native adapter must fail the actual cancel/join contract,
         * not merely the choice of waiting syscall. Observe its sleeping raw
         * read too, then let the parent request cancellation without data. */
        int raw_blocked_read = sliced && probe->reading && probe->kind == RECEIVE_BLOCKED &&
                               number == (probe->vector_read ? SYS_readv : SYS_read);
        if (sliced && !raw_blocked_read) {
            struct pollfd interest;
            struct timespec duration;
            uint64_t mask;
            if (number != SYS_ppoll || args[1] != 1 ||
                !snapshot(memory, args[0], &interest, sizeof(interest)) ||
                !same_io_object((unsigned)interest.fd, probe->fd) || interest.events != POLLIN ||
                args[2] == 0 || !snapshot(memory, args[2], &duration, sizeof(duration)) ||
                args[3] == 0 || !snapshot(memory, args[3], &mask, sizeof(mask))) goto retry_receive;
            REQUIRE(duration.tv_sec == 0 && duration.tv_nsec > 0 && duration.tv_nsec <= 50000000,
                    "native receive waits in bounded nonzero slices");
            REQUIRE(args[4] == sizeof(mask) && ((mask >> (SIGUSR2 - 1)) & 1) == 1 &&
                        ((mask >> (SIGUSR1 - 1)) & 1) == 0,
                    "native receive atomically reinstates the complete original mask");
        } else if (probe->vector_read) {
            if (number != SYS_readv || !same_io_object(args[0], probe->fd) ||
                args[2] != (unsigned)(probe->mapped ? 9 : 3)) goto retry_receive;
        } else if (probe->reading) {
            if (number != SYS_read || !same_io_object(args[0], probe->fd) ||
                args[1] != (uintptr_t)probe->data || args[2] != probe->length) goto retry_receive;
        } else if (probe->message) {
            if (number != SYS_recvmsg || !same_io_object(args[0], probe->fd)) goto retry_receive;
        } else if (number != SYS_recvfrom || !same_io_object(args[0], probe->fd) ||
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

static void send_receive_rights(int fd, int transferred) {
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct iovec vector = {(void *)"DATA", 4};
    struct msghdr message = {
        .msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes),
    };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(transferred));
    memcpy(CMSG_DATA(header), &transferred, sizeof(transferred));
    REQUIRE(syscall(SYS_sendmsg, fd, &message, MSG_NOSIGNAL) == 4,
            "queue one independently owned descriptor with its payload");
}

static void receive_initialize(struct receive_probe *probe, enum receive_kind kind,
                               int fd, int from, int fortified, int message, int mapped,
                               int reading, int vector_read) {
    memset(probe, 0, sizeof(*probe));
    probe->kind = kind;
    probe->fd = fd;
    probe->from = from;
    probe->fortified = fortified;
    probe->message = message;
    probe->mapped = mapped;
    probe->reading = reading;
    probe->vector_read = vector_read;
    probe->flags = kind == RECEIVE_PEEK ? MSG_PEEK :
                   kind == RECEIVE_DONTWAIT ? MSG_DONTWAIT :
                   kind == RECEIVE_WAITALL ? MSG_WAITALL :
                   kind == RECEIVE_TRUNCATE ? MSG_TRUNC :
                   kind == RECEIVE_RIGHTS_CLOEXEC ? MSG_CMSG_CLOEXEC : 0;
    probe->length = kind == RECEIVE_LENGTH_ZERO || kind == RECEIVE_EMPTY_RECORD ? 0 :
                    kind == RECEIVE_TRUNCATE ? 1 :
                    kind == RECEIVE_WAITALL || kind == RECEIVE_LOWAT || message || vector_read ? 4 : 1;
    probe->address_length = sizeof(probe->address);
    memset(probe->data, 0xa5, sizeof(probe->data));
    memset(&probe->address, 0xa5, sizeof(probe->address));
    if (message || vector_read) {
        /* A zero-length middle vector and a split payload exercise the actual
         * recvmsg scatter path, including a header retained across EAGAIN probes.
         * Nine vectors exceed the hardened importer's inline capacity, so its
         * mapping and Rust cleanup landing pad must survive native cancellation. */
        probe->vectors[0] = (struct iovec){probe->data, probe->length != 0 ? 1 : 0};
        probe->vectors[1] = (struct iovec){probe->data + 1, 0};
        probe->vectors[2] = (struct iovec){probe->data + 1,
                                         probe->length != 0 ? probe->length - 1 : 0};
        memset(&probe->control, 0xa5, sizeof(probe->control));
        probe->header = (struct msghdr){
            .msg_name = from ? &probe->address : NULL,
            .msg_namelen = from ? sizeof(probe->address) : 0,
            .msg_iov = probe->vectors,
            .msg_iovlen = mapped ? 9 : 3,
            .msg_control = probe->control.bytes,
            .msg_controllen = kind == RECEIVE_CONTROL_TRUNCATE ? 1 : sizeof(probe->control.bytes),
            .msg_flags = 0x13579,
        };
    }
    probe->observed.result = -222;
    atomic_init(&probe->observed.ready, 0);
    atomic_init(&probe->observed.release, 0);
    atomic_init(&probe->observed.returned, 0);
    atomic_init(&probe->observed.cleaned, 0);
}

static void check_received_payload(const struct receive_probe *probe,
                                   const struct sockaddr_in *peer) {
    int expected = probe->kind == RECEIVE_TRUNCATE && !probe->reading ? 4 : (int)probe->length;
    REQUIRE(probe->observed.result == expected && probe->observed.error == EDOM,
            "receive returns exact payload length without changing errno");
    REQUIRE(memcmp(probe->data, "DATA", probe->length) == 0,
            "receive preserves payload bytes");
    for (size_t i = probe->length; i < sizeof(probe->data); ++i)
        REQUIRE(probe->data[i] == 0xa5, "receive leaves trailing buffer bytes alone");
    if (probe->from) {
        const struct sockaddr_in *address = (const struct sockaddr_in *)&probe->address;
        socklen_t length = probe->message ? probe->header.msg_namelen : probe->address_length;
        REQUIRE(length == sizeof(*address) && address->sin_family == AF_INET &&
                    address->sin_addr.s_addr == peer->sin_addr.s_addr &&
                    address->sin_port == peer->sin_port,
                "recvfrom publishes the actual sender address exactly once");
    }
    if (probe->message) {
        REQUIRE(probe->header.msg_iov == probe->vectors &&
                    probe->header.msg_iovlen == (probe->mapped ? 9U : 3U) &&
                    probe->header.msg_control == probe->control.bytes &&
                    probe->header.msg_name == (probe->from ? &probe->address : NULL),
                "recvmsg publishes output scalars without replacing the caller's pointer graph");
        int expected_flags = probe->kind == RECEIVE_TRUNCATE ? MSG_TRUNC :
                             probe->kind == RECEIVE_CONTROL_TRUNCATE ? MSG_CTRUNC : 0;
        /* Linux echoes MSG_CMSG_CLOEXEC in msg_flags when it was requested. */
        expected_flags |= probe->flags & MSG_CMSG_CLOEXEC;
        REQUIRE(probe->header.msg_flags == expected_flags,
                "recvmsg preserves truncation and close-on-exec result flags");
        if (probe->kind != RECEIVE_RIGHTS && probe->kind != RECEIVE_RIGHTS_CLOEXEC &&
            probe->kind != RECEIVE_RIGHTS_PRESSURE)
            REQUIRE(probe->header.msg_controllen == 0,
                    "recvmsg reports zero ancillary bytes when none fit or none were sent");
    }
}

static int receive_contract_main(char **argv) {
    int vector_read = strncmp(case_name, "readv-", 6) == 0;
    int reading = vector_read || strncmp(case_name, "read-", 5) == 0;
    int message = strncmp(case_name, "recvmsg-", 8) == 0;
    int from = strncmp(case_name, "recvfrom-", 9) == 0;
    const char *suffix = case_name + (vector_read ? 6 : message ? 8 : from ? 9 : 5);
    int mapped = strncmp(suffix, "mapped-", 7) == 0;
    if (mapped) suffix += 7;
    int alias = strncmp(suffix, "alias-", 6) == 0;
    int fortified = strncmp(suffix, "fortified-", 10) == 0;
    if (alias) suffix += 6;
    if (fortified) suffix += 10;
    enum descriptor_transport transport = reading ? parse_descriptor_transport(&suffix) : DESCRIPTOR_STREAM;
    if (message && strncmp(suffix, "datagram-", 9) == 0) {
        from = 1;
        suffix += 9;
    }
    int timed = strncmp(suffix, "timed-", 6) == 0;
    if (timed) suffix += 6;
    const char *names[] = {"blocked", "pending", "disabled", "ready", "ready-late", "peek",
                          "nonblock", "dontwait", "timeout", "signal", "signal-restart",
                          "competing", "waitall", "lowat", "eof", "zero", "errors",
                          "length-zero", "truncate", "empty-record", "pipe-fallback", "datagram-fallback",
                          "probe-enosys", "probe-eperm", "probe-eacces", "rights", "rights-cloexec",
                          "control-truncate", "rights-pressure"};
    int value = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(suffix, names[i]) == 0) value = (int)i;
    if (value < 0 || (from && alias && !message) || ((message || vector_read) && fortified) ||
        (mapped && !message && !vector_read) ||
        (reading && (value == RECEIVE_PEEK || value == RECEIVE_DONTWAIT || value == RECEIVE_WAITALL)) ||
        (!reading && value >= RECEIVE_READ_PIPE && value <= RECEIVE_READ_ACCESS) ||
        (!from && transport == DESCRIPTOR_STREAM &&
         (value == RECEIVE_ZERO || value == RECEIVE_TRUNCATE || value == RECEIVE_EMPTY_RECORD)) ||
        (!reading && value == RECEIVE_EMPTY_RECORD) ||
        (from && (value == RECEIVE_WAITALL || value == RECEIVE_LOWAT || value == RECEIVE_EOF)) ||
        (value >= RECEIVE_RIGHTS && (!message || from)))
        return 2;
    enum receive_kind kind = (enum receive_kind)value;
    int pin = pin_receive_provider(argv[2], from, alias, fortified, message, reading, vector_read);
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
    if (kind == RECEIVE_READ_PIPE) {
        REQUIRE(pipe2(pair, O_CLOEXEC) == 0, "create original pipe read endpoints");
    } else if (kind == RECEIVE_READ_DATAGRAM) {
        REQUIRE(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, pair) == 0,
                "create original datagram read endpoints");
    } else if (transport != DESCRIPTOR_STREAM) {
        descriptor_socket_pair(transport, pair);
    } else if (from) {
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
    struct timeval configured_timeout = {0, 0};
    if (timed || kind == RECEIVE_TIMEOUT) {
        struct timeval timeout = {kind == RECEIVE_TIMEOUT ? 0 : 4, 150001};
        REQUIRE(setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
                "set caller-owned receive timeout");
        socklen_t size = sizeof(configured_timeout);
        REQUIRE(getsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &configured_timeout, &size) == 0 &&
                    size == sizeof(configured_timeout),
                "capture the kernel-rounded receive timeout");
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
    receive_initialize(&probe, kind, pair[0], from, fortified, message, mapped, reading, vector_read);
    size_t sent_length = kind == RECEIVE_LENGTH_ZERO ? 1 : probe.length;
    int rights[2] = {-1, -1};
    if (kind >= RECEIVE_RIGHTS) {
        REQUIRE(pipe2(rights, O_CLOEXEC) == 0, "create the transferred descriptor's pipe");
        REQUIRE(syscall(SYS_write, rights[1], "R", 1) == 1,
                "queue an independent descriptor-identity marker");
    }
    size_t original_descriptors = descriptor_count();
    if (kind == RECEIVE_PENDING || kind == RECEIVE_READY || kind == RECEIVE_PEEK ||
        kind == RECEIVE_LENGTH_ZERO)
        send_receive_bytes(pair[1], "DATA", sent_length);
    if (kind == RECEIVE_TRUNCATE) send_receive_bytes(pair[1], "DATA", 4);
    if (kind == RECEIVE_ZERO) send_receive_bytes(pair[1], "", 0);
    if (kind == RECEIVE_TRUNCATE && reading) send_receive_bytes(pair[1], "NEXT", 4);
    if (kind == RECEIVE_EMPTY_RECORD) {
        send_receive_bytes(pair[1], "", 0);
        send_receive_bytes(pair[1], "D", 1);
    }
    if (kind == RECEIVE_RIGHTS_PRESSURE) send_receive_rights(pair[1], rights[0]);
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
        receive_initialize(&competitor, kind, pair[0], from, fortified, message, mapped, reading, vector_read);
        REQUIRE(pthread_create(&competitor.observed.thread, NULL, receive_worker, &competitor) == 0,
                "create competing socket receiver");
        wait_ready(&competitor.observed);
        atomic_store_explicit(&competitor.observed.release, 1, memory_order_release);
        observe_receive_parked(&probe, memory);
        observe_receive_parked(&competitor, memory);
        send_receive_bytes(pair[1], "DATA", sent_length);
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
            kind == RECEIVE_READ_PIPE || kind == RECEIVE_READ_DATAGRAM || read_probe_denial(kind) ||
            kind == RECEIVE_WAITALL || kind == RECEIVE_LOWAT ||
            (kind >= RECEIVE_RIGHTS && kind != RECEIVE_RIGHTS_PRESSURE)) {
            observe_receive_parked(&probe, memory);
            if (timed && kind == RECEIVE_READY_LATE) {
                int64_t deadline = monotonic_ns() + 120000000;
                while (monotonic_ns() < deadline) pause_briefly();
                observe_receive_parked(&probe, memory);
                REQUIRE(probe.data[0] == 0xa5,
                        "finite receive retains its empty buffer across multiple wait slices");
            }
            if (kind >= RECEIVE_RIGHTS) {
                /* Cross several empty native retries before acquiring control
                 * data, proving EAGAIN did not shrink the caller's capacity. */
                int64_t deadline = monotonic_ns() + 120000000;
                while (monotonic_ns() < deadline) pause_briefly();
                observe_receive_parked(&probe, memory);
                REQUIRE(probe.header.msg_controllen ==
                            (kind == RECEIVE_CONTROL_TRUNCATE ? 1 : sizeof(probe.control.bytes)) &&
                            probe.header.msg_flags == 0x13579,
                        "empty recvmsg probes leave the output header untouched");
                send_receive_rights(pair[1], rights[0]);
            }
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
                       kind == RECEIVE_SIGNAL_RESTART || kind == RECEIVE_READ_DATAGRAM ||
                       read_probe_denial(kind)) {
                send_receive_bytes(pair[1], "DATA", sent_length);
            } else if (kind == RECEIVE_READ_PIPE) {
                REQUIRE(syscall(SYS_write, pair[1], "DATA", sent_length) == (ssize_t)sent_length,
                        "release the original blocking pipe read");
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
            if (message)
                REQUIRE(probe.header.msg_flags == 0x13579 &&
                            probe.header.msg_controllen == sizeof(probe.control.bytes) &&
                            probe.header.msg_namelen == (from ? sizeof(probe.address) : 0),
                        "cancelled recvmsg publishes no ancillary or source metadata");
        } else if (kind == RECEIVE_NONBLOCK || kind == RECEIVE_DONTWAIT || kind == RECEIVE_TIMEOUT) {
            REQUIRE(probe.observed.result == -1 && probe.observed.error == EAGAIN,
                    "caller nonblocking and timeout contracts preserve EAGAIN");
            if (kind == RECEIVE_TIMEOUT)
                REQUIRE(probe.observed.elapsed_ns >=
                            configured_timeout.tv_sec * 1000000000 + configured_timeout.tv_usec * 1000 - 5000000 &&
                            probe.observed.elapsed_ns < 2000000000,
                        "receive waits for its kernel-rounded deadline including the final fraction");
        } else if (kind == RECEIVE_SIGNAL) {
            REQUIRE(probe.observed.result == -1 && probe.observed.error == EINTR,
                    "non-restarting receive preserves EINTR");
        } else if (kind == RECEIVE_EOF || kind == RECEIVE_ZERO) {
            REQUIRE(probe.observed.result == 0 && probe.observed.error == EDOM && probe.data[0] == 0xa5,
                    "EOF and zero-byte datagrams retain successful zero results");
        } else if (kind != RECEIVE_ERRORS) {
            check_received_payload(&probe, &peer);
        }
        if (kind == RECEIVE_RIGHTS || kind == RECEIVE_RIGHTS_CLOEXEC || kind == RECEIVE_RIGHTS_PRESSURE) {
            struct cmsghdr *control = CMSG_FIRSTHDR(&probe.header);
            REQUIRE(control != NULL && control->cmsg_level == SOL_SOCKET &&
                        control->cmsg_type == SCM_RIGHTS && control->cmsg_len == CMSG_LEN(sizeof(int)) &&
                        CMSG_NXTHDR(&probe.header, control) == NULL,
                    "recvmsg publishes exactly one complete SCM_RIGHTS record");
            int acquired = -1;
            memcpy(&acquired, CMSG_DATA(control), sizeof(acquired));
            REQUIRE(acquired >= 0 && descriptor_count() == original_descriptors + 1,
                    "recvmsg acquires exactly one descriptor without retries or leaks");
            int descriptor_flags = fcntl(acquired, F_GETFD);
            REQUIRE(descriptor_flags >= 0 && ((descriptor_flags & FD_CLOEXEC) != 0) ==
                        (kind == RECEIVE_RIGHTS_CLOEXEC),
                    "MSG_CMSG_CLOEXEC atomically controls received descriptor inheritance");
            char marker = 0;
            REQUIRE(syscall(SYS_read, acquired, &marker, 1) == 1 && marker == 'R',
                    "the published descriptor refers to the transmitted object");
            REQUIRE(close(acquired) == 0, "release received descriptor");
        }
        if (kind >= RECEIVE_RIGHTS)
            REQUIRE(descriptor_count() == original_descriptors,
                    "truncated or accepted ancillary data leaves no hidden descriptor");
    }
    if (kind == RECEIVE_PENDING || kind == RECEIVE_PEEK || (kind == RECEIVE_LENGTH_ZERO && !from)) {
        unsigned char remaining[8] = {0};
        REQUIRE(syscall(SYS_recvfrom, pair[0], remaining, sizeof(remaining), MSG_DONTWAIT,
                        NULL, NULL) == (ssize_t)sent_length &&
                    memcmp(remaining, "DATA", sent_length) == 0,
                "pending cancellation, PEEK and empty descriptor reads preserve payload");
    }
    if (kind == RECEIVE_EMPTY_RECORD) {
        unsigned char remaining[8] = {0xa5};
        REQUIRE(syscall(SYS_recvfrom, pair[0], remaining, sizeof(remaining), MSG_DONTWAIT,
                        NULL, NULL) == 0 && remaining[0] == 0xa5,
                "zero-capacity read/readv leaves an empty message queued");
        REQUIRE(syscall(SYS_recvfrom, pair[0], remaining, sizeof(remaining), MSG_DONTWAIT,
                        NULL, NULL) == 1 && remaining[0] == 'D',
                "zero-capacity descriptor reads preserve the following record too");
    }
    if (kind == RECEIVE_TRUNCATE && reading) {
        unsigned char remaining[8] = {0};
        REQUIRE(syscall(SYS_recvfrom, pair[0], remaining, sizeof(remaining), MSG_DONTWAIT,
                        NULL, NULL) == 4 && memcmp(remaining, "NEXT", 4) == 0,
                "short descriptor reads discard only the current record's tail");
    }
    if (kind == RECEIVE_READ_PIPE) {
        struct pollfd interest = {pair[0], POLLIN, 0};
        REQUIRE(syscall(SYS_poll, &interest, 1, 0) == 0, "pipe fallback consumes its byte exactly once");
    } else if (kind != RECEIVE_EOF) {
        unsigned char remaining;
        REQUIRE(syscall(SYS_recvfrom, pair[0], &remaining, 1, MSG_DONTWAIT, NULL, NULL) == -1 &&
                    errno == EAGAIN, "receive consumes each queued payload at most once");
    }
    REQUIRE(fcntl(pair[0], F_GETFL) == original_flags, "receive never changes shared O_NONBLOCK flags");
    if (timed || kind == RECEIVE_TIMEOUT) {
        struct timeval after = {0, 0};
        socklen_t size = sizeof(after);
        REQUIRE(getsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &after, &size) == 0 &&
                    size == sizeof(after) && after.tv_sec == configured_timeout.tv_sec &&
                    after.tv_usec == configured_timeout.tv_usec,
                "receive never rewrites the shared socket timeout");
    }
    REQUIRE(descriptor_count() == original_descriptors,
            "completed or canceled receive releases every private descriptor");
    if (kind >= RECEIVE_RIGHTS)
        REQUIRE(close(rights[0]) == 0 && close(rights[1]) == 0,
                "release transferred descriptor source");
    REQUIRE(close(memory) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0,
            "release receive fixture descriptors");
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}

enum send_kind {
    SEND_BLOCKED, SEND_PENDING, SEND_DISABLED, SEND_READY, SEND_READY_LATE,
    SEND_NONBLOCK, SEND_DONTWAIT, SEND_TIMEOUT, SEND_SIGNAL, SEND_SIGNAL_RESTART,
    SEND_ERRORS, SEND_LENGTH_ZERO, SEND_PEER_CLOSED, SEND_PARTIAL,
    SEND_PARTIAL_CANCEL, SEND_PARTIAL_ERROR, SEND_ADDRESS, SEND_OVERSIZE, SEND_SEQPACKET,
    SEND_RIGHTS, SEND_RIGHTS_PARTIAL, SEND_RIGHTS_INVALID, SEND_IOV_MAX, SEND_DESCRIPTOR_ERRORS, SEND_MAPPED_PARTIAL,
    SEND_PIPE_FALLBACK, SEND_DATAGRAM_FALLBACK, SEND_PROBE_NOSYS, SEND_PROBE_PERM, SEND_PROBE_ACCESS,
    SEND_ZERO_BLOCKED, SEND_ZERO_READY_LATE, SEND_EMPTY_QUEUED
};
struct send_probe {
    struct state observed;
    enum send_kind kind;
    int fd, to, message_api, writing, flags, socket_type;
    size_t length;
    unsigned char data[65536];
    struct sockaddr_in address;
    socklen_t address_length;
    struct msghdr message;
    struct iovec vectors[1024];
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
    int rights_fd, rights_received;
};
static ssize_t (*selected_send)(int, const void *, size_t, int);
static ssize_t (*selected_sendto)(int, const void *, size_t, int,
                                 const struct sockaddr *, socklen_t);
static ssize_t (*selected_sendmsg)(int, const struct msghdr *, int);
static ssize_t (*selected_write)(int, const void *, size_t);
static ssize_t (*selected_writev)(int, const struct iovec *, int);

static int pin_send_provider(const char *expected, int entry, int alias) {
    int base = pin_providers(expected, 0, EVENT_NONE);
    if (base != 0) return base;
    const char *name = entry == 4 ? (alias ? "__writev" : "writev") :
                       entry == 3 ? (alias ? "__write" : "write") :
                       entry == 2 ? (alias ? "__sendmsg" : "sendmsg") :
                       entry == 1 ? (alias ? "__sendto" : "sendto") : alias ? "__send" : "send";
    Dl_info info = {0};
    struct stat actual, wanted;
    void *symbol = dlsym(RTLD_DEFAULT, name);
    if (!symbol || !dladdr(symbol, &info) || !info.dli_fname ||
        stat(expected, &wanted) || stat(info.dli_fname, &actual) ||
        actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
        fprintf(stderr, "pthread-native-poll:provider-mismatch:%s\n", name);
        return 86;
    }
    if (entry == 4) selected_writev = (__typeof__(selected_writev))symbol;
    else if (entry == 3) selected_write = (__typeof__(selected_write))symbol;
    else if (entry == 2) selected_sendmsg = (__typeof__(selected_sendmsg))symbol;
    else if (entry == 1) selected_sendto = (__typeof__(selected_sendto))symbol;
    else selected_send = (__typeof__(selected_send))symbol;
    return 0;
}

static ssize_t send_call(struct send_probe *probe) {
    if (probe->message_api || probe->writing == 2) {
        struct msghdr original = probe->message;
        struct iovec vectors[1024];
        REQUIRE(probe->message.msg_iovlen <= 1024, "bounded fixture vector snapshot");
        memcpy(vectors, probe->vectors, probe->message.msg_iovlen * sizeof(*vectors));
        ssize_t result = probe->writing == 2 ?
            selected_writev(probe->fd, probe->vectors, (int)probe->message.msg_iovlen) :
            selected_sendmsg(probe->fd, &probe->message, probe->flags);
        REQUIRE(memcmp(&original, &probe->message, sizeof(original)) == 0 &&
                    memcmp(vectors, probe->vectors,
                           probe->message.msg_iovlen * sizeof(*vectors)) == 0,
                "sendmsg never modifies the caller header or vector geometry");
        return result;
    }
    if (probe->writing) return selected_write(probe->fd, probe->data, probe->length);
    if (probe->to)
        return selected_sendto(probe->fd, probe->data, probe->length, probe->flags,
                               probe->address_length ? (struct sockaddr *)&probe->address : NULL,
                               probe->address_length);
    return selected_send(probe->fd, probe->data, probe->length, probe->flags);
}

static int write_probe_denial(enum send_kind kind) {
    return kind == SEND_PROBE_NOSYS ? ENOSYS : kind == SEND_PROBE_PERM ? EPERM :
           kind == SEND_PROBE_ACCESS ? EACCES : 0;
}

static ssize_t write_call(const struct send_probe *probe, int fd, const void *buffer, size_t length) {
    if (probe->writing == 2) {
        struct iovec vector = {(void *)buffer, length};
        return selected_writev(fd, &vector, 1);
    }
    return selected_write(fd, buffer, length);
}

static void check_write_errors(struct send_probe *probe) {
    int pipefd[2];
    REQUIRE(pipe(pipefd) == 0, "write fallback error pipe");
    REQUIRE(write_call(probe, -1, NULL, 0) == -1 && errno == EBADF,
            "empty write still validates the descriptor");
    REQUIRE(write_call(probe, pipefd[0], probe->data, 0) == -1 && errno == EBADF,
            "empty write rejects a read-only descriptor");
    errno = EDOM;
    REQUIRE(write_call(probe, pipefd[1], NULL, 0) == 0 && errno == EDOM,
            "zero-length pipe write preserves success and errno");
    REQUIRE(write_call(probe, pipefd[1], NULL, 1) == -1 && errno == EFAULT,
            "nonempty write keeps null-buffer EFAULT");
    errno = EDOM;
    REQUIRE(write_call(probe, pipefd[1], "P", 1) == 1 && errno == EDOM,
            "ordinary pipe writes retain the original syscall");
    unsigned char byte = 0;
    REQUIRE(syscall(SYS_read, pipefd[0], &byte, 1) == 1 && byte == 'P',
            "pipe fallback publishes exactly its successful payload");
    REQUIRE(close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "release write error pipe");
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *guard = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(guard != MAP_FAILED, "guarded write payload");
    REQUIRE(write_call(probe, probe->fd, guard, 1) == -1 && errno == EFAULT,
            "stream write probe preserves inaccessible-payload EFAULT");
    REQUIRE(munmap(guard, page) == 0, "release write payload guard");
}

static void check_writev_descriptors(struct send_probe *probe) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *guard = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(guard != MAP_FAILED, "guarded writev descriptor source");
    REQUIRE(selected_writev(probe->fd, guard, 1) == -1 && errno == EFAULT,
            "writev inaccessible descriptors remain EFAULT");
    REQUIRE(selected_writev(probe->fd, guard, 1025) == -1 && errno == EINVAL,
            "writev invalid count precedes descriptor copying");
    REQUIRE(selected_writev(probe->fd, guard, -1) == -1 && errno == EINVAL,
            "writev negative count remains EINVAL");
    REQUIRE(selected_writev(-1, guard, 0) == -1 && errno == EBADF,
            "empty writev validates the descriptor first");
    errno = EDOM;
    REQUIRE(selected_writev(probe->fd, guard, 0) == 0 && errno == EDOM,
            "empty writev does not import inaccessible descriptors");
    struct iovec empty[3] = {{guard, 0}, {NULL, 0}, {probe->data, 0}};
    REQUIRE(selected_writev(probe->fd, empty, 3) == 0 && errno == EDOM,
            "writev with only empty buffers remains a successful no-op");
    struct iovec overflow[2] = {{probe->data, SIZE_MAX}, {NULL, 1}};
    REQUIRE(selected_writev(probe->fd, overflow, 2) == -1 && errno == EINVAL,
            "writev aggregate overflow remains EINVAL");
    REQUIRE(munmap(guard, page) == 0, "release writev descriptor guard");
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
    if (probe->writing && probe->kind == SEND_PEER_CLOSED) sigaddset(&mask, SIGPIPE);
    REQUIRE(pthread_sigmask(SIG_SETMASK, &mask, NULL) == 0, "send entry signal mask");
    if (write_probe_denial(probe->kind))
        deny_io_probe(probe->writing == 2 ? SYS_sendmsg : SYS_sendto, write_probe_denial(probe->kind));
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
        probe->fd = original;
        if (probe->writing) {
            check_write_errors(probe);
        } else {
            int pipefd[2];
            REQUIRE(pipe(pipefd) == 0, "send error pipe");
            probe->fd = pipefd[1];
            REQUIRE(send_call(probe) == -1 && errno == ENOTSOCK,
                    "send metadata probes do not replace ENOTSOCK");
            REQUIRE(close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "close send error pipe");
            probe->fd = original;
        }
        state->result = 0;
    } else if (probe->kind == SEND_RIGHTS_INVALID) {
        int invalid = (int)syscall(SYS_fcntl, probe->fd, F_DUPFD_CLOEXEC, 0);
        REQUIRE(invalid >= 0 && syscall(SYS_close, invalid) == 0,
                "choose the descriptor number an unintended private pin would occupy");
        memcpy(CMSG_DATA(CMSG_FIRSTHDR(&probe->message)), &invalid, sizeof(invalid));
        state->result = (int)send_call(probe);
    } else if (probe->kind == SEND_DESCRIPTOR_ERRORS && probe->writing == 2) {
        check_writev_descriptors(probe);
        state->result = 0;
    } else if (probe->kind == SEND_DESCRIPTOR_ERRORS) {
        struct msghdr header = probe->message;
        size_t page = (size_t)sysconf(_SC_PAGESIZE);
        void *guard = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(guard != MAP_FAILED, "guarded sendmsg descriptor source");
        REQUIRE(selected_sendmsg(probe->fd, guard, probe->flags) == -1 && errno == EFAULT,
                "sendmsg inaccessible header remains a kernel EFAULT");
        header.msg_iov = guard;
        REQUIRE(selected_sendmsg(probe->fd, &header, probe->flags) == -1 && errno == EFAULT,
                "sendmsg inaccessible vectors remain a kernel EFAULT");
        header.msg_iovlen = 1025;
        REQUIRE(selected_sendmsg(probe->fd, &header, probe->flags) == -1 && errno == EMSGSIZE,
                "sendmsg validates vector count before copying an inaccessible vector");
        REQUIRE(selected_sendmsg(-1, guard, probe->flags) == -1 && errno == EBADF,
                "sendmsg snapshot fallback preserves invalid-fd error precedence");
        int pipefd[2];
        REQUIRE(pipe2(pipefd, O_CLOEXEC) == 0, "sendmsg nonsocket error pipe");
        REQUIRE(selected_sendmsg(pipefd[1], guard, probe->flags) == -1 && errno == ENOTSOCK,
                "sendmsg snapshot rejection preserves nonsocket error precedence");
        REQUIRE(close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "close descriptor error pipe");
        REQUIRE(munmap(guard, page) == 0, "release descriptor guard");
        state->result = 0;
    } else {
        state->result = (int)send_call(probe);
    }
    state->error = errno;
    if (probe->writing && probe->kind == SEND_PEER_CLOSED) {
        sigset_t pending;
        REQUIRE(sigpending(&pending) == 0 &&
                    sigismember(&pending, SIGPIPE) == (probe->socket_type == SOCK_STREAM),
                "closed-peer writes preserve each protocol's SIGPIPE behavior");
    }
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

static void send_initialize(struct send_probe *probe, enum send_kind kind, int fd, int entry, int mapped) {
    memset(probe, 0, sizeof(*probe));
    probe->kind = kind;
    probe->fd = fd;
    probe->to = entry == 1;
    probe->message_api = entry == 2;
    probe->writing = entry >= 3 ? entry - 2 : 0;
    probe->socket_type = SOCK_STREAM;
    probe->rights_fd = -1;
    probe->flags = kind == SEND_DONTWAIT ? MSG_DONTWAIT | MSG_NOSIGNAL :
                   kind == SEND_PARTIAL_ERROR ? 0 : MSG_NOSIGNAL;
    if (probe->writing) probe->flags = 0;
    probe->length = kind == SEND_LENGTH_ZERO || kind == SEND_ZERO_BLOCKED ||
                    kind == SEND_ZERO_READY_LATE || kind == SEND_EMPTY_QUEUED ? 0 :
                    kind == SEND_PARTIAL || kind == SEND_PARTIAL_CANCEL ||
                    kind == SEND_PARTIAL_ERROR || kind == SEND_RIGHTS_PARTIAL ||
                    kind == SEND_OVERSIZE || kind == SEND_MAPPED_PARTIAL ? sizeof(probe->data) :
                    kind == SEND_IOV_MAX ? 1024 : 1;
    for (size_t i = 0; i < sizeof(probe->data); ++i)
        probe->data[i] = (unsigned char)(i % 251);
    if (probe->message_api || probe->writing == 2) {
        probe->message.msg_iov = probe->vectors;
        probe->message.msg_iovlen = kind == SEND_IOV_MAX || kind == SEND_MAPPED_PARTIAL || mapped ? 1024 : 4;
        if (probe->message.msg_iovlen == 1024) {
            size_t piece = probe->length / 1024;
            for (size_t i = 0; i < 1024; ++i)
                probe->vectors[i] = (struct iovec){probe->data + i * piece, piece};
            probe->vectors[1023].iov_len += probe->length % 1024;
        } else {
            // Empty entries and a non-page boundary expose incorrect prefix
            // accounting even when a short kernel send ends inside an iovec.
            size_t first = probe->length / 3;
            probe->vectors[0] = (struct iovec){probe->data, 0};
            probe->vectors[1] = (struct iovec){probe->data, first};
            probe->vectors[2] = (struct iovec){probe->data + first, 0};
            probe->vectors[3] = (struct iovec){probe->data + first, probe->length - first};
        }
    }
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

static size_t fill_write_pipe(int fd) {
    int original = fcntl(fd, F_GETFL);
    REQUIRE(original >= 0 && fcntl(fd, F_SETFL, original | O_NONBLOCK) == 0,
            "prepare nonblocking pipe fill before the worker starts");
    unsigned char bytes[4096];
    memset(bytes, 'F', sizeof(bytes));
    size_t total = 0;
    for (;;) {
        ssize_t written = syscall(SYS_write, fd, bytes, sizeof(bytes));
        if (written < 0) {
            REQUIRE(errno == EAGAIN, "fill pipe to kernel backpressure");
            break;
        }
        REQUIRE(written > 0, "positive pipe fill");
        total += (size_t)written;
    }
    REQUIRE(total > 0 && fcntl(fd, F_SETFL, original) == 0,
            "restore the original blocking pipe before the tested write");
    return total;
}

static void drain_send_socket(int fd, size_t initial, size_t *filler, size_t *payload,
                              int *empty_records, struct send_probe *probe) {
    unsigned char bytes[8192];
    for (;;) {
        union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(8 * sizeof(int))]; } control;
        struct iovec vector = {bytes, sizeof(bytes)};
        struct msghdr message = {0};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        ssize_t received;
        if (probe->kind == SEND_PIPE_FALLBACK) {
            received = syscall(SYS_read, fd, bytes, sizeof(bytes));
            message.msg_controllen = 0;
        } else {
            received = syscall(SYS_recvmsg, fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        }
        if (received < 0) {
            REQUIRE(errno == EAGAIN, "drain only available send payload");
            return;
        }
        REQUIRE(!(message.msg_flags & MSG_CTRUNC), "sender ancillary data is not truncated");
        REQUIRE(!(message.msg_flags & MSG_TRUNC), "send records fit their independent receive buffer");
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg;
             cmsg = CMSG_NXTHDR(&message, cmsg)) {
            REQUIRE(probe->rights_fd >= 0 && cmsg->cmsg_level == SOL_SOCKET &&
                        cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_len == CMSG_LEN(sizeof(int)),
                    "sendmsg carries exactly the expected descriptor control message");
            int transferred;
            memcpy(&transferred, CMSG_DATA(cmsg), sizeof(transferred));
            struct stat original, acquired;
            REQUIRE(fstat(probe->rights_fd, &original) == 0 && fstat(transferred, &acquired) == 0 &&
                        original.st_dev == acquired.st_dev && original.st_ino == acquired.st_ino,
                    "sendmsg transfers the intended open file description");
            REQUIRE(close(transferred) == 0, "close received sendmsg descriptor");
            ++probe->rights_received;
        }
        if (received == 0) {
            ++*empty_records;
            if (probe->socket_type == SOCK_STREAM) return;
            continue;
        }
        if (probe->socket_type != SOCK_STREAM) {
            if (*filler < initial)
                REQUIRE((size_t)received <= initial - *filler,
                        "a message cannot combine filler and tested payload");
            else
                REQUIRE((size_t)received == probe->length,
                        "vectored message writes publish the entire payload in one record");
        }
        for (ssize_t i = 0; i < received; ++i) {
            if (*filler < initial) {
                REQUIRE(bytes[i] == 'F', "queued filler precedes the new send payload");
                ++*filler;
            } else {
                REQUIRE(*payload < probe->length && bytes[i] == probe->data[*payload],
                        "send preserves byte order across vector and partial-write boundaries");
                ++*payload;
            }
        }
    }
}

static void observe_send_parked(struct send_probe *probe, int memory) {
    struct state *state = &probe->observed;
    int sliced = expect_native && probe->kind != SEND_DISABLED &&
                 probe->kind != SEND_TIMEOUT && probe->kind != SEND_SIGNAL &&
                 probe->kind != SEND_SIGNAL_RESTART &&
                 probe->kind != SEND_PIPE_FALLBACK && !write_probe_denial(probe->kind);
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
        /* Prove cancellation of the already blocked operation. The old native
         * raw write must reach the no-rescue join deadline after cancellation,
         * rather than failing only because it did not enter ppoll. */
        int raw_blocked_write = sliced && probe->writing &&
                                (probe->kind == SEND_BLOCKED || probe->kind == SEND_ZERO_BLOCKED) &&
                                number == (probe->writing == 2 ? SYS_writev : SYS_write);
        if (sliced && !raw_blocked_write) {
            struct pollfd interest;
            struct timespec duration;
            uint64_t mask;
            if (number != SYS_ppoll || args[1] != 1 ||
                !snapshot(memory, args[0], &interest, sizeof(interest)) ||
                !same_io_object((unsigned)interest.fd, probe->fd) || interest.events != POLLOUT ||
                args[2] == 0 || !snapshot(memory, args[2], &duration, sizeof(duration)) ||
                args[3] == 0 || !snapshot(memory, args[3], &mask, sizeof(mask))) goto retry_send;
            REQUIRE(duration.tv_sec == 0 && duration.tv_nsec > 0 && duration.tv_nsec <= 50000000,
                    "native send waits in bounded nonzero slices");
            REQUIRE(args[4] == sizeof(mask) && ((mask >> (SIGUSR2 - 1)) & 1) == 1 &&
                        ((mask >> (SIGUSR1 - 1)) & 1) == 0,
                    "native send atomically reinstates the complete original mask");
        } else {
            if (probe->writing == 2) {
                if (number != SYS_writev || !same_io_object(args[0], probe->fd) ||
                    args[2] != probe->message.msg_iovlen) goto retry_send;
            } else if (probe->writing) {
                if (number != SYS_write || !same_io_object(args[0], probe->fd) ||
                    args[1] != (uintptr_t)probe->data || args[2] != probe->length) goto retry_send;
            } else if (probe->message_api) {
                struct msghdr message;
                if (number != SYS_sendmsg || !same_io_object(args[0], probe->fd) ||
                    !snapshot(memory, args[1], &message, sizeof(message)) ||
                    message.msg_iovlen != probe->message.msg_iovlen) goto retry_send;
            } else if (number != SYS_sendto || !same_io_object(args[0], probe->fd) ||
                       args[1] != (uintptr_t)probe->data || args[2] != probe->length) {
                goto retry_send;
            }
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
    int vector_write = strncmp(case_name, "writev-", 7) == 0;
    int writing = vector_write || strncmp(case_name, "write-", 6) == 0;
    int to = strncmp(case_name, "sendto-", 7) == 0;
    int message_api = strncmp(case_name, "sendmsg-", 8) == 0;
    const char *suffix = case_name + (vector_write ? 7 : writing ? 6 : message_api ? 8 : to ? 7 : 5);
    int mapped = vector_write && strncmp(suffix, "mapped-", 7) == 0;
    if (mapped) suffix += 7;
    int alias = strncmp(suffix, "alias-", 6) == 0;
    if (alias) suffix += 6;
    enum descriptor_transport transport = writing ? parse_descriptor_transport(&suffix) : DESCRIPTOR_STREAM;
    int datagram = message_api && strncmp(suffix, "datagram-", 9) == 0;
    if (datagram) suffix += 9;
    int timed = strncmp(suffix, "timed-", 6) == 0;
    if (timed) suffix += 6;
    int partial_timeout = timed && strcmp(suffix, "partial-timeout") == 0;
    if (partial_timeout) suffix = "partial";
    const char *names[] = {"blocked", "pending", "disabled", "ready", "ready-late",
                          "nonblock", "dontwait", "timeout", "signal", "signal-restart",
                          "errors", "length-zero", "peer-closed", "partial",
                          "partial-cancel", "partial-error", "address", "oversize", "seqpacket",
                          "rights", "rights-partial", "rights-invalid", "iov-max", "descriptor-errors", "mapped-partial",
                          "pipe-fallback", "datagram-fallback", "probe-enosys", "probe-eperm", "probe-eacces",
                          "zero-blocked", "zero-ready-late", "empty-queued"};
    int value = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(suffix, names[i]) == 0) value = (int)i;
    if (value < 0 ||
        (to && (value == SEND_PARTIAL || value == SEND_PARTIAL_CANCEL || value == SEND_PARTIAL_ERROR)) ||
        (!to && !message_api &&
         (value == SEND_ADDRESS || (value == SEND_OVERSIZE && transport == DESCRIPTOR_STREAM))) ||
        (writing && value == SEND_DONTWAIT) ||
        (!message_api && (value == SEND_RIGHTS || value == SEND_RIGHTS_PARTIAL || value == SEND_RIGHTS_INVALID)) ||
        (!message_api && !vector_write && value >= SEND_IOV_MAX && value <= SEND_MAPPED_PARTIAL) ||
        (!writing && value >= SEND_PIPE_FALLBACK) ||
        (value >= SEND_ZERO_BLOCKED && transport == DESCRIPTOR_STREAM) ||
        ((value == SEND_ZERO_BLOCKED || value == SEND_ZERO_READY_LATE) && vector_write) ||
        (value == SEND_EMPTY_QUEUED && !vector_write)) return 2;
    enum send_kind kind = (enum send_kind)value;
    int entry = vector_write ? 4 : writing ? 3 : message_api ? 2 : to;
    int pin = pin_send_provider(argv[2], entry, alias);
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
    int type = kind == SEND_SEQPACKET || transport == DESCRIPTOR_SEQPACKET ? SOCK_SEQPACKET :
               to || datagram || transport != DESCRIPTOR_STREAM ||
               kind == SEND_ADDRESS || kind == SEND_DATAGRAM_FALLBACK ? SOCK_DGRAM : SOCK_STREAM;
    struct sockaddr_in address = {0};
    if (kind == SEND_PIPE_FALLBACK) {
        int pipefd[2];
        REQUIRE(pipe2(pipefd, O_CLOEXEC) == 0, "create original write pipe");
        pair[0] = pipefd[1];
        pair[1] = pipefd[0];
        REQUIRE(fcntl(pair[1], F_SETFL, fcntl(pair[1], F_GETFL) | O_NONBLOCK) == 0,
                "independent pipe reader drains only available bytes");
    } else if (transport != DESCRIPTOR_STREAM) {
        descriptor_socket_pair(transport, pair);
    } else if (kind == SEND_ADDRESS) {
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
    if (kind != SEND_PIPE_FALLBACK)
        REQUIRE(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) == 0,
                "bound the kernel send buffer");
    if (kind == SEND_NONBLOCK)
        REQUIRE(fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_NONBLOCK) == 0,
                "set caller-owned send nonblocking flag");
    struct timeval configured_timeout = {0, 0};
    if (timed || kind == SEND_TIMEOUT) {
        struct timeval timeout = {kind == SEND_TIMEOUT || partial_timeout ? 0 : 4, 150001};
        REQUIRE(setsockopt(pair[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0,
                "set caller-owned send timeout");
        socklen_t size = sizeof(configured_timeout);
        REQUIRE(getsockopt(pair[0], SOL_SOCKET, SO_SNDTIMEO, &configured_timeout, &size) == 0 &&
                    size == sizeof(configured_timeout),
                "capture the kernel-rounded send timeout");
    }
    int original_flags = fcntl(pair[0], F_GETFL);
    REQUIRE(original_flags >= 0, "capture original sender flags");
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (memory < 0) skip("socket-send-wait-snapshot-unavailable");
    size_t initial = 0, filler = 0, payload = 0;
    int empty_records = 0;
    if (kind == SEND_BLOCKED || kind == SEND_DISABLED || kind == SEND_READY_LATE ||
        kind == SEND_NONBLOCK || kind == SEND_DONTWAIT || kind == SEND_TIMEOUT ||
        kind == SEND_SIGNAL || kind == SEND_SIGNAL_RESTART || kind == SEND_SEQPACKET ||
        kind == SEND_PIPE_FALLBACK || kind == SEND_DATAGRAM_FALLBACK || write_probe_denial(kind) ||
        kind == SEND_ZERO_BLOCKED || kind == SEND_ZERO_READY_LATE || kind == SEND_EMPTY_QUEUED)
        initial = kind == SEND_PIPE_FALLBACK ? fill_write_pipe(pair[0]) : fill_send_socket(pair[0]);
    if (kind == SEND_PEER_CLOSED)
        REQUIRE(close(pair[1]) == 0, "close send peer");
    struct send_probe probe;
    send_initialize(&probe, kind, pair[0], entry, mapped);
    probe.socket_type = type;
    if (kind == SEND_ADDRESS) {
        probe.address = address;
        probe.address_length = sizeof(address);
        probe.message.msg_name = &probe.address;
        probe.message.msg_namelen = probe.address_length;
    }
    int rights[2] = {-1, -1};
    if (kind == SEND_RIGHTS || kind == SEND_RIGHTS_PARTIAL || kind == SEND_RIGHTS_INVALID) {
        if (kind != SEND_RIGHTS_INVALID)
            REQUIRE(pipe2(rights, O_CLOEXEC) == 0, "prepare sendmsg descriptor transfer");
        probe.rights_fd = rights[0];
        probe.message.msg_control = probe.control.bytes;
        probe.message.msg_controllen = sizeof(probe.control.bytes);
        struct cmsghdr *control = CMSG_FIRSTHDR(&probe.message);
        control->cmsg_level = SOL_SOCKET;
        control->cmsg_type = SCM_RIGHTS;
        control->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(control), &rights[0], sizeof(rights[0]));
    }
    size_t original_descriptors = descriptor_count();
    REQUIRE(pthread_create(&probe.observed.thread, NULL, send_worker, &probe) == 0,
            "create send worker");
    wait_ready(&probe.observed);
    if (kind == SEND_PENDING)
        REQUIRE(pthread_cancel(probe.observed.thread) == 0, "request pending send cancellation");
    atomic_store_explicit(&probe.observed.release, 1, memory_order_release);
    int partial = kind == SEND_PARTIAL || kind == SEND_PARTIAL_CANCEL ||
                  kind == SEND_PARTIAL_ERROR || kind == SEND_RIGHTS_PARTIAL || kind == SEND_MAPPED_PARTIAL;
    if (kind == SEND_BLOCKED || kind == SEND_DISABLED || kind == SEND_READY_LATE ||
        kind == SEND_SIGNAL || kind == SEND_SIGNAL_RESTART || kind == SEND_SEQPACKET || partial ||
        kind == SEND_PIPE_FALLBACK || kind == SEND_DATAGRAM_FALLBACK || write_probe_denial(kind) ||
        kind == SEND_ZERO_BLOCKED || kind == SEND_ZERO_READY_LATE) {
        observe_send_parked(&probe, memory);
        if (timed && kind == SEND_READY_LATE) {
            int64_t deadline = monotonic_ns() + 120000000;
            while (monotonic_ns() < deadline) pause_briefly();
            observe_send_parked(&probe, memory);
            REQUIRE(!probe.observed.returned,
                    "finite send retains backpressure across multiple wait slices");
        }
        if (kind == SEND_BLOCKED || kind == SEND_DISABLED || kind == SEND_PARTIAL_CANCEL ||
            kind == SEND_ZERO_BLOCKED)
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
        if (!partial_timeout && (kind == SEND_DISABLED || kind == SEND_READY_LATE || kind == SEND_SIGNAL_RESTART ||
            kind == SEND_PARTIAL || kind == SEND_RIGHTS_PARTIAL || kind == SEND_MAPPED_PARTIAL ||
            kind == SEND_SEQPACKET || kind == SEND_PIPE_FALLBACK || kind == SEND_DATAGRAM_FALLBACK ||
            write_probe_denial(kind) || kind == SEND_ZERO_READY_LATE)) {
            int64_t deadline = monotonic_ns() + 2000000000;
            while (!atomic_load_explicit(&probe.observed.returned, memory_order_acquire)) {
                REQUIRE(monotonic_ns() < deadline, "send completion after draining backpressure");
                drain_send_socket(pair[1], initial, &filler, &payload, &empty_records, &probe);
                pause_briefly();
            }
        }
    }
    void *result = join_bounded(&probe.observed);
    int canceled = kind == SEND_PENDING || kind == SEND_BLOCKED ||
                   kind == SEND_DISABLED || kind == SEND_PARTIAL_CANCEL || kind == SEND_ZERO_BLOCKED;
    REQUIRE(result == (canceled ? PTHREAD_CANCELED : &probe.observed), "send join result");
    REQUIRE(probe.observed.cleaned == 1, "send cleanup count");
    if (kind == SEND_PENDING || kind == SEND_BLOCKED || kind == SEND_ZERO_BLOCKED) {
        REQUIRE(!probe.observed.returned, "cancellation precedes any send result");
    } else if (kind == SEND_NONBLOCK || kind == SEND_DONTWAIT || kind == SEND_TIMEOUT) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EAGAIN,
                "caller nonblocking and send timeout contracts preserve EAGAIN");
        if (kind == SEND_TIMEOUT)
            REQUIRE(probe.observed.elapsed_ns >=
                        configured_timeout.tv_sec * 1000000000 + configured_timeout.tv_usec * 1000 - 5000000 &&
                        probe.observed.elapsed_ns < 2000000000,
                    "send waits for its kernel-rounded deadline including the final fraction");
    } else if (kind == SEND_SIGNAL) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EINTR,
                "non-restarting send preserves EINTR");
    } else if (kind == SEND_RIGHTS_INVALID) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EBADF,
                "a private pin must not turn invalid SCM_RIGHTS into a transmitted socket");
    } else if (kind == SEND_PEER_CLOSED) {
        REQUIRE(probe.observed.result == -1 &&
                    probe.observed.error == (type == SOCK_DGRAM ? ECONNREFUSED : EPIPE),
                "closed peer preserves its socket error without SIGPIPE");
    } else if (kind == SEND_PARTIAL_CANCEL || kind == SEND_PARTIAL_ERROR || partial_timeout) {
        REQUIRE(probe.observed.returned && probe.observed.result > 0 &&
                    probe.observed.result < (int)probe.length && probe.observed.error == EDOM,
                "interrupted partial send returns its committed prefix");
        if (partial_timeout)
            REQUIRE(probe.observed.elapsed_ns >=
                        configured_timeout.tv_sec * 1000000000 + configured_timeout.tv_usec * 1000 - 5000000 &&
                        probe.observed.elapsed_ns < 2000000000,
                    "a timed partial send spends one budget and preserves its successful prefix");
    } else if (kind == SEND_OVERSIZE) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EMSGSIZE,
                "oversized atomic datagram preserves EMSGSIZE");
    } else if (kind != SEND_ERRORS && kind != SEND_DESCRIPTOR_ERRORS) {
        REQUIRE(probe.observed.result == (int)probe.length && probe.observed.error == EDOM,
                "send completes the entire payload without changing errno");
    }
    if (kind != SEND_PEER_CLOSED && kind != SEND_PARTIAL_ERROR) {
        drain_send_socket(pair[1], initial, &filler, &payload, &empty_records, &probe);
        size_t accepted = probe.observed.result > 0 ? (size_t)probe.observed.result : 0;
        REQUIRE(payload == accepted, "each accepted send byte is delivered exactly once");
        REQUIRE(empty_records == ((kind == SEND_LENGTH_ZERO || kind == SEND_ZERO_READY_LATE) &&
                                  type != SOCK_STREAM && !vector_write),
                "zero-byte sends preserve datagram records and stream behavior");
    }
    REQUIRE(filler == initial, "send cancellation does not consume queued peer data");
    REQUIRE(probe.rights_received == (kind == SEND_RIGHTS || kind == SEND_RIGHTS_PARTIAL),
            "sendmsg delivers ancillary rights exactly once across all stream fragments");
    REQUIRE(descriptor_count() == original_descriptors,
            "completed or canceled send releases every private descriptor");
    if (rights[0] >= 0)
        REQUIRE(close(rights[0]) == 0 && close(rights[1]) == 0, "release sender rights sources");
    REQUIRE(fcntl(pair[0], F_GETFL) == original_flags, "send never changes shared O_NONBLOCK flags");
    if (timed || kind == SEND_TIMEOUT) {
        struct timeval after = {0, 0};
        socklen_t size = sizeof(after);
        REQUIRE(getsockopt(pair[0], SOL_SOCKET, SO_SNDTIMEO, &after, &size) == 0 &&
                    size == sizeof(after) && after.tv_sec == configured_timeout.tv_sec &&
                    after.tv_usec == configured_timeout.tv_usec,
                "send never rewrites the shared socket timeout");
    }
    REQUIRE(close(memory) == 0 && close(pair[0]) == 0, "release sender fixture descriptors");
    if (kind != SEND_PEER_CLOSED) REQUIRE(close(pair[1]) == 0, "release sender peer");
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}

/* A blocked kernel I/O operation owns its original open file description even
 * when dup2 replaces the public number. Keep the old endpoint alive explicitly
 * so EPIPE/EOF cannot hide an adapter that silently switches to the new socket. */
static void observe_reuse_parked(struct state *state, int memory, int fd, long raw, int writing) {
    int64_t deadline = monotonic_ns() + 2000000000;
    while (monotonic_ns() < deadline) {
        REQUIRE(!atomic_load_explicit(&state->returned, memory_order_acquire),
                "I/O remains blocked before descriptor replacement");
        char call[512], status[512];
        long number = -1;
        unsigned long long args[6] = {0};
        if (!read_proc(state, "syscall", call, sizeof(call)) ||
            sscanf(call, "%ld %llx %llx %llx %llx %llx %llx", &number,
                   &args[0], &args[1], &args[2], &args[3], &args[4], &args[5]) < 5)
            goto retry_reuse;
        int found = number == raw && same_io_object(args[0], fd);
        if (expect_native && number == SYS_ppoll && args[1] == 1) {
            struct pollfd interest;
            found = snapshot(memory, args[0], &interest, sizeof(interest)) &&
                    same_io_object((unsigned)interest.fd, fd) &&
                    interest.events == (writing ? POLLOUT : POLLIN);
        }
        if (!found || !read_proc(state, "stat", status, sizeof(status))) goto retry_reuse;
        char *end = strrchr(status, ')');
        if (end != NULL && end[1] == ' ' && end[2] == 'S') return;
retry_reuse:
        pause_briefly();
    }
    fail("no independently observed sleeping I/O on the original socket");
}

static int io_reuse_contract_main(char **argv) {
    const char *names[] = {"read", "recv", "recvfrom", "recvmsg", "readv",
                           "write", "send", "sendto", "sendmsg", "writev"};
    const long raw[] = {SYS_read, SYS_recvfrom, SYS_recvfrom, SYS_recvmsg, SYS_readv,
                        SYS_write, SYS_sendto, SYS_sendto, SYS_sendmsg, SYS_writev};
    const char *name = case_name + strlen("fd-reuse-");
    enum descriptor_transport transport = parse_descriptor_transport(&name);
    int api = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(name, names[i]) == 0) api = (int)i;
    if (api < 0) return 2;
    int writing = api >= 5;
    int entry = api == 5 ? 3 : api == 9 ? 4 : api - 6;
    int pin = writing ? pin_send_provider(argv[2], entry, 0) :
        pin_receive_provider(argv[2], api == 2, 0, 0, api == 3, api == 0 || api == 4, api == 4);
    if (pin != 0) return pin;
    expect_native = getenv("FRANKENLIBC_THREAD_NATIVE") != NULL &&
                    strcmp(getenv("FRANKENLIBC_THREAD_NATIVE"), "1") == 0;
    creator_tp = (uintptr_t)__builtin_thread_pointer();
    creator_tid = (pid_t)syscall(SYS_gettid);
    creator_thread = pthread_self();
    struct sigaction action = {0};
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    REQUIRE(sigaction(SIGUSR1, &action, NULL) == 0, "reuse test signal disposition");
    alarm(15);
    int original[2], replacement[2];
    descriptor_socket_pair(transport, original);
    descriptor_socket_pair(transport, replacement);
    int keeper = (int)syscall(SYS_fcntl, original[0], F_DUPFD_CLOEXEC, 64);
    REQUIRE(keeper >= 64, "retain the original socket without retaining its public number");
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (memory < 0) skip("fd-reuse-snapshot-unavailable");
    int original_flags = fcntl(original[0], F_GETFL);
    int replacement_flags = fcntl(replacement[0], F_GETFL);
    size_t initial = 0, filler = 0, payload = 0;
    int empty_records = 0;
    if (writing) {
        int capacity = 8192;
        REQUIRE(setsockopt(original[0], SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) == 0,
                "bound the original socket's send buffer");
        initial = fill_send_socket(original[0]);
    }
    struct receive_probe receiver;
    struct send_probe sender;
    struct state *state;
    if (writing) {
        send_initialize(&sender, SEND_READY_LATE, original[0], entry, 0);
        sender.socket_type = transport == DESCRIPTOR_SEQPACKET ? SOCK_SEQPACKET :
                             transport == DESCRIPTOR_DATAGRAM ? SOCK_DGRAM : SOCK_STREAM;
        state = &sender.observed;
    } else {
        receive_initialize(&receiver, RECEIVE_READY_LATE, original[0], api == 2, 0,
                           api == 3, 0, api == 0 || api == 4, api == 4);
        if (api == 3) {
            receiver.header.msg_control = NULL;
            receiver.header.msg_controllen = 0;
        }
        state = &receiver.observed;
    }
    size_t original_descriptors = descriptor_count();
    REQUIRE(pthread_create(&state->thread, NULL, writing ? send_worker : receive_worker,
                           writing ? (void *)&sender : (void *)&receiver) == 0,
            "create descriptor reuse worker");
    wait_ready(state);
    atomic_store_explicit(&state->release, 1, memory_order_release);
    observe_reuse_parked(state, memory, original[0], raw[api], writing);
    REQUIRE(syscall(SYS_dup2, replacement[0], original[0]) == original[0],
            "atomically close and replace the public descriptor number");
    if (writing) {
        int64_t deadline = monotonic_ns() + 2000000000;
        while (!atomic_load_explicit(&state->returned, memory_order_acquire)) {
            REQUIRE(monotonic_ns() < deadline, "bounded original socket write completion");
            drain_send_socket(original[1], initial, &filler, &payload, &empty_records, &sender);
            pause_briefly();
        }
    } else {
        send_receive_bytes(original[1], "DATA", receiver.length);
        send_receive_bytes(replacement[1], "NEW!", receiver.length);
    }
    REQUIRE(join_bounded(state) == state && state->cleaned == 1 && state->error == EDOM,
            "reused descriptor I/O completes normally and cleans up once");
    if (writing) {
        drain_send_socket(original[1], initial, &filler, &payload, &empty_records, &sender);
        REQUIRE(state->result == (int)sender.length && filler == initial && payload == sender.length &&
                    empty_records == 0,
                "blocked writes publish their entire payload only to the original socket");
        unsigned char byte;
        REQUIRE(syscall(SYS_recvfrom, replacement[1], &byte, 1, MSG_DONTWAIT, NULL, NULL) == -1 &&
                    errno == EAGAIN, "descriptor replacement receives no misdirected write bytes");
    } else {
        REQUIRE(state->result == (int)receiver.length &&
                    memcmp(receiver.data, "DATA", receiver.length) == 0,
                "blocked reads consume the original socket's bytes after descriptor reuse");
        unsigned char bytes[8];
        REQUIRE(syscall(SYS_recvfrom, replacement[0], bytes, sizeof(bytes), MSG_DONTWAIT,
                        NULL, NULL) == (ssize_t)receiver.length &&
                    memcmp(bytes, "NEW!", receiver.length) == 0,
                "descriptor replacement retains its independent queued bytes");
        REQUIRE(syscall(SYS_recvfrom, keeper, bytes, sizeof(bytes), MSG_DONTWAIT, NULL, NULL) == -1 &&
                    errno == EAGAIN, "original receive payload is consumed exactly once");
    }
    REQUIRE(fcntl(keeper, F_GETFL) == original_flags && fcntl(replacement[0], F_GETFL) == replacement_flags,
            "reuse protection does not mutate either open file's status flags");
    REQUIRE(descriptor_count() == original_descriptors,
            "reused I/O releases its private pin after normal completion");
    REQUIRE(close(original[0]) == 0 && close(original[1]) == 0 &&
                close(replacement[0]) == 0 && close(replacement[1]) == 0 &&
                close(keeper) == 0 && close(memory) == 0,
            "release all descriptor reuse fixture resources");
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}

/* sendmmsg must preserve both record ownership and each msg_len publication
 * while a native cancellation request arrives during socket backpressure. */
enum batch_send_kind {
    BATCH_BLOCKED, BATCH_PENDING, BATCH_DISABLED, BATCH_READY, BATCH_READY_LATE,
    BATCH_NONBLOCK, BATCH_DONTWAIT, BATCH_TIMEOUT, BATCH_SIGNAL, BATCH_SIGNAL_RESTART,
    BATCH_PARTIAL_ERROR, BATCH_ERRORS, BATCH_ZERO, BATCH_COUNT_ZERO,
    BATCH_RIGHTS_INVALID, BATCH_OUTPUT_FAULT, BATCH_REUSE
};
static int (*selected_sendmmsg)(int, struct mmsghdr *, unsigned int, int);
struct batch_send_probe {
    struct state observed;
    enum batch_send_kind kind;
    int fd, flags;
    unsigned count;
    struct mmsghdr messages[3], *active;
    struct iovec vectors[3];
    unsigned char bytes[3];
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
};

static int pin_batch_send_provider(const char *expected, int alias) {
    int base = pin_providers(expected, 0, EVENT_NONE);
    if (base) return base;
    const char *name = alias ? "__sendmmsg" : "sendmmsg";
    void *symbol = dlsym(RTLD_DEFAULT, name);
    Dl_info info = {0};
    struct stat actual, wanted;
    if (!symbol || !dladdr(symbol, &info) || !info.dli_fname ||
        stat(expected, &wanted) || stat(info.dli_fname, &actual) ||
        actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
        fprintf(stderr, "pthread-native-poll:provider-mismatch:%s\n", name);
        return 86;
    }
    selected_sendmmsg = (__typeof__(selected_sendmmsg))symbol;
    return 0;
}

static void batch_send_cleanup(void *argument) {
    struct batch_send_probe *probe = argument;
    sigset_t mask;
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0 &&
                sigismember(&mask, SIGUSR1) == 0 && sigismember(&mask, SIGUSR2) == 1,
            "batch send cleanup preserves the complete entry signal mask");
    REQUIRE(atomic_fetch_add_explicit(&probe->observed.cleaned, 1, memory_order_release) == 0,
            "batch send cleanup runs once");
}

static void *batch_send_worker(void *argument) {
    struct batch_send_probe *probe = argument;
    struct state *state = &probe->observed;
    capture_identity(state);
    REQUIRE(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0,
            "deferred batch send cancellation");
    if (probe->kind == BATCH_DISABLED)
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0,
                "disable batch send cancellation");
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    REQUIRE(pthread_sigmask(SIG_SETMASK, &mask, NULL) == 0, "batch send entry mask");
    pthread_cleanup_push(batch_send_cleanup, probe);
    atomic_store_explicit(&state->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&state->release, memory_order_acquire))
        (void)syscall(SYS_sched_yield);
    errno = EDOM;
    int64_t started = monotonic_ns();
    if (probe->kind == BATCH_ERRORS) {
        REQUIRE(selected_sendmmsg(-1, (void *)(uintptr_t)1, 1, MSG_NOSIGNAL) == -1 && errno == EBADF,
                "sendmmsg retains invalid-descriptor precedence");
        int pipefd[2];
        REQUIRE(pipe2(pipefd, O_CLOEXEC) == 0, "batch error pipe");
        REQUIRE(selected_sendmmsg(pipefd[1], (void *)(uintptr_t)1, 1, MSG_NOSIGNAL) == -1 &&
                    errno == ENOTSOCK, "sendmmsg retains nonsocket precedence");
        REQUIRE(close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "close batch error pipe");
        REQUIRE(selected_sendmmsg(probe->fd, (void *)(uintptr_t)1, 1, MSG_NOSIGNAL) == -1 &&
                    errno == EFAULT, "sendmmsg keeps fault-checked header import");
        state->result = 0;
    } else {
        if (probe->kind == BATCH_RIGHTS_INVALID) {
            int invalid = (int)syscall(SYS_fcntl, probe->fd, F_DUPFD_CLOEXEC, 0);
            REQUIRE(invalid >= 0 && syscall(SYS_close, invalid) == 0,
                    "reserve the fd an unsafe socket pin would occupy");
            memcpy(CMSG_DATA(CMSG_FIRSTHDR(&probe->messages[0].msg_hdr)), &invalid, sizeof(invalid));
        }
        state->result = selected_sendmmsg(probe->fd, probe->active, probe->count, probe->flags);
    }
    state->error = errno;
    state->elapsed_ns = monotonic_ns() - started;
    atomic_store_explicit(&state->returned, 1, memory_order_release);
    pthread_cleanup_pop(1);
    if (probe->kind == BATCH_DISABLED) {
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0,
                "restore batch send cancellation");
        pthread_testcancel();
        fail("batch send lost a disabled cancellation request");
    }
    return state;
}

static size_t fill_batch_socket(int fd) {
    size_t count = 0;
    while (syscall(SYS_sendto, fd, "F", 1, MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0) == 1)
        ++count;
    REQUIRE(count != 0 && errno == EAGAIN, "fill socket with independent one-byte records");
    return count;
}

static void drain_batch_socket(int fd, size_t initial, size_t *filler, unsigned *records,
                               const struct batch_send_probe *probe) {
    for (;;) {
        unsigned char byte[8];
        ssize_t count = syscall(SYS_recvfrom, fd, byte, sizeof(byte), MSG_DONTWAIT, NULL, NULL);
        if (count < 0) {
            REQUIRE(errno == EAGAIN, "batch drain only consumes available records");
            return;
        }
        if (*filler < initial) {
            REQUIRE(count == 1 && byte[0] == 'F', "batch preserves queued filler records");
            ++*filler;
        } else {
            REQUIRE(*records < 3, "batch never replays a committed record");
            size_t length = probe->kind == BATCH_ZERO || *records == 2 ? 0 : 1;
            REQUIRE(count == (ssize_t)length &&
                        (length == 0 || byte[0] == (unsigned char)('A' + *records)),
                    "batch preserves record order, payload and empty-message boundaries");
            ++*records;
        }
    }
}

static int batch_send_contract_once(char **argv, int fault_after_prefix, int udp_binding) {
    const char *suffix = case_name + strlen("sendmmsg-");
    int alias = strncmp(suffix, "alias-", 6) == 0;
    if (alias) suffix += 6;
    int type;
    if (strncmp(suffix, "datagram-", 9) == 0) { type = SOCK_DGRAM; suffix += 9; }
    else if (strncmp(suffix, "seqpacket-", 10) == 0) { type = SOCK_SEQPACKET; suffix += 10; }
    else return 2;
    int timed = strncmp(suffix, "timed-", 6) == 0;
    if (timed) suffix += 6;
    int separate_budgets = timed && strcmp(suffix, "budgets") == 0;
    if (separate_budgets) suffix = "ready-late";
    const char *names[] = {
        "blocked", "pending", "disabled", "ready", "ready-late", "nonblock", "dontwait",
        "timeout", "signal", "signal-restart", "partial-error", "errors", "zero", "count-zero",
        "rights-invalid", "output-fault", "reuse"
    };
    int value = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(suffix, names[i]) == 0) value = (int)i;
    if (value < 0) return 2;
    enum batch_send_kind kind = (enum batch_send_kind)value;
    int pin = pin_batch_send_provider(argv[2], alias);
    if (pin) return pin;
    expect_native = getenv("FRANKENLIBC_THREAD_NATIVE") != NULL &&
                    strcmp(getenv("FRANKENLIBC_THREAD_NATIVE"), "1") == 0;
    creator_tp = (uintptr_t)__builtin_thread_pointer();
    creator_tid = (pid_t)syscall(SYS_gettid);
    creator_thread = pthread_self();
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = kind == BATCH_SIGNAL || kind == BATCH_SIGNAL_RESTART ? user_signal : SIG_DFL;
    action.sa_flags = kind == BATCH_SIGNAL_RESTART ? SA_RESTART : 0;
    REQUIRE(sigaction(SIGUSR1, &action, NULL) == 0, "batch signal disposition");
    alarm(15);
    int pair[2];
    struct sockaddr_in destination = {0};
    if (!udp_binding) {
        REQUIRE(socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, pair) == 0, "batch socket pair");
    } else {
        pair[0] = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        pair[1] = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        REQUIRE(pair[0] >= 0 && pair[1] >= 0, "batch UDP endpoints");
        struct sockaddr_in local = {0};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(bind(pair[1], (struct sockaddr *)&local, sizeof(local)) == 0,
                "bind batch UDP receiver");
        if (udp_binding == 1)
            REQUIRE(bind(pair[0], (struct sockaddr *)&local, sizeof(local)) == 0,
                    "explicitly bind batch UDP sender");
        socklen_t length = sizeof(destination);
        REQUIRE(getsockname(pair[1], (struct sockaddr *)&destination, &length) == 0 &&
                    length == sizeof(destination) && destination.sin_port != 0,
                "capture live UDP destination port");
        length = sizeof(local);
        REQUIRE(getsockname(pair[0], (struct sockaddr *)&local, &length) == 0 &&
                    ((local.sin_port != 0) == (udp_binding == 1)),
                "UDP sender binding matches the intended admission or fallback path");
    }
    int send_buffer = 8192;
    REQUIRE(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) == 0,
            "bounded batch send buffer");
    if (kind == BATCH_NONBLOCK)
        REQUIRE(fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_NONBLOCK) == 0,
                "caller-owned nonblocking batch socket");
    if (timed || kind == BATCH_TIMEOUT) {
        struct timeval timeout = {kind == BATCH_TIMEOUT || separate_budgets ? 0 : 4,
                                  separate_budgets ? 500000 : 150001};
        REQUIRE(setsockopt(pair[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0,
                "caller-owned batch timeout");
    }
    int original_flags = fcntl(pair[0], F_GETFL);
    REQUIRE(original_flags >= 0, "capture batch socket flags");
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (memory < 0) skip("batch-send-wait-snapshot-unavailable");
    int blocked = kind == BATCH_BLOCKED || kind == BATCH_DISABLED || kind == BATCH_READY_LATE ||
                  kind == BATCH_SIGNAL || kind == BATCH_SIGNAL_RESTART || kind == BATCH_REUSE;
    size_t initial = 0, filler = 0;
    unsigned records = 0;
    if (blocked || kind == BATCH_NONBLOCK || kind == BATCH_DONTWAIT || kind == BATCH_TIMEOUT)
        initial = fill_batch_socket(pair[0]);
    int keeper = -1, replacement[2] = {-1, -1};
    if (kind == BATCH_REUSE) {
        keeper = fcntl(pair[0], F_DUPFD_CLOEXEC, 3);
        REQUIRE(keeper >= 0 && socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, replacement) == 0,
                "prepare batch descriptor replacement");
    }
    struct batch_send_probe probe;
    memset(&probe, 0, sizeof(probe));
    probe.kind = kind;
    probe.fd = pair[0];
    probe.flags = MSG_NOSIGNAL | (kind == BATCH_DONTWAIT ? MSG_DONTWAIT : 0);
    probe.count = kind == BATCH_COUNT_ZERO ? 0 : kind == BATCH_ZERO ? 1 :
                  kind == BATCH_OUTPUT_FAULT ? 1U + (unsigned)fault_after_prefix : 3;
    probe.active = probe.messages;
    for (unsigned i = 0; i < 3; ++i) {
        probe.bytes[i] = (unsigned char)('A' + i);
        probe.vectors[i] = (struct iovec){&probe.bytes[i], i == 2 || kind == BATCH_ZERO ? 0 : 1};
        probe.messages[i].msg_hdr.msg_iov = &probe.vectors[i];
        probe.messages[i].msg_hdr.msg_iovlen = 1;
        if (udp_binding) {
            probe.messages[i].msg_hdr.msg_name = &destination;
            probe.messages[i].msg_hdr.msg_namelen = sizeof(destination);
        }
        probe.messages[i].msg_len = UINT32_C(0xa5a5a5a5);
    }
    if (kind == BATCH_PARTIAL_ERROR) probe.vectors[1].iov_base = (void *)(uintptr_t)1;
    if (kind == BATCH_RIGHTS_INVALID) {
        probe.messages[0].msg_hdr.msg_control = probe.control.bytes;
        probe.messages[0].msg_hdr.msg_controllen = sizeof(probe.control.bytes);
        struct cmsghdr *control = CMSG_FIRSTHDR(&probe.messages[0].msg_hdr);
        control->cmsg_level = SOL_SOCKET;
        control->cmsg_type = SCM_RIGHTS;
        control->cmsg_len = CMSG_LEN(sizeof(int));
    }
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *read_only = MAP_FAILED;
    if (kind == BATCH_OUTPUT_FAULT) {
        read_only = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(read_only != MAP_FAILED, "batch output guard mapping");
        /* Place either the first or second entry in a read-only page. Linux
         * transmits that record before faulting its msg_len publication. */
        probe.active = (struct mmsghdr *)((unsigned char *)read_only + page -
                         (fault_after_prefix ? sizeof(struct mmsghdr) : 0));
        memcpy(probe.active, probe.messages, probe.count * sizeof(*probe.active));
        REQUIRE(mprotect((unsigned char *)read_only + page, page, PROT_READ) == 0,
                "readable message header with unwritable msg_len");
    }
    struct iovec original_vectors[3];
    struct msghdr original_headers[3];
    memcpy(original_vectors, probe.vectors, sizeof(original_vectors));
    for (unsigned i = 0; i < 3; ++i)
        memcpy(&original_headers[i], &probe.messages[i].msg_hdr, sizeof(original_headers[i]));
    probe.observed.result = -222;
    atomic_init(&probe.observed.ready, 0);
    atomic_init(&probe.observed.release, 0);
    atomic_init(&probe.observed.returned, 0);
    atomic_init(&probe.observed.cleaned, 0);
    size_t original_descriptors = descriptor_count();
    REQUIRE(pthread_create(&probe.observed.thread, NULL, batch_send_worker, &probe) == 0,
            "create batch send worker");
    wait_ready(&probe.observed);
    if (kind == BATCH_PENDING)
        REQUIRE(pthread_cancel(probe.observed.thread) == 0, "pending batch cancellation");
    atomic_store_explicit(&probe.observed.release, 1, memory_order_release);
    if (blocked) {
        /* Accept both the old raw wait and the new bounded ppoll. The old
         * implementation must fail on cancellation, not a changed wait shape. */
        observe_reuse_parked(&probe.observed, memory, pair[0], SYS_sendmmsg, 1);
        if (kind == BATCH_BLOCKED || kind == BATCH_DISABLED)
            REQUIRE(pthread_cancel(probe.observed.thread) == 0, "blocked batch cancellation");
        if (kind == BATCH_SIGNAL || kind == BATCH_SIGNAL_RESTART) {
            REQUIRE(pthread_kill(probe.observed.thread, SIGUSR1) == 0, "interrupt batch send");
            int64_t deadline = monotonic_ns() + 2000000000;
            while (!atomic_load_explicit(&signals_delivered, memory_order_acquire)) {
                REQUIRE(monotonic_ns() < deadline, "batch signal delivery deadline");
                pause_briefly();
            }
            if (kind == BATCH_SIGNAL_RESTART)
                observe_reuse_parked(&probe.observed, memory, pair[0], SYS_sendmmsg, 1);
        }
        if (kind == BATCH_REUSE)
            REQUIRE(dup2(replacement[0], pair[0]) == pair[0], "replace public batch socket fd");
        if (kind == BATCH_DISABLED || kind == BATCH_READY_LATE ||
            kind == BATCH_SIGNAL_RESTART || kind == BATCH_REUSE) {
            if (separate_budgets) {
                int64_t deadline = monotonic_ns() + 300000000;
                while (monotonic_ns() < deadline) {
                    REQUIRE(!probe.observed.returned, "first batch message waits for its own budget");
                    pause_briefly();
                }
                unsigned char byte = 0;
                REQUIRE(syscall(SYS_recvfrom, pair[1], &byte, 1, MSG_DONTWAIT, NULL, NULL) == 1 && byte == 'F',
                        "free exactly one record slot after part of the first timeout");
                ++filler;
                unsigned first_length = UINT32_C(0xa5a5a5a5);
                deadline = monotonic_ns() + 2000000000;
                while (first_length != 1) {
                    REQUIRE(!probe.observed.returned && monotonic_ns() < deadline,
                            "first batch message publishes before its successor can proceed");
                    REQUIRE(snapshot(memory, (unsigned long long)(uintptr_t)&probe.active[0].msg_len,
                                     &first_length, sizeof(first_length)),
                            "observe the committed first record without racing C memory");
                    if (first_length != 1) pause_briefly();
                }
                deadline = monotonic_ns() + 300000000;
                while (monotonic_ns() < deadline) {
                    REQUIRE(!probe.observed.returned,
                            "second batch message receives a fresh timeout instead of the first message's remainder");
                    pause_briefly();
                }
            }
            int64_t deadline = monotonic_ns() + 2000000000;
            while (!atomic_load_explicit(&probe.observed.returned, memory_order_acquire)) {
                REQUIRE(monotonic_ns() < deadline, "batch completion after draining backpressure");
                drain_batch_socket(pair[1], initial, &filler, &records, &probe);
                pause_briefly();
            }
        }
    }
    void *result = join_bounded(&probe.observed);
    int canceled = kind == BATCH_PENDING || kind == BATCH_BLOCKED || kind == BATCH_DISABLED;
    REQUIRE(result == (canceled ? PTHREAD_CANCELED : &probe.observed), "batch join result");
    REQUIRE(probe.observed.cleaned == 1, "batch cleanup count");
    if (separate_budgets)
        REQUIRE(probe.observed.elapsed_ns > 500000000,
                "the complete batch may outlive one message's timeout while each message succeeds");
    unsigned published = 0, delivered = 0;
    if (kind == BATCH_PENDING || kind == BATCH_BLOCKED) {
        REQUIRE(!probe.observed.returned, "batch cancellation precedes result publication");
    } else if (kind == BATCH_NONBLOCK || kind == BATCH_DONTWAIT || kind == BATCH_TIMEOUT) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EAGAIN,
                "batch nonblocking and timeout error contracts");
        if (kind == BATCH_TIMEOUT)
            REQUIRE(probe.observed.elapsed_ns >= 100000000 && probe.observed.elapsed_ns < 2000000000,
                    "batch timeout keeps its kernel deadline");
    } else if (kind == BATCH_SIGNAL) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EINTR,
                "batch send retains non-restarting EINTR");
    } else if (kind == BATCH_RIGHTS_INVALID) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EBADF,
                "batch pin does not legitimize invalid SCM_RIGHTS");
    } else if (kind == BATCH_OUTPUT_FAULT) {
        published = fault_after_prefix ? 1U : 0U;
        delivered = published + 1U;
        REQUIRE(probe.observed.result == (fault_after_prefix ? 1 : -1) &&
                    probe.observed.error == (fault_after_prefix ? EDOM : EFAULT),
                "batch retains its published prefix after a later msg_len fault");
        REQUIRE(probe.active[published].msg_len == UINT32_C(0xa5a5a5a5),
                "faulted msg_len remains unchanged after exactly one transmission");
    } else if (kind != BATCH_ERRORS) {
        published = delivered = kind == BATCH_PARTIAL_ERROR ? 1 : probe.count;
        REQUIRE(probe.observed.result == (int)published && probe.observed.error == EDOM,
                "batch returns its exact committed prefix without clobbering errno");
    }
    if (udp_binding) {
        int64_t deadline = monotonic_ns() + 2000000000;
        while (records < delivered) {
            drain_batch_socket(pair[1], initial, &filler, &records, &probe);
            if (records < delivered) {
                REQUIRE(monotonic_ns() < deadline, "loopback batch datagram delivery deadline");
                pause_briefly();
            }
        }
        struct sockaddr_in local = {0};
        socklen_t length = sizeof(local);
        REQUIRE(getsockname(pair[0], (struct sockaddr *)&local, &length) == 0 &&
                    length == sizeof(local) && local.sin_port != 0,
                "successful UDP batch preserves explicit binding or performs kernel autobind");
    }
    drain_batch_socket(pair[1], initial, &filler, &records, &probe);
    REQUIRE(filler == initial && records == delivered, "batch records are delivered exactly once");
    for (unsigned i = 0; i < 3; ++i) {
        unsigned expected = i < published ? (unsigned)probe.vectors[i].iov_len : UINT32_C(0xa5a5a5a5);
        unsigned actual = i < probe.count ? probe.active[i].msg_len : probe.messages[i].msg_len;
        REQUIRE(actual == expected, "only completed batch entries publish msg_len");
        const struct msghdr *actual_header = i < probe.count ?
            &probe.active[i].msg_hdr : &probe.messages[i].msg_hdr;
        REQUIRE(memcmp(actual_header, &original_headers[i], sizeof(original_headers[i])) == 0,
                "batch preserves each caller input header");
    }
    REQUIRE(memcmp(probe.vectors, original_vectors, sizeof(original_vectors)) == 0,
            "batch preserves caller iovec geometry");
    if (kind == BATCH_REUSE) {
        unsigned char byte;
        REQUIRE(syscall(SYS_recvfrom, replacement[1], &byte, 1, MSG_DONTWAIT, NULL, NULL) == -1 &&
                    errno == EAGAIN, "batch cannot migrate to a replacement open file description");
    }
    REQUIRE(descriptor_count() == original_descriptors, "batch releases every private descriptor");
    REQUIRE(fcntl(pair[0], F_GETFL) == original_flags, "batch leaves shared socket status flags unchanged");
    REQUIRE(close(memory) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0,
            "release batch fixture descriptors");
    if (keeper >= 0)
        REQUIRE(close(keeper) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0,
                "release batch replacement descriptors");
    if (read_only != MAP_FAILED) REQUIRE(munmap(read_only, 2 * page) == 0, "release batch output mapping");
    return 0;
}

static int batch_send_contract_main(char **argv) {
    int result = batch_send_contract_once(argv, 0, 0);
    if (result != 0) return result;
    if (strstr(case_name, "-output-fault") != NULL) {
        result = batch_send_contract_once(argv, 1, 0);
        if (result != 0) return result;
    }
    if (strcmp(case_name, "sendmmsg-datagram-ready") == 0) {
        for (int udp_binding = 1; udp_binding <= 2; ++udp_binding) {
            result = batch_send_contract_once(argv, 0, udp_binding);
            if (result != 0) return result;
        }
    }
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}


/* Keep the complete kernel receive batch: recvmmsg defers a later error on
 * the socket after returning a successful prefix. */
enum batch_receive_kind {
    BATCH_RECEIVE_BLOCKED, BATCH_RECEIVE_PENDING, BATCH_RECEIVE_DISABLED,
    BATCH_RECEIVE_READY, BATCH_RECEIVE_READY_LATE, BATCH_RECEIVE_PREFIX,
    BATCH_RECEIVE_SINGLE, BATCH_RECEIVE_SINGLE_BLOCKED, BATCH_RECEIVE_FULL,
    BATCH_RECEIVE_NONBLOCK, BATCH_RECEIVE_DONTWAIT, BATCH_RECEIVE_TIMEOUT,
    BATCH_RECEIVE_FINITE, BATCH_RECEIVE_TRUNC_EMPTY, BATCH_RECEIVE_OUTPUT_FAULT,
    BATCH_RECEIVE_ERRORS, BATCH_RECEIVE_COUNT_ZERO, BATCH_RECEIVE_REUSE,
    BATCH_RECEIVE_RIGHTS, BATCH_RECEIVE_SIGNAL, BATCH_RECEIVE_SIGNAL_RESTART
};
static int (*selected_recvmmsg)(int, struct mmsghdr *, unsigned int, int, struct timespec *);
struct batch_receive_probe {
    struct state observed;
    enum batch_receive_kind kind;
    int fd, flags, expected_right, fault_after_prefix;
    int deferred_result, deferred_error, explicit_timeout, copy_denied;
    unsigned count;
    struct timespec timeout, *timeout_argument;
    unsigned char timeout_bytes[sizeof(struct timespec) + 1];
    struct mmsghdr messages[3], *active;
    struct iovec vectors[3];
    unsigned char bytes[3][4];
    struct sockaddr_storage addresses[3];
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control;
};

static int pin_batch_receive_provider(const char *expected) {
    int base = pin_providers(expected, 0, EVENT_NONE);
    if (base) return base;
    void *symbol = dlsym(RTLD_DEFAULT, "recvmmsg");
    Dl_info info = {0};
    struct stat actual, wanted;
    if (!symbol || !dladdr(symbol, &info) || !info.dli_fname ||
        stat(expected, &wanted) || stat(info.dli_fname, &actual) ||
        actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
        fprintf(stderr, "pthread-native-poll:provider-mismatch:recvmmsg\n");
        return 86;
    }
    selected_recvmmsg = (__typeof__(selected_recvmmsg))symbol;
    return 0;
}

static void batch_receive_cleanup(void *argument) {
    struct batch_receive_probe *probe = argument;
    sigset_t mask;
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0 &&
                sigismember(&mask, SIGUSR1) == 0 && sigismember(&mask, SIGUSR2) == 1,
            "batch receive cleanup preserves the complete entry signal mask");
    REQUIRE(atomic_fetch_add_explicit(&probe->observed.cleaned, 1, memory_order_release) == 0,
            "batch receive cleanup runs once");
}

static void *batch_receive_worker(void *argument) {
    struct batch_receive_probe *probe = argument;
    struct state *state = &probe->observed;
    capture_identity(state);
    REQUIRE(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0,
            "deferred batch receive cancellation");
    if (probe->kind == BATCH_RECEIVE_DISABLED)
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0,
                "disable batch receive cancellation");
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    REQUIRE(pthread_sigmask(SIG_SETMASK, &mask, NULL) == 0, "batch receive entry mask");
    pthread_cleanup_push(batch_receive_cleanup, probe);
    atomic_store_explicit(&state->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&state->release, memory_order_acquire))
        (void)syscall(SYS_sched_yield);
    if (probe->copy_denied) deny_io_probe(SYS_process_vm_readv, EPERM);
    errno = EDOM;
    int64_t started = monotonic_ns();
    if (probe->kind == BATCH_RECEIVE_ERRORS) {
        if (probe->explicit_timeout) {
            REQUIRE(selected_recvmmsg(-1, (void *)(uintptr_t)1, 1, MSG_WAITFORONE,
                                     (struct timespec *)(uintptr_t)1) == -1 && errno == EFAULT,
                    "recvmmsg imports its timeout before validating the descriptor");
            const struct timespec invalid[] = {{-1, 0}, {0, -1}, {0, 1000000000}};
            for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
                struct timespec timeout = invalid[i];
                REQUIRE(selected_recvmmsg(-1, (void *)(uintptr_t)1, 1, MSG_WAITFORONE,
                                         &timeout) == -1 && errno == EINVAL,
                        "recvmmsg validates timeout syntax before the descriptor and message");
            }
        }
        REQUIRE(selected_recvmmsg(-1, (void *)(uintptr_t)1, 1, MSG_WAITFORONE,
                                 probe->timeout_argument) == -1 &&
                    errno == EBADF, "recvmmsg retains invalid-descriptor precedence");
        int pipefd[2];
        REQUIRE(pipe2(pipefd, O_CLOEXEC) == 0, "batch receive error pipe");
        REQUIRE(selected_recvmmsg(pipefd[0], (void *)(uintptr_t)1, 1, MSG_WAITFORONE,
                                 probe->timeout_argument) == -1 &&
                    errno == ENOTSOCK, "recvmmsg retains nonsocket precedence");
        REQUIRE(close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "close batch receive error pipe");
        REQUIRE(selected_recvmmsg(probe->fd, (void *)(uintptr_t)1, 1, MSG_WAITFORONE,
                                 probe->timeout_argument) == -1 &&
                    errno == EFAULT, "recvmmsg keeps fault-checked header import");
        state->result = 0;
    } else {
        if (probe->kind == BATCH_RECEIVE_RIGHTS) {
            probe->expected_right = (int)syscall(SYS_fcntl, probe->fd, F_DUPFD_CLOEXEC, 3);
            REQUIRE(probe->expected_right >= 0 &&
                        syscall(SYS_close, probe->expected_right) == 0,
                    "reserve the descriptor a receive pin must not consume");
        }
        state->result = selected_recvmmsg(probe->fd, probe->active, probe->count,
                                         probe->flags, probe->timeout_argument);
    }
    state->error = errno;
    state->elapsed_ns = monotonic_ns() - started;
    if (probe->kind == BATCH_RECEIVE_OUTPUT_FAULT && probe->fault_after_prefix) {
        unsigned char byte = 0xa5;
        struct iovec vector = {&byte, 1};
        struct mmsghdr next = {0};
        next.msg_hdr.msg_iov = &vector;
        next.msg_hdr.msg_iovlen = 1;
        next.msg_len = UINT32_C(0xa5a5a5a5);
        probe->deferred_result = selected_recvmmsg(probe->fd, &next, 1, MSG_DONTWAIT, NULL);
        probe->deferred_error = errno;
        REQUIRE(byte == 0xa5 && next.msg_len == UINT32_C(0xa5a5a5a5),
                "the deferred receive error consumes no following record");
    }
    atomic_store_explicit(&state->returned, 1, memory_order_release);
    pthread_cleanup_pop(1);
    if (probe->kind == BATCH_RECEIVE_DISABLED) {
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0,
                "restore batch receive cancellation");
        pthread_testcancel();
        fail("batch receive lost a disabled cancellation request");
    }
    return state;
}

static size_t batch_receive_length(unsigned index, int truncated) {
    return truncated ? (index == 0 ? 4 : index == 1 ? 0 : 1) : (index == 2 ? 0 : 1);
}

static void feed_batch_receive(int fd, unsigned index, int truncated) {
    const char *payload = index == 0 ? (truncated ? "ABCD" : "A") : index == 1 ? "B" : "C";
    size_t length = batch_receive_length(index, truncated);
    REQUIRE(syscall(SYS_sendto, fd, payload, length, MSG_NOSIGNAL, NULL, 0) == (long)length,
            "queue an independent batch receive record");
}

static int batch_receive_contract_once(char **argv, int fault_after_prefix, int udp) {
    const char *suffix = case_name + strlen("recvmmsg-");
    int type;
    if (strncmp(suffix, "datagram-", 9) == 0) { type = SOCK_DGRAM; suffix += 9; }
    else if (strncmp(suffix, "seqpacket-", 10) == 0) { type = SOCK_SEQPACKET; suffix += 10; }
    else return 2;
    int timed = strncmp(suffix, "timed-", 6) == 0;
    if (timed) suffix += 6;
    int explicit_timeout = strncmp(suffix, "explicit-", 9) == 0;
    if (explicit_timeout) suffix += 9;
    int readonly_timeout = explicit_timeout && strncmp(suffix, "readonly-", 9) == 0;
    if (readonly_timeout) suffix += 9;
    int zero_timeout = explicit_timeout && strncmp(suffix, "zero-", 5) == 0;
    if (zero_timeout) suffix += 5;
    int expired_timeout = explicit_timeout && strncmp(suffix, "expired-", 8) == 0;
    if (expired_timeout) suffix += 8;
    int unaligned_timeout = explicit_timeout && strncmp(suffix, "unaligned-", 10) == 0;
    if (unaligned_timeout) suffix += 10;
    int aliased_timeout = explicit_timeout && strncmp(suffix, "alias-", 6) == 0;
    if (aliased_timeout) suffix += 6;
    int copy_denied = explicit_timeout && strncmp(suffix, "denied-", 7) == 0;
    if (copy_denied) suffix += 7;
    const char *names[] = {
        "blocked", "pending", "disabled", "ready", "ready-late", "prefix",
        "single", "single-blocked", "fullbatch", "nonblock", "dontwait", "timeout",
        "finite-timeout", "trunc-empty", "output-fault", "errors", "count-zero", "reuse",
        "rights", "signal", "signal-restart"
    };
    int value = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(suffix, names[i]) == 0) value = (int)i;
    if (value < 0) return 2;
    enum batch_receive_kind kind = (enum batch_receive_kind)value;
    int pin = pin_batch_receive_provider(argv[2]);
    if (pin) return pin;
    expect_native = getenv("FRANKENLIBC_THREAD_NATIVE") != NULL &&
                    strcmp(getenv("FRANKENLIBC_THREAD_NATIVE"), "1") == 0;
    creator_tp = (uintptr_t)__builtin_thread_pointer();
    creator_tid = (pid_t)syscall(SYS_gettid);
    creator_thread = pthread_self();
    struct sigaction action = {0};
    sigemptyset(&action.sa_mask);
    action.sa_handler = kind == BATCH_RECEIVE_SIGNAL || kind == BATCH_RECEIVE_SIGNAL_RESTART ?
                        user_signal : SIG_DFL;
    action.sa_flags = kind == BATCH_RECEIVE_SIGNAL_RESTART ? SA_RESTART : 0;
    REQUIRE(sigaction(SIGUSR1, &action, NULL) == 0, "batch receive signal disposition");
    alarm(15);
    int pair[2];
    descriptor_socket_pair(udp ? DESCRIPTOR_UDP :
                           type == SOCK_DGRAM ? DESCRIPTOR_DATAGRAM : DESCRIPTOR_SEQPACKET, pair);
    struct sockaddr_in peer = {0};
    if (udp) {
        socklen_t length = sizeof(peer);
        REQUIRE(getsockname(pair[1], (struct sockaddr *)&peer, &length) == 0 &&
                    length == sizeof(peer), "identify UDP batch sender");
    }
    if (kind == BATCH_RECEIVE_NONBLOCK)
        REQUIRE(fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_NONBLOCK) == 0,
                "caller-owned nonblocking batch receive socket");
    if (timed || kind == BATCH_RECEIVE_TIMEOUT) {
        struct timeval timeout = {kind == BATCH_RECEIVE_TIMEOUT ? 0 : 4, 150001};
        REQUIRE(setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
                "caller-owned batch receive timeout");
    }
    int original_flags = fcntl(pair[0], F_GETFL);
    REQUIRE(original_flags >= 0, "capture batch receive socket flags");
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (memory < 0) skip("batch-receive-wait-snapshot-unavailable");
    int keeper = -1, replacement[2] = {-1, -1}, rights_pipe[2] = {-1, -1};
    if (kind == BATCH_RECEIVE_REUSE) {
        keeper = fcntl(pair[0], F_DUPFD_CLOEXEC, 3);
        REQUIRE(keeper >= 0 && socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, replacement) == 0,
                "prepare batch receive descriptor replacement");
    }
    if (kind == BATCH_RECEIVE_RIGHTS)
        REQUIRE(pipe2(rights_pipe, O_CLOEXEC) == 0, "create batch ancillary descriptor");
    struct batch_receive_probe probe;
    memset(&probe, 0, sizeof(probe));
    probe.kind = kind;
    probe.fd = pair[0];
    probe.fault_after_prefix = fault_after_prefix;
    probe.explicit_timeout = explicit_timeout;
    probe.copy_denied = copy_denied;
    probe.flags = kind == BATCH_RECEIVE_SINGLE || kind == BATCH_RECEIVE_SINGLE_BLOCKED ||
                  kind == BATCH_RECEIVE_FULL ? 0 : MSG_WAITFORONE;
    if (kind == BATCH_RECEIVE_DONTWAIT) probe.flags |= MSG_DONTWAIT;
    if (kind == BATCH_RECEIVE_TRUNC_EMPTY) probe.flags |= MSG_TRUNC;
    if (kind == BATCH_RECEIVE_RIGHTS) probe.flags |= MSG_CMSG_CLOEXEC;
    probe.count = kind == BATCH_RECEIVE_COUNT_ZERO ? 0 :
                  kind == BATCH_RECEIVE_SINGLE || kind == BATCH_RECEIVE_SINGLE_BLOCKED ||
                  kind == BATCH_RECEIVE_RIGHTS ? 1 :
                  kind == BATCH_RECEIVE_OUTPUT_FAULT ? 1U + (unsigned)fault_after_prefix : 3;
    probe.active = probe.messages;
    if (explicit_timeout || kind == BATCH_RECEIVE_FINITE) {
        probe.timeout = (struct timespec){1, explicit_timeout ? 500000000 : 0};
        if (zero_timeout) probe.timeout = (struct timespec){0, 0};
        if (expired_timeout) probe.timeout = (struct timespec){0, 150001000};
        probe.timeout_argument = &probe.timeout;
        if (unaligned_timeout) {
            memcpy(probe.timeout_bytes + 1, &probe.timeout, sizeof(probe.timeout));
            probe.timeout_argument = (struct timespec *)(probe.timeout_bytes + 1);
        }
    }
    struct timespec original_timeout = probe.timeout;
    memset(probe.bytes, 0xa5, sizeof(probe.bytes));
    memset(probe.addresses, 0xa5, sizeof(probe.addresses));
    memset(&probe.control, 0xa5, sizeof(probe.control));
    for (unsigned i = 0; i < 3; ++i) {
        probe.vectors[i] = (struct iovec){probe.bytes[i], 1};
        probe.messages[i].msg_hdr = (struct msghdr){
            .msg_name = &probe.addresses[i],
            .msg_namelen = sizeof(probe.addresses[i]),
            .msg_iov = &probe.vectors[i],
            .msg_iovlen = 1,
            .msg_flags = 0x13579,
        };
        probe.messages[i].msg_len = UINT32_C(0xa5a5a5a5);
    }
    if (kind == BATCH_RECEIVE_RIGHTS) {
        probe.messages[0].msg_hdr.msg_control = probe.control.bytes;
        probe.messages[0].msg_hdr.msg_controllen = sizeof(probe.control.bytes);
    }
    if (aliased_timeout)
        probe.vectors[0].iov_base = probe.timeout_argument;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *read_only = MAP_FAILED, *timeout_mapping = MAP_FAILED;
    if (readonly_timeout) {
        timeout_mapping = mmap(NULL, page, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(timeout_mapping != MAP_FAILED, "read-only batch timeout mapping");
        memcpy(timeout_mapping, &probe.timeout, sizeof(probe.timeout));
        REQUIRE(mprotect(timeout_mapping, page, PROT_READ) == 0,
                "timeout is readable on entry but unwritable after message consumption");
        probe.timeout_argument = timeout_mapping;
    }
    if (kind == BATCH_RECEIVE_OUTPUT_FAULT) {
        read_only = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(read_only != MAP_FAILED, "batch receive output guard mapping");
        /* The complete msghdr remains writable. Only msg_len and subsequent
         * storage cross into the read-only page, after data is consumed. */
        probe.active = (struct mmsghdr *)((unsigned char *)read_only + page -
                         offsetof(struct mmsghdr, msg_len) -
                         (fault_after_prefix ? sizeof(struct mmsghdr) : 0));
        memcpy(probe.active, probe.messages, probe.count * sizeof(*probe.active));
        REQUIRE(mprotect((unsigned char *)read_only + page, page, PROT_READ) == 0,
                "writable receive header with unwritable message length");
    }
    struct iovec original_vectors[3];
    struct msghdr original_headers[3];
    memcpy(original_vectors, probe.vectors, sizeof(original_vectors));
    for (unsigned i = 0; i < 3; ++i)
        memcpy(&original_headers[i], &probe.messages[i].msg_hdr, sizeof(original_headers[i]));
    unsigned queued = kind == BATCH_RECEIVE_READY || kind == BATCH_RECEIVE_PENDING ||
                      kind == BATCH_RECEIVE_FINITE || kind == BATCH_RECEIVE_TRUNC_EMPTY ||
                      kind == BATCH_RECEIVE_OUTPUT_FAULT ? 3 :
                      kind == BATCH_RECEIVE_PREFIX || kind == BATCH_RECEIVE_COUNT_ZERO ? 1 : 0;
    int truncated = kind == BATCH_RECEIVE_TRUNC_EMPTY;
    /* One loopback record also proves WAITFORONE does not wait for the rest of
     * its vector, without assuming all UDP packets arrive in one scheduling turn. */
    if (udp) queued = 1;
    for (unsigned i = 0; i < queued; ++i) feed_batch_receive(pair[1], i, truncated);
    if (kind == BATCH_RECEIVE_RIGHTS) {
        unsigned char byte = 'A';
        struct iovec vector = {&byte, 1};
        union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
        struct msghdr message = {
            .msg_iov = &vector, .msg_iovlen = 1,
            .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes),
        };
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &rights_pipe[0], sizeof(rights_pipe[0]));
        REQUIRE(syscall(SYS_sendmsg, pair[1], &message, MSG_NOSIGNAL) == 1,
                "queue ancillary rights before the batch receive");
        queued = 1;
    }
    probe.observed.result = -222;
    atomic_init(&probe.observed.ready, 0);
    atomic_init(&probe.observed.release, 0);
    atomic_init(&probe.observed.returned, 0);
    atomic_init(&probe.observed.cleaned, 0);
    size_t original_descriptors = descriptor_count();
    REQUIRE(pthread_create(&probe.observed.thread, NULL, batch_receive_worker, &probe) == 0,
            "create batch receive worker");
    wait_ready(&probe.observed);
    if (kind == BATCH_RECEIVE_PENDING)
        REQUIRE(pthread_cancel(probe.observed.thread) == 0, "pending batch receive cancellation");
    atomic_store_explicit(&probe.observed.release, 1, memory_order_release);

    int blocked = kind == BATCH_RECEIVE_BLOCKED || kind == BATCH_RECEIVE_DISABLED ||
                  kind == BATCH_RECEIVE_READY_LATE || kind == BATCH_RECEIVE_SINGLE ||
                  kind == BATCH_RECEIVE_SINGLE_BLOCKED || kind == BATCH_RECEIVE_FULL ||
                  kind == BATCH_RECEIVE_REUSE || kind == BATCH_RECEIVE_SIGNAL ||
                  kind == BATCH_RECEIVE_SIGNAL_RESTART;
    if (blocked) {
        observe_reuse_parked(&probe.observed, memory, pair[0], SYS_recvmmsg, 0);
        if (explicit_timeout) {
            if (expired_timeout || kind == BATCH_RECEIVE_READY_LATE || kind == BATCH_RECEIVE_SINGLE) {
                int64_t deadline = monotonic_ns() + (expired_timeout ? 230000000 : 120000000);
                while (monotonic_ns() < deadline) {
                    REQUIRE(!atomic_load_explicit(&probe.observed.returned, memory_order_acquire),
                            "an explicit recvmmsg timeout cannot end an empty first receive");
                    pause_briefly();
                }
                observe_reuse_parked(&probe.observed, memory, pair[0], SYS_recvmmsg, 0);
            }
            struct timespec unchanged;
            REQUIRE(snapshot(memory, (unsigned long long)(uintptr_t)probe.timeout_argument,
                             &unchanged, sizeof(unchanged)) &&
                        unchanged.tv_sec == original_timeout.tv_sec &&
                        unchanged.tv_nsec == original_timeout.tv_nsec,
                    "empty receive retries never publish an intermediate timeout");
        }
        if (kind == BATCH_RECEIVE_BLOCKED || kind == BATCH_RECEIVE_SINGLE_BLOCKED ||
            kind == BATCH_RECEIVE_DISABLED)
            REQUIRE(pthread_cancel(probe.observed.thread) == 0,
                    "cancel an independently observed blocked batch receive");
        if (kind == BATCH_RECEIVE_SIGNAL || kind == BATCH_RECEIVE_SIGNAL_RESTART) {
            REQUIRE(pthread_kill(probe.observed.thread, SIGUSR1) == 0,
                    "interrupt the original batch receive");
            int64_t deadline = monotonic_ns() + 2000000000;
            while (!atomic_load_explicit(&signals_delivered, memory_order_acquire)) {
                REQUIRE(monotonic_ns() < deadline, "batch receive signal delivery deadline");
                pause_briefly();
            }
            if (kind == BATCH_RECEIVE_SIGNAL_RESTART)
                observe_reuse_parked(&probe.observed, memory, pair[0], SYS_recvmmsg, 0);
        }
        if (kind == BATCH_RECEIVE_FULL) {
            feed_batch_receive(pair[1], 0, 0);
            int64_t deadline = monotonic_ns() + 2000000000;
            unsigned first_length = UINT32_C(0xa5a5a5a5);
            while (first_length != 1) {
                REQUIRE(!atomic_load_explicit(&probe.observed.returned, memory_order_acquire),
                        "ordinary recvmmsg does not return a short available prefix");
                REQUIRE(monotonic_ns() < deadline, "first ordinary batch record publication");
                REQUIRE(snapshot(memory, (unsigned long long)(uintptr_t)&probe.active[0].msg_len,
                                 &first_length, sizeof(first_length)),
                        "observe kernel publication without racing C memory accesses");
                if (first_length != 1) pause_briefly();
            }
            observe_reuse_parked(&probe.observed, memory, pair[0], SYS_recvmmsg, 0);
            feed_batch_receive(pair[1], 1, 0);
            feed_batch_receive(pair[1], 2, 0);
            queued = 3;
        } else if (kind == BATCH_RECEIVE_DISABLED || kind == BATCH_RECEIVE_READY_LATE ||
                   kind == BATCH_RECEIVE_SINGLE || kind == BATCH_RECEIVE_REUSE ||
                   kind == BATCH_RECEIVE_SIGNAL_RESTART) {
            if (kind == BATCH_RECEIVE_REUSE) {
                REQUIRE(syscall(SYS_sendto, replacement[1], "X", 1, MSG_NOSIGNAL, NULL, 0) == 1,
                        "make replacement receive socket independently ready");
                REQUIRE(dup2(replacement[0], pair[0]) == pair[0],
                        "replace the public batch receive descriptor");
            }
            if (kind == BATCH_RECEIVE_DISABLED)
                observe_reuse_parked(&probe.observed, memory, pair[0], SYS_recvmmsg, 0);
            feed_batch_receive(pair[1], 0, 0);
            queued = 1;
        }
    }
    void *result = join_bounded(&probe.observed);
    int canceled = kind == BATCH_RECEIVE_PENDING || kind == BATCH_RECEIVE_BLOCKED ||
                   kind == BATCH_RECEIVE_SINGLE_BLOCKED || kind == BATCH_RECEIVE_DISABLED;
    REQUIRE(result == (canceled ? PTHREAD_CANCELED : &probe.observed), "batch receive join result");
    REQUIRE(probe.observed.cleaned == 1, "batch receive cleanup count");
    unsigned published = 0, consumed = 0;
    if (kind == BATCH_RECEIVE_PENDING || kind == BATCH_RECEIVE_BLOCKED ||
        kind == BATCH_RECEIVE_SINGLE_BLOCKED) {
        REQUIRE(!probe.observed.returned, "batch cancellation precedes result publication");
    } else if (kind == BATCH_RECEIVE_NONBLOCK || kind == BATCH_RECEIVE_DONTWAIT ||
               kind == BATCH_RECEIVE_TIMEOUT) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EAGAIN,
                "batch receive preserves nonblocking and socket-timeout errors");
        if (kind == BATCH_RECEIVE_TIMEOUT)
            REQUIRE(probe.observed.elapsed_ns >= 100000000 && probe.observed.elapsed_ns < 2000000000,
                    "batch receive keeps the kernel socket deadline");
    } else if (kind == BATCH_RECEIVE_SIGNAL) {
        REQUIRE(probe.observed.result == -1 && probe.observed.error == EINTR,
                "batch receive retains non-restarting EINTR");
    } else if (kind == BATCH_RECEIVE_OUTPUT_FAULT) {
        published = fault_after_prefix ? 1U : 0U;
        consumed = published + 1;
        REQUIRE(probe.observed.result == (fault_after_prefix && !readonly_timeout ? 1 : -1),
                "batch receive preserves the prefix preceding msg_len EFAULT");
        if (readonly_timeout && fault_after_prefix)
            REQUIRE(probe.observed.error == EFAULT,
                    "a timeout publication fault overrides a completed prefix without replay");
        if (fault_after_prefix)
            REQUIRE(probe.deferred_result == -1 && probe.deferred_error == EFAULT,
                    "recvmmsg defers its later output fault to the next receive");
        else
            REQUIRE(probe.observed.error == EFAULT, "first output fault returns EFAULT");
    } else if (kind != BATCH_RECEIVE_ERRORS) {
        published = consumed = queued;
        if (kind == BATCH_RECEIVE_COUNT_ZERO) published = consumed = 0;
        if (zero_timeout && published > 1) published = consumed = 1;
        REQUIRE(probe.observed.result == (readonly_timeout && published != 0 ? -1 : (int)published),
                "batch receive returns its completed count or the final timeout publication fault");
        if (readonly_timeout && published != 0)
            REQUIRE(probe.observed.error == EFAULT,
                    "an unwritable timeout reports EFAULT after messages and lengths are committed");
    }
    if (explicit_timeout) {
        struct timespec remaining;
        memcpy(&remaining, probe.timeout_argument, sizeof(remaining));
        if (readonly_timeout || published == 0) {
            REQUIRE(remaining.tv_sec == original_timeout.tv_sec &&
                        remaining.tv_nsec == original_timeout.tv_nsec,
                    "zero-result, error and canceled batches leave the explicit timeout unchanged");
        } else if (zero_timeout || expired_timeout) {
            REQUIRE(remaining.tv_sec == 0 && remaining.tv_nsec == 0,
                    "the first record after explicit expiry publishes a zero remainder");
        } else {
            int64_t before = original_timeout.tv_sec * 1000000000 + original_timeout.tv_nsec;
            int64_t after = remaining.tv_sec * 1000000000 + remaining.tv_nsec;
            REQUIRE(remaining.tv_sec >= 0 && remaining.tv_nsec >= 0 &&
                        remaining.tv_nsec < 1000000000 && after > 0 && after <= before,
                    "a completed batch publishes a normalized explicit timeout remainder");
            if (kind == BATCH_RECEIVE_READY_LATE || kind == BATCH_RECEIVE_SINGLE)
                REQUIRE(after <= before - 80000000,
                        "the explicit remainder includes time spent waiting before the first record");
        }
    }
    if (kind == BATCH_RECEIVE_FINITE)
        REQUIRE(probe.timeout.tv_sec == 0 && probe.timeout.tv_nsec >= 0 &&
                    probe.timeout.tv_nsec < 1000000000,
                "nonnull batch timeout keeps kernel remaining-time publication");
    for (unsigned i = 0; i < 3; ++i) {
        const struct mmsghdr *actual = i < probe.count ? &probe.active[i] : &probe.messages[i];
        const struct msghdr *header = &actual->msg_hdr;
        const struct msghdr *original = &original_headers[i];
        REQUIRE(actual->msg_len == (i < published ?
                    (unsigned)batch_receive_length(i, truncated) : UINT32_C(0xa5a5a5a5)),
                "only completed batch receive entries publish message lengths");
        REQUIRE(header->msg_name == original->msg_name && header->msg_iov == original->msg_iov &&
                    header->msg_iovlen == original->msg_iovlen &&
                    header->msg_control == original->msg_control,
                "batch receive preserves caller pointer and iovec inputs");
        if (i < consumed) {
            int expected_flags = truncated && i == 0 ? MSG_TRUNC : 0;
            expected_flags |= probe.flags & MSG_CMSG_CLOEXEC;
            REQUIRE((header->msg_flags & ~MSG_EOR) == expected_flags,
                    "batch receive publishes per-record output flags");
            if (udp) {
                const struct sockaddr_in *address = (const struct sockaddr_in *)&probe.addresses[i];
                REQUIRE(header->msg_namelen == sizeof(*address) && address->sin_family == AF_INET &&
                            address->sin_addr.s_addr == peer.sin_addr.s_addr &&
                            address->sin_port == peer.sin_port,
                        "each UDP batch entry publishes its actual sender address");
            } else {
                REQUIRE(header->msg_namelen == 0, "unnamed local batch source address");
            }
            if (kind != BATCH_RECEIVE_RIGHTS)
                REQUIRE(header->msg_controllen == 0, "ordinary batch receives publish no control");
        } else {
            REQUIRE(memcmp(header, original, sizeof(*header)) == 0,
                    "unreceived batch headers retain every sentinel field");
            for (size_t j = 0; j < sizeof(probe.addresses[i]); ++j)
                REQUIRE(((unsigned char *)&probe.addresses[i])[j] == 0xa5,
                        "unreceived batch source storage is unchanged");
        }
        size_t copied = i < consumed && batch_receive_length(i, truncated) != 0 &&
                        !(aliased_timeout && i == 0) ? 1 : 0;
        for (size_t j = 0; j < sizeof(probe.bytes[i]); ++j)
            REQUIRE(probe.bytes[i][j] == (j < copied ? (unsigned char)('A' + i) : 0xa5),
                    "batch receive consumes each record once and preserves trailing buffers");
    }
    REQUIRE(memcmp(probe.vectors, original_vectors, sizeof(original_vectors)) == 0,
            "batch receive never rewrites caller iovec geometry");
    if (kind == BATCH_RECEIVE_RIGHTS) {
        const struct msghdr *message = &probe.active[0].msg_hdr;
        struct cmsghdr *header = CMSG_FIRSTHDR(message);
        REQUIRE(header != NULL && header->cmsg_level == SOL_SOCKET &&
                    header->cmsg_type == SCM_RIGHTS && header->cmsg_len == CMSG_LEN(sizeof(int)) &&
                    message->msg_controllen <= sizeof(probe.control.bytes),
                "batch receives one complete SCM_RIGHTS message");
        int received = -1;
        memcpy(&received, CMSG_DATA(header), sizeof(received));
        REQUIRE(received == probe.expected_right && same_io_object((unsigned)received, rights_pipe[0]) &&
                    (fcntl(received, F_GETFD) & FD_CLOEXEC) != 0,
                "batch socket pin preserves the available rights slot and CLOEXEC");
        REQUIRE(close(received) == 0, "release received batch descriptor");
    }
    int original_fd = keeper >= 0 ? keeper : pair[0];
    for (unsigned i = consumed; i < queued; ++i) {
        unsigned char bytes[8];
        ssize_t length = syscall(SYS_recvfrom, original_fd, bytes, sizeof(bytes),
                                 MSG_DONTWAIT, NULL, NULL);
        size_t expected = batch_receive_length(i, truncated);
        REQUIRE(length == (ssize_t)expected &&
                    (expected == 0 || bytes[0] == (unsigned char)('A' + i)),
                "each unconsumed record remains available in order");
    }
    unsigned char extra;
    REQUIRE(syscall(SYS_recvfrom, original_fd, &extra, 1, MSG_DONTWAIT, NULL, NULL) == -1 &&
                errno == EAGAIN, "batch receive neither duplicates nor hides queued records");
    if (kind == BATCH_RECEIVE_REUSE) {
        REQUIRE(syscall(SYS_recvfrom, replacement[0], &extra, 1, MSG_DONTWAIT, NULL, NULL) == 1 &&
                    extra == 'X', "batch receive cannot migrate to the replacement description");
    }
    REQUIRE(descriptor_count() == original_descriptors, "batch receive releases private descriptors");
    REQUIRE(fcntl(original_fd, F_GETFL) == original_flags,
            "batch receive leaves shared socket status flags unchanged");
    REQUIRE(close(memory) == 0 && close(pair[0]) == 0 && close(pair[1]) == 0,
            "release batch receive fixture descriptors");
    if (keeper >= 0)
        REQUIRE(close(keeper) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0,
                "release batch receive replacement descriptors");
    if (rights_pipe[0] >= 0)
        REQUIRE(close(rights_pipe[0]) == 0 && close(rights_pipe[1]) == 0,
                "release original ancillary descriptors");
    if (read_only != MAP_FAILED)
        REQUIRE(munmap(read_only, 2 * page) == 0, "release batch receive output mapping");
    if (timeout_mapping != MAP_FAILED)
        REQUIRE(munmap(timeout_mapping, page) == 0, "release read-only batch timeout");
    return 0;
}

static int batch_receive_contract_main(char **argv) {
    int result = batch_receive_contract_once(argv, 0, 0);
    if (result != 0) return result;
    if (strstr(case_name, "-output-fault") != NULL) {
        result = batch_receive_contract_once(argv, 1, 0);
        if (result != 0) return result;
    }
    if (strcmp(case_name, "recvmmsg-datagram-ready") == 0) {
        result = batch_receive_contract_once(argv, 0, 1);
        if (result != 0) return result;
    }
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    case_name = argv[1];
    if (strncmp(case_name, "sendmmsg-", 9) == 0) return batch_send_contract_main(argv);
    if (strncmp(case_name, "recvmmsg-", 9) == 0) return batch_receive_contract_main(argv);
    if (strncmp(case_name, "fd-reuse-", 9) == 0) return io_reuse_contract_main(argv);
    if (strncmp(case_name, "write-", 6) == 0 || strncmp(case_name, "writev-", 7) == 0 ||
        strncmp(case_name, "send-", 5) == 0 || strncmp(case_name, "sendto-", 7) == 0 ||
        strncmp(case_name, "sendmsg-", 8) == 0)
        return send_contract_main(argv);
    if (strncmp(case_name, "read-", 5) == 0 || strncmp(case_name, "readv-", 6) == 0 ||
        strncmp(case_name, "recv-", 5) == 0 || strncmp(case_name, "recvfrom-", 9) == 0 ||
        strncmp(case_name, "recvmsg-", 8) == 0)
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
