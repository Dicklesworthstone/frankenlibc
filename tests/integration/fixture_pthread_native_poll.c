/* Real blocked poll/ppoll cancellation and signal behavior, with a GNU oracle.
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

static int pin_providers(const char *expected, int alias) {
    const char *names[] = {
        "pthread_create", "pthread_join", "pthread_tryjoin_np", "pthread_cancel",
        "pthread_self", "pthread_setcancelstate", "pthread_setcanceltype",
        "pthread_testcancel", "pthread_kill", "pthread_sigmask", "sigaction",
        "poll", "ppoll", "__errno_location", "__pthread_register_cancel",
        "__pthread_unregister_cancel", "__pthread_unwind_next", alias ? "__ppoll" : "ppoll"
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
    selected_ppoll = (ppoll_function)dlsym(RTLD_DEFAULT, alias ? "__ppoll" : "ppoll");
    return 0;
}

enum kind {
    BLOCKED, PENDING, DISABLED, SIGNAL, SIGNAL_RESTART, READY, REUSE,
    MASK_UNBLOCK, MASK_BLOCK, READONLY_TIMEOUT, EMPTY_BLOCKED, MASK_CANCEL, MASK_CANCEL_BLOCK
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
};

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
    if (state->use_ppoll) {
        const sigset_t *temporary = state->kind == MASK_UNBLOCK || state->kind == MASK_BLOCK ||
                                    state->kind == MASK_CANCEL || state->kind == MASK_CANCEL_BLOCK
                                      ? &state->temporary_mask : NULL;
        state->result = selected_ppoll(fds, state->count, state->timeout, temporary);
    } else {
        state->result = poll(fds, state->count, -1);
    }
    state->error = errno;
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
    fail("no sleeping syscall with the exact application pollfd entries");
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
                       const int pipefd[2], const struct timespec *timeout) {
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
    int seeded = kind == PENDING || kind == READY;
    if (seeded) seed_pipe(state);
    REQUIRE(pthread_create(&state->thread, NULL, worker, state) == 0, "create worker");
    wait_ready(state);
    if (kind == PENDING)
        REQUIRE(pthread_cancel(state->thread) == 0, "queue pending cancellation");
    if (kind == MASK_UNBLOCK)
        REQUIRE(pthread_kill(state->thread, SIGUSR1) == 0, "queue masked user signal");
    atomic_store_explicit(&state->release, 1, memory_order_release);
    if (kind != PENDING && kind != READY && kind != MASK_UNBLOCK)
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
    if (kind == PENDING)
        REQUIRE(state->fds[0].revents == 0x4000, "pending cancellation precedes output publication");
    if (kind == SIGNAL || kind == SIGNAL_RESTART || kind == MASK_UNBLOCK) {
        REQUIRE(state->result == -1 && state->error == EINTR, "user signal returns EINTR without restart");
        REQUIRE(atomic_load_explicit(&signals_delivered, memory_order_relaxed) == 1, "one user signal delivered");
    } else if (kind == READY) {
        REQUIRE(state->result == 2, "duplicate pollfd entries retain multiplicity");
        REQUIRE(state->fds[0].revents == POLLIN && state->fds[2].revents == POLLIN &&
                state->fds[1].revents == 0 && state->fds[3].revents == 0,
                "ready and ignored pollfd outputs");
    } else if (kind == DISABLED || kind == MASK_BLOCK) {
        REQUIRE(state->result == 1 && state->fds[0].revents == POLLIN, "controlled readiness result");
    } else if (kind == READONLY_TIMEOUT) {
        REQUIRE(state->result == 0 && state->fds[0].revents == 0, "read-only timeout expires normally");
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
                       const struct timespec *timeout, int memory) {
    struct state state;
    initialize(&state, READY, use_ppoll, pipefd, timeout);
    run_case(&state, memory); /* Resolve runtime state before measuring lifetime. */
    size_t before = descriptor_count();
    for (int round = 0; round < 8; ++round) {
        initialize(&state, BLOCKED, use_ppoll, pipefd, timeout);
        run_case(&state, memory);
        REQUIRE(descriptor_count() == before, "retired poll thread leaked a descriptor");
        initialize(&state, READY, use_ppoll, pipefd, timeout);
        run_case(&state, memory);
        REQUIRE(descriptor_count() == before, "replacement thread leaked or inherited cancellation");
    }
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    case_name = argv[1];
    int use_ppoll = strncmp(case_name, "ppoll-", 6) == 0;
    int alias = strncmp(case_name, "ppoll-alias-", 12) == 0;
    if (!use_ppoll && strncmp(case_name, "poll-", 5) != 0) return 2;
    const char *suffix = case_name + (alias ? 12 : use_ppoll ? 6 : 5);
    const char *names[] = {"blocked", "pending", "disabled", "signal", "signal-restart", "ready",
                          "reuse", "mask-unblock", "mask-block", "readonly-timeout", "empty-blocked",
                          "mask-cancel", "mask-cancel-block"};
    int index = -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (strcmp(suffix, names[i]) == 0) index = (int)i;
    if (index < 0 || (!use_ppoll && ((index >= MASK_UNBLOCK && index <= READONLY_TIMEOUT) ||
                                    index == MASK_CANCEL || index == MASK_CANCEL_BLOCK))) return 2;
    enum kind kind = (enum kind)index;
    int pin = pin_providers(argv[2], alias);
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
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (memory < 0) skip("kernel-poll-array-snapshot-unavailable");
    long page = sysconf(_SC_PAGESIZE);
    REQUIRE(page > 0, "page size");
    struct timespec *timeout = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(timeout != MAP_FAILED, "map timeout storage");
    *timeout = kind == READONLY_TIMEOUT ? (struct timespec){0, 500000000} : (struct timespec){60, 0};
    struct timespec expected = *timeout;
    REQUIRE(mprotect(timeout, (size_t)page, PROT_READ) == 0, "protect timeout storage");
    if (kind == REUSE) {
        reuse_case(use_ppoll, pipefd, timeout, memory);
    } else {
        struct state state;
        initialize(&state, kind, use_ppoll, pipefd, timeout);
        run_case(&state, memory);
    }
    REQUIRE(timeout->tv_sec == expected.tv_sec && timeout->tv_nsec == expected.tv_nsec,
            "ppoll must not change the caller timeout");
    REQUIRE(munmap(timeout, (size_t)page) == 0, "release timeout storage");
    REQUIRE(close(memory) == 0 && close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "release fixture descriptors");
    printf("pthread-native-poll:%s:PASS\n", case_name);
    return 0;
}
