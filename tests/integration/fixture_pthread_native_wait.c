/* Already-parked native wait cancellation, with a live GNU oracle.
 * Cancellation cases observe a real sleeping syscall before requesting it.
 * Missing procfs/seccomp evidence is exit 77 with an explicit SKIP transcript.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_futex_waitv
#define SYS_futex_waitv 449
#endif

static const char *case_name;
static uintptr_t creator_tp;
static pid_t creator_tid;
static pthread_t creator_thread;
static int expect_native;
typedef int (*join_function)(pthread_t, void **);
static join_function alias_join;

static void fail(const char *message) {
    fprintf(stderr, "pthread-native-wait:%s:FAIL:%s\n", case_name, message);
    _Exit(1);
}
#define REQUIRE(condition, message) do { if (!(condition)) fail(message); } while (0)

static void skip(const char *message) {
    printf("pthread-native-wait:%s:SKIP\n", case_name);
    fprintf(stderr, "pthread-native-wait:%s:SKIP:%s\n", case_name, message);
    fflush(stdout);
    _Exit(77);
}

static uintptr_t thread_pointer(void) {
    return (uintptr_t)__builtin_thread_pointer();
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

static int pin_providers(const char *expected) {
    const char *names[] = {
        "pthread_create", "pthread_join", "pthread_timedjoin_np", "pthread_clockjoin_np",
        "pthread_tryjoin_np", "pthread_cancel", "pthread_self",
        "pthread_setcancelstate", "pthread_setcanceltype", "pthread_testcancel",
        "pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_trylock",
        "pthread_cond_wait", "pthread_cond_timedwait", "pthread_cond_clockwait",
        "pthread_cond_signal", "sem_wait", "sem_timedwait", "sem_clockwait",
        "sem_post", "sem_trywait", "sem_getvalue", "__errno_location",
        "wait", "waitpid", "wait3", "wait4", "waitid", "sigaction", "pthread_kill",
        "sigwait", "sigpending", "pthread_sigmask",
        "__pthread_register_cancel", "__pthread_unregister_cancel", "__pthread_unwind_next",
        strstr(case_name, "join-alias") ? "__pthread_join" : "pthread_join",
        strstr(case_name, "sigwait-alias") ? "__sigwait" : "sigwait"
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
            fprintf(stderr, "pthread-native-wait:provider-mismatch:%s\n", names[i]);
            return 86;
        }
    }
    return 0;
}

enum operation {
    SEM_WAIT, SEM_TIMED, SEM_REAL, SEM_MONO,
    COND_WAIT, COND_TIMED, COND_REAL, COND_MONO,
    JOIN_WAIT, JOIN_ALIAS, JOIN_TIMED, JOIN_REAL, JOIN_MONO, JOIN_TIMED_NULL, JOIN_CLOCK_NULL
};

struct state {
    enum operation operation;
    int disabled;
    int peers;
    int go;
    struct state *shared;
    sem_t semaphore;
    pthread_cond_t condition;
    pthread_mutex_t mutex;
    pthread_t thread;
    _Atomic int ready, returned, cleaned;
    pid_t tid;
    char proc_path[128];
    pthread_t target;
    _Atomic int target_ready, target_release, target_exited;
    uintptr_t target_tid_word;
    int target_value;
    void *join_value;
};

static int is_condition(const struct state *state) {
    return state->operation >= COND_WAIT && state->operation < JOIN_WAIT;
}

static int is_join(const struct state *state) {
    return state->operation >= JOIN_WAIT;
}

static struct state *condition_owner(struct state *state) {
    return state->shared != NULL ? state->shared : state;
}

static pid_t check_worker_identity(void) {
    pid_t tid = (pid_t)syscall(SYS_gettid);
    REQUIRE(tid > 0 && tid != creator_tid, "distinct kernel thread");
    REQUIRE(!pthread_equal(pthread_self(), creator_thread), "distinct pthread identity");
    /* Current clone backend passes TLS=0 without CLONE_SETTLS, including the
     * owned-tls-cache feature. A host fallback would allocate a distinct TP.
     * This witness must change when native threads acquire their own TCBs. */
    REQUIRE((thread_pointer() == creator_tp) == expect_native,
            "thread backend does not match inherited/native or hosted TP");
    return tid;
}

static void capture_worker_identity(struct state *state) {
    state->tid = check_worker_identity();
    char target[104];
    ssize_t length = readlink("/proc/thread-self", target, sizeof(target) - 1);
    if (length < 0) skip("proc-thread-self-unavailable");
    REQUIRE((size_t)length < sizeof(target) - 1, "proc thread path truncated");
    target[length] = 0;
    /* procfs can expose an outer PID namespace: raw gettid is not its task ID. */
    int count = snprintf(state->proc_path, sizeof(state->proc_path), "/proc/%s", target);
    REQUIRE(count > 0 && (size_t)count < sizeof(state->proc_path), "proc path capacity");
}

static void *gated_target(void *argument) {
    struct state *state = argument;
    (void)check_worker_identity();
    void *word = NULL;
    if (prctl(PR_GET_TID_ADDRESS, &word, 0, 0, 0) != 0)
        skip("kernel-clear-tid-address-unavailable");
    REQUIRE(word != NULL, "target has a kernel clear-child-tid word");
    state->target_tid_word = (uintptr_t)word;
    atomic_store_explicit(&state->target_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&state->target_release, memory_order_acquire))
        pause_briefly();
    atomic_store_explicit(&state->target_exited, 1, memory_order_release);
    return &state->target_value;
}

static void cleanup(void *argument) {
    struct state *state = argument;
    if (is_condition(state))
        REQUIRE(pthread_mutex_unlock(&condition_owner(state)->mutex) == 0,
                "condition cancellation must reacquire the ERRORCHECK mutex");
    REQUIRE(atomic_fetch_add_explicit(&state->cleaned, 1, memory_order_release) == 0,
            "cleanup ran more than once");
}

static void *worker(void *argument) {
    struct state *state = argument;
    capture_worker_identity(state);
    REQUIRE(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0, "deferred type");
    if (state->disabled)
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0, "disable cancellation");
    if (is_condition(state))
        REQUIRE(pthread_mutex_lock(&condition_owner(state)->mutex) == 0, "worker mutex lock");
    pthread_cleanup_push(cleanup, state);
    struct state *shared = condition_owner(state);
    struct timespec until;
    clockid_t clock = state->operation == SEM_MONO || state->operation == COND_MONO ||
                     state->operation == JOIN_MONO || state->operation == JOIN_CLOCK_NULL
                          ? CLOCK_MONOTONIC : CLOCK_REALTIME;
    REQUIRE(clock_gettime(clock, &until) == 0, "wait deadline clock");
    until.tv_sec += 60;
    atomic_store_explicit(&state->ready, 1, memory_order_release);
    int result = 0;
    if (is_condition(state)) {
        while (!shared->go) {
            if (state->operation == COND_WAIT)
                result = pthread_cond_wait(&shared->condition, &shared->mutex);
            else if (state->operation == COND_TIMED)
                result = pthread_cond_timedwait(&shared->condition, &shared->mutex, &until);
            else
                result = pthread_cond_clockwait(&shared->condition, &shared->mutex, clock, &until);
            REQUIRE(result == 0, "condition returned an unexpected error before cancellation");
        }
        --shared->go;
    } else if (is_join(state)) {
        if (state->operation == JOIN_WAIT)
            result = pthread_join(state->target, &state->join_value);
        else if (state->operation == JOIN_ALIAS)
            result = alias_join(state->target, &state->join_value);
        else if (state->operation == JOIN_TIMED || state->operation == JOIN_TIMED_NULL)
            result = pthread_timedjoin_np(state->target, &state->join_value,
                                         state->operation == JOIN_TIMED_NULL ? NULL : &until);
        else
            result = pthread_clockjoin_np(state->target, &state->join_value, clock,
                                         state->operation == JOIN_CLOCK_NULL ? NULL : &until);
        REQUIRE(result == 0, "join returned before the gated target exited");
    } else {
        if (state->operation == SEM_WAIT)
            result = sem_wait(&state->semaphore);
        else if (state->operation == SEM_TIMED)
            result = sem_timedwait(&state->semaphore, &until);
        else
            result = sem_clockwait(&state->semaphore, clock, &until);
        REQUIRE(result == 0, "semaphore returned an unexpected error before cancellation");
    }
    atomic_store_explicit(&state->returned, 1, memory_order_release);
    pthread_cleanup_pop(1);
    if (state->disabled) {
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0, "restore cancellation");
        pthread_testcancel();
        fail("disabled wait lost its pending cancellation");
    }
    return state;
}

static int read_proc(const struct state *state, const char *leaf, char *buffer, size_t capacity) {
    char path[160];
    int count = snprintf(path, sizeof(path), "%s/%s", state->proc_path, leaf);
    REQUIRE(count > 0 && (size_t)count < sizeof(path), "observation path capacity");
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) skip("proc-task-observation-denied");
        fail("worker task disappeared before a parked wait was observed");
    }
    ssize_t length = read(fd, buffer, capacity - 1);
    int error = errno;
    REQUIRE(close(fd) == 0, "close proc observation");
    if (length < 0 && (error == EACCES || error == EPERM)) skip("proc-task-observation-denied");
    REQUIRE(length > 0 && (size_t)length < capacity - 1, "complete proc observation");
    buffer[length] = 0;
    return 0;
}

static int operation_address(const struct state *state, uint64_t address) {
    if (is_join(state)) return address == state->target_tid_word;
    const struct state *shared = state->shared != NULL ? state->shared : state;
    uintptr_t first = is_condition(state) ? (uintptr_t)&shared->condition
                                          : (uintptr_t)&state->semaphore;
    size_t size = is_condition(state) ? sizeof(state->condition) : sizeof(state->semaphore);
    return address >= first && address - first <= size - sizeof(uint32_t);
}

static int waitv_targets_operation(const struct state *state, uint64_t address,
                                  unsigned long long count) {
    if (count != 2) return 0;
    /* Public Linux futex_waitv ABI. Snapshot through the kernel, never through
     * an unsynchronized C load of another thread's automatic objects. */
    struct entry { uint64_t value, address; uint32_t flags, reserved; } entries[2];
    _Static_assert(sizeof(struct entry) == 24, "Linux futex_waitv entry size");
    int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (fd < 0) skip("waitv-kernel-snapshot-unavailable");
    ssize_t length = pread(fd, entries, sizeof(entries), (off_t)address);
    int error = errno;
    REQUIRE(close(fd) == 0, "close waitv snapshot");
    if (length < 0 && (error == EACCES || error == EPERM))
        skip("waitv-kernel-snapshot-denied");
    if (length != (ssize_t)sizeof(entries)) return 0;
    if (is_join(state)) {
        for (unsigned i = 0; i < 2; ++i)
            if (operation_address(state, entries[i].address))
                REQUIRE(!(entries[i].flags & FUTEX_PRIVATE_FLAG), "join waitv uses shared clear-tid word");
    }
    return operation_address(state, entries[0].address) +
           operation_address(state, entries[1].address) == 1;
}

static void observe_parked(const struct state *state) {
    const int64_t limit = monotonic_ns() + 2000000000;
    while (!atomic_load_explicit(&state->ready, memory_order_acquire)) {
        REQUIRE(monotonic_ns() < limit, "worker failed to publish readiness");
        pause_briefly();
    }
    for (;;) {
        char call[512], status[512];
        long number = -1;
        unsigned long long address = 0, operation = 0;
        read_proc(state, "syscall", call, sizeof(call));
        int parsed = sscanf(call, "%ld %llx %llx", &number, &address, &operation);
        int waiting = parsed >= 3 && number == SYS_futex_waitv &&
                      waitv_targets_operation(state, address, operation);
        if (parsed >= 3 && number == SYS_futex) {
            unsigned command = (unsigned)operation & FUTEX_CMD_MASK;
            waiting = (command == FUTEX_WAIT || command == FUTEX_WAIT_BITSET) &&
                      operation_address(state, address);
            if (waiting && is_join(state))
                REQUIRE(!(operation & FUTEX_PRIVATE_FLAG), "join futex uses shared clear-tid word");
        }
        if (waiting) {
            read_proc(state, "stat", status, sizeof(status));
            char *end = strrchr(status, ')');
            REQUIRE(end != NULL && end[1] == ' ', "parse proc task state");
            if (end[2] == 'S') return;
        }
        REQUIRE(!atomic_load_explicit(&state->returned, memory_order_acquire),
                "operation returned without a token or condition signal");
        REQUIRE(monotonic_ns() < limit, "no sleeping futex/waitv observed");
        pause_briefly();
    }
}

static void *join_bounded(pthread_t thread, const char *failure) {
    const int64_t limit = monotonic_ns() + 3000000000;
    for (;;) {
        void *result = NULL;
        int error = pthread_tryjoin_np(thread, &result);
        if (error == 0) return result;
        REQUIRE(error == EBUSY, "tryjoin failed");
        REQUIRE(monotonic_ns() < limit, failure);
        pause_briefly();
    }
}

static void join_canceled(struct state *state) {
    REQUIRE(join_bounded(state->thread, "canceled waiter did not exit without a rescue wake") ==
            PTHREAD_CANCELED, "waiter did not exit by cancellation");
}

static void condition_peers(struct state *state) {
    struct state peer = {0};
    peer.operation = COND_WAIT;
    peer.shared = state;
    REQUIRE(pthread_create(&state->thread, NULL, worker, state) == 0, "create canceled condition peer");
    observe_parked(state);
    REQUIRE(pthread_create(&peer.thread, NULL, worker, &peer) == 0, "create surviving condition peer");
    observe_parked(&peer);
    observe_parked(state);
    REQUIRE(pthread_mutex_lock(&state->mutex) == 0, "own shared condition mutex");
    REQUIRE(pthread_cancel(state->thread) == 0, "cancel one already-parked condition peer");
    state->go = 1;
    REQUIRE(pthread_cond_signal(&state->condition) == 0, "publish one condition signal");
    REQUIRE(pthread_mutex_unlock(&state->mutex) == 0, "allow both peers to reacquire");
    join_canceled(state);
    REQUIRE(!atomic_load(&state->returned) && atomic_load(&state->cleaned) == 1,
            "canceled peer did not consume the predicate");
    /* No second signal/broadcast can conceal a signal stolen by cancellation. */
    REQUIRE(join_bounded(peer.thread, "cancellation stranded the single signaled peer") == &peer,
            "uncanceled condition peer completed normally");
    REQUIRE(atomic_load(&peer.returned) == 1 && atomic_load(&peer.cleaned) == 1 && state->go == 0,
            "exactly one surviving waiter consumed the predicate");
    REQUIRE(pthread_mutex_trylock(&state->mutex) == 0 && pthread_mutex_unlock(&state->mutex) == 0,
            "both peer cleanups released the shared mutex");
    REQUIRE(pthread_cond_destroy(&state->condition) == 0 && pthread_mutex_destroy(&state->mutex) == 0,
            "no stranded condition peers");
}

static void finish_target(struct state *state) {
    REQUIRE(!atomic_load(&state->target_release) && !atomic_load(&state->target_exited),
            "target stayed gated until canceled joiner completed");
    REQUIRE(state->join_value == &creator_tid, "canceled join left return-value slot untouched");
    void *value = &creator_tid;
    REQUIRE(pthread_tryjoin_np(state->target, &value) == EBUSY && value == &creator_tid,
            "canceled join did not claim or detach the live target");
    atomic_store_explicit(&state->target_release, 1, memory_order_release);
    const int64_t limit = monotonic_ns() + 3000000000;
    for (;;) {
        int error = pthread_tryjoin_np(state->target, &value);
        if (error == 0) {
            REQUIRE(value == &state->target_value && atomic_load(&state->target_exited),
                    "another thread can join the released target with its value");
            return;
        }
        REQUIRE(error == EBUSY && monotonic_ns() < limit, "target ownership was not retained");
        pause_briefly();
    }
}

static void force_waitv_enosys(void) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_futex_waitv, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = {(unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
                                instructions};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0)
        skip("seccomp-waitv-enosys-unavailable");
    errno = 0;
    REQUIRE(syscall(SYS_futex_waitv, NULL, 0, 0, NULL, CLOCK_MONOTONIC) == -1 && errno == ENOSYS,
            "futex_waitv ENOSYS filter is active");
}

enum child_operation { CHILD_WAIT, CHILD_WAITPID, CHILD_WAIT3, CHILD_WAIT4, CHILD_WAITID };

struct child_state {
    struct state worker;
    enum child_operation operation;
    pid_t child;
    uid_t uid;
    int gate;
    int disabled, nohang, nowait, completes, interrupted, restart, nested, siginfo, foreign;
    int pidfd_nonblock, pidfd, current_group;
    int result, status, error;
    struct rusage usage;
    siginfo_t info;
    _Atomic int signals;
};

static struct child_state *signal_child;

static int all_bytes(const void *pointer, size_t length, unsigned char value) {
    const unsigned char *bytes = pointer;
    for (size_t i = 0; i < length; ++i)
        if (bytes[i] != value) return 0;
    return 1;
}

static int child_outputs_untouched(const struct child_state *state) {
    return state->status == 0x5a5a5a5a && all_bytes(&state->usage, sizeof(state->usage), 0xa5) &&
           all_bytes(&state->info, sizeof(state->info), 0xa5);
}

static void initialize_child_outputs(struct child_state *state) {
    state->status = 0x5a5a5a5a;
    memset(&state->usage, 0xa5, sizeof(state->usage));
    memset(&state->info, 0xa5, sizeof(state->info));
}

static void check_child_info(const struct child_state *state, int ready) {
    siginfo_t expected;
    memset(&expected, 0xa5, sizeof(expected));
    expected.si_signo = ready ? SIGCHLD : 0;
    expected.si_errno = 0;
    expected.si_code = ready ? CLD_EXITED : 0;
    expected.si_pid = ready ? state->child : 0;
    expected.si_uid = ready ? state->uid : 0;
    expected.si_status = ready ? 37 : 0;
    REQUIRE(!memcmp(&state->info, &expected, sizeof(expected)),
            "waitid preserves padding and publishes exactly the child fields");
}

static void check_interrupted_child_outputs(const struct child_state *state) {
    if (state->operation == CHILD_WAITID) {
        check_child_info(state, 0);
        REQUIRE(state->status == 0x5a5a5a5a &&
                all_bytes(&state->usage, sizeof(state->usage), 0xa5),
                "waitid does not modify unrelated status or usage storage");
    } else {
        REQUIRE(child_outputs_untouched(state), "interrupted wait preserves status and usage");
    }
}

static int call_child_wait(struct child_state *state) {
    int options = state->nohang ? WNOHANG : 0;
    if (state->operation == CHILD_WAITID)
        return waitid(state->pidfd_nonblock ? P_PIDFD : state->current_group ? P_PGID : P_PID,
                      (id_t)(state->pidfd_nonblock ? state->pidfd : state->current_group ? 0 : state->child),
                      &state->info,
                      options | WEXITED | (state->nowait ? WNOWAIT : 0));
    if (state->operation == CHILD_WAIT) return wait(&state->status);
    if (state->operation == CHILD_WAITPID)
        return waitpid(state->current_group ? 0 : state->child, &state->status, options);
    if (state->operation == CHILD_WAIT3) return wait3(&state->status, options, &state->usage);
    return wait4(state->current_group ? 0 : state->child, &state->status, options, &state->usage);
}

static void child_cleanup(void *argument) {
    struct child_state *state = argument;
    sigset_t mask;
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0, "cleanup reads signal mask");
    REQUIRE(sigismember(&mask, SIGUSR1) == 0 && sigismember(&mask, SIGUSR2) == 0 &&
            sigismember(&mask, SIGALRM) == 0, "cancellation restores the wait's original mask");
    REQUIRE(atomic_fetch_add(&state->worker.cleaned, 1) == 0, "one child-wait cleanup");
}

static void *child_worker(void *argument) {
    struct child_state *state = argument;
    capture_worker_identity(&state->worker);
    REQUIRE(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0, "child wait deferred type");
    if (state->disabled)
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0,
                "disable child-wait cancellation");
    pthread_cleanup_push(child_cleanup, state);
    atomic_store_explicit(&state->worker.ready, 1, memory_order_release);
    errno = ENOTTY;
    state->result = call_child_wait(state);
    state->error = errno;
    if (state->nohang) {
        REQUIRE(state->result == 0 && state->error == ENOTTY, "empty WNOHANG preserves errno");
        if (state->operation == CHILD_WAITID) check_child_info(state, 0);
        else REQUIRE(child_outputs_untouched(state), "empty WNOHANG leaves status and usage alone");
        initialize_child_outputs(state);
        REQUIRE(pthread_cancel(pthread_self()) == 0, "make cancellation pending before WNOHANG");
        (void)call_child_wait(state);
        fail("WNOHANG did not deliver already-pending cancellation");
    }
    atomic_store_explicit(&state->worker.returned, 1, memory_order_release);
    pthread_cleanup_pop(1);
    if (state->disabled) {
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0,
                "reenable child-wait cancellation");
        pthread_testcancel();
        fail("disabled child wait lost its pending cancellation");
    }
    return state;
}

static void child_signal(int signum) {
    int saved = errno;
    struct child_state *state = signal_child;
    check_interrupted_child_outputs(state);
    atomic_fetch_add(&state->signals, 1);
    if (signum == SIGUSR1 && state->nested)
        REQUIRE(syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR2) == 0,
                "deliver nested signal to the interrupted waiter");
    errno = saved;
}

static void child_siginfo_signal(int signum, siginfo_t *info, void *context) {
    REQUIRE(info != NULL && context != NULL && info->si_signo == signum,
            "SA_SIGINFO receives the kernel signal frame");
    child_signal(signum);
}

static void observe_child_parked(const struct child_state *state) {
    const int64_t limit = monotonic_ns() + 2000000000;
    while (!atomic_load_explicit(&state->worker.ready, memory_order_acquire)) {
        REQUIRE(monotonic_ns() < limit, "child waiter publishes readiness");
        pause_briefly();
    }
    for (;;) {
        char call[512], status[512];
        long number = -1;
        unsigned long long first = 0, second = 0;
        read_proc(&state->worker, "syscall", call, sizeof(call));
        int parsed = sscanf(call, "%ld %llx %llx", &number, &first, &second);
        int native_slice = expect_native && !state->disabled &&
                           !state->interrupted && !state->restart && !state->current_group;
        int waiting = parsed >= 3 &&
            (native_slice ? number == SYS_ppoll && first == 0 && second == 0 :
             state->operation == CHILD_WAITID ? number == SYS_waitid &&
                 first == (unsigned long long)(state->current_group ? P_PGID : P_PID) &&
                 second == (unsigned long long)(state->current_group ? 0 : state->child) :
             number == SYS_wait4 &&
                 (state->operation == CHILD_WAIT || state->operation == CHILD_WAIT3 ||
                  (pid_t)first == (state->current_group ? 0 : state->child)));
        if (waiting) {
            read_proc(&state->worker, "stat", status, sizeof(status));
            char *end = strrchr(status, ')');
            REQUIRE(end != NULL && end[1] == ' ', "parse child waiter state");
            if (end[2] == 'S') return;
        }
        REQUIRE(!atomic_load(&state->worker.returned), "child wait returned before its gated event");
        REQUIRE(monotonic_ns() < limit, "no sleeping child wait observed");
        pause_briefly();
    }
}

static void release_child(struct child_state *state) {
    REQUIRE(write(state->gate, "x", 1) == 1, "release child only after the wait witness");
    REQUIRE(close(state->gate) == 0, "close child gate");
}

static int child_case(void) {
    static const char *names[] = {"child-wait", "child-waitpid", "child-wait3",
                                  "child-wait4", "child-waitid"};
    struct child_state state = {0};
    const char *suffix = NULL;
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        size_t length = strlen(names[i]);
        if (!strncmp(case_name, names[i], length) &&
            (case_name[length] == 0 || case_name[length] == '-')) {
            state.operation = (enum child_operation)i;
            suffix = case_name + length;
            break;
        }
    }
    if (suffix == NULL) return 2;
    state.disabled = !strcmp(suffix, "-disabled");
    state.nohang = !strcmp(suffix, "-nohang");
    state.nowait = !strcmp(suffix, "-nowait");
    state.pidfd_nonblock = !strcmp(suffix, "-pidfd-nonblock");
    state.current_group = !strcmp(suffix, "-pgrp-ready");
    state.siginfo = strstr(suffix, "-siginfo") != NULL;
    state.nested = strstr(suffix, "-nested") != NULL;
    state.foreign = !strcmp(suffix, "-foreign-restart");
    state.interrupted = strstr(suffix, "-eintr") != NULL;
    state.restart = strstr(suffix, "-restart") != NULL;
    state.completes = !strcmp(suffix, "-ready") || state.nowait || state.restart || state.current_group;
    if (*suffix && !state.disabled && !state.nohang && !state.completes && !state.interrupted &&
        !state.pidfd_nonblock)
        return 2;
    if ((state.nohang && state.operation == CHILD_WAIT) ||
        ((state.nowait || state.pidfd_nonblock) && state.operation != CHILD_WAITID)) return 2;
    initialize_child_outputs(&state);
    state.uid = getuid();
    signal_child = &state;
    if (state.interrupted || state.restart) {
        struct sigaction action = {0};
        sigemptyset(&action.sa_mask);
        action.sa_flags = (state.restart ? SA_RESTART : 0) | (state.siginfo ? SA_SIGINFO : 0);
        if (state.siginfo) action.sa_sigaction = child_siginfo_signal;
        else action.sa_handler = child_signal;
        int (*install)(int, const struct sigaction *, struct sigaction *) = sigaction;
        if (state.foreign) {
            /* Install through the actual host provider before the wait, to
             * exercise the explicit foreign-handler fallback, not its adapter. */
            void *host = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
            REQUIRE(host != NULL, "open GNU signal provider");
            install = (int (*)(int, const struct sigaction *, struct sigaction *))
                dlsym(host, "sigaction");
            REQUIRE(install != NULL, "resolve GNU sigaction");
        }
        REQUIRE(install(SIGUSR1, &action, NULL) == 0, "install child wait signal");
        if (state.nested) {
            action.sa_flags = (state.restart ? 0 : SA_RESTART) |
                              (state.siginfo ? SA_SIGINFO : 0);
            REQUIRE(sigaction(SIGUSR2, &action, NULL) == 0, "install opposite nested restart action");
        }
    }
    int gate[2];
    REQUIRE(pipe2(gate, O_CLOEXEC) == 0, "create gated child pipe");
    state.child = fork();
    REQUIRE(state.child >= 0, "fork gated child");
    if (state.child == 0) {
        close(gate[1]);
        char byte;
        /* Parent failure/timeout closes the only writer, so the child also
         * exits on EOF. No failed probe can leave a permanently parked child. */
        while (read(gate[0], &byte, 1) < 0 && errno == EINTR) {}
        _exit(37);
    }
    REQUIRE(close(gate[0]) == 0, "close parent's child-read descriptor");
    state.gate = gate[1];
    if (state.pidfd_nonblock) {
        state.pidfd = (int)syscall(SYS_pidfd_open, state.child, O_NONBLOCK);
        if (state.pidfd < 0 && (errno == ENOSYS || errno == EINVAL || errno == EPERM))
            skip("nonblocking-pidfd-unavailable");
        REQUIRE(state.pidfd >= 0, "open nonblocking pidfd");
    }
    REQUIRE(pthread_create(&state.worker.thread, NULL, child_worker, &state) == 0,
            "create native child waiter");
    if (!state.nohang && !state.pidfd_nonblock) observe_child_parked(&state);
    if (state.interrupted || state.restart) {
        REQUIRE(pthread_kill(state.worker.thread, SIGUSR1) == 0, "interrupt parked child wait");
        if (state.restart) {
            const int64_t limit = monotonic_ns() + 2000000000;
            while (atomic_load(&state.signals) != (state.nested ? 2 : 1)) {
                REQUIRE(monotonic_ns() < limit, "signal handlers completed");
                pause_briefly();
            }
            observe_child_parked(&state);
        }
    } else if (!state.completes && !state.nohang && !state.pidfd_nonblock) {
        REQUIRE(pthread_cancel(state.worker.thread) == 0, "cancel already-parked child wait");
    }
    if (state.disabled) {
        observe_child_parked(&state);
        REQUIRE(!atomic_load(&state.worker.cleaned), "disabled child wait remains parked");
    }
    if (state.completes || state.disabled) release_child(&state);
    void *result = join_bounded(state.worker.thread, "child waiter did not finish without a rescue");
    int canceled = !state.completes && !state.interrupted && !state.pidfd_nonblock;
    REQUIRE(result == (canceled ? PTHREAD_CANCELED : &state), "child waiter completion kind");
    REQUIRE(atomic_load(&state.worker.cleaned) == 1, "child waiter cleanup completed once");
    REQUIRE(atomic_load(&state.worker.returned) ==
            (state.completes || state.interrupted || state.disabled || state.pidfd_nonblock),
            "only completed or interrupted waits publish a return");
    if (state.pidfd_nonblock) {
        REQUIRE(state.result == -1 && state.error == EAGAIN,
                "nonblocking pidfd wait reports EAGAIN without parking");
        check_interrupted_child_outputs(&state);
    } else if (state.interrupted) {
        REQUIRE(state.result == -1 && state.error == EINTR, "nonrestarting signal interrupts wait");
        REQUIRE(atomic_load(&state.signals) == (state.nested ? 2 : 1), "expected handler deliveries");
        check_interrupted_child_outputs(&state);
    } else if (state.completes || state.disabled) {
        REQUIRE(state.error == ENOTTY, "completed child wait preserves caller errno");
        if (state.operation == CHILD_WAITID) {
            REQUIRE(state.result == 0, "completed waitid result");
            check_child_info(&state, 1);
        } else {
            REQUIRE(state.result == state.child && WIFEXITED(state.status) &&
                    WEXITSTATUS(state.status) == 37, "completed child pid and exit status");
            if (state.operation == CHILD_WAIT3 || state.operation == CHILD_WAIT4)
                REQUIRE(state.usage.ru_utime.tv_sec >= 0 && state.usage.ru_stime.tv_sec >= 0,
                        "completed wait publishes resource usage");
        }
    } else {
        if (state.nohang)
            REQUIRE(child_outputs_untouched(&state), "pending cancellation precedes WNOHANG output");
        else
            check_interrupted_child_outputs(&state);
    }
    int status = -1;
    if ((!state.completes && !state.disabled) || state.nowait) {
        if (!state.nowait) {
            REQUIRE(waitpid(state.child, &status, WNOHANG) == 0 && status == -1,
                    "cancellation or interruption did not reap the live child");
            release_child(&state);
        }
        REQUIRE(waitpid(state.child, &status, 0) == state.child && WIFEXITED(status) &&
                WEXITSTATUS(status) == 37, "another wait retains the child's exit result");
    }
    errno = 0;
    REQUIRE(waitpid(state.child, &status, WNOHANG) == -1 && errno == ECHILD,
            "each child is reaped exactly once");
    if (state.pidfd_nonblock) REQUIRE(close(state.pidfd) == 0, "close child pidfd");
    printf("pthread-native-wait:%s:PASS\n", case_name);
    return 0;
}

struct signal_wait_state {
    struct state worker;
    sigset_t set;
    int disabled, completes, interrupted, pending, alias;
    int result, signal, error;
    _Atomic int handlers, retained;
};

static struct signal_wait_state *signal_waiter;

static void signal_wait_handler(int signal) {
    if (signal != SIGUSR2) _Exit(3);
    atomic_fetch_add_explicit(&signal_waiter->handlers, 1, memory_order_release);
}

static void signal_wait_cleanup(void *argument) {
    struct signal_wait_state *state = argument;
    sigset_t mask;
    REQUIRE(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0 &&
            sigismember(&mask, SIGUSR1) == 1 && sigismember(&mask, SIGUSR2) == 0,
            "sigwait cleanup preserves the caller's signal mask");
    if (state->pending) {
        sigset_t pending;
        REQUIRE(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR1) == 1,
                "pending cancellation must not consume an already-queued signal");
        atomic_store_explicit(&state->retained, 1, memory_order_release);
    }
    REQUIRE(atomic_fetch_add_explicit(&state->worker.cleaned, 1, memory_order_release) == 0,
            "sigwait cleanup ran exactly once");
}

static void *signal_wait_worker(void *argument) {
    struct signal_wait_state *state = argument;
    capture_worker_identity(&state->worker);
    REQUIRE(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0,
            "sigwait deferred cancellation type");
    if (state->disabled)
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0,
                "disable sigwait cancellation");
    typedef int (*sigwait_function)(const sigset_t *, int *);
    sigwait_function wait = state->alias
        ? (sigwait_function)dlsym(RTLD_DEFAULT, "__sigwait") : sigwait;
    REQUIRE(wait != NULL, "sigwait entrypoint available");
    pthread_cleanup_push(signal_wait_cleanup, state);
    if (state->pending) {
        REQUIRE(pthread_kill(pthread_self(), SIGUSR1) == 0, "queue signal before sigwait");
        REQUIRE(pthread_cancel(pthread_self()) == 0, "queue cancellation before sigwait");
    }
    errno = ENOTTY;
    atomic_store_explicit(&state->worker.ready, 1, memory_order_release);
    state->result = wait(&state->set, &state->signal);
    state->error = errno;
    atomic_store_explicit(&state->worker.returned, 1, memory_order_release);
    pthread_cleanup_pop(1);
    if (state->disabled) {
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0,
                "restore sigwait cancellation");
        pthread_testcancel();
        fail("disabled sigwait lost its pending cancellation");
    }
    return state;
}

static void observe_signal_wait_parked(const struct signal_wait_state *state) {
    const int64_t limit = monotonic_ns() + 2000000000;
    while (!atomic_load_explicit(&state->worker.ready, memory_order_acquire)) {
        REQUIRE(monotonic_ns() < limit, "sigwait worker publishes readiness");
        pause_briefly();
    }
    for (;;) {
        char call[512], status[512];
        long number = -1;
        read_proc(&state->worker, "syscall", call, sizeof(call));
        if (sscanf(call, "%ld", &number) == 1 && number == SYS_rt_sigtimedwait) {
            read_proc(&state->worker, "stat", status, sizeof(status));
            char *end = strrchr(status, ')');
            REQUIRE(end != NULL && end[1] == ' ', "parse sigwait task state");
            if (end[2] == 'S') return;
        }
        REQUIRE(!atomic_load_explicit(&state->worker.returned, memory_order_acquire),
                "sigwait returned without a selected signal");
        REQUIRE(monotonic_ns() < limit, "no sleeping rt_sigtimedwait observed");
        pause_briefly();
    }
}

static int signal_wait_case(void) {
    struct signal_wait_state state = {0};
    state.disabled = strstr(case_name, "-disabled") != NULL;
    state.interrupted = strstr(case_name, "-eintr") != NULL;
    state.completes = strstr(case_name, "-ready") != NULL || state.interrupted;
    state.pending = strstr(case_name, "-pending") != NULL;
    state.alias = strstr(case_name, "-alias") != NULL;
    state.signal = 0x5a5a5a5a;
    state.result = 0x5a5a5a5a;
    REQUIRE(sigemptyset(&state.set) == 0 && sigaddset(&state.set, SIGUSR1) == 0,
            "sigwait set");
    sigset_t before, mask;
    REQUIRE(pthread_sigmask(SIG_BLOCK, &state.set, &before) == 0, "block selected signal");
    REQUIRE(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGUSR2) == 0 &&
            pthread_sigmask(SIG_UNBLOCK, &mask, NULL) == 0, "unblock unrelated handler");
    signal_waiter = &state;
    struct sigaction action = {0}, old_action;
    action.sa_handler = signal_wait_handler;
    sigemptyset(&action.sa_mask);
    REQUIRE(sigaction(SIGUSR2, &action, &old_action) == 0, "install unrelated signal handler");
    REQUIRE(pthread_create(&state.worker.thread, NULL, signal_wait_worker, &state) == 0,
            "create native signal waiter");
    if (!state.pending) {
        observe_signal_wait_parked(&state);
        if (state.interrupted) {
            REQUIRE(pthread_kill(state.worker.thread, SIGUSR2) == 0,
                    "interrupt sigwait with an unrelated handler");
            const int64_t limit = monotonic_ns() + 2000000000;
            while (!atomic_load_explicit(&state.handlers, memory_order_acquire)) {
                REQUIRE(monotonic_ns() < limit, "unrelated handler ran");
                pause_briefly();
            }
            observe_signal_wait_parked(&state);
        }
        if (!state.completes)
            REQUIRE(pthread_cancel(state.worker.thread) == 0, "cancel already-parked sigwait");
        if (state.disabled) {
            /* Outlast several bounded slices: cancellation must stay pending. */
            const int64_t limit = monotonic_ns() + 160000000;
            while (monotonic_ns() < limit) pause_briefly();
            observe_signal_wait_parked(&state);
            REQUIRE(!atomic_load(&state.worker.cleaned), "disabled sigwait remains parked");
        }
        if (state.completes || state.disabled)
            REQUIRE(pthread_kill(state.worker.thread, SIGUSR1) == 0, "deliver selected signal");
    }
    void *result = join_bounded(state.worker.thread, "sigwait cancellation did not wake the waiter");
    REQUIRE(result == (state.completes ? &state : PTHREAD_CANCELED), "sigwait completion kind");
    REQUIRE(atomic_load(&state.worker.cleaned) == 1, "sigwait cleanup completed once");
    REQUIRE(atomic_load(&state.worker.returned) == (state.completes || state.disabled),
            "sigwait only returns after consuming a selected signal");
    if (state.completes || state.disabled) {
        REQUIRE(state.result == 0 && state.signal == SIGUSR1, "sigwait publishes selected signal");
        /* GNU may leave EINTR after retrying an unrelated handler. Neither
         * implementation may leak the adapter's internal slice timeout. */
        REQUIRE(state.error == ENOTTY || (state.interrupted && state.error == EINTR),
                "sigwait does not publish an internal timeout errno");
    } else {
        REQUIRE(state.result == 0x5a5a5a5a && state.signal == 0x5a5a5a5a,
                "cancellation leaves sigwait output untouched");
    }
    REQUIRE(atomic_load(&state.retained) == state.pending, "queued signal ownership retained");
    REQUIRE(atomic_load(&state.handlers) == state.interrupted, "unrelated handler runs once");
    REQUIRE(sigaction(SIGUSR2, &old_action, NULL) == 0 &&
            pthread_sigmask(SIG_SETMASK, &before, NULL) == 0, "restore signal disposition and mask");
    printf("pthread-native-wait:%s:PASS\n", case_name);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    case_name = argv[1];
    int pinned = pin_providers(argv[2]);
    if (pinned) return pinned;
    const char *native = getenv("FRANKENLIBC_THREAD_NATIVE");
    expect_native = native != NULL && !strcmp(native, "1");
    creator_tp = thread_pointer();
    creator_tid = (pid_t)syscall(SYS_gettid);
    creator_thread = pthread_self();
    if (!strncmp(case_name, "child-", 6)) return child_case();
    if (!strncmp(case_name, "sigwait", 7)) return signal_wait_case();
    const char *names[] = {"sem-wait", "sem-timed", "sem-clock-real", "sem-clock-mono",
                           "cond-wait", "cond-timed", "cond-clock-real", "cond-clock-mono",
                           "join", "join-alias", "join-timed", "join-clock-real", "join-clock-mono",
                           "join-timed-null", "join-clock-null"};
    struct state state = {0};
    int found = 0;
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        size_t length = strlen(names[i]);
        if (!strncmp(case_name, names[i], length) &&
            (case_name[length] == 0 || case_name[length] == '-')) {
            const char *suffix = case_name + length;
            if (*suffix && strcmp(suffix, "-disabled") && strcmp(suffix, "-enosys") &&
                strcmp(suffix, "-disabled-enosys") && strcmp(suffix, "-peers") &&
                strcmp(suffix, "-peers-enosys")) continue;
            state.operation = (enum operation)i;
            state.disabled = strstr(suffix, "-disabled") != NULL;
            state.peers = strstr(suffix, "-peers") != NULL;
            found = 1;
            break;
        }
    }
    if (!found) return 2;
    if (state.peers && state.operation != COND_WAIT) return 2;
    if (strstr(case_name, "-enosys")) force_waitv_enosys();
    if (is_join(&state)) {
        if (state.operation == JOIN_ALIAS) {
            alias_join = (join_function)dlsym(RTLD_DEFAULT, "__pthread_join");
            REQUIRE(alias_join != NULL, "join alias available");
        }
        state.join_value = &creator_tid;
        REQUIRE(pthread_create(&state.target, NULL, gated_target, &state) == 0, "create gated target");
        const int64_t limit = monotonic_ns() + 2000000000;
        while (!atomic_load_explicit(&state.target_ready, memory_order_acquire)) {
            REQUIRE(monotonic_ns() < limit, "target publishes kernel wait word");
            pause_briefly();
        }
    } else if (is_condition(&state)) {
        pthread_mutexattr_t attr;
        REQUIRE(pthread_mutexattr_init(&attr) == 0, "mutex attributes");
        REQUIRE(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) == 0, "ERRORCHECK type");
        REQUIRE(pthread_mutex_init(&state.mutex, &attr) == 0, "mutex initialization");
        REQUIRE(pthread_mutexattr_destroy(&attr) == 0, "destroy mutex attributes");
        REQUIRE(pthread_cond_init(&state.condition, NULL) == 0, "condition initialization");
    } else {
        REQUIRE(sem_init(&state.semaphore, 0, 0) == 0, "zero-token semaphore");
    }
    if (state.peers) {
        condition_peers(&state);
        printf("pthread-native-wait:%s:PASS\n", case_name);
        return 0;
    }
    REQUIRE(pthread_create(&state.thread, NULL, worker, &state) == 0, "create waiter");
    observe_parked(&state);
    if (is_condition(&state))
        REQUIRE(pthread_mutex_lock(&state.mutex) == 0, "parent owns released condition mutex");
    REQUIRE(pthread_cancel(state.thread) == 0, "cancel parked waiter");
    if (state.disabled) {
        observe_parked(&state);
        REQUIRE(!atomic_load(&state.cleaned) && !atomic_load(&state.returned),
                "disabled waiter must remain blocked");
        if (is_join(&state)) {
            atomic_store_explicit(&state.target_release, 1, memory_order_release);
        } else if (is_condition(&state)) {
            state.go = 1;
            REQUIRE(pthread_cond_signal(&state.condition) == 0, "release disabled condition wait");
        } else {
            REQUIRE(sem_post(&state.semaphore) == 0, "release disabled semaphore wait");
        }
    }
    if (is_condition(&state))
        REQUIRE(pthread_mutex_unlock(&state.mutex) == 0, "allow cancellation mutex reacquisition");
    /* Enabled cases get no post/signal: cancellation itself must wake the wait. */
    join_canceled(&state);
    REQUIRE(atomic_load(&state.cleaned) == 1, "one cleanup");
    REQUIRE(atomic_load(&state.returned) == state.disabled, "operation return respects cancellation state");
    if (is_join(&state)) {
        if (state.disabled)
            REQUIRE(atomic_load(&state.target_exited) && state.join_value == &state.target_value,
                    "disabled join completed before pending cancellation was delivered");
        else
            finish_target(&state);
    } else if (is_condition(&state)) {
        REQUIRE(pthread_mutex_trylock(&state.mutex) == 0, "cleanup released condition mutex");
        REQUIRE(pthread_mutex_unlock(&state.mutex) == 0, "release reused mutex");
        REQUIRE(pthread_cond_destroy(&state.condition) == 0, "no stranded condition waiter");
        REQUIRE(pthread_mutex_destroy(&state.mutex) == 0, "destroy reused mutex");
    } else {
        int value = -1;
        REQUIRE(sem_getvalue(&state.semaphore, &value) == 0 && value == 0, "no lost or invented token");
        REQUIRE(sem_post(&state.semaphore) == 0 && sem_trywait(&state.semaphore) == 0,
                "semaphore remains reusable after cancellation");
        errno = 0;
        REQUIRE(sem_trywait(&state.semaphore) == -1 && errno == EAGAIN, "exactly one posted token");
        REQUIRE(sem_destroy(&state.semaphore) == 0, "no stranded semaphore waiter");
    }
    printf("pthread-native-wait:%s:PASS\n", case_name);
    return 0;
}
